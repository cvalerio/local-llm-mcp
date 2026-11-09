"""FastMCP server: the tools, the delegation pipeline, compaction, control socket.

Invariant that everything here is arranged around:
  * everything that goes TO the worker or the shell is REHYDRATED (placeholders -> values);
  * everything that LEAVES the server (tool results, artifacts, status, summaries)
    is SCRUBBED (values -> placeholders) — fully in PII mode, secrets-only in ASSIST mode.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, AsyncIterator

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import prompts
from .arming import ARM_CHOICES, MAX_ARM_ASKS, NO_DIALOG_TEXT, OFF_TEXT, UNANSWERED_TEXT, EnableChoice, arm_message
from . import savings as sv
from .config import MODES, Config
from .disclosure import CHOICES, DisclosureChoice, detected_tiers, dialog_message, found_text
from .control import socket_path, start as start_control
from .llm import LLMError, LocalLLM
from .material import ShellNotFound, cap, read_paths, run_command
from .observers import load_observer
from . import policy as cp
from .scrub import PLACEHOLDER_RE, TIERS, Policy, ScrubResult, Scrubber
from .session import Session
from . import verbatim as vb

log = logging.getLogger("local_llm_mcp.server")


def build_decider(cfg: Config):
    """The decision engine over this server's own workers: the primary and the configured fallback, in the
    order LOCAL_LLM_MCP_DECIDE_PREFER asks for (a smaller dense model can be the better judge)."""
    from .decision_engine import Engine, Worker
    extra = {} if cfg.thinking else {"chat_template_kwargs": {"enable_thinking": False}}
    workers = [Worker(cfg.base_url, cfg.model, cfg.api_key, extra)]
    if cfg.fallback_base_url:
        workers.append(Worker(cfg.fallback_base_url, cfg.fallback_model or cfg.model, cfg.fallback_api_key, extra))
    if cfg.decide_prefer == "fallback":
        workers.reverse()
    return Engine(workers, timeout=cfg.decide_timeout, reasoning=cfg.decide_reasoning)


class App:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = Session(cfg)
        self.llm = LocalLLM(cfg)
        self.decider = None
        if cfg.decide:  # optional, off by default: nothing is created or exposed unless switched on
            self.decider = build_decider(cfg)
        self.scrubber = Scrubber(cfg.rules_path, cfg.private_terms_path, strict=cfg.strict_pii, shapes=cfg.shapes)
        self.observer = load_observer(cfg)
        self.prices = sv.Prices(cfg.prices_path, cfg.caller_model)
        self.ledger = sv.Ledger(cfg.state_dir / "savings.jsonl")
        self.allow = cp.AllowList(cfg.run_allow_path)
        self.pending: dict[asyncio.Task, tuple[str, dict]] = {}  # token measurements in flight
        self.lock = asyncio.Lock()
        self.compacting: asyncio.Task | None = None
        self.control_server: asyncio.AbstractServer | None = None
        self.control_path = None

    # ---- boundaries ------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self.session.mode

    def policy(self) -> Policy:
        """What may leave in clear right now: the mode plus this session's disclosure state."""
        return self.session.disclosure.policy(self.mode)

    def outbound(self, text: str, policy: Policy | None = None, *, keep_lines: bool = False) -> ScrubResult:
        """Everything that leaves the server passes through here."""
        return self.scrubber.scrub(text, self.session.vault, policy=policy or self.policy(), keep_lines=keep_lines)

    def vault_memory(self) -> int:
        """When a session moves to PII mode (or identity values get masked): values already
        written into its memory under the old policy get vaulted, so they leave masked from
        now on. Returns how many distinct values were registered."""
        turns = self.session.turns()
        texts = [self.session.summary()] + [str(t.get("excerpt") or "") for t in turns] + [str(t.get("result") or "") for t in turns]
        counts = self.scrubber.register_material("\n".join(texts), self.session.vault, policy=Policy.register(entropy=False))
        return sum(counts.values())

    async def ensure_armed(self, ctx: Context | None, trigger: str = "a tool") -> tuple[bool, str]:
        """The opt-in gate. Returns (on, text): when on, ``text`` is empty or the operating rules to
        prepend to this first result; when off, ``text`` is the refusal to return instead of working.
        Passes without a dialog only on the user's standing approval (LOCAL_LLM_MCP_ARM=on) or a
        session already turned on (dialog, tool, or the admin app)."""
        self.note_client(ctx)
        if self.cfg.arm == "on":
            if self.session.armed_state() != "on":
                self.session.set_armed("on", "env")
                self.observer.event("session", "armed", {"state": "on", "source": "env", "session": self.session.key})
            return True, ""
        self.session.reload_meta_if_changed()
        state = self.session.armed_state()
        if state == "on":
            return True, ""
        if state == "off":
            return False, OFF_TEXT
        if not self.client_can_ask(ctx):
            return False, NO_DIALOG_TEXT
        asks = self.session.bump_armed_asks()
        if asks > MAX_ARM_ASKS:
            self.session.set_armed("off", "unanswered")
            return False, OFF_TEXT
        action, choice = "error", ""
        try:
            res = await asyncio.wait_for(ctx.elicit(arm_message(self.mode, self.cfg.model, trigger), EnableChoice),
                                         timeout=self.cfg.dialog_timeout)
            action = str(res.action)
            if action == "accept" and res.data is not None:
                choice = str(res.data.choice or "").strip().lower()
        except asyncio.TimeoutError:
            action = "timeout"
        except Exception as exc:
            log.warning("turn-on dialog failed: %s", exc)
        if action != "accept" or choice not in ARM_CHOICES:
            self.observer.event("session", "armed", {"state": "unanswered", "source": action, "session": self.session.key})
            return False, UNANSWERED_TEXT.format(action=action)
        if choice == "off":
            self.session.set_armed("off", "dialog")
            self.observer.event("session", "armed", {"state": "off", "source": "dialog", "session": self.session.key})
            return False, OFF_TEXT
        if choice == "on_pii" and self.mode != "pii":
            self.session.set_mode("pii")
            self.vault_memory()
        self.session.set_armed("on", "dialog")
        self.observer.event("session", "armed", {"state": "on", "source": "dialog", "mode": self.mode, "session": self.session.key})
        return True, (f"[local-llm-mcp] The user turned this server on for this session (mode {self.mode.upper()}). "
                      "Operating rules:\n" + prompts.client_instructions(self.mode, self.cfg.model, self.cfg.base_url))

    async def approve_command(self, ctx: Context | None, command: str, cwd: str = "") -> tuple[bool, str, str]:
        """The command policy. Returns (may run, refusal to return instead, label for the turn).

        Deny shapes first and always — no allow entry and no dialog can exempt them. Then the
        operator's allow list. Then the user is asked, showing the exact command; a client that
        cannot ask gets the deny check only and a trailer line saying so.
        """
        if self.cfg.run_policy == "off":
            return True, "", "policy off"
        secrets = [ph for ph, rec in self.session.vault.by_placeholder.items() if rec.get("kind") in TIERS["secrets"]]
        d = cp.check(command, self.allow, secrets, expanded=self.inbound(command))
        if d.verdict == "deny":
            self.session.note_run_policy("denied", d.rule, command)
            self.observer.event("execute_tool", "local_llm.policy",
                                {"verdict": "denied", "rule": d.rule, "session": self.session.key})
            return False, cp.refusal_text(d), d.label
        if d.verdict == "allow":
            self.session.note_run_policy("allowed", d.rule)
            return True, "", d.label
        if self.cfg.run_policy == "allow" or not self.client_can_ask(ctx):
            self.session.note_run_policy("unasked")
            return True, "", cp.NO_DIALOG_NOTE
        if self.session.run_policy_asks() >= cp.MAX_ASKS:
            self.session.note_run_policy("refused", "ask limit", command)
            return False, ("[local-llm-mcp] REFUSED: this session has already asked the user about "
                           f"{cp.MAX_ASKS} commands. Nothing was run. The user can add the shapes they want "
                           f"to allow to {self.cfg.run_allow_path}."), "refused: ask limit"
        shapes = cp.shapes_for(command)
        action, choice = "error", ""
        try:
            res = await asyncio.wait_for(ctx.elicit(cp.dialog_message(command, cwd, shapes), cp.RunChoice),
                                         timeout=self.cfg.dialog_timeout)
            action = str(res.action)
            if action == "accept" and res.data is not None:
                choice = str(res.data.choice or "").strip().lower()
        except asyncio.TimeoutError:
            action = "timeout"
        except Exception as exc:
            log.warning("command dialog failed: %s", exc)
        if action != "accept" or choice not in cp.CHOICES or choice == "refuse":
            refused = choice == "refuse"
            self.session.note_run_policy("refused", "user" if refused else action, command)
            self.observer.event("execute_tool", "local_llm.policy",
                                {"verdict": "refused", "rule": "user" if refused else action, "session": self.session.key})
            return False, (cp.user_refusal_text(command) if refused else cp.unanswered_text(action)), \
                (f"refused: user" if refused else f"refused: {action}")
        if choice == "always":
            written = self.allow.add_all(shapes)
            label = ", ".join(shapes)
            self.session.note_run_policy("asked_always", label)
            self.observer.event("execute_tool", "local_llm.policy",
                                {"verdict": "always", "rule": label, "session": self.session.key})
            return True, "", f"asked:always ({label})" if written else f"asked:run (could not write {self.cfg.run_allow_path})"
        self.session.note_run_policy("asked_once")
        self.observer.event("execute_tool", "local_llm.policy", {"verdict": "once", "session": self.session.key})
        return True, "", "asked:run"

    def note_client(self, ctx: Context | None) -> None:
        """Remember which MCP client this session belongs to (name, version, whether it can show a dialog)."""
        try:
            params = ctx.session.client_params if ctx is not None else None
            info = params.clientInfo if params is not None else None
            if info is None:
                return
            rec = {"name": str(info.name), "version": str(getattr(info, "version", "") or ""),
                   "elicitation": self.client_can_ask(ctx)}
            if self.session.meta.get("client") != rec:
                self.session.meta["client"] = rec
                self.session._save_meta()
        except Exception:  # bookkeeping only
            pass

    @staticmethod
    def client_can_ask(ctx: Context | None) -> bool:
        """Did the client declare the elicitation capability (it can show the user a dialog)?"""
        try:
            params = ctx.session.client_params if ctx is not None else None
            return bool(params and params.capabilities and params.capabilities.elicitation is not None)
        except Exception:
            return False

    async def decide(self, ctx: Context | None, counts: dict, source: str) -> tuple[Policy | None, str, str]:
        """First identity/number values in an ASSIST session. Ask the human when the client can
        show a dialog (the worker keeps working meanwhile), else apply the escalation policy.
        Returns (policy override for THIS turn or None, notice for the caller, trailer label)."""
        d = self.session.disclosure
        found = found_text(counts)
        esc = self.cfg.escalation
        if esc == "off":
            d.set(identity="open", source="policy")
            self.session.set_disclosure(d)
            self.observer.event("session", "disclosure", {"decision": "open", "source": "policy", "session": self.session.key})
            return None, "", "identity open (policy)"
        if esc == "auto" or not self.client_can_ask(ctx) or d.asked >= 3:
            d.set(identity="masked", source="auto")
            self.session.set_disclosure(d)
            self.observer.event("session", "disclosure", {"decision": "masked", "source": "auto", "session": self.session.key})
            return None, (f"[local-llm-mcp] Personal data found ({found}) and masked: in this ASSIST session secrets, "
                          "account/id numbers and identity values (names, addresses, emails, phones) come back as "
                          "placeholders. If the user wants identity values shown, call local_llm_disclosure(identity='open'); "
                          "for numbers too, numbers='open'; or switch to PII mode."), "masked (auto)"
        d.asked += 1
        self.session.set_disclosure(d)
        action, choice = "error", ""
        try:
            res = await asyncio.wait_for(ctx.elicit(dialog_message(counts, source), DisclosureChoice),
                                         timeout=self.cfg.dialog_timeout)
            action = str(res.action)
            if action == "accept" and res.data is not None:
                choice = str(res.data.choice or "").strip().lower()
        except asyncio.TimeoutError:
            action = "timeout"
        except Exception as exc:
            log.warning("disclosure dialog failed: %s", exc)
        if action != "accept" or choice not in CHOICES:
            self.observer.event("session", "disclosure", {"decision": "none", "source": action, "session": self.session.key})
            return Policy.assist(False, False), (f"[local-llm-mcp] The user did not answer the disclosure dialog ({action}); "
                                                 "this result is masked. The dialog is shown again the next time personal "
                                                 "data appears."), f"dialog {action}: masked"
        switched = d.apply(choice, source="dialog")
        self.session.set_disclosure(d)
        self.observer.event("session", "disclosure", {"decision": choice, "source": "dialog", "session": self.session.key})
        if switched:
            self.session.set_mode("pii")
            self.vault_memory()
            self.observer.event("session", "mode_change", {"from": "assist", "to": "pii", "session": self.session.key})
            return Policy.everything(), ("[local-llm-mcp] The user switched this session to PII mode: every private value is a "
                                         "placeholder from now on, including this result. New instructions:\n"
                                         + prompts.client_instructions("pii", self.cfg.model, self.cfg.base_url)), "asked → switched to PII"
        if choice == "continue":
            return None, ("[local-llm-mcp] The user chose to continue in ASSIST: identity values (names, addresses, emails, "
                          "phones) are shown; secrets, account/card/id numbers and dates of birth stay masked."), "asked → continue"
        return None, ("[local-llm-mcp] The user chose to continue in ASSIST and show everything except secrets: identity "
                      "values and account/card/id numbers pass in clear."), "asked → everything"

    def inbound(self, text: str) -> str:
        """Everything that goes to the worker or the shell passes through here."""
        return self.session.vault.rehydrate(text)

    # ---- pipeline --------------------------------------------------------------

    @staticmethod
    def _trailer(parts: list[str]) -> str:
        return "\n\n— local-llm · " + " · ".join(p for p in parts if p)

    async def locate_lines(self, task: str, material: str, source: str) -> list[tuple[int, int]]:
        """Verbatim mode: ask the worker for the line ranges the task refers to, chunk by chunk."""
        lines = material.split("\n")
        total = len(lines)
        windows = vb.chunk_lines(lines, self.cfg.chunk_chars)
        sem = asyncio.Semaphore(self.cfg.parallel_chunks)

        async def one(a: int, b: int) -> list[tuple[int, int]]:
            if b <= a:
                return []
            async with sem:
                numbered = vb.number_lines(lines[a:b], a + 1)
                text, _u = await self.llm.chat(prompts.LOCATE_SYSTEM, prompts.LOCATE_USER.format(
                    task=task, source=source, first=a + 1, last=b, total=total, numbered=numbered),
                    max_tokens=1024, temperature=0.0)
                return vb.parse_ranges(text, total)

        found = await asyncio.gather(*(one(a, b) for a, b in windows))
        return vb.merge_ranges([r for part in found for r in part], total)

    def quote_lines(self, material: str, ranges: list[tuple[int, int]], source: str, max_output_chars: int,
                    policy: Policy) -> tuple[str, list]:
        """Quote the ranges from the SCRUBBED material: a range that starts inside a multi-line secret
        holds only a fragment of it, and no scrub can recognise a fragment afterwards."""
        if not ranges:
            return "", []  # nothing to quote: the caller falls back to a digest
        label = source if not source.startswith(("paths:", "inline")) and ";" not in source else f"combined material ({source})"
        return vb.quote(self.outbound(material, policy, keep_lines=True).text.split("\n"), ranges, label, max_output_chars)

    def _measure(self, turn: dict, gathered_text: str, returned_text: str) -> None:
        """Record the turn in the savings ledger with the worker's exact token counts,
        measured in the background so the caller never waits on it. A failed or
        cancelled measurement still records the turn (chars only)."""
        key = self.session.key
        if turn.get("error") or not (gathered_text or returned_text):
            self.ledger.append(key, turn)
            return

        async def run() -> None:
            gt = await self.llm.count_tokens(gathered_text) if gathered_text else 0
            rt = await self.llm.count_tokens(returned_text) if returned_text else 0
            self.ledger.append(key, {**turn, "gathered_tokens": gt, "returned_tokens": rt})

        try:
            task = asyncio.get_running_loop().create_task(run())
        except RuntimeError:
            self.ledger.append(key, turn)
            return
        self.pending[task] = (key, turn)

        def done(t: asyncio.Task) -> None:
            self.pending.pop(t, None)
            if t.cancelled() or t.exception():
                if not t.cancelled():
                    log.warning("token measurement failed: %s", t.exception())
                self.ledger.append(key, turn)

        task.add_done_callback(done)

    async def flush_measurements(self, timeout: float = 15.0) -> None:
        """At shutdown: give in-flight measurements a moment, then record the rest unmeasured."""
        tasks = list(self.pending)
        if not tasks:
            return
        await asyncio.wait(tasks, timeout=timeout)
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def delegate(self, *, kind: str, task: str, material: str, source: str,
                       max_output_chars: int, extra: dict | None = None, verbatim: bool = False,
                       ctx: Context | None = None) -> str:
        t0 = time.monotonic()
        self.note_client(ctx)
        mode = self.mode
        extra = dict(extra or {})
        gathered_text = extra.pop("_gathered_text", None)
        if gathered_text is None:
            gathered_text = material if kind == "run" else ""
        async with self.lock:
            # EVERYTHING detectable in the material gets a placeholder BEFORE the worker
            # sees it, whatever the mode: the vault is local, an exact echo in the answer
            # is then caught in any context, and a later switch to PII is retroactive.
            # Only the high-entropy rule is PII-mode-only (ASSIST digests keep SHAs exact).
            counts = self.scrubber.register_material(material, self.session.vault,
                                                     policy=Policy.register(entropy=(mode == "pii")))
            entities = 0
            if mode == "pii" and material and self.cfg.entity_pass:
                entities = await self.entity_pass(material)
            context = self.inbound(self.session.context_block(self.cfg.context_chars))
            system = prompts.worker_system(mode, max_output_chars, context)
            error = ""
            answer = ""
            usage = None
            finalized = False
            left_out: list = []
            # The worker starts now; a disclosure dialog, if one is due, runs while it works.
            if verbatim and material:
                work = asyncio.ensure_future(self.locate_lines(self.inbound(task), material, source))
            else:
                work = asyncio.ensure_future(self.llm.digest(
                    system, self.inbound(task), material, source,
                    max_output_chars=max_output_chars,
                    render_user=prompts.render_user, render_reduce=prompts.render_reduce))
            override: Policy | None = None
            notice = ""
            decision = ""
            fallback = False  # verbatim asked for, nothing matched, digested instead
            if mode == "assist" and detected_tiers(counts) and self.session.disclosure.identity == "undecided":
                try:
                    override, notice, decision = await self.decide(ctx, counts, source)
                except Exception as exc:  # never lose the worker's answer to bookkeeping
                    log.warning("disclosure decision failed: %s", exc)
                mode = self.mode  # a switch to PII lands here
            try:
                if verbatim and material:
                    # quoted only now: a disclosure dialog may have just decided what can be shown
                    answer, left_out = self.quote_lines(material, await work, source, max_output_chars,
                                                        override or self.policy())
                    usage = None
                    if not answer:
                        # A locate pass that matches nothing almost always means the task was a
                        # question, not a reproduction. Answer it rather than return nothing.
                        fallback, verbatim = True, False
                        answer, usage = await self.llm.digest(
                            system, self.inbound(task), material, source,
                            max_output_chars=max_output_chars,
                            render_user=prompts.render_user, render_reduce=prompts.render_reduce)
                else:
                    answer, usage = await work
                if not verbatim and prompts.needs_finalize(answer):
                    final, u2 = await self.llm.chat(
                        system, prompts.render_finalize(self.inbound(task), answer, max_output_chars),
                        max_tokens=self.llm.tokens_for(max_output_chars), temperature=0.1)
                    usage.add(u2)
                    answer, finalized = final, True
            except LLMError as exc:
                error = str(exc)
            policy = override or self.policy()
            secs = round(time.monotonic() - t0, 2)
            ref = self.session.store_artifact(material, {"kind": kind, "source": source[:300], "chars": len(material),
                                                         "ts": datetime.now().astimezone().isoformat(timespec="seconds"),
                                                         **{k: v for k, v in extra.items() if k in ("rc", "timed_out", "truncated")}}) if material else ""
            scrubbed = self.outbound(answer, policy) if answer else ScrubResult("", 0, {})
            # The answer pass runs whenever identity is MASKED by the effective policy — PII mode, and ASSIST
            # until the user opens identity — so an unlabelled bare name the worker echoes cannot slip past the
            # shape layers. None = not applicable (identity open), True = ran, False = could not run.
            leak_checked = None
            if scrubbed.text and not (policy.open & set(TIERS["identity"])):
                found, leak_checked = await self.answer_pass(scrubbed.text)
                if found:
                    scrubbed = self.outbound(scrubbed.text, policy)
            # What the worker SAW is part of its memory too, not only what it said —
            # bounded, and scrubbed like everything else that is written down.
            excerpt = self.outbound(material, policy).text[:self.cfg.excerpt_chars] if material else ""  # scrub, then cut
            turn = {
                "kind": kind, "mode": mode, "task": task[:2000], "source": source[:300], "excerpt": excerpt,
                "verbatim": verbatim,
                "result": scrubbed.text[:6000] if not error else f"ERROR: {error[:500]}",
                "ref": ref, "raw_chars": len(material), "out_chars": len(scrubbed.text), "secs": secs,
                "model": self.llm.last_model, "error": bool(error),
                **({"disclosure": decision} if decision else {}), **({"verbatim_fallback": True} if fallback else {}), **extra,
            }
            tid = self.session.append_turn(turn)
            turn["id"] = tid  # append_turn writes a copy; the ledger row must carry the same id (backfill dedupes on it)
            est = sv.estimate_turn(turn, self.prices.assumptions)
            saved = est["avoided_input"] + est["avoided_output"]
            self._measure(turn, gathered_text, scrubbed.text)
            self.observer.event("execute_tool", f"local_llm.{kind}", {
                "mode": mode, "turn": tid, "ref": ref, "raw_chars": len(material), "out_chars": len(scrubbed.text),
                "secs": secs, "model": self.llm.last_model, "rc": extra.get("rc"), "error": bool(error),
                "scrubbed": scrubbed.replaced, "chunks": getattr(usage, "chunks", 1) if usage else 0,
                "finalized": finalized, "entities": entities, "verbatim": verbatim, "verbatim_fallback": fallback,
                "session": self.session.key,
                "saved_tokens": saved, "gathered_chars": int(extra.get("gathered_chars") or 0),
                "disclosure": decision or None,
            })
            if error:
                trailer = self._trailer([mode, f"turn {tid}", f"ref {ref}" if ref else "", f"{secs}s"])
                return f"Error: {self.outbound(error).text}{trailer}"  # a worker's error body may echo input
            trailer = self._trailer([
                mode, f"turn {tid}", f"ref {ref}" if ref else "",
                f"rc {extra['rc']}" if "rc" in extra else "",
                f"policy: {extra['policy']}" if extra.get("policy") else "",
                f"raw {len(material)} chars" + (" (truncated)" if extra.get("truncated") else "") if material else "no material",
                f"{usage.chunks} chunks" if usage and usage.chunks > 1 else "",
                "finalized" if finalized else "",
                ("verbatim" + (f" · not shown: lines {', '.join(f'{a}-{b}' for a, b in left_out)} (fetch with local_llm_artifact line_start/line_end)" if left_out else "")) if verbatim else "",
                "verbatim: no lines matched, digested instead" if fallback else "",
                self.llm.last_model, f"{secs}s", f"saved ≈ {sv.fmt_tokens(saved)} tok" if saved else "",
                f"disclosure: {decision}" if decision else "",
                "" if leak_checked is None else ("leak-check ok" if leak_checked else "leak-check FAILED (deterministic layers only)"),
                scrubbed.trailer(),
            ])
            result = scrubbed.text + (("\n\n" + notice) if notice else "") + trailer
        self.maybe_autocompact()
        return result

    async def answer_pass(self, answer: str) -> tuple[int, bool]:
        """The last line wherever identity is masked: ask the worker what private values this OUTBOUND text
        (a result, a compaction summary, an artifact slice) still holds — it is short, so this covers it
        whole, unlike the material pass, bounded to two chunks — register them, and let the caller
        re-scrub. Returns (values registered, pass ran). Every run and every failure is counted on the
        session, so a weakened guarantee is visible in status and the admin app."""
        try:
            text, _u = await self.llm.chat(prompts.ENTITY_SYSTEM, prompts.ENTITY_USER.format(material=answer),
                                           max_tokens=1024, temperature=0.0)
            found = prompts.parse_entities(text)
            n = self.scrubber.register_entities(found, answer, self.session.vault)
            self.session.note_leak_check(True)
            return n, True
        except Exception as exc:
            log.warning("answer leak-check failed: %s", exc)
            self.session.note_leak_check(False, str(exc)[:160])
            return 0, False

    def identity_masked(self) -> bool:
        """True while the effective policy masks identity (PII mode; ASSIST until the user opens it)."""
        return not (self.policy().open & set(TIERS["identity"]))

    async def outbound_slice(self, piece: str) -> tuple[ScrubResult, str]:
        """An artifact slice leaves through the same layers as a result: the scrub, then — while identity
        is masked — the answer pass over the slice itself, so a bare name deep in a large file that no
        answer ever mentioned cannot leave through this channel. Returns (scrubbed, trailer note)."""
        scrubbed = self.outbound(piece)
        note = ""
        if scrubbed.text and self.identity_masked():
            found, ran = await self.answer_pass(scrubbed.text)
            if found:
                scrubbed = self.outbound(scrubbed.text)
            note = "leak-check ok" if ran else "leak-check FAILED (deterministic layers only)"
        # The piece was cut from scrubbed text, so what it masks is counted from its placeholders.
        kinds: dict[str, int] = {}
        for m in PLACEHOLDER_RE.finditer(scrubbed.text):
            kinds[m.group("kind")] = kinds.get(m.group("kind"), 0) + 1
        return ScrubResult(scrubbed.text, sum(kinds.values()), kinds), note

    async def artifact_slice(self, ref: str, offset: int, limit: int, line_start: int, line_end: int) -> str:
        """An exact slice of stored material, cut AFTER the whole of it is scrubbed: a slice that starts
        inside a secret holds only a fragment, and no scrub can recognise a fragment afterwards. Lines
        keep their numbers; character offsets count the scrubbed text."""
        raw = self.session.read_artifact(ref)
        if raw is None:
            return f"Error: no artifact {ref} in this session (refs are per conversation; see local_llm_status)."
        clean = self.outbound(raw, keep_lines=True).text
        if line_start > 0:
            lines = clean.split("\n")
            end = min(len(lines), line_end or line_start + 199)
            piece = vb.number_lines(lines[line_start - 1:end], line_start) if line_start <= len(lines) else ""
            scrubbed, leak = await self.outbound_slice(piece)
            return scrubbed.text + self._trailer([f"artifact {ref}", f"lines {line_start}-{end} of {len(lines)}",
                                                  f"next line {end + 1}" if end < len(lines) else "end", leak, scrubbed.trailer()])
        scrubbed, leak = await self.outbound_slice(clean[offset:offset + limit])
        return scrubbed.text + self._trailer([f"artifact {ref}", f"chars {offset}-{min(offset + limit, len(clean))} of {len(clean)}",
                                              f"next offset {offset + limit}" if offset + limit < len(clean) else "end",
                                              leak, scrubbed.trailer()])

    async def entity_pass(self, material: str) -> int:
        """Ask the worker what private values the material holds; register them.
        Bounded to the first two chunks; failures cost nothing (the shape rules,
        the private terms and the worker's own placeholder discipline still apply)."""
        try:
            sample, _ = cap(material, self.cfg.chunk_chars * 2)
            text, _u = await self.llm.chat(prompts.ENTITY_SYSTEM, prompts.ENTITY_USER.format(material=sample),
                                           max_tokens=2048, temperature=0.0)
            found = prompts.parse_entities(text)
            return self.scrubber.register_entities(found, material, self.session.vault)
        except Exception as exc:
            log.warning("entity pass failed: %s", exc)
            return 0

    # ---- compaction ------------------------------------------------------------

    def schedule_compaction(self, reason: str) -> asyncio.Task:
        if self.compacting and not self.compacting.done():
            return self.compacting
        self.compacting = asyncio.get_running_loop().create_task(self.compact(reason))
        return self.compacting

    def maybe_autocompact(self) -> None:
        try:
            if self.session.uncompacted_chars() > self.cfg.auto_compact_chars:
                self.schedule_compaction("auto: running context grew past the threshold")
        except Exception as exc:  # never let bookkeeping break a result
            log.warning("autocompact check failed: %s", exc)

    async def compact(self, reason: str) -> dict:
        t0 = time.monotonic()
        mode = self.mode
        async with self.lock:
            turns = [t for t in self.session.turns_since_compaction() if t.get("kind") != "compaction"]
            previous = self.session.summary()
            if not turns:
                return {"ok": True, "skipped": "no new turns since the last compaction", "summary_chars": len(previous)}
            turns_text = "\n".join(Session.render_turn(t, task_chars=1500, result_chars=3500,
                                                        excerpt_chars=self.cfg.excerpt_chars) for t in turns)
            turns_text, _ = cap(turns_text, self.cfg.chunk_chars * 2)
            system, user = prompts.compaction_prompts(mode, self.inbound(previous), self.inbound(turns_text),
                                                      self.cfg.summary_chars)
            try:
                summary, usage = await self.llm.chat(system, user, max_tokens=self.llm.tokens_for(self.cfg.summary_chars),
                                                     temperature=0.1)
            except LLMError as exc:
                self.observer.event("session", "compaction_failed", {"error": str(exc)[:200], "session": self.session.key})
                return {"ok": False, "error": str(exc)}
            scrubbed = self.outbound(summary)
            if scrubbed.text and not (self.policy().open & set(TIERS["identity"])):
                # the summary is the worker's prose: while identity is masked, ask it what private values the
                # summary still names and mask those too — the same answer pass every result gets
                found, _ran = await self.answer_pass(scrubbed.text)
                if found:
                    scrubbed = self.outbound(scrubbed.text)
            self.session.write_summary(scrubbed.text)
            secs = round(time.monotonic() - t0, 2)
            self.session.meta["compactions"] = int(self.session.meta.get("compactions", 0)) + 1
            self.session.meta["last_compaction"] = datetime.now().astimezone().isoformat(timespec="seconds")
            self.session.append_turn({"kind": "compaction", "task": reason, "mode": mode,
                                      "result": f"compacted {len(turns)} turns into {len(scrubbed.text)} chars",
                                      "secs": secs, "model": self.llm.last_model})
            self.observer.event("session", "compaction", {
                "reason": reason[:120], "turns": len(turns), "summary_chars": len(scrubbed.text), "secs": secs,
                "scrubbed": scrubbed.replaced, "session": self.session.key})
            log.info("compacted %d turns -> %d chars in %.1fs (%s)", len(turns), len(scrubbed.text), secs, reason)
            return {"ok": True, "turns": len(turns), "summary_chars": len(scrubbed.text), "secs": secs,
                    "compactions": self.session.meta["compactions"], "scrubbed": scrubbed.replaced}

    # ---- control socket --------------------------------------------------------

    async def ctl_compact(self, req: dict) -> dict:
        sid = str(req.get("session_id") or "")
        if sid:
            self.session.adopt_session_id(sid, source="hook")
        trigger = str(req.get("trigger") or "unknown")
        self.schedule_compaction(f"caller compaction ({trigger})")
        return {"ok": True, "queued": True, "session": self.session.key}

    async def ctl_session(self, req: dict) -> dict:
        sid = str(req.get("session_id") or "")
        changed = self.session.adopt_session_id(sid, source=str(req.get("source") or "hook"))
        return {"ok": True, "session": self.session.key, "changed": changed, "mode": self.mode}

    async def ctl_status(self, req: dict) -> dict:
        return {"ok": True, **self.session.status()}

    async def start_control(self) -> None:
        self.control_path = socket_path(self.cfg.sock_dir, self.session.claude_pid)
        try:
            self.control_server = await start_control(self.control_path, {
                "compact": self.ctl_compact, "session": self.ctl_session, "status": self.ctl_status})
        except Exception as exc:
            log.warning("control socket unavailable (%s); hook-driven compaction disabled", exc)

    async def stop_control(self) -> None:
        if self.control_server:
            self.control_server.close()
            try:
                await self.control_server.wait_closed()
            except Exception:
                pass
        if self.control_path and self.control_path.exists():
            try:
                self.control_path.unlink()
            except OSError:
                pass


def _short_path(p: str, keep: int = 96) -> str:
    """Show a path whole when it fits, else its tail (the name is what the caller needs)."""
    return p if len(p) <= keep else "…/" + "/".join(p.rstrip("/").split("/")[-2:])


APP: App | None = None


def _app() -> App:
    assert APP is not None, "server not built"
    try:
        if APP.session.refresh_identity():
            APP.observer.event("session", "id_change", {"session": APP.session.key,
                                                          "claude_session_id": APP.session.claude_session_id})
    except Exception as exc:  # identity is bookkeeping; never fail a tool call on it
        log.warning("identity refresh failed: %s", exc)
    return APP


def build(cfg: Config) -> FastMCP:
    global APP
    APP = App(cfg)
    app = APP

    @asynccontextmanager
    async def lifespan(_server: FastMCP) -> AsyncIterator[dict]:
        app.lock = asyncio.Lock()
        await app.start_control()
        try:
            await app.observer.start({"session": app.session.key, "claude_session_id": app.session.claude_session_id,
                                      "mode": app.mode, "model": cfg.model, "endpoint": cfg.base_url})
        except Exception as exc:
            log.debug("observer start failed: %s", exc)
        try:
            yield {}
        finally:
            app.observer.event("session", "end", {"session": app.session.key,
                                                    "turns": app.session.meta.get("turns", 0)})
            try:
                await app.flush_measurements()
            except Exception as exc:
                log.warning("measurement flush failed: %s", exc)
            await app.stop_control()
            try:
                await app.observer.end("done")
            except Exception:
                pass
            await app.llm.aclose()

    mcp = FastMCP(
        "local_llm_mcp",
        instructions=prompts.gate_instructions(app.mode, cfg.model),
        lifespan=lifespan,
        log_level=cfg.log_level if cfg.log_level in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL") else "INFO",
    )

    def _budget(v: int) -> int:
        return v if v > 0 else cfg.max_output_chars

    @mcp.tool(
        name="local_llm_run",
        title="Run a command here and receive a digest of its output",
        description=(
            "Execute a shell command on this host (bash -c, this user's privileges, stdin closed) and have the local "
            "worker model digest the output for you. You receive the digest plus a trailer (turn id, artifact ref, "
            "exit code, raw size); the raw output is stored as an artifact you can slice with local_llm_artifact. "
            "Use this instead of your own shell tool whenever the command would print more than you need to read "
            "(logs, tests, builds, listings, git output, grep results); rule of thumb: anything over ~40 lines / 2 KB "
            "of output belongs here, while commands that print little or nothing run directly. Placeholders in the "
            "command are expanded server-side before execution and never appear in the result — except a secret, "
            "which is never handed to a shell. The server holds its own command policy: destructive shapes are "
            "refused outright, and anything outside the user's allow list is put to the user in a dialog, so a "
            "refusal here is the user's or the server's answer and not something to work around."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False),
    )
    async def local_llm_run(
        command: Annotated[str, Field(min_length=1, description="The shell command to run, e.g. 'journalctl -u nginx --since -1h' or 'pytest -q'.")],
        task: Annotated[str, Field(description="What to report from the output. Default: outcome, every error/warning verbatim, key values.")] = "",
        cwd: Annotated[str, Field(description="Working directory for the command. Default: the server's own cwd.")] = "",
        timeout_s: Annotated[int, Field(ge=0, le=3600, description="Kill the command after this many seconds (0 = server default).")] = 0,
        max_output_chars: Annotated[int, Field(ge=0, le=20000, description="Soft budget for the digest (0 = server default).")] = 0,
        verbatim: Annotated[bool, Field(description="Copy the matching output lines byte for byte instead of digesting (the worker only locates them). Only for text you must reproduce or edit (a function, a config block, an error with its stack). NOT for questions, counts, summaries or listings: those need the digest, which is the default.")] = False,
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_run")
        if not on:
            return note
        may, refusal, plabel = await a.approve_command(ctx, command, cwd)
        if not may:
            return (note + "\n\n" + refusal) if note else refusal
        try:
            res = await run_command(a.inbound(command), cwd=cwd or None,
                                    timeout=float(timeout_s or cfg.command_timeout), max_chars=cfg.material_max_chars)
        except ShellNotFound as exc:
            msg = f"[local-llm-mcp] {exc}"
            return (note + "\n\n" + msg) if note else msg
        task_text = task.strip() or prompts.DEFAULT_RUN_TASK
        if res.timed_out:
            task_text += f" NOTE: the command was killed after {timeout_s or int(cfg.command_timeout)}s; say so."
        if res.rc not in (0, None):
            task_text += f" NOTE: exit code {res.rc}."
        material = res.output
        if not material.strip():
            material = f"(no output; exit code {res.rc}{', timed out' if res.timed_out else ''})"
        result = await a.delegate(kind="run", task=task_text, material=material, source=f"command: {command[:200]}",
                                  max_output_chars=_budget(max_output_chars), verbatim=verbatim,
                                  extra={"rc": res.rc, "timed_out": res.timed_out, "truncated": res.truncated,
                                         "cmd_secs": res.secs, "gathered_chars": len(res.output),
                                         "policy": plabel}, ctx=ctx)
        return (note + "\n\n" + result) if note else result

    @mcp.tool(
        name="local_llm_delegate",
        title="Delegate a task with inline material and/or files",
        description=(
            "Hand a task to the local worker model over material you name: inline text (material), files or "
            "directories to read (paths; directories are listed), and/or the output of a shell command (command). "
            "Use for reading or summarizing files and documents, research and synthesis over provided text, "
            "calculations, format transformations, parsing, boilerplate drafting, and — in PII mode — anything that "
            "touches private data (names, addresses, credentials, personal mail; the worker reads it, you receive "
            "placeholders such as [PERSON-1] that you can reuse in later calls). Set verbatim=true ONLY when you will "
            "reproduce or edit the text itself (code, config, an error with its stack): the worker locates the lines and "
            "the server quotes them. Leave it false for anything to be answered, counted, summarised or listed. The worker "
            "also carries its own running memory of this conversation, so follow-up tasks can refer to earlier results "
            "by turn id (t_xxxxxx) or artifact ref (a_xxxxxxxx)."),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False),
    )
    async def local_llm_delegate(
        task: Annotated[str, Field(min_length=1, description="What to do, precisely: what to extract, what to report, thresholds, output shape.")],
        material: Annotated[str, Field(description="Inline text to work on (pasted output, a document, data). Optional.")] = "",
        paths: Annotated[list[str], Field(description="Files or directories to read as material (~ expands). Optional.")] = [],
        command: Annotated[str, Field(description="Shell command whose output is added to the material (bash -c; placeholders expanded server-side, secrets never). Subject to the same command policy as local_llm_run. Optional.")] = "",
        cwd: Annotated[str, Field(description="Base directory for relative paths and the command.")] = "",
        max_output_chars: Annotated[int, Field(ge=0, le=20000, description="Soft budget for the answer (0 = server default).")] = 0,
        verbatim: Annotated[bool, Field(description="Copy the matching lines byte for byte instead of answering (the worker only locates them). Only for text you must reproduce or edit (a function, a config block, an error with its stack). NOT for questions, counts, summaries or listings: those need the digest, which is the default.")] = False,
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_delegate")
        if not on:
            return note
        if command:
            # The same shell, so the same policy: a command reaching the worker through
            # delegate is not a way around the check local_llm_run makes.
            may, refusal, plabel = await a.approve_command(ctx, command, cwd)
            if not may:
                return (note + "\n\n" + refusal) if note else refusal
        pieces: list[str] = []
        sources: list[str] = []
        extra: dict = {}
        gathered = 0  # chars the caller did NOT already hold (command output, files)
        gathered_parts: list[str] = []
        if material:
            pieces.append(material)
            sources.append(f"inline ({len(material)} chars)")
        if command:
            try:
                res = await run_command(a.inbound(command), cwd=cwd or None, timeout=cfg.command_timeout,
                                        max_chars=cfg.material_max_chars)
            except ShellNotFound as exc:
                msg = f"[local-llm-mcp] {exc}"
                return (note + "\n\n" + msg) if note else msg
            pieces.append(f"### COMMAND: {command}\n### exit code: {res.rc}{' (timed out)' if res.timed_out else ''}\n"
                          + (res.output or "(no output)"))
            sources.append(f"command: {command[:120]}")
            gathered += len(res.output or "")
            gathered_parts.append(res.output or "")
            extra.update({"rc": res.rc, "timed_out": res.timed_out, "cmd_secs": res.secs, "policy": plabel})
        if paths:
            expanded = [a.inbound(p) for p in paths]
            single = Path(os.path.expanduser(expanded[0])) if len(expanded) == 1 else None
            if single is not None and not single.is_absolute() and cwd:
                single = Path(cwd) / single
            if verbatim and not pieces and single is not None and single.is_file():
                # One file, verbatim: quote it by ITS OWN line numbers — no header, no
                # concatenation — so a quoted range is a range the caller can edit.
                raw = single.read_bytes().decode("utf-8", "replace")
                text, truncated_file = cap(raw, cfg.material_max_chars)
                pieces.append(text)
                gathered += len(text)
                gathered_parts.append(text)
                sources.append(_short_path(str(single)))
                if truncated_file:
                    extra["truncated"] = True
            else:
                text, meta = read_paths(expanded, max_chars=cfg.material_max_chars, cwd=cwd or None)
                pieces.append(text)
                gathered += len(text)
                gathered_parts.append(text)
                sources.append("paths: " + ", ".join(_short_path(p) for p in expanded[:8]) + (" …" if len(expanded) > 8 else ""))
        joined = "\n\n".join(pieces)
        joined, truncated = cap(joined, cfg.material_max_chars)
        if truncated:
            extra["truncated"] = True
        extra["gathered_chars"] = gathered
        extra["_gathered_text"] = "\n\n".join(gathered_parts)
        result = await a.delegate(kind="delegate", task=task, material=joined, source="; ".join(sources) or "none",
                                  max_output_chars=_budget(max_output_chars), extra=extra, verbatim=verbatim, ctx=ctx)
        return (note + "\n\n" + result) if note else result

    @mcp.tool(
        name="local_llm_artifact",
        title="Read a slice of a stored raw output",
        description=(
            "Return an exact slice of the raw material behind an earlier result, by its artifact ref (a_xxxxxxxx from a "
            "trailer): by line (line_start/line_end, numbered) or by character (offset/limit). Use when the digest left "
            "out something you need exactly. In PII mode the slice is scrubbed (placeholders); in ASSIST mode only "
            "secrets are scrubbed. Line numbers are those of the raw material; character offsets count the scrubbed text."),
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_artifact(
        ref: Annotated[str, Field(pattern=r"^a_[0-9a-f]{8}$", description="Artifact ref from a result trailer, e.g. a_1f2e3d4c.")],
        offset: Annotated[int, Field(ge=0, description="Character offset to start from (character mode).")] = 0,
        limit: Annotated[int, Field(ge=100, le=20000, description="Maximum characters to return (character mode).")] = 4000,
        line_start: Annotated[int, Field(ge=0, description="First line to return, 1-based (line mode; 0 = character mode).")] = 0,
        line_end: Annotated[int, Field(ge=0, description="Last line to return, inclusive (0 = line_start + 199).")] = 0,
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_artifact")
        if not on:
            return note
        return await a.artifact_slice(ref, offset, limit, line_start, line_end)

    @mcp.tool(
        name="local_llm_status",
        title="Show the worker's session state",
        description="Mode, session identity, worker (primary/fallback, which is active), turns since compaction, context size, compaction count, placeholder counts, artifact count, and the tokens-saved estimate for this session and all sessions.",
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_status(ctx: Context = None) -> str:
        a = _app()
        a.note_client(ctx)
        st = a.session.status()
        st["decide"] = {"enabled": True, **a.decider.status()} if a.decider else {"enabled": False}
        st["client"] = a.session.meta.get("client") or None
        a.session.reload_meta_if_changed()
        armed_rec = a.session.meta.get("armed") if isinstance(a.session.meta.get("armed"), dict) else {}
        st["armed"] = {**armed_rec, "state": ("on" if cfg.arm == "on" else armed_rec.get("state") or "off"),
                       "policy": cfg.arm, "client_can_ask": App.client_can_ask(ctx),
                       "note": ("standing approval LOCAL_LLM_MCP_ARM=on" if cfg.arm == "on" else
                                {"on": "turned on for this session", "off": "off for this session"}.get(armed_rec.get("state"),
                                 "off — nothing runs until the user turns it on (dialog, LOCAL_LLM_MCP_ARM=on, or the admin app)"))}
        a.allow.load()
        st["run_policy"] = {**st.get("run_policy", {}), "policy": cfg.run_policy,
                            "allow_file": str(cfg.run_allow_path), "allow_entries": list(a.allow.entries),
                            "client_can_ask": App.client_can_ask(ctx),
                            "note": {"ask": "commands outside the allow list are put to the user in a dialog",
                                     "allow": "deny shapes only; nothing else is asked about",
                                     "off": "no command policy — every command runs"}[cfg.run_policy]}
        st["disclosure"] = {**a.session.disclosure.to_meta(), "escalation": cfg.escalation,
                            "open_kinds": sorted(a.policy().open), "client_can_ask": App.client_can_ask(ctx)}
        st["summary"] = a.outbound(a.session.summary()).text
        st["control_socket"] = str(a.control_path) if a.control_server else None
        st["observer"] = a.observer.name
        st["observer_run"] = a.observer.run_id or None
        st["compaction_in_progress"] = bool(a.compacting and not a.compacting.done())
        st["worker"] = a.llm.worker_status()
        st["tokens_saved"] = sv.report(a.session.keys(), a.ledger, a.prices, pending=len(a.pending))
        return json.dumps(st, indent=1)

    @mcp.tool(
        name="local_llm_compact",
        title="Compact the worker's running context now",
        description=(
            "Ask the worker to compress its running memory of this conversation into a fresh summary. Normally "
            "automatic (a PreCompact hook triggers it when your own context is compacted, and the server compacts on "
            "its own when its context grows large); call it only if you compacted manually and the hook is absent."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_compact(
        reason: Annotated[str, Field(description="Why (recorded in the context log).")] = "requested by caller",
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_compact")
        if not on:
            return note
        res = await a.compact(reason)
        return json.dumps(res, indent=1)

    @mcp.tool(
        name="local_llm_set_mode",
        title="Switch between PII and ASSIST mode",
        description=(
            "Switch the server's mode for the rest of this conversation and return the instructions that apply in the "
            "new mode. 'pii': delegate everything that may touch private data; results are fully sanitized. "
            "'assist': delegate anything context-free whose output would be larger than its digest; only secrets are scrubbed."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_set_mode(
        mode: Annotated[str, Field(pattern=r"^(pii|assist)$", description="'pii' or 'assist'.")],
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_set_mode")
        if not on:
            return note
        if mode not in MODES:
            return f"Error: mode must be one of {MODES}"
        previous = a.mode
        a.session.set_mode(mode)
        if mode == "pii" and previous != "pii":
            a.vault_memory()
        a.session.append_turn({"kind": "mode", "task": f"mode {previous} -> {mode}", "result": "", "mode": mode})
        a.observer.event("session", "mode_change", {"from": previous, "to": mode, "session": a.session.key})
        return f"Mode is now {mode} (was {previous}).\n\n" + prompts.client_instructions(mode, cfg.model, cfg.base_url)

    @mcp.prompt(name="local_llm_instructions",
                description="When and how to call this server (the same text as the connection instructions; for "
                            "clients that do not surface them).")
    def local_llm_instructions_prompt() -> str:
        a = _app()
        off = "" if a.session.armed_state() == "on" or cfg.arm == "on" else "(OFF for this session until the user turns it on: call local_llm_enable.)\n\n"
        return off + prompts.client_instructions(a.mode, cfg.model, cfg.base_url)

    @mcp.resource("local-llm://instructions", name="local_llm_instructions", mime_type="text/plain",
                  description="Current mode and the rules for calling this server.")
    def local_llm_instructions_resource() -> str:
        a = _app()
        off = "" if a.session.armed_state() == "on" or cfg.arm == "on" else "(OFF for this session until the user turns it on: call local_llm_enable.)\n\n"
        return off + prompts.client_instructions(a.mode, cfg.model, cfg.base_url)

    @mcp.tool(
        name="local_llm_enable",
        title="Offer to turn this server on for the session (the user decides)",
        description=(
            "Ask the user whether to turn local-llm-mcp on for this session. The server shows the user a dialog; nothing "
            "is delegated unless they say yes. Call it once when a step would print far more than you need or would "
            "touch private data. If the user declined, do not call it again unless they ask. Returns the operating "
            "rules when the user turns it on, or a refusal otherwise."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_enable(ctx: Context = None) -> str:
        a = _app()
        already = a.session.armed_state() == "on" or cfg.arm == "on"
        on, note = await a.ensure_armed(ctx, "local_llm_enable")
        if not on:
            return note
        if already or not note:
            return (f"[local-llm-mcp] Already on for this session (mode {a.mode.upper()}). Operating rules:\n"
                    + prompts.client_instructions(a.mode, cfg.model, cfg.base_url))
        return note

    @mcp.tool(
        name="local_llm_disclosure",
        title="Set what private values may be shown in ASSIST mode",
        description=(
            "Record the user's decision on what this ASSIST session may show in clear, when the user has said so in "
            "the conversation (otherwise the server asks the user itself the first time personal data appears). "
            "identity = names, addresses, emails, phones; numbers = account/card/id/SSN numbers and dates of birth "
            "(masked by default). Secrets are never shown in either mode. identity='ask' resets the question. "
            "Returns the resulting state."),
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False),
    )
    async def local_llm_disclosure(
        identity: Annotated[str, Field(pattern=r"^(open|masked|ask|keep)$", description="'open', 'masked', 'ask' (reset) or 'keep'.")] = "keep",
        numbers: Annotated[str, Field(pattern=r"^(open|masked|keep)$", description="'open', 'masked' or 'keep'.")] = "keep",
        reason: Annotated[str, Field(description="What the user said, in a few words. Recorded in the session log.")] = "",
        ctx: Context = None,
    ) -> str:
        a = _app()
        on, note = await a.ensure_armed(ctx, "local_llm_disclosure")
        if not on:
            return note
        d = a.session.disclosure
        before = d.to_meta()
        d.set(identity=("undecided" if identity == "ask" else identity) if identity != "keep" else None,
              numbers=numbers if numbers != "keep" else None, source="tool")
        a.session.set_disclosure(d)
        if d.identity == "masked" and before.get("identity") == "open":
            a.vault_memory()
        a.session.append_turn({"kind": "disclosure", "mode": a.mode, "result": "",
                               "task": f"identity={d.identity} numbers={d.numbers}" + (f" — {reason[:200]}" if reason else "")})
        a.observer.event("session", "disclosure", {"decision": f"identity={d.identity},numbers={d.numbers}", "source": "tool",
                                                   "session": a.session.key})
        return json.dumps({"mode": a.mode, **d.to_meta(), "open_kinds": sorted(a.policy().open),
                           "note": "secrets are never shown; in PII mode everything is masked regardless"}, indent=1)

    if cfg.decide:
        from .decide_tools import register as register_decide_tools
        register_decide_tools(mcp, _app)
    return mcp
