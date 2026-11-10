"""Per-session running context: identity, turn log, summary, artifacts, vault.

Session identity
----------------
The server is spawned by the caller (Claude Code) as a child process and is
told nothing about which conversation it belongs to. Two things fix that:

* ``hooks/local-llm-mcp-hook.py`` runs on the caller's SessionStart and writes
  ``<state>/pidmap/<claude_pid>`` = the caller's session id. The server walks
  its own ancestry and adopts the first mapped pid it finds, so a resumed
  conversation (new process, same session id) lands on the same context.
* Until that mapping exists the key is ``pid-<claude_pid>`` and the directory
  is migrated the moment a session id is learned (pidmap or the control
  socket's ``session`` op).

Layout under ``<state>/sessions/<key>/`` (0700):
  meta.json · context.jsonl (turns) · summary.md (compacted memory) ·
  placeholders.json (vault, 0600) · artifacts/a_xxxx.txt (raw outputs, 0600)
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path

from .config import Config
from .disclosure import Disclosure
from .scrub import Vault

log = logging.getLogger("local_llm_mcp.session")

SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ksh"}
SELF_MARKERS = ("local-llm-mcp", "local_llm_mcp")


# --------------------------------------------------------------------------- process tree


def _proc(pid: int) -> tuple[int, str, str] | None:
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="replace") as fh:
            stat = fh.read()
        ppid = int(stat.rsplit(")", 1)[1].split()[1])
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as fh:
            comm = fh.read().strip()
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        return ppid, comm, cmd
    except Exception:
        return None


def ancestors(start: int | None = None, max_depth: int = 10) -> list[tuple[int, str, str]]:
    """[(pid, comm, cmdline), ...] from the parent of ``start`` upward, nearest first."""
    pid = start if start is not None else os.getppid()
    out: list[tuple[int, str, str]] = []
    for _ in range(max_depth):
        if pid <= 1:
            break
        info = _proc(pid)
        if info is None:
            break
        ppid, comm, cmd = info
        out.append((pid, comm, cmd))
        pid = ppid
    return out


def is_claude_process(comm: str, cmdline: str) -> bool:
    """True for the Claude Code binary itself — judged by the EXECUTABLE, never by
    any path in the arguments (a scratch dir called /tmp/claude-… must not match)."""
    argv0 = cmdline.split(" ", 1)[0] if cmdline else ""
    base = os.path.basename(argv0)
    if base == "claude" or base.startswith("claude-code"):
        return True
    if "/ccd-cli/" in argv0 or "/.claude/local/" in argv0:  # desktop app / local installer layouts
        return True
    if base.startswith("node") and "claude-code" in cmdline and "cli.js" in cmdline:
        return True
    return False


def spawning_client(start: int | None = None) -> tuple[int, bool]:
    """(pid of the client that spawned this server, is it Claude Code).

    The NEAREST real ancestor, skipping shells and our own wrappers — not the nearest Claude
    ancestor. The difference is load-bearing: another agent harness (Codex, kimi, opencode) may
    itself have been launched from inside a Claude Code session, and it is a different
    conversation with a different user-facing dialog. Keying it by the Claude process further up
    the tree would hand it that conversation's vault, memory AND its answer to the opt-in gate —
    one client's approval silently arming another. Measured 2026-09-10: a Codex run launched from
    a Claude Code session adopted that session's id.
    """
    for pid, comm, cmd in ancestors(start):
        if comm in SHELLS or any(m in cmd.lower() for m in SELF_MARKERS):
            continue
        return pid, is_claude_process(comm, cmd)
    return os.getppid(), False


def find_claude_pid(start: int | None = None) -> int:
    """The pid this session is keyed by: the spawning client, whatever it is."""
    return spawning_client(start)[0]


def read_pidmap(state_dir: Path, pid: int) -> dict | None:
    p = state_dir / "pidmap" / str(pid)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def write_pidmap(state_dir: Path, pid: int, session_id: str, **extra) -> None:
    d = state_dir / "pidmap"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    rec = {"session_id": session_id, "ts": time.time(), **extra}
    tmp = d / f".{pid}.tmp"
    tmp.write_text(json.dumps(rec), encoding="utf-8")
    os.replace(tmp, d / str(pid))


# --------------------------------------------------------------------------- session


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class Session:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.state_dir = cfg.state_dir
        (self.state_dir / "sessions").mkdir(parents=True, exist_ok=True, mode=0o700)
        self.claude_pid, self.under_claude = spawning_client()
        self.claude_session_id = ""
        if cfg.session_override:
            self.key = cfg.session_override
        else:
            self.key = f"pid-{self.claude_pid}"
            # The pidmap is Claude Code's own hook telling us which conversation this is. Only
            # consult it when Claude Code is the client that spawned us; another harness gets its
            # own pid-keyed session even though a Claude process sits further up its tree.
            if self.under_claude:
                for pid, _comm, _cmd in ancestors():
                    rec = read_pidmap(self.state_dir, pid)
                    if rec and rec.get("session_id"):
                        self.key = rec["session_id"]
                        self.claude_session_id = rec["session_id"]
                        break
        self.dir = self.state_dir / "sessions" / self.key
        self._open_dir()

    # ---- storage -----------------------------------------------------------

    def _open_dir(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.dir / "artifacts").mkdir(exist_ok=True, mode=0o700)
        self.meta_path = self.dir / "meta.json"
        self.context_path = self.dir / "context.jsonl"
        self.summary_path = self.dir / "summary.md"
        self.vault = Vault(self.dir / "placeholders.json")
        self.meta = self._load_meta()
        self.meta.update({
            "key": self.key,
            "claude_pid": self.claude_pid,
            "claude_session_id": self.claude_session_id or self.meta.get("claude_session_id", ""),
            "model": self.cfg.model,
            "last_seen": _now_iso(),
        })
        self.meta.setdefault("mode", self.cfg.mode)
        self.meta.setdefault("created", _now_iso())
        self.meta.setdefault("compactions", 0)
        self.meta.setdefault("turns", 0)
        self.meta.setdefault("last_compaction", None)
        self._save_meta()

    def _meta_stamp(self):
        try:
            st = self.meta_path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _load_meta(self) -> dict:
        self._meta_seen = self._meta_stamp()
        if self.meta_path.is_file():
            try:
                return json.loads(self.meta_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_meta(self) -> None:
        tmp = self.dir / ".meta.tmp"
        tmp.write_text(json.dumps(self.meta, indent=1), encoding="utf-8")
        os.replace(tmp, self.meta_path)
        self._meta_seen = self._meta_stamp()

    def reload_meta_if_changed(self) -> bool:
        """Pick up a change another process made to meta.json (the admin app arming a session)."""
        if self._meta_stamp() == getattr(self, "_meta_seen", None):
            return False
        self.meta = self._load_meta()
        return True

    # ---- the opt-in gate ------------------------------------------------------

    def armed_state(self) -> str | None:
        rec = self.meta.get("armed")
        return rec.get("state") if isinstance(rec, dict) else None

    def set_armed(self, state: str | None, source: str) -> None:
        rec = dict(self.meta.get("armed") or {}) if isinstance(self.meta.get("armed"), dict) else {}
        rec.update({"state": state, "source": source, "ts": _now_iso()})
        self.meta["armed"] = rec
        self._save_meta()

    def note_leak_check(self, ok: bool, error: str = "") -> None:
        """Count every answer pass (item: the guarantee's last line) and every failure, so status and the
        admin app can show when the deterministic layers were left on their own."""
        rec = dict(self.meta.get("leak_check") or {}) if isinstance(self.meta.get("leak_check"), dict) else {}
        rec["ran"] = int(rec.get("ran") or 0) + 1
        if not ok:
            rec["failed"] = int(rec.get("failed") or 0) + 1
            rec["last_failure"] = {"ts": _now_iso(), "error": error}
        self.meta["leak_check"] = rec
        self._save_meta()

    def leak_check(self) -> dict:
        rec = self.meta.get("leak_check") if isinstance(self.meta.get("leak_check"), dict) else {}
        return {"ran": int(rec.get("ran") or 0), "failed": int(rec.get("failed") or 0), "last_failure": rec.get("last_failure")}

    def note_run_policy(self, verdict: str, rule: str = "", command: str = "") -> None:
        """Count every command-policy decision, so status and the admin app show how much is
        running on the operator's standing approval and what has been refused. A refusal keeps
        the shape and the command (this vault is local and 0600); an approval keeps counts only."""
        rec = dict(self.meta.get("run_policy") or {}) if isinstance(self.meta.get("run_policy"), dict) else {}
        rec[verdict] = int(rec.get(verdict) or 0) + 1
        if verdict in ("denied", "refused", "unasked_refused"):
            rec["last_refusal"] = {"ts": _now_iso(), "rule": rule, "command": command[:300]}
        self.meta["run_policy"] = rec
        self._save_meta()

    def run_policy(self) -> dict:
        rec = self.meta.get("run_policy") if isinstance(self.meta.get("run_policy"), dict) else {}
        out = {k: int(rec.get(k) or 0) for k in ("allowed", "asked_once", "asked_always", "refused", "denied", "unasked",
                                                      "unasked_refused")}
        out["last_refusal"] = rec.get("last_refusal")
        return out

    def run_policy_asks(self) -> int:
        rec = self.meta.get("run_policy") if isinstance(self.meta.get("run_policy"), dict) else {}
        return sum(int(rec.get(k) or 0) for k in ("asked_once", "asked_always", "refused"))

    def bump_armed_asks(self) -> int:
        rec = dict(self.meta.get("armed") or {}) if isinstance(self.meta.get("armed"), dict) else {}
        rec["asked"] = int(rec.get("asked") or 0) + 1
        self.meta["armed"] = rec
        self._save_meta()
        return rec["asked"]

    @property
    def mode(self) -> str:
        return self.meta.get("mode", self.cfg.mode)

    def set_mode(self, mode: str) -> None:
        self.meta["mode"] = mode
        self._save_meta()

    @property
    def disclosure(self) -> Disclosure:
        """This session's disclosure state (a fresh object each time; write back with set_disclosure)."""
        return Disclosure.from_meta(self.meta, self.cfg.assist_numbers)

    def set_disclosure(self, d: Disclosure) -> None:
        self.meta["disclosure"] = d.to_meta()
        self._save_meta()

    def refresh_identity(self) -> bool:
        """Late pidmap lookup. The SessionStart hook can fire before this server has
        opened its socket (measured: it did, on the first real resume), so a
        pid-keyed session re-checks the map on every tool call until it is named."""
        if not self.key.startswith("pid-") or self.cfg.session_override or not self.under_claude:
            return False
        for pid, _comm, _cmd in ancestors():
            rec = read_pidmap(self.state_dir, pid)
            if rec and rec.get("session_id"):
                return self.adopt_session_id(rec["session_id"], source="pidmap-late")
        return False

    def adopt_session_id(self, session_id: str, **extra) -> bool:
        """Learn the caller's session id; migrate a pid-keyed dir onto it. Returns True if changed."""
        session_id = (session_id or "").strip()
        if not session_id or session_id == self.key:
            if session_id:
                self.claude_session_id = session_id
            return False
        if self.cfg.session_override:
            return False
        write_pidmap(self.state_dir, self.claude_pid, session_id, **extra)
        target = self.state_dir / "sessions" / session_id
        if self.key.startswith("pid-"):
            if target.exists():
                # An older process of the same conversation already owns a
                # directory: fold our few turns into it rather than lose them.
                if self.context_path.is_file():
                    with open(target / "context.jsonl", "a", encoding="utf-8") as dst, \
                            open(self.context_path, "r", encoding="utf-8") as src:
                        dst.write(src.read())
                shutil.rmtree(self.dir, ignore_errors=True)
            else:
                shutil.move(str(self.dir), str(target))
        old_key = self.key
        self.key = session_id
        self.claude_session_id = session_id
        self.dir = target
        self._open_dir()
        prev = [k for k in self.meta.get("previous_keys", []) if k != session_id]
        if old_key not in prev:
            prev.append(old_key)
        self.meta["previous_keys"] = prev  # the savings ledger is keyed by session; keep the old rows attributable
        self._save_meta()
        log.info("session adopted id %s", session_id)
        return True

    def keys(self) -> list[str]:
        """This session's key plus every key it was known by before (ledger attribution)."""
        return [self.key] + [k for k in self.meta.get("previous_keys", []) if k != self.key]

    # ---- turns -------------------------------------------------------------

    def append_turn(self, rec: dict) -> str:
        rec = dict(rec)
        rec.setdefault("id", "t_" + uuid.uuid4().hex[:6])
        rec.setdefault("ts", _now_iso())
        with open(self.context_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if rec.get("kind") != "compaction":
            self.meta["turns"] = int(self.meta.get("turns", 0)) + 1
        self.meta["last_seen"] = rec["ts"]
        self._save_meta()
        return rec["id"]

    def _all_turns(self) -> list[dict]:
        if not self.context_path.is_file():
            return []
        out = []
        with open(self.context_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    def turns(self) -> list[dict]:
        return self._all_turns()

    def turns_since_compaction(self) -> list[dict]:
        turns = self._all_turns()
        last = -1
        for i, t in enumerate(turns):
            if t.get("kind") == "compaction":
                last = i
        return turns[last + 1:]

    def uncompacted_chars(self) -> int:
        return sum(len(json.dumps(t, ensure_ascii=False)) for t in self.turns_since_compaction())

    def summary(self) -> str:
        if self.summary_path.is_file():
            return self.summary_path.read_text(encoding="utf-8")
        return ""

    def write_summary(self, text: str) -> None:
        tmp = self.dir / ".summary.tmp"
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.summary_path)

    @staticmethod
    def render_turn(t: dict, task_chars: int = 240, result_chars: int = 480, excerpt_chars: int = 400) -> str:
        ts = (t.get("ts") or "")[11:16]
        task = (t.get("task") or "").replace("\n", " ")
        res = (t.get("result") or "").replace("\n", " ")
        exc = (t.get("excerpt") or "").replace("\n", " ")
        src = t.get("source") or ""
        head = f"[{t.get('id','?')} {ts}] {t.get('kind','?')}"
        if src:
            head += f" ({src[:120]})"
        if len(task) > task_chars:
            task = task[:task_chars] + "…"
        if len(res) > result_chars:
            res = res[:result_chars] + "…"
        if len(exc) > excerpt_chars:
            exc = exc[:excerpt_chars] + "…"
        out = f"{head}\n  TASK: {task}"
        if exc:
            out += f"\n  MATERIAL (excerpt): {exc}"
        return out + f"\n  RESULT: {res}"

    def context_block(self, budget_chars: int) -> str:
        """Summary + as many recent turns as fit, oldest dropped first."""
        summary = self.summary().strip()
        parts_recent: list[str] = []
        used = len(summary)
        for t in reversed(self.turns_since_compaction()):
            if t.get("kind") == "compaction":
                continue
            r = self.render_turn(t)
            if used + len(r) > budget_chars and parts_recent:
                break
            parts_recent.append(r)
            used += len(r)
        parts_recent.reverse()
        block = "SESSION MEMORY (compacted summary of earlier turns):\n" + (summary or "(none yet)")
        block += "\n\nRECENT TURNS (oldest first):\n" + ("\n".join(parts_recent) if parts_recent else "(none)")
        return block

    # ---- artifacts ---------------------------------------------------------

    def store_artifact(self, text: str, meta: dict | None = None) -> str:
        ref = "a_" + uuid.uuid4().hex[:8]
        p = self.dir / "artifacts" / f"{ref}.txt"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if meta:
            (self.dir / "artifacts" / f"{ref}.json").write_text(json.dumps(meta), encoding="utf-8")
        return ref

    def read_artifact(self, ref: str) -> str | None:
        if not ref or not ref.startswith("a_") or not ref[2:].isalnum():
            return None
        p = self.dir / "artifacts" / f"{ref}.txt"
        if not p.is_file():
            return None
        return p.read_text(encoding="utf-8", errors="replace")

    def artifact_count(self) -> int:
        return len(list((self.dir / "artifacts").glob("a_*.txt")))

    # ---- status ------------------------------------------------------------

    def status(self) -> dict:
        since = self.turns_since_compaction()
        return {
            "mode": self.mode,
            "session_key": self.key,
            "claude_session_id": self.claude_session_id or self.meta.get("claude_session_id", ""),
            "claude_pid": self.claude_pid,
            "model": self.cfg.model,
            "endpoint": self.cfg.base_url,
            "turns_total": int(self.meta.get("turns", 0)),
            "turns_since_compaction": len([t for t in since if t.get("kind") != "compaction"]),
            "uncompacted_chars": self.uncompacted_chars(),
            "summary_chars": len(self.summary()),
            "compactions": int(self.meta.get("compactions", 0)),
            "last_compaction": self.meta.get("last_compaction"),
            "leak_check": self.leak_check(),
            "run_policy": self.run_policy(),
            "placeholders": self.vault.counts(),
            "artifacts": self.artifact_count(),
            "created": self.meta.get("created"),
            "state_dir": str(self.dir),
        }
