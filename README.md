# local-llm-mcp

[![tests](https://github.com/lealvona/local-llm-mcp/actions/workflows/tests.yml/badge.svg)](https://github.com/lealvona/local-llm-mcp/actions/workflows/tests.yml)

**A local worker model for your cloud model.** `local-llm-mcp` is an
[MCP](https://modelcontextprotocol.io) server that sits between a calling model
(Claude Code, or any MCP client) and an LLM running on your own network. The caller
hands work over; the local model does it; the caller gets back a result that is either
**sanitized** (private values replaced by stable placeholders) or **digested** (long
raw output reduced to what the caller needs). The local model keeps its **own running
memory** of the conversation and compacts it whenever the caller compacts its own.

It exists for two reasons:

1. **Privacy.** Some material must never reach a cloud model: credentials, keys,
   personal mail, contacts, addresses, account numbers, the contents of `.env` files.
   In **PII mode** the caller is told to delegate every such step; the worker reads the
   real data and the caller only ever sees `[EMAIL-1]`, `[PERSON-2]`, `[SECRET-3]`.
2. **Context economy.** A cloud model's context is expensive and finite. Most of what
   a shell command prints is noise to the caller. In **ASSIST mode** the caller is told
   to route any context-free step whose raw output would exceed the digest it needs:
   logs, test runs, listings, `git` output, `grep` results, file reads, calculations.

The server is deployment-agnostic: endpoint, key, detection rules, private terms and
attribution are all configuration. Nothing about any particular network lives in the
package.

---

## Contents

- [How it works](#how-it-works)
- [Turning it on — nothing happens without the user's say-so](#turning-it-on--nothing-happens-without-the-users-say-so)
- [The command policy — what may actually run](#the-command-policy--what-may-actually-run)
- [The two modes and when the caller calls](#the-two-modes-and-when-the-caller-calls)
- [Tools](#tools)
- [The privacy boundary](#the-privacy-boundary)
- [Session memory and compaction](#session-memory-and-compaction)
- [Tokens saved](#tokens-saved)
- [Install and wire into Claude Code](#install-and-wire-into-claude-code)
- [Using it from other MCP clients](#using-it-from-other-mcp-clients)
- [Configuration reference](#configuration-reference)
- [Rules file](#rules-file)
- [Private terms](#private-terms)
- [Observers](#observers)
- [Admin app](#admin-app)
- [Keeping a deployment separate from the code](#keeping-a-deployment-separate-from-the-code)
- [State on disk](#state-on-disk)
- [Testing and verification](#testing-and-verification)
- [Threat model and limits](#threat-model-and-limits)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [License](#license)

---

## How it works

```
 caller (Claude Code)                        local-llm-mcp (stdio child)                   local model
 ────────────────────                        ───────────────────────────                   ───────────
 tool call ──────────────────────────────►  1. rehydrate placeholders in task/command
                                             2. gather material (run command / read files)
                                             3. register detectable values in the vault
                                             4. PII mode: entity pass ─────────────────────► "which private
                                                register what the worker found                values are here?"
                                             5. build prompt: rules + session memory +
                                                task + material ───────────────────────────► answer
                                             6. draft revises itself? one finalize call ───► committed answer
                                             7. SCRUB the answer (rules · secret shapes ·
                                                identity shapes · private terms · every vault value)
                                             8. store artifact (raw) + turn (scrubbed)
 digest + trailer ◄──────────────────────── 9. return
                                             ...
 PreCompact hook ── unix socket ──────────►  compact own memory (background) ─────────────► new summary
```

Every value that goes **to** the worker or the shell is rehydrated; every value that
**leaves** the server is scrubbed. That asymmetry is the whole design.

There is a second path beside the digest: **verbatim mode**. A digest paraphrases, and a
caller that needs code or configuration text cannot act on a paraphrase. With
`verbatim=true` the worker is shown numbered lines and asked only *which line ranges* the
task refers to; the server then copies those lines out of the material exactly (still
scrubbed on the way out). The model's judgement chooses the region; it never rewrites a
character of it.

## Turning it on — nothing happens without the user's say-so

The server never starts intercepting on its own. At connect time the model sees only the
offer: what the server can do and that it is **off until the user turns it on**. The first time
the model calls a working tool — or calls `local_llm_enable` to offer it — the server asks the
**user** directly through MCP elicitation (Claude Code shows a dialog naming the tool that was
attempted, never its arguments): turn it on for this session, turn it on in PII mode, or keep it
off. Only then does anything run; the result of that first call carries the full operating rules.

- **off** is remembered for the session; further calls return a refusal and the model is told not
  to ask again. A cancelled dialog refuses that call and may ask again later (three times at most).
- A client that **cannot show a dialog** is refused, with the text telling the model how the user
  can enable the server: `LOCAL_LLM_MCP_ARM=on` in that client's MCP configuration for the server
  (the user's standing approval for that client), or the **turn on** switch on the session's row in
  the admin app. Those two, and the dialog, are the only ways the gate is ever passed.
- `local_llm_status` is the one tool that answers while off (it shows the gate's state).
- The dialog is **default-safe by construction**, whatever the client does with it: the answer
  field is required, has no default, and lists **off** first, so a client that auto-accepts a
  form (empty, with defaults, or with its first option) yields "not answered" or "off" — never
  "on". Only an explicit **on** or **on_pii** chosen by the user arms the server.

## The command policy — what may actually run

Turning the server on is one decision; what it then executes is another. Every command a caller
hands to `local_llm_run` (or to `local_llm_delegate`'s `command`) runs with **your** privileges,
and a client in a bypass or auto permission mode never shows you a per-tool prompt — so the
server holds its own line, in three layers:

1. **Deny shapes** — refused outright, nothing run, the reason returned to the caller:
   privilege escalation (`sudo`, `doas`, `su`, `pkexec`), power state (`shutdown`, `reboot`,
   `halt`), filesystem writes (`mkfs*`, `fdisk`, `parted`, `wipefs`, `dd of=`), recursive `rm`,
   recursive `chmod`/`chown`, package installs, `shred`, a pipe from `curl`/`wget` into a shell,
   a write to a real device under `/dev/`, and any write under **`/etc`, `/boot` or `~/.ssh`**
   (reading them is fine). A command containing a placeholder that would rehydrate to a
   **secret** is refused too — a secret is never handed to a shell.
2. **Your allow list** — one glob per line in `~/.config/local-llm-mcp/run-allow.txt`
   (`LOCAL_LLM_MCP_RUN_ALLOW`). These run without a question: the standing approval for the
   shapes you delegate every day.

   ```
   git log*
   journalctl*
   ls*
   rg*
   pytest*
   ```

   **Every segment of a command line must match an entry**, so approving `ls*` does not approve
   `ls; something-else`. Approving `git log*` does not approve `git push*`: for a multiplexer
   (git, docker, systemctl, uv, npm…) the subcommand is part of the shape.
3. **Everything else asks.** The same MCP elicitation the gate uses, showing you the exact
   command and its working directory: **refuse / run once / always allow this shape**. "Always"
   appends the shape to the allow file, so the file stays the record of what you approved and
   you can edit it by hand. Like the turn-on dialog it lists **refuse** first and has no
   default, so a client that auto-accepts a form can never approve a command.

**No allow entry, and no dialog answer, can exempt a deny shape** — layer 1 is checked first,
always. A client that cannot show a dialog gets layer 1 and a trailer line saying it was not
asked. Every decision is stamped on the turn and in the trailer (`policy: allow-list (ls*)`,
`policy: asked:run`, `policy: refused: recursive rm`), counted in `local_llm_status.run_policy`,
and shown as a chip on the session's row in the admin app.

`LOCAL_LLM_MCP_RUN_POLICY` chooses how much of this runs: `ask` (default), `allow` (layer 1
only — never ask), or `off` (no policy at all).

This is deliberately **not a sandbox**. It reads command position, quoting and redirection well
enough to judge shapes; it does not follow a script it invokes, a variable it expands, or an
alias. It is a second lock on a door you already opened.

## The two modes and when the caller calls

The server tells the caller, in its MCP `instructions` (returned at initialize and
again by `local_llm_set_mode`), how often and under what circumstances to call. The
active mode's rule is written first.

| | PII mode | ASSIST mode |
|---|---|---|
| **Route here** | every step that might touch private data: names, home/postal addresses, phone numbers, personal email, family details, account/card/bank numbers, credentials, API keys, tokens, vault contents, `.env`/`.secrets`/`.ssh`, password or key prompts, personal mail/messages/contacts/calendars | every step that needs no conversational context and whose raw output would exceed the digest: a direct call returning more than ~40 lines / 2 KB — logs, journals, test/build/lint runs, listings, `git log/diff/status`, `grep`/`find`, package and process lists, service/container output, API responses, long dumps; file reads and summaries; research over material; calculations; transformations; boilerplate |
| **Do directly** | anything with no private data | calls that print little or nothing (`mkdir`, `cp`, `mv`, `rm`, `touch`, `chmod`, one-line checks); files under ~40 lines; edits; anything needing exact raw bytes |
| **What comes back** | fully sanitized: placeholders for every private value; secrets are used server-side and never returned | the result edited for clarity and usefulness; only secret shapes are scrubbed |
| **When unsure** | delegate | keep exact counts/sorts in the command (`wc`, `sort -n`, `awk`, `jq`); the worker digests, it does not compute over long lists |

The mode is a server setting (`LOCAL_LLM_MCP_MODE`) and can be switched per
conversation with `local_llm_set_mode`. Claude Code truncates server instructions at
2048 characters; both texts fit.

## Tools

All tools return text; every result ends with a trailer:

```
— local-llm · pii · turn t_ef33d4 · ref a_1606e7eb · rc 0 · raw 4471 chars · finalized · local · 1.8s · scrubbed 2 EMAIL, 1 SECRET
```

`turn` is the id in the session memory, `ref` the stored raw material, `rc` the exit
code (for commands), `finalized` marks a draft folded into a committed answer.

### `local_llm_run`

Run a shell command on the host (`bash -c`, this user's privileges, stdin closed,
output capped) and receive a digest of its output. Raw output is kept as an artifact.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `command` | string | required | the command; placeholders (`[SECRET-1]`) are expanded server-side before execution |
| `task` | string | outcome, errors/warnings verbatim, key values | what to report |
| `cwd` | string | server cwd | working directory |
| `timeout_s` | int | `LOCAL_LLM_MCP_COMMAND_TIMEOUT` | kill after |
| `max_output_chars` | int | `LOCAL_LLM_MCP_MAX_OUTPUT_CHARS` | soft digest budget |
| `verbatim` | bool | `false` | copy the matching output lines byte for byte instead of digesting — only for text you will reproduce or edit; never for questions, counts, summaries or listings. If nothing matches, the turn is digested instead and the trailer says so |

A timeout or non-zero exit is reported inside the digest and in the trailer.

### `local_llm_delegate`

Hand a task to the worker over material you name: inline text, files or directories
(listed; `~` expands; missing or unreadable paths are reported inline), and/or the output
of a shell command.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `task` | string | required | what to do — what to extract, thresholds, output shape |
| `material` | string | `""` | inline text |
| `paths` | list[string] | `[]` | files or directories to read |
| `command` | string | `""` | shell command whose output is added to the material |
| `cwd` | string | `""` | base for relative paths and the command |
| `max_output_chars` | int | server default | soft answer budget |
| `verbatim` | bool | `false` | copy the matching lines byte for byte instead of answering — only for text you will reproduce or edit; never for questions, counts, summaries or listings |

Without material the worker answers from the task and its session memory. In verbatim
mode the result is one or more `source lines a-b:` blocks with numbered lines; ranges
that did not fit the budget are named in the trailer so you can fetch them with
`local_llm_artifact`.

### `local_llm_artifact`

Return an exact slice of a stored raw output by ref, scrubbed (fully in PII mode,
secrets only in ASSIST mode). Line mode: `line_start` / `line_end` (1-based, inclusive,
numbered output; `line_end` defaults to 200 lines). Character mode: `offset` / `limit`
(default 4000, max 20000). The trailer says where the next slice starts.

### `local_llm_status`

Mode, session key, the caller's session id, model, endpoint, turn counts, context
size, compaction count and time, placeholder counts by kind, artifact count, the
scrubbed summary, control-socket path, observer name.

The block also carries `tokens_saved`: the estimate for this session and for all sessions (see [Tokens saved](#tokens-saved)).

### `local_llm_enable`

`local_llm_enable()` offers the server to the user: the server shows the dialog and returns the
operating rules if the user turns it on, or a refusal. The model should call it once, when a step
would print far more than it needs or would touch private data, and never again in a session where
the user said no. Every other working tool asks the same question on its first use.

### `local_llm_disclosure`

`local_llm_disclosure(identity="open"|"masked"|"ask"|"keep", numbers="open"|"masked"|"keep", reason="")`
records what this ASSIST session may show in clear, for when the user has said so in the
conversation; `identity="ask"` resets the question. Returns the resulting state. Secrets are
never shown; PII mode masks everything regardless. See [Disclosure](#disclosure--what-may-come-back-in-clear).

### `local_llm_compact`

Compact now. Normally automatic; useful when a client has no `PreCompact` hook.

### `local_llm_set_mode`

Switch `pii` ↔ `assist` for the rest of the conversation; returns the instructions for
the new mode so the caller learns the rule in-context.

### Optional: `local_llm_decide` and `local_llm_governance`

Present only when `LOCAL_LLM_MCP_DECIDE=1`. They ask your own worker to pick one of a short list of named
options, as advice that never acts — nothing extra to install. Off (the default), the server exposes nothing
of it. Details, settings and how a decision is made: [docs/DECISIONS.md](docs/DECISIONS.md).

## The privacy boundary

### Placeholders

Every detected private value maps to a placeholder that is **stable for the whole
conversation**: `[EMAIL-1]` is the same address every time it appears, in every
result, artifact slice and summary. Kinds: `PERSON`, `ADDRESS`, `PHONE`, `EMAIL`,
`SSN`, `CARD`, `ACCOUNT`, `SECRET`, `PII`.

The map lives in the session vault (`placeholders.json`, mode 0600) and is never
returned. Placeholders are **re-expanded server-side** when the caller reuses them:
"reply to `[EMAIL-1]`" reaches the worker with the real address; `curl -H
'Authorization: Bearer [SECRET-1]' …` runs with the real token. The caller never holds
the value.

### Detection — layered, deterministic

| Layer | What it catches | Source |
|---|---|---|
| shape rules | emails, phone numbers, national ids, payment cards (Luhn-checked), IBANs, key prefixes, PEM headers | built in, or your rules file (`LOCAL_LLM_MCP_RULES`) |
| secret shapes | PEM blocks, JWTs, bearer headers, well-known token prefixes, `KEY=value` lines, `password: …` / `password is …` assignments; in PII mode any 32+ character mixed letters-and-digits run outside a path or URL | built in |
| identity shapes (PII mode) | what identifies a person by shape alone, no seed data: street addresses and PO boxes, `City, ST 12345`, names introduced by an honorific (`Dr Example`), a form label (`patient: Jane Example`, `"name": "…"`), a mail header (`From: …`), a greeting (`Dear …,`) or a sign-off, dates of birth, labelled account and identity numbers (`account no. …`, `passport: …`, `NHS number …`) | built in; bounded regexes, low milliseconds per 100 KB; `LOCAL_LLM_MCP_SHAPES=0` turns it off Italian forms too: codice fiscale (check character verified), labelled partita IVA, `Via Roma 12`, `Sig.ra`/`Dott.`, labelled names, greetings and sign-offs, `+39` and labelled phones |
| private terms | the operator's own literal names, addresses, numbers — an unlabelled name has no shape | terms file (`LOCAL_LLM_MCP_PRIVATE_TERMS`) |
| entity pass (PII mode) | whatever private values the worker itself finds in the material: names, addresses, dates of birth, credentials it recognises in context | one extra local call per delegation; only exact substrings of the material are accepted, never a label or a variable name |
| known values | every value already in the vault, exact-matched | automatic |
| answer pass (while identity is masked) | after the scrub, the worker is asked what private values the OUTBOUND text still holds — every result, every compaction summary and every artifact slice, in PII mode and in ASSIST until the user opens identity; the text is short, so this covers it whole, unlike the material pass (first two chunks); anything found is registered and the text re-scrubbed; the trailer says `leak-check ok`, or `leak-check FAILED` when the pass could not run. Runs and failures are counted per session (`leak_check` in status, a warning chip in the admin app) so a weakened guarantee is never silent | one short local call per outbound text |

Order of operations matters:

1. Everything detectable in **incoming material** is registered in the vault *before*
   the worker sees it. An echo in the answer is then caught by exact match even in a
   context no rule would recognise.
2. The worker is instructed to write placeholders itself and never quote a secret.
3. The answer is scrubbed (rules · secret shapes · identity shapes · terms · every vault value), then
   re-scanned; anything still detectable becomes `[REDACTED]`. In PII mode the worker is
   then asked what private values the scrubbed answer still contains, and those are masked
   too (the answer pass). A privacy boundary cannot rest on a model choosing to comply, so
   step 2 is help, not the guarantee; the deterministic layers and the answer pass are.

### Disclosure — what may come back in clear

Mode never decides where work runs: everything runs on the local worker in both modes, and a
delegation by shape ("read this PDF", "list the accounts") lands here either way. Mode decides
what comes **back** to the caller. Three tiers:

| Tier | Kinds | PII mode | ASSIST mode |
|---|---|---|---|
| secrets | keys, tokens, passwords, PEM blocks | masked | masked, always |
| numbers | SSN, card, account and id numbers, dates of birth | masked | masked by default (`LOCAL_LLM_MCP_ASSIST_NUMBERS=open` changes the default) |
| identity | person, address, email, phone | masked | open once the **user** says so |

The first time identity or number values appear in an ASSIST session, the server asks the
user directly through MCP elicitation (Claude Code shows a dialog; the worker keeps working
meanwhile): **switch** the session to PII mode, **continue** with identity values shown, or
show **everything** except secrets. The answer is kept for the session, shown in
`local_llm_status`, stamped into that result's trailer (`disclosure: asked → continue`) and
listed in the admin app. Cancelling the dialog masks that result and asks again next time,
three times at most. Choosing "switch" also vaults the values already written into the
session's memory, so they leave masked from then on.

Bypasses, in order of directness: the dialog itself; `local_llm_disclosure(identity=…,
numbers=…)`, which the caller invokes when the user has said what they want in the
conversation ("just show me the names"), so no dialog is needed; and the deployment default
`LOCAL_LLM_MCP_ESCALATION`: `ask` (default), `auto` (no dialog: mask and tell the caller,
also what a client without elicitation gets) or `off` (identity values pass as they always
did). Nothing opens secrets.

The high-entropy rule is PII-only, so git SHAs and ids stay exact in ASSIST digests. In
ASSIST, everything detectable is still registered in the session vault (it is local), which is
what makes a later switch retroactive and lets the caller reuse `[CARD-1]` in a follow-up
command that needs the real digits.

### The endpoint must be local

`LOCAL_LLM_MCP_BASE_URL` must resolve to a loopback, RFC 1918 private or CGNAT
(`100.64.0.0/10`, e.g. a tailnet) address. Anything else is refused at startup, and
there is no override. This is the one setting that is not the operator's to relax.

## Session memory and compaction

The server is a stdio child of the caller and is told nothing about which
conversation it serves. Two small hooks close that gap; the server copes without them.

**Identity.** The `SessionStart` hook walks its own process ancestry to the Claude
Code process and writes `<state>/pidmap/<pid>` = the session id; the server walks
*its* ancestry and adopts the mapped id, migrating a pid-keyed directory onto it. A
resumed conversation (new process, same id) lands on the same memory. Because the hook
can fire before the server has opened its socket, a pid-keyed session re-checks the
map on every tool call until it is named.

**Memory.** Each tool call appends a turn: kind, task, source, a scrubbed excerpt of
what the worker saw, the scrubbed result, ref, sizes, timing. Every prompt to the
worker carries the compacted summary plus as many recent turns as fit
(`LOCAL_LLM_MCP_CONTEXT_CHARS`), rehydrated for the worker's eyes only.

**Compaction.** The `PreCompact` hook sends `{"op":"compact"}` to the control socket
(`$XDG_RUNTIME_DIR/local-llm-mcp/<pid>.sock`, 0600). The server queues a compaction
and answers immediately, so the caller's own compaction is never delayed; the worker
then rewrites its summary (goals, decisions, facts with exact identifiers, placeholders
in use, open items) under a lock, and the summary is scrubbed like everything else. The
server also compacts on its own when uncompacted turns exceed
`LOCAL_LLM_MCP_AUTO_COMPACT_CHARS`, and `local_llm_compact` does it on demand.

**Control socket ops:** `compact` (queue), `session` (announce the session id),
`status`. One JSON object per line in, one out.

## Tokens saved

Every counted turn records what the server **gathered** on the caller's behalf (command
output, files) and what it **returned** (the digest). From those two sizes the server
estimates what the caller did not have to spend, per session and across all sessions:

| Quantity | Estimate | Why |
|---|---|---|
| avoided input | tokens(gathered) − tokens(returned) | the caller read the digest instead of the raw output; inline material it pasted was already in its context and counts for nothing |
| avoided output | tokens(returned) × `output_credit[kind]` | for a delegation the worker wrote the answer the caller would otherwise have generated (credit 1.0); a digest of command output (0) and verbatim quoting (0) replace reading, not writing |
| carried | avoided input × `context_reuse_calls` | every token that enters the caller's context is re-sent on each later model call until compaction; priced at the model's cache-read rate where it has one, else at the input rate |

Token counts are **exact where the worker can count**: after each result is returned, the server asks
the worker's own tokenize endpoint (vLLM's `POST /tokenize`, or llama.cpp's) for the token count
of what it gathered and of what it returned, in the background, and records both in the ledger. A
worker with no such endpoint, or a turn that outlives the process, falls back to characters ÷
`chars_per_token`; the report says how many turns were measured. The counts are the worker
tokenizer's, not the caller model's, so each price row may carry a **`tokenizer_factor`**: that
model's tokens per character relative to the worker's, applied at pricing time only (the ledger
stays in worker tokens). Seeded at 1.3 for the Claude 4.7+ tokenizer family from Anthropic's own
note that it yields roughly 30 % more tokens, 1.0 (assumed equal) everywhere else; editable per
row in the admin app and the override file. The status block and the admin table show which
factor priced the headline. **Measure it instead of assuming it**: `tools/measure_tokenizer.py`
counts public text only (this repository's README, source and price table, plus synthesized
listings, process tables and journal lines) with the worker's tokenizer and with Anthropic's
token-count endpoint, prints the ratio per text class, and with `--write` sets each row's factor
in the override file from the measurement. Nothing private ever leaves the machine for this.

Dollars are **list prices** per 1M tokens for flagship models of every major provider, read
from the providers' own pricing pages and stamped with the date they were checked
(`local_llm_mcp/prices.json`). They are an equivalent, not an invoice: on a subscription the
figure is the usage kept out of the plan's limits; batch, flex and long-context tiers are
ignored (the `context_note` names them).

Where it shows:

- every result trailer carries `saved ≈ N tok` (avoided input + avoided output for that turn);
- `local_llm_status` returns a `tokens_saved` block — this session, all sessions, the headline
  model's dollar figure, and a per-model table;
- the admin app's **Tokens saved** tab: all-time tiles, by model, by session, and an editor for
  the assumptions and prices.

Everything is configurable and applies retroactively, because the ledger stores characters,
not tokens: `chars_per_token` (only for unmeasured turns; default 3.8 — deliberately conservative: Anthropic states that Claude 4.7
and later use a tokenizer producing roughly 30 % more tokens for the same text, so for those models the
true figure is nearer 3, and the estimate understates the saving), `context_reuse_calls` (default 8), the output
credits, and the headline model (`caller_model`, or `LOCAL_LLM_MCP_CALLER_MODEL`). Edits go to
the override file `LOCAL_LLM_MCP_PRICES` (default `~/.config/local-llm-mcp/prices.json`),
which merges over the package defaults by model id, can add models or disable one
(`"enabled": false`), and is hot-reloaded. The admin tab writes that file; "reset" removes it.
Prices go stale: the tab, the status block and `--check` flag the table once its `checked` date is
older than `stale_after_days` (default 30), so re-check the providers' pages and save.
The cross-session ledger is `<state>/savings.jsonl`, append-only, one line per counted turn;
it survives session purges. Sessions recorded before the ledger existed can be added from their
context logs with `local-llm-mcp-admin --backfill-savings` (or the button on the tab); the
gathered size of those older turns is inferred from the turn's raw size and source. Idempotent.

## Install and wire into Claude Code

Requirements: Python 3.12+, a local OpenAI-compatible chat endpoint (vLLM, llama.cpp
server, LM Studio, Ollama's OpenAI route, …).

```bash
uv tool install git+https://github.com/lealvona/local-llm-mcp    # or pipx; or uv pip install into a venv you manage
mkdir -p ~/.config/local-llm-mcp
cat > ~/.config/local-llm-mcp/env <<'EOF2'
LOCAL_LLM_MCP_MODE=assist
LOCAL_LLM_MCP_BASE_URL=http://127.0.0.1:8000/v1
LOCAL_LLM_MCP_MODEL=local
LOCAL_LLM_MCP_API_KEY_FILE=$HOME/.config/local-llm-mcp/model.key
EOF2
chmod 600 ~/.config/local-llm-mcp/env
local-llm-mcp --check            # prints effective config, rules source, session key, and probes the model
claude mcp add --scope user local-llm -- local-llm-mcp
```

Hooks — add to `~/.claude/settings.json` (both entries run the same stdlib-only
script, exit 0 always, cost milliseconds):

```json
{
  "hooks": {
    "SessionStart": [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}],
    "PreCompact":   [{"hooks": [{"type": "command", "command": "/usr/bin/python3 /path/to/local-llm-mcp-hook.py", "timeout": 5}]}]
  }
}
```

`hooks/local-llm-mcp-hook.py` ships in the repo; copy it wherever you keep hooks.
Verify with `claude mcp list` (should say Connected) and, in a new session, the
`local_llm_status` tool.

Other MCP clients: run `local-llm-mcp` over stdio. Without the hooks, sessions are
keyed by the parent process id and compaction is manual or automatic-by-size.

## Using it from other MCP clients

The server is a plain stdio MCP server; nothing in it requires Claude Code. Every client below
was exercised against this code (protocol clients with the reference tooling, agents with a real
model turn) — what changes from client to client is only what you lose without Claude Code's
hooks, listed after the table.

| Client | Register | Verified |
|---|---|---|
| **Claude Code** | `claude mcp add --scope user local-llm -- /path/to/venv/bin/local-llm-mcp` + the two hooks (see above) | full: hooks, dialog, compaction trigger |
| **Codex CLI** | `codex mcp add local-llm -- /path/to/venv/bin/local-llm-mcp` (writes `[mcp_servers.local-llm]` in `~/.codex/config.toml`) | agent turn: tools called and digested; it **does** declare elicitation. Note the non-interactive caveat below |
| **Hermes Agent** | in `config.yaml`: `mcp_servers:\n  local-llm:\n    command: /path/to/venv/bin/local-llm-mcp` | agent turn: Hermes called `local_llm_run` and returned the digest with the server's trailer |
| **Kimi Code CLI** | `~/.kimi-code/mcp.json`: `{"mcpServers": {"local-llm": {"command": "/path/to/venv/bin/local-llm-mcp", "args": []}}}` — ⚠️ **not `~/.kimi/`**, which 0.37 no longer reads | agent turn: `local_llm_run` called, digest and trailer returned. **Declares no elicitation**, so it needs the standing approvals below |
| **opencode** | `opencode.json(c)`: `{"mcp": {"local-llm": {"type": "local", "command": ["/path/to/venv/bin/local-llm-mcp"], "enabled": true}}}` | see below |
| **Claude Desktop, Cursor, Windsurf and most others** | `{"mcpServers": {"local-llm": {"command": "/path/to/venv/bin/local-llm-mcp"}}}` in the client's MCP config | same wire protocol as the Inspector run below |
| **MCP Inspector** (reference client) | `npx @modelcontextprotocol/inspector --cli /path/to/venv/bin/local-llm-mcp --method tools/list` | `tools/list` and a `tools/call` of `local_llm_run` |
| **Python SDK** | `StdioServerParameters(command="/path/to/venv/bin/local-llm-mcp")` + `ClientSession` | `tools/smoke.py` is exactly this client and drives every feature, the disclosure dialog included |

Pass configuration the same way for every client: put it in the dotenv the server reads
(`~/.config/local-llm-mcp/env`), or in the client's per-server `env`.

What you lose without Claude Code's hooks, and what replaces it:

- **Session identity.** Claude Code's SessionStart hook maps the conversation id onto the server;
  elsewhere the session is keyed by the client process that spawned the server (`pid-<pid>`),
  one per conversation, or by `LOCAL_LLM_MCP_SESSION` if the client sets it. The pidmap is read
  **only** when Claude Code is the process that spawned the server, so another harness launched
  from inside a Claude Code session gets its own session rather than inheriting that
  conversation's vault, memory and answer to the gate. The session records
  which client it belongs to (`client` in `local_llm_status` and the admin sessions table).
- **Compaction trigger.** The PreCompact hook tells the worker to compact when the caller does;
  without it the worker still compacts itself at `LOCAL_LLM_MCP_AUTO_COMPACT_CHARS` and on
  `local_llm_compact`.
- **The connection instructions.** Some clients never show the model the `instructions` field of
  `initialize`. The same text is therefore also an MCP **prompt** (`local_llm_instructions`) and a
  **resource** (`local-llm://instructions`), and the routing rules are written into the tool
  descriptions, which every client shows. For a harness that reads an instructions file
  (`AGENTS.md`, a system prompt), paste the ASSIST or PII text from `local_llm_status`.
- **A non-interactive run cannot answer a dialog.** A client may declare elicitation and still
  auto-**decline** every question when it has no user in front of it — `codex exec` does, and so
  does Claude Code's print mode. That is the right direction to fail: the gate stays off and no
  command runs. For an unattended run, give that client its standing approvals explicitly in its
  own server config — `LOCAL_LLM_MCP_ARM=on`, plus the command shapes in `LOCAL_LLM_MCP_RUN_ALLOW`
  (or `LOCAL_LLM_MCP_RUN_POLICY=allow`). Both are needed: they are separate decisions, and each
  dialog is refused on its own.
- **The turn-on, disclosure and command dialogs** need a client that supports MCP elicitation
  (Claude Code and Codex do; **Kimi Code 0.37 does not**). Without it, the server refuses to start
  until the user sets `LOCAL_LLM_MCP_ARM=on` in that client's server configuration (their explicit
  approval); disclosure falls back to `auto` (masked, with a note telling the model to call
  `local_llm_disclosure` when the user decides); and the command policy falls back to its deny
  shapes alone, with a trailer line saying the user was not asked — **so in such a client the allow
  list is the only per-command control, and it is worth filling in.** Measured on Kimi Code 0.37:
  refused as designed, then with `ARM=on` and one allow entry it returned the digest and the full
  trailer, `policy: allow-list (echo*)` included.

One server process serves one conversation; that is the isolation model behind the vault. Do
not put it behind a multi-user MCP gateway (a shared mcpo instance serving a chat UI, say): every
user would share one placeholder map, and `local_llm_run` runs shell commands as the user that
owns the process.

## Configuration reference

The process environment wins over the dotenv file
(`~/.config/local-llm-mcp/env`, or `LOCAL_LLM_MCP_ENV_FILE`); the file accepts
`KEY=VALUE`, `export KEY=VALUE`, quotes, `#` comments and `$HOME`.

| Variable | Default | Meaning |
|---|---|---|
| `LOCAL_LLM_MCP_MODE` | `assist` | `pii` or `assist` |
| `LOCAL_LLM_MCP_BASE_URL` | `http://127.0.0.1:8000/v1` | OpenAI-compatible endpoint; must be local |
| `LOCAL_LLM_MCP_MODEL` | `local` | model name sent to the endpoint |
| `LOCAL_LLM_MCP_FALLBACK_BASE_URL` | unset | a second local worker used when the primary is unreachable or answers 5xx (must be local too) |
| `LOCAL_LLM_MCP_FALLBACK_MODEL` | primary model | model name at the fallback |
| `LOCAL_LLM_MCP_FALLBACK_API_KEY` / `_FALLBACK_API_KEY_FILE` | unset | its key |
| `LOCAL_LLM_MCP_FAILOVER_COOLDOWN` | `120` | seconds the fallback is asked first after the primary fails |
| `LOCAL_LLM_MCP_API_KEY` / `LOCAL_LLM_MCP_API_KEY_FILE` | unset | bearer for the endpoint (file: one line, keep it 0600) |
| `LOCAL_LLM_MCP_THINKING` | `0` | pass `enable_thinking` to the chat template. Off is right for most local models: a reasoning budget can consume the whole `max_tokens` and return empty content |
| `LOCAL_LLM_MCP_MAX_OUTPUT_CHARS` | `2000` | default digest budget; `max_tokens` is derived from it |
| `LOCAL_LLM_MCP_MAX_TOKENS_CAP` | `8192` | ceiling on `max_tokens` |
| `LOCAL_LLM_MCP_LLM_TIMEOUT` | `300` | seconds per model call |
| `LOCAL_LLM_MCP_CHUNK_CHARS` | `24000` | material above this is processed map-reduce style |
| `LOCAL_LLM_MCP_PARALLEL_CHUNKS` | `4` | concurrent chunk calls |
| `LOCAL_LLM_MCP_MATERIAL_MAX_CHARS` | `400000` | cap on gathered material (head 70 % + tail 30 % kept, marker in between) |
| `LOCAL_LLM_MCP_CONTEXT_CHARS` | `12000` | budget for summary + recent turns in each prompt |
| `LOCAL_LLM_MCP_EXCERPT_CHARS` | `1500` | scrubbed excerpt of material kept per turn |
| `LOCAL_LLM_MCP_SUMMARY_CHARS` | `6000` | compaction target |
| `LOCAL_LLM_MCP_AUTO_COMPACT_CHARS` | `60000` | self-compaction threshold on uncompacted turns |
| `LOCAL_LLM_MCP_COMMAND_TIMEOUT` | `120` | default command timeout, seconds |
| `LOCAL_LLM_MCP_RUN_POLICY` | `ask` | the command policy: `ask` (deny shapes, then the allow list, then ask the user), `allow` (deny shapes only), `off` (no policy) |
| `LOCAL_LLM_MCP_RUN_ALLOW` | `~/.config/local-llm-mcp/run-allow.txt` | commands that run without asking, one glob per line; the "always" answer appends here |
| `LOCAL_LLM_MCP_STRICT_PII` | `0` | treat every bare 10-digit run as a phone number (default: only formatted numbers or ones near phone words) |
| `LOCAL_LLM_MCP_ENTITY_PASS` | `1` | PII mode: ask the worker for the private values before answering |
| `LOCAL_LLM_MCP_ARM` | `ask` | the opt-in gate: `ask` = the user is asked in a dialog on first use (a client without one is refused); `on` = the user's standing approval for this client configuration |
| `LOCAL_LLM_MCP_ESCALATION` | `ask` | first identity/number values in an ASSIST session: `ask` the user (dialog), `auto` (mask and tell the caller), `off` (show identity values) |
| `LOCAL_LLM_MCP_ASSIST_NUMBERS` | `masked` | whether account/card/id numbers and dates of birth are shown in ASSIST before the user decides |
| `LOCAL_LLM_MCP_DIALOG_TIMEOUT` | `600` | seconds to wait for the disclosure dialog before masking that result |
| `LOCAL_LLM_MCP_SHAPES` | `1` | PII mode: the identity-shape layer (addresses, labelled names, dates of birth, labelled id numbers) |
| `LOCAL_LLM_MCP_PRICES` | `~/.config/local-llm-mcp/prices.json` | override file for the tokens-saved estimate (assumptions + prices; the admin app writes it) |
| `LOCAL_LLM_MCP_CALLER_MODEL` | unset | headline model for the dollar figure (defaults to the prices file's `caller_model`, then the first model) |
| `LOCAL_LLM_MCP_RULES` | built-in | JSON rules file (see below) |
| `LOCAL_LLM_MCP_PRIVATE_TERMS` | `~/.config/local-llm-mcp/private_terms.json` | terms file (see below) |
| `LOCAL_LLM_MCP_TERMS_SEED` | `~/.config/local-llm-mcp/terms-seed.json` | optional suggestions for the onboarding page; keep it beside the terms file, never in the repo |
| `LOCAL_LLM_MCP_TERMS_BACKUP_STAMP` | unset | file whose first word is the sha256 of the last backed-up terms file; the onboarding page shows whether it is current |
| `LOCAL_LLM_MCP_STATE_DIR` | `~/.local/state/local-llm-mcp` | sessions, pidmap |
| `LOCAL_LLM_MCP_SOCK_DIR` | `$XDG_RUNTIME_DIR/local-llm-mcp` (else `<state>/sock`) | control sockets; AF_UNIX paths cap at 108 bytes, keep it short |
| `LOCAL_LLM_MCP_OBSERVER` | unset | `webhook`, or `module:Class` |
| `LOCAL_LLM_MCP_OBSERVER_URL` | unset | webhook target (also available to your own observer) |
| `LOCAL_LLM_MCP_OBSERVER_PATH` | unset | directory added to `sys.path` to import your observer |
| `LOCAL_LLM_MCP_SESSION` | unset | force a session key (tests, scripts) |
| `LOCAL_LLM_MCP_ADMIN_BIND` / `_ADMIN_PORT` | `127.0.0.1` / `8631` | admin app listener |
| `LOCAL_LLM_MCP_ADMIN_TOKEN` / `_ADMIN_TOKEN_FILE` | unset | bearer token the admin API requires (set it whenever the bind is not loopback — a non-loopback bind with neither this nor the override below set refuses to start) |
| `LOCAL_LLM_MCP_ADMIN_ALLOW_NO_TOKEN` | `0` | start anyway on a non-loopback bind with no token |
| `LOCAL_LLM_MCP_LOG_LEVEL` | `INFO` | stderr logging |
| `LOCAL_LLM_MCP_DECIDE` | `0` | optional decision tools answered by your own worker; `0` exposes none of them ([docs/DECISIONS.md](docs/DECISIONS.md)) |
| `LOCAL_LLM_MCP_DECIDE_PREFER` | `primary` | which worker answers decisions first: `primary` or `fallback` |
| `LOCAL_LLM_MCP_DECIDE_REASONING` / `_DECIDE_TIMEOUT_S` | `1` / `5` | one sentence of reasoning before the (still restricted) choice; how long the first request may take before the engine asks without the restriction |

CLI: `local-llm-mcp [--mode pii|assist] [--session KEY] [--check]`.

## Rules file

`LOCAL_LLM_MCP_RULES` points at a JSON file that **replaces** the built-in shape
rules. The schema is deliberately compatible with a privacy-routing rules file another
tool might already maintain — other top-level keys are ignored, so one file can serve
several tools:

```json
{
  "regex_rules": [
    {"id": "email",       "pattern": "[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}"},
    {"id": "phone",       "pattern": "(?<![\\d.-])(?:\\+\\d{1,3}[ .-]?)?(?:\\(\\d{3}\\)|\\d{3})[ .-]?\\d{3}[ .-]?\\d{4}(?![\\d.-])"},
    {"id": "credit_card", "pattern": "\\b(?:\\d[ -]?){12,18}\\d\\b", "luhn": true},
    {"id": "employee_id", "pattern": "\\bEMP-\\d{6}\\b", "enabled": true}
  ]
}
```

The rule `id` decides the placeholder kind: `email`→EMAIL, `phone`→PHONE,
`us_ssn`→SSN, `credit_card`→CARD, `iban`→ACCOUNT; ids containing `key`, `token`,
`secret`, `private`, `password` or `credential`→SECRET; `mail`/`phone`/`card`/`ssn`/
`account`/`bank`/`routing` by substring; anything else→PII. The file is hot-reloaded
on change. Keep quantifiers bounded — an unbounded email pattern backtracks
quadratically on long unbroken runs.

Built-in acceptance filters apply to any rules file: a bare ten-digit `phone` match in
non-strict mode needs formatting or a nearby phone word (timestamps and ids are not
phone numbers); a `credit_card` match shaped like `YYYYMMDD-HHMMSS` is a build id, not
a card.

## Private terms

```json
{
  "terms": [
    {"kind": "PERSON",  "values": ["Jane Q. Example", "J. Example"]},
    {"kind": "ADDRESS", "values": ["12 Example Lane"]},
    {"kind": "PHONE",   "values": ["+1 555 010 0000"]},
    {"kind": "PII",     "values": []}
  ]
}
```

Case-insensitive, whole-word, longest first, hot-reloaded. **Each term matches in every common format, so
write it once, any way:**

| Kind | Also matched |
|---|---|
| `PHONE` | the same digits with any separators (spaces, dots, dashes, brackets, slashes) or none; with or without the country code (`+1`/`1`/`001` for a 10- or 11-digit North-American number, `+`/`00` for one saved with a prefix); never inside a longer number |
| `ACCOUNT`, `PII` that are numbers (6+ digits) | the same digits grouped with spaces, dashes or dots, or not at all |
| `EMAIL` | `name at domain dot com`, `name [at] domain [dot] com`, `name (at) …`, any case |
| `ADDRESS` | written out or abbreviated (Street/St., Avenue/Ave, Apartment/Apt/Unit/#, North/N., Suite/Ste, …), commas and full stops optional, parts across line breaks |
| `PERSON` | any spacing or line break between the parts, `Last, First`, a middle initial |
| any value of two or more words, except an e-mail | its words run together, joined by nothing or by up to three spaces, dots, dashes, slashes, brackets or underscores: `Jane Example` also matches `JaneExample`, `janeexample`, `jane.example`, `jane_example` and the name in `JANEEXAMPLE-notes`, but not `xjaneexample` or `janeexample2`. An underscore joins words only; it never separates the digits of a number |

**A placeholder restores exactly what was written**, never a tidied-up version: the vault holds each written form
of a term as its own value. Placeholders are rehydrated into the commands the caller runs, so this matters:
`grep -c '4400-1234-5678' ledger.csv` must still search for the dashes, `wc -l Example,Jane` must still read the
file called `Example,Jane`, and `/srv/janeexample/notes.txt` must come back unchanged.

The written forms of one term share its number. The first form seen in a conversation takes `[PERSON-1]`; each
other spelling takes the next suffix:

| Written | Placeholder | Restores |
|---|---|---|
| `Example, Jane` | `[PERSON-1]` | `Example, Jane` |
| `Jane Example` | `[PERSON-1.2]` | `Jane Example` |
| `janeexample` | `[PERSON-1.3]` | `janeexample` |
| `Pat Sample` (another term) | `[PERSON-2]` | `Pat Sample` |

Each written form keeps its placeholder for the whole conversation. The worker is told that `[PERSON-1.2]` is
another spelling of `[PERSON-1]` and to copy placeholders exactly; the caller's instructions show the pair. Counts (the disclosure dialog, `local_llm_status`) count values, not spellings:
the three above are one `PERSON`. A form is told apart byte for byte, so `JANE EXAMPLE`, `Jane  Example` (two
spaces) and `Jane\nExample` are three more forms. A vault written before this change keeps its placeholders, and new
spellings of a term whose saved value it holds number from that value's placeholder.

Whole-word applies to matching a term. Once a written form is in the session's vault, the scrub also
exact-matches every vault value wherever it appears, with no word boundaries, so later in that conversation it is
masked inside longer tokens too: `janeexamplelaptop` becomes `[PERSON-1.3]laptop`.

Put the names, addresses and numbers of the people this deployment protects here; keep usernames and hostnames
out (they appear in every path). A two-word name also matches its run-together form, so a login name that is a
saved name written together (`janeexample`) is masked wherever it appears, paths included. For the same reason a
two-word term whose joined form is an ordinary word masks that word everywhere: a person saved as `Mark Down`
masks every `markdown`, and once vaulted, `markdownlint` too. That errs toward privacy by design: an over-masked word costs the caller some clarity, a
missed name leaks it. This is the deterministic floor for identity that no pattern can infer;
the entity pass adds what the worker finds on top.

## Observers

Observers receive **scalar-only** events — tool name, turn id, ref, sizes, seconds,
exit code, scrub and entity counts, session key — never task text, material or
results. Three options:

- unset — no observer;
- `LOCAL_LLM_MCP_OBSERVER=webhook` with `LOCAL_LLM_MCP_OBSERVER_URL` — one JSON object
  per event: `{"event": "start"|"event"|"end", ...}`;
- `LOCAL_LLM_MCP_OBSERVER=mymodule:MyObserver` with `LOCAL_LLM_MCP_OBSERVER_PATH=/dir`
  — your own subclass, kept outside this package:

```python
# /dir/mymodule.py
from local_llm_mcp.observers import Observer

class MyObserver(Observer):
    name = "mine"
    async def start(self, info: dict) -> None: ...     # session, claude_session_id, mode, model, endpoint
    def event(self, span: str, kind: str, attrs: dict) -> None: ...   # must not block
    async def end(self, state: str = "done") -> None: ...
    @property
    def run_id(self) -> str: return ""                  # shown in local_llm_status
```

A broken or unreachable observer never fails a tool call; the server logs and continues.

## Admin app

`local-llm-mcp-admin` serves a small single-page app plus a JSON API for the PII layer —
the parts the caller never sees:

| Tab | What it shows (glance) | What it does (delve) |
|---|---|---|
| Overview | counts: terms by kind, sessions and how many are live, placeholders by kind, rules source, entity pass | each tile opens its tab |
| Terms | the private terms by kind, values masked (hover or *reveal values*) | add a term; remove one; **harvest** candidates from pasted text with the local model and tick the ones to keep |
| Sessions | one row per conversation: live dot, mode, last seen, turns, compactions, placeholder counts, artifacts, size | open a row: the placeholder vault (placeholder → kind → value), compacted memory, recent turns, artifacts; purge placeholders, delete artifacts, delete the session — refused while a server holds it |
| Scrub tester | paste text, pick a mode | the text as it would leave the server, every detected span highlighted by kind, and the placeholders that would be minted |
| Rules · Config | the shape rules in force and their source; the effective configuration (key shown as set/unset) | read-only |

**Onboarding page — `/onboard`.** A guided way to fill in the private terms. It uses the admin token. Both admin pages accept it in a link, as `#token=<token>` (preferred: a fragment never reaches the server) or `?token=<token>`; the page keeps it for the browser session, sends it as the `Authorization` header, and removes it from the address bar and history at once. It lists suggestions to confirm,
correct or reject: from an optional seed file your deployment provides (`LOCAL_LLM_MCP_TERMS_SEED`, default
`~/.config/local-llm-mcp/terms-seed.json`, `{"suggestions": [{"kind", "value", "source", "confidence", "note"}]}`),
from this machine (git name and e-mail, the account's full name, the login name) and from variants of the names.
Each category comes with guidance; values that would over-mask (very short, common words, a single name) are
flagged; a *Try it* box shows what a pasted text would look like once scrubbed. Choices are staged until you
save. A rejected suggestion is remembered **only as a hash** (`<state>/terms-rejected.json`), so it does not
come back and is not kept in plain text. If your deployment backs the terms file up, point
`LOCAL_LLM_MCP_TERMS_BACKUP_STAMP` at a file holding the sha256 of the last backed-up version and the page shows
whether the terms changed since.

```bash
local-llm-mcp-admin                 # http://127.0.0.1:8631/  (loopback, no token)
LOCAL_LLM_MCP_ADMIN_BIND=0.0.0.0 LOCAL_LLM_MCP_ADMIN_PORT=8631 \
LOCAL_LLM_MCP_ADMIN_TOKEN_FILE=~/.config/local-llm-mcp/admin.token local-llm-mcp-admin
```

It reads the same dotenv, state directory and terms file as the server (terms are
hot-reloaded, so an edit here applies to running servers at once). **It shows private
values to whoever reaches the port**: it binds to loopback by default, and when bound
wider it should sit behind a firewall *and* a token (`LOCAL_LLM_MCP_ADMIN_TOKEN` or
`_TOKEN_FILE`; the page asks once per tab) — a non-loopback bind with no token set
**refuses to start** rather than serving the vault to whoever finds the port; set
`LOCAL_LLM_MCP_ADMIN_ALLOW_NO_TOKEN=1` if you genuinely want that (a LAN you already
trust, say) and understand what it means. No external assets; `?demo=1` renders the
page with sample data and no server, for a look at the UI.

## Keeping a deployment separate from the code

This package carries nothing about any network. A deployment is:

| Layer | Where | Contents |
|---|---|---|
| general code | this repo | the package, hook script, tests, tools |
| runtime | a venv you install the package into (`uv tool install`, `pipx`, or `uv pip install /path/to/repo`) | re-installed to update |
| instance config | `~/.config/local-llm-mcp/` | dotenv, key files (0600, never committed), `private_terms.json`, a rules file or a pointer to one, observer plugin(s), your notes |

A minimal sync script for a checkout-based deployment:

```bash
#!/usr/bin/env bash
set -euo pipefail
REPO=~/src/local-llm-mcp; INST=~/.local/share/local-llm-mcp
[[ -d $INST/venv ]] || uv venv --python 3.12 "$INST/venv"
uv pip install --python "$INST/venv/bin/python" --reinstall-package local-llm-mcp "$REPO"
install -m 755 "$REPO/hooks/local-llm-mcp-hook.py" "$INST/hooks/local-llm-mcp-hook.py"
"$INST/venv/bin/local-llm-mcp" --check
```

Point Claude Code at `$INST/venv/bin/local-llm-mcp` and the hook copy; edit the repo,
run the script, and new sessions pick up the change. Version the config directory
privately if you like (ignore `*.key`).

### The git gate — nothing personal reaches a commit, a message, or a push

The separation above is enforced at the repository, not by care. `tools/install-hooks.sh`
points a clone at the tracked hooks in `tools/githooks/`, and every one of them calls
`tools/publiccheck.py`:

| Hook | Refuses |
|---|---|
| `pre-commit` | staged content or file names carrying a private network address (a LAN host written by its last octet alone included), a home-directory path, a non-example e-mail, a tailnet name, or a denylisted term; then `gitleaks` on the staged changes when it is installed |
| `commit-msg` | the same terms in the message; any attribution trailer (`Co-Authored-By`, "generated with"); an author or committer other than the identity configured for the repository (`--author`, `GIT_AUTHOR_*`, `-c user.email` are all caught) |
| `pre-push` | every commit the push would publish, checked in full — identity, message, file names and the whole tree at that commit — so a commit made with `--no-verify`, a rebase, a cherry-pick or an amend cannot slip past the earlier two; and any direct push that moves an existing `main` — it changes by merging a pull request (`LOCAL_LLM_MCP_ALLOW_MAIN_PUSH=1` overrides once). It also runs **your own global `pre-push`** (`git config --global core.hooksPath`), which a repository-local hooks path would otherwise switch off |

The **denylist** is a private file the repository never sees — one term per line in
`$LOCAL_LLM_MCP_DENYLIST` (default `~/.config/local-llm-mcp/publiccheck-denylist.txt`):
your user name, host names, project names, model aliases, domains, anything that identifies you or
your network. Terms match case-insensitively on word boundaries, and a space in a term matches a
space, underscore or hyphen, so one entry covers `Blue Kettle`, `Blue-Kettle` and `blue_kettle`.
Hits are reported by line number, never by value, so a refusal can be pasted anywhere.

⚠️ **Keep it current: the shape checks catch addresses, but only the denylist catches NAMES.** A host
or project name has no shape a regex can find, so a name that is not on your list will pass every
gate — this is the one place the gate depends on you. When `publiccheck` runs without the list — on
CI, where the file does not exist — it says so instead of reporting "clean", because half the gate
did not run there. `python tools/publiccheck.py --all` on a machine that has the list is the real
proof, and it reads annotated tags as well as commits.

## State on disk

```
~/.local/state/local-llm-mcp/
  pidmap/<pid>                      caller pid → session id (written by the SessionStart hook)
  sessions/<session>/               0700
    meta.json                       mode, counts, timestamps, identity
    context.jsonl                   turns (scrubbed); a "compaction" turn marks each summary
    summary.md                      the compacted memory (scrubbed)
    placeholders.json               the vault: placeholder ↔ value, 0600 — never leaves the host
    artifacts/a_xxxxxxxx.txt        raw material per turn, 0600 (served only through the scrub)
$XDG_RUNTIME_DIR/local-llm-mcp/<pid>.sock   control socket, 0600, removed on exit
```

Sessions are never deleted automatically; `rm -r` a session directory to forget it.

## Testing and verification

```bash
uv sync
.venv/bin/python -m pytest -q                       # scrubber, vault, rules file, dotenv, entity registration, verbatim helpers, admin API
.venv/bin/python tools/smoke.py                      # end to end over stdio against your configured model
.venv/bin/python tools/leakcheck.py ~/.secrets/app.env   # a REAL secrets file through PII mode; asserts no value leaks
.venv/bin/python tools/piicheck.py                   # adversarial tasks over SYNTHETIC private data, PII mode + ASSIST default: nothing may come back
ANTHROPIC_API_KEY=… .venv/bin/python tools/measure_tokenizer.py [--write]   # tokenizer factors from PUBLIC text, never from turns
python tools/publiccheck.py --all                    # every commit in the history: nothing personal, no stray identity or trailer
```

The smoke client exercises: initialize (instructions carry the mode), tool listing,
status, a calculation, a command digest, a PII delegation (the email and password
never come back), placeholder rehydration through a shell command (an uppercased echo
comes back re-scrubbed), artifact slicing, compaction over the control socket exactly
as the hook does it, recall of a fact after compaction, verbatim quoting of a function out
of a 190-line file, line-mode artifact slicing, a command supplied to delegate, and a mode
switch.

`leakcheck.py` reads a file you name only to build the list of values to guard, runs
a fresh PII-mode server against it, and prints the digest only if none of those values
— not even a 12-character fragment — appears in it.

## Threat model and limits

**Protects against:** private values in material (files, command output, pasted
text) reaching the caller, including when the worker paraphrases, uppercases, or
quotes them; private values surviving into summaries and artifact slices; and — through
the command policy — a caller running a destructive command, or one built around a
secret, on a client whose own approval prompts are turned off.

**Assumes:** the host and the local model endpoint are trusted; the caller is not
malicious toward the operator (it is instructed, not sandboxed); the operator lists
the identities to protect or accepts the entity pass's recall; and that what they put on
the allow list is what they meant to approve.

**Does not protect against:** a caller that reads private files with its *own* tools
instead of delegating (the instructions say not to; nothing enforces it — put a hook in
front of those tools if you need enforcement); names and addresses that are neither in
the terms file nor recognised by the worker; secrets shaped like ordinary words with no
label; side channels such as the *length* of a rehydrated value (a command can measure
it); the worker's own logs at the endpoint. **The command policy is not a sandbox** — it
judges shapes, not shell semantics, so it does not follow a script it invokes, a variable
it expands, or an alias; a command the user approves runs as the user.

**Known behaviours:** bare ten-digit numbers in command output are ids unless
formatted or near a phone word (`LOCAL_LLM_MCP_STRICT_PII=1` flips that); in PII mode,
long mixed alphanumeric runs (git SHAs included) become `[SECRET-n]`; a variable *name*
is never treated as a secret, its value always is; a no-thinking model that revises in
the open is folded into a committed answer by a second short call.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `claude mcp list` says `CONNECTION_CLOSED` | read Claude's log: `~/.cache/claude-cli-nodejs/<project>/mcp-logs-local-llm/*.jsonl` — it captures the server's stderr. Common: config error (bad endpoint, missing key file), or the package not importable from Claude's cwd (install it, do not rely on a working-directory import) |
| `refusing to start … not a loopback, private-network or CGNAT address` | the endpoint must be local; that is the design |
| empty answers / `spent its budget on reasoning` | keep `LOCAL_LLM_MCP_THINKING=0`, or raise `max_output_chars` |
| the caller ignores the mode rules | instructions are truncated at 2048 chars by Claude Code; check `local_llm_status` shows the mode you expect, and `local_llm_set_mode` to re-deliver the rule |
| `status` shows `session_key: pid-…` with an empty `claude_session_id` | the SessionStart hook is not installed or not on that path; the server still works, keyed by pid, and adopts the id as soon as the hook's mapping appears |
| compaction never triggers on the caller's compaction | the PreCompact hook is missing, or the socket dir differs between hook and server (`LOCAL_LLM_MCP_SOCK_DIR` must be identical in both environments); `local_llm_compact` still works |
| `socket path … near the AF_UNIX limit` | set `LOCAL_LLM_MCP_SOCK_DIR` to something short |
| the digest hides variable names as `[SECRET-n]` | a rules file rule is matching the name; names shaped `WORD_WORD` are exempt from the built-in assignment rule but not from custom rules |
| everything is `[PHONE-n]` | `LOCAL_LLM_MCP_STRICT_PII=1` on technical output; turn it off |

Logs go to stderr (Claude Code captures them); `LOCAL_LLM_MCP_LOG_LEVEL=DEBUG` for
observer traffic.

## FAQ

**Why placeholders instead of `[REDACTED]`?** So the caller can keep working: it can
address `[EMAIL-1]`, compare `[PERSON-1]` and `[PERSON-2]`, and pass `[SECRET-1]` into
a command — all without holding the value. Referential integrity survives
sanitization.

**When should I use verbatim mode?** Whenever you will *reproduce* the text rather than
act on a summary of it: a function to copy, a config block to edit, an error to quote. The
worker only chooses the lines; the bytes come from the source. A digest is for when you
need to know what something says; verbatim is for when you need to have it.

**Why does the worker get its own memory instead of the caller's?** The caller's
context is what we are trying to keep small and clean. The worker's memory is local,
cheap, and rehydrated only for the worker; the caller receives a summary only through
the scrub.

**Why one extra call in PII mode (the entity pass)?** Because a regex knows the shape of
an email, not a person's name. Asking the worker "what private values are here?" and
registering the exact substrings it names turns the model's judgement into a
deterministic guarantee — the scrub catches those strings regardless of what the
final answer says.

**Why refuse non-local endpoints outright?** The server's purpose is that private
material never leaves the network. A configuration mistake must not be able to defeat
that.

**Can I use a cloud model as the worker over a tunnel?** If it resolves to a private
address the check passes, but you would be defeating the purpose. Don't.

**Does it work without Claude Code?** Yes, with any MCP client over stdio. The hooks
are Claude Code specific; without them, sessions are keyed by parent pid and compaction
is by size or on demand.

**Why isn't it on PyPI?** Because publishing a package is a support commitment, and the
author isn't taking one. Install it from git — the line above works, and `uv tool install
git+https://github.com/lealvona/local-llm-mcp` does too. The repository is MIT: fork it,
package it, publish it under your own name if you want a release you can rely on.

## License

MIT — see `LICENSE`.
