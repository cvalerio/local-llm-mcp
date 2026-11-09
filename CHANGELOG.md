# Changelog

All notable changes to local-llm-mcp. Dates are the day the change was pushed.

## Unreleased

### Fixed — secrets, the allow list and the worker's route (security review)
- **A slice no longer shows part of a secret.** `local_llm_artifact` and `verbatim=true` cut from the raw material and
  scrubbed afterwards, and a scrub cannot recognise a fragment: a slice starting inside a private key returned its body.
  Both now scrub the whole material first and cut from the result. Line numbers are unchanged, since a masked multi-line
  value leaves its line breaks behind; **character offsets of `local_llm_artifact` now count the scrubbed text.** The
  stored excerpt is cut after the scrub too, and a private key with no END line loses its body with its header.
- **More secret shapes are masked:** JSON keys (`"password": "..."`, also escaped, also with spaces in the value),
  `NAME_PASSWORD=...` anywhere on a line, NUL-separated environments (`/proc/<pid>/environ`), passwords in URLs and
  `Authorization: Basic`. A value is treated as a reference only if all of it looks like one, so `$3cr3t!`, `/Xk29` and
  `{abc` are now masked while `$VAR`, `${VAR}`, `{{ x }}` and `/run/secrets/x` stay readable.
- **The command policy reads inside double quotes.** Bash runs `$(...)` and backticks there, but they were not segments:
  `ls "$(sudo id)"` passed an allow entry for `ls*` and no deny shape saw `sudo`. They are now judged as commands.
- **Worker traffic ignores proxy variables.** `httpx` honoured `HTTP(S)_PROXY`, which could route private material off the
  local network past the endpoint check.

### Fixed — the git gate refuses a LAN host written by its last octet
- `tools/publiccheck.py` has a new shape check, `short host address`: a dot and two or three digits written the way
  prose names a host (after whitespace, an opening bracket or quote, or the start of a line; a port or a possessive may
  follow). Before, a commit message or file that named a host this way passed every check, because only full addresses
  had a shape check. Decimals and CSS alphas, versions, file names and full addresses do not match. The new check found
  nothing in this repository's tree or history when it was added. Opt a line out with `public:allow short host address`.

### Fixed — a placeholder restores a private term exactly as it was written
- Every match of a private term now restores the text it replaced, not the term as saved. Before, only a run-together
  match did (#10): `Example, Robin`, `ROBIN EXAMPLE`, `Robin J. Example`, a double space or a line break all came
  back as `Robin Example`; an abbreviated address as the full saved address; `001 555 010 0222` as `555-010-0222`;
  `4400-1234-5678` and `440012345678` as `4400 1234 5678`; `name at example dot org` as `name@example.org`. Rehydrated
  text runs in the shell, so a reused placeholder changed the command: `grep -c '4400-1234-5678' ledger.csv`
  counted 0 instead of 1, `printf '<%s>' ACCT=4400-1234-5678` split into three arguments, and `wc -l Example,Robin`
  read a different file, `Robin`. Tests now run those commands through the server's own shell runner.
- The written forms of one term share its number: the first form seen is `[PERSON-1]`, the next spelling
  `[PERSON-1.2]`, then `[PERSON-1.3]`. A run-together form, which #10 numbered as a new value (`[PERSON-2]`), is now
  `[PERSON-1.n]`, so the next person is `[PERSON-2]` again. Disclosure counts and `local_llm_status` count values,
  not spellings: a name inside an e-mail address still registers as that person (#10), but together with the same
  name written elsewhere it counts as one `PERSON`, not two. The worker is told that `[PERSON-1.2]` is another
  spelling of `[PERSON-1]` and to copy a placeholder exactly, suffix included; the caller's instructions, which are
  capped at 2040 characters, replace "one per spelling" with that pair as the example. The placeholder pattern (`scrub.PLACEHOLDER_RE`)
  accepts the suffix, and so does the admin onboarding page's highlighter.
- A vault written before this change loads unchanged; a new spelling of a term whose saved value it holds takes
  that value's number.
- A phone term saved with a country code no longer starts a match on a separator before the number
  (`office 44 20 7946 0958` matched ` 44 …` with the leading space, and lost the space on the way back).
- Linear time: the e-mail term pattern let a whitespace run after the local part be split two ways (`\s*` around
  `\s+at\s+`), which was quadratic: measured 0.29 s at 5 KB, 1.15 s at 10 KB, 4.6 s at 20 KB, so about three hours at
  1 MB by extrapolation. It is now linear. A test times term matching and rehydration on thirteen 1 MB adversarial
  texts covering every format, and requires 1 MB to cost under 3× what 0.5 MB does.

### Changed — price table refreshed from the providers' own pages (2026-10-13)
- `prices.json` re-read from every provider's current pricing page, 34 → 57 rows, all dated 2026-10-13. Value
  changes: OpenAI now publishes cache-write prices for the astra/sol/terra/luna line; Kimi K3 publishes a cache-write
  price; Mistral publishes cached-input prices and its pricing page moved to `docs.mistral.ai`; `deepseek-v4-flash` is
  a retired name billed at the cheaper `deepseek-flash` (V4.1 Flash) price; `gemini-3.5-flash` is retired and routes to
  `gemini-3.6-flash`. Retired or legacy rows are kept and say so in `context_note` (Nova Premier past EOL, Llama 4 on
  Bedrock legacy). Added the newer models each provider lists: Claude Opus 5.5 / Sonnet 5.5 / Haiku 5.5, GPT-6.1 Sol,
  GPT-6 Sol, GPT-6 Luna, Gemini 4 Argon, Gemini 3.6 Flash, Grok 4.7, DeepSeek V4.1 Flash, Kimi K2.7 Code, GLM-5.3-Flash,
  Mistral Large 4, and the other models the pages list: Claude Fable 5, Mythos 5 and Opus 4.8, GPT-5.4 Pro, Gemini 3.1
  Flash-Lite, Grok 4.20, Kimi K2.7 Code highspeed, GLM-5.3-FlashX, MiniMax-M2.7, Llama 4 Scout. Bedrock values come from AWS's own Price List API offer file (the pricing page renders client-side).
  The headline `caller_model` assumption is unchanged (`claude-opus-5`).

### Changed — a multi-word private term also matches with its words run together
- A term of two or more words (any kind except an e-mail) also matches its words joined by nothing or by up to
  three of the separators numbers already allow (spaces, dots, dashes, slashes, brackets) or underscores:
  `Jane Example` matches `JaneExample`, `janeexample`, `jane.example`, `jane_example` and the name in
  `JANEEXAMPLE-notes`. Term matching is still whole-word, so `xjaneexample` and `janeexample2` do not match, and
  every earlier format still matches. Once a run-together form is in the session's vault, though, the scrub's
  exact match of vault values (which has no word boundaries) masks it inside longer tokens for the rest of the
  conversation: `janeexamplelaptop`, or `markdownlint` for a term `Mark Down`. An underscore joins words only and
  never separates the digits of a number. A single-word term's pattern is unchanged. The words are cut on the joiners first, so no word contains one and matching stays
  linear; tests hold eleven 100,000-character adversarial texts, five of them underscore-heavy, under one second.
- A run-together match restores exactly as written. Each run-together form gets its own vault entry and
  placeholder, so `/srv/janeexample/notes.txt`, `JaneExample/repo.git` or `jane.example-cv.pdf` comes back
  unchanged when the placeholder is reused in a command, rather than with the saved spaced name
  (`/srv/Jane Example/notes.txt`). One person can therefore appear under more than one placeholder. Text that an
  earlier format already matches is not a run-together match and still restores the saved form: words separated
  only by whitespace (a tab, a line break), and an `ADDRESS` whose parts are joined by nothing, full stops or
  commas (`12examplelane` restores as `12 Example Lane`).
- A match that is not run together is still vaulted under the saved value and restores it as before. Its
  placeholder NUMBER, and the disclosure counts, can shift, because a run-together form now also counts as a value
  of its own where nothing matched before. In the server's order, `register_material` before the scrub, the name
  inside `jane.example@example.org` is registered as an extra `PERSON` (`[PERSON-1]` = `jane.example`), so the
  next person is `[PERSON-2]`, and the disclosure dialog reports one more name. Round trips stay exact.
- A login name that is a saved name written together is now masked too, paths included. So is an ordinary word
  that happens to be a two-word term's joined form (`Mark Down` masks `markdown`, and once vaulted `markdownlint`):
  this errs toward privacy.

### Changed — private terms match in every common format
- A phone number matches with any separators or none and with or without its country code; a numeric account or
  id with any grouping; an e-mail in its usual disguises (`at`/`dot`, `[at]`, `(at)`); an address written out or
  abbreviated, with optional punctuation and line breaks; a name across line breaks, as `Last, First`, or with a
  middle initial. Previously a term matched only as written (apart from case), so `555-010-0222` missed
  `(555) 010-0222`. Near-misses (a different or longer number, `Robinson` for `Robin`) still do not match.

### Added — a guided onboarding page for private terms
- The admin app serves `/onboard`: suggestions to confirm, correct or reject (from an optional seed file, this
  machine's git identity and account name, and name variants), guidance per category, over-masking warnings, a
  *Try it* scrub preview, staged choices with an unsaved-changes guard, and a backup-status chip
  (`LOCAL_LLM_MCP_TERMS_BACKUP_STAMP`). Rejected suggestions are remembered only as hashes. New endpoints:
  `GET /api/terms/suggestions`, `POST /api/terms/review`, `POST /api/terms/lint`, `GET /api/terms/backup`,
  `DELETE /api/terms/rejections`.

### Added — optional decisions from your own worker (off by default)
- `LOCAL_LLM_MCP_DECIDE=1` adds `local_llm_decide`, `local_llm_governance` (three preset policies) and the
  `local-llm://decision-policies` resource. Your existing worker answers — no extra model or server. Left off,
  nothing of it is registered or created.
- The reply is restricted to the caller's option ids with vLLM `structured_outputs` and checked anyway; a slow
  first request or an ignored restriction falls back to a strict re-ask; the other worker is tried when one
  fails; no valid answer is `unavailable`, never a guess. By default the worker gives one sentence of
  reasoning first (`LOCAL_LLM_MCP_DECIDE_REASONING`), and `LOCAL_LLM_MCP_DECIDE_PREFER` chooses which worker
  answers first.
- The evidence is fenced as untrusted data in the prompt, so instructions or suggested answers inside it are
  ignored, and every caller string is scrubbed on its own before it leaves. See `docs/DECISIONS.md`.

### Fixed — an audit for adopters other than the maintainer
- `local_llm_run`/`local_llm_delegate`'s command execution hardcoded `executable="/bin/bash"`. On any
  system where bash isn't at that exact path (NixOS, some minimal containers) every command call raised
  an unhandled `FileNotFoundError`. Now resolved via `PATH`, with a clear refusal — not a stack trace —
  when there is none.
- The admin app's non-loopback-bind check only logged a warning before starting anyway, so binding it
  wider (a documented, supported use — `LOCAL_LLM_MCP_ADMIN_BIND` exists for exactly this) with the
  token unset served the whole PII vault to anyone who found the port. It now refuses to start; set
  `LOCAL_LLM_MCP_ADMIN_ALLOW_NO_TOKEN=1` if that is genuinely what you want.

### Changed — nothing is pushed automatically; main moves only through a pull request
- `--autopush` and its `post-commit` hook are gone. They pushed every commit the moment it landed, on whatever
  branch — `main` included — so work went public with no review. A commit is not a reason to publish: push
  when the work is ready. `install-hooks.sh` clears the old setting from a clone that had it.
- `pre-push` refuses a direct push that moves an existing `main`, and still scans the commits so every problem
  is reported at once. A first push that creates the branch is allowed, and so is every push of any other
  branch. `LOCAL_LLM_MCP_ALLOW_MAIN_PUSH=1` overrides once.
- `pre-push` also runs the user's own global `pre-push` (from `git config --global core.hooksPath`). This repository's
  local hooks path replaces the global hooks, which silently switched off any machine-wide guard (for example one that
  refuses to push a secret from the user's key files). Nothing changes where no global hooks are configured.
- The history scan accepts GitHub as the **committer** of a pull request merged on the site (it names no one).
  The author is still checked. Without this, the first merge through a pull request failed the repository's
  own history check on any machine with an identity configured.

### The command policy

The opt-in gate decides whether the server works at all; this decides what it executes. Every command
a caller hands to `local_llm_run` — or to `local_llm_delegate`'s `command`, the same shell — runs with
the user's privileges, and a client in a bypass or auto permission mode never shows a per-tool prompt.
The server now holds its own line, in three layers.

- **Deny shapes** are refused outright, nothing run, the reason returned: privilege escalation, power
  state, filesystem and device writes, `dd of=`, recursive `rm`/`chmod`/`chown`, package installs,
  `shred`, a pipe from `curl`/`wget` into a shell, and any write under `/etc`, `/boot` or `~/.ssh`
  (reading them is untouched). Deny shapes are judged per command-line segment, so a quoted mention
  in an argument is not a match and a second command after a `;` is not hidden by the first.
- **A secret is never handed to a shell.** A command containing a placeholder that would rehydrate to
  a `[SECRET-n]` is refused. This *removes* a previously advertised behaviour — such placeholders used
  to be expanded server-side — because a command is not a boundary the server can hold.
- **An allow list** the user owns: one glob per line in `~/.config/local-llm-mcp/run-allow.txt`
  (`LOCAL_LLM_MCP_RUN_ALLOW`). Every segment of a command must match an entry, and for a multiplexer
  the subcommand is part of the shape — `git log*` is not `git push*`.
- **Everything else asks**, through the same MCP elicitation as the gate, showing the exact command and
  its working directory: refuse / run once / always allow this shape. "Always" appends the shape to the
  file. The dialog lists **refuse** first and has no default, so a client that auto-accepts a form can
  never approve a command. No allow entry and no dialog answer can exempt a deny shape.
- A client that cannot show a dialog gets the deny shapes and a trailer line saying it was not asked.
  `LOCAL_LLM_MCP_RUN_POLICY=ask|allow|off` chooses how much of this runs; a session stops asking after
  12 dialogs.
- Every decision is stamped on the turn and in the trailer (`policy: allow-list (ls*)`), counted in
  `local_llm_status.run_policy`, and shown as a chip on the session's row in the admin app.

It is deliberately not a sandbox: it reads command position, quoting and redirection well enough to
judge shapes, and does not follow a script it invokes, a variable it expands, or an alias.

### Fixed — one client's approval could arm another

A server spawned by a **different** agent harness that had itself been launched from inside a Claude
Code session adopted that session's id: its vault, its memory, and its answer to the opt-in gate.
Found by running the Codex CLI against this server for the first time — it landed in the Claude Code
conversation that started it.

The session is now keyed by the **nearest real ancestor**, and Claude Code's pidmap is consulted only
when Claude Code is the process that spawned the server. Another harness gets its own pid-keyed
session and is asked the turn-on question for itself, which is the whole point of the gate.

### Verified against the other agent CLIs
- **Kimi Code CLI**: its config home is `~/.kimi-code/`, and 0.37 no longer reads `~/.kimi/` — the
  registration this README gave was in a directory the installed client ignores, which is why it had
  never connected. Corrected. It declares **no elicitation**, so it needs `LOCAL_LLM_MCP_ARM=on` and
  an allow list; with those it returned the digest and the full trailer.

### Decided
- **PyPI is not a target.** Publishing a package is a support commitment the author is not taking;
  the install path is git. `ROADMAP.md` is gone with it — both items it held are settled, one built
  and one declined.

### Fixed
- A code comment in the identity-shape layer used a real machine name from the author's own network as
  its example of a benign over-match. Replaced with an invented one. An adversarial audit found it; the
  gate did not, because a name has no shape a regex can see — which is what the hardening below is for.

### The publication gate, hardened
- **A refusal no longer prints what it caught** unless stderr is a terminal (or `--show-values`). CI
  logs are world-readable on a public repository, so a failing check could previously publish the very
  value it refused.
- **Lockfiles and every other text file are scanned.** Only binary formats are skipped.
- **Annotated tags are scanned** — message and tagger — by `pre-push` and by `--all`; `git rev-list`
  never shows either.
- New checks: **public IPv4** addresses (loopback, link-local, multicast and the RFC 5737 documentation
  ranges excluded) and **IPv6 unique-local / link-local**. Home paths now also match the root account's
  home, `/Users/…`, Windows `C:\Users\…` (single- or double-backslashed), and a path with no trailing
  slash.
- A **real subnet** such as a `/24` is now refused; RFC range constants are allowed by value, so
  documentation and code may still name them without an opt-out.
- `public:allow` may **name the check** it exempts; a bare one still exempts the shape checks, and
  **neither form can ever exempt a denylist term**.
- A denylist term containing a space also matches the underscore and hyphen forms.
- With no denylist present the output **says the name-based checks did not run** instead of "clean".
- `pre-commit` **refuses** when gitleaks is installed but cannot run, rather than recording a commit no
  secret scanner has read (`LOCAL_LLM_MCP_ALLOW_NO_GITLEAKS=1` overrides once).
- `LOCAL_LLM_MCP_DENYLIST` pointing at a file that does not exist is now an **error**, not a silent
  degrade — a typo used to disable every name-based check while still printing a pass. Leaving the
  variable unset still means "no list", which is how CI runs.
- `.gitignore` now covers the instance material the README tells you to keep beside the code — the
  dotenv, key and PEM files, the private terms, a prices override, a denylist copy — root-anchored so
  the package's own `prices.json` stays tracked.

## 0.1.0 — 2026-09-09

First tagged release. Everything below is in it.

### The boundary
- Two modes: **PII** (every private value comes back as a stable placeholder, rehydrated server-side when reused)
  and **ASSIST** (secrets always masked; account/card/id/DOB numbers masked by default; identity values shown
  only after the user says so).
- Layered deterministic detection: a rules file, built-in secret shapes, private terms, an identity-shape layer
  (addresses, labelled names, dates of birth, id numbers by shape alone), a worker entity pass over the material
  in PII mode, and — new in this release — an **answer pass** in PII mode that asks the worker what private
  values the scrubbed answer still holds and masks those too (trailer: `leak-check ok` / `leak-check FAILED`).
- Worker error text is scrubbed before it is returned.
- The **disclosure lifecycle**: the first time identity or number values appear in an ASSIST session the server
  asks the user directly through MCP elicitation; `local_llm_disclosure` records a decision made in chat;
  `LOCAL_LLM_MCP_ESCALATION=ask|auto|off`.
- The endpoint must be loopback, private-LAN or CGNAT; anything else is refused at startup.

### The opt-in gate
- The server does nothing in a session until the user turns it on: the first working tool call (or
  `local_llm_enable`) asks the user in a dialog — on / on in PII mode / off. "Off" is remembered. A client that
  cannot show a dialog is refused with the instructions for enabling it explicitly (`LOCAL_LLM_MCP_ARM=on`, or
  the admin app's per-session switch). Connect-time instructions only offer the server.
- The dialog is default-safe by construction: the answer is required, has no default, and lists "off" first,
  so a client that auto-accepts a form can never turn the server on.

### Working with the worker
- `local_llm_run` (command → digest), `local_llm_delegate` (task over files / inline material / a command),
  `local_llm_artifact` (exact slices of stored raw output), `local_llm_compact`, `local_llm_set_mode`,
  `local_llm_status` (works while off), `local_llm_enable`, `local_llm_disclosure`.
- **Verbatim mode**: the worker only locates line ranges and the server quotes them byte-exact; falls back to a
  digest when nothing matches.
- The worker keeps its own running memory of the conversation, compacted when the caller's is (PreCompact hook
  over a control socket) and when it grows large.
- **Failover** to a second local worker when the first is unreachable or answers 5xx, with a cooldown.
- Client-agnostic: any stdio MCP client; the instructions are also an MCP prompt and a resource; the session
  records its client.

### Tokens saved
- Every counted turn records what was gathered and what was returned; exact token counts come from the worker's
  own tokenizer in the background, with a characters-per-token fallback; a cross-session ledger; list prices for
  34 flagship models with a source and date per row, an override file, a staleness flag, and an admin tab.
- Per-model **tokenizer factor** (new): counts are the worker tokenizer's; each price row may carry the ratio of
  that model's tokenizer to it, applied at pricing time. Seeded at 1.3 for the Claude 4.7+ tokenizer family.

### Operating it
- Admin app: private terms, session vaults, memory and artifacts, scrub tester, prices editor, per-session gate
  and disclosure state.
- `--check` probes every configured worker; `tools/smoke.py` drives every feature over stdio, the dialogs
  included; `tools/leakcheck.py` runs a real secrets file through PII mode; `tools/piicheck.py` runs adversarial
  tasks over synthetic private data in both modes.

### Repository hygiene
- `tools/publiccheck.py` refuses deployment-specific or personal content in the tree, in staged changes, in commit
  messages and identities, and in every commit a push would publish (`--range`, `--all`), with an operator-private
  denylist reported by line number only.
- Tracked git hooks (`tools/githooks/`, installed per clone by `tools/install-hooks.sh`, local git config only)
  enforce it at pre-commit, commit-msg and pre-push; CI re-runs the tree and whole-history checks.
