"""Command policy: what may actually be executed when a caller delegates a shell command.

The opt-in gate (:mod:`.arming`) covers turning the server ON for a session. After that,
every command the caller chooses runs here with this user's privileges — and a client in a
bypass or auto permission mode never shows the user a per-tool prompt, so the client's own
approval layer cannot be relied on. This module is the server's own line, in three layers:

1. **Deny shapes** — refused outright, nothing run, the reason returned to the caller. Shapes
   only: destructive or privilege-changing verbs, package installs, a pipe from the network
   into a shell, and writes into ``/etc``, ``/boot`` or ``~/.ssh``. A command that would
   rehydrate a **secret** placeholder is refused too — a secret is never handed to a shell.
2. **An allow list** the operator keeps (``LOCAL_LLM_MCP_RUN_ALLOW``, one glob per line): the
   standing approval for the shapes they delegate every day (``git log*``, ``journalctl*``,
   ``ls*``, ``rg*``, ``pytest*``). Every segment of the command must match one.
3. **Everything else asks** — the same MCP elicitation the gate uses, showing the exact
   command: run once / always allow this shape / refuse. "Always" appends to the allow file.
   A client that cannot ask is refused (``LOCAL_LLM_MCP_UNASKED=refuse``, the default) or, with
   ``LOCAL_LLM_MCP_UNASKED=run``, gets layer 1 only and a trailer line saying so.

No allow entry can exempt a deny shape; layer 1 is checked first, always.

Non-goals, deliberately: this is not a sandbox and does not parse shell semantics. It reads
command position, quoting and redirection well enough to judge shapes, and it does not try to
follow a script it invokes, a variable it expands, or an alias. It is a second lock on a door
the user already opened, not a jail.
"""
from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from pydantic import BaseModel, Field

from .scrub import PLACEHOLDER_RE

RUN_POLICIES = ("ask", "allow", "off")
CHOICES = ("refuse", "once", "always")  # "refuse" FIRST: a client that auto-fills a form with its first option can never approve a command
CHOICE_TEXT = {
    "refuse": "Don't run it",
    "once": "Run this command, this once",
    "always": "Run it, and stop asking for commands of this shape",
}
MAX_ASKS = 12  # per session; past this the answer is "refuse" without a dialog

# Programs whose FIRST argument is really part of the name, so the remembered shape is
# "git log*", not "git*" — approving `git log` must not approve `git push --force`.
SUBCOMMAND_PROGRAMS = frozenset({
    "git", "docker", "podman", "systemctl", "journalctl", "kubectl", "npm", "pnpm", "yarn",
    "uv", "uvx", "pip", "pip3", "cargo", "go", "gh", "apt", "apt-get", "dnf", "brew", "conda",
    "poetry", "make", "terraform", "aws", "gcloud", "az", "helm", "flatpak", "snap", "rustup",
})
# Wrappers that precede the real program; the shape is taken from what follows.
_WRAPPERS = frozenset({"env", "nohup", "time", "command", "exec", "nice", "ionice", "stdbuf", "setsid"})

_INSTALL_PROGRAMS = frozenset({
    "apt", "apt-get", "aptitude", "dnf", "yum", "zypper", "pacman", "apk", "emerge", "brew",
    "snap", "flatpak", "pip", "pip3", "pipx", "npm", "pnpm", "yarn", "gem", "cargo", "go",
    "uv", "conda", "poetry", "rustup", "nix-env",
})
_INSTALL_SUBCOMMANDS = frozenset({
    "install", "uninstall", "remove", "purge", "erase", "add", "upgrade", "update", "reinstall",
    "-s", "-sy", "-syu", "-r", "-u",  # pacman short forms
})
# Programs that WRITE to the paths they are given; the protected-path rule only fires for these.
_MUTATING = frozenset({"rm", "rmdir", "mv", "cp", "tee", "install", "truncate", "shred", "dd",
                       "chmod", "chown", "chgrp", "ln", "mkdir", "touch", "rsync"})
# For these the destination is the LAST argument, so naming a protected path as a SOURCE is fine
# (`cp /etc/hosts /tmp/` reads; `cp x /etc/hosts` writes).
_DEST_LAST = frozenset({"mv", "cp", "install", "ln", "rsync"})
PROTECTED_PATHS = ("/etc", "/boot", "~/.ssh")
# Writing to these devices is normal and universal; every other /dev target is a device write.
_SAFE_DEVICES = frozenset({"null", "stdout", "stderr", "zero", "full", "tty", "fd"})

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^\n]*?\|\s*(?:sudo\s+|doas\s+|env\s+[^|]*)?(?:/[\w./-]*/)?(?:ba|z|k|da|fi|a)?sh\b", re.I)
_DEVICE_WRITE_RE = re.compile(r">>?\s*(?:/dev/(?P<dev>[\w/]+))")
_REDIRECT_RE = re.compile(r">>?\s*(?P<target>[^\s;&|)<>]+)")


@dataclass(frozen=True)
class Decision:
    """What the policy concluded about one command."""

    verdict: str          # "deny" | "allow" | "ask"
    rule: str = ""        # the deny shape's label, or the allow glob that matched
    reason: str = ""      # one line, safe to return to the caller (never a secret value)
    segment: str = ""     # the part of the command the deny shape matched

    @property
    def label(self) -> str:
        """The short token stamped on the turn and shown in the trailer and the admin app."""
        if self.verdict == "deny":
            return f"refused: {self.rule}"
        if self.verdict == "allow":
            return f"allow-list ({self.rule})" if self.rule else "allowed"
        return "ask"


class RunChoice(BaseModel):
    """The dialog's one field. Primitive on purpose (elicitation allows nothing else)."""

    choice: str = Field(
        description="refuse | once | always",
        json_schema_extra={"enum": list(CHOICES), "enumNames": [CHOICE_TEXT[c] for c in CHOICES]},
    )


# --------------------------------------------------------------------------- parsing


def _substitution_end(command: str, start: int) -> int:
    """Index of the character closing the ``$(`` or backtick at ``start``; ``len(command)`` when it
    is never closed, so an unterminated substitution is judged to the end of the line."""
    n = len(command)
    if command[start] == "`":
        i = start + 1
        while i < n:
            if command[i] == "\\":
                i += 2
                continue
            if command[i] == "`":
                return i
            i += 1
        return n
    depth, quote, i = 1, "", start + 2
    while i < n:
        c = command[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if not depth:
                return i
        i += 1
    return n


def _heredoc_word(command: str, j: int) -> tuple[int, str, bool, bool]:
    """Read the delimiter after ``<<`` at ``j``: (index after it, delimiter, ``<<-``, quoted).
    Any quote or backslash in the word makes the body literal, as in bash."""
    n = len(command)
    strip = j < n and command[j] == "-"
    j += 1 if strip else 0
    while j < n and command[j] in " \t":
        j += 1
    word: list[str] = []
    quote, quoted = "", False
    while j < n:
        c = command[j]
        if quote:
            if c == quote:
                quote = ""
            else:
                word.append(c)
            j += 1
            continue
        if c in "'\"":
            quote, quoted = c, True
        elif c == "\\" and j + 1 < n:
            word.append(command[j + 1])
            quoted = True
            j += 1
        elif c.isspace() or c in ";|&<>()":
            break
        else:
            word.append(c)
        j += 1
    return j, "".join(word), strip, quoted


def _body_substitutions(body: str) -> list[str]:
    """The commands bash runs while expanding an UNQUOTED heredoc body: its ``$(...)`` and backticks."""
    out: list[str] = []
    k, n = 0, len(body)
    while k < n:
        if body[k] == "\\":
            k += 2
            continue
        if body[k] == "`" or body.startswith("$(", k):
            end = _substitution_end(body, k)
            out.extend(split_segments(body[k + (1 if body[k] == "`" else 2):end]))
            k = end + 1
            continue
        k += 1
    return out


def split_segments(command: str) -> list[str]:
    """Split a command line on the shell operators that start a NEW command — ``;``, ``&&``,
    ``||``, ``|``, ``&`` and newline — respecting quotes, so ``grep 'a|b' x`` stays one segment.
    Subshell punctuation is dropped. Every segment is judged on its own.

    Double quotes do not stop bash from running a ``$(...)`` or a backtick command inside them, so
    those commands are segments too: ``ls "$(sudo id)"`` is judged as ``ls …`` AND ``sudo id``.

    A heredoc body is input, not commands: ``tool <<'EOF'`` stays one segment and its body lines
    are not judged. An unquoted delimiter (``<<EOF``) still lets bash run the body's ``$(...)``
    and backticks, so those become segments."""
    return _split(command)[0]


def _arith_end(command: str, start: int) -> int:
    """Index of the ``))`` closing the arithmetic that starts at ``start``; ``len(command)`` if never closed."""
    depth, i, n = 0, start, len(command)
    while i < n:
        if command[i] == "(":
            depth += 1
        elif command[i] == ")":
            if not depth and command.startswith("))", i):
                return i
            depth = max(0, depth - 1)
        i += 1
    return n


def _split(command: str, arith: bool = False) -> tuple[list[str], list[tuple[int, int]]]:
    """``split_segments``, plus the spans of literal (quoted-delimiter) heredoc bodies.
    ``arith``: inside ``((…))``, where ``<<`` is a shift, never a heredoc."""
    out: list[str] = []
    buf: list[str] = []
    literal: list[tuple[int, int]] = []
    heredocs: list[tuple[str, bool, bool]] = []
    quote = ""
    i = 0
    n = len(command)
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 2
                continue
            if quote == '"' and (c == "`" or command.startswith("$(", i)):
                end = _substitution_end(command, i)
                out.extend(split_segments(command[i + (1 if c == "`" else 2):end]))
                buf.append(command[i + 1:end + 1])  # kept whole: its quotes must not end this string
                i = end + 1
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "'\"":
            quote = c
            buf.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if command.startswith("((", i) or command.startswith("$((", i):
            # Arithmetic: its `<<` is a shift. A `$(...)` inside it still runs, so it is still read.
            s = i + (3 if c == "$" else 2)
            end = _arith_end(command, s)
            out.append("".join(buf))
            buf = []
            out.extend(_split(command[s:end], arith=True)[0])
            i = end + 2
            continue
        if command.startswith("<<<", i):  # a here-string: one word of input, no body
            buf.append("<<<")
            i += 3
            continue
        if command.startswith("<<", i) and not arith:
            j, delim, strip, quoted = _heredoc_word(command, i + 2)
            buf.append(command[i:j] if delim else "<<")
            if delim:
                heredocs.append((delim, strip, quoted))
            i = j if delim else i + 2
            continue
        if c == "\n" and heredocs:
            # The bodies start on the next line, one after another, each up to its delimiter line.
            out.append("".join(buf))
            buf = []
            i += 1
            for delim, strip, quoted in heredocs:
                start = i
                while i < n:
                    end = command.find("\n", i)
                    end = n if end < 0 else end
                    line = command[i:end]
                    if (line.lstrip("\t") if strip else line) == delim:
                        body_end, i = i, end + 1
                        break
                    i = end + 1
                else:
                    body_end = n
                if quoted:
                    literal.append((start, body_end))
                else:
                    out.extend(_body_substitutions(command[start:body_end]))
            heredocs = []
            continue
        if c == "&" and not command.startswith("&&", i):
            # A lone & is a separator only when it is not part of a redirection
            # (`2>&1`, `&>log`): those keep the segment whole.
            prev = "".join(buf).rstrip()[-1:]
            nxt = command[i + 1:i + 2]
            if prev == ">" or nxt == ">" or nxt.isdigit() or nxt == "-":
                buf.append(c)
                i += 1
                continue
        if c in ";|&\n" or (c == "$" and command.startswith("$(", i)):
            if c == "$":
                out.append("".join(buf))
                buf = []
                i += 2
                continue
            out.append("".join(buf))
            buf = []
            i += 2 if command[i:i + 2] in ("&&", "||") else 1
            continue
        if c in "()`":
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()], literal


def _tokens(segment: str) -> list[str]:
    """Cheap word split that keeps quoted arguments whole and strips their quotes."""
    out: list[str] = []
    buf: list[str] = []
    quote = ""
    for c in segment:
        if quote:
            if c == quote:
                quote = ""
            else:
                buf.append(c)
            continue
        if c in "'\"":
            quote = c
            continue
        if c.isspace():
            if buf:
                out.append("".join(buf))
                buf = []
            continue
        buf.append(c)
    if buf:
        out.append("".join(buf))
    return out


def _program(tokens: Sequence[str]) -> tuple[str, list[str]]:
    """The real program and its arguments: leading ``VAR=value`` assignments and wrappers skipped,
    a path reduced to its basename (``/usr/bin/sudo`` is ``sudo``)."""
    rest = list(tokens)
    while rest and (_ASSIGNMENT_RE.match(rest[0]) or os.path.basename(rest[0]) in _WRAPPERS):
        rest = rest[1:]
    if not rest:
        return "", []
    return os.path.basename(rest[0]).lower(), rest[1:]


def shape_for(command: str) -> str:
    """The glob for ONE segment: the program (plus its subcommand, for a multiplexer like git) and
    a trailing ``*``. Falls back to the exact text when there is nothing to generalise."""
    prog, args = _program(_tokens(command))
    if not prog:
        return command.strip()
    if prog in SUBCOMMAND_PROGRAMS and args and not args[0].startswith("-"):
        return f"{prog} {args[0]}*"
    return f"{prog}*"


def shapes_for(command: str) -> list[str]:
    """Every shape "always allow" must remember for this command line. A match needs every segment,
    so ``git log … | head -5`` teaches two shapes, not one — otherwise "always" would answer the
    dialog and then ask again on the very next identical command."""
    out: list[str] = []
    for seg in split_segments(command) or [command.strip()]:
        sh = shape_for(seg)
        if sh and sh not in out:
            out.append(sh)
    return out


def _expand(token: str) -> str:
    t = os.path.expandvars(token)
    if t.startswith("~"):
        t = os.path.expanduser(t)
    return t


def _protected(token: str) -> str:
    """The protected prefix this token falls under, or "" — after ~ and $HOME expansion."""
    path = _expand(token)
    if not path.startswith("/"):
        return ""
    norm = os.path.normpath(path)
    for prot in PROTECTED_PATHS:
        base = os.path.normpath(os.path.expanduser(prot))
        if norm == base or norm.startswith(base.rstrip("/") + "/"):
            return prot
    return ""


# --------------------------------------------------------------------------- deny shapes


def _deny_segment(segment: str) -> tuple[str, str]:
    """(label, reason) for the first deny shape this ONE segment matches, else ("", "")."""
    tokens = _tokens(segment)
    prog, args = _program(tokens)
    flags = [a for a in args if a.startswith("-")]
    short = "".join(a.lstrip("-") for a in flags if not a.startswith("--"))

    if prog in ("sudo", "doas", "pkexec", "su"):
        return "privilege escalation", f"{prog} runs as another user; this server only ever runs as you"
    if prog in ("shutdown", "reboot", "halt", "poweroff", "init", "systemctl-halt"):
        return "power state", f"{prog} would stop or restart this machine"
    if prog.startswith("mkfs") or prog in ("mkswap", "fdisk", "sfdisk", "parted", "wipefs"):
        return "filesystem", f"{prog} writes filesystem or partition structures"
    if prog == "dd" and any(a.startswith("of=") for a in args):
        return "dd of=", "dd writing to a target overwrites it in place"
    if prog == "rm" and ("r" in short or "--recursive" in flags or "-R" in flags):
        return "recursive rm", "a recursive delete is not something to run on a model's say-so"
    if prog in ("chmod", "chown", "chgrp") and ("R" in short or "--recursive" in flags):
        return f"recursive {prog}", f"a recursive {prog} rewrites a whole tree's ownership or permissions"
    if prog in _INSTALL_PROGRAMS:
        head = [a.lower() for a in args[:3] if not _ASSIGNMENT_RE.match(a)]
        if any(a in _INSTALL_SUBCOMMANDS for a in head):
            return "package install", f"{prog} would install, upgrade or remove packages on this machine"
    if prog in ("shred", "srm"):
        return "shred", "shred destroys data irrecoverably"

    m = _DEVICE_WRITE_RE.search(segment)
    if m and m.group("dev").split("/")[0] not in _SAFE_DEVICES:
        return "device write", f"writing to /dev/{m.group('dev')} writes to a device, not a file"

    for m in _REDIRECT_RE.finditer(segment):
        prot = _protected(m.group("target"))
        if prot:
            return "protected path", f"redirecting output into {prot} changes system or credential state"
    if prog in _MUTATING:
        targets = args[-1:] if prog in _DEST_LAST else args
        for a in targets:
            if a.startswith("-"):
                continue
            prot = _protected(a)
            if prot:
                return "protected path", f"{prog} would write under {prot}"
    if prog == "sed" and any(a.startswith("-i") or a == "--in-place" for a in flags):
        for a in args:
            prot = _protected(a)
            if prot:
                return "protected path", f"an in-place edit under {prot} changes system state"
    return "", ""


def deny_reason(command: str) -> tuple[str, str, str]:
    """(label, reason, segment) for the first deny shape the command matches, else ("", "", "")."""
    segments, literal = _split(command)
    code = command
    for start, end in reversed(literal):  # a literal heredoc body is text the program reads, not shell
        code = code[:start] + code[end:]
    if _PIPE_TO_SHELL_RE.search(code):
        return "network pipe to shell", "piping a download straight into a shell runs code nobody has read", command.strip()
    for seg in segments:
        label, reason = _deny_segment(seg)
        if label:
            return label, reason, seg
    return "", "", ""


# --------------------------------------------------------------------------- the allow list


class AllowList:
    """The operator's standing approvals: one glob per line in a file they own.

    Missing file means an empty list, not an error — the server simply asks about everything.
    ``#`` comments and blank lines are ignored. Appends are made by the "always" answer to the
    dialog, so the file is the record of what the user has approved and can be edited by hand.
    """

    def __init__(self, path: Path | None):
        self.path = Path(path).expanduser() if path else None
        self.entries: list[str] = []
        self.load()

    def load(self) -> list[str]:
        self.entries = []
        if self.path and self.path.is_file():
            for raw in self.path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    self.entries.append(line)
        return self.entries

    def matches(self, command: str) -> str:
        """The glob that covers this command, or "". EVERY segment must match an entry: a standing
        approval for ``ls*`` is not an approval for ``ls; something-else``."""
        if not self.entries:
            return ""
        segs = split_segments(command) or [command.strip()]
        hit: list[str] = []
        for seg in segs:
            for glob in self.entries:
                if fnmatch.fnmatchcase(seg, glob) or seg == glob:
                    hit.append(glob)
                    break
            else:
                return ""
        return ", ".join(dict.fromkeys(hit))

    def add_all(self, globs: Sequence[str]) -> bool:
        """Append every shape a command needs. False when any of them could not be written."""
        return all([self.add(g) for g in globs]) and bool(globs)

    def add(self, glob: str) -> bool:
        """Append a glob (idempotent). Returns False when there is nowhere to write it."""
        glob = glob.strip()
        if not glob or self.path is None:
            return False
        if glob in self.entries:
            return True
        self.path.parent.mkdir(parents=True, exist_ok=True)
        header = "" if self.path.exists() else (
            "# local-llm-mcp: commands that may run without asking. One glob per line;\n"
            "# every segment of a command line must match an entry. Deny shapes always win.\n")
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(header + glob + "\n")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass
        self.entries.append(glob)
        return True


# --------------------------------------------------------------------------- the decision


def secret_placeholders_in(command: str, secrets: Iterable[str]) -> list[str]:
    """Placeholders in the command that would rehydrate to a secret."""
    wanted = set(secrets)
    return [m.group(0) for m in PLACEHOLDER_RE.finditer(command) if m.group(0) in wanted]


def check(command: str, allow: AllowList | None = None, secrets: Iterable[str] = (),
          expanded: str | None = None) -> Decision:
    """Judge one command. Deny shapes first — no allow entry can exempt them.

    ``command`` is what the caller wrote, placeholders and all: that is what the secret check
    reads and what the user is shown. ``expanded`` is the same command after rehydration, if it
    differs — the deny shapes are checked against BOTH, so a placeholder cannot smuggle a
    protected path past them.
    """
    command = command.strip()
    if not command:
        return Decision("deny", "empty", "there is no command to run")
    leaked = secret_placeholders_in(command, secrets)
    if leaked:
        return Decision("deny", "secret in command",
                        f"{', '.join(leaked)} stands for a secret, and a secret is never handed to a shell. "
                        "Ask the user to run this themselves, or use a form of the command that reads the "
                        "secret from a file or the environment.")
    try:
        for text in (command,) if not expanded or expanded == command else (command, expanded):
            label, reason, segment = deny_reason(text)
            if label:
                return Decision("deny", label, reason, segment if text == command else "")
        glob = allow.matches(command) if allow else ""
    except RecursionError:  # substitutions nested past what can be read are not approved unread
        return Decision("deny", "nesting", "this command nests substitutions too deeply to be judged")
    if glob:
        return Decision("allow", glob)
    return Decision("ask")


def dialog_message(command: str, cwd: str, shapes: Sequence[str]) -> str:
    """What the human sees: the exact command, in full."""
    shown = command if len(command) <= 900 else command[:880] + " …(truncated for display)"
    where = cwd or "the server's own working directory"
    return (
        "local-llm-mcp wants to run a command on this machine, as you.\n\n"
        f"    {shown}\n\n"
        f"Working directory: {where}\n"
        f"• refuse — {CHOICE_TEXT['refuse']}\n"
        f"• once — {CHOICE_TEXT['once']}\n"
        f"• always — {CHOICE_TEXT['always']} ({', '.join(shapes)})\n"
        "Cancel refuses it."
    )


def refusal_text(d: Decision) -> str:
    """What the caller gets instead of a result. Names the shape, never invents a workaround."""
    where = f" (in: {d.segment[:160]})" if d.segment and d.segment.strip() != "" else ""
    return (f"[local-llm-mcp] REFUSED — {d.rule}{where}: {d.reason}. Nothing was run. This server refuses this "
            "shape of command whatever the client's permission mode; the user can run it themselves, or you can "
            "propose a narrower command.")


def user_refusal_text(command: str) -> str:
    return ("[local-llm-mcp] REFUSED: the user was asked about this command and declined. Nothing was run. "
            "Do not retry it; ask the user what they would prefer.")


def unanswered_text(action: str) -> str:
    return (f"[local-llm-mcp] NOT RUN: the user did not answer the dialog asking whether to run this command "
            f"({action}). Nothing was run.")


NO_DIALOG_NOTE = "policy: not asked (this client cannot show the user a dialog)"
UNASKED_REFUSED_LABEL = "refused: not in allow list and client cannot ask"


def unasked_refusal_text(allow_path) -> str:
    """RUN_POLICY=ask, a client with no dialog, LOCAL_LLM_MCP_UNASKED=refuse."""
    return ("[local-llm-mcp] REFUSED: this command is not on the user's allow list, and this client cannot show "
            "the user a dialog to ask about it. Nothing was run. Do not try to get around this refusal — not with "
            "another tool, a rewritten command, or a script that runs it. If the user wants commands of this shape "
            f"to run, they can add the shape (a glob such as 'git log*') to {allow_path}.")
