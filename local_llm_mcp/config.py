"""Configuration: ``LOCAL_LLM_MCP_*`` environment variables, optionally seeded from a
dotenv file.

Precedence: process environment > dotenv file (``~/.config/local-llm-mcp/env`` by
default, ``LOCAL_LLM_MCP_ENV_FILE`` overrides) > built-in defaults. Nothing
deployment-specific lives in this package: endpoint, key, rules, private terms and
observer all come from the environment, so the same code serves every install.

One rule is enforced here and cannot be configured away: the model endpoint must
be a loopback, private-network (RFC 1918) or CGNAT/tailnet address. This server
exists so private material never leaves the local network.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ENV_PREFIX = "LOCAL_LLM_MCP_"
MODES = ("pii", "assist")
ESCALATIONS = ("ask", "auto", "off")  # first identity/number values in an ASSIST session
RUN_POLICIES = ("ask", "allow", "off")  # what happens to a command that is not on the allow list
UNASKED_POLICIES = ("refuse", "run")  # RUN_POLICY=ask with a client that cannot show a dialog
DEFAULT_ENV_FILE = "~/.config/local-llm-mcp/env"
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ConfigError(RuntimeError):
    pass


def load_env_file(path: str | None = None) -> int:
    """Seed ``os.environ`` from a KEY=VALUE file without overriding what is already set.

    Accepts plain dotenv lines, ``export KEY=VALUE``, quoted values, ``#`` comments
    and ``$HOME``-style references. Returns the number of variables it set.
    """
    p = Path(os.environ.get(ENV_PREFIX + "ENV_FILE") or path or DEFAULT_ENV_FILE).expanduser()
    if not p.is_file():
        return 0
    n = 0
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if not _KEY_RE.fullmatch(key):
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        value = os.path.expandvars(value)
        if key not in os.environ:
            os.environ[key] = value
            n += 1
    return n


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(ENV_PREFIX + name, default)


def _int(name: str, default: int) -> int:
    raw = _env(name)
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = _env(name)
    try:
        return float(raw) if raw not in (None, "") else default
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw in (None, ""):
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _path(name: str, default: str) -> Path:
    return Path(_env(name, default) or default).expanduser()


def _opt_path(name: str) -> Path | None:
    raw = _env(name)
    return Path(raw).expanduser() if raw else None


def default_sock_dir() -> str:
    """AF_UNIX paths are capped at 108 bytes: prefer the short per-user runtime dir."""
    run = os.environ.get("XDG_RUNTIME_DIR")
    if run and os.path.isdir(run):
        return os.path.join(run, "local-llm-mcp")
    return os.path.expanduser("~/.local/state/local-llm-mcp/sock")


def _load_api_key(prefix: str = "") -> str:
    key = (_env(prefix + "API_KEY") or "").strip()
    if key:
        return key
    key_file = _env(prefix + "API_KEY_FILE")
    if key_file:
        p = Path(key_file).expanduser()
        if not p.is_file():
            raise ConfigError(f"{ENV_PREFIX}{prefix}API_KEY_FILE={p} does not exist")
        return p.read_text(encoding="utf-8").strip()
    return ""


def assert_local_endpoint(base_url: str) -> None:
    """Refuse any endpoint that is not loopback, private or CGNAT/tailnet."""
    host = urlparse(base_url).hostname
    if not host:
        raise ConfigError(f"{ENV_PREFIX}BASE_URL={base_url!r} has no host")
    if host == "localhost":
        return
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except OSError as exc:
            raise ConfigError(f"cannot resolve {host!r} for the model endpoint: {exc}") from exc
    if ip.is_loopback or ip.is_private or (ip.version == 4 and ip in _CGNAT):
        return
    raise ConfigError(
        f"{ENV_PREFIX}BASE_URL={base_url} resolves to {ip}, which is not a loopback, private-network "
        "or CGNAT address. local-llm-mcp only ever talks to a local model; refusing to start."
    )


@dataclass
class Config:
    mode: str
    base_url: str
    model: str
    api_key: str
    fallback_base_url: str
    fallback_model: str
    fallback_api_key: str
    failover_cooldown: float
    thinking: bool
    max_output_chars: int
    max_tokens_cap: int
    llm_timeout: float
    chunk_chars: int
    parallel_chunks: int
    material_max_chars: int
    context_chars: int
    excerpt_chars: int
    summary_chars: int
    auto_compact_chars: int
    command_timeout: float
    strict_pii: bool
    entity_pass: bool
    escalation: str
    arm: str
    run_policy: str
    unasked: str
    run_allow_path: Path
    assist_numbers: str
    dialog_timeout: float
    shapes: bool
    prices_path: Path
    caller_model: str
    state_dir: Path
    sock_dir: Path
    rules_path: Path | None
    private_terms_path: Path
    terms_seed_path: Path
    terms_backup_stamp: Path | None
    observer: str
    observer_path: Path | None
    observer_url: str
    decide: bool
    decide_prefer: str
    decide_timeout: float
    decide_reasoning: bool
    session_override: str
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        mode = (_env("MODE", "assist") or "assist").strip().lower()
        if mode not in MODES:
            raise ConfigError(f"{ENV_PREFIX}MODE must be one of {MODES}, got {mode!r}")
        base_url = (_env("BASE_URL", "http://127.0.0.1:8000/v1") or "").rstrip("/")
        assert_local_endpoint(base_url)
        fallback_base_url = (_env("FALLBACK_BASE_URL", "") or "").strip().rstrip("/")
        if fallback_base_url:
            assert_local_endpoint(fallback_base_url)
        arm = (_env("ARM", "ask") or "ask").strip().lower()
        if arm not in ("ask", "on"):
            raise ConfigError(f"{ENV_PREFIX}ARM must be 'ask' (default: the user is asked in a dialog) or 'on' (the user's standing approval for this client), got {arm!r}")
        escalation = (_env("ESCALATION", "ask") or "ask").strip().lower()
        if escalation not in ESCALATIONS:
            raise ConfigError(f"{ENV_PREFIX}ESCALATION must be one of {ESCALATIONS}, got {escalation!r}")
        run_policy = (_env("RUN_POLICY", "ask") or "ask").strip().lower()
        if run_policy not in RUN_POLICIES:
            raise ConfigError(f"{ENV_PREFIX}RUN_POLICY must be one of {RUN_POLICIES}, got {run_policy!r}")
        unasked = (_env("UNASKED", "refuse") or "refuse").strip().lower()
        if unasked not in UNASKED_POLICIES:
            raise ConfigError(f"{ENV_PREFIX}UNASKED must be one of {UNASKED_POLICIES}, got {unasked!r}")
        assist_numbers = (_env("ASSIST_NUMBERS", "masked") or "masked").strip().lower()
        if assist_numbers not in ("masked", "open"):
            raise ConfigError(f"{ENV_PREFIX}ASSIST_NUMBERS must be 'masked' or 'open', got {assist_numbers!r}")
        decide_prefer = (_env("DECIDE_PREFER", "primary") or "primary").strip().lower()
        if decide_prefer not in ("primary", "fallback"):
            raise ConfigError(f"{ENV_PREFIX}DECIDE_PREFER must be primary or fallback, got {decide_prefer!r}")
        return cls(
            mode=mode,
            base_url=base_url,
            model=_env("MODEL", "local") or "local",
            api_key=_load_api_key(),
            fallback_base_url=fallback_base_url,
            fallback_model=(_env("FALLBACK_MODEL") or "").strip(),
            fallback_api_key=_load_api_key("FALLBACK_") if fallback_base_url else "",
            failover_cooldown=_float("FAILOVER_COOLDOWN", 120.0),
            thinking=_bool("THINKING", False),
            max_output_chars=_int("MAX_OUTPUT_CHARS", 2000),
            max_tokens_cap=_int("MAX_TOKENS_CAP", 8192),
            llm_timeout=_float("LLM_TIMEOUT", 300.0),
            chunk_chars=_int("CHUNK_CHARS", 24000),
            parallel_chunks=max(1, _int("PARALLEL_CHUNKS", 4)),
            material_max_chars=_int("MATERIAL_MAX_CHARS", 400_000),
            context_chars=_int("CONTEXT_CHARS", 12000),
            excerpt_chars=_int("EXCERPT_CHARS", 1500),
            summary_chars=_int("SUMMARY_CHARS", 6000),
            auto_compact_chars=_int("AUTO_COMPACT_CHARS", 60000),
            command_timeout=_float("COMMAND_TIMEOUT", 120.0),
            strict_pii=_bool("STRICT_PII", False),
            entity_pass=_bool("ENTITY_PASS", True),
            escalation=escalation,
            arm=arm,
            run_policy=run_policy,
            unasked=unasked,
            run_allow_path=_path("RUN_ALLOW", "~/.config/local-llm-mcp/run-allow.txt"),
            assist_numbers=assist_numbers,
            dialog_timeout=_float("DIALOG_TIMEOUT", 600.0),
            shapes=_bool("SHAPES", True),
            prices_path=_path("PRICES", "~/.config/local-llm-mcp/prices.json"),
            caller_model=(_env("CALLER_MODEL") or "").strip(),
            state_dir=_path("STATE_DIR", "~/.local/state/local-llm-mcp"),
            sock_dir=_path("SOCK_DIR", default_sock_dir()),
            rules_path=_opt_path("RULES"),
            private_terms_path=_path("PRIVATE_TERMS", "~/.config/local-llm-mcp/private_terms.json"),
            terms_seed_path=_path("TERMS_SEED", "~/.config/local-llm-mcp/terms-seed.json"),
            terms_backup_stamp=_opt_path("TERMS_BACKUP_STAMP"),
            observer=(_env("OBSERVER") or "").strip(),
            observer_path=_opt_path("OBSERVER_PATH"),
            observer_url=(_env("OBSERVER_URL") or "").strip().rstrip("/"),
            decide=_bool("DECIDE", False),
            decide_prefer=decide_prefer,
            decide_timeout=_float("DECIDE_TIMEOUT_S", 5.0),
            decide_reasoning=_bool("DECIDE_REASONING", True),
            session_override=(_env("SESSION") or "").strip(),
            log_level=(_env("LOG_LEVEL", "INFO") or "INFO").upper(),
        )

    def public(self) -> dict:
        """Config as safe to show a caller: never the key."""
        d = {k: (str(v) if isinstance(v, Path) else v) for k, v in self.__dict__.items()}
        d["api_key"] = "set" if self.api_key else "unset"
        d["fallback_api_key"] = "set" if self.fallback_api_key else "unset"
        return d
