"""The git gate: nothing deployment-specific or personal reaches a commit, a message, or a push."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "tools" / "githooks"
CHECK = ROOT / "tools" / "publiccheck.py"


@pytest.fixture
def repo(tmp_path):
    """A throwaway repository wired to the tracked hooks, a bare remote, and a private denylist."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
           "LOCAL_LLM_MCP_DENYLIST": str(tmp_path / "deny.txt"), "GIT_TERMINAL_PROMPT": "0"}
    (tmp_path / "deny.txt").write_text("# private terms\norchid-nine\nhost-zebra\n")
    work, bare = tmp_path / "work", tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True, env=env)
    subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True, env=env)

    def g(*args, check=True, **kw):
        return subprocess.run(["git", *args], cwd=work, env=env, capture_output=True, text=True, check=check, **kw)

    g("config", "user.name", "Test Author")
    g("config", "user.email", "author@example.org")
    g("config", "core.hooksPath", str(HOOKS))
    g("remote", "add", "origin", str(bare))
    (work / "README.md").write_text("hello\n")
    g("add", "README.md")
    g("commit", "-q", "-m", "first")
    g("push", "-q", "-u", "origin", "main")
    return work, g


def test_clean_commit_and_push_pass(repo):
    work, g = repo
    g("switch", "-q", "-c", "topic")
    (work / "a.py").write_text("print('fine')\n")
    g("add", "a.py")
    assert g("commit", "-q", "-m", "add a").returncode == 0
    assert g("push", "-q", "-u", "origin", "topic").returncode == 0


def _remote_tip(g, branch):
    r = g("ls-remote", "origin", f"refs/heads/{branch}")
    return r.stdout.split()[0] if r.stdout else None


def test_a_direct_push_that_moves_main_is_refused(repo):
    """main changes by merging a pull request. The fixture's first push created it, which stays allowed."""
    work, g = repo
    before = _remote_tip(g, "main")
    (work / "a.py").write_text("x = 1\n")
    g("add", "a.py")
    g("commit", "-q", "-m", "straight to main")
    r = g("push", "-q", check=False)
    assert r.returncode != 0 and "direct push to main" in r.stderr
    assert _remote_tip(g, "main") == before
    r = subprocess.run(["git", "push", "-q"], cwd=work, capture_output=True, text=True,
                       env={**os.environ, "GIT_CONFIG_GLOBAL": str(work.parent / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
                            "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt"), "LOCAL_LLM_MCP_ALLOW_MAIN_PUSH": "1"})
    assert r.returncode == 0 and "allowed by" in r.stderr
    assert _remote_tip(g, "main") == g("rev-parse", "HEAD").stdout.strip()


def test_a_commit_is_never_pushed_automatically(repo):
    """No hook publishes on commit, on any branch, even in a clone still carrying the old autopush setting."""
    work, g = repo
    assert not (HOOKS / "post-commit").exists()
    g("config", "local-llm-mcp.autopush", "true")
    before = _remote_tip(g, "main")
    for branch in ("main", "topic"):
        if branch != "main":
            g("switch", "-q", "-c", branch)
        (work / f"{branch}.py").write_text("x = 1\n")
        g("add", f"{branch}.py")
        g("commit", "-q", "-m", f"on {branch}")
    assert _remote_tip(g, "main") == before and _remote_tip(g, "topic") is None


def test_staged_private_address_is_refused(repo):
    work, g = repo
    (work / "cfg.py").write_text("URL = 'http://192.168.4.20:8000'\n")  # public:allow: synthetic fixture
    g("add", "cfg.py")
    r = g("commit", "-q", "-m", "wire it", check=False)
    assert r.returncode != 0 and "private IPv4 address" in r.stderr and "staged cfg.py" in r.stderr
    assert "wire it" not in g("log", "--oneline").stdout


def test_staged_denylisted_term_and_file_name_are_refused(repo):
    work, g = repo
    (work / "notes-host-zebra.md").write_text("Orchid-Nine handles the rest.\n")  # case-insensitive, word-bounded
    g("add", "notes-host-zebra.md")
    r = g("commit", "-q", "-m", "notes", check=False)
    assert r.returncode != 0 and "denylist term #2" in r.stderr and "denylist term #3" in r.stderr
    assert "orchid" not in r.stderr.lower() and "zebra" not in r.stderr.lower()  # reported by number, never by value


def test_message_with_term_address_or_attribution_is_refused(repo):
    work, g = repo
    (work / "b.py").write_text("x = 1\n")
    g("add", "b.py")
    for msg, expect in [("tested on host-zebra", "denylist term #3"),
                        ("see /home/someone/notes", "home directory path"),  # public:allow: synthetic fixture
                        ("full suite passed on .142", "short host address"),  # public:allow short host address
                        ("add b\n\nCo-Authored-By: Robot <robot@example.org>", "attribution trailer"),
                        ("add b\n\n🤖 Generated with Something", "attribution trailer")]:
        r = g("commit", "-q", "-m", msg, check=False)
        assert r.returncode != 0 and expect in r.stderr, msg
    assert g("commit", "-q", "-m", "add b").returncode == 0


def test_wrong_identity_is_refused(repo):
    work, g = repo
    (work / "c.py").write_text("y = 2\n")
    g("add", "c.py")
    r = g("commit", "-q", "-m", "add c", "--author=Someone Else <else@example.org>", check=False)
    # the unexpected identity is a real name and address: withheld unless stderr is a terminal
    assert r.returncode != 0 and "author is" in r.stderr and "not the configured Test Author" in r.stderr
    assert "Someone Else" not in r.stderr and "withheld" in r.stderr
    r = g("-c", "user.email=other@example.org", "commit", "-q", "-m", "add c", check=False)
    assert r.returncode != 0 and ("committer is" in r.stderr or "author is" in r.stderr)


def test_push_refuses_a_commit_that_bypassed_the_earlier_hooks(repo):
    work, g = repo
    g("switch", "-q", "-c", "topic")
    g("push", "-q", "-u", "origin", "topic")
    (work / "d.py").write_text("HOST = '10.1.2.3'\n")  # public:allow: synthetic fixture
    g("add", "d.py")
    assert g("commit", "-q", "--no-verify", "-m", "sneaky").returncode == 0  # skips pre-commit and commit-msg
    (work / "e.py").write_text("ok = True\n")
    g("add", "e.py")
    g("commit", "-q", "--no-verify", "-m", "on top\n\nCo-Authored-By: Robot <robot@example.org>")
    r = g("push", "-q", check=False)
    assert r.returncode != 0 and "private IPv4 address" in r.stderr and "attribution trailer" in r.stderr
    assert "2 commit(s)" in r.stderr
    g("reset", "-q", "--hard", "HEAD~2")
    assert g("push", "-q").returncode == 0


def test_range_and_all_scan_every_commit_tree_not_only_diffs(repo):
    work, g = repo
    (work / "f.py").write_text("addr = '172.16.9.9'\n")  # public:allow: synthetic fixture
    g("add", "f.py")
    g("commit", "-q", "--no-verify", "-m", "bad")
    (work / "f.py").write_text("addr = 'gone'\n")
    g("add", "f.py")
    g("commit", "-q", "-m", "fixed")  # the tip is clean; the history is not
    env = {**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt")}
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "private IPv4 address" in r.stderr
    r = subprocess.run([sys.executable, str(CHECK)], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 0  # the tree alone is clean — which is exactly why the push gate scans commits


def test_history_scan_without_an_identity_checks_everything_else(repo):
    work, g = repo
    (work / "g.py").write_text("z = 3\n")
    g("add", "g.py")
    g("commit", "-q", "--no-verify", "-m", "add g\n\nCo-Authored-By: Robot <robot@example.org>")
    env = {**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt"), "GIT_CONFIG_GLOBAL": str(work.parent / "gitconfig")}
    g("config", "--unset", "user.email")
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 1 and "identities not checked" in r.stdout and "attribution trailer" in r.stderr
    assert "no user.email" not in r.stderr  # the missing identity is a note, not a refusal, in a history scan


def test_installer_is_scoped_to_this_repository(tmp_path):
    """The gate is per-clone: the installer refuses any other repository and never writes global config."""
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1"}
    other = tmp_path / "other"
    subprocess.run(["git", "init", "-q", str(other)], check=True, env=env)
    r = subprocess.run(["bash", str(ROOT / "tools/install-hooks.sh")], cwd=other, env=env, capture_output=True, text=True)
    assert r.returncode == 2 and "not the local-llm-mcp repository" in r.stderr
    assert subprocess.run(["git", "config", "--local", "--get", "core.hooksPath"], cwd=other, env=env, capture_output=True).returncode != 0
    assert not (tmp_path / "gitconfig").exists() or "hooksPath" not in (tmp_path / "gitconfig").read_text()


def test_new_shapes_are_refused_and_rfc_ranges_are_not(repo):
    """The gaps a 2026-09-09 adversarial audit found in this gate, each with a live probe."""
    work, g = repo
    cases = {
        "cidr.py": ("HOST = '192.168.1.0/24'", True),          # a real subnet, not an RFC constant  # public:allow private IPv4 address
        "rfc.py": ("CGNAT = '100.64.0.0/10'", False),           # a range constant identifies nobody
        "doc.py": ("EX = '203.0.113.9'", False),                # RFC 5737 documentation address
        "pub.py": ("VPS = '198.41.30.7'", True),                # a routable public address  # public:allow public IPv4 address
        "v6.py": ("ULA = 'fd00:1234::5'", True),  # public:allow IPv6 address
        "root.py": ("KEY = '/root/.ssh/id_rsa'", True),  # public:allow home directory path
        "bare.py": ("P = '/home/someone'", True),               # no trailing slash  # public:allow home directory path
        "win.py": ("P = 'C:\\\\Users\\\\someone\\\\notes'", True),
        "uv.lock": ("url = 'http://192.168.9.9/simple'", True), # lockfiles are text and are scanned  # public:allow private IPv4 address
        "legacy.py": ("H = '10.9.9.9'  # public:allow", False), # a bare opt-out still exempts shape checks
        # the probe's own opt-out names the WRONG check, so the probe is still flagged; the trailing
        # comment is on this source line only, exempting the fixture from the tree scan
        "wrong.py": ("H = '10.9.9.9'  # public:allow tailnet hostname", True),  # public:allow private IPv4 address
    }
    for name, (body, _) in cases.items():
        (work / name).write_text(body + "\n")
    g("add", "-A")
    r = g("commit", "-q", "-m", "probes", check=False)
    assert r.returncode != 0
    for name, (_, should_flag) in cases.items():
        assert (name in r.stderr) == should_flag, f"{name}: expected flagged={should_flag}\n{r.stderr}"


def test_a_host_written_by_its_last_octet_is_refused_and_decimals_are_not(repo):
    """A short LAN host reference passed every check before; it names one network as surely as the full address."""
    work, g = repo
    flagged = ["ran it on .142 today", "see (.142)", "`.142`", ".142:8000 answers", "the .142's venv",  # public:allow short host address
               "\t.42 and", "'.142'"]  # public:allow short host address
    clean = ["rgba(0,0,0,.25)", "re.compile(r'\\.\\d{1,3}')", "v0.142", "1.142", "x.142", "a/.142", "0.5", "-.25em",
             "2.5 .5", ".1 s", "file.142.txt", ".142abc"]
    for i, body in enumerate(flagged):
        (work / f"f{i}.md").write_text(body + "\n")
    for i, body in enumerate(clean):
        (work / f"c{i}.md").write_text(body + "\n")
    (work / "allowed.md").write_text("quoted on purpose: .142  public:allow short host address\n")  # public:allow short host address
    g("add", "-A")
    r = g("commit", "-q", "-m", "probes", check=False)
    assert r.returncode != 0
    for i, body in enumerate(flagged):
        assert f"staged f{i}.md:1: short host address" in r.stderr, (body, r.stderr)
    for i, body in enumerate(clean):
        assert f"c{i}.md" not in r.stderr, (body, r.stderr)
    assert "allowed.md" not in r.stderr
    assert ".142" not in r.stderr  # public:allow short host address


def test_a_denylist_term_can_never_be_opted_out(repo):
    work, g = repo
    (work / "n.md").write_text("deployed on host-zebra  # public:allow denylist term\n")
    g("add", "n.md")
    r = g("commit", "-q", "-m", "notes", check=False)
    assert r.returncode != 0 and "denylist term #3" in r.stderr


def test_a_refusal_withholds_the_value_when_output_is_not_a_terminal(repo):
    work, g = repo
    (work / "c.py").write_text("H = '192.168.4.20'\n")  # public:allow private IPv4 address
    g("add", "c.py")
    r = g("commit", "-q", "-m", "wire", check=False)
    assert r.returncode != 0 and "192.168.4.20" not in r.stderr and "withheld" in r.stderr  # public:allow private IPv4 address


def test_an_annotated_tag_message_and_tagger_are_scanned(repo):
    work, g = repo
    g("tag", "-a", "v9", "-m", "cut for host-zebra")
    r = subprocess.run([sys.executable, str(CHECK), "--tag", "v9"], cwd=work,
                       env={**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt")},
                       capture_output=True, text=True)
    assert r.returncode == 1 and "denylist term #3" in r.stderr
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work,
                       env={**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(work.parent / "deny.txt")},
                       capture_output=True, text=True)
    assert r.returncode == 1 and "annotated tag" not in r.stdout  # refused, so no clean line


def test_a_tag_is_scanned_without_an_identity_configured(repo, tmp_path):
    """CI has no user.email. Commit scanning already skipped identities there; tag scanning must too,
    or every history scan on a runner refuses on the tagger alone."""
    work, g = repo
    g("tag", "-a", "v8", "-m", "ordinary release note")
    g("config", "--unset", "user.email", check=False)
    env = {k: v for k, v in os.environ.items() if k != "LOCAL_LLM_MCP_DENYLIST"}
    env["XDG_CONFIG_HOME"] = str(tmp_path / "empty-config")
    env["GIT_CONFIG_GLOBAL"] = str(tmp_path / "gitconfig")  # or the real user's identity leaks in as "expected"
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "annotated tag" in r.stdout and "no user.email" not in r.stderr


def test_a_mistyped_denylist_path_refuses_instead_of_degrading(repo, tmp_path):
    """Unset means "no list" (CI). Set-but-absent means a typo, and must not silently disable the names."""
    work, g = repo
    env = {**os.environ, "LOCAL_LLM_MCP_DENYLIST": str(tmp_path / "typo.txt")}
    r = subprocess.run([sys.executable, str(CHECK)], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 2 and "does not exist" in r.stderr
    env.pop("LOCAL_LLM_MCP_DENYLIST")
    env["XDG_CONFIG_HOME"] = str(tmp_path / "empty-config")
    r = subprocess.run([sys.executable, str(CHECK)], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "NO DENYLIST was found" in r.stdout


def test_the_package_ships_no_instance_material(tmp_path):
    """A source distribution must not carry a deployment's dotenv, keys, terms or price override."""
    ignored = (Path(ROOT) / ".gitignore").read_text()
    for pattern in ("/env", "/*.key", "/*.pem", "/private_terms.json", "/prices.json"):
        assert pattern in ignored, f"{pattern} must be ignored so no build can sweep it in"
    assert "/local_llm_mcp/prices.json" not in ignored  # the package's own table stays tracked


def test_a_gitleaks_that_cannot_run_refuses_the_commit(repo, tmp_path):
    """A secret scanner that errors must not read as a pass. This regressed once, silently."""
    work, g = repo
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "gitleaks").write_text("#!/bin/sh\nexit 3\n")
    (fake / "gitleaks").chmod(0o755)
    (work / "a.py").write_text("x = 1\n")
    g("add", "a.py")
    env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"}
    r = subprocess.run(["git", "commit", "-q", "-m", "probe"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode != 0 and "could not run" in r.stderr and "refusing" in r.stderr
    env["LOCAL_LLM_MCP_ALLOW_NO_GITLEAKS"] = "1"
    r = subprocess.run(["git", "commit", "-q", "-m", "probe"], cwd=work, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "allowed by" in r.stderr


def test_pushing_a_tag_scans_the_tag_object(repo, tmp_path):
    """pre-push must scan an annotated tag: rev-list shows neither its message nor its tagger."""
    work, g = repo
    assert "refs/tags/" in (ROOT / "tools/githooks/pre-push").read_text()
    g("tag", "-a", "v7", "-m", "cut for host-zebra")
    r = g("push", "-q", "origin", "v7", check=False)
    assert r.returncode != 0 and "denylist term #3" in r.stderr
    g("tag", "-d", "v7")
    g("tag", "-a", "v7", "-m", "an ordinary release")
    assert g("push", "-q", "origin", "v7").returncode == 0


def test_this_repository_history_is_clean(tmp_path):
    """Every commit and tag of THIS repository passes the shape checks.

    The denylist is deliberately absent: it lives outside the repository and differs
    per operator, so including it here would make this test pass on CI and fail on a machine whose list
    happens to be wider. The denylist proof is the hooks' job, on the machine that authors the commit.

    The operator's git identity is absent for the same reason: the history holds every contributor's
    commits, so comparing them with whoever runs the test fails on any clone but one author's. CI has no
    identity and skips that check; checking the identity of a NEW commit is the hooks' job too.
    """
    env = {k: v for k, v in os.environ.items() if k != "LOCAL_LLM_MCP_DENYLIST"}
    env["XDG_CONFIG_HOME"] = str(tmp_path / "empty-config")  # unset, not mistyped: "no list", as CI runs
    env["GIT_CONFIG_GLOBAL"] = os.devnull                     # no user.email, as CI runs
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    r = subprocess.run([sys.executable, str(CHECK), "--all"], cwd=ROOT, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "NO DENYLIST was found" in r.stdout  # and it says so, rather than reporting "clean"


def test_a_pull_request_merged_on_github_passes_the_history_scan(repo, tmp_path):
    """Merging on GitHub records GitHub as the committer. That identity names no one and is accepted;
    the author is still checked, so a merge cannot carry someone else's name in."""
    work, g = repo
    def commit_as(committer, author, name):
        env = {**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_COMMITTER_NAME": committer[0], "GIT_COMMITTER_EMAIL": committer[1],
               "GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1]}
        (work / f"{name}.py").write_text("x = 1\n")
        g("add", f"{name}.py")
        subprocess.run(["git", "commit", "-q", "--no-verify", "-m", name], cwd=work, env=env, check=True)
    def history():
        env = {**os.environ, "GIT_CONFIG_GLOBAL": str(tmp_path / "gitconfig"), "GIT_CONFIG_NOSYSTEM": "1",
               "LOCAL_LLM_MCP_DENYLIST": str(tmp_path / "deny.txt")}
        return subprocess.run([sys.executable, str(CHECK), "--all"], cwd=work, env=env, capture_output=True, text=True)
    me, github = ("Test Author", "author@example.org"), ("GitHub", "noreply@github.com")  # public:allow non-example email address
    commit_as(github, me, "merged")
    assert history().returncode == 0
    commit_as(github, github, "not-mine")
    r = history()
    assert r.returncode != 0 and "author is" in r.stderr


def test_the_users_global_pre_push_still_runs(repo, tmp_path):
    """A repository-local core.hooksPath replaces the global hooks; pre-push runs the user's global one too, so a
    machine-wide guard (no secret from their key files may leave) is not silently switched off by this repo."""
    work, g = repo
    hooks = tmp_path / "global-hooks"
    hooks.mkdir()
    seen, verdict = tmp_path / "seen.txt", tmp_path / "verdict"
    (hooks / "pre-push").write_text(f'#!/bin/sh\ncat > "{seen}"\nexit $(cat "{verdict}")\n')
    (hooks / "pre-push").chmod(0o755)
    g("config", "--global", "core.hooksPath", str(hooks))
    g("switch", "-q", "-c", "topic")
    (work / "a.py").write_text("x = 1\n")
    g("add", "a.py")
    g("commit", "-q", "-m", "add a")
    verdict.write_text("1")
    r = g("push", "-q", "-u", "origin", "topic", check=False)
    assert r.returncode != 0 and "refused by your global pre-push" in r.stderr
    verdict.write_text("0")
    assert g("push", "-q", "-u", "origin", "topic").returncode == 0
    assert "refs/heads/topic" in seen.read_text()          # it got the real push details on stdin
    g("config", "--global", "--unset", "core.hooksPath")
    seen.unlink()
    (work / "b.py").write_text("y = 2\n")
    g("add", "b.py")
    g("commit", "-q", "-m", "add b")
    assert g("push", "-q").returncode == 0 and not seen.exists()   # no global hooks configured: nothing extra runs
