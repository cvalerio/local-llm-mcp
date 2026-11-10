"""The delegation pipeline with the worker stubbed: verbatim quoting, and the digest fallback when nothing matches."""
import asyncio
import json
import os

from local_llm_mcp.config import Config
from local_llm_mcp.llm import Usage
from local_llm_mcp.server import App


def make_app(monkeypatch, tmp_path) -> App:
    for k in ("FALLBACK_BASE_URL", "API_KEY", "API_KEY_FILE", "RULES", "OBSERVER"):
        monkeypatch.delenv("LOCAL_LLM_MCP_" + k, raising=False)
    # The default, unless a test set one before calling us.
    monkeypatch.setenv("LOCAL_LLM_MCP_RUN_POLICY", os.environ.get("LOCAL_LLM_MCP_RUN_POLICY", "ask"))
    monkeypatch.setenv("LOCAL_LLM_MCP_UNASKED", os.environ.get("LOCAL_LLM_MCP_UNASKED", "refuse"))
    # Never let a test append to the operator's own allow list.
    monkeypatch.setenv("LOCAL_LLM_MCP_RUN_ALLOW", str(tmp_path / "run-allow.txt"))
    monkeypatch.setenv("LOCAL_LLM_MCP_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SOCK_DIR", str(tmp_path / "sock"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRICES", str(tmp_path / "prices.json"))
    monkeypatch.setenv("LOCAL_LLM_MCP_PRIVATE_TERMS", str(tmp_path / "terms.json"))
    monkeypatch.setenv("LOCAL_LLM_MCP_SESSION", "t-delegate")
    monkeypatch.setenv("LOCAL_LLM_MCP_MODE", "assist")
    app = App(Config.from_env())

    async def count_tokens(text):
        return len(text.split())

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return f"digested: {task} over {len(material)} chars", Usage()

    app.llm.count_tokens = count_tokens
    app.llm.digest = digest
    return app


def run(app: App, **kw) -> str:
    async def go():
        out = await app.delegate(**kw)
        await app.flush_measurements()
        return out
    return asyncio.run(go())


def test_verbatim_quotes_when_lines_match(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def locate(task, material, source):
        return [(2, 2)]
    app.locate_lines = locate
    out = run(app, kind="run", task="the beta line", material="alpha\nbeta\ngamma\n", source="command: x",
              max_output_chars=500, verbatim=True)
    assert "\n2: beta" in out and "· verbatim" in out and "digested instead" not in out
    turn = app.session.turns()[-1]
    assert turn["verbatim"] is True and "verbatim_fallback" not in turn


def test_verbatim_with_no_match_is_digested_instead(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def locate(task, material, source):
        return []
    app.locate_lines = locate
    out = run(app, kind="run", task="How many lines?", material="alpha\nbeta\ngamma\n", source="command: x",
              max_output_chars=500, verbatim=True)
    assert out.startswith("digested: How many lines? over 17 chars")
    assert "verbatim: no lines matched, digested instead" in out and "· verbatim ·" not in out
    turn = app.session.turns()[-1]
    assert turn["verbatim"] is False and turn["verbatim_fallback"] is True and turn["result"].startswith("digested:")
    rows = [json.loads(l) for l in (tmp_path / "state" / "savings.jsonl").read_text().splitlines()]
    assert rows[-1]["turn"] == turn["id"] and rows[-1]["verbatim"] is False  # counted as a digest, not a quote


def test_pii_answer_pass_masks_an_echoed_unlabelled_name(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    app.session.set_mode("pii")
    calls = []

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return "The letter was written by Zed Quillfeather to Ora Vantablack about the roof.", Usage()

    async def chat(system, user, *, max_tokens, temperature=0.2):
        calls.append(user)
        if "Zed Quillfeather" in user:  # the answer pass sees the answer; the material pass saw nothing useful
            return '[{"kind": "PERSON", "value": "Zed Quillfeather"}, {"kind": "PERSON", "value": "Ora Vantablack"}]', {}
        return "[]", {}
    app.llm.digest = digest
    app.llm.chat = chat
    out = run(app, kind="delegate", task="who wrote to whom?", material="x" * 100, source="paths: letter.txt",
              max_output_chars=500)
    assert "Zed Quillfeather" not in out and "Ora Vantablack" not in out
    assert "[PERSON-1]" in out and "[PERSON-2]" in out and "leak-check ok" in out
    assert app.session.vault.by_value.get("Zed Quillfeather", "").startswith("[PERSON-")


def test_pii_answer_pass_failure_is_visible_not_silent(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    app.session.set_mode("pii")

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return "nothing private here", Usage()

    async def chat(system, user, *, max_tokens, temperature=0.2):
        raise RuntimeError("worker down")
    app.llm.digest = digest
    app.llm.chat = chat
    out = run(app, kind="delegate", task="t", material="m" * 50, source="paths: f", max_output_chars=500)
    assert out.startswith("nothing private here") and "leak-check FAILED" in out


def test_error_text_is_scrubbed_before_it_leaves(monkeypatch, tmp_path):
    from local_llm_mcp.llm import LLMError
    app = make_app(monkeypatch, tmp_path)

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        raise LLMError("worker returned HTTP 400: cannot process jane.example@example.org key sk-abcdefghijklmnopqrstuvwxyz0123")  # gitleaks:allow
    app.llm.digest = digest
    out = run(app, kind="run", task="t", material="m", source="command: x", max_output_chars=500)
    assert out.startswith("Error:") and "sk-abcdefghijklmnop" not in out and "[SECRET-1]" in out


def _echo_names_worker(app):
    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return "Zed Quillfeather wrote to Ora Vantablack about the roof.", Usage()

    async def chat(system, user, *, max_tokens, temperature=0.2):
        if "Zed Quillfeather" in user:
            return '[{"kind": "PERSON", "value": "Zed Quillfeather"}, {"kind": "PERSON", "value": "Ora Vantablack"}]', {}
        return "[]", {}
    app.llm.digest = digest
    app.llm.chat = chat


def test_assist_answer_pass_runs_while_identity_is_masked(monkeypatch, tmp_path):
    """ASSIST before the user has opened identity: a bare, unlabelled name the worker echoes is masked."""
    app = make_app(monkeypatch, tmp_path)
    _echo_names_worker(app)
    out = run(app, kind="delegate", task="who wrote to whom?", material="x" * 100, source="paths: letter.txt", max_output_chars=500)
    assert "Zed Quillfeather" not in out and "Ora Vantablack" not in out and "[PERSON-1]" in out and "leak-check ok" in out


def test_assist_answer_pass_skipped_once_identity_is_open(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)
    d = app.session.disclosure
    d.set(identity="open", numbers="masked", source="tool")
    app.session.set_disclosure(d)
    _echo_names_worker(app)
    out = run(app, kind="delegate", task="who wrote to whom?", material="x" * 100, source="paths: letter.txt", max_output_chars=500)
    assert "Zed Quillfeather" in out and "leak-check" not in out  # the user chose to see names: no pass, no note


def test_compaction_summary_gets_the_answer_pass_while_identity_is_masked(monkeypatch, tmp_path):
    import asyncio
    app = make_app(monkeypatch, tmp_path)

    async def digest(system, task, material, source, *, max_output_chars, render_user, render_reduce):
        return "The roof was discussed.", Usage()

    async def chat(system, user, *, max_tokens, temperature=0.2):
        if "Pim Osterhagen" in user:  # the answer pass over the summary
            return '[{"kind": "PERSON", "value": "Pim Osterhagen"}]', {}
        if "[]" == user.strip():
            return "[]", {}
        return "Pim Osterhagen asked about the roof; nothing else happened.", {}  # the summarizer (and any other prompt)
    app.llm.digest = digest
    app.llm.chat = chat
    run(app, kind="delegate", task="t", material="m" * 50, source="paths: f", max_output_chars=500)
    res = asyncio.run(app.compact("test"))
    assert res.get("ok") and "Pim Osterhagen" not in app.session.summary() and "[PERSON-" in app.session.summary()


def test_artifact_slice_gets_the_answer_pass_and_failures_are_counted(monkeypatch, tmp_path):
    import asyncio
    app = make_app(monkeypatch, tmp_path)

    async def chat(system, user, *, max_tokens, temperature=0.2):
        if "Lucasta Wrenholm" in user:
            return '[{"kind": "PERSON", "value": "Lucasta Wrenholm"}]', {}
        return "[]", {}
    app.llm.chat = chat
    piece = "line 401\nPS — the plot goes to Lucasta Wrenholm, who prefers mornings.\n"
    scrubbed, note = asyncio.run(app.outbound_slice(piece))
    assert "Lucasta Wrenholm" not in scrubbed.text and "[PERSON-1]" in scrubbed.text and note == "leak-check ok"
    assert app.session.leak_check() == {"ran": 1, "failed": 0, "last_failure": None}
    d = app.session.disclosure
    d.set(identity="open", numbers="masked", source="tool")
    app.session.set_disclosure(d)
    scrubbed2, note2 = asyncio.run(app.outbound_slice("Pim Osterhagen said hello"))
    assert "Pim Osterhagen" in scrubbed2.text and note2 == ""  # identity open: no pass, no note, no count

    async def broken(system, user, *, max_tokens, temperature=0.2):
        raise RuntimeError("worker down")
    app.llm.chat = broken
    d.set(identity="masked", numbers="masked", source="tool")
    app.session.set_disclosure(d)
    scrubbed3, note3 = asyncio.run(app.outbound_slice("Zed Quillfeather again"))
    assert note3.startswith("leak-check FAILED") and app.session.leak_check()["failed"] == 1 and app.session.leak_check()["ran"] == 2
    assert app.session.leak_check()["last_failure"]["error"] == "worker down"
    assert app.session.status()["leak_check"]["failed"] == 1


# ---- a slice is cut from scrubbed text ----------------------------------------------

PEM = "-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEbodyline1AAAAAAAA\nMIIEFAKEbodyline2BBBBBBBB\n-----END RSA PRIVATE KEY-----"
TOKEN = "ghp_" + "a1B2" * 8
RAW = "header\n" + PEM + "\n" + TOKEN + "\nlast line\n"


def stored(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def chat(system, user, *, max_tokens, temperature=0.2):
        return "[]", {}
    app.llm.chat = chat
    return app, app.session.store_artifact(RAW, {"kind": "run"})


def test_a_line_slice_inside_a_private_key_shows_none_of_it(monkeypatch, tmp_path):
    app, ref = stored(monkeypatch, tmp_path)
    out = asyncio.run(app.artifact_slice(ref, 0, 4000, 3, 4))
    assert "MIIEFAKE" not in out


def test_line_numbers_survive_a_masked_multi_line_secret(monkeypatch, tmp_path):
    app, ref = stored(monkeypatch, tmp_path)
    out = asyncio.run(app.artifact_slice(ref, 0, 4000, 7, 7))  # line 7 of RAW, after the four PEM lines and the token
    assert out.startswith("7: last line") and "lines 7-7 of 8" in out


def test_a_character_slice_starting_inside_a_token_shows_none_of_it(monkeypatch, tmp_path):
    app, ref = stored(monkeypatch, tmp_path)
    clean_start = asyncio.run(app.artifact_slice(ref, 0, 4000, 0, 0))
    assert TOKEN not in clean_start and "[SECRET-" in clean_start and "scrubbed" in clean_start
    for offset in range(0, len(clean_start), 3):
        assert TOKEN[8:24] not in asyncio.run(app.artifact_slice(ref, offset, 100, 0, 0))


def test_a_verbatim_range_inside_a_private_key_quotes_none_of_it(monkeypatch, tmp_path):
    app = make_app(monkeypatch, tmp_path)

    async def locate(task, material, source):
        return [(3, 4)]

    async def chat(system, user, *, max_tokens, temperature=0.2):
        return "[]", {}
    app.locate_lines, app.llm.chat = locate, chat
    out = run(app, kind="run", task="the key", material=RAW, source="command: x", max_output_chars=500, verbatim=True)
    assert "MIIEFAKE" not in out and "· verbatim" in out
