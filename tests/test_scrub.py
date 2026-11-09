"""Scrubber, vault, rules-file and dotenv contracts. Self-contained: built-in rules only."""
import asyncio
import json
import os
import shutil
import time
from pathlib import Path

import pytest

from local_llm_mcp.config import load_env_file
from local_llm_mcp.scrub import PLACEHOLDER_RE, Scrubber, Vault, codice_fiscale_ok


@pytest.fixture
def terms(tmp_path):
    p = tmp_path / "terms.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "PERSON", "values": ["Jane Q. Example"]},
        {"kind": "ADDRESS", "values": ["12 Example Lane"]},
    ]}))
    return p


@pytest.fixture
def scrubber(terms):
    return Scrubber(None, terms)


@pytest.fixture
def vault(tmp_path):
    return Vault(tmp_path / "vault.json")


def test_email_and_key_get_placeholders(scrubber, vault):
    text = "contact jane.example@example.org, key sk-abcdefghijklmnopqrstuvwxyz0123, again jane.example@example.org"  # gitleaks:allow
    r = scrubber.scrub(text, vault)
    assert "jane.example@example.org" not in r.text
    assert "sk-abcdefghijklmnop" not in r.text
    assert r.text.count("[EMAIL-1]") == 2
    assert "[SECRET-1]" in r.text
    assert r.replaced == 3


def test_placeholders_stable_and_rehydrate(scrubber, vault):
    r1 = scrubber.scrub("mail a@example.org", vault)
    r2 = scrubber.scrub("again a@example.org and b@example.org", vault)
    assert "[EMAIL-1]" in r1.text and "[EMAIL-1]" in r2.text and "[EMAIL-2]" in r2.text
    assert vault.rehydrate("send to [EMAIL-1], cc [EMAIL-2], keep [EMAIL-9]") == \
        "send to a@example.org, cc b@example.org, keep [EMAIL-9]"


def test_material_values_are_scrubbed_from_any_output(scrubber, vault):
    scrubber.register_material("PHONE: (555) 010-2233 belongs to Jane Q. Example", vault)
    r = scrubber.scrub("call (555) 010-2233; Jane Q. Example answered", vault)
    assert "(555) 010-2233" not in r.text and "Jane Q. Example" not in r.text
    assert "[PERSON-1]" in r.text


def test_private_terms_case_insensitive_whole_word(scrubber, vault):
    r = scrubber.scrub("JANE Q. EXAMPLE lives at 12 example lane; examples are fine", vault)
    assert "[PERSON-1]" in r.text and "[ADDRESS-1]" in r.text
    assert "examples are fine" in r.text


def test_env_lines_assignments_and_pem(scrubber, vault):
    text = ("export OPENAI_API_KEY=abcdef1234567890\nPASSWORD='hunter2hunter2'\n"  # gitleaks:allow
            "the password is hunter2\nthe secret is stored in the vault\n"  # gitleaks:allow
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabcMIIabc\n-----END RSA PRIVATE KEY-----\n")  # gitleaks:allow
    r = scrubber.scrub(text, vault, secrets_only=True)
    for leaked in ("abcdef1234567890", "hunter2hunter2", "hunter2\n", "MIIabc"):  # gitleaks:allow
        assert leaked not in r.text, leaked
    assert "the secret is stored in the vault" in r.text
    assert r.kinds.get("SECRET", 0) >= 4


def test_references_and_placeholders_are_not_secrets(scrubber, vault):
    text = "api_key: os.environ/VLLM_KEY\npassword = $PASS\nTOKEN=<redacted>\nsecret: null\nkey: [SECRET-1]"
    r = scrubber.scrub(text, vault, secrets_only=True)
    assert r.replaced == 0, r


def test_secrets_only_keeps_email_but_full_scrub_does_not(scrubber, vault):
    r = scrubber.scrub("maintainer bob@example.org", vault, secrets_only=True)
    assert "bob@example.org" in r.text
    r = scrubber.scrub("maintainer bob@example.org", vault)
    assert "bob@example.org" not in r.text


def test_phone_bare_digits_need_context_unless_strict(tmp_path, terms):
    # Fresh vault per case: a value one scrub registers is exact-matched by the next.
    def fresh(i):
        return Vault(tmp_path / f"v{i}.json")
    sc = Scrubber(None, terms)
    assert sc.scrub("build 1788893464 finished", fresh(1)).replaced == 0
    assert sc.scrub("call me at 5550102233 tomorrow", fresh(2)).replaced == 1
    assert sc.scrub("5550102233", fresh(3)).replaced == 0
    assert sc.scrub("(555) 010-2233", fresh(4)).replaced == 1
    strict = Scrubber(None, terms, strict=True)
    assert strict.scrub("5550102233", fresh(5)).replaced == 1


def test_card_needs_luhn_and_is_not_a_timestamp_id(scrubber, vault):
    assert scrubber.scrub("card 4242 4242 4242 4242 on file", vault).kinds.get("CARD") == 1  # gitleaks:allow
    assert scrubber.scrub("card 4242 4242 4242 4243 on file", vault).replaced == 0
    assert scrubber.scrub("backup 20260908-154500 done", vault).replaced == 0


def test_vault_persists_with_0600(tmp_path, scrubber):
    v = Vault(tmp_path / "v.json")
    scrubber.scrub("x@example.org", v)
    assert oct(os.stat(tmp_path / "v.json").st_mode & 0o777) == "0o600"
    v2 = Vault(tmp_path / "v.json")
    assert v2.rehydrate("[EMAIL-1]") == "x@example.org"
    assert v2.counts() == {"EMAIL": 1}


def test_nothing_detectable_survives(scrubber, vault):
    text = ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz\n"  # gitleaks:allow
            "xoxb-123456789012-abcdefghij")  # gitleaks:allow
    r = scrubber.scrub(text, vault)
    assert not [s for s in scrubber.find_spans(r.text) if not PLACEHOLDER_RE.fullmatch(s[3])]


def test_pii_mode_catches_unnamed_long_credentials(scrubber, vault):
    text = "WEIRD_NAME=Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS  path=/opt/x/Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS0"  # gitleaks:allow
    full = scrubber.scrub(text, vault)
    assert "Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS " not in full.text and "[SECRET-1]" in full.text
    assert "/opt/x/Zq8pL2mN4vB7xC1kR9tY3wE6uI0oP5aS0" in full.text  # a path segment is not a credential
    sha = "commit 3f2a9c1d4e5b6a7f8091a2b3c4d5e6f708192a3b4"
    assert scrubber.scrub(sha, vault, secrets_only=True).replaced == 0  # ASSIST mode keeps SHAs


def test_entity_registration_takes_values_not_labels(scrubber, vault):
    material = "DB_PASSWORD=hunter2hunter2\nOwner: Jane Q. Example\n"  # gitleaks:allow
    n = scrubber.register_entities([
        {"kind": "SECRET", "value": "DB_PASSWORD"},          # a label: ignored
        {"kind": "SECRET", "value": "hunter2hunter2"},       # the value: registered  # gitleaks:allow
        {"kind": "PERSON", "value": "Jane Q. Example"},
        {"kind": "PERSON", "value": "Nobody Here"},          # not in the material: ignored
    ], material, vault)
    assert n == 2
    r = scrubber.scrub("DB_PASSWORD is set for Jane Q. Example to hunter2hunter2", vault)  # gitleaks:allow
    assert r.text.startswith("DB_PASSWORD is set for [PERSON-") and "hunter2hunter2" not in r.text  # gitleaks:allow


def test_rules_file_replaces_builtins_and_tolerates_extra_keys(tmp_path, terms, vault):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({
        "enabled": True, "router_name": "unrelated", "phrase_rules": [{"id": "p", "pattern": "my password"}],
        "regex_rules": [
            {"id": "email", "pattern": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"},
            {"id": "employee_id", "pattern": r"\bEMP-\d{6}\b"},
            {"id": "disabled_one", "pattern": r"never", "enabled": False},
        ]}))
    sc = Scrubber(rules, terms)
    assert sc.rules.source == str(rules) and len(sc.rules.regex) == 2
    r = sc.scrub("EMP-123456 wrote to a@example.org", vault)
    assert "[PII-1]" in r.text and "[EMAIL-1]" in r.text


def test_env_file_seeds_without_overriding(tmp_path, monkeypatch):
    f = tmp_path / "env"
    f.write_text('# comment\nexport LOCAL_LLM_MCP_MODEL="m1"\nLOCAL_LLM_MCP_MODE=pii # trailing\n'
                 'LOCAL_LLM_MCP_STATE_DIR=$HOME/x\nnot a line\n')
    monkeypatch.setenv("LOCAL_LLM_MCP_ENV_FILE", str(f))
    monkeypatch.setenv("LOCAL_LLM_MCP_MODE", "assist")
    monkeypatch.delenv("LOCAL_LLM_MCP_MODEL", raising=False)
    monkeypatch.delenv("LOCAL_LLM_MCP_STATE_DIR", raising=False)
    assert load_env_file() == 2
    assert os.environ["LOCAL_LLM_MCP_MODEL"] == "m1"
    assert os.environ["LOCAL_LLM_MCP_MODE"] == "assist"
    assert os.environ["LOCAL_LLM_MCP_STATE_DIR"] == os.path.expandvars("$HOME/x")


def test_assignment_value_that_is_a_variable_name_is_a_label(scrubber, vault):
    assert scrubber.scrub("SECRET: TELEGRAM_BOT_TOKEN\nCONFIG: OPENAI_BASE_URL", vault, secrets_only=True).replaced == 0
    assert scrubber.scrub("password: HUNTER2X", vault, secrets_only=True).replaced == 1  # gitleaks:allow


# ---------------------------------------------------------------- identity shapes (PII mode)


def test_identity_shapes_addresses(scrubber, vault):
    text = ("Ship to 1234 N Maple Street, Apt 4B, Springfield, IL 62704 and P.O. Box 889, Boston, MA 02134; "
            "office at 10 Downing Street. Meet in Portland, OR 97201.")
    r = scrubber.scrub(text, vault)
    for v in ("1234 N Maple Street, Apt 4B, Springfield, IL 62704", "P.O. Box 889, Boston, MA 02134",
              "10 Downing Street", "Portland, OR 97201"):
        assert v not in r.text, v
    assert r.kinds == {"ADDRESS": 4}
    assert "[ADDRESS-1]" in r.text and "[ADDRESS-4]" in r.text


def test_identity_shapes_names(scrubber, vault):
    text = ("Dr Ada Lovelace-Byron called. patient: Grace Hopper today.\n"
            "From: Alan M. Turing <alan@example.org>\nDear Hedy,\nthanks for the note.\nRegards,\nLinus Torvalds\n"
            '{"name": "Margaret Hamilton"}\nfirst name: Ken')
    r = scrubber.scrub(text, vault)
    for v in ("Ada Lovelace-Byron", "Grace Hopper", "Alan M. Turing", "Hedy", "Linus Torvalds", "Margaret Hamilton", "Ken"):
        assert v not in r.text, v
    assert r.kinds["PERSON"] == 7 and r.kinds["EMAIL"] == 1
    assert "Dr [PERSON-1] called" in r.text and "Regards,\n[PERSON-" in r.text and '"name": "[PERSON-' in r.text


def test_identity_shapes_dob_and_ids(scrubber, vault):
    text = ("DOB: 03/14/1988; born on 14 March 1988; passport no. X1234567; NHS number: 4857773456; "
            "account number: 00012345678; SSN 123 45 6789; driver's license: D1234567")
    r = scrubber.scrub(text, vault)
    for v in ("03/14/1988", "14 March 1988", "X1234567", "4857773456", "00012345678", "123 45 6789", "D1234567"):
        assert v not in r.text, v
    assert r.kinds == {"DOB": 2, "ID": 3, "ACCOUNT": 1, "SSN": 1}
    assert "passport no. [ID-1]" in r.text and "DOB: [DOB-1]" in r.text


def test_identity_shapes_address_beats_honorific(scrubber, vault):
    r = scrubber.scrub("sent to 12 Sample Dr Springfield IL 62704 yesterday", vault)
    assert r.kinds == {"ADDRESS": 1}
    assert r.text == "sent to [ADDRESS-1] yesterday"


def test_identity_shapes_leave_technical_text_alone(scrubber, vault):
    text = ("PR 12345 merged; graphics card: RTX 5090; license: GPL-3.0; Hi there, hello world\n"
            "hostname: Ms-Alpha; name: local-llm-mcp; version 3 of the way forward; Mr-Beta is a host\n"
            "swift: 5.9; policy: ALLOW; Best\npractices apply; Dear Sir, Hello World!")
    r = scrubber.scrub(text, vault)
    assert r.replaced == 0, r


def test_identity_shapes_pii_mode_only_and_switchable(terms, vault):
    text = "Dr Ada Lovelace lives at 12 Sample Drive, Springfield, IL 62704"
    on = Scrubber(None, terms)
    assert on.scrub(text, vault, secrets_only=True).text == text        # ASSIST mode: untouched
    assert on.scrub(text, vault).kinds == {"PERSON": 1, "ADDRESS": 1}   # PII mode
    off = Scrubber(None, terms, shapes=False)
    assert off.scrub(text, Vault(vault.path.parent / "v2.json")).replaced == 0


def test_nested_placeholder_from_a_worker_collapses(scrubber, vault):
    r = scrubber.scrub("card: [CARD-4111 1111 1111 1111] and again [CARD-4111 1111 1111 1111]", vault)
    assert r.text == "card: [CARD-1] and again [CARD-1]" and r.kinds == {"CARD": 2}
    assert scrubber.scrub("[PERSON-[PERSON-3]] said hi", vault).text == "[PERSON-3] said hi"


# ---- private terms match the value in every common format ---------------------------------------------------

@pytest.fixture
def any_format(tmp_path):
    p = tmp_path / "terms.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "PHONE", "values": ["555-010-0222", "+44 20 7946 0958"]},
        {"kind": "ACCOUNT", "values": ["4400 1234 5678"]},
        {"kind": "EMAIL", "values": ["robin.example@example.org"]},
        {"kind": "ADDRESS", "values": ["12 North Example Street, Apt 4B"]},
        {"kind": "PERSON", "values": ["Robin Example"]},
    ]}))
    return Scrubber(None, p)


@pytest.mark.parametrize("written", [
    "555-010-0222", "(555) 010-0222", "555.010.0222", "555 010 0222", "5550100222", "+1 555 010 0222",
    "+1-555-010-0222", "1 (555) 010-0222", "001 555 010 0222", "555–010–0222", "(555)010-0222",
])
def test_a_phone_number_in_any_format(any_format, vault, written):
    r = any_format.scrub(f"call me on {written} tonight", vault)
    assert "[PHONE-" in r.text and "0222" not in r.text, (written, r.text)


@pytest.mark.parametrize("written", ["+44 20 7946 0958", "+442079460958", "0044 20 7946 0958", "+44 (20) 7946-0958"])
def test_an_international_number_with_or_without_its_prefix(any_format, vault, written):
    r = any_format.scrub(f"office {written}", vault)
    assert "[PHONE-" in r.text and "0958" not in r.text, (written, r.text)


@pytest.mark.parametrize("text", ["555-010-0223", "1555-010-0222-9", "order 85550100222", "555-010-02221"])
def test_a_different_or_longer_number_is_not_the_phone(any_format, vault, text):
    # the term layer alone: the built-in phone shape rightly masks ANY formatted number, term or not
    assert not [sp for sp in any_format.terms.spans(text) if sp[2] == "PHONE"], text


@pytest.mark.parametrize("written", ["4400 1234 5678", "440012345678", "4400-1234-5678", "4400.1234.5678"])
def test_an_account_number_with_any_grouping(any_format, vault, written):
    r = any_format.scrub(f"acct {written}.", vault)
    assert "[ACCOUNT-" in r.text and "5678" not in r.text, (written, r.text)


@pytest.mark.parametrize("written", ["robin.example@example.org", "ROBIN.EXAMPLE@EXAMPLE.ORG", "robin.example at example dot org",  # public:allow non-example email address
                                     "robin.example [at] example [dot] org", "robin.example(at)example(dot)org",
                                     "mailto:robin.example@example.org"])
def test_an_email_in_its_usual_disguises(any_format, vault, written):
    r = any_format.scrub(f"write to {written} please", vault)
    assert "robin.example" not in r.text.lower(), (written, r.text)


@pytest.mark.parametrize("written", ["12 North Example Street, Apt 4B", "12 N. Example St. Apt 4B", "12 N Example St, #4B",
                                     "12 north example street apartment 4b", "12 North Example St\nApt 4B", "12 N Example St Unit 4B"])
def test_an_address_written_out_or_abbreviated(any_format, vault, written):
    r = any_format.scrub(f"Ship to: {written}", vault)
    assert "[ADDRESS-" in r.text and "Example" not in r.text.split(":", 1)[1], (written, r.text)


@pytest.mark.parametrize("written", ["Robin Example", "ROBIN EXAMPLE", "Robin  Example", "Robin\nExample", "Example, Robin",
                                     "Robin J. Example", "Robin J Example"])
def test_a_name_across_spacing_order_and_a_middle_initial(any_format, vault, written):
    r = any_format.scrub(f"signed {written}", vault)
    assert "[PERSON-" in r.text, (written, r.text)


def test_near_misses_are_not_the_terms(any_format):
    text = "Robin Examples met Robinson Example at 12 Example Lane; dial 555-010-0333"
    assert any_format.terms.spans(text) == []


def test_a_match_reports_the_value_as_written_and_takes_the_whole_number(any_format):
    text = "call (555) 010-0222 now"
    [(a, b, kind, value)] = [sp for sp in any_format.terms.spans(text) if sp[2] == "PHONE"]
    assert value == text[a:b] == "(555) 010-0222"
    assert any_format.terms.saved_form("PHONE", value) == "555-010-0222"


# ---- a multi-word term also matches with its words run together ---------------------------------------------

@pytest.fixture
def run_together(tmp_path):
    p = tmp_path / "terms.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "PERSON", "values": ["Zqxa Synthname", "Ovrel-Dax Quembly"]},
        {"kind": "PII", "values": ["Brindle Okapo"]},
    ]}))
    return Scrubber(None, p)


@pytest.mark.parametrize("written, matched, value, kind", [
    ("ZqxaSynthname", "ZqxaSynthname", "Zqxa Synthname", "PERSON"),
    ("zqxasynthname", "zqxasynthname", "Zqxa Synthname", "PERSON"),
    ("ZQXASYNTHNAME-notes", "ZQXASYNTHNAME", "Zqxa Synthname", "PERSON"),
    ("zqxa.synthname", "zqxa.synthname", "Zqxa Synthname", "PERSON"),
    ("zqxa-synthname", "zqxa-synthname", "Zqxa Synthname", "PERSON"),
    ("zqxa/synthname", "zqxa/synthname", "Zqxa Synthname", "PERSON"),
    ("zqxa - synthname", "zqxa - synthname", "Zqxa Synthname", "PERSON"),
    ("zqxasynthname_2026.txt", "zqxasynthname", "Zqxa Synthname", "PERSON"),
    ("OvrelDaxQuembly", "OvrelDaxQuembly", "Ovrel-Dax Quembly", "PERSON"),
    ("ovrel.dax.quembly", "ovrel.dax.quembly", "Ovrel-Dax Quembly", "PERSON"),
    ("brindleokapo", "brindleokapo", "Brindle Okapo", "PII"),
])
def test_a_multi_word_term_run_together(run_together, vault, written, matched, value, kind):
    text = f"see {written} today"
    # a match reports the text as written (its own vault entry), not the saved value
    assert [(text[a:b], k, v) for a, b, k, v in run_together.terms.spans(text)] == [(matched, kind, matched)], text
    assert matched != value
    assert f"[{kind}-1]" in run_together.scrub(text, vault).text


@pytest.mark.parametrize("written", ["zqxa_synthname", "ZQXA_SYNTHNAME", "zqxa__synthname", "zqxa_-_synthname",
                                     "ovrel_dax_quembly", "brindle_okapo"])
def test_an_underscore_joins_run_together_words(run_together, written):
    text = f"user {written} logged in"
    assert [text[a:b] for a, b, _k, _v in run_together.terms.spans(text)] == [written], text


def test_underscore_behaviour_is_pinned(run_together):
    # at most three joiners, underscores included
    assert run_together.terms.spans("zqxa____synthname") == []
    # an underscore after the name is a boundary, not part of a longer word
    assert [sp[3] for sp in run_together.terms.spans("zqxa_synthname_notes")] == ["zqxa_synthname"]


def test_an_underscore_never_separates_digits(any_format):
    # an underscore joins words only: it is not in _SEP, so it never separates the digits of a number
    assert not [sp for sp in any_format.terms.spans("ref 555_010_0222") if sp[2] == "PHONE"]
    assert not [sp for sp in any_format.terms.spans("ref 4400_1234_5678") if sp[2] == "ACCOUNT"]


@pytest.fixture
def joined_kinds(tmp_path):
    p = tmp_path / "terms.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "ADDRESS", "values": ["12 Zqxa Lane"]},
        {"kind": "SSN", "values": ["000 12 3456"]},
        {"kind": "ID", "values": ["QX 7781 22"]},
        {"kind": "ACCOUNT", "values": ["AB12 CD34 EF56"]},
        {"kind": "EMAIL", "values": ["zqxa.synthname@example.org"]},
    ]}))
    return Scrubber(None, p)


@pytest.mark.parametrize("written, kind", [
    ("12-zqxa-lane", "ADDRESS"), ("12_Zqxa_Lane", "ADDRESS"), ("12/zqxa/lane", "ADDRESS"),
    ("000123456", "SSN"), ("000-12-3456", "SSN"), ("000_12_3456", "SSN"),
    ("qx778122", "ID"), ("QX-7781-22", "ID"), ("qx_7781_22", "ID"),
    ("ab12cd34ef56", "ACCOUNT"), ("AB12-CD34-EF56", "ACCOUNT"), ("ab12_cd34_ef56", "ACCOUNT"),
])
def test_run_together_for_other_kinds(joined_kinds, vault, written, kind):
    text = f"on file: {written}."
    assert [(text[a:b], k) for a, b, k, _v in joined_kinds.terms.spans(text)] == [(written, kind)], text
    r = joined_kinds.scrub(text, vault)
    assert written not in r.text and vault.rehydrate(r.text) == text


@pytest.mark.parametrize("text", ["0001234567", "1000123456", "qx7781221", "xab12cd34ef56"])
def test_run_together_for_other_kinds_keeps_boundaries(joined_kinds, text):
    assert joined_kinds.terms.spans(text) == [], text


def test_an_email_gets_no_run_together_form(joined_kinds):
    from local_llm_mcp.scrub import _run_together_pattern, term_pattern
    joined = _run_together_pattern("zqxa synthname@example.org")
    assert joined and joined not in term_pattern("PII", "zqxa synthname@example.org")
    assert joined_kinds.terms.spans("zqxasynthnameexampleorg and zqxa_synthname_example_org") == []


# ---- a run-together match survives the round trip: the placeholder restores the text exactly as written --------

@pytest.mark.parametrize("text", [
    "cat /home/zqxasynthname/notes.txt",                    # a path  # public:allow home directory path
    "git clone ZqxaSynthname/repo.git",                     # a repository
    "open zqxa.synthname-cv.pdf",                           # a file name
    "see https://example.org/u/zqxa_synthname/profile",     # a URL
    "ping @zqxa_synthname or @ZQXASYNTHNAME",               # handles, two forms in one text
    "mv ovrel.dax.quembly.txt OvrelDaxQuembly/",            # a split word, two forms
    "cp brindle-okapo.cfg /srv/brindleokapo/",              # PII kind
])
def test_a_run_together_match_round_trips_exactly(run_together, vault, text):
    r = run_together.scrub(text, vault)
    for name in ("synthname", "quembly", "okapo"):
        assert name not in r.text.lower(), r.text
    assert vault.rehydrate(r.text) == text


def test_each_written_form_keeps_one_placeholder_for_the_conversation(run_together, vault):
    first = run_together.scrub("Zqxa Synthname owns /home/zqxasynthname and ZqxaSynthname/repo", vault).text  # public:allow home directory path
    again = run_together.scrub("again: ZqxaSynthname/repo, /home/zqxasynthname, Synthname, Zqxa", vault).text  # public:allow home directory path
    assert first == "[PERSON-1] owns /home/[PERSON-1.2] and [PERSON-1.3]/repo"
    assert again == "again: [PERSON-1.3]/repo, /home/[PERSON-1.2], [PERSON-1.4]"
    assert [vault.by_placeholder[ph]["value"] for ph in ("[PERSON-1]", "[PERSON-1.2]", "[PERSON-1.3]", "[PERSON-1.4]")] \
        == ["Zqxa Synthname", "zqxasynthname", "ZqxaSynthname", "Synthname, Zqxa"]
    assert run_together.scrub("Ovrel-Dax Quembly", vault).text == "[PERSON-2]"  # the next person, next number


# ---- every written form of a private term restores exactly as written ------------------------------------------
# Measured on main (b03f3c2) by the review of PR #10: these restored the term AS SAVED ("Example, Robin" came back as
# "Robin Example", "4400-1234-5678" as "4400 1234 5678"), which changed what a reused placeholder did in a command.

@pytest.mark.parametrize("text", [
    # names: order, case, spacing, a line break, a middle initial
    "signed Robin Example", "signed Example, Robin", "signed Example ,Robin", "signed ROBIN EXAMPLE",
    "signed robin example", "signed Robin J. Example", "signed Robin J Example", "signed Robin  Example",
    "signed Robin\nExample",
    # addresses: abbreviated, and run together with nothing, full stops or commas
    "Ship to: 12 North Example Street, Apt 4B", "Ship to: 12 N. Example St. Apt 4B", "Ship to: 12 N Example St, #4B",
    "Ship to: 12 north example street apartment 4b", "Ship to: 12 North Example St\nApt 4B",
    "Ship to: 12 N Example St Unit 4B", "Ship to: 12northexamplestreetapt4b", "Ship to: 12.North.Example.Street.Apt.4B",
    "Ship to: 12,North,Example,Street,Apt,4B",
    # phones: with and without a country-code prefix, any grouping
    "call 555-010-0222 tonight", "call 001 555 010 0222 tonight", "call +1 555 010 0222 tonight",
    "call 1 (555) 010-0222 tonight", "call (555) 010-0222 tonight", "call 5550100222 tonight",
    "call 555–010–0222 tonight", "office +44 20 7946 0958", "office 0044 20 7946 0958", "office +442079460958",
    "office +44 (20) 7946-0958", "office 44 20 7946 0958", "office:442079460958",
    # account numbers: any grouping
    "acct 4400 1234 5678.", "acct 4400-1234-5678.", "acct 440012345678.", "acct 4400.1234.5678.",
    "ACCT=4400-1234-5678",
    # e-mails in their usual disguises
    "write to robin.example@example.org please", "write to robin.example at example dot org please",
    "write to robin.example [at] example [dot] org please", "write to robin.example(at)example(dot)org please",
    "write to ROBIN.EXAMPLE@EXAMPLE.ORG please", "write to mailto:robin.example@example.org please",  # public:allow non-example email address
])
def test_every_written_form_round_trips_exactly(any_format, vault, text):
    r = any_format.scrub(text, vault)
    for private in ("robin", "example", "0222", "0958", "7946", "5678"):
        assert private not in r.text.lower(), (text, r.text)
    assert vault.rehydrate(r.text) == text, r.text


def test_the_spellings_of_one_value_share_its_number(any_format, vault):
    text = "Example, Robin wrote; Robin Example replied; ROBIN EXAMPLE and robinexample signed"
    r = any_format.scrub(text, vault)
    assert r.text == "[PERSON-1] wrote; [PERSON-1.2] replied; [PERSON-1.3] and [PERSON-1.4] signed"
    assert vault.rehydrate(r.text) == text
    assert vault.by_placeholder["[PERSON-1.3]"] == {"kind": "PERSON", "value": "ROBIN EXAMPLE", "term": "Robin Example"}
    assert vault.counts() == {"PERSON": 1}  # one person, four spellings


def test_disclosure_counts_values_not_spellings(any_format, vault, tmp_path):
    from local_llm_mcp.scrub import Policy
    material = "Example, Robin; Robin Example; robinexample; acct 4400-1234-5678 and 440012345678"
    counts = any_format.register_material(material, vault, policy=Policy.register(entropy=False))
    assert counts == {"PERSON": 1, "ACCOUNT": 1}
    # the name inside an e-mail address is that person, not another one
    mail = "From: robin.example@example.org (Robin Example)"
    assert any_format.register_material(mail, Vault(tmp_path / "mail.json"), policy=Policy.register(entropy=False)) \
        == {"EMAIL": 1, "PERSON": 1}


def test_spelling_numbers_survive_a_reload(run_together, tmp_path):
    run_together.scrub("Zqxa Synthname, zqxasynthname", Vault(tmp_path / "v.json"))
    again = Vault(tmp_path / "v.json")
    assert run_together.scrub("ZQXA SYNTHNAME and Ovrel-Dax Quembly", again).text == "[PERSON-1.3] and [PERSON-2]"


def test_a_vault_from_before_spellings_had_numbers_keeps_its_entries(any_format, tmp_path):
    p = tmp_path / "v.json"
    p.write_text(json.dumps({"placeholders": {"[PERSON-1]": {"kind": "PERSON", "value": "Robin Example"},
                                              "[PERSON-2]": {"kind": "PERSON", "value": "robinexample"}}}))
    v = Vault(p)
    r = any_format.scrub("Example, Robin, Robin Example, robinexample", v)
    assert r.text == "[PERSON-1.2], [PERSON-1], [PERSON-2]"  # the saved value's entry takes the new spelling
    assert v.rehydrate(r.text) == "Example, Robin, Robin Example, robinexample"


def test_a_spelling_placeholder_is_a_placeholder(scrubber, vault):
    assert PLACEHOLDER_RE.fullmatch("[PERSON-1.2]")
    assert scrubber.scrub("[PERSON-[PERSON-1.2]] said hi", vault).text == "[PERSON-1.2] said hi"
    assert vault.rehydrate("keep [PERSON-1.9] and [PERSON-1.]") == "keep [PERSON-1.9] and [PERSON-1.]"


# The reviewer's measurements, run through the server's own shell runner: the command the caller writes with a
# placeholder must do what the original command did.
@pytest.mark.skipif(shutil.which("bash") is None, reason="the shell runner needs bash")
@pytest.mark.parametrize("command, expected", [
    ("grep -c '4400-1234-5678' ledger.csv", "1"),                  # was 0: a silent wrong answer
    ("printf '<%s>' ACCT=4400-1234-5678", "<ACCT=4400-1234-5678>"),  # was <ACCT=4400><1234><5678>
    ("wc -l Example,Robin", "2 Example,Robin"),                     # was wc -l Robin Example: another file read
    ("cat 'Robin  Example.txt'", "double-spaced"),
])
def test_a_reused_placeholder_runs_the_command_as_written(any_format, vault, tmp_path, command, expected):
    from local_llm_mcp.material import run_command

    def run(cmd: str) -> str:
        return asyncio.run(run_command(cmd, cwd=str(tmp_path), timeout=30, max_chars=10_000)).output.strip()

    (tmp_path / "ledger.csv").write_text("4400-1234-5678,12.00\n")
    (tmp_path / "Example,Robin").write_text("one\ntwo\n")
    (tmp_path / "Robin").write_text("an unrelated file\n" * 5)
    (tmp_path / "Robin  Example.txt").write_text("double-spaced\n")
    scrubbed = any_format.scrub(command, vault).text
    assert "Robin" not in scrubbed and "5678" not in scrubbed, scrubbed
    assert run(command) == expected
    assert run(vault.rehydrate(scrubbed)) == expected


@pytest.mark.parametrize("text", ["xzqxasynthname", "zqxasynthname2", "zqxasynthnames", "9zqxasynthname",
                                  "zqxasynth name", "synthnamezqxa", "ovreldax quemblyx"])
def test_run_together_keeps_word_boundaries(run_together, text):
    assert run_together.terms.spans(text) == [], text


@pytest.mark.parametrize("written", ["Zqxa Synthname", "zqxa\nsynthname", "Synthname, Zqxa", "Zqxa R. Synthname",
                                     "Ovrel-Dax Quembly", "Quembly, Ovrel-Dax"])
def test_run_together_keeps_every_earlier_format(run_together, vault, written):
    assert "[PERSON-" in run_together.scrub(f"signed {written}", vault).text, written


@pytest.mark.parametrize("kind, value, expected", [
    ("PERSON", "Zqxa", r"(?<![A-Za-z0-9])Zqxa(?![A-Za-z0-9])"),
    ("PERSON", "Ovrel-Dax", r"(?<![A-Za-z0-9])Ovrel\-Dax(?![A-Za-z0-9])"),
    ("PII", "Synthname", r"(?<![A-Za-z0-9])Synthname(?![A-Za-z0-9])"),
])
def test_a_single_word_term_is_unchanged(kind, value, expected):
    from local_llm_mcp.scrub import term_pattern
    assert term_pattern(kind, value) == expected


@pytest.mark.parametrize("shape", [
    "zqxa" * 25_000,                                   # the first word over and over, never the second
    "zqxa-./" * 14_286,                                # the first word, then a full run of separators
    "zqxa synthnam " * 7_143,                          # near misses: the second word one letter short
    " -.()/" * 16_667,                                 # nothing but separators
    "zqxa" + " " * 99_996,                             # one first word, then a single long whitespace run
    "ovrel-dax-" * 10_000,                             # a word that holds a separator, repeated
    "_" * 100_000,                                     # nothing but underscores
    "zqxa___" * 14_286,                                # the first word, then a full run of underscores
    "zqxa_synthnam_" * 7_143,                          # underscore-joined near misses
    "zqxa_-_._/_" * 9_091,                             # the first word, then underscores mixed with separators
    "ovrel_dax_" * 10_000,                             # a word split on an underscore, repeated
], ids=["first-word-repeated", "first-word-then-separators", "near-miss", "separators-only", "long-whitespace",
        "split-word-repeated", "underscores-only", "first-word-then-underscores", "underscore-near-miss",
        "underscores-and-separators", "underscore-split-word-repeated"])
def test_run_together_matching_is_linear_on_adversarial_text(run_together, shape):
    import time
    text = shape[:100_000]
    assert len(text) == 100_000
    t0 = time.perf_counter()
    spans = run_together.terms.spans(text)
    elapsed = time.perf_counter() - t0
    assert spans == [] and elapsed < 1.0, (elapsed, shape[:20])


# ---- term matching and rehydration stay linear on 1 MB of adversarial text --------------------------------------

def _repeat(unit: str, n: int) -> str:
    return (unit * (n // len(unit) + 1))[:n]


_ADVERSARIAL = {  # every shape matches nothing, so all the work is failed attempts
    "email-local-then-spaces": lambda n: ("qelvo.tarnish" + " " * n)[:n],  # was quadratic: 4.6 s at 20 KB on main
    "email-local-at-then-spaces": lambda n: ("qelvo.tarnish at" + " " * n)[:n],
    "email-disguises-repeated": lambda n: _repeat("qelvo.tarnish (at) example (dot) ", n),
    "name-first-then-spaces": lambda n: ("Robin" + " " * n)[:n],
    "name-last-comma-then-spaces": lambda n: ("Example," + " " * n)[:n],
    "name-first-initial-repeated": lambda n: _repeat("Robin J. ", n),
    "address-number-then-separators": lambda n: ("12" + _repeat(",. ", n))[:n],
    "address-words-repeated": lambda n: _repeat("12 north example st apt ", n),
    "phone-digits-then-separators": lambda n: ("555" + _repeat(" -.", n))[:n],
    "phone-prefix-then-separators": lambda n: ("+" + _repeat(" (", n))[:n],
    "account-groups-repeated": lambda n: _repeat("4400 1234 ", n),
    "run-together-near-miss": lambda n: _repeat("zqxa_synthnam ", n),
    "placeholder-prefixes": lambda n: _repeat("[PERSON-1.", n),
}


@pytest.fixture
def every_format(tmp_path):
    p = tmp_path / "every.json"
    p.write_text(json.dumps({"terms": [
        {"kind": "PHONE", "values": ["555-010-0222", "+44 20 7946 0958"]},
        {"kind": "ACCOUNT", "values": ["4400 1234 5678"]},
        {"kind": "EMAIL", "values": ["qelvo.tarnish@example.org"]},  # a local part that is no name's run-together form
        {"kind": "ADDRESS", "values": ["12 North Example Street, Apt 4B"]},
        {"kind": "PERSON", "values": ["Robin Example", "Zqxa Synthname", "Ovrel-Dax Quembly"]},
    ]}))
    return Scrubber(None, p)


@pytest.mark.parametrize("shape", list(_ADVERSARIAL))
def test_term_matching_and_rehydration_are_linear_on_1mb(every_format, tmp_path, shape):
    vault = Vault(tmp_path / "v.json")
    for written in ("Robin Example", "robinexample", "Example, Robin"):
        vault.placeholder_for("PERSON", written, term="Robin Example")

    def cost(n: int) -> tuple[float, list]:
        text = _ADVERSARIAL[shape](n)
        assert len(text) == n
        t0 = time.perf_counter()
        spans = every_format.terms.spans(text)
        vault.rehydrate(text)
        return time.perf_counter() - t0, spans

    small, spans = cost(16_000)  # fail fast: a quadratic shape already takes seconds at this size
    assert spans == [] and small < 0.5, (shape, small)
    half, _ = cost(500_000)
    full, spans = cost(1_000_000)
    assert spans == [] and full < 10.0, (shape, full)
    assert full < 3 * half + 0.05, (shape, half, full)  # linear doubles; quadratic would quadruple


@pytest.mark.parametrize("text, secret", [
    ('{"password": "hunter2secret"}', "hunter2secret"),
    ('{"api_key":"abcd1234value"}', "abcd1234value"),
    ('{"password": "three word phrase"}', "three word phrase"),
    ('{\\"password\\":\\"hunter2secret\\"}', "hunter2secret"),
    ("docker run -e DB_PASSWORD=S3cretValue123 img", "S3cretValue123"),
    ("FOO=1 MY_API_TOKEN=abcdef123456 cmd", "abcdef123456"),
    ("run AWS_SECRET_ACCESS_KEY=abc123def456 x", "abc123def456"),
    ("A=1\0GITHUB_TOKEN=abcdef123456\0B=2\0", "abcdef123456"),
    ("A=1\0LOCAL_LLM_MCP_API_KEY=zzz123456\0", "zzz123456"),
    ("postgres://app:p4ssw0rd@dbhost:5432/db", "p4ssw0rd"),
    ("redis://:p4ssw0rd@cache:6379/0", "p4ssw0rd"),
    ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("password=$3cr3tValue!", "$3cr3tValue!"),
    ("password: /Xk29sjabc", "/Xk29sjabc"),
    ("password={abc12345", "{abc12345"),
])
def test_common_secret_shapes_are_masked(scrubber, vault, text, secret):
    assert secret not in scrubber.scrub(text, vault, secrets_only=True).text


def test_a_nul_separated_environment_keeps_its_other_variables(scrubber, vault):
    out = scrubber.scrub("HOME=/srv/app\0GITHUB_TOKEN=abcdef123456\0LANG=C\0", vault, secrets_only=True).text
    assert "HOME=/srv/app\0" in out and "\0LANG=C\0" in out


@pytest.mark.parametrize("text", [
    "password = $DB_PASS", "password = $db_pass", "token=${VAULT_TOKEN}", "secret: $(cat /run/key)", "password: %DB_PASS%",
    "password = {{ vault_db }}", "password={password}", "TOKEN=<redacted>", "password_file: /run/secrets/db",
    "password: /run/secrets/db", "api_key: ~/keys/service", "https://example.org:8443/path@v2", "a basic setup is fine",
])
def test_references_and_lookalikes_stay_readable(scrubber, vault, text):
    assert scrubber.scrub(text, vault, secrets_only=True).text == text


def test_a_pem_cut_before_its_end_loses_its_body_too(scrubber, vault):
    out = scrubber.scrub("-----BEGIN PRIVATE KEY-----\nMIIEFAKEbodyline1AAAA\nMIIEFAKEbodyline2BBBB\n", vault, secrets_only=True).text
    assert "MIIEFAKE" not in out


def test_keep_lines_leaves_the_line_count_alone(scrubber, vault):
    text = "a\n-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\nz"
    out = scrubber.scrub(text, vault, secrets_only=True, keep_lines=True).text
    assert out.count("\n") == text.count("\n") and out.split("\n")[-1] == "z"


def test_a_long_capital_run_stays_fast(scrubber, vault):
    t0 = time.monotonic()
    scrubber.find_spans("KEY_" * 50_000, secrets_only=True)
    assert time.monotonic() - t0 < 5


# ---- Italian --------------------------------------------------------------------------

@pytest.mark.parametrize("text, private", [
    ("Codice fiscale: RSSMRA85T10A562S", "RSSMRA85T10A562S"),
    ("cf rssmra85t10a562s nel modulo", "rssmra85t10a562s"),
    ("P.IVA 01234567890", "01234567890"),
    ("Partita IVA: IT01234567890", "01234567890"),
    ("Indirizzo: Via Roma 12, 00184 Roma", "Via Roma 12"),
    ("Indirizzo: Via Roma 12, 00184 Roma", "00184 Roma"),
    ("abita in via XX Settembre 5/B", "XX Settembre 5"),
    ("in Piazza dell'Unità d'Italia, 3", "Unità"),
    ("Corso Vittorio Emanuele n. 21", "Vittorio Emanuele"),
    ("spedire a 20121 Milano (MI)", "20121 Milano"),
    ("Sig. Mario Rossi", "Mario Rossi"),
    ("la Sig.ra Niccolò De Luca", "Niccolò De Luca"),
    ("Dott.ssa Anna Bianchi", "Anna Bianchi"),
    ("Avv. Carlo Verdi", "Carlo Verdi"),
    ("Nome: Mario Rossi", "Mario Rossi"),
    ("Cognome: Rossi", "Rossi"),
    ("Nome e cognome: Anna Bianchi", "Anna Bianchi"),
    ("Intestatario: Anna Bianchi", "Anna Bianchi"),
    ("Da: Anna Bianchi <x@example.org>", "Anna Bianchi"),
    ("Gentile Mario Rossi,", "Mario Rossi"),
    ("Ciao Mario,\ncome va?", "Mario"),
    ("Cordiali saluti,\nAnna Bianchi\n", "Anna Bianchi"),
    ("Data di nascita: 10/12/1985", "10/12/1985"),
    ("nato a Reggio Emilia il 3 marzo 1985", "3 marzo 1985"),
    ("Patente n. U1A2B3C4D", "U1A2B3C4D"),
    ("Carta d'identità: CA12345AB", "CA12345AB"),
    ("conto corrente 000123456789", "000123456789"),
    ("+39 333 1234567", "333 1234567"),
    ("Telefono: 06 1234567", "06 1234567"),
    ("cell. 3331234567", "3331234567"),
    ("chiamami al 333 1234567", "333 1234567"),
])
def test_italian_private_data_is_masked(scrubber, vault, text, private):
    assert private not in scrubber.scrub(text, vault).text


@pytest.mark.parametrize("text", [
    "RSSMRA85T10A562X", "via HTTP 200", "accesso via SSH 22", "via CLI 2", "arrivato via email", "installato su Arch Linux", "una Rag Pipeline",
    "Buongiorno a tutti,", "Gentile Cliente,", "il token è scaduto", "la password è sbagliata", "numero 3331234567 in coda",
    "2026-09-08T21:10:11 host systemd[1]: pid 3345 rc=0 bytes=1234567", "nato il giorno prima", "il corso di Python",
])
def test_italian_lookalikes_stay_readable(scrubber, vault, text):
    assert scrubber.scrub(text, vault).text == text


def test_a_codice_fiscale_homocode_is_checked_and_masked(scrubber, vault):
    body = "RSSMRA85T10A56N"  # the 2 of A562 replaced by its homocode letter
    good = next(body + c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if codice_fiscale_ok(body + c))
    assert good not in scrubber.scrub(good, vault).text


@pytest.mark.parametrize("text, secret", [
    ("la password è hunter2value", "hunter2value"), ("il token è abcd1234", "abcd1234"), ("la parola d'ordine era Pippo-99", "Pippo-99"),
    ("il PIN è 4821", "4821"),
])
def test_italian_prose_secrets_are_masked_in_assist_too(scrubber, vault, text, secret):
    assert secret not in scrubber.scrub(text, vault, secrets_only=True).text


def test_italian_identity_shapes_follow_the_switch_and_the_policy(terms, vault):
    text = "Sig. Mario Rossi, Codice fiscale RSSMRA85T10A562S"
    assert Scrubber(None, terms, shapes=False).scrub(text, vault).text == text
    assert Scrubber(None, terms).scrub(text, vault, secrets_only=True).text == text


@pytest.mark.parametrize("shape", ["Via " * 40_000, "Via Roma " * 20_000, "A" * 160_000, "nato a " * 25_000, "Sig. " * 30_000, "333 " * 40_000])
def test_italian_shapes_stay_fast_on_hostile_text(scrubber, shape):
    t0 = time.monotonic()
    scrubber.find_spans(shape)
    assert time.monotonic() - t0 < 5
