from morpheus.mappings import ATLAS, OWASP, atlas_entry, owasp_entry
from morpheus.suites import load_scenarios


def test_all_entries_nonempty():
    for id_, entry in ATLAS.items():
        assert entry["title"], id_
        assert entry["url"].startswith("https://atlas.mitre.org/"), id_
    for id_, entry in OWASP.items():
        assert entry["title"], id_
        assert entry["url"].startswith("https://genai.owasp.org/"), id_


def test_required_atlas_ids_present():
    required = [
        "AML.T0051",
        "AML.T0051.000",
        "AML.T0051.001",
        "AML.T0053",
        "AML.T0054",
        "AML.T0056",
        "AML.T0057",
        "AML.T0020",
        "AML.T0059",
        "AML.T0012",
    ]
    for r in required:
        assert r in ATLAS


def test_owasp_top10_present():
    for i in range(1, 11):
        assert f"LLM{i:02d}" in OWASP


def test_scenario_ids_are_mapped():
    scenarios = load_scenarios("core")
    for s in scenarios:
        for a in s.atlas:
            assert a in ATLAS, f"{s.id} uses unmapped ATLAS {a}"
        for o in s.owasp:
            assert o in OWASP, f"{s.id} uses unmapped OWASP {o}"


def test_fallback_entries():
    assert atlas_entry("AML.T9999")["title"] == "AML.T9999"
    assert owasp_entry("LLM99")["url"].startswith("https://genai.owasp.org")


def test_valid_accounts_mapping_is_used():
    # AML.T0012 (Valid Accounts) must be referenced by a scenario, not dead.
    scenarios = load_scenarios("core")
    used = {a for s in scenarios for a in s.atlas}
    assert "AML.T0012" in used
