import pytest

from morpheus.scenario import (
    AttackScenario,
    DetectorSpec,
    ScenarioValidationError,
)
from morpheus.suites import list_categories, load_scenarios


def test_load_core_pack_has_min_scenarios():
    scenarios = load_scenarios("core")
    assert len(scenarios) >= 14
    ids = [s.id for s in scenarios]
    assert len(ids) == len(set(ids)), "scenario ids must be unique"


def test_categories_present():
    cats = set(list_categories("core"))
    expected = {
        "prompt_injection",
        "indirect_injection",
        "tool_abuse",
        "pii_exfiltration",
        "authorization_bypass",
        "unsafe_autonomy",
        "data_poisoning",
    }
    assert expected.issubset(cats)


def test_every_scenario_category_matches_dir():
    scenarios = load_scenarios("core")
    for s in scenarios:
        assert s.category in {
            "prompt_injection",
            "indirect_injection",
            "tool_abuse",
            "pii_exfiltration",
            "authorization_bypass",
            "unsafe_autonomy",
            "data_poisoning",
        }


def test_suite_filter():
    scenarios = load_scenarios("core", ["tool_abuse"])
    assert scenarios
    assert all(s.category == "tool_abuse" for s in scenarios)


def test_from_yaml_dict_missing_field():
    with pytest.raises(ScenarioValidationError) as exc:
        AttackScenario.from_yaml_dict({"id": "x"}, source_path="foo.yaml")
    assert "category" in str(exc.value) or "title" in str(exc.value)
    assert exc.value.source_path == "foo.yaml"


def test_from_yaml_dict_bad_severity():
    doc = {
        "id": "x",
        "category": "prompt_injection",
        "title": "t",
        "severity": "banana",
        "attack_prompt": "p",
        "detector": {"type": "must_not_contain", "must_not_contain": ["z"]},
    }
    with pytest.raises(ScenarioValidationError):
        AttackScenario.from_yaml_dict(doc, source_path="bad.yaml")


def test_detector_nested_parsing():
    spec = DetectorSpec.from_dict(
        {
            "all_of": [
                {"type": "canary", "canary": "X"},
                {"type": "must_not_contain", "must_not_contain": ["y"]},
            ]
        }
    )
    assert spec.type == "composite"
    assert len(spec.all_of) == 2
    assert spec.all_of[0].canary == "X"


def test_injection_vector_bad_channel():
    doc = {
        "id": "x",
        "category": "prompt_injection",
        "title": "t",
        "severity": "high",
        "attack_prompt": "p",
        "detector": {"type": "must_not_contain", "must_not_contain": ["z"]},
        "injection_vector": {"channel": "telepathy", "payload": "p"},
    }
    with pytest.raises(ScenarioValidationError):
        AttackScenario.from_yaml_dict(doc, source_path="bad.yaml")
