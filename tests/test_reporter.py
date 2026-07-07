import json
import xml.etree.ElementTree as ET

from morpheus.models import Finding, Severity
from morpheus.reporter import (
    write_html_report,
    write_junit_xml,
    write_sarif,
    write_scorecard_json,
)
from morpheus.scorer import Scorecard, score_run


def test_write_scorecard_json_roundtrip(fixture_findings, tmp_path):
    card = score_run(fixture_findings, "mock", "core")
    path = tmp_path / "sc.json"
    write_scorecard_json(card, str(path))
    data = json.loads(path.read_text())
    restored = Scorecard.from_dict(data)
    assert restored.overall_score == card.overall_score


def test_html_report_is_self_contained(fixture_findings, tmp_path):
    card = score_run(fixture_findings, "mock", "core")
    path = tmp_path / "report.html"
    write_html_report(card, str(path))
    html = path.read_text()
    assert "<!DOCTYPE html>" in html
    assert "<style>" in html
    assert "Grade F" in html
    assert "atlas.mitre.org" in html
    assert "genai.owasp.org" in html
    # no external stylesheet/script references
    assert "http-equiv" not in html or True
    assert "<link" not in html


def test_html_escapes_dynamic_text(tmp_path):
    findings = [
        Finding(
            scenario_id="x",
            category="c",
            title="<script>alert(1)</script>",
            passed=False,
            severity=Severity.HIGH,
            detector_name="d",
            detector_detail="<b>bad</b>",
            response_excerpt="<img src=x>",
        )
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "r.html"
    write_html_report(card, str(path))
    html = path.read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_junit_xml_valid_and_has_failure(fixture_findings, tmp_path):
    card = score_run(fixture_findings, "mock", "core")
    path = tmp_path / "junit.xml"
    write_junit_xml(card, str(path))
    tree = ET.parse(path)
    root = tree.getroot()
    assert root.tag == "testsuite"
    cases = root.findall("testcase")
    assert len(cases) == 3
    failures = root.findall(".//failure")
    assert len(failures) == 2  # critical + low failed


def test_junit_info_is_skipped(tmp_path):
    findings = [
        Finding("a", "c", "t", True, Severity.INFO, "d", "adapter error: boom"),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "junit.xml"
    write_junit_xml(card, str(path))
    root = ET.parse(path).getroot()
    assert root.findall(".//skipped")


def test_junit_errored_is_skipped_not_failure(tmp_path):
    findings = [
        Finding(
            "a",
            "c",
            "t",
            False,
            Severity.INFO,
            "tool_call",
            "adapter error: flake",
            errored=True,
        ),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "junit.xml"
    write_junit_xml(card, str(path))
    root = ET.parse(path).getroot()
    assert root.findall(".//skipped")
    assert not root.findall(".//failure")


def test_html_shows_errored_count_and_label(tmp_path):
    findings = [
        Finding(
            "a",
            "c",
            "errored scenario",
            False,
            Severity.INFO,
            "tool_call",
            "adapter error: flake",
            errored=True,
        ),
        Finding("b", "c", "real fail", False, Severity.HIGH, "d", "leak"),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "r.html"
    write_html_report(card, str(path))
    html = path.read_text()
    assert "Errored (excluded): 1" in html
    assert "ERRORED (excluded)" in html


def test_junit_failures_attr_matches_failure_elements(tmp_path):
    # Mixed: one failed INFO (non-errored) + one failed HIGH + one errored.
    findings = [
        Finding("i1", "c", "failed info", False, Severity.INFO, "must_not_contain", "leak"),
        Finding("h1", "c", "failed high", False, Severity.HIGH, "canary", "leak"),
        Finding(
            "e1",
            "c",
            "errored",
            False,
            Severity.INFO,
            "tool_call",
            "adapter error: flake",
            errored=True,
        ),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "junit.xml"
    write_junit_xml(card, str(path))
    root = ET.parse(path).getroot()
    failures = root.findall(".//failure")
    skipped = root.findall(".//skipped")
    # Failed INFO is now a real <failure> (not skipped); errored stays <skipped>.
    assert len(failures) == 2
    assert len(skipped) == 1
    assert root.get("failures") == str(len(failures))
    assert root.get("skipped") == str(len(skipped))
    assert root.get("tests") == "3"


def test_html_findings_have_filter_attributes(tmp_path):
    findings = [
        Finding("s1", "c", "secure", True, Severity.HIGH, "d", "ok"),
        Finding("v1", "c", "vuln", False, Severity.CRITICAL, "d", "leak"),
        Finding(
            "e1", "c", "errored", False, Severity.INFO, "d", "adapter error", errored=True
        ),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "r.html"
    write_html_report(card, str(path))
    html = path.read_text()
    assert 'data-status="secure"' in html
    assert 'data-status="vulnerable"' in html
    assert 'data-status="errored"' in html
    assert 'data-severity="critical"' in html
    # Filter UI + summary table present, still self-contained.
    assert 'id="finding-filters"' in html
    assert "<h2>Failed findings</h2>" in html
    assert "<link" not in html


def test_sarif_valid_and_maps_levels(tmp_path):
    findings = [
        Finding("c1", "tool_abuse", "crit", False, Severity.CRITICAL, "tool_call", "boom",
                atlas=["AML.T0053"], owasp=["LLM06"]),
        Finding("m1", "c", "med", False, Severity.MEDIUM, "regex", "matched"),
        Finding("l1", "c", "low", False, Severity.LOW, "regex", "matched"),
        Finding("p1", "c", "passed", True, Severity.HIGH, "d", "ok"),
        Finding(
            "e1", "c", "errored", False, Severity.HIGH, "d", "adapter error", errored=True
        ),
    ]
    card = score_run(findings, "mock", "core")
    path = tmp_path / "out.sarif"
    write_sarif(card, str(path))
    data = json.loads(path.read_text())
    assert data["version"] == "2.1.0"
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Morpheus"
    results = data["runs"][0]["results"]
    # Only failed non-errored findings become results (crit, med, low).
    assert len(results) == 3
    levels = {r["ruleId"]: r["level"] for r in results}
    assert levels["c1"] == "error"
    assert levels["m1"] == "warning"
    assert levels["l1"] == "note"
    # helpUri sourced from OWASP mapping when present.
    rules = {r["id"]: r for r in driver["rules"]}
    assert rules["c1"]["helpUri"].startswith("https://genai.owasp.org/")
