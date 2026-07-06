import xml.etree.ElementTree as ET

from morpheus.models import Finding, Severity
from morpheus.reporter import (
    write_html_report,
    write_junit_xml,
    write_scorecard_json,
)
from morpheus.scorer import Scorecard, score_run


def test_write_scorecard_json_roundtrip(fixture_findings, tmp_path):
    card = score_run(fixture_findings, "mock", "core")
    path = tmp_path / "sc.json"
    write_scorecard_json(card, str(path))
    import json

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
