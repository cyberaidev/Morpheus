"""Write scorecards as JSON, self-contained HTML, and JUnit XML.

HTML and JUnit generation use only the standard library so ``jinja2`` is not a
runtime dependency.
"""

from __future__ import annotations

import html
import json
import os
import xml.etree.ElementTree as ET

from . import __version__
from .mappings import atlas_entry, owasp_entry
from .models import Severity, to_serializable
from .scorer import Scorecard

_TEMPLATE = os.path.join(os.path.dirname(__file__), "templates", "report.html.tmpl")

# SARIF result levels keyed by finding severity.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_GAUGE_COLORS = {
    "A": "#1a7f37",
    "B": "#4c9a2a",
    "C": "#b8860b",
    "D": "#d1491c",
    "F": "#b3001b",
}


def write_scorecard_json(scorecard: Scorecard, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    data = to_serializable(scorecard)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def _sev_class(sev: str) -> str:
    return f"sev-{sev}"


def _links(ids: list[str], kind: str) -> str:
    cells = []
    for i in ids:
        entry = atlas_entry(i) if kind == "atlas" else owasp_entry(i)
        cells.append(
            f'<a href="{html.escape(entry["url"])}" '
            f'title="{html.escape(entry["title"])}">{html.escape(i)}</a>'
        )
    return ", ".join(cells) if cells else "&mdash;"


def _finding_status(f) -> str:
    """Return the finding status token used for filtering: secure|vulnerable|errored."""
    if f.errored:
        return "errored"
    return "secure" if f.passed else "vulnerable"


def _findings_html(scorecard: Scorecard) -> str:
    blocks = []
    for f in scorecard.findings:
        data_status = _finding_status(f)
        if data_status == "errored":
            status = '<span class="sev-info">ERRORED (excluded)</span>'
        elif data_status == "secure":
            status = '<span class="pass">SECURE (passed)</span>'
        else:
            status = '<span class="fail">VULNERABLE (failed)</span>'
        sev = f.severity.value
        summary = (
            f"{html.escape(f.scenario_id)} &mdash; {html.escape(f.title)} "
            f'[<span class="{_sev_class(sev)}">{html.escape(sev)}</span>] {status}'
        )
        block = (
            f'<details class="finding" data-severity="{html.escape(sev)}" '
            f'data-status="{html.escape(data_status)}">\n'
            f"  <summary>{summary}</summary>\n"
            f'  <p class="kv"><strong>Category:</strong> {html.escape(f.category)}</p>\n'
            f'  <p class="kv"><strong>Detector:</strong> {html.escape(f.detector_name)}'
            f" &mdash; {html.escape(f.detector_detail)}</p>\n"
            f'  <p class="kv"><strong>ATLAS:</strong> {_links(f.atlas, "atlas")}'
            f' &middot; <strong>OWASP:</strong> {_links(f.owasp, "owasp")}</p>\n'
            f'  <p class="kv"><strong>Remediation:</strong> {html.escape(f.remediation)}</p>\n'
            f'  <p class="kv"><strong>Attack prompt:</strong></p>\n'
            f'  <div class="excerpt">{html.escape(f.request_prompt)}</div>\n'
            f'  <p class="kv"><strong>Response excerpt:</strong></p>\n'
            f'  <div class="excerpt">{html.escape(f.response_excerpt)}</div>\n'
            "</details>"
        )
        blocks.append(block)
    return "\n".join(blocks) if blocks else "<p>No findings.</p>"


def _failed_findings_rows(scorecard: Scorecard) -> str:
    """Rows for the top 'Failed findings' summary table (failed, non-errored)."""
    rows = []
    for f in scorecard.findings:
        if f.passed or f.errored:
            continue
        remediation = f.remediation or ""
        one_line = remediation.replace("\n", " ").strip()
        if len(one_line) > 160:
            one_line = one_line[:157] + "..."
        rows.append(
            "      <tr>"
            f"<td>{html.escape(f.scenario_id)}</td>"
            f'<td class="{_sev_class(f.severity.value)}">'
            f"{html.escape(f.severity.value)}</td>"
            f"<td>{html.escape(f.title)}</td>"
            f'<td>{_links(f.atlas, "atlas")} &middot; {_links(f.owasp, "owasp")}</td>'
            f"<td>{html.escape(one_line)}</td>"
            "</tr>"
        )
    if not rows:
        return (
            '      <tr><td colspan="5">No failed findings &mdash; '
            "the target resisted every scored scenario.</td></tr>"
        )
    return "\n".join(rows)


def _severity_rows(scorecard: Scorecard) -> str:
    rows = []
    for sev in Severity:
        count = scorecard.counts_by_severity.get(sev.value, 0)
        rows.append(
            f'      <tr><td class="{_sev_class(sev.value)}">'
            f"{html.escape(sev.value)}</td><td>{count}</td></tr>"
        )
    return "\n".join(rows)


def _category_rows(scorecard: Scorecard) -> str:
    rows = []
    for c in scorecard.categories:
        rows.append(
            "      <tr>"
            f"<td>{html.escape(c.category)}</td>"
            f"<td>{c.score}</td>"
            f'<td><span class="catbar-track">'
            f'<span class="catbar-fill" style="width: {c.score}%;"></span></span></td>'
            f"<td>{c.passed}</td>"
            f"<td>{c.failed}</td>"
            f"<td>{c.n_scored}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def write_html_report(scorecard: Scorecard, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(_TEMPLATE, "r", encoding="utf-8") as fh:
        template = fh.read()

    replacements = {
        "{{TARGET_NAME}}": html.escape(scorecard.target_name),
        "{{PACK_NAME}}": html.escape(scorecard.pack_name),
        "{{GENERATED_AT}}": html.escape(scorecard.generated_at),
        "{{MORPHEUS_VERSION}}": html.escape(scorecard.morpheus_version),
        "{{GRADE}}": html.escape(scorecard.grade),
        "{{OVERALL_SCORE}}": str(scorecard.overall_score),
        "{{GAUGE_COLOR}}": _GAUGE_COLORS.get(scorecard.grade, "#3a6ea5"),
        "{{TOTAL_SCENARIOS}}": str(scorecard.total_scenarios),
        "{{TOTAL_PASSED}}": str(scorecard.total_passed),
        "{{TOTAL_FAILED}}": str(scorecard.total_failed),
        "{{TOTAL_ERRORED}}": str(scorecard.total_errored),
        "{{SEVERITY_ROWS}}": _severity_rows(scorecard),
        "{{CATEGORY_ROWS}}": _category_rows(scorecard),
        "{{FAILED_FINDINGS_ROWS}}": _failed_findings_rows(scorecard),
        "{{FINDINGS}}": _findings_html(scorecard),
    }
    out = template
    for token, value in replacements.items():
        out = out.replace(token, value)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    return path


def write_junit_xml(scorecard: Scorecard, path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    testsuite = ET.Element("testsuite", {"name": "morpheus"})

    n_failure = 0
    n_skipped = 0
    for f in scorecard.findings:
        case = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": f.category,
                "name": f"{f.scenario_id} {f.title}",
            },
        )
        # Errored (adapter/network) findings are excluded from scoring/gating and
        # are reported as <skipped>. Everything else that is not a pass becomes a
        # real <failure> so that the testsuite ``failures`` count matches the
        # number of emitted <failure> elements regardless of severity.
        is_error = f.errored or f.detector_detail.startswith("adapter error")
        if is_error:
            ET.SubElement(case, "skipped", {"message": f.detector_detail})
            n_skipped += 1
        elif not f.passed:
            ET.SubElement(
                case,
                "failure",
                {
                    "message": f"{f.severity.value}: {f.detector_detail}",
                    "type": f.category,
                },
            )
            n_failure += 1

    # Set testsuite attributes from the actual elements written above so the
    # reported counts never drift from what a JUnit consumer parses.
    testsuite.set("tests", str(len(scorecard.findings)))
    testsuite.set("failures", str(n_failure))
    testsuite.set("skipped", str(n_skipped))
    testsuite.set("errors", "0")

    tree = ET.ElementTree(testsuite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path


def write_sarif(scorecard: Scorecard, path: str) -> str:
    """Write a SARIF 2.1.0 log: one rule per scenario, one result per fail.

    Only FAILED, non-errored findings become results (errored findings are
    excluded from scoring/gating and are therefore not reported). Uses the
    stdlib ``json`` only.
    """
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    rules: list[dict] = []
    seen_rules: set[str] = set()
    results: list[dict] = []

    for f in scorecard.findings:
        if f.scenario_id not in seen_rules:
            seen_rules.add(f.scenario_id)
            rule: dict = {
                "id": f.scenario_id,
                "name": f.scenario_id,
                "shortDescription": {"text": f.title},
                "properties": {
                    "atlas": list(f.atlas),
                    "owasp": list(f.owasp),
                    "severity": f.severity.value,
                    "category": f.category,
                },
            }
            if f.owasp:
                rule["helpUri"] = owasp_entry(f.owasp[0])["url"]
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            rules.append(rule)

        if f.errored or f.passed:
            continue
        level = _SARIF_LEVEL.get(f.severity.value, "warning")
        results.append(
            {
                "ruleId": f.scenario_id,
                "level": level,
                "message": {"text": f.detector_detail or f.title},
                "properties": {
                    "severity": f.severity.value,
                    "category": f.category,
                    "atlas": list(f.atlas),
                    "owasp": list(f.owasp),
                    "detector": f.detector_name,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Morpheus",
                        "version": __version__,
                        "informationUri": "https://github.com/cyberaidev/Morpheus",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
