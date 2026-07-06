"""Write scorecards as JSON, self-contained HTML, and JUnit XML.

HTML and JUnit generation use only the standard library so ``jinja2`` is not a
runtime dependency.
"""

from __future__ import annotations

import html
import json
import os
import xml.etree.ElementTree as ET

from .mappings import atlas_entry, owasp_entry
from .models import Severity, to_serializable
from .scorer import Scorecard

_TEMPLATE = os.path.join(os.path.dirname(__file__), "templates", "report.html.tmpl")

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


def _findings_html(scorecard: Scorecard) -> str:
    blocks = []
    for f in scorecard.findings:
        if f.errored:
            status = '<span class="sev-info">ERRORED (excluded)</span>'
        elif f.passed:
            status = '<span class="pass">SECURE (passed)</span>'
        else:
            status = '<span class="fail">VULNERABLE (failed)</span>'
        sev = f.severity.value
        summary = (
            f"{html.escape(f.scenario_id)} &mdash; {html.escape(f.title)} "
            f'[<span class="{_sev_class(sev)}">{html.escape(sev)}</span>] {status}'
        )
        block = (
            "<details>\n"
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
    testsuite = ET.Element(
        "testsuite",
        {
            "name": "morpheus",
            "tests": str(scorecard.total_scenarios),
            "failures": str(scorecard.total_failed),
        },
    )
    for f in scorecard.findings:
        case = ET.SubElement(
            testsuite,
            "testcase",
            {
                "classname": f.category,
                "name": f"{f.scenario_id} {f.title}",
            },
        )
        is_error = f.errored or f.detector_detail.startswith("adapter error")
        if is_error or f.severity == Severity.INFO:
            ET.SubElement(
                case,
                "skipped",
                {"message": f.detector_detail},
            )
        elif not f.passed:
            ET.SubElement(
                case,
                "failure",
                {
                    "message": f"{f.severity.value}: {f.detector_detail}",
                    "type": f.category,
                },
            )
    tree = ET.ElementTree(testsuite)
    ET.indent(tree, space="  ")
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return path
