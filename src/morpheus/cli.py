"""Morpheus command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from typing import Optional

from . import __version__
from .adapters import get_adapter
from .adapters.base import AdapterError
from .adapters.http_generic import _expand, _redact, _resolve_env
from .config import apply_dotenv
from .config import load as load_config
from .models import Severity
from .reporter import (
    write_html_report,
    write_junit_xml,
    write_sarif,
    write_scorecard_json,
)
from .runner import Runner
from .scenario import AttackScenario
from .scorer import Scorecard, score_run
from .suites import DEFAULT_PACK, load_scenarios

EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
EXIT_INTERNAL = 3

_FAIL_ON_CHOICES = ["critical", "high", "medium", "low", "none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="Run attack scenarios against cloud-deployed AI agents.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"morpheus {__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run scenarios against a target")
    run_p.add_argument(
        "--target",
        default="mock",
        choices=["http", "mock", "bedrock", "azure", "openai", "vertex"],
    )
    run_p.add_argument("--config", default=None)
    run_p.add_argument("--suite", action="append", default=None)
    run_p.add_argument("--pack", default=DEFAULT_PACK)
    run_p.add_argument("--out", default="reports/")
    run_p.add_argument("--fail-on", default="high", choices=_FAIL_ON_CHOICES)
    run_p.add_argument("--format", default="text", choices=["text", "json"])
    run_p.add_argument("--sarif", default=None, help="also write a SARIF 2.1.0 log")
    run_p.add_argument(
        "--dry-run",
        action="store_true",
        help="print the expanded request for the first scenario and exit (no network)",
    )
    run_p.add_argument(
        "--log-responses",
        action="store_true",
        help="write each raw response (redacted) to <out>/responses/<id>.json",
    )

    list_p = sub.add_parser("list", help="list scenarios (no network)")
    list_p.add_argument("--pack", default=DEFAULT_PACK)
    list_p.add_argument("--suite", action="append", default=None)
    list_p.add_argument("--format", default="text", choices=["text", "json"])

    report_p = sub.add_parser("report", help="regenerate reports from a scorecard JSON")
    report_p.add_argument("--scorecard", required=True)
    report_p.add_argument("--out", default="reports/")

    sub.add_parser("version", help="print version")

    return parser


def _resolve_default_config(explicit: Optional[str]) -> Optional[str]:
    if explicit:
        return explicit
    if os.path.exists("morpheus.yaml"):
        return "morpheus.yaml"
    return None


def _gate_tripped(scorecard: Scorecard, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = Severity.from_str(fail_on).rank
    total = 0
    for sev_name, count in scorecard.counts_by_severity.items():
        if Severity.from_str(sev_name).rank >= threshold:
            total += count
    return total > 0


def _build_adapter_config(cfg, target: str) -> dict:
    adapter_cfg = cfg.adapter_config(target)
    # A top-level "http" block also applies for the http adapter.
    if target == "http" and "http" not in adapter_cfg and cfg.get("http"):
        adapter_cfg = dict(adapter_cfg)
        adapter_cfg["http"] = cfg.get("http")
    return adapter_cfg


def _log_responses_enabled(args: argparse.Namespace) -> bool:
    if getattr(args, "log_responses", False):
        return True
    return os.environ.get("MORPHEUS_LOG_RESPONSES", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _cmd_run(args: argparse.Namespace) -> int:
    config_path = _resolve_default_config(args.config)
    try:
        cfg = load_config(config_path)
    except (ValueError, OSError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # Apply parsed .env into the process env (os.environ wins) so that
    # ${ENV_VAR} placeholders resolve values that live only in .env.
    apply_dotenv(cfg)

    adapter_cfg = _build_adapter_config(cfg, args.target)

    try:
        scenarios = load_scenarios(args.pack, args.suite)
    except (FileNotFoundError, ValueError) as exc:
        print(f"scenario error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if not scenarios:
        print("no scenarios matched the requested pack/suite", file=sys.stderr)
        return EXIT_USAGE

    if args.dry_run:
        return _dry_run(args.target, adapter_cfg, scenarios)

    try:
        adapter = get_adapter(args.target, adapter_cfg)
    except AdapterError as exc:
        print(f"adapter error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    on_scenario = None
    if args.format != "json":
        def on_scenario(index: int, total: int, scenario: AttackScenario) -> None:
            print(f"[{index}/{total}] {scenario.id}", file=sys.stderr)

    run_result = Runner(adapter).run(
        scenarios, pack_name=args.pack, on_scenario=on_scenario
    )
    adapter.close()

    scorecard = score_run(
        run_result.findings,
        target_name=run_result.target_name,
        pack_name=run_result.pack_name,
        generated_at=run_result.finished_at,
    )

    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "scorecard.json")
    html_path = os.path.join(out_dir, "report.html")
    junit_path = os.path.join(out_dir, "junit.xml")
    write_scorecard_json(scorecard, json_path)
    write_html_report(scorecard, html_path)
    write_junit_xml(scorecard, junit_path)
    if args.sarif:
        write_sarif(scorecard, args.sarif)

    if _log_responses_enabled(args):
        _write_response_logs(out_dir, scorecard)

    if args.format == "json":
        print(json.dumps(scorecard.as_dict(), indent=2, sort_keys=True))
    else:
        _print_text_summary(scorecard, out_dir)

    return EXIT_GATE if _gate_tripped(scorecard, args.fail_on) else EXIT_OK


def _dry_run(target: str, adapter_cfg: dict, scenarios: list[AttackScenario]) -> int:
    """Print the expanded request + redacted headers for the first scenario."""
    scenario = sorted(scenarios, key=lambda s: (s.category, s.id))[0]
    request = Runner().build_request(scenario)
    print(f"DRY RUN - target={target} scenario={scenario.id}")
    if target == "http":
        http = adapter_cfg.get("http") or {}
        template = http.get("request_template", {"prompt": "${prompt}"})
        ctx = {
            "prompt": request.prompt,
            "system": request.system or "",
            "conversation_id": request.conversation_id or "",
            "context_documents": list(request.context_documents or []),
        }
        body = _expand(template, ctx)
        headers = {"Content-Type": "application/json"}
        for key, value in (http.get("headers") or {}).items():
            headers[key] = _redact(_resolve_env(str(value)))
        print("Request body:")
        print(json.dumps(body, indent=2, sort_keys=True))
        print("Resolved headers (redacted):")
        print(json.dumps(headers, indent=2, sort_keys=True))
    else:
        print(
            f"(note: --dry-run request expansion is only meaningful for the http "
            f"target; the {target!r} adapter builds its request internally.)"
        )
        print("Prompt:")
        print(request.prompt)
        if request.system:
            print("System:")
            print(request.system)
    return EXIT_OK


def _write_response_logs(out_dir: str, scorecard: Scorecard) -> None:
    """Write each finding's response excerpt, redacted, to <out>/responses/."""
    responses_dir = os.path.join(out_dir, "responses")
    os.makedirs(responses_dir, exist_ok=True)
    for f in scorecard.findings:
        record = {
            "scenario_id": f.scenario_id,
            "category": f.category,
            "passed": f.passed,
            "errored": f.errored,
            "detector_detail": _redact(f.detector_detail or ""),
            "request_prompt": _redact(f.request_prompt or ""),
            "response_excerpt": _redact(f.response_excerpt or ""),
        }
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in f.scenario_id)
        path = os.path.join(responses_dir, f"{safe_id}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")


def _print_text_summary(scorecard: Scorecard, out_dir: str) -> None:
    print(f"Morpheus {scorecard.morpheus_version} - target={scorecard.target_name} "
          f"pack={scorecard.pack_name}")
    print(f"Overall: {scorecard.overall_score}/100  Grade {scorecard.grade}")
    print(
        f"Scenarios: {scorecard.total_scenarios}  "
        f"passed(secure)={scorecard.total_passed}  "
        f"failed(vulnerable)={scorecard.total_failed}  "
        f"errored={scorecard.total_errored}"
    )
    print("Failed by severity: " + ", ".join(
        f"{s}={scorecard.counts_by_severity.get(s, 0)}"
        for s in ["critical", "high", "medium", "low", "info"]
    ))
    print("Categories:")
    for c in scorecard.categories:
        print(f"  - {c.category}: {c.score}/100 "
              f"(passed={c.passed} failed={c.failed} scored={c.n_scored})")
    print(f"Reports written to: {out_dir}")


def _scenario_metadata(scenario: AttackScenario) -> dict:
    return {
        "id": scenario.id,
        "category": scenario.category,
        "title": scenario.title,
        "severity": scenario.severity.value,
        "atlas": list(scenario.atlas),
        "owasp": list(scenario.owasp),
        "detector": scenario.detector.type,
        "description": scenario.description,
        "remediation": scenario.remediation,
    }


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        scenarios = load_scenarios(args.pack, args.suite)
    except (FileNotFoundError, ValueError) as exc:
        print(f"scenario error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    ordered = sorted(scenarios, key=lambda s: (s.category, s.id))
    if getattr(args, "format", "text") == "json":
        print(json.dumps([_scenario_metadata(s) for s in ordered], indent=2, sort_keys=True))
        return EXIT_OK
    print(f"pack={args.pack}  scenarios={len(ordered)}")
    for s in ordered:
        atlas = ",".join(s.atlas) or "-"
        owasp = ",".join(s.owasp) or "-"
        print(f"  [{s.severity.value:<8}] {s.id:<28} {s.category:<20} "
              f"{s.title}  (ATLAS {atlas}; OWASP {owasp})")
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    if not os.path.exists(args.scorecard):
        print(f"scorecard not found: {args.scorecard}", file=sys.stderr)
        return EXIT_USAGE
    try:
        with open(args.scorecard, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        scorecard = Scorecard.from_dict(data)
    except (ValueError, KeyError) as exc:
        print(f"invalid scorecard: {exc}", file=sys.stderr)
        return EXIT_USAGE
    os.makedirs(args.out, exist_ok=True)
    html_path = os.path.join(args.out, "report.html")
    junit_path = os.path.join(args.out, "junit.xml")
    write_html_report(scorecard, html_path)
    write_junit_xml(scorecard, junit_path)
    print(f"regenerated: {html_path}, {junit_path}")
    return EXIT_OK


def _cmd_version() -> int:
    print(f"morpheus {__version__}")
    print(f"python {platform.python_version()}")
    return EXIT_OK


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return _cmd_run(args)
        if args.command == "list":
            return _cmd_list(args)
        if args.command == "report":
            return _cmd_report(args)
        if args.command == "version":
            return _cmd_version()
        parser.error("unknown command")
        return EXIT_USAGE
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - top-level guard
        print(f"internal error: {exc}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
