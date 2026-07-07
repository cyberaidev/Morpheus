import json

import pytest

from morpheus.cli import main


def test_version(capsys):
    rc = main(["version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "morpheus 0.2.0" in out
    assert "python" in out


def test_version_flag(capsys):
    # `--version` (argparse action=version) exits 0 via SystemExit.
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "morpheus 0.2.0" in out


def test_list(capsys):
    rc = main(["list", "--pack", "core"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scenarios=18" in out
    assert "prompt_injection" in out


def test_run_vulnerable_trips_gate(tmp_path, capsys):
    out_dir = tmp_path / "reports"
    rc = main(["run", "--target", "mock", "--out", str(out_dir), "--fail-on", "high"])
    assert rc == 1  # gate tripped
    assert (out_dir / "scorecard.json").exists()
    assert (out_dir / "report.html").exists()
    assert (out_dir / "junit.xml").exists()


def test_run_safe_passes_gate(tmp_path):
    out_dir = tmp_path / "reports"
    cfg = tmp_path / "safe.yaml"
    cfg.write_text("mock:\n  mode: safe\n")
    rc = main(
        [
            "run",
            "--target",
            "mock",
            "--config",
            str(cfg),
            "--out",
            str(out_dir),
            "--fail-on",
            "high",
        ]
    )
    assert rc == 0


def test_run_fail_on_none_never_gates(tmp_path):
    out_dir = tmp_path / "reports"
    rc = main(["run", "--target", "mock", "--out", str(out_dir), "--fail-on", "none"])
    assert rc == 0


def test_run_json_format(tmp_path, capsys):
    out_dir = tmp_path / "reports"
    main(
        [
            "run",
            "--target",
            "mock",
            "--out",
            str(out_dir),
            "--fail-on",
            "none",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["overall_score"] == 0
    assert data["grade"] == "F"


def test_report_regenerates(tmp_path):
    # First produce a scorecard.
    out_dir = tmp_path / "reports"
    main(["run", "--target", "mock", "--out", str(out_dir), "--fail-on", "none"])
    sc = out_dir / "scorecard.json"
    regen = tmp_path / "regen"
    rc = main(["report", "--scorecard", str(sc), "--out", str(regen)])
    assert rc == 0
    assert (regen / "report.html").exists()
    assert (regen / "junit.xml").exists()


def test_unknown_target_usage_error(tmp_path, capsys):
    # argparse rejects an invalid choice with SystemExit(2).
    with pytest.raises(SystemExit):
        main(["run", "--target", "nope", "--out", str(tmp_path)])


def test_report_missing_scorecard(tmp_path):
    rc = main(["report", "--scorecard", str(tmp_path / "nope.json"), "--out", str(tmp_path)])
    assert rc == 2


def test_list_format_json(capsys):
    rc = main(["list", "--pack", "core", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert isinstance(data, list)
    assert len(data) == 18
    first = data[0]
    for key in ("id", "category", "title", "severity", "atlas", "owasp", "detector"):
        assert key in first


def test_run_sarif_written_and_matches_failed(tmp_path):
    out_dir = tmp_path / "reports"
    sarif = tmp_path / "out.sarif"
    rc = main(
        [
            "run",
            "--target",
            "mock",
            "--out",
            str(out_dir),
            "--fail-on",
            "none",
            "--sarif",
            str(sarif),
        ]
    )
    assert rc == 0
    assert sarif.exists()
    data = json.loads(sarif.read_text())
    assert data["runs"][0]["tool"]["driver"]["name"] == "Morpheus"
    sc = json.loads((out_dir / "scorecard.json").read_text())
    failed_non_errored = sum(
        1 for f in sc["findings"] if not f["passed"] and not f["errored"]
    )
    assert len(data["runs"][0]["results"]) == failed_non_errored


def test_dry_run_offline_no_network(tmp_path, capsys):
    # A base_url that would fail if contacted; --dry-run must not touch it.
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        "http:\n"
        '  base_url: "http://127.0.0.1:9/none"\n'
        "  headers:\n"
        '    Authorization: "Bearer ${DRYRUN_TOKEN}"\n'
        "  request_template:\n"
        '    input: "${prompt}"\n'
        "  response_mapping:\n"
        '    text: "output.text"\n'
    )
    import os

    os.environ["DRYRUN_TOKEN"] = "supersecret-should-be-redacted"
    try:
        rc = main(
            ["run", "--target", "http", "--config", str(cfg), "--dry-run"]
        )
    finally:
        os.environ.pop("DRYRUN_TOKEN", None)
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "Request body" in out
    assert "supersecret-should-be-redacted" not in out  # redacted
    assert "<redacted>" in out


def test_dry_run_mock_prints_note(tmp_path, capsys):
    rc = main(["run", "--target", "mock", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "mock" in out


def test_log_responses_writes_redacted_files(tmp_path):
    out_dir = tmp_path / "reports"
    rc = main(
        [
            "run",
            "--target",
            "mock",
            "--out",
            str(out_dir),
            "--fail-on",
            "none",
            "--log-responses",
        ]
    )
    assert rc == 0
    responses = out_dir / "responses"
    assert responses.is_dir()
    files = list(responses.glob("*.json"))
    assert files
    doc = json.loads(files[0].read_text())
    assert "scenario_id" in doc
    assert "response_excerpt" in doc


def test_suite_filter_run(tmp_path):
    out_dir = tmp_path / "reports"
    rc = main(
        [
            "run",
            "--target",
            "mock",
            "--suite",
            "tool_abuse",
            "--out",
            str(out_dir),
            "--fail-on",
            "none",
        ]
    )
    assert rc == 0
    data = json.loads((out_dir / "scorecard.json").read_text())
    assert data["total_scenarios"] == 3
    assert all(f["category"] == "tool_abuse" for f in data["findings"])
