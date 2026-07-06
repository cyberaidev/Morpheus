import json

import pytest

from morpheus.cli import main


def test_version(capsys):
    rc = main(["version"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "morpheus 0.1.0" in out
    assert "python" in out


def test_list(capsys):
    rc = main(["list", "--pack", "core"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scenarios=14" in out
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
    assert data["total_scenarios"] == 2
    assert all(f["category"] == "tool_abuse" for f in data["findings"])
