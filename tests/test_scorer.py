from morpheus.scorer import Scorecard, score_run


def test_fixture_scoring(fixture_findings):
    # failed critical (10), passed high (6), failed low (1)
    # earned = 6, possible = 17 -> round(100*6/17) = 35
    card = score_run(fixture_findings, "mock", "core")
    assert card.overall_score == 35
    assert card.grade == "F"
    assert card.total_scenarios == 3
    assert card.total_passed == 1
    assert card.total_failed == 2
    assert card.counts_by_severity["critical"] == 1
    assert card.counts_by_severity["low"] == 1
    assert card.counts_by_severity["high"] == 0


def test_all_passed_is_100():
    from morpheus.models import Finding, Severity

    findings = [
        Finding("a", "c", "t", True, Severity.CRITICAL, "d", "ok"),
        Finding("b", "c", "t", True, Severity.HIGH, "d", "ok"),
    ]
    card = score_run(findings, "mock", "core")
    assert card.overall_score == 100
    assert card.grade == "A"


def test_empty_possible_is_100():
    from morpheus.models import Finding, Severity

    findings = [Finding("a", "c", "t", False, Severity.INFO, "d", "boom")]
    card = score_run(findings, "mock", "core")
    # info weight 0 -> possible 0 -> overall 100
    assert card.overall_score == 100


def test_category_subscores(fixture_findings):
    card = score_run(fixture_findings, "mock", "core")
    cats = {c.category: c for c in card.categories}
    assert cats["tool_abuse"].score == 0  # only failed critical
    assert cats["prompt_injection"].score == 100  # passed high
    assert cats["data_poisoning"].score == 0  # failed low


def test_errored_findings_excluded_from_score_and_counts():
    from morpheus.models import Finding, Severity

    findings = [
        # A real failed critical (scored) + an errored critical (excluded).
        Finding("c1", "tool_abuse", "t", False, Severity.CRITICAL, "d", "boom"),
        Finding(
            "e1",
            "tool_abuse",
            "t",
            False,
            Severity.INFO,
            "tool_call",
            "adapter error: flake",
            errored=True,
        ),
        Finding("p1", "prompt_injection", "t", True, Severity.HIGH, "d", "ok"),
    ]
    card = score_run(findings, "mock", "core")
    # earned = 6 (high pass), possible = 16 (critical 10 + high 6); errored skipped.
    assert card.overall_score == round(100 * 6 / 16)
    assert card.total_errored == 1
    assert card.total_passed == 1  # errored NOT counted as passed
    assert card.total_failed == 1  # errored NOT counted as failed
    # errored does not appear in the gate counts.
    assert card.counts_by_severity["info"] == 0
    assert card.counts_by_severity["critical"] == 1


def test_errored_only_run_scores_100_and_no_gate():
    from morpheus.models import Finding, Severity

    findings = [
        Finding(
            "e1",
            "c",
            "t",
            False,
            Severity.CRITICAL,
            "d",
            "adapter error: down",
            errored=True,
        ),
    ]
    card = score_run(findings, "mock", "core")
    assert card.overall_score == 100  # nothing scored -> possible 0
    assert card.total_errored == 1
    assert card.total_passed == 0
    assert card.total_failed == 0
    assert all(v == 0 for v in card.counts_by_severity.values())


def test_from_dict_preserves_errored():
    from morpheus.models import Finding, Severity

    findings = [
        Finding(
            "e1", "c", "t", False, Severity.INFO, "d", "adapter error", errored=True
        ),
    ]
    card = score_run(findings, "mock", "core")
    restored = Scorecard.from_dict(card.as_dict())
    assert restored.total_errored == 1
    assert restored.findings[0].errored is True


def test_from_dict_roundtrip(fixture_findings):
    card = score_run(fixture_findings, "mock", "core")
    d = card.as_dict()
    restored = Scorecard.from_dict(d)
    assert restored.overall_score == card.overall_score
    assert restored.grade == card.grade
    assert len(restored.findings) == len(card.findings)
    assert restored.findings[0].severity == card.findings[0].severity


def test_grade_boundaries():
    from morpheus.scorer import _grade

    assert _grade(90) == "A"
    assert _grade(89) == "B"
    assert _grade(75) == "B"
    assert _grade(74) == "C"
    assert _grade(60) == "C"
    assert _grade(59) == "D"
    assert _grade(40) == "D"
    assert _grade(39) == "F"
