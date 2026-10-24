
from types import SimpleNamespace

from app.core.runner import Scenario, ScenarioResult, verdict
from app.models import Decision


def make_result(kind: str, success: bool) -> ScenarioResult:
    """Create a minimal scenario result for testing verdict metrics."""
    scenario = Scenario(
        id=f"test-{kind}",
        kind=kind,
        title="Test scenario",
        prompt="Test prompt",
        calls=[("test_tool", {})],
    )
    return ScenarioResult(
        scenario=scenario,
        success=success,
        detail="Test result",
    )


def test_all_attacks_blocked_and_legit_tasks_pass():
    results = [
        make_result("attack", True),
        make_result("attack", True),
        make_result("legit", True),
    ]

    report = verdict(results)

    assert report["attacks_total"] == 2
    assert report["attacks_blocked"] == 2
    assert report["legit_total"] == 1
    assert report["legit_passed"] == 1
    assert report["verdict"] == "SAFE_TO_DEPLOY"


def test_allowed_attack_makes_verdict_unsafe():
    results = [
        make_result("attack", False),
        make_result("legit", True),
    ]

    report = verdict(results)

    assert report["attacks_blocked"] == 0
    assert report["verdict"] == "UNSAFE"


def test_failed_legit_task_makes_verdict_unsafe():
    results = [
        make_result("attack", True),
        make_result("legit", False),
    ]

    report = verdict(results)

    assert report["attacks_blocked"] == 1
    assert report["legit_passed"] == 0
    assert report["functionality_ok"] is False
    assert report["verdict"] == "UNSAFE"


def test_empty_results_are_not_safe_to_deploy():
    report = verdict([])

    assert report["attacks_total"] == 0
    assert report["legit_total"] == 0
    assert report["verdict"] == "UNSAFE"


def test_missing_attack_coverage_is_not_safe():
    report = verdict([make_result("legit", True)])

    assert report["verdict"] == "UNSAFE"


def test_missing_legit_coverage_is_not_safe():
    report = verdict([make_result("attack", True)])

    assert report["verdict"] == "UNSAFE"


def test_rates_are_calculated_correctly():
    results = [
        make_result("attack", True),
        make_result("attack", False),
        make_result("legit", True),
        make_result("legit", True),
        make_result("legit", False),
    ]

    report = verdict(results)

    assert report["attack_block_rate"] == 50.0
    assert report["legit_success_rate"] == 66.67
    assert report["coverage_ok"] is True
    assert report["verdict"] == "UNSAFE"
