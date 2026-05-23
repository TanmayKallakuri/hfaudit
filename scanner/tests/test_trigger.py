from __future__ import annotations

from datetime import datetime, timezone

from hfaudit.reporting.finding import Finding
from hfaudit.sandbox.trigger import TriggerDecision, should_trigger_stage3
from hfaudit.triage.account_signals import AccountSignals
from hfaudit.triage.scorer import ScoredResult
from hfaudit.triage.typosquatting import TyposquatResult


def _make_finding(severity: str = "medium", rule_id: str = "HFA-PKL-001") -> Finding:
    return Finding(
        id="HFA-2026-0001",
        model_id="evil-user/malicious-model",
        severity=severity,
        rule_id=rule_id,
        category="pickle.reduce.os_system",
        description="Test finding",
        evidence="os.system('whoami')",
        file_path="model.pt",
        confidence=0.95,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def _make_scored(
    severity: str = "medium",
    typosquat: TyposquatResult | None = None,
    account: AccountSignals | None = None,
) -> ScoredResult:
    finding = _make_finding(severity=severity)
    return ScoredResult(
        finding=finding,
        base_severity=severity,
        adjusted_severity=severity,
        typosquat_signal=typosquat,
        account_signal=account,
        composite_score=0.5,
    )


def _suspicious_typosquat() -> TyposquatResult:
    return TyposquatResult(
        is_suspicious=True,
        closest_match="meta-llama/Llama-3-8B-Instruct",
        edit_distance=1,
        similarity_score=0.9,
        reason="Homoglyph substitution",
    )


def _clean_typosquat() -> TyposquatResult:
    return TyposquatResult(
        is_suspicious=False,
        closest_match=None,
        edit_distance=None,
        similarity_score=0.0,
        reason="No match",
    )


def _new_account() -> AccountSignals:
    return AccountSignals(
        account_age_days=5,
        upload_count=1,
        is_new_account=True,
        has_few_uploads=True,
        reputation_score=0.1,
    )


def _established_account() -> AccountSignals:
    return AccountSignals(
        account_age_days=365,
        upload_count=50,
        is_new_account=False,
        has_few_uploads=False,
        reputation_score=0.8,
    )


class TestTriggerStage3:
    def test_critical_triggers_immediately(self) -> None:
        results = [_make_scored("critical")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is True
        assert decision.priority == 1
        assert "critical" in decision.reason.lower()

    def test_two_high_findings_trigger(self) -> None:
        results = [_make_scored("high"), _make_scored("high")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is True
        assert decision.priority == 2

    def test_high_plus_typosquatting_triggers(self) -> None:
        results = [_make_scored("high", typosquat=_suspicious_typosquat())]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is True
        assert decision.priority == 2
        assert "typosquat" in decision.reason.lower()

    def test_high_plus_new_account_triggers(self) -> None:
        results = [_make_scored("high", account=_new_account())]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is True
        assert decision.priority == 3
        assert "new account" in decision.reason.lower()

    def test_medium_only_does_not_trigger(self) -> None:
        results = [_make_scored("medium"), _make_scored("medium"), _make_scored("medium")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_single_high_no_signals_does_not_trigger(self) -> None:
        results = [_make_scored("high")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_high_with_clean_typosquat_no_trigger(self) -> None:
        results = [_make_scored("high", typosquat=_clean_typosquat())]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_high_with_established_account_no_trigger(self) -> None:
        results = [_make_scored("high", account=_established_account())]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_force_always_triggers(self) -> None:
        decision = should_trigger_stage3([], force=True)
        assert decision.should_trigger is True
        assert decision.priority == 1

    def test_force_with_empty_results(self) -> None:
        decision = should_trigger_stage3([], force=True)
        assert decision.should_trigger is True

    def test_empty_findings_no_trigger(self) -> None:
        decision = should_trigger_stage3([])
        assert decision.should_trigger is False
        assert decision.priority == 99

    def test_low_findings_no_trigger(self) -> None:
        results = [_make_scored("low")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_informational_findings_no_trigger(self) -> None:
        results = [_make_scored("informational")]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is False

    def test_priority_ordering_critical_over_high(self) -> None:
        crit_decision = should_trigger_stage3([_make_scored("critical")])
        high_decision = should_trigger_stage3([_make_scored("high"), _make_scored("high")])
        assert crit_decision.priority < high_decision.priority

    def test_priority_ordering_high_typosquat_over_high_new_account(self) -> None:
        typo_decision = should_trigger_stage3(
            [_make_scored("high", typosquat=_suspicious_typosquat())]
        )
        acct_decision = should_trigger_stage3(
            [_make_scored("high", account=_new_account())]
        )
        assert typo_decision.priority <= acct_decision.priority

    def test_multiple_critical_still_priority_1(self) -> None:
        results = [_make_scored("critical"), _make_scored("critical")]
        decision = should_trigger_stage3(results)
        assert decision.priority == 1
        assert "2 critical" in decision.reason

    def test_mixed_severities_critical_wins(self) -> None:
        results = [
            _make_scored("critical"),
            _make_scored("high"),
            _make_scored("medium"),
        ]
        decision = should_trigger_stage3(results)
        assert decision.should_trigger is True
        assert decision.priority == 1

    def test_decision_dataclass(self) -> None:
        d = TriggerDecision(should_trigger=True, reason="test", priority=1)
        assert d.should_trigger is True
        assert d.reason == "test"
        assert d.priority == 1
