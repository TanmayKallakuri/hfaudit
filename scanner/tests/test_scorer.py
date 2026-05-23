from __future__ import annotations



from hfaudit.reporting.finding import Finding
from hfaudit.triage.account_signals import AccountSignals
from hfaudit.triage.scorer import ScoredResult, score_findings
from hfaudit.triage.typosquatting import TyposquatResult


def _make_finding(severity: str = "medium", **overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": "HFA-2026-0001",
        "model_id": "user/test-model",
        "severity": severity,
        "rule_id": "HFA-PKL-001",
        "category": "pickle.reduce.dangerous_callable",
        "description": "test finding",
        "evidence": "test evidence",
        "file_path": "model.pkl",
        "confidence": 0.9,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _make_typosquat(*, suspicious: bool, score: float = 0.8) -> TyposquatResult:
    return TyposquatResult(
        is_suspicious=suspicious,
        closest_match="meta-llama/Llama-3.1-8B-Instruct" if suspicious else None,
        edit_distance=1 if suspicious else 10,
        similarity_score=score,
        reason="test typosquat" if suspicious else "no match",
    )


def _make_account(*, new: bool, few: bool) -> AccountSignals:
    return AccountSignals(
        account_age_days=5 if new else 365,
        upload_count=1 if few else 50,
        is_new_account=new,
        has_few_uploads=few,
        reputation_score=0.2 if new else 0.8,
        flags=["New account"] if new else [],
    )


class TestSeverityNeverDowngraded:
    def test_critical_stays_critical_with_no_signals(self) -> None:
        findings = [_make_finding(severity="critical")]
        results = score_findings(findings)
        assert results[0].adjusted_severity == "critical"

    def test_critical_stays_critical_with_clean_signals(self) -> None:
        findings = [_make_finding(severity="critical")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=False),
            account=_make_account(new=False, few=False),
        )
        assert results[0].adjusted_severity == "critical"

    def test_high_never_becomes_medium(self) -> None:
        findings = [_make_finding(severity="high")]
        results = score_findings(findings)
        assert results[0].adjusted_severity == "high"


class TestSeverityUpgrade:
    def test_medium_upgraded_to_high_with_strong_signals(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True, score=0.9),
            account=_make_account(new=True, few=True),
        )
        assert results[0].adjusted_severity == "high"
        assert results[0].composite_score > 0.5

    def test_low_upgraded_with_typosquat(self) -> None:
        findings = [_make_finding(severity="low")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True, score=0.9),
            account=_make_account(new=True, few=True),
        )
        assert results[0].adjusted_severity in ("medium", "high")
        assert results[0].composite_score > results[0].finding.confidence * 0  # sanity

    def test_no_upgrade_without_signals(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(findings)
        assert results[0].adjusted_severity == "medium"


class TestAdjustmentReasons:
    def test_reasons_populated_on_upgrade(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True),
            account=_make_account(new=True, few=True),
        )
        assert len(results[0].adjustment_reasons) > 0

    def test_reasons_empty_with_no_signals(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(findings)
        assert results[0].adjustment_reasons == []

    def test_typosquat_reason_present(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True),
        )
        assert any("Typosquat" in r for r in results[0].adjustment_reasons)

    def test_account_reason_present(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(
            findings,
            account=_make_account(new=True, few=True),
        )
        assert any("account" in r.lower() or "upload" in r.lower()
                    for r in results[0].adjustment_reasons)


class TestCompositeScore:
    def test_critical_base_score(self) -> None:
        findings = [_make_finding(severity="critical")]
        results = score_findings(findings)
        assert results[0].composite_score == 1.0

    def test_info_base_score(self) -> None:
        findings = [_make_finding(severity="informational")]
        results = score_findings(findings)
        assert results[0].composite_score == 0.0

    def test_score_capped_at_one(self) -> None:
        findings = [_make_finding(severity="critical")]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True, score=1.0),
            account=_make_account(new=True, few=True),
        )
        assert results[0].composite_score <= 1.0

    def test_score_increases_with_signals(self) -> None:
        findings = [_make_finding(severity="medium")]
        without = score_findings(findings)
        with_signals = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True),
            account=_make_account(new=True, few=True),
        )
        assert with_signals[0].composite_score > without[0].composite_score


class TestMultipleFindings:
    def test_all_findings_scored(self) -> None:
        findings = [
            _make_finding(severity="critical"),
            _make_finding(severity="medium", rule_id="HFA-PKL-002"),
            _make_finding(severity="low", rule_id="HFA-PKL-003"),
        ]
        results = score_findings(findings)
        assert len(results) == 3

    def test_empty_findings(self) -> None:
        results = score_findings([])
        assert results == []

    def test_each_finding_preserves_original(self) -> None:
        findings = [_make_finding(severity="medium")]
        results = score_findings(findings)
        assert results[0].base_severity == "medium"
        assert results[0].finding is findings[0]


class TestResultTypes:
    def test_result_structure(self) -> None:
        findings = [_make_finding()]
        results = score_findings(
            findings,
            typosquat=_make_typosquat(suspicious=True),
            account=_make_account(new=True, few=True),
        )
        r = results[0]
        assert isinstance(r, ScoredResult)
        assert isinstance(r.composite_score, float)
        assert isinstance(r.adjustment_reasons, list)
        assert r.typosquat_signal is not None
        assert r.account_signal is not None
