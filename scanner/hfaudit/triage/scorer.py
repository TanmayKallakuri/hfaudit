from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from hfaudit.reporting.finding import Finding
from hfaudit.triage.account_signals import AccountSignals
from hfaudit.triage.typosquatting import TyposquatResult

Severity = Literal["critical", "high", "medium", "low", "informational"]

_SEVERITY_BASE_SCORES: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "informational": 0.0,
}

_SEVERITY_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]


@dataclass
class ScoredResult:
    finding: Finding
    base_severity: str
    adjusted_severity: str
    typosquat_signal: TyposquatResult | None
    account_signal: AccountSignals | None
    composite_score: float
    adjustment_reasons: list[str] = field(default_factory=list)


def _severity_index(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


def _score_to_severity(score: float) -> Severity:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score >= 0.15:
        return "low"
    return "informational"


def score_findings(
    findings: list[Finding],
    typosquat: TyposquatResult | None = None,
    account: AccountSignals | None = None,
) -> list[ScoredResult]:
    """Combine Stage 1 findings with Stage 2 signals into scored results."""
    results: list[ScoredResult] = []

    for finding in findings:
        base = _SEVERITY_BASE_SCORES.get(finding.severity, 0.0)
        adjustment = 0.0
        reasons: list[str] = []

        if typosquat is not None and typosquat.is_suspicious:
            typo_boost = typosquat.similarity_score * 0.2
            adjustment += typo_boost
            reasons.append(
                f"Typosquatting signal (+{typo_boost:.2f}): {typosquat.reason}"
            )

        if account is not None:
            acct_boost = 0.0
            if account.is_new_account and account.has_few_uploads:
                acct_boost = 0.15
                reasons.append(
                    f"New account with few uploads (+{acct_boost:.2f})"
                )
            elif account.is_new_account:
                acct_boost = 0.10
                reasons.append(
                    f"New account (+{acct_boost:.2f})"
                )
            elif account.has_few_uploads:
                acct_boost = 0.05
                reasons.append(
                    f"Few uploads (+{acct_boost:.2f})"
                )
            adjustment += acct_boost

        composite = round(min(1.0, base + adjustment), 4)
        candidate_severity = _score_to_severity(composite)

        base_idx = _severity_index(finding.severity)
        candidate_idx = _severity_index(candidate_severity)
        if candidate_idx < base_idx:
            adjusted_severity = finding.severity
        else:
            adjusted_severity = candidate_severity

        if adjusted_severity != finding.severity:
            reasons.append(
                f"Severity upgraded: {finding.severity} -> {adjusted_severity}"
            )

        results.append(
            ScoredResult(
                finding=finding,
                base_severity=finding.severity,
                adjusted_severity=adjusted_severity,
                typosquat_signal=typosquat,
                account_signal=account,
                composite_score=composite,
                adjustment_reasons=reasons,
            )
        )

    return results
