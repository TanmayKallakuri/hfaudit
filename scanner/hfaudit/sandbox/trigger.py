from __future__ import annotations

from dataclasses import dataclass

from hfaudit.triage.scorer import ScoredResult


@dataclass
class TriggerDecision:
    should_trigger: bool
    reason: str
    priority: int


def should_trigger_stage3(
    scored_results: list[ScoredResult],
    force: bool = False,
) -> TriggerDecision:
    """Decide whether Stage 3 sandbox analysis should run based on scored findings."""
    if force:
        return TriggerDecision(
            should_trigger=True,
            reason="Forced trigger requested",
            priority=1,
        )

    if not scored_results:
        return TriggerDecision(
            should_trigger=False,
            reason="No findings to evaluate",
            priority=99,
        )

    critical_count = 0
    high_count = 0
    has_typosquat = False
    has_new_account = False

    for sr in scored_results:
        sev = sr.adjusted_severity
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1

        if sr.typosquat_signal is not None and sr.typosquat_signal.is_suspicious:
            has_typosquat = True
        if sr.account_signal is not None and sr.account_signal.is_new_account:
            has_new_account = True

    if critical_count > 0:
        return TriggerDecision(
            should_trigger=True,
            reason=f"{critical_count} critical finding(s) detected",
            priority=1,
        )

    if high_count >= 2:
        return TriggerDecision(
            should_trigger=True,
            reason=f"{high_count} high findings detected",
            priority=2,
        )

    if high_count >= 1 and has_typosquat:
        return TriggerDecision(
            should_trigger=True,
            reason="High finding with typosquatting suspicion",
            priority=2,
        )

    if high_count >= 1 and has_new_account:
        return TriggerDecision(
            should_trigger=True,
            reason="High finding from new account",
            priority=3,
        )

    return TriggerDecision(
        should_trigger=False,
        reason="Insufficient signals to warrant sandbox analysis",
        priority=99,
    )
