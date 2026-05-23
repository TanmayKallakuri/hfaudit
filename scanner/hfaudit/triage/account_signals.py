from __future__ import annotations

from dataclasses import dataclass, field

_NEW_ACCOUNT_THRESHOLD_DAYS = 30
_FEW_UPLOADS_THRESHOLD = 3


@dataclass
class AccountSignals:
    account_age_days: int | None
    upload_count: int | None
    is_new_account: bool
    has_few_uploads: bool
    reputation_score: float
    flags: list[str] = field(default_factory=list)


def analyze_account(
    model_id: str,
    account_age_days: int | None = None,
    upload_count: int | None = None,
) -> AccountSignals:
    """Analyze HuggingFace account metadata for reputation signals."""
    flags: list[str] = []
    score = 0.5

    org: str | None = None
    if "/" in model_id:
        org = model_id.split("/", 1)[0]

    is_new = False
    if account_age_days is None:
        flags.append("Account age unknown - cannot verify reputation")
        score -= 0.15
    elif account_age_days < _NEW_ACCOUNT_THRESHOLD_DAYS:
        is_new = True
        flags.append(f"New account ({account_age_days} days old)")
        score -= 0.25
    else:
        score += min(account_age_days / 365.0, 0.3)

    few_uploads = False
    if upload_count is None:
        flags.append("Upload count unknown - cannot assess activity")
        score -= 0.1
    elif upload_count < _FEW_UPLOADS_THRESHOLD:
        few_uploads = True
        flags.append(f"Very few uploads ({upload_count})")
        score -= 0.2
    else:
        score += min(upload_count / 100.0, 0.2)

    if is_new and few_uploads:
        flags.append("New account with minimal upload history - elevated risk")
        score -= 0.1

    if org is None:
        flags.append("No organization - individual upload")
        score -= 0.05

    score = round(max(0.0, min(1.0, score)), 4)

    return AccountSignals(
        account_age_days=account_age_days,
        upload_count=upload_count,
        is_new_account=is_new,
        has_few_uploads=few_uploads,
        reputation_score=score,
        flags=flags,
    )
