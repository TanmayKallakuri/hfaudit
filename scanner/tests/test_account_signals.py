from __future__ import annotations

from hfaudit.triage.account_signals import AccountSignals, analyze_account


class TestAnalyzeAccount:
    def test_new_account_flagged(self) -> None:
        result = analyze_account("newuser/model", account_age_days=5, upload_count=1)
        assert result.is_new_account
        assert result.has_few_uploads
        assert any("New account" in f for f in result.flags)
        assert result.reputation_score < 0.5

    def test_old_account_not_flagged(self) -> None:
        result = analyze_account("veteran/model", account_age_days=365, upload_count=50)
        assert not result.is_new_account
        assert not result.has_few_uploads
        assert result.reputation_score > 0.5

    def test_none_age_flagged(self) -> None:
        result = analyze_account("unknown/model", account_age_days=None, upload_count=10)
        assert not result.is_new_account
        assert any("unknown" in f.lower() for f in result.flags)

    def test_none_uploads_flagged(self) -> None:
        result = analyze_account("org/model", account_age_days=100, upload_count=None)
        assert not result.has_few_uploads
        assert any("Upload count unknown" in f for f in result.flags)

    def test_both_none(self) -> None:
        result = analyze_account("x/y", account_age_days=None, upload_count=None)
        assert result.reputation_score < 0.5
        assert len(result.flags) >= 2

    def test_boundary_age_29(self) -> None:
        result = analyze_account("u/m", account_age_days=29, upload_count=10)
        assert result.is_new_account

    def test_boundary_age_30(self) -> None:
        result = analyze_account("u/m", account_age_days=30, upload_count=10)
        assert not result.is_new_account

    def test_boundary_uploads_2(self) -> None:
        result = analyze_account("u/m", account_age_days=100, upload_count=2)
        assert result.has_few_uploads

    def test_boundary_uploads_3(self) -> None:
        result = analyze_account("u/m", account_age_days=100, upload_count=3)
        assert not result.has_few_uploads

    def test_no_org_flagged(self) -> None:
        result = analyze_account("standalone-model", account_age_days=100, upload_count=10)
        assert any("No organization" in f for f in result.flags)

    def test_score_clamped_to_bounds(self) -> None:
        result = analyze_account("u/m", account_age_days=0, upload_count=0)
        assert 0.0 <= result.reputation_score <= 1.0

    def test_very_old_account_score_capped(self) -> None:
        result = analyze_account("u/m", account_age_days=3650, upload_count=500)
        assert result.reputation_score <= 1.0

    def test_result_types(self) -> None:
        result = analyze_account("org/model", account_age_days=50, upload_count=5)
        assert isinstance(result, AccountSignals)
        assert isinstance(result.flags, list)
        assert isinstance(result.reputation_score, float)
