from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from hfaudit.reporting.finding import Finding
from hfaudit.reporting.persistence import (
    ScanPersistence,
    ScanRecord,
    SupabaseConfig,
    _dt_to_iso,
)


def _make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "id": "HFA-2026-0001",
        "model_id": "user/dangerous-model",
        "severity": "critical",
        "rule_id": "HFA-PKL-001",
        "category": "pickle.reduce.dangerous_callable",
        "description": "os.system called via __reduce__",
        "evidence": "GLOBAL opcode: os.system",
        "file_path": "model.pkl",
        "confidence": 0.95,
        "references": ["https://example.com/advisory"],
        "false_positive_notes": "",
        "bypass_notes": "",
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _mock_client() -> MagicMock:
    client = MagicMock()
    table_mock = MagicMock()
    client.table.return_value = table_mock
    table_mock.upsert.return_value = table_mock
    table_mock.insert.return_value = table_mock
    table_mock.select.return_value = table_mock
    table_mock.eq.return_value = table_mock
    table_mock.execute.return_value = MagicMock(data=[])
    return client


class TestSupabaseConfig:
    def test_from_env_success(self) -> None:
        with patch.dict(
            os.environ,
            {"SUPABASE_URL": "https://x.supabase.co", "SUPABASE_SERVICE_KEY": "svc-key"},
        ):
            cfg = SupabaseConfig.from_env()
            assert cfg.url == "https://x.supabase.co"
            assert cfg.service_key == "svc-key"

    def test_from_env_missing_url(self) -> None:
        with patch.dict(os.environ, {"SUPABASE_SERVICE_KEY": "svc-key"}, clear=True):
            with pytest.raises(EnvironmentError, match="SUPABASE_URL"):
                SupabaseConfig.from_env()

    def test_from_env_missing_key(self) -> None:
        with patch.dict(os.environ, {"SUPABASE_URL": "https://x.supabase.co"}, clear=True):
            with pytest.raises(EnvironmentError, match="SUPABASE_SERVICE_KEY"):
                SupabaseConfig.from_env()

    def test_from_env_both_missing(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(EnvironmentError, match="SUPABASE_URL.*SUPABASE_SERVICE_KEY"):
                SupabaseConfig.from_env()

    def test_from_env_empty_values_treated_as_missing(self) -> None:
        with patch.dict(
            os.environ, {"SUPABASE_URL": "", "SUPABASE_SERVICE_KEY": ""}, clear=True
        ):
            with pytest.raises(EnvironmentError):
                SupabaseConfig.from_env()


class TestSaveFinding:
    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_finding_column_mapping(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        ts = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        finding = _make_finding(timestamp=ts)

        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_finding(finding)

        client.table.assert_called_with("findings")
        upsert_call = client.table.return_value.upsert
        upsert_call.assert_called_once()
        row = upsert_call.call_args[0][0]

        assert row["id"] == "HFA-2026-0001"
        assert row["model_id"] == "user/dangerous-model"
        assert row["severity"] == "critical"
        assert row["rule_id"] == "HFA-PKL-001"
        assert row["category"] == "pickle.reduce.dangerous_callable"
        assert row["description"] == "os.system called via __reduce__"
        assert row["evidence"] == "GLOBAL opcode: os.system"
        assert row["file_path"] == "model.pkl"
        assert row["confidence"] == 0.95
        assert row["false_positive_notes"] == ""
        assert row["bypass_notes"] == ""

    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_finding_references_as_list(self, mock_create: MagicMock) -> None:
        """The references column is JSONB; we pass a Python list directly."""
        client = _mock_client()
        mock_create.return_value = client

        finding = _make_finding(references=["https://cve.org/1", "https://cve.org/2"])
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_finding(finding)

        row = client.table.return_value.upsert.call_args[0][0]
        assert row["references"] == ["https://cve.org/1", "https://cve.org/2"]

    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_finding_upsert_on_conflict_id(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        finding = _make_finding()
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_finding(finding)

        upsert_call = client.table.return_value.upsert
        assert upsert_call.call_args[1]["on_conflict"] == "id"

    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_finding_datetime_iso_format(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        ts = datetime(2026, 3, 15, 8, 30, 0, tzinfo=timezone.utc)
        finding = _make_finding(timestamp=ts)
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_finding(finding)

        row = client.table.return_value.upsert.call_args[0][0]
        assert row["updated_at"] == "2026-03-15T08:30:00+00:00"


class TestSaveScan:
    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_scan_insert_payload(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        scan = ScanRecord(
            model_id="user/test-model",
            scan_type="manual",
            status="completed",
            stage_reached=2,
            findings_count=5,
            duration_ms=1234,
            error_message=None,
        )
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_scan(scan)

        client.table.assert_called_with("scans")
        insert_call = client.table.return_value.insert
        insert_call.assert_called_once()
        row = insert_call.call_args[0][0]

        assert row["model_id"] == "user/test-model"
        assert row["scan_type"] == "manual"
        assert row["status"] == "completed"
        assert row["stage_reached"] == 2
        assert row["findings_count"] == 5
        assert row["duration_ms"] == 1234
        assert "completed_at" in row

    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_scan_pending_omits_optional_fields(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        scan = ScanRecord(
            model_id="user/test-model",
            scan_type="new_upload",
            status="pending",
        )
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_scan(scan)

        row = client.table.return_value.insert.call_args[0][0]
        assert "stage_reached" not in row
        assert "duration_ms" not in row
        assert "error_message" not in row
        assert "completed_at" not in row

    @patch("hfaudit.reporting.persistence.create_client")
    def test_save_scan_failed_includes_error_message(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        scan = ScanRecord(
            model_id="user/broken",
            scan_type="triggered",
            status="failed",
            error_message="Connection timeout",
        )
        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.save_scan(scan)

        row = client.table.return_value.insert.call_args[0][0]
        assert row["error_message"] == "Connection timeout"
        assert "completed_at" not in row


class TestUpdateAccount:
    @patch("hfaudit.reporting.persistence.create_client")
    def test_update_account_upsert(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.update_account("evil-user", {"reputation_score": 0.1, "flagged_count": 3})

        client.table.assert_called_with("accounts")
        upsert_call = client.table.return_value.upsert
        upsert_call.assert_called_once()
        row = upsert_call.call_args[0][0]

        assert row["username"] == "evil-user"
        assert row["reputation_score"] == 0.1
        assert row["flagged_count"] == 3
        assert "last_seen" in row
        assert upsert_call.call_args[1]["on_conflict"] == "username"


class TestGetPublishedFindings:
    @patch("hfaudit.reporting.persistence.create_client")
    def test_get_published_findings_returns_list(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client
        client.table.return_value.execute.return_value = MagicMock(
            data=[{"id": "HFA-2026-0001", "severity": "critical"}]
        )

        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        results = p.get_published_findings()

        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["id"] == "HFA-2026-0001"
        client.table.return_value.select.assert_called_with("*")
        client.table.return_value.eq.assert_called_with("disclosure_status", "published")

    @patch("hfaudit.reporting.persistence.create_client")
    def test_get_published_findings_empty(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        results = p.get_published_findings()

        assert results == []


class TestUpdateStats:
    @patch("hfaudit.reporting.persistence.create_client")
    def test_update_stats_upsert_with_date(self, mock_create: MagicMock) -> None:
        client = _mock_client()
        mock_create.return_value = client

        p = ScanPersistence(SupabaseConfig(url="https://x.supabase.co", service_key="svc"))
        p.update_stats({"total_scanned": 100, "findings_critical": 2, "findings_high": 5})

        client.table.assert_called_with("scan_stats")
        upsert_call = client.table.return_value.upsert
        row = upsert_call.call_args[0][0]

        assert row["total_scanned"] == 100
        assert row["findings_critical"] == 2
        assert row["findings_high"] == 5
        assert "stat_date" in row
        assert upsert_call.call_args[1]["on_conflict"] == "stat_date"


class TestDatetimeSerialization:
    def test_aware_datetime_preserved(self) -> None:
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert _dt_to_iso(dt) == "2026-01-15T12:00:00+00:00"

    def test_naive_datetime_gets_utc(self) -> None:
        dt = datetime(2026, 6, 1, 0, 0, 0)
        result = _dt_to_iso(dt)
        assert "+00:00" in result

    def test_microsecond_precision(self) -> None:
        dt = datetime(2026, 3, 1, 8, 30, 15, 123456, tzinfo=timezone.utc)
        result = _dt_to_iso(dt)
        assert "123456" in result
