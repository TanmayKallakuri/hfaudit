from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from supabase import Client, create_client

from hfaudit.reporting.finding import Finding


@dataclass(frozen=True)
class SupabaseConfig:
    url: str
    service_key: str

    @classmethod
    def from_env(cls) -> SupabaseConfig:
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_SERVICE_KEY", "")
        missing: list[str] = []
        if not url:
            missing.append("SUPABASE_URL")
        if not key:
            missing.append("SUPABASE_SERVICE_KEY")
        if missing:
            raise EnvironmentError(
                f"Required environment variable(s) not set: {', '.join(missing)}"
            )
        return cls(url=url, service_key=key)


@dataclass
class ScanRecord:
    model_id: str
    scan_type: str
    status: str
    stage_reached: int | None = None
    findings_count: int = 0
    duration_ms: int | None = None
    error_message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def _dt_to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


class ScanPersistence:
    def __init__(self, config: SupabaseConfig) -> None:
        self._client: Client = create_client(config.url, config.service_key)

    @classmethod
    def from_env(cls) -> ScanPersistence:
        return cls(SupabaseConfig.from_env())

    def save_finding(self, finding: Finding) -> None:
        """Insert or update a finding in the findings table."""
        row: dict[str, Any] = {
            "id": finding.id,
            "model_id": finding.model_id,
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "category": finding.category,
            "description": finding.description,
            "evidence": finding.evidence,
            "file_path": finding.file_path,
            "confidence": finding.confidence,
            "references": finding.references,
            "false_positive_notes": finding.false_positive_notes,
            "bypass_notes": finding.bypass_notes,
            "updated_at": _dt_to_iso(finding.timestamp),
        }
        self._client.table("findings").upsert(row, on_conflict="id").execute()

    def save_scan(self, scan: ScanRecord) -> None:
        """Record a scan job with its results."""
        row: dict[str, Any] = {
            "model_id": scan.model_id,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "findings_count": scan.findings_count,
            "metadata": scan.metadata,
        }
        if scan.stage_reached is not None:
            row["stage_reached"] = scan.stage_reached
        if scan.duration_ms is not None:
            row["duration_ms"] = scan.duration_ms
        if scan.error_message is not None:
            row["error_message"] = scan.error_message
        if scan.status == "completed":
            row["completed_at"] = _dt_to_iso(datetime.now(timezone.utc))
        self._client.table("scans").insert(row).execute()

    def update_account(self, username: str, signals: dict[str, Any]) -> None:
        """Upsert account reputation data."""
        row: dict[str, Any] = {"username": username, **signals}
        row["last_seen"] = _dt_to_iso(datetime.now(timezone.utc))
        self._client.table("accounts").upsert(row, on_conflict="username").execute()

    def get_published_findings(self) -> list[dict[str, Any]]:
        """Get all published findings for the dashboard."""
        response = (
            self._client.table("findings")
            .select("*")
            .eq("disclosure_status", "published")
            .execute()
        )
        return response.data  # type: ignore[return-value]

    def update_stats(self, stats: dict[str, int]) -> None:
        """Insert or update daily aggregate stats."""
        today = date.today().isoformat()
        row: dict[str, Any] = {"stat_date": today, **stats}
        self._client.table("scan_stats").upsert(row, on_conflict="stat_date").execute()
