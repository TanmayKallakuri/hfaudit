from __future__ import annotations

from datetime import datetime, timezone
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, field_validator


class Finding(BaseModel):
    id: str = Field(description="Finding identifier, e.g. HFA-2026-0001")
    model_id: str = Field(description="HuggingFace model identifier")
    severity: Literal["critical", "high", "medium", "low", "informational"]
    rule_id: str = Field(description="Rule that triggered this finding")
    category: str
    description: str
    evidence: str
    file_path: str = Field(description="File in the model repo that triggered the finding")
    confidence: float = Field(ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)
    false_positive_notes: str = ""
    bypass_notes: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("id")
    @classmethod
    def id_must_have_prefix(cls, v: str) -> str:
        if not v.startswith("HFA-"):
            raise ValueError("Finding id must start with 'HFA-'")
        return v

    _SEVERITY_TO_SARIF: ClassVar[dict[str, str]] = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "informational": "note",
    }

    def to_sarif(self) -> dict[str, object]:
        """Return this finding as a SARIF result object (v2.1.0 schema)."""
        return {
            "ruleId": self.rule_id,
            "level": self._SEVERITY_TO_SARIF[self.severity],
            "message": {"text": self.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.file_path},
                    }
                }
            ],
            "properties": {
                "id": self.id,
                "model_id": self.model_id,
                "severity": self.severity,
                "category": self.category,
                "confidence": self.confidence,
                "evidence": self.evidence,
                "references": self.references,
                "false_positive_notes": self.false_positive_notes,
                "bypass_notes": self.bypass_notes,
                "timestamp": self.timestamp.isoformat(),
            },
        }
