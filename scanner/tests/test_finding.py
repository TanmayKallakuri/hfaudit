from __future__ import annotations

from datetime import datetime, timezone

import pytest

from hfaudit.reporting.finding import Finding


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


class TestFindingCreation:
    def test_basic_creation(self) -> None:
        f = _make_finding()
        assert f.id == "HFA-2026-0001"
        assert f.severity == "critical"
        assert 0.0 <= f.confidence <= 1.0

    def test_timestamp_auto_set(self) -> None:
        f = _make_finding()
        assert isinstance(f.timestamp, datetime)
        assert f.timestamp.tzinfo is not None

    def test_id_prefix_validation(self) -> None:
        with pytest.raises(ValueError, match="HFA-"):
            _make_finding(id="BAD-0001")

    def test_confidence_bounds_low(self) -> None:
        with pytest.raises(ValueError):
            _make_finding(confidence=-0.1)

    def test_confidence_bounds_high(self) -> None:
        with pytest.raises(ValueError):
            _make_finding(confidence=1.5)

    def test_invalid_severity(self) -> None:
        with pytest.raises(ValueError):
            _make_finding(severity="unknown")

    def test_defaults_for_optional_fields(self) -> None:
        f = _make_finding(references=[], false_positive_notes="", bypass_notes="")
        assert f.references == []
        assert f.false_positive_notes == ""
        assert f.bypass_notes == ""


class TestFindingSerialization:
    def test_model_dump_roundtrip(self) -> None:
        f = _make_finding()
        data = f.model_dump()
        restored = Finding(**data)
        assert restored.id == f.id
        assert restored.confidence == f.confidence

    def test_model_dump_json(self) -> None:
        f = _make_finding()
        json_str = f.model_dump_json()
        assert "HFA-2026-0001" in json_str
        assert "critical" in json_str


class TestFindingSarif:
    def test_sarif_structure(self) -> None:
        f = _make_finding()
        sarif = f.to_sarif()
        assert sarif["ruleId"] == "HFA-PKL-001"
        assert sarif["level"] == "error"
        assert isinstance(sarif["message"], dict)
        assert isinstance(sarif["locations"], list)
        assert len(sarif["locations"]) == 1  # type: ignore[arg-type]

    def test_sarif_severity_mapping(self) -> None:
        for sev, expected in [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("informational", "note"),
        ]:
            f = _make_finding(severity=sev)
            assert f.to_sarif()["level"] == expected

    def test_sarif_properties_contain_metadata(self) -> None:
        f = _make_finding()
        sarif = f.to_sarif()
        props = sarif["properties"]
        assert isinstance(props, dict)
        assert props["model_id"] == "user/dangerous-model"
        assert props["confidence"] == 0.95

    def test_sarif_artifact_location(self) -> None:
        f = _make_finding(file_path="weights/model.bin")
        sarif = f.to_sarif()
        loc = sarif["locations"][0]  # type: ignore[index]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "weights/model.bin"

    def test_sarif_timestamp_is_iso(self) -> None:
        ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        f = _make_finding(timestamp=ts)
        sarif = f.to_sarif()
        assert sarif["properties"]["timestamp"] == "2026-01-15T12:00:00+00:00"
