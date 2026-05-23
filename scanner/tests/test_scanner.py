from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hfaudit.fetchers import FetchResult, FileContent, ModelFile
from hfaudit.scanner import ScanResult, _classify_file, scan_model


class TestClassifyFile:
    def test_pickle_extensions(self) -> None:
        for ext in (".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle"):
            mf = ModelFile(path=f"model{ext}", size=100, is_lfs=True, oid=None)
            assert _classify_file(mf) == "pickle"

    def test_savedmodel(self) -> None:
        mf = ModelFile(path="saved_model.pb", size=100, is_lfs=False, oid=None)
        assert _classify_file(mf) == "savedmodel"

    def test_keras_h5(self) -> None:
        mf = ModelFile(path="model.h5", size=100, is_lfs=True, oid=None)
        assert _classify_file(mf) == "keras"

    def test_keras_format(self) -> None:
        mf = ModelFile(path="model.keras", size=100, is_lfs=True, oid=None)
        assert _classify_file(mf) == "keras"

    def test_safetensors_skipped(self) -> None:
        mf = ModelFile(path="model.safetensors", size=100, is_lfs=True, oid=None)
        assert _classify_file(mf) is None

    def test_readme_skipped(self) -> None:
        mf = ModelFile(path="README.md", size=100, is_lfs=False, oid=None)
        assert _classify_file(mf) is None

    def test_nested_savedmodel(self) -> None:
        mf = ModelFile(path="subdir/saved_model.pb", size=100, is_lfs=False, oid=None)
        assert _classify_file(mf) == "savedmodel"


class TestScanResult:
    def test_no_findings(self) -> None:
        result = ScanResult(model_id="test/model")
        assert not result.has_findings

    def test_with_findings(self) -> None:
        from hfaudit.reporting.finding import Finding

        result = ScanResult(model_id="test/model")
        result.findings.append(
            Finding(
                id="HFA-2026-TEST",
                model_id="test/model",
                severity="critical",
                rule_id="HFA-PKL-001",
                category="test",
                description="test finding",
                evidence="test evidence",
                file_path="model.pt",
                confidence=1.0,
            )
        )
        assert result.has_findings

    def test_to_json(self) -> None:
        result = ScanResult(model_id="test/model", files_scanned=3, duration_ms=150)
        output = result.to_json()
        assert '"model_id": "test/model"' in output
        assert '"files_scanned": 3' in output

    def test_to_sarif(self) -> None:
        result = ScanResult(model_id="test/model")
        sarif = result.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1  # type: ignore[arg-type]


class TestScanModelIntegration:
    @patch("hfaudit.scanner.HFFetcher")
    def test_model_not_found(self, mock_fetcher_cls: MagicMock) -> None:
        from hfaudit.fetchers.exceptions import ModelNotFoundError

        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.side_effect = ModelNotFoundError("not-real/model")
        mock_fetcher_cls.return_value = mock_fetcher

        result = scan_model("not-real/model")
        assert len(result.errors) == 1
        assert "not found" in result.errors[0].lower()
        assert result.has_errors

    @patch("hfaudit.scanner.HFFetcher")
    def test_clean_model_no_findings(self, mock_fetcher_cls: MagicMock) -> None:
        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.return_value = FetchResult(
            model_id="clean/model",
            files=[
                ModelFile(path="config.json", size=200, is_lfs=False, oid=None),
                ModelFile(path="model.safetensors", size=5000, is_lfs=True, oid=None),
            ],
        )
        mock_fetcher_cls.return_value = mock_fetcher

        result = scan_model("clean/model")
        assert result.files_scanned == 0
        assert result.files_skipped == 2
        assert not result.has_findings

    @patch("hfaudit.scanner.HFFetcher")
    def test_malicious_pickle_detected(self, mock_fetcher_cls: MagicMock) -> None:
        import os
        import pickle

        class Payload:
            def __reduce__(self) -> tuple[object, tuple[str]]:
                return (os.system, ("echo pwned",))

        malicious_bytes = pickle.dumps(Payload())

        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.return_value = FetchResult(
            model_id="evil/model",
            files=[
                ModelFile(path="model.pt", size=len(malicious_bytes), is_lfs=True, oid=None),
            ],
        )
        mock_fetcher.fetch_file_header.return_value = FileContent(
            path="model.pt",
            data=malicious_bytes,
            is_partial=False,
            total_size=len(malicious_bytes),
        )
        mock_fetcher_cls.return_value = mock_fetcher

        result = scan_model("evil/model")
        assert result.files_scanned == 1
        assert result.has_findings
        severities = {f.severity for f in result.findings}
        assert "critical" in severities
        rule_ids = {f.rule_id for f in result.findings}
        assert "HFA-PKL-001" in rule_ids

    @patch("hfaudit.scanner.HFFetcher")
    def test_multiple_files_scanned(self, mock_fetcher_cls: MagicMock) -> None:
        import pickle

        clean_bytes = pickle.dumps({"weights": [1.0, 2.0, 3.0]})

        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.return_value = FetchResult(
            model_id="multi/model",
            files=[
                ModelFile(path="model.pt", size=len(clean_bytes), is_lfs=True, oid=None),
                ModelFile(path="optimizer.pt", size=len(clean_bytes), is_lfs=True, oid=None),
                ModelFile(path="README.md", size=100, is_lfs=False, oid=None),
            ],
        )
        mock_fetcher.fetch_file_header.return_value = FileContent(
            path="model.pt",
            data=clean_bytes,
            is_partial=False,
            total_size=len(clean_bytes),
        )
        mock_fetcher_cls.return_value = mock_fetcher

        result = scan_model("multi/model")
        assert result.files_scanned == 2
        assert result.files_skipped == 1

    @patch("hfaudit.scanner.HFFetcher")
    def test_rate_limit_breaks_file_loop(self, mock_fetcher_cls: MagicMock) -> None:
        from hfaudit.fetchers.exceptions import RateLimitError

        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.return_value = FetchResult(
            model_id="test/model",
            files=[
                ModelFile(path="a.pt", size=100, is_lfs=True, oid=None),
                ModelFile(path="b.pt", size=100, is_lfs=True, oid=None),
                ModelFile(path="c.pt", size=100, is_lfs=True, oid=None),
            ],
        )
        mock_fetcher.fetch_file_header.side_effect = RateLimitError(retry_after=60.0)
        mock_fetcher_cls.return_value = mock_fetcher

        result = scan_model("test/model")
        assert result.has_errors
        assert len(result.errors) == 1
        assert mock_fetcher.fetch_file_header.call_count == 1

    @patch("hfaudit.scanner.HFFetcher")
    def test_missing_optional_dep_warns(self, mock_fetcher_cls: MagicMock) -> None:
        mock_fetcher = MagicMock()
        mock_fetcher.list_model_files.return_value = FetchResult(
            model_id="test/model",
            files=[
                ModelFile(path="saved_model.pb", size=500, is_lfs=False, oid=None),
            ],
        )
        mock_fetcher_cls.return_value = mock_fetcher

        with patch.dict("sys.modules", {"tensorflow": None, "tensorflow.core": None,
                                         "tensorflow.core.protobuf": None,
                                         "tensorflow.core.protobuf.saved_model_pb2": None}):
            result = scan_model("test/model")

        assert result.files_skipped == 1
        assert result.files_scanned == 0
        assert any("tensorflow" in e.lower() for e in result.errors)
