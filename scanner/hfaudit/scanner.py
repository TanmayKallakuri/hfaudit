from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

from hfaudit.detectors.pickle_detector import PickleDetector
from hfaudit.fetchers import FetchError, HFFetcher, ModelFile, ModelNotFoundError, RateLimitError
from hfaudit.parsers.pickle_parser import PickleParser
from hfaudit.reporting.finding import Finding

PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"})
SAVEDMODEL_FILES = frozenset({"saved_model.pb"})
KERAS_EXTENSIONS = frozenset({".h5", ".keras"})

_MAX_HEADER_BYTES = 1_048_576  # matches hf_fetcher._DEFAULT_HEADER_BYTES


@dataclass
class ScanResult:
    model_id: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    has_errors: bool = False

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "model_id": self.model_id,
                "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped,
                "findings": [f.model_dump(mode="json") for f in self.findings],
                "errors": self.errors,
                "duration_ms": self.duration_ms,
            },
            indent=2,
        )

    def to_sarif(self) -> dict[str, object]:
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "hfaudit",
                            "informationUri": "https://github.com/TanmayKallakuri/hfaudit",
                        }
                    },
                    "results": [f.to_sarif() for f in self.findings],
                }
            ],
        }


def _classify_file(mf: ModelFile) -> str | None:
    """Return the format category for a model file, or None to skip."""
    path_lower = mf.path.lower()
    for ext in PICKLE_EXTENSIONS:
        if path_lower.endswith(ext):
            return "pickle"
    if mf.path.split("/")[-1] in SAVEDMODEL_FILES:
        return "savedmodel"
    for ext in KERAS_EXTENSIONS:
        if path_lower.endswith(ext):
            return "keras"
    return None


def _set_error(result: ScanResult, msg: str) -> None:
    result.errors.append(msg)
    result.has_errors = True


def scan_model(model_id: str, *, token: str | None = None) -> ScanResult:
    """Run the full Stage 1 static analysis pipeline on a HuggingFace model."""
    start = time.monotonic()
    result = ScanResult(model_id=model_id)
    fetcher = HFFetcher(token=token)

    try:
        fetch_result = fetcher.list_model_files(model_id)
    except ModelNotFoundError:
        _set_error(result, f"Model not found: {model_id}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
    except RateLimitError as e:
        _set_error(result, f"Rate limited: {e}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
    except FetchError as e:
        _set_error(result, f"Fetch error: {e}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    pickle_parser = PickleParser()
    pickle_detector = PickleDetector()

    savedmodel_parser = None
    savedmodel_detector = None
    try:
        from hfaudit.parsers.savedmodel_parser import SavedModelParser, _TF_AVAILABLE
        from hfaudit.detectors.savedmodel_detector import SavedModelDetector
        if _TF_AVAILABLE:
            savedmodel_parser = SavedModelParser()
            savedmodel_detector = SavedModelDetector()
    except ImportError:
        pass

    keras_parser = None
    keras_detector = None
    try:
        from hfaudit.parsers.keras_parser import KerasParser
        from hfaudit.detectors.keras_detector import KerasDetector
        keras_parser = KerasParser()
        keras_detector = KerasDetector()
    except ImportError:
        pass

    for mf in fetch_result.files:
        fmt = _classify_file(mf)
        if fmt is None:
            result.files_skipped += 1
            continue

        if fmt == "savedmodel" and (savedmodel_parser is None or savedmodel_detector is None):
            result.files_skipped += 1
            _set_error(
                result,
                f"Skipped {mf.path}: tensorflow not installed "
                "(install hfaudit[tf] for SavedModel scanning)",
            )
            continue

        if fmt == "keras" and (keras_parser is None or keras_detector is None):
            result.files_skipped += 1
            _set_error(
                result,
                f"Skipped {mf.path}: h5py not installed "
                "(install hfaudit[keras] for Keras scanning)",
            )
            continue

        try:
            content = fetcher.fetch_file_header(model_id, mf.path, max_bytes=_MAX_HEADER_BYTES)
        except RateLimitError as e:
            _set_error(result, f"Rate limited fetching {mf.path}: {e}")
            break
        except FetchError as e:
            _set_error(result, f"Failed to fetch {mf.path}: {e}")
            result.files_skipped += 1
            continue

        result.files_scanned += 1

        if fmt == "pickle":
            pkl_analysis = pickle_parser.parse(content.data, file_path=mf.path)
            pkl_findings = pickle_detector.detect(pkl_analysis)
            for f in pkl_findings:
                f.model_id = model_id
            result.findings.extend(pkl_findings)

        elif fmt == "savedmodel" and savedmodel_parser and savedmodel_detector:
            sm_analysis = savedmodel_parser.parse(content.data, file_path=mf.path)
            sm_findings = savedmodel_detector.detect(sm_analysis)
            for f in sm_findings:
                f.model_id = model_id
            result.findings.extend(sm_findings)

        elif fmt == "keras" and keras_parser and keras_detector:
            keras_analysis = keras_parser.parse(content.data, file_path=mf.path)
            keras_findings = keras_detector.detect(keras_analysis)
            for f in keras_findings:
                f.model_id = model_id
            result.findings.extend(keras_findings)

    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
