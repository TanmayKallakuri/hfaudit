from __future__ import annotations

import base64
import io
import json
import marshal
import dis
import zipfile
from dataclasses import dataclass
from typing import Any

from hfaudit.parsers.base import BaseParser

try:
    import h5py  # noqa: F401 — availability check; actual usage via deferred import

    _H5PY_AVAILABLE = True
except ImportError:
    _H5PY_AVAILABLE = False


def _require_h5py() -> None:
    if not _H5PY_AVAILABLE:
        raise ImportError(
            "h5py is required for Keras .h5 parsing. Install with: pip install hfaudit[keras]"
        )


@dataclass
class LambdaLayerInfo:
    name: str
    function_source: str | None
    function_raw: str | None
    config: dict[str, object]


@dataclass
class KerasAnalysis:
    format: str
    model_config: dict[str, object]
    lambda_layers: list[LambdaLayerInfo]
    custom_objects: list[str]
    keras_version: str | None


def _safe_disassemble(raw_b64: str) -> str | None:
    """Disassemble a base64-encoded marshalled code object without executing it."""
    try:
        raw_bytes = base64.b64decode(raw_b64)
        code_obj = marshal.loads(raw_bytes)
        buf = io.StringIO()
        dis.dis(code_obj, file=buf)
        return buf.getvalue()
    except Exception:
        return None


def _collect_lambdas(
    config: dict[str, Any], *, path: str = ""
) -> list[LambdaLayerInfo]:
    """Recursively walk a Keras model config and extract all Lambda layer entries."""
    results: list[LambdaLayerInfo] = []
    class_name = config.get("class_name", "")
    layer_config = config.get("config", {})

    if class_name == "Lambda":
        name = layer_config.get("name", path or "unnamed_lambda")
        func_raw = layer_config.get("function")
        func_source: str | None = None
        if isinstance(func_raw, str) and func_raw:
            func_source = _safe_disassemble(func_raw)
        elif isinstance(func_raw, list) and func_raw:
            # Keras sometimes serialises the function as [base64, arg_type, return_type]
            func_source = _safe_disassemble(func_raw[0])
            func_raw = func_raw[0]

        results.append(
            LambdaLayerInfo(
                name=name,
                function_source=func_source,
                function_raw=func_raw if isinstance(func_raw, str) else None,
                config=layer_config,
            )
        )

    # Recurse into nested layers (Sequential, Functional, Model subclassing)
    if isinstance(layer_config, dict):
        for key in ("layers", "input_layers", "output_layers"):
            layers = layer_config.get(key)
            if isinstance(layers, list):
                for i, layer in enumerate(layers):
                    if isinstance(layer, dict):
                        child_path = f"{path}.{key}[{i}]" if path else f"{key}[{i}]"
                        results.extend(_collect_lambdas(layer, path=child_path))

    # Handle the "build_config" / "module" nesting patterns in Keras 3
    for nest_key in ("build_config", "module"):
        nested = config.get(nest_key)
        if isinstance(nested, dict):
            child_path = f"{path}.{nest_key}" if path else nest_key
            results.extend(_collect_lambdas(nested, path=child_path))

    return results


def _collect_custom_objects(config: dict[str, Any]) -> list[str]:
    """Identify references to custom objects (non-standard class_names) in the config."""
    _BUILTIN_CLASSES = frozenset({
        "Sequential", "Model", "Functional",
        "Dense", "Conv1D", "Conv2D", "Conv3D",
        "MaxPooling1D", "MaxPooling2D", "MaxPooling3D",
        "AveragePooling1D", "AveragePooling2D", "AveragePooling3D",
        "GlobalAveragePooling1D", "GlobalAveragePooling2D",
        "GlobalMaxPooling1D", "GlobalMaxPooling2D",
        "Flatten", "Reshape", "Permute", "RepeatVector",
        "Lambda", "Dropout", "SpatialDropout1D", "SpatialDropout2D",
        "BatchNormalization", "LayerNormalization", "GroupNormalization",
        "Activation", "ReLU", "LeakyReLU", "PReLU", "ELU", "Softmax",
        "Input", "InputLayer", "InputSpec",
        "Embedding", "LSTM", "GRU", "SimpleRNN", "Bidirectional", "TimeDistributed",
        "Add", "Subtract", "Multiply", "Average", "Maximum", "Minimum",
        "Concatenate", "Dot",
        "ZeroPadding1D", "ZeroPadding2D",
        "Cropping1D", "Cropping2D",
        "UpSampling1D", "UpSampling2D",
        "DepthwiseConv2D", "SeparableConv1D", "SeparableConv2D",
        "Conv1DTranspose", "Conv2DTranspose", "Conv3DTranspose",
        "Wrapper", "Attention", "MultiHeadAttention",
        "StringLookup", "IntegerLookup", "TextVectorization",
        "Normalization", "Discretization", "CategoryEncoding",
        "Hashing", "HashedCrossing", "Rescaling", "Resizing",
        "CenterCrop", "RandomFlip", "RandomRotation", "RandomZoom",
        "RandomCrop", "RandomTranslation", "RandomContrast",
    })
    custom: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            cn = node.get("class_name")
            if isinstance(cn, str) and cn not in _BUILTIN_CLASSES:
                if cn not in custom:
                    custom.append(cn)
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(config)
    return custom


def _parse_config_json(raw: str | bytes) -> dict[str, Any]:
    """Parse a model config JSON string, handling bytes from HDF5 attrs."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    return json.loads(raw)  # type: ignore[no-any-return]


class KerasParser(BaseParser):
    """Parse Keras .h5 and .keras model files for security analysis."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".h5", ".keras"]

    def parse(self, data: bytes, file_path: str) -> KerasAnalysis:
        lower = file_path.lower()
        if lower.endswith(".keras"):
            return self._parse_keras_zip(data, file_path)
        return self._parse_h5(data, file_path)

    def _parse_h5(self, data: bytes, file_path: str) -> KerasAnalysis:
        _require_h5py()
        import h5py as h5

        buf = io.BytesIO(data)
        try:
            hf = h5.File(buf, "r")
        except Exception as exc:
            raise ValueError(f"Failed to open HDF5 file '{file_path}': {exc}") from exc

        try:
            return self._extract_from_h5(hf)
        finally:
            hf.close()

    def _extract_from_h5(self, hf: Any) -> KerasAnalysis:
        model_config: dict[str, Any] = {}
        keras_version: str | None = None

        # Try standard attribute locations for the model config
        for key in ("model_config", "model_weights"):
            if key in hf.attrs:
                try:
                    model_config = _parse_config_json(hf.attrs[key])
                    break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

        if not model_config and "model_config" in hf:
            # Some formats store config as a dataset
            try:
                raw = hf["model_config"][()]
                model_config = _parse_config_json(raw)
            except Exception:
                pass

        # Extract Keras version from metadata
        for vkey in ("keras_version",):
            if vkey in hf.attrs:
                val = hf.attrs[vkey]
                keras_version = val.decode("utf-8") if isinstance(val, bytes) else str(val)
                break

        lambdas = _collect_lambdas(model_config) if model_config else []
        custom = _collect_custom_objects(model_config) if model_config else []

        return KerasAnalysis(
            format="h5",
            model_config=model_config,
            lambda_layers=lambdas,
            custom_objects=custom,
            keras_version=keras_version,
        )

    def _parse_keras_zip(self, data: bytes, file_path: str) -> KerasAnalysis:
        buf = io.BytesIO(data)
        try:
            zf = zipfile.ZipFile(buf, "r")
        except (zipfile.BadZipFile, Exception) as exc:
            raise ValueError(
                f"Failed to open .keras zip file '{file_path}': {exc}"
            ) from exc

        model_config: dict[str, Any] = {}
        keras_version: str | None = None

        try:
            # Keras 3 stores config.json at the zip root
            for candidate in ("config.json", "model_config.json"):
                if candidate in zf.namelist():
                    try:
                        raw = zf.read(candidate)
                        model_config = json.loads(raw)
                        break
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue

            # Try to extract Keras version from metadata.json
            if "metadata.json" in zf.namelist():
                try:
                    meta = json.loads(zf.read("metadata.json"))
                    keras_version = meta.get("keras_version")
                except Exception:
                    pass
        finally:
            zf.close()

        lambdas = _collect_lambdas(model_config) if model_config else []
        custom = _collect_custom_objects(model_config) if model_config else []

        return KerasAnalysis(
            format="keras",
            model_config=model_config,
            lambda_layers=lambdas,
            custom_objects=custom,
            keras_version=keras_version,
        )
