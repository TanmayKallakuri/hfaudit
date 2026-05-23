from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hfaudit.parsers.base import BaseParser

try:
    from tensorflow.core.protobuf import saved_model_pb2  # type: ignore[import-untyped]

    _TF_AVAILABLE = True
except ImportError:
    _TF_AVAILABLE = False


@dataclass
class OpInfo:
    name: str
    node_name: str
    inputs: list[str]
    attrs: dict[str, str]


@dataclass
class FunctionInfo:
    name: str
    ops: list[OpInfo]


@dataclass
class SavedModelAnalysis:
    ops: list[OpInfo]
    dangerous_ops: list[OpInfo]
    functions: list[FunctionInfo]
    has_py_function: bool
    has_numpy_function: bool
    metadata: dict[str, str]


_DANGEROUS_OPS: frozenset[str] = frozenset({
    "ReadFile", "WriteFile", "MatchingFiles", "DeleteFile",
    "PrintV2",
    "PyFunc", "PyFuncStateless", "EagerPyFunc",
    "NumpyFunction",
})


def _extract_attrs(node: Any) -> dict[str, str]:
    """Pull string-representable attrs from a NodeDef proto."""
    result: dict[str, str] = {}
    try:
        for key in node.attr:
            attr_val = node.attr[key]
            if attr_val.HasField("s"):
                result[key] = attr_val.s.decode("utf-8", errors="replace")
            elif attr_val.HasField("type"):
                result[key] = str(attr_val.type)
            elif attr_val.HasField("i"):
                result[key] = str(attr_val.i)
            elif attr_val.HasField("f"):
                result[key] = str(attr_val.f)
            elif attr_val.HasField("b"):
                result[key] = str(attr_val.b)
    except Exception:
        pass
    return result


def _walk_graph_def(graph_def: Any) -> list[OpInfo]:
    """Extract OpInfo from every node in a GraphDef proto."""
    ops: list[OpInfo] = []
    try:
        for node in graph_def.node:
            ops.append(OpInfo(
                name=str(node.op),
                node_name=str(node.name),
                inputs=[str(inp) for inp in node.input],
                attrs=_extract_attrs(node),
            ))
    except Exception:
        pass
    return ops


class SavedModelParser(BaseParser):
    """Parser for TensorFlow SavedModel protobuf files."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".pb"]

    def parse(self, data: bytes, file_path: str) -> SavedModelAnalysis:
        if not _TF_AVAILABLE:
            raise RuntimeError(
                "tensorflow is required for SavedModel parsing. "
                "Install it with: pip install hfaudit[tf]"
            )
        return self._parse_with_tf(data, file_path)

    def _parse_with_tf(self, data: bytes, file_path: str) -> SavedModelAnalysis:
        saved_model = saved_model_pb2.SavedModel()
        try:
            saved_model.ParseFromString(data)
        except Exception as exc:
            raise ValueError(
                f"Failed to parse SavedModel protobuf from {file_path}: {exc}"
            ) from exc

        all_ops: list[OpInfo] = []
        functions: list[FunctionInfo] = []
        metadata: dict[str, str] = {}

        for idx, meta_graph in enumerate(saved_model.meta_graphs):
            tags = list(meta_graph.meta_info_def.tags)
            if tags:
                metadata[f"meta_graph_{idx}_tags"] = ",".join(tags)

            for sig_key in meta_graph.signature_def:
                metadata[f"signature_{sig_key}"] = str(
                    meta_graph.signature_def[sig_key].method_name
                )

            graph_ops = _walk_graph_def(meta_graph.graph_def)
            all_ops.extend(graph_ops)

            try:
                func_lib = meta_graph.graph_def.library
                for func_def in func_lib.function:
                    func_name = str(func_def.signature.name)
                    func_ops: list[OpInfo] = []
                    for node in func_def.node_def:
                        func_ops.append(OpInfo(
                            name=str(node.op),
                            node_name=str(node.name),
                            inputs=[str(inp) for inp in node.input],
                            attrs=_extract_attrs(node),
                        ))
                    all_ops.extend(func_ops)
                    functions.append(FunctionInfo(name=func_name, ops=func_ops))
            except Exception:
                pass

        dangerous_ops = [op for op in all_ops if op.name in _DANGEROUS_OPS]

        has_py = any(op.name in ("PyFunc", "PyFuncStateless", "EagerPyFunc") for op in all_ops)
        has_numpy = any(op.name == "NumpyFunction" for op in all_ops)

        return SavedModelAnalysis(
            ops=all_ops,
            dangerous_ops=dangerous_ops,
            functions=functions,
            has_py_function=has_py,
            has_numpy_function=has_numpy,
            metadata=metadata,
        )
