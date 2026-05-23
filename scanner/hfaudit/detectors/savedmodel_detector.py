from __future__ import annotations

import uuid
from typing import Any

from hfaudit.detectors.base import BaseDetector
from hfaudit.detectors.tf_op_allowlist import SAFE_TF_OPS
from hfaudit.parsers.savedmodel_parser import OpInfo, SavedModelAnalysis
from hfaudit.reporting.finding import Finding

_FILESYSTEM_OPS: frozenset[str] = frozenset({
    "ReadFile", "WriteFile", "MatchingFiles", "DeleteFile",
})

_STRING_CONSTRUCTION_OPS: frozenset[str] = frozenset({
    "StringFormat", "StringJoin", "ReduceJoin", "StringSplit", "StringSplitV2",
    "Substr", "RegexReplace", "StaticRegexReplace",
    "DecodeBase64", "AsString",
})

_OUTPUT_SINK_OPS: frozenset[str] = frozenset({
    "PrintV2", "Print",
})

_PROCESS_EXEC_OPS: frozenset[str] = frozenset({
    "ShellExecute",
})

_PY_FUNCTION_OPS: frozenset[str] = frozenset({
    "PyFunc", "PyFuncStateless", "EagerPyFunc",
})

_NUMPY_FUNCTION_OPS: frozenset[str] = frozenset({
    "NumpyFunction",
})

_NETWORK_OPS: frozenset[str] = frozenset({
    "TcpClient", "TcpServer", "HttpRequest",
    "CollectiveReduce", "CollectiveBcastSend", "CollectiveBcastRecv",
    "CollectiveGather",
})


def _make_finding_id() -> str:
    short = uuid.uuid4().hex[:8].upper()
    return f"HFA-SM-{short}"


def _build_node_index(analysis: SavedModelAnalysis) -> dict[str, OpInfo]:
    """Map node names to their OpInfo for graph traversal."""
    index: dict[str, OpInfo] = {}
    for op in analysis.ops:
        index[op.node_name] = op
    return index


def _strip_control_prefix(name: str) -> str:
    """Remove TF control dependency prefix (^) and output index suffix (:N)."""
    if name.startswith("^"):
        name = name[1:]
    if ":" in name:
        name = name.rsplit(":", 1)[0]
    return name


def _trace_inputs_backward(
    node_name: str,
    node_index: dict[str, OpInfo],
    visited: set[str] | None = None,
    max_depth: int = 20,
) -> list[OpInfo]:
    """Walk input edges backward from a node, collecting all reachable ops."""
    if visited is None:
        visited = set()
    if node_name in visited or max_depth <= 0:
        return []
    visited.add(node_name)

    op = node_index.get(node_name)
    if op is None:
        return []

    result = [op]
    for inp in op.inputs:
        clean = _strip_control_prefix(inp)
        result.extend(_trace_inputs_backward(clean, node_index, visited, max_depth - 1))
    return result


def _detect_printv2_chain(analysis: SavedModelAnalysis) -> list[Finding]:
    """HFA-SM-002: Detect PrintV2 ops receiving dynamically constructed strings.

    The attack pattern chains PrintV2 <- StringFormat/StringJoin <- Const nodes
    containing payload fragments. We trace backward from every output-sink op
    and flag when string construction ops appear in the input ancestry.
    """
    findings: list[Finding] = []
    node_index = _build_node_index(analysis)

    for op in analysis.ops:
        if op.name not in _OUTPUT_SINK_OPS:
            continue

        ancestors = _trace_inputs_backward(op.node_name, node_index)
        ancestor_ops = {a.name for a in ancestors} - {op.name}
        string_ops_found = ancestor_ops & _STRING_CONSTRUCTION_OPS
        has_const_source = any(a.name == "Const" for a in ancestors if a.node_name != op.node_name)

        if string_ops_found and has_const_source:
            chain_nodes = [a.node_name for a in ancestors if a.name in _STRING_CONSTRUCTION_OPS]
            const_nodes = [a.node_name for a in ancestors if a.name == "Const"]
            findings.append(Finding(
                id=_make_finding_id(),
                model_id="",
                severity="critical",
                rule_id="HFA-SM-002",
                category="savedmodel.printv2_chain",
                description=(
                    f"{op.name} node '{op.node_name}' receives dynamically constructed "
                    f"string input via {sorted(string_ops_found)}. This pattern matches "
                    f"the PrintV2 op chain bypass (ProtectAI ModelScan issue #342)."
                ),
                evidence=(
                    f"Sink: {op.node_name} ({op.name}); "
                    f"String ops: {chain_nodes}; "
                    f"Const sources: {const_nodes}"
                ),
                file_path="",
                confidence=0.95,
                references=[
                    "https://github.com/protectai/modelscan/issues/342",
                ],
                false_positive_notes=(
                    "PrintV2 is sometimes used in TF debugging. A standalone PrintV2 "
                    "with a constant string input is likely benign. The dangerous pattern "
                    "is PrintV2 receiving dynamically constructed strings."
                ),
                bypass_notes=(
                    "The original bypass used PrintV2 -> StringFormat/StringJoin -> Const. "
                    "Variants could use different string construction ops, split the payload "
                    "across more nodes, or use other 'benign' output ops as the terminal "
                    "node. An evolved scanner should trace ALL output ops backward, not "
                    "just PrintV2."
                ),
            ))

    return findings


class SavedModelDetector(BaseDetector):
    """Detection rules for TensorFlow SavedModel files."""

    @property
    def rule_ids(self) -> list[str]:
        return [
            "HFA-SM-001",
            "HFA-SM-002",
            "HFA-SM-003",
            "HFA-SM-004",
            "HFA-SM-005",
            "HFA-SM-006",
        ]

    def detect(self, parsed_model: Any) -> list[Finding]:
        if not isinstance(parsed_model, SavedModelAnalysis):
            return []

        findings: list[Finding] = []
        findings.extend(self._detect_filesystem_ops(parsed_model))
        findings.extend(_detect_printv2_chain(parsed_model))
        findings.extend(self._detect_process_exec(parsed_model))
        findings.extend(self._detect_py_function(parsed_model))
        findings.extend(self._detect_allowlist_violation(parsed_model))
        findings.extend(self._detect_network_ops(parsed_model))
        return findings

    def _detect_filesystem_ops(self, analysis: SavedModelAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for op in analysis.ops:
            if op.name in _FILESYSTEM_OPS:
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="critical",
                    rule_id="HFA-SM-001",
                    category="savedmodel.dangerous_filesystem_op",
                    description=(
                        f"Dangerous filesystem op '{op.name}' found at node "
                        f"'{op.node_name}'. This op can read/write arbitrary files "
                        f"on the host when the model is loaded."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}, Inputs: {op.inputs}",
                    file_path="",
                    confidence=0.99,
                    false_positive_notes=(
                        "ReadFile can appear in legitimate image-loading pipelines "
                        "within SavedModels that bundle preprocessing. Check whether "
                        "the path input is a constant pointing to a bundled asset vs. "
                        "a user-controlled placeholder."
                    ),
                    bypass_notes=(
                        "Attacker could wrap filesystem ops inside custom ops or use "
                        "tf.py_function to invoke filesystem calls indirectly."
                    ),
                ))
        return findings

    def _detect_process_exec(self, analysis: SavedModelAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for op in analysis.ops:
            if op.name in _PROCESS_EXEC_OPS:
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="critical",
                    rule_id="HFA-SM-003",
                    category="savedmodel.process_execution",
                    description=(
                        f"Process execution op '{op.name}' found at node "
                        f"'{op.node_name}'. This op can execute arbitrary system commands."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}, Inputs: {op.inputs}",
                    file_path="",
                    confidence=0.99,
                    false_positive_notes="No legitimate model should contain process execution ops.",
                    bypass_notes=(
                        "Custom ops or tf.py_function could wrap shell execution. "
                        "Also check for ops registered via tf.load_op_library."
                    ),
                ))
        return findings

    def _detect_py_function(self, analysis: SavedModelAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for op in analysis.ops:
            if op.name in _PY_FUNCTION_OPS:
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="high",
                    rule_id="HFA-SM-004",
                    category="savedmodel.py_function",
                    description=(
                        f"tf.py_function usage detected at node '{op.node_name}'. "
                        f"This embeds arbitrary Python code that executes on model load."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}",
                    file_path="",
                    confidence=0.90,
                    false_positive_notes=(
                        "py_function is used in legitimate preprocessing pipelines "
                        "and custom training loops. Inspect the serialized Python "
                        "callable to determine intent."
                    ),
                    bypass_notes=(
                        "The Python callable inside py_function can do anything the "
                        "Python runtime allows. Obfuscation is trivial."
                    ),
                ))
            elif op.name in _NUMPY_FUNCTION_OPS:
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="high",
                    rule_id="HFA-SM-004",
                    category="savedmodel.numpy_function",
                    description=(
                        f"tf.numpy_function usage detected at node '{op.node_name}'. "
                        f"This embeds arbitrary Python code that executes on model load."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}",
                    file_path="",
                    confidence=0.90,
                    false_positive_notes=(
                        "numpy_function is occasionally used for custom numeric ops. "
                        "Inspect the serialized callable."
                    ),
                    bypass_notes=(
                        "Same as py_function: the embedded callable has full Python "
                        "runtime access."
                    ),
                ))
        return findings

    def _detect_allowlist_violation(self, analysis: SavedModelAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        seen_ops: set[str] = set()
        for op in analysis.ops:
            if op.name not in SAFE_TF_OPS and op.name not in seen_ops:
                seen_ops.add(op.name)
                # Skip ops already covered by higher-severity rules
                if op.name in (
                    _FILESYSTEM_OPS
                    | _OUTPUT_SINK_OPS
                    | _PROCESS_EXEC_OPS
                    | _PY_FUNCTION_OPS
                    | _NUMPY_FUNCTION_OPS
                    | _NETWORK_OPS
                ):
                    continue
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="medium",
                    rule_id="HFA-SM-005",
                    category="savedmodel.unknown_op",
                    description=(
                        f"Op '{op.name}' is not in the standard TensorFlow op allowlist. "
                        f"First seen at node '{op.node_name}'."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}",
                    file_path="",
                    confidence=0.50,
                    false_positive_notes=(
                        "The allowlist is intentionally tight. Legitimate models using "
                        "newer TF ops, contrib ops, or domain-specific ops (e.g., "
                        "audio, text) may trigger this. Review the op documentation "
                        "before escalating."
                    ),
                    bypass_notes=(
                        "An attacker registering a custom op could name it to look "
                        "benign. The allowlist approach catches novel ops but can be "
                        "evaded by hijacking an allowed op name via tf.load_op_library."
                    ),
                ))
        return findings

    def _detect_network_ops(self, analysis: SavedModelAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for op in analysis.ops:
            if op.name in _NETWORK_OPS:
                findings.append(Finding(
                    id=_make_finding_id(),
                    model_id="",
                    severity="medium",
                    rule_id="HFA-SM-006",
                    category="savedmodel.network_op",
                    description=(
                        f"Network-related op '{op.name}' found at node "
                        f"'{op.node_name}'. This could indicate network access "
                        f"during model load or inference."
                    ),
                    evidence=f"Op: {op.name}, Node: {op.node_name}, Inputs: {op.inputs}",
                    file_path="",
                    confidence=0.70,
                    false_positive_notes=(
                        "Collective ops are used in legitimate distributed training "
                        "setups. Suspicious when found in a model intended for "
                        "single-device inference."
                    ),
                    bypass_notes=(
                        "Network access could be hidden inside py_function or custom "
                        "ops. This rule only catches known network op names."
                    ),
                ))
        return findings
