from __future__ import annotations

import pytest

from hfaudit.detectors.savedmodel_detector import SavedModelDetector
from hfaudit.detectors.tf_op_allowlist import SAFE_TF_OPS
from hfaudit.parsers.savedmodel_parser import (
    OpInfo,
    SavedModelAnalysis,
)


def _op(name: str, node_name: str = "", inputs: list[str] | None = None) -> OpInfo:
    return OpInfo(
        name=name,
        node_name=node_name or name.lower() + "_0",
        inputs=inputs or [],
        attrs={},
    )


def _clean_analysis(ops: list[OpInfo] | None = None) -> SavedModelAnalysis:
    """A normal model with only safe ops."""
    if ops is None:
        ops = [
            _op("Const", "input_const"),
            _op("MatMul", "dense/matmul", ["input_const"]),
            _op("BiasAdd", "dense/bias_add", ["dense/matmul"]),
            _op("Relu", "dense/relu", ["dense/bias_add"]),
            _op("Softmax", "output/softmax", ["dense/relu"]),
        ]
    return SavedModelAnalysis(
        ops=ops,
        dangerous_ops=[],
        functions=[],
        has_py_function=False,
        has_numpy_function=False,
        metadata={"meta_graph_0_tags": "serve"},
    )


class TestCleanModel:
    def test_no_findings_on_clean_model(self) -> None:
        detector = SavedModelDetector()
        findings = detector.detect(_clean_analysis())
        assert findings == []

    def test_rule_ids(self) -> None:
        detector = SavedModelDetector()
        assert "HFA-SM-001" in detector.rule_ids
        assert "HFA-SM-002" in detector.rule_ids
        assert len(detector.rule_ids) == 6

    def test_non_savedmodel_input_returns_empty(self) -> None:
        detector = SavedModelDetector()
        assert detector.detect({"not": "a savedmodel"}) == []
        assert detector.detect(None) == []
        assert detector.detect(42) == []


class TestFilesystemOps:
    """HFA-SM-001: Dangerous filesystem ops."""

    @pytest.mark.parametrize("op_name", ["ReadFile", "WriteFile", "MatchingFiles", "DeleteFile"])
    def test_detects_filesystem_op(self, op_name: str) -> None:
        analysis = _clean_analysis([
            _op("Const", "path_const"),
            _op(op_name, f"{op_name.lower()}_node", ["path_const"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm001 = [f for f in findings if f.rule_id == "HFA-SM-001"]
        assert len(sm001) == 1
        assert sm001[0].severity == "critical"
        assert op_name in sm001[0].description

    def test_multiple_filesystem_ops(self) -> None:
        analysis = _clean_analysis([
            _op("ReadFile", "read_node"),
            _op("WriteFile", "write_node"),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm001 = [f for f in findings if f.rule_id == "HFA-SM-001"]
        assert len(sm001) == 2


class TestPrintV2Chain:
    """HFA-SM-002: PrintV2 chain bypass -- the prior ProtectAI disclosure."""

    def test_detects_printv2_stringjoin_const_chain(self) -> None:
        """Classic bypass pattern: Const -> StringJoin -> PrintV2."""
        analysis = _clean_analysis([
            _op("Const", "payload_part1"),
            _op("Const", "payload_part2"),
            _op("StringJoin", "join_node", ["payload_part1", "payload_part2"]),
            _op("PrintV2", "print_node", ["join_node"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1
        assert sm002[0].severity == "critical"
        assert "PrintV2" in sm002[0].description
        assert "342" in sm002[0].references[0]

    def test_detects_printv2_stringformat_chain(self) -> None:
        """Variant: Const -> StringFormat -> PrintV2."""
        analysis = _clean_analysis([
            _op("Const", "template_const"),
            _op("Const", "value_const"),
            _op("StringFormat", "format_node", ["template_const", "value_const"]),
            _op("PrintV2", "print_node", ["format_node"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_detects_reducejoin_chain(self) -> None:
        """Variant: Const -> ReduceJoin -> PrintV2."""
        analysis = _clean_analysis([
            _op("Const", "fragments"),
            _op("Const", "axis"),
            _op("ReduceJoin", "reduce_node", ["fragments", "axis"]),
            _op("PrintV2", "print_node", ["reduce_node"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_deep_chain_still_detected(self) -> None:
        """Multi-hop: Const -> StringJoin -> StringFormat -> PrintV2."""
        analysis = _clean_analysis([
            _op("Const", "c1"),
            _op("Const", "c2"),
            _op("StringJoin", "join", ["c1", "c2"]),
            _op("StringFormat", "fmt", ["join"]),
            _op("PrintV2", "sink", ["fmt"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_standalone_printv2_not_flagged(self) -> None:
        """A PrintV2 with only a direct Const input is benign (no string ops)."""
        analysis = _clean_analysis([
            _op("Const", "debug_msg"),
            _op("PrintV2", "print_node", ["debug_msg"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 0

    def test_control_dependency_prefix_handled(self) -> None:
        """Inputs with ^ prefix (control deps) should be traversed."""
        analysis = _clean_analysis([
            _op("Const", "payload"),
            _op("StringJoin", "joiner", ["payload"]),
            _op("PrintV2", "printer", ["^joiner"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_output_index_suffix_handled(self) -> None:
        """Inputs with :N suffix (output index) should be traversed."""
        analysis = _clean_analysis([
            _op("Const", "fragment"),
            _op("StringJoin", "join", ["fragment:0"]),
            _op("PrintV2", "sink", ["join:0"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_print_op_also_traced(self) -> None:
        """The older Print op (not just PrintV2) should also be checked."""
        analysis = _clean_analysis([
            _op("Const", "c"),
            _op("StringJoin", "j", ["c"]),
            _op("Print", "p", ["j"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1

    def test_decodebase64_in_chain(self) -> None:
        """DecodeBase64 used to reconstruct payload: Const -> DecodeBase64 -> PrintV2."""
        analysis = _clean_analysis([
            _op("Const", "encoded_payload"),
            _op("DecodeBase64", "decoder", ["encoded_payload"]),
            _op("PrintV2", "sink", ["decoder"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1


class TestProcessExec:
    """HFA-SM-003: Process execution ops."""

    def test_detects_shell_execute(self) -> None:
        analysis = _clean_analysis([
            _op("ShellExecute", "exec_node"),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm003 = [f for f in findings if f.rule_id == "HFA-SM-003"]
        assert len(sm003) == 1
        assert sm003[0].severity == "critical"


class TestPyFunction:
    """HFA-SM-004: py_function / numpy_function detection."""

    @pytest.mark.parametrize("op_name", ["PyFunc", "PyFuncStateless", "EagerPyFunc"])
    def test_detects_py_function(self, op_name: str) -> None:
        analysis = _clean_analysis([_op(op_name, f"{op_name}_node")])
        analysis.has_py_function = True
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm004 = [f for f in findings if f.rule_id == "HFA-SM-004"]
        assert len(sm004) == 1
        assert sm004[0].severity == "high"

    def test_detects_numpy_function(self) -> None:
        analysis = _clean_analysis([_op("NumpyFunction", "np_func_node")])
        analysis.has_numpy_function = True
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm004 = [f for f in findings if f.rule_id == "HFA-SM-004"]
        assert len(sm004) == 1
        assert sm004[0].severity == "high"
        assert "numpy_function" in sm004[0].category


class TestOpAllowlist:
    """HFA-SM-005: Op allowlist violation."""

    def test_unknown_op_flagged(self) -> None:
        analysis = _clean_analysis([
            _op("Const", "c"),
            _op("MatMul", "mm"),
            _op("SuspiciousCustomOp", "custom_node"),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm005 = [f for f in findings if f.rule_id == "HFA-SM-005"]
        assert len(sm005) == 1
        assert sm005[0].severity == "medium"
        assert "SuspiciousCustomOp" in sm005[0].description

    def test_all_safe_ops_pass(self) -> None:
        safe_sample = ["Const", "MatMul", "BiasAdd", "Relu", "Softmax", "Conv2D", "MaxPool"]
        ops = [_op(name, f"{name.lower()}_node") for name in safe_sample]
        analysis = _clean_analysis(ops)
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm005 = [f for f in findings if f.rule_id == "HFA-SM-005"]
        assert len(sm005) == 0

    def test_filesystem_ops_not_double_reported_as_allowlist(self) -> None:
        """ReadFile triggers SM-001 (critical) but should NOT also trigger SM-005."""
        analysis = _clean_analysis([_op("ReadFile", "rf_node")])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm005 = [f for f in findings if f.rule_id == "HFA-SM-005"]
        assert len(sm005) == 0

    def test_multiple_unknown_ops_deduplicated(self) -> None:
        """Same unknown op appearing twice should only fire once."""
        analysis = _clean_analysis([
            _op("WeirdOp", "weird_1"),
            _op("WeirdOp", "weird_2"),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm005 = [f for f in findings if f.rule_id == "HFA-SM-005"]
        assert len(sm005) == 1

    def test_allowlist_is_frozen(self) -> None:
        assert isinstance(SAFE_TF_OPS, frozenset)
        assert "MatMul" in SAFE_TF_OPS
        assert "ReadFile" not in SAFE_TF_OPS


class TestNetworkOps:
    """HFA-SM-006: Network-related ops."""

    @pytest.mark.parametrize("op_name", ["TcpClient", "TcpServer", "HttpRequest"])
    def test_detects_network_op(self, op_name: str) -> None:
        analysis = _clean_analysis([_op(op_name, f"{op_name.lower()}_node")])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm006 = [f for f in findings if f.rule_id == "HFA-SM-006"]
        assert len(sm006) == 1
        assert sm006[0].severity == "medium"


class TestFindingQuality:
    """Verify findings have required fields populated correctly."""

    def test_finding_has_valid_id_prefix(self) -> None:
        analysis = _clean_analysis([_op("ReadFile", "rf")])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        for f in findings:
            assert f.id.startswith("HFA-")

    def test_finding_confidence_in_bounds(self) -> None:
        analysis = _clean_analysis([
            _op("ReadFile", "rf"),
            _op("Const", "c"),
            _op("StringJoin", "sj", ["c"]),
            _op("PrintV2", "pv", ["sj"]),
            _op("PyFunc", "pf"),
            _op("WeirdOp", "wo"),
            _op("HttpRequest", "hr"),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        assert len(findings) > 0
        for f in findings:
            assert 0.0 <= f.confidence <= 1.0

    def test_finding_evidence_nonempty(self) -> None:
        analysis = _clean_analysis([_op("ReadFile", "rf")])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        for f in findings:
            assert f.evidence != ""

    def test_bypass_notes_on_printv2_chain(self) -> None:
        analysis = _clean_analysis([
            _op("Const", "c"),
            _op("StringJoin", "sj", ["c"]),
            _op("PrintV2", "pv", ["sj"]),
        ])
        detector = SavedModelDetector()
        findings = detector.detect(analysis)
        sm002 = [f for f in findings if f.rule_id == "HFA-SM-002"]
        assert len(sm002) == 1
        assert "342" in sm002[0].bypass_notes or "342" in sm002[0].references[0]
        assert "output ops" in sm002[0].bypass_notes.lower()


class TestParserGracefulDegradation:
    """Verify the parser raises clearly when TF is missing."""

    def test_parser_import_without_tf(self) -> None:
        from hfaudit.parsers.savedmodel_parser import SavedModelParser
        parser = SavedModelParser()
        assert ".pb" in parser.supported_extensions

    def test_parser_raises_on_parse_without_tf(self) -> None:
        from unittest.mock import patch
        from hfaudit.parsers.savedmodel_parser import SavedModelParser
        parser = SavedModelParser()
        with patch("hfaudit.parsers.savedmodel_parser._TF_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="tensorflow is required"):
                parser.parse(b"", "test.pb")
