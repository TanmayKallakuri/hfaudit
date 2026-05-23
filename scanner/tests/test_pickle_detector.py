from __future__ import annotations

import collections
import io
import pickle
import pickletools
import struct

import pytest

from hfaudit.detectors.pickle_detector import PickleDetector
from hfaudit.parsers.pickle_parser import (
    ImportInfo,
    OpcodeInfo,
    PickleAnalysis,
    PickleParser,
    ReduceCall,
)


# ---------------------------------------------------------------------------
# Helpers to create malicious pickle bytestreams
# ---------------------------------------------------------------------------


def _make_reduce_pickle(module: str, name: str, args: tuple[object, ...] = ()) -> bytes:
    """Build a pickle that calls module.name(*args) via __reduce__."""
    # Build it by hand using pickle opcodes for full control
    buf = io.BytesIO()
    # Protocol 2 header
    buf.write(b"\x80\x02")
    # GLOBAL opcode: "module name\n"
    buf.write(b"c")
    buf.write(f"{module}\n{name}\n".encode())
    # Push args as a tuple
    if not args:
        buf.write(b")\x85")  # EMPTY_TUPLE via TUPLE1 trick won't work; use ) for empty tuple
        buf.write(b"R")  # REDUCE
    else:
        buf.write(b"(")  # MARK
        for arg in args:
            if isinstance(arg, str):
                encoded = arg.encode("utf-8")
                buf.write(b"X")  # BINUNICODE
                buf.write(struct.pack("<I", len(encoded)))
                buf.write(encoded)
            elif isinstance(arg, int):
                buf.write(b"J")  # BININT
                buf.write(struct.pack("<i", arg))
        buf.write(b"t")  # TUPLE
        buf.write(b"R")  # REDUCE
    buf.write(b".")  # STOP
    return buf.getvalue()


def _make_stack_global_pickle(module: str, name: str, arg_str: str = "") -> bytes:
    """Build a pickle that uses STACK_GLOBAL to reference module.name."""
    buf = io.BytesIO()
    buf.write(b"\x80\x04")  # Protocol 4
    # SHORT_BINUNICODE for module
    mod_bytes = module.encode("utf-8")
    buf.write(b"\x8c")
    buf.write(bytes([len(mod_bytes)]))
    buf.write(mod_bytes)
    # SHORT_BINUNICODE for name
    name_bytes = name.encode("utf-8")
    buf.write(b"\x8c")
    buf.write(bytes([len(name_bytes)]))
    buf.write(name_bytes)
    # STACK_GLOBAL
    buf.write(b"\x93")
    if arg_str:
        arg_bytes = arg_str.encode("utf-8")
        buf.write(b"\x8c")
        buf.write(bytes([len(arg_bytes)]))
        buf.write(arg_bytes)
        buf.write(b"\x85")  # TUPLE1
    else:
        buf.write(b")")  # EMPTY_TUPLE
    buf.write(b"R")  # REDUCE
    buf.write(b".")  # STOP
    return buf.getvalue()


def _make_multi_import_pickle(modules: list[tuple[str, str]]) -> bytes:
    """Build a pickle referencing multiple globals."""
    buf = io.BytesIO()
    buf.write(b"\x80\x02")
    for mod, name in modules:
        buf.write(b"c")
        buf.write(f"{mod}\n{name}\n".encode())
    buf.write(b".")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestPickleParser:
    def setup_method(self) -> None:
        self.parser = PickleParser()

    def test_supported_extensions(self) -> None:
        exts = self.parser.supported_extensions
        assert ".pkl" in exts
        assert ".pt" in exts
        assert ".bin" in exts

    def test_parse_clean_dict(self) -> None:
        data = pickle.dumps({"learning_rate": 0.001, "epochs": 10})
        analysis = self.parser.parse(data, "config.pkl")
        assert not analysis.has_exec_opcodes
        assert len(analysis.reduce_calls) == 0
        assert analysis.file_path == "config.pkl"

    def test_parse_clean_list(self) -> None:
        data = pickle.dumps([1, 2, 3, "hello"])
        analysis = self.parser.parse(data, "data.pkl")
        assert not analysis.has_exec_opcodes
        assert "hello" in analysis.raw_strings

    def test_parse_ordered_dict(self) -> None:
        data = pickle.dumps(collections.OrderedDict([("a", 1), ("b", 2)]))
        analysis = self.parser.parse(data, "state_dict.bin")
        # OrderedDict uses REDUCE in pickle, so has_exec_opcodes is True (factual, not a threat signal)
        assert analysis.has_exec_opcodes
        assert any(
            rc.callable_module == "collections" and rc.callable_name == "OrderedDict"
            for rc in analysis.reduce_calls
        )

    def test_parse_os_system_reduce(self) -> None:
        data = _make_reduce_pickle("os", "system", ("echo pwned",))
        analysis = self.parser.parse(data, "evil.pkl")
        assert analysis.has_exec_opcodes
        assert len(analysis.reduce_calls) >= 1
        rc = analysis.reduce_calls[0]
        assert rc.callable_module == "os"
        assert rc.callable_name == "system"

    def test_parse_stack_global(self) -> None:
        data = _make_stack_global_pickle("subprocess", "Popen", "ls -la")
        analysis = self.parser.parse(data, "evil2.pkl")
        assert analysis.has_exec_opcodes
        has_subprocess = any(
            imp.module == "subprocess" and imp.name == "Popen"
            for imp in analysis.imports
        )
        assert has_subprocess

    def test_parse_global_import_extraction(self) -> None:
        data = _make_reduce_pickle("socket", "socket")
        analysis = self.parser.parse(data, "net.pkl")
        has_socket = any(imp.module == "socket" for imp in analysis.imports)
        assert has_socket

    def test_parse_truncated_stream(self) -> None:
        data = pickle.dumps({"a": 1, "b": [2, 3]})
        truncated = data[:10]
        analysis = self.parser.parse(truncated, "partial.pkl")
        assert analysis.truncated
        assert len(analysis.opcodes) > 0

    def test_parse_empty_bytes(self) -> None:
        analysis = self.parser.parse(b"", "empty.pkl")
        assert len(analysis.opcodes) == 0

    def test_parse_garbage_bytes(self) -> None:
        analysis = self.parser.parse(b"\xff\xfe\xfd\xfc\xfb", "garbage.pkl")
        assert analysis.truncated or len(analysis.opcodes) == 0

    def test_raw_strings_extraction(self) -> None:
        data = pickle.dumps({"key": "http://evil.com/payload"})
        analysis = self.parser.parse(data, "strings.pkl")
        assert any("http://evil.com" in s for s in analysis.raw_strings)

    def test_multiple_reduce_calls(self) -> None:
        # Build a pickle with two separate reduce calls
        buf = io.BytesIO()
        buf.write(b"\x80\x02")
        buf.write(b"cos\nsystem\n")
        buf.write(b"(X\x06\x00\x00\x00echo 1t")
        buf.write(b"R")
        buf.write(b"cos\npopen\n")
        buf.write(b"(X\x06\x00\x00\x00echo 2t")
        buf.write(b"R")
        buf.write(b".")
        data = buf.getvalue()
        analysis = self.parser.parse(data, "multi.pkl")
        assert len(analysis.reduce_calls) >= 2


# ---------------------------------------------------------------------------
# Detector tests
# ---------------------------------------------------------------------------


class TestPickleDetector:
    def setup_method(self) -> None:
        self.parser = PickleParser()
        self.detector = PickleDetector()

    def _scan(self, data: bytes, file_path: str = "model.pkl") -> list[object]:
        analysis = self.parser.parse(data, file_path)
        return self.detector.detect(analysis)

    # --- HFA-PKL-001: Dangerous reduce ---

    def test_001_os_system(self) -> None:
        data = _make_reduce_pickle("os", "system", ("echo pwned",))
        findings = self._scan(data)
        rule_ids = [f.rule_id for f in findings]
        assert "HFA-PKL-001" in rule_ids

    def test_001_subprocess_popen(self) -> None:
        data = _make_reduce_pickle("subprocess", "Popen", ("ls",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_001_eval(self) -> None:
        data = _make_reduce_pickle("builtins", "eval", ("__import__('os')",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_001_posix_system(self) -> None:
        data = _make_reduce_pickle("posix", "system", ("id",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_001_nt_system(self) -> None:
        data = _make_reduce_pickle("nt", "system", ("whoami",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_001_severity_is_critical(self) -> None:
        data = _make_reduce_pickle("os", "system", ("id",))
        findings = self._scan(data)
        pkl_001 = [f for f in findings if f.rule_id == "HFA-PKL-001"]
        assert all(f.severity == "critical" for f in pkl_001)

    def test_001_evidence_includes_callable(self) -> None:
        data = _make_reduce_pickle("os", "system", ("whoami",))
        findings = self._scan(data)
        pkl_001 = [f for f in findings if f.rule_id == "HFA-PKL-001"]
        assert len(pkl_001) > 0
        assert "os.system" in pkl_001[0].evidence

    # --- HFA-PKL-002: Builtins exec ---

    def test_002_builtins_exec(self) -> None:
        data = _make_reduce_pickle("builtins", "exec", ("print('hi')",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-002" for f in findings)

    def test_002_builtins_eval(self) -> None:
        data = _make_reduce_pickle("builtins", "eval", ("1+1",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-002" for f in findings)

    def test_002_builtins_compile(self) -> None:
        data = _make_reduce_pickle("builtins", "compile", ("pass",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-002" for f in findings)

    def test_002_builtins_import(self) -> None:
        data = _make_reduce_pickle("builtins", "__import__", ("os",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-002" for f in findings)

    # --- HFA-PKL-003: Network imports ---

    def test_003_socket_import(self) -> None:
        data = _make_reduce_pickle("socket", "socket")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-003" for f in findings)

    def test_003_requests_import(self) -> None:
        data = _make_reduce_pickle("requests", "get", ("http://evil.com",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-003" for f in findings)

    def test_003_urllib_import(self) -> None:
        data = _make_reduce_pickle("urllib", "urlopen")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-003" for f in findings)

    def test_003_http_client_import(self) -> None:
        data = _make_reduce_pickle("http.client", "HTTPConnection")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-003" for f in findings)

    # --- HFA-PKL-004: System imports ---

    def test_004_ctypes_import(self) -> None:
        data = _make_reduce_pickle("ctypes", "cdll")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-004" for f in findings)

    def test_004_pty_import(self) -> None:
        data = _make_reduce_pickle("pty", "spawn")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-004" for f in findings)

    def test_004_shutil_import(self) -> None:
        data = _make_reduce_pickle("shutil", "rmtree")
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-004" for f in findings)

    # --- HFA-PKL-005: Filesystem writes ---

    def test_005_builtins_open(self) -> None:
        data = _make_reduce_pickle("builtins", "open", ("/etc/passwd",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-005" for f in findings)

    def test_005_io_open(self) -> None:
        data = _make_reduce_pickle("io", "open", ("/tmp/evil",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-005" for f in findings)

    def test_005_os_makedirs(self) -> None:
        data = _make_reduce_pickle("os", "makedirs", ("/tmp/evil",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-005" for f in findings)

    # --- HFA-PKL-006: Reverse shell ---

    def test_006_socket_plus_pty(self) -> None:
        data = _make_multi_import_pickle([("socket", "socket"), ("pty", "spawn")])
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-006" for f in findings)

    def test_006_socket_plus_subprocess(self) -> None:
        data = _make_multi_import_pickle([("socket", "socket"), ("subprocess", "call")])
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-006" for f in findings)

    def test_006_socket_plus_os(self) -> None:
        data = _make_multi_import_pickle([("socket", "socket"), ("os", "dup2")])
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-006" for f in findings)

    def test_006_no_false_positive_single_socket(self) -> None:
        data = _make_reduce_pickle("socket", "socket")
        findings = self._scan(data)
        assert not any(f.rule_id == "HFA-PKL-006" for f in findings)

    # --- HFA-PKL-007: Network strings ---

    def test_007_ip_address_in_string(self) -> None:
        data = pickle.dumps({"config": "connect to 192.168.1.100:4444"})
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-007" for f in findings)

    def test_007_url_in_string(self) -> None:
        data = pickle.dumps({"url": "http://evil.com/malware.sh"})
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-007" for f in findings)

    def test_007_benign_localhost_excluded(self) -> None:
        data = pickle.dumps({"host": "127.0.0.1"})
        findings = self._scan(data)
        assert not any(
            f.rule_id == "HFA-PKL-007" and "127.0.0.1" in f.evidence for f in findings
        )

    def test_007_no_false_positive_clean_strings(self) -> None:
        data = pickle.dumps({"name": "bert-base-uncased", "version": "1.0"})
        findings = self._scan(data)
        assert not any(f.rule_id == "HFA-PKL-007" for f in findings)

    # --- HFA-PKL-008: Getattr chains ---

    def test_008_deep_getattr_chain(self) -> None:
        analysis = PickleAnalysis(
            file_path="obfuscated.pkl",
            reduce_calls=[
                ReduceCall("builtins", "getattr", ["obj", "a"], pos=10),
                ReduceCall("builtins", "getattr", ["obj", "b"], pos=20),
                ReduceCall("builtins", "getattr", ["obj", "c"], pos=30),
                ReduceCall("builtins", "getattr", ["obj", "d"], pos=40),
            ],
            imports=[],
            opcodes=[],
            has_exec_opcodes=True,
        )
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-008" for f in findings)

    def test_008_no_fire_shallow_getattr(self) -> None:
        analysis = PickleAnalysis(
            file_path="ok.pkl",
            reduce_calls=[
                ReduceCall("builtins", "getattr", ["obj", "a"], pos=10),
                ReduceCall("builtins", "getattr", ["obj", "b"], pos=20),
            ],
            imports=[],
            opcodes=[],
            has_exec_opcodes=True,
        )
        findings = self.detector.detect(analysis)
        assert not any(f.rule_id == "HFA-PKL-008" for f in findings)

    # --- HFA-PKL-009: Nested payloads ---

    def test_009_nested_pickle_detected(self) -> None:
        analysis = PickleAnalysis(
            file_path="nested.pkl",
            nested_pickles=[b"\x80\x04nested_data"],
            imports=[],
            opcodes=[],
        )
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-009" for f in findings)

    def test_009_no_fire_clean(self) -> None:
        data = pickle.dumps({"clean": True})
        findings = self._scan(data)
        assert not any(f.rule_id == "HFA-PKL-009" for f in findings)

    # --- HFA-PKL-010: Unusual globals ---

    def test_010_unusual_global(self) -> None:
        data = _make_reduce_pickle("webbrowser", "open", ("http://evil.com",))
        findings = self._scan(data)
        assert any(f.rule_id == "HFA-PKL-010" for f in findings)

    def test_010_torch_is_allowlisted(self) -> None:
        analysis = PickleAnalysis(
            file_path="model.pt",
            imports=[
                ImportInfo(module="torch._utils", name="_rebuild_tensor_v2", pos=10),
                ImportInfo(module="torch.nn.modules.linear", name="Linear", pos=20),
                ImportInfo(module="collections", name="OrderedDict", pos=30),
            ],
            opcodes=[],
        )
        findings = self.detector.detect(analysis)
        assert not any(f.rule_id == "HFA-PKL-010" for f in findings)

    def test_010_numpy_is_allowlisted(self) -> None:
        analysis = PickleAnalysis(
            file_path="model.pkl",
            imports=[
                ImportInfo(module="numpy.core.multiarray", name="_reconstruct", pos=10),
                ImportInfo(module="numpy", name="dtype", pos=20),
            ],
            opcodes=[],
        )
        findings = self.detector.detect(analysis)
        assert not any(f.rule_id == "HFA-PKL-010" for f in findings)

    def test_010_severity_is_low(self) -> None:
        data = _make_reduce_pickle("webbrowser", "open")
        findings = self._scan(data)
        pkl_010 = [f for f in findings if f.rule_id == "HFA-PKL-010"]
        assert all(f.severity == "low" for f in pkl_010)


# ---------------------------------------------------------------------------
# Clean model tests (no findings expected for safe patterns)
# ---------------------------------------------------------------------------


class TestCleanModels:
    def setup_method(self) -> None:
        self.parser = PickleParser()
        self.detector = PickleDetector()

    def _scan(self, data: bytes, file_path: str = "model.pkl") -> list[object]:
        analysis = self.parser.parse(data, file_path)
        return self.detector.detect(analysis)

    def test_simple_dict_no_findings(self) -> None:
        data = pickle.dumps({"learning_rate": 0.001, "batch_size": 32})
        findings = self._scan(data)
        # clean dicts should produce zero critical/high/medium findings
        serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
        assert len(serious) == 0

    def test_nested_dict_no_findings(self) -> None:
        data = pickle.dumps({"model": {"layers": [1, 2, 3], "config": {"dropout": 0.1}}})
        findings = self._scan(data)
        serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
        assert len(serious) == 0

    def test_ordered_dict_no_findings(self) -> None:
        data = pickle.dumps(collections.OrderedDict([("weight", 1.0), ("bias", 0.5)]))
        findings = self._scan(data)
        serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
        assert len(serious) == 0

    def test_list_of_numbers_no_findings(self) -> None:
        data = pickle.dumps([float(i) for i in range(100)])
        findings = self._scan(data)
        serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
        assert len(serious) == 0

    def test_bytes_object_no_findings(self) -> None:
        data = pickle.dumps(b"\x00\x01\x02\x03" * 100)
        findings = self._scan(data)
        serious = [f for f in findings if f.severity in ("critical", "high", "medium")]
        assert len(serious) == 0


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def setup_method(self) -> None:
        self.parser = PickleParser()
        self.detector = PickleDetector()

    def test_truncated_pickle_partial_analysis(self) -> None:
        data = pickle.dumps({"key": "value", "nested": [1, 2, 3]})
        truncated = data[:15]
        analysis = self.parser.parse(truncated, "truncated.pkl")
        assert analysis.truncated
        # should not crash, should have partial data
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)

    def test_empty_input(self) -> None:
        analysis = self.parser.parse(b"", "empty.pkl")
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_single_byte(self) -> None:
        analysis = self.parser.parse(b"\x80", "single.pkl")
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)

    def test_non_pickle_input(self) -> None:
        analysis = self.parser.parse(b"this is just plain text, not pickle", "text.pkl")
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)

    def test_finding_has_required_fields(self) -> None:
        data = _make_reduce_pickle("os", "system", ("id",))
        analysis = self.parser.parse(data, "evil.pkl")
        findings = self.detector.detect(analysis)
        assert len(findings) > 0
        f = findings[0]
        assert f.id.startswith("HFA-")
        assert f.severity in ("critical", "high", "medium", "low", "informational")
        assert f.rule_id.startswith("HFA-PKL-")
        assert len(f.evidence) > 0
        assert f.file_path == "evil.pkl"
        assert 0.0 <= f.confidence <= 1.0

    def test_finding_sarif_roundtrip(self) -> None:
        data = _make_reduce_pickle("os", "system", ("id",))
        analysis = self.parser.parse(data, "evil.pkl")
        findings = self.detector.detect(analysis)
        for f in findings:
            sarif = f.to_sarif()
            assert sarif["ruleId"] == f.rule_id
            assert isinstance(sarif["level"], str)

    def test_unicode_string_in_pickle(self) -> None:
        data = pickle.dumps({"key": "value with unicode: ☃ ❤ \U0001f600"})
        analysis = self.parser.parse(data, "unicode.pkl")
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)

    def test_very_large_string_in_pickle(self) -> None:
        data = pickle.dumps({"big": "A" * 100_000})
        analysis = self.parser.parse(data, "large.pkl")
        findings = self.detector.detect(analysis)
        assert isinstance(findings, list)

    def test_stack_global_reduce_detection(self) -> None:
        data = _make_stack_global_pickle("os", "system", "whoami")
        analysis = self.parser.parse(data, "sg.pkl")
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_detector_accepts_wrong_type_gracefully(self) -> None:
        findings = self.detector.detect("not a PickleAnalysis")
        assert findings == []

    def test_detector_accepts_none_gracefully(self) -> None:
        findings = self.detector.detect(None)
        assert findings == []


# ---------------------------------------------------------------------------
# Real-world-ish pickle via pickle.dumps with __reduce__
# ---------------------------------------------------------------------------


class TestRealWorldPatterns:
    def setup_method(self) -> None:
        self.parser = PickleParser()
        self.detector = PickleDetector()

    def test_real_os_system_via_reduce_class(self) -> None:
        """Uses actual pickle.dumps with a class that has __reduce__."""
        import os

        class Evil:
            def __reduce__(self) -> tuple[object, ...]:
                return (os.system, ("echo pwned",))

        data = pickle.dumps(Evil())
        analysis = self.parser.parse(data, "real_evil.pkl")
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)
        assert analysis.has_exec_opcodes

    def test_real_exec_via_reduce_class(self) -> None:
        class ExecEvil:
            def __reduce__(self) -> tuple[object, ...]:
                return (exec, ("import os; os.system('id')",))

        data = pickle.dumps(ExecEvil())
        analysis = self.parser.parse(data, "exec_evil.pkl")
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)

    def test_real_eval_via_reduce_class(self) -> None:
        class EvalEvil:
            def __reduce__(self) -> tuple[object, ...]:
                return (eval, ("1+1",))

        data = pickle.dumps(EvalEvil())
        analysis = self.parser.parse(data, "eval_evil.pkl")
        findings = self.detector.detect(analysis)
        assert any(f.rule_id == "HFA-PKL-001" for f in findings)
