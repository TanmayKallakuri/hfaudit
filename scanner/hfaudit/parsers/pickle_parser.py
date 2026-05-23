from __future__ import annotations

import ast
import io
import pickletools
from dataclasses import dataclass, field
from typing import Any

from hfaudit.parsers.base import BaseParser


@dataclass
class OpcodeInfo:
    name: str
    arg: str | None
    pos: int


@dataclass
class ReduceCall:
    callable_module: str
    callable_name: str
    args: list[str]
    pos: int


@dataclass
class ImportInfo:
    module: str
    name: str
    pos: int


@dataclass
class PickleAnalysis:
    opcodes: list[OpcodeInfo] = field(default_factory=list)
    reduce_calls: list[ReduceCall] = field(default_factory=list)
    imports: list[ImportInfo] = field(default_factory=list)
    nested_pickles: list[bytes] = field(default_factory=list)
    raw_strings: list[str] = field(default_factory=list)
    has_exec_opcodes: bool = False
    file_path: str = ""
    truncated: bool = False
    parse_error: str | None = None


_EXEC_OPCODE_NAMES = frozenset({"REDUCE", "BUILD", "INST", "OBJ"})

_GLOBAL_OPCODE_NAMES = frozenset({"GLOBAL", "STACK_GLOBAL", "INST"})

# Pickle protocol magic bytes for nested pickle detection
_PICKLE_MAGIC_V2 = b"\x80\x02"
_PICKLE_MAGIC_V3 = b"\x80\x03"
_PICKLE_MAGIC_V4 = b"\x80\x04"
_PICKLE_MAGIC_V5 = b"\x80\x05"

# Marshal magic: first two bytes of a marshal code object
_MARSHAL_HEADER = b"\xe3"



class PickleParser(BaseParser):
    """Analyzes pickle byte streams without executing them."""

    @property
    def supported_extensions(self) -> list[str]:
        return [".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt"]

    def parse(self, data: bytes, file_path: str) -> PickleAnalysis:
        analysis = PickleAnalysis(file_path=file_path)
        self._walk_opcodes(data, analysis)
        self._extract_fickling_info(data, analysis)
        self._detect_nested_pickles(data, analysis)
        return analysis

    def _walk_opcodes(self, data: bytes, analysis: PickleAnalysis) -> None:
        """Walk opcodes via pickletools.genops, tolerating truncated streams."""
        try:
            for opcode, arg, pos in pickletools.genops(data):
                arg_str = repr(arg) if arg is not None else None
                info = OpcodeInfo(name=opcode.name, arg=arg_str, pos=pos)
                analysis.opcodes.append(info)

                if opcode.name in _EXEC_OPCODE_NAMES:
                    analysis.has_exec_opcodes = True

                if opcode.name in _GLOBAL_OPCODE_NAMES:
                    self._extract_global_import(opcode.name, arg, pos, analysis)

                if isinstance(arg, str) and len(arg) > 0:
                    analysis.raw_strings.append(arg)

        except Exception:
            analysis.truncated = True
            # partial analysis is still useful

        self._resolve_reduce_calls(data, analysis)

    def _extract_global_import(
        self, opcode_name: str, arg: Any, pos: int, analysis: PickleAnalysis
    ) -> None:
        """Extract module and name from GLOBAL/INST opcodes."""
        if opcode_name == "GLOBAL" and isinstance(arg, str):
            parts = arg.split(" ", 1)
            if len(parts) == 2:
                analysis.imports.append(ImportInfo(module=parts[0], name=parts[1], pos=pos))
            elif len(parts) == 1:
                # single token like "eval" => builtins
                analysis.imports.append(ImportInfo(module="builtins", name=parts[0], pos=pos))
        elif opcode_name == "INST" and isinstance(arg, str):
            parts = arg.split(" ", 1)
            if len(parts) == 2:
                analysis.imports.append(ImportInfo(module=parts[0], name=parts[1], pos=pos))

    def _resolve_reduce_calls(self, data: bytes, analysis: PickleAnalysis) -> None:
        """Walk the opcode list to pair STACK_GLOBAL/GLOBAL with subsequent REDUCE."""
        pending_module: str | None = None
        pending_name: str | None = None
        pending_pos: int = 0
        arg_strings: list[str] = []

        i = 0
        opcodes = analysis.opcodes
        while i < len(opcodes):
            op = opcodes[i]

            if op.name == "GLOBAL" and op.arg is not None:
                raw = op.arg.strip("'\"")
                parts = raw.split(" ", 1)
                if len(parts) == 2:
                    pending_module, pending_name = parts[0], parts[1]
                else:
                    pending_module, pending_name = "builtins", parts[0]
                pending_pos = op.pos
                arg_strings = []

            elif op.name == "STACK_GLOBAL":
                # STACK_GLOBAL uses the two preceding stack items (module, name)
                mod, name = self._find_stack_global_args(opcodes, i)
                if mod is not None and name is not None:
                    pending_module = mod
                    pending_name = name
                    pending_pos = op.pos
                    # also record the import
                    analysis.imports.append(ImportInfo(module=mod, name=name, pos=op.pos))
                arg_strings = []

            elif op.name in ("SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING", "BINSTRING"):
                if op.arg is not None:
                    arg_strings.append(op.arg.strip("'\""))

            elif op.name == "REDUCE" and pending_module is not None and pending_name is not None:
                analysis.reduce_calls.append(
                    ReduceCall(
                        callable_module=pending_module,
                        callable_name=pending_name,
                        args=list(arg_strings),
                        pos=pending_pos,
                    )
                )
                pending_module = None
                pending_name = None
                arg_strings = []

            i += 1

    def _find_stack_global_args(
        self, opcodes: list[OpcodeInfo], stack_global_idx: int
    ) -> tuple[str | None, str | None]:
        """Walk backwards from STACK_GLOBAL to find the module and name strings."""
        name: str | None = None
        module: str | None = None
        for j in range(stack_global_idx - 1, -1, -1):
            op = opcodes[j]
            if op.name in ("SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING", "BINSTRING"):
                raw = op.arg.strip("'\"") if op.arg else ""
                if name is None:
                    name = raw
                elif module is None:
                    module = raw
                    break
            elif op.name == "MEMOIZE":
                continue
            elif op.name in _EXEC_OPCODE_NAMES or op.name in _GLOBAL_OPCODE_NAMES:
                break
        return module, name

    def _extract_fickling_info(self, data: bytes, analysis: PickleAnalysis) -> None:
        """Use fickling for higher-level AST analysis to supplement opcode walking."""
        try:
            from fickling.fickle import Pickled

            pickled = Pickled.load(io.BytesIO(data))
            tree = pickled.ast

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        imp = ImportInfo(module=node.module, name=alias.name, pos=-1)
                        if not self._import_already_recorded(imp, analysis):
                            analysis.imports.append(imp)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.rsplit(".", 1)
                        mod = parts[0] if len(parts) > 1 else ""
                        nm = parts[-1]
                        imp = ImportInfo(module=mod, name=nm, pos=-1)
                        if not self._import_already_recorded(imp, analysis):
                            analysis.imports.append(imp)

        except Exception:
            # fickling may fail on malformed/partial data; opcode analysis still stands
            pass

    def _import_already_recorded(self, imp: ImportInfo, analysis: PickleAnalysis) -> bool:
        return any(
            existing.module == imp.module and existing.name == imp.name
            for existing in analysis.imports
        )

    def _detect_nested_pickles(self, data: bytes, analysis: PickleAnalysis) -> None:
        """Scan raw bytes for embedded pickle/marshal/dill streams."""
        # Look for marshal code objects embedded in pickle string literals
        if _MARSHAL_HEADER in data:
            idx = 0
            while True:
                idx = data.find(_MARSHAL_HEADER, idx)
                if idx == -1:
                    break
                # marshal code object: \xe3 followed by argcount etc
                # only flag if it looks like it's inside a string opcode's payload
                if idx > 0 and self._is_inside_string_payload(data, idx):
                    chunk = data[idx : idx + 256]
                    analysis.nested_pickles.append(chunk)
                idx += 1

        # Look for nested pickle streams (pickle-in-pickle)
        for magic in (_PICKLE_MAGIC_V2, _PICKLE_MAGIC_V3, _PICKLE_MAGIC_V4, _PICKLE_MAGIC_V5):
            idx = 0
            while True:
                idx = data.find(magic, idx)
                if idx <= 0:
                    # skip the very first occurrence (that's the outer pickle)
                    if idx == -1:
                        break
                    idx += 1
                    continue
                chunk = data[idx : idx + 512]
                analysis.nested_pickles.append(chunk)
                idx += len(magic)

    def _is_inside_string_payload(self, data: bytes, offset: int) -> bool:
        """Heuristic: check if offset is preceded by a BINSTRING/BINUNICODE length header."""
        # SHORT_BINUNICODE = 0x8c, BINUNICODE = 0x8d, SHORT_BINSTRING = 0x55, BINSTRING = 0x54
        # BINBYTES = 0x42, SHORT_BINBYTES = 0x43
        if offset < 2:
            return False
        for lookback in range(1, min(6, offset + 1)):
            byte = data[offset - lookback]
            if byte in (0x8C, 0x8D, 0x55, 0x54, 0x42, 0x43, 0xC4, 0xC5):
                return True
        return False
