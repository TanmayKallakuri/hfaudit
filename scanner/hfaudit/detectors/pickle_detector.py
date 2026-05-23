from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Any

import yaml

from hfaudit.detectors.base import BaseDetector
from hfaudit.parsers.pickle_parser import ImportInfo, PickleAnalysis, ReduceCall
from hfaudit.reporting.finding import Finding

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules"


def _load_yaml_rule(filename: str) -> dict[str, Any]:
    path = _RULES_DIR / filename
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)  # type: ignore[no-any-return]


def _generate_finding_id() -> str:
    short = uuid.uuid4().hex[:8]
    return f"HFA-2026-{short}"


class PickleDetector(BaseDetector):
    """Detects malicious patterns in parsed pickle streams."""

    def __init__(self) -> None:
        self._rules: dict[str, dict[str, Any]] = {}
        rule_files = [
            "pickle-dangerous-reduce.yaml",
            "pickle-builtins-exec.yaml",
            "pickle-network-imports.yaml",
            "pickle-system-imports.yaml",
            "pickle-filesystem-write.yaml",
            "pickle-reverse-shell.yaml",
            "pickle-network-strings.yaml",
            "pickle-getattr-chain.yaml",
            "pickle-nested-payload.yaml",
            "pickle-unusual-global.yaml",
        ]
        for rf in rule_files:
            try:
                rule = _load_yaml_rule(rf)
                self._rules[rule["id"]] = rule
            except Exception:
                pass

        self._allowlist_prefixes: list[str] = []
        rule_010 = self._rules.get("HFA-PKL-010")
        if rule_010:
            self._allowlist_prefixes = rule_010.get("allowlist_modules", [])

    @property
    def rule_ids(self) -> list[str]:
        return [
            "HFA-PKL-001", "HFA-PKL-002", "HFA-PKL-003", "HFA-PKL-004",
            "HFA-PKL-005", "HFA-PKL-006", "HFA-PKL-007", "HFA-PKL-008",
            "HFA-PKL-009", "HFA-PKL-010",
        ]

    def detect(self, parsed_model: Any) -> list[Finding]:
        if not isinstance(parsed_model, PickleAnalysis):
            return []

        findings: list[Finding] = []
        analysis: PickleAnalysis = parsed_model

        findings.extend(self._check_dangerous_reduce(analysis))
        findings.extend(self._check_builtins_exec(analysis))
        findings.extend(self._check_network_imports(analysis))
        findings.extend(self._check_system_imports(analysis))
        findings.extend(self._check_filesystem_write(analysis))
        findings.extend(self._check_reverse_shell(analysis))
        findings.extend(self._check_network_strings(analysis))
        findings.extend(self._check_getattr_chains(analysis))
        findings.extend(self._check_nested_payloads(analysis))
        findings.extend(self._check_unusual_globals(analysis))

        return findings

    def _make_finding(
        self,
        rule_id: str,
        evidence: str,
        file_path: str,
        confidence: float,
        model_id: str = "",
    ) -> Finding:
        rule = self._rules.get(rule_id, {})
        return Finding(
            id=_generate_finding_id(),
            model_id=model_id,
            severity=rule.get("severity", "medium"),
            rule_id=rule_id,
            category=rule.get("category", "pickle.unknown"),
            description=rule.get("description", ""),
            evidence=evidence,
            file_path=file_path,
            confidence=confidence,
            references=rule.get("references", []),
            false_positive_notes=rule.get("false_positive_notes", ""),
            bypass_notes=rule.get("bypass_notes", ""),
        )

    def _qualified_name(self, rc: ReduceCall) -> str:
        return f"{rc.callable_module}.{rc.callable_name}"

    def _qualified_import(self, imp: ImportInfo) -> str:
        if imp.module:
            return f"{imp.module}.{imp.name}"
        return imp.name

    # --- HFA-PKL-001: Dangerous reduce callables ---

    def _check_dangerous_reduce(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-001")
        if not rule:
            return []
        targets = set(rule.get("targets", []))
        findings: list[Finding] = []
        for rc in analysis.reduce_calls:
            qname = self._qualified_name(rc)
            # check exact match and bare name match (e.g., "eval" matches "eval")
            if qname in targets or rc.callable_name in targets:
                evidence = (
                    f"REDUCE at byte {rc.pos}: {qname}({', '.join(rc.args)})"
                )
                findings.append(self._make_finding(
                    "HFA-PKL-001", evidence, analysis.file_path, 0.95,
                ))
        return findings

    # --- HFA-PKL-002: Builtins code execution ---

    def _check_builtins_exec(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-002")
        if not rule:
            return []
        targets = set(rule.get("targets", []))
        findings: list[Finding] = []
        seen: set[str] = set()
        for rc in analysis.reduce_calls:
            qname = self._qualified_name(rc)
            if qname in targets and qname not in seen:
                seen.add(qname)
                evidence = f"REDUCE at byte {rc.pos}: {qname}({', '.join(rc.args)})"
                findings.append(self._make_finding(
                    "HFA-PKL-002", evidence, analysis.file_path, 0.95,
                ))
        for imp in analysis.imports:
            qname = self._qualified_import(imp)
            if qname in targets and qname not in seen:
                seen.add(qname)
                evidence = f"GLOBAL/IMPORT at byte {imp.pos}: {qname}"
                findings.append(self._make_finding(
                    "HFA-PKL-002", evidence, analysis.file_path, 0.90,
                ))
        return findings

    # --- HFA-PKL-003: Network imports ---

    def _check_network_imports(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-003")
        if not rule:
            return []
        targets = set(rule.get("targets", []))
        findings: list[Finding] = []
        seen: set[str] = set()
        for imp in analysis.imports:
            mod_root = imp.module.split(".")[0] if imp.module else ""
            if (imp.module in targets or mod_root in targets) and imp.module not in seen:
                seen.add(imp.module)
                evidence = f"GLOBAL at byte {imp.pos}: {self._qualified_import(imp)}"
                findings.append(self._make_finding(
                    "HFA-PKL-003", evidence, analysis.file_path, 0.85,
                ))
        return findings

    # --- HFA-PKL-004: System imports ---

    def _check_system_imports(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-004")
        if not rule:
            return []
        targets = set(rule.get("targets", []))
        findings: list[Finding] = []
        seen: set[str] = set()
        for imp in analysis.imports:
            mod_root = imp.module.split(".")[0] if imp.module else ""
            if (imp.module in targets or mod_root in targets) and imp.module not in seen:
                seen.add(imp.module)
                evidence = f"GLOBAL at byte {imp.pos}: {self._qualified_import(imp)}"
                findings.append(self._make_finding(
                    "HFA-PKL-004", evidence, analysis.file_path, 0.80,
                ))
        return findings

    # --- HFA-PKL-005: Filesystem write primitives ---

    def _check_filesystem_write(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-005")
        if not rule:
            return []
        targets = set(rule.get("targets", []))
        findings: list[Finding] = []
        for rc in analysis.reduce_calls:
            qname = self._qualified_name(rc)
            if qname in targets:
                evidence = f"REDUCE at byte {rc.pos}: {qname}({', '.join(rc.args)})"
                findings.append(self._make_finding(
                    "HFA-PKL-005", evidence, analysis.file_path, 0.90,
                ))
        # also check imports for the module part (e.g., "io" module with "open")
        for imp in analysis.imports:
            qname = self._qualified_import(imp)
            if qname in targets:
                evidence = f"GLOBAL at byte {imp.pos}: {qname}"
                findings.append(self._make_finding(
                    "HFA-PKL-005", evidence, analysis.file_path, 0.85,
                ))
        return findings

    # --- HFA-PKL-006: Reverse shell indicators ---

    def _check_reverse_shell(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-006")
        if not rule:
            return []
        imported_modules = {imp.module.split(".")[0] for imp in analysis.imports if imp.module}
        imported_modules |= {imp.name for imp in analysis.imports}

        findings: list[Finding] = []
        compound_sets = [
            ({"socket", "pty"}, "socket + pty.spawn pattern"),
            ({"socket", "subprocess"}, "socket + subprocess pattern"),
            ({"socket", "os"}, "socket + os (potential dup2 shell)"),
        ]
        for required_mods, label in compound_sets:
            if required_mods.issubset(imported_modules):
                modules_str = ", ".join(sorted(required_mods))
                evidence = f"Compound import pattern [{modules_str}]: {label}"
                findings.append(self._make_finding(
                    "HFA-PKL-006", evidence, analysis.file_path, 0.90,
                ))
        return findings

    # --- HFA-PKL-007: Network strings ---

    _IPV4_RE = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    )
    _URL_RE = re.compile(r"https?://[^\s'\"]{4,}")
    _BENIGN_IPS = frozenset({"127.0.0.1", "0.0.0.0", "255.255.255.255"})

    def _check_network_strings(self, analysis: PickleAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        for s in analysis.raw_strings:
            for match in self._IPV4_RE.finditer(s):
                ip = match.group()
                if ip not in self._BENIGN_IPS:
                    evidence = f"IPv4 address in string literal: {ip}"
                    findings.append(self._make_finding(
                        "HFA-PKL-007", evidence, analysis.file_path, 0.70,
                    ))
            for match in self._URL_RE.finditer(s):
                url = match.group()
                evidence = f"URL in string literal: {url}"
                findings.append(self._make_finding(
                    "HFA-PKL-007", evidence, analysis.file_path, 0.65,
                ))
        return findings

    # --- HFA-PKL-008: Getattr chains ---

    def _check_getattr_chains(self, analysis: PickleAnalysis) -> list[Finding]:
        rule = self._rules.get("HFA-PKL-008")
        if not rule:
            return []
        threshold = rule.get("threshold", 3)
        findings: list[Finding] = []

        # count consecutive getattr-style reduce calls
        getattr_depth = 0
        max_depth = 0
        for rc in analysis.reduce_calls:
            if rc.callable_name == "getattr":
                getattr_depth += 1
                max_depth = max(max_depth, getattr_depth)
            else:
                getattr_depth = 0

        if max_depth > threshold:
            evidence = (
                f"getattr chain depth {max_depth} exceeds threshold {threshold}"
            )
            findings.append(self._make_finding(
                "HFA-PKL-008", evidence, analysis.file_path, 0.75,
            ))

        # also check import-level getattr patterns (multiple builtins.getattr)
        getattr_imports = [
            imp for imp in analysis.imports
            if imp.name == "getattr" and imp.module in ("builtins", "")
        ]
        if len(getattr_imports) > threshold:
            evidence = (
                f"{len(getattr_imports)} getattr imports detected (threshold {threshold})"
            )
            findings.append(self._make_finding(
                "HFA-PKL-008", evidence, analysis.file_path, 0.70,
            ))

        return findings

    # --- HFA-PKL-009: Nested payloads ---

    def _check_nested_payloads(self, analysis: PickleAnalysis) -> list[Finding]:
        if not analysis.nested_pickles:
            return []
        evidence = f"{len(analysis.nested_pickles)} nested pickle/marshal/dill payload(s) detected"
        return [self._make_finding(
            "HFA-PKL-009", evidence, analysis.file_path, 0.70,
        )]

    # --- HFA-PKL-010: Unusual globals ---

    def _check_unusual_globals(self, analysis: PickleAnalysis) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for imp in analysis.imports:
            mod = imp.module
            if not mod:
                continue
            root = mod.split(".")[0]
            if root in seen:
                continue
            if not self._is_allowlisted(mod):
                seen.add(root)
                evidence = f"Non-allowlisted global: {self._qualified_import(imp)} at byte {imp.pos}"
                findings.append(self._make_finding(
                    "HFA-PKL-010", evidence, analysis.file_path, 0.50,
                ))
        return findings

    def _is_allowlisted(self, module: str) -> bool:
        root = module.split(".")[0]
        for prefix in self._allowlist_prefixes:
            if root == prefix or module == prefix or module.startswith(prefix + "."):
                return True
        return False
