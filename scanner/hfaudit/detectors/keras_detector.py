from __future__ import annotations

import re
import uuid

from hfaudit.detectors.base import BaseDetector
from hfaudit.parsers.keras_parser import KerasAnalysis, LambdaLayerInfo
from hfaudit.reporting.finding import Finding

_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bos\b"),
    re.compile(r"\bsubprocess\b"),
    re.compile(r"\bsocket\b"),
    re.compile(r"\beval\b"),
    re.compile(r"\bexec\b"),
    re.compile(r"\b__import__\b"),
    re.compile(r"\bcompile\b"),
    re.compile(r"\bctypes\b"),
    re.compile(r"\bpty\b"),
    re.compile(r"\bshutil\b"),
    re.compile(r"\bsys\b"),
    re.compile(r"\bbuiltins\b"),
    re.compile(r"\bpickle\b"),
    re.compile(r"\bmarshal\b"),
    re.compile(r"\bopen\b"),
]

_NETWORK_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bhttp\b", re.IGNORECASE),
    re.compile(r"\burllib\b"),
    re.compile(r"\brequests\b"),
    re.compile(r"\bsocket\b"),
    re.compile(r"\burlopen\b"),
    re.compile(r"\bftplib\b"),
    re.compile(r"\bhttplib\b"),
    re.compile(r"\bhttp\.client\b"),
]

_OBFUSCATION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bbase64\b"),
    re.compile(r"\bcodecs\b"),
    re.compile(r"\brot13\b", re.IGNORECASE),
    re.compile(r"\bexec\b"),
    re.compile(r"\beval\b"),
    re.compile(r"\bgetattr\b"),
    re.compile(r"\bsetattr\b"),
    re.compile(r"\b__dict__\b"),
    re.compile(r"\bcompile\b"),
]


def _make_finding_id() -> str:
    short = uuid.uuid4().hex[:8].upper()
    return f"HFA-KRS-{short}"


def _searchable_text(layer: LambdaLayerInfo) -> str:
    """Combine all available text from a Lambda layer for pattern matching."""
    parts: list[str] = []
    if layer.function_source:
        parts.append(layer.function_source)
    if layer.function_raw:
        parts.append(layer.function_raw)
    for v in layer.config.values():
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> list[str]:
    """Return pattern strings that matched in text."""
    return [p.pattern for p in patterns if p.search(text)]


class KerasDetector(BaseDetector):
    """Detect malicious patterns in Keras model files."""

    @property
    def rule_ids(self) -> list[str]:
        return [
            "HFA-KRS-001",
            "HFA-KRS-002",
            "HFA-KRS-003",
            "HFA-KRS-004",
            "HFA-KRS-005",
        ]

    def detect(self, parsed_model: KerasAnalysis) -> list[Finding]:
        if not isinstance(parsed_model, KerasAnalysis):
            return []

        findings: list[Finding] = []
        file_ext = f".{parsed_model.format}"

        for layer in parsed_model.lambda_layers:
            findings.append(self._finding_krs001(layer, file_ext))

            text = _searchable_text(layer)
            if not text:
                continue

            dangerous = _matches_any(text, _DANGEROUS_PATTERNS)
            if dangerous:
                findings.append(self._finding_krs002(layer, file_ext, dangerous))

            network = _matches_any(text, _NETWORK_PATTERNS)
            if network:
                findings.append(self._finding_krs003(layer, file_ext, network))

            obfusc = _matches_any(text, _OBFUSCATION_PATTERNS)
            # Only flag obfuscation if there are indicators beyond the basics
            exec_eval_only = {r"\bexec\b", r"\beval\b"}
            if obfusc and not set(obfusc).issubset(exec_eval_only):
                findings.append(self._finding_krs004(layer, file_ext, obfusc))

        if parsed_model.custom_objects:
            findings.append(
                self._finding_krs005(parsed_model.custom_objects, file_ext)
            )

        return findings

    def _finding_krs001(self, layer: LambdaLayerInfo, ext: str) -> Finding:
        return Finding(
            id=_make_finding_id(),
            model_id="",
            severity="high",
            rule_id="HFA-KRS-001",
            category="keras.lambda_layer",
            description=(
                f"Lambda layer '{layer.name}' detected. Lambda layers embed arbitrary Python "
                f"code that executes on model load."
            ),
            evidence=f"Layer name: {layer.name}, has code: {layer.function_raw is not None}",
            file_path=f"<scanned_file>{ext}",
            confidence=0.7,
            references=[
                "https://keras.io/api/layers/core_layers/lambda/",
            ],
            false_positive_notes=(
                "Lambda layers are used in legitimate Keras models for custom operations "
                "(e.g., custom activation functions, tensor manipulation). A model with a "
                "Lambda layer containing only standard NumPy/TF operations is likely benign. "
                "The presence of a Lambda layer alone warrants inspection but is not conclusive."
            ),
            bypass_notes=(
                "An attacker could split malicious code across multiple Lambda layers or "
                "obfuscate the code object to evade string-based detection. The serialized "
                "code object could also be manipulated at the bytecode level to avoid "
                "known-bad function names."
            ),
        )

    def _finding_krs002(
        self, layer: LambdaLayerInfo, ext: str, matches: list[str]
    ) -> Finding:
        return Finding(
            id=_make_finding_id(),
            model_id="",
            severity="high",
            rule_id="HFA-KRS-002",
            category="keras.lambda_layer.dangerous_import",
            description=(
                f"Lambda layer '{layer.name}' contains references to dangerous callables: "
                f"{', '.join(matches)}"
            ),
            evidence=f"Matched patterns: {matches}",
            file_path=f"<scanned_file>{ext}",
            confidence=0.85,
            references=[
                "https://keras.io/api/layers/core_layers/lambda/",
            ],
            false_positive_notes=(
                "Some matches may be incidental (e.g., a variable named 'open' or 'compile' "
                "in disassembled bytecode). Verify by inspecting the full disassembly."
            ),
            bypass_notes=(
                "Attacker can obfuscate imports via getattr, __import__, or dynamic string "
                "construction to avoid matching known-bad names in static analysis."
            ),
        )

    def _finding_krs003(
        self, layer: LambdaLayerInfo, ext: str, matches: list[str]
    ) -> Finding:
        return Finding(
            id=_make_finding_id(),
            model_id="",
            severity="medium",
            rule_id="HFA-KRS-003",
            category="keras.lambda_layer.network_code",
            description=(
                f"Lambda layer '{layer.name}' contains network-related references: "
                f"{', '.join(matches)}"
            ),
            evidence=f"Matched patterns: {matches}",
            file_path=f"<scanned_file>{ext}",
            confidence=0.75,
            references=[],
            false_positive_notes=(
                "Network references in Lambda layer code are almost never legitimate. "
                "However, false positives can occur if disassembled names coincidentally "
                "match (e.g., a co_name containing 'http')."
            ),
            bypass_notes=(
                "An attacker can encode URLs or use indirect module loading to avoid "
                "matching network-related pattern strings."
            ),
        )

    def _finding_krs004(
        self, layer: LambdaLayerInfo, ext: str, matches: list[str]
    ) -> Finding:
        return Finding(
            id=_make_finding_id(),
            model_id="",
            severity="medium",
            rule_id="HFA-KRS-004",
            category="keras.lambda_layer.obfuscation",
            description=(
                f"Lambda layer '{layer.name}' shows obfuscation indicators: "
                f"{', '.join(matches)}"
            ),
            evidence=f"Matched patterns: {matches}",
            file_path=f"<scanned_file>{ext}",
            confidence=0.65,
            references=[],
            false_positive_notes=(
                "Legitimate models may reference base64 or codecs for data processing. "
                "Obfuscation scoring is heuristic; review the full disassembly for intent."
            ),
            bypass_notes=(
                "Sophisticated obfuscation can avoid all pattern-based detection. Bytecode "
                "manipulation at the marshal level can rename co_names and co_consts to "
                "evade string matching entirely."
            ),
        )

    def _finding_krs005(self, custom_objects: list[str], ext: str) -> Finding:
        return Finding(
            id=_make_finding_id(),
            model_id="",
            severity="low",
            rule_id="HFA-KRS-005",
            category="keras.custom_objects",
            description=(
                f"Model references custom objects: {', '.join(custom_objects[:10])}"
                + (f" (and {len(custom_objects) - 10} more)" if len(custom_objects) > 10 else "")
            ),
            evidence=f"Custom class_names: {custom_objects}",
            file_path=f"<scanned_file>{ext}",
            confidence=0.5,
            references=[],
            false_positive_notes=(
                "Custom objects are common in research models and production architectures. "
                "This finding is informational; the objects themselves are not dangerous "
                "unless they contain untrusted code."
            ),
            bypass_notes=(
                "Custom objects require custom_objects dict at load time, which limits "
                "the attack surface compared to Lambda layers. However, a malicious custom "
                "class could still execute arbitrary code if the user supplies it."
            ),
        )
