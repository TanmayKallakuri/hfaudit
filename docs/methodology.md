# Detection Methodology

HFAudit uses a three-stage detection pipeline. Every model passes through Stage 1. Only models with Stage 1 hits proceed to Stage 2. Only corroborated findings reach Stage 3.

## Stage 1 — Static Analysis

Fast, deterministic, defendable. Per-format detectors scan model files without executing them.

**Formats analyzed:**
- PyTorch pickle files (`.pt`, `.pth`, `.bin`, `.ckpt`) — opcode-level analysis of `__reduce__` callables and pickle opcodes
- TensorFlow SavedModel (`.pb`) — graph traversal with op allowlist, known bypass chain detection
- Keras (`.h5`, `.keras`) — Lambda layer identification and code object inspection
- ONNX — custom operator domain detection
- GGUF — metadata anomaly detection
- safetensors — format guarantee verification

**Detection rules** are defined in YAML and loaded at runtime. Every rule includes:
- Severity classification (Critical / High / Medium / Low / Informational)
- Known false positive conditions
- Known bypass techniques (how an attacker might evade this rule)

## Stage 2 — Heuristic and Reputation Signals

Probabilistic signals that adjust priority and severity scoring:
- Account age and upload history
- Model name similarity to popular models (typosquatting)
- Upload metadata anomalies
- Cross-reference with previously flagged accounts

Stage 2 does not condemn a model alone. It adjusts the priority queue for Stage 3 and contributes to overall severity.

## Stage 3 — Sandboxed Dynamic Analysis

The most expensive stage, reserved for Stage 1 Critical/High hits or strong Stage 2 corroboration. Models are loaded in an isolated container with:
- No network access
- Read-only filesystem (except tmpfs workspace)
- CPU, memory, and wall-clock limits
- Full syscall tracing

Confirmed malicious behaviors: process execution, network connect attempts, filesystem writes outside workspace, DNS queries.

## Severity Rubric

| Severity | Definition | Public Disclosure |
|---|---|---|
| Critical | Confirmed code execution primitive, exploitable | Named after disclosure window |
| High | Strong malicious indicators, multiple signals | Named after disclosure window |
| Medium | Suspicious patterns, warrants investigation | Aggregate stats only |
| Low | Anomalies, likely explainable | Aggregate stats only |
| Informational | Format observations, no security impact | Internal only |

## Coverage Tiers

| Tier | Formats | Depth |
|---|---|---|
| 1 | PyTorch pickle, TensorFlow SavedModel | Deep analysis |
| 2 | Keras | Rigorous inspection |
| 3 | ONNX, GGUF, safetensors | Light coverage |
