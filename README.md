# HFAudit

Find malicious code hiding in HuggingFace model files before it executes on your machine.

PyTorch models use pickle, which runs arbitrary Python on load. SavedModel graphs can embed file I/O ops. Keras Lambda layers contain serialized bytecode. If you download and load a model without inspecting it first, you're trusting that nobody put a reverse shell in the weights file.

HFAudit scans model files at the opcode and graph level, flags account-level deception like typosquatting, and optionally loads suspicious models in a sandboxed container to watch what they actually do.

## Install

```
pip install hfaudit
```

## Scan a model

```
hfaudit scan meta-llama/Llama-3-8B
```

Output is JSON by default. SARIF is also supported:

```
hfaudit scan meta-llama/Llama-3-8B --format sarif
```

## What it catches

HFAudit runs three analysis stages. Every model goes through Stage 1. Only flagged models advance.

**Stage 1 -- Static analysis.** Opcode-level pickle inspection (dangerous `__reduce__` callables, suspicious imports, obfuscation via getattr chains or marshal/dill nesting). SavedModel graph traversal against an op allowlist (including the PrintV2 op chain bypass disclosed by this project's author to ProtectAI, which no other public scanner detects). Keras Lambda layer decompilation. ONNX custom op detection. 17 detection rules defined in YAML, each with documented bypass techniques.

**Stage 2 -- Heuristic signals.** Account age and upload patterns. Typosquatting detection using Levenshtein distance and homoglyph matching against the top 1,000 model names. Upload metadata anomalies.

**Stage 3 -- Sandboxed dynamic analysis.** Models flagged Critical or High get loaded inside a gVisor container with no network, a read-only filesystem, resource caps, and strace syscall tracing. Any `execve`, network connect, or filesystem write outside tmpfs is flagged as confirmed malicious behavior.

## Format coverage

| Tier | Formats | Depth |
|------|---------|-------|
| 1 (Deep) | PyTorch `.pt` `.pth` `.bin` `.ckpt`, TensorFlow SavedModel `.pb` | Opcode/graph-level analysis |
| 2 (Rigorous) | Keras `.h5` `.keras` | Lambda layer inspection + decompilation |
| 3 (Light) | ONNX, GGUF, safetensors | Custom op detection, metadata checks, format verification |

## Why this exists

The author previously disclosed a HIGH severity SavedModel scanner bypass to ProtectAI (ModelScan issue #342) -- a PrintV2 op chain that evades existing scanners. That detection is built into HFAudit's rules from day one.

Existing tools cover parts of the problem:

- **Picklescan** (used by HuggingFace on upload) has been bypassed historically and doesn't cover SavedModel or Keras vectors.
- **ModelScan** is a production scanner with known bypass classes.
- **Fickling** is a strong pickle analysis library but doesn't cover other formats or provide monitoring.

HFAudit combines multi-format static analysis, behavioral signals, sandboxed execution, and continuous monitoring into a single tool. See COMPARISON.md for an honest feature matrix.

## Observatory dashboard

A public web dashboard shows live scan statistics, published findings (after disclosure windows close), and the full detection ruleset. All detection rules are public by design -- security through obscurity is not a goal.

## Disclosure policy

HFAudit operates a coordinated disclosure pipeline with HuggingFace's security team. Default 90-day window. No models or uploaders are named publicly until the window closes and fixes are confirmed. See RESPONSIBLE_DISCLOSURE.md for the full policy.

## Detection rules

All 17 rules live in `scanner/rules/` as YAML files. Each rule includes:

- Severity level and category
- Known false positive conditions
- Documented bypass techniques (how an attacker might evade the rule)
- References to prior research

See CONTRIBUTING.md to add new detection rules.

## Reporting vulnerabilities in HFAudit itself

See SECURITY.md.

## License

Apache 2.0
