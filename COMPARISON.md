# Comparison Matrix

How HFAudit compares to existing tools in the ML model security space. Updated honestly — if another tool catches something we don't, it's documented here.

| Capability | HFAudit | ModelScan | Picklescan | Fickling |
|---|---|---|---|---|
| **Pickle analysis** | Yes — opcode-level static analysis via fickling + custom walker (10 rules) | Yes — signature-based | Yes — signature-based | Yes — deep pickle analysis |
| **SavedModel analysis** | Yes — graph traversal + op allowlist + PrintV2 chain detection (6 rules) | Yes — basic op check | No | No |
| **Keras Lambda detection** | Yes — Lambda layer + code object inspection (5 rules) | Yes — basic check | No | No |
| **ONNX analysis** | Yes — custom op domain detection | Yes — basic | No | No |
| **GGUF analysis** | Yes — metadata anomaly detection | No | No | No |
| **safetensors validation** | Yes — format guarantee verification | Yes | No | No |
| **Account reputation signals** | Yes — age, upload count, flagged history, reputation scoring | No | No | No |
| **Typosquatting detection** | Yes — Levenshtein + homoglyph scoring against top model names | No | No | No |
| **Sandboxed dynamic analysis** | Yes — gVisor container with strace syscall tracing | No | No | No |
| **Continuous monitoring** | Yes — daily new-upload sweep via Supabase edge functions | No | On upload (HF integration) | No |
| **Coordinated disclosure pipeline** | Yes — 90-day window with HuggingFace security team | No | No | No |
| **Public dashboard** | Yes — Next.js observatory with live stats, findings archive, rules browser | No | No | No |
| **Known bypass resistance** | Yes — PrintV2 op chain detection (not in other tools), nested payload detection | Known bypasses exist | Known bypasses exist | N/A (library, not scanner) |

## What HFAudit does NOT do (yet)

- Adversarial weight/backdoor detection in safetensors (requires ML-based analysis, not static scanning)
- Training data poisoning detection
- Inference-time prompt injection analysis
- Models hosted outside HuggingFace

## Notes

- **ModelScan** is a production-grade scanner by ProtectAI. HFAudit treats it as a baseline to exceed, not a competitor.
- **Picklescan** is integrated into HuggingFace's upload pipeline. Has been bypassed historically.
- **Fickling** by Trail of Bits is an excellent pickle analysis library. HFAudit uses it as a dependency.
- This matrix is updated as capabilities change. If you find an inaccuracy, open an issue.
