# Comparison Matrix

How HFAudit compares to existing tools in the ML model security space. Updated honestly — if another tool catches something we don't, it's documented here.

| Capability | HFAudit | ModelScan | Picklescan | Fickling |
|---|---|---|---|---|
| **Pickle analysis** | Planned — opcode-level static analysis via fickling + custom walker | Yes — signature-based | Yes — signature-based | Yes — deep pickle analysis |
| **SavedModel analysis** | Planned — graph traversal + op allowlist + PrintV2 chain detection | Yes — basic op check | No | No |
| **Keras Lambda detection** | Planned — Lambda layer + code object inspection | Yes — basic check | No | No |
| **ONNX analysis** | Planned — custom op domain detection | Yes — basic | No | No |
| **GGUF analysis** | Planned — metadata anomaly detection | No | No | No |
| **safetensors validation** | Planned — format guarantee verification | Yes | No | No |
| **Account reputation signals** | Planned — age, upload count, flagged history | No | No | No |
| **Typosquatting detection** | Planned — edit distance against top-1000 models | No | No | No |
| **Sandboxed dynamic analysis** | Planned — gVisor container with syscall tracing | No | No | No |
| **Continuous monitoring** | Planned — daily new-upload sweep | No | On upload (HF integration) | No |
| **Coordinated disclosure pipeline** | Planned — 90-day window with HuggingFace | No | No | No |
| **Public dashboard** | Planned | No | No | No |
| **Known bypass resistance** | Planned — PrintV2 chain (not in other tools) | Known bypasses exist | Known bypasses exist | N/A (library, not scanner) |

## Notes

- **ModelScan** is a production-grade scanner by ProtectAI. HFAudit treats it as a baseline to exceed, not a competitor.
- **Picklescan** is integrated into HuggingFace's upload pipeline. Has been bypassed historically.
- **Fickling** by Trail of Bits is an excellent pickle analysis library. HFAudit uses it as a dependency.
- This matrix will be updated as HFAudit capabilities move from "Planned" to "Implemented" and as other tools evolve.
