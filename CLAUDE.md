# HFAudit

**An automated security observatory for the HuggingFace model repository.**

HFAudit continuously monitors HuggingFace for malicious payloads embedded in machine learning model files, performs multi-stage static and behavioral analysis, and operates a coordinated vulnerability disclosure pipeline with the HuggingFace security team. Findings are published as a research archive after disclosure windows close.

This is a security research project, not a commercial scanner. Tone, code quality, and operational discipline are pitched at the level of a professional offensive security team.

---

## Author and Context

**Project lead:** Tanmay Kallakuri
**Background:** 4+ years cybersecurity (penetration testing, vulnerability management, application security); previously disclosed a HIGH severity SavedModel scanner bypass to ProtectAI (ModelScan GitHub issue #342, PrintV2 op chain).
**Sibling project:** CRX Audit (browser extension security auditor) — same authorial conventions and platform pattern apply here.

This file is the persistent context for Claude Code. Read it at the start of every session. When in doubt, prefer the decision recorded here over inference.

---

## Threat Model

Before any code is written, the threat model is the source of truth for what the tool must catch.

### Primary attack vectors in scope

1. **Pickle deserialization RCE.** PyTorch (`.pt`, `.pth`, `.bin`, `.ckpt`) and any other format that uses Python pickle. This is where the overwhelming majority of in-the-wild malicious model activity occurs. The `__reduce__` method and pickle opcodes (`REDUCE`, `BUILD`, `INST`, `OBJ`, `STACK_GLOBAL`) can be abused to invoke arbitrary callables on `pickle.load`. Detection target: opcode-level static analysis without executing the pickle stream.

2. **TensorFlow SavedModel op abuse.** Malicious or unexpected ops embedded in the graph (e.g., `ReadFile`, `WriteFile`, `MatchingFiles`, `PrintV2`, and the op chains used in the project lead's prior ProtectAI disclosure). Detection target: graph traversal with an op allowlist and known-bypass-chain heuristics.

3. **Keras Lambda layer code execution.** Keras `.h5` and `.keras` files can contain Lambda layers with serialized Python bytecode that executes on model load. Detection target: identify Lambda layers and decompile/inspect their code objects.

4. **Typosquatting and supply chain attacks.** Models named to impersonate popular releases (`Llama-3-8B-instruct` with a homoglyph, `bert-base-uncased-v2` from an unknown account, etc.). Detection target: name similarity scoring against a known-good model corpus + account reputation signals.

5. **Custom ops and obfuscation.** ONNX custom operators, GGUF metadata abuse, marshal/dill-nested pickles, getattr chains designed to evade signature scanners.

### Explicitly out of scope (for v1)

- Adversarial weights / backdoor triggers in safetensors (this is a real threat but the detection problem is research-grade and not solvable with static analysis alone — track as future work)
- Training data poisoning
- Inference-time prompt injection in LLMs
- Models hosted outside HuggingFace

### Adversary model

Assume the adversary is technically sophisticated, has read the public methodology and detection ruleset (which is intentional — security through obscurity is not a goal), and is actively attempting to bypass detection. Every detection rule must be written with the assumption that an attacker will try to evade it. Document known bypass classes in `/rules/known-bypasses.md` as they are discovered.

---

## Differentiation

Existing tools in the space and where HFAudit differs:

- **ProtectAI ModelScan** — production scanner with known bypass classes (the project lead disclosed one). HFAudit treats ModelScan as a baseline to exceed, not a competitor to displace. Maintain a public comparison matrix.
- **HuggingFace Picklescan integration** — runs on uploads; has been bypassed historically. HFAudit complements this by adding behavioral signals, account reputation, and post-upload monitoring.
- **Trail of Bits Fickling** — excellent pickle analysis library. HFAudit uses it as a dependency where appropriate; the value-add is the observatory, disclosure pipeline, and multi-format coverage.
- **JFrog research** — point-in-time research publications. HFAudit is continuous.

The unfair advantage is the project lead's prior bypass research (SavedModel op chains). That detection signature should be present in HFAudit on day one and is not present in any other public tool.

A `COMPARISON.md` file in the repo root will maintain an honest matrix of what HFAudit catches vs. existing tools, updated as the project evolves.

---

## Architecture

Monorepo, three primary components, designed to run cheaply and stay alive without daily babysitting.

```
hfaudit/
├── scanner/                 # Python CLI + library (the engine)
│   ├── hfaudit/
│   │   ├── __init__.py
│   │   ├── cli.py           # entry point: `hfaudit scan <model_id>`
│   │   ├── fetchers/        # HuggingFace API + file streaming
│   │   ├── parsers/         # per-format parsers (pickle, savedmodel, keras, onnx, gguf, safetensors)
│   │   ├── detectors/       # detection rules organized by category
│   │   ├── triage/          # severity scoring + heuristics
│   │   ├── sandbox/         # dynamic analysis (gVisor/Firecracker wrappers)
│   │   ├── reporting/       # finding objects, JSON/SARIF output
│   │   └── disclosure/      # disclosure ID tracking, redaction
│   ├── rules/               # YAML detection rules (public, contributable)
│   ├── tests/               # unit + integration + malicious-corpus tests
│   └── pyproject.toml
├── web/                     # Next.js dashboard (the public face)
│   ├── app/
│   │   ├── page.tsx                    # overview + live stats
│   │   ├── methodology/page.tsx        # detection methodology
│   │   ├── findings/[id]/page.tsx      # individual disclosed findings
│   │   ├── rules/page.tsx              # public detection ruleset browser
│   │   └── disclosure/page.tsx         # disclosure policy + contact
│   ├── lib/supabase.ts
│   └── package.json
├── findings/                # Markdown writeups of disclosed findings
│   └── 2026/
│       └── HFA-2026-0001.md
├── rules/                   # YAML detection ruleset (mirrored from scanner/rules)
├── infra/                   # Supabase schema, edge functions, cron config
│   ├── migrations/
│   ├── functions/
│   └── README.md
├── docs/                    # methodology, threat model, disclosure policy
├── COMPARISON.md
├── SECURITY.md
├── RESPONSIBLE_DISCLOSURE.md
├── CONTRIBUTING.md
├── LICENSE                  # Apache 2.0
└── CLAUDE.md                # this file
```

### Component responsibilities

**Scanner (Python).** Pure logic, no infrastructure dependencies. Must be runnable as `hfaudit scan <model_id>` on a developer laptop with `pip install hfaudit`. All HuggingFace interaction goes through the `fetchers` module. All format parsing goes through `parsers`. Detectors are pure functions that take a parsed model representation and emit `Finding` objects. The scanner is the open-source artifact that security researchers will actually use; treat its API as a public surface.

**Web dashboard (Next.js + Tailwind, on Vercel).** Read-only public surface. Pulls aggregate stats and closed findings from Supabase. No write paths exposed publicly. Mirrors the visual structure of CRX Audit for consistency with the project lead's portfolio.

**Backend (Supabase).** Postgres for findings storage, edge functions for scheduled scanning, Supabase auth for the (private) admin console. Schedule: daily new-upload sweep, weekly top-N refresh, on-demand triggered scans.

### Tech stack (locked unless explicitly revisited)

- Python 3.11+ for scanner. Type hints required. `ruff` for lint, `mypy --strict` for type checking, `pytest` for tests.
- Dependencies (scanner): `fickling`, `pickletools` (stdlib), `tensorflow` (for SavedModel parsing, optional extra), `h5py`, `onnx`, `huggingface_hub`, `pydantic`, `click`, `rich`.
- TypeScript 5+ for web. `next@14+` app router. Tailwind. `shadcn/ui` components. `supabase-js`.
- Supabase Postgres + Edge Functions (Deno). Cron via Supabase scheduled functions.
- Hosting: Vercel (web), Supabase (backend), GitHub Actions (CI + scanner workers if needed).
- Sandbox: gVisor-based containers in v1 (cheap, sufficient for syscall-level isolation). Firecracker can be considered later if memory analysis is added.

---

## Detection Methodology

The detection pipeline runs in three stages. Every model passes through Stage 1; only Stage 1 hits proceed to Stage 2; only Stage 2 hits proceed to Stage 3.

### Stage 1 — Static analysis (fast, deterministic, defendable)

Per-format detectors emit `RuleHit` objects when patterns match. Rules live in YAML under `scanner/rules/` and are loaded at runtime. Every rule must include:

- `id` (e.g., `HFA-PKL-001`)
- `severity` (one of: critical, high, medium, low, informational)
- `category` (e.g., `pickle.reduce.os_system`)
- `description`
- `references` (CVEs, blog posts, prior disclosures)
- `false_positive_notes`
- `bypass_notes` (known ways an attacker might evade this rule)

Initial rule catalog (must exist in v1):

- **Pickle:** dangerous reduce callables (`os.system`, `subprocess.Popen`, `eval`, `exec`, `compile`, `__import__`, `posix.system`, `nt.system`), suspicious imports (`socket`, `requests`, `urllib`, `ctypes`, `pty`, `paramiko`), filesystem write primitives, network indicators (IP literals, base64-encoded URLs), obfuscation signals (deep getattr chains, marshal/dill nesting).
- **SavedModel:** op allowlist violations, `ReadFile`/`WriteFile`/`MatchingFiles` ops, PrintV2 chain variants (the project lead's prior bypass research), unexpected `tf.py_function`/`tf.numpy_function` usage.
- **Keras:** presence of Lambda layers, deserialized code object inspection.
- **ONNX:** custom operator domains outside the standard ai.onnx namespace.
- **GGUF:** metadata size anomalies, unexpected key patterns.
- **Cross-format:** typosquatting against a curated list of the top 1,000 model names.

### Stage 2 — Heuristic and reputation signals (probabilistic, fast)

Inputs:
- Account age, upload count, download velocity
- Model lineage (fork-of, base model, license)
- Upload metadata anomalies (timing, README quality, missing license)
- Cross-reference with prior-flagged accounts

Stage 2 does not condemn a model on its own. It adjusts the priority queue for Stage 3 and contributes to overall severity scoring.

### Stage 3 — Sandboxed dynamic analysis (slow, expensive, last resort)

Only triggered by Stage 1 Critical/High hits or strong Stage 2 corroboration. Load the model in a gVisor-isolated container with:
- No network egress (DNS sinkholed)
- Read-only filesystem except for a tmpfs workdir
- Resource caps (CPU, memory, wall clock)
- Syscall tracing via `strace` or `ptrace`-based wrapper

Observed behaviors that constitute confirmed malicious activity:
- Any `execve` / `clone` invoking external binaries
- Any network connect attempts
- Any writes outside the tmpfs workdir
- Any DNS queries

Stage 3 results are recorded with full traces and are the gold-standard evidence for disclosure.

### Severity rubric

| Severity | Definition | Public naming policy |
|---|---|---|
| Critical | Confirmed code execution primitive present and exploitable | Named after disclosure window closes |
| High | Strong indicators of malicious intent, multiple corroborating signals | Named after disclosure window closes |
| Medium | Suspicious patterns warranting investigation | Aggregate stats only |
| Low | Anomalies worth tracking but explainable | Aggregate stats only |
| Informational | Format observations, no security implication | Internal only |

---

## Coverage Tiers (Scope of Formats)

| Tier | Formats | Coverage depth | Rationale |
|---|---|---|---|
| 1 | PyTorch `.pt`, `.pth`, `.bin`, `.ckpt` | Deep — opcode-level pickle analysis | Highest in-the-wild threat surface |
| 1 | TensorFlow SavedModel (`.pb` + variants) | Deep — graph traversal, op analysis | Project lead's existing research edge |
| 2 | Keras `.h5`, `.keras` | Rigorous — Lambda layer inspection | Known code execution vector |
| 3 | ONNX, GGUF | Light — custom op detection, metadata anomalies | Lower threat realism, table stakes coverage |
| 3 | safetensors | Light — verify format guarantees hold | Theoretically safe; scanned for completeness |

When a new format gains adoption or a new attack class emerges, it gets added to the tier table with a justification commit message.

---

## Scanning Strategy

Three layers running concurrently.

### Layer 1 — Continuous high-value monitoring (daily heartbeat)

Watch new uploads via HuggingFace API, filter to high-signal candidates:
- Pickle-based formats
- New accounts (age < 30 days) uploading large models
- Names within edit distance 2 of top-1000 model names (typosquatting candidates)
- Uploads with missing/suspicious metadata

Expected volume: 200-500 models/day. Tractable on a single worker.

### Layer 2 — Top-N baseline corpus (credibility builder)

One-time deep scan of the top 10,000 most-downloaded models. Publish as a foundational research artifact: *"State of HuggingFace Model Security: Top 10K Analysis"*. Refresh quarterly with delta reporting.

### Layer 3 — Triggered deep-dive (responsive layer)

External signal sources (Twitter/X security accounts, security advisories, vendor reports) feed a watchlist. Layer 3 jobs run on-demand and may invoke Stage 3 sandboxed analysis.

### Bandwidth discipline

Never download full model weights when header analysis suffices. Pickle scanning typically needs only the first 100KB-1MB of the file. Use HTTP range requests against the HuggingFace LFS endpoints where possible. Full-weight download is reserved for Stage 3 dynamic analysis and is gated behind explicit cost-aware logic.

---

## Disclosure Policy

This is load-bearing. Bad disclosure burns the project; good disclosure builds career-defining credibility.

### Workflow

1. **Detection.** Stage 1/2/3 produces a finding with severity Critical or High.
2. **Internal validation.** Two independent reproductions required before disclosure. Logged with timestamps and analyst notes.
3. **Disclosure ID assignment.** Format: `HFA-YYYY-NNNN` (e.g., `HFA-2026-0001`). Tracked in `disclosure/ledger.json` (private).
4. **Vendor notification.** Email to `security@huggingface.co` with:
   - Disclosure ID
   - Model identifier and uploader
   - Technical analysis (the writeup that will eventually be published)
   - Suggested mitigations
   - Disclosure timeline (default 90 days)
5. **Acknowledgment window.** 7 days. If no response, escalate via secondary channel.
6. **Coordination period.** Default 90 days; extensible by mutual agreement. During this window:
   - No public mention of the specific model or uploader
   - Aggregate stats may be published ("N High-severity findings under coordinated disclosure")
   - Methodology and rules may be discussed publicly
7. **Publication.** After window closes (or fix is confirmed earlier), publish the full writeup at `findings/YYYY/HFA-YYYY-NNNN.md` and the dashboard.

### Hard rules

- No public naming before disclosure closes. Ever.
- No screenshots of malicious payloads on social media before publication.
- Credit HuggingFace security team in every published writeup.
- If HuggingFace requests a specific change to a writeup before publication and it doesn't compromise technical accuracy, honor it.
- All published findings include a disclosure timeline (when found, when reported, when acknowledged, when fixed, when published).

### Templates

`docs/disclosure/notification-template.md` and `findings/_template.md` must exist in v1.

---

## Operational Conventions

### Code style

- Python: `ruff` (default config + line length 100), `mypy --strict`, no `Any` without justification comment.
- TypeScript: `eslint` + `prettier`, strict mode on.
- Commit messages: Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `chore:`, `security:`).
- Branch names: `feat/<short-description>`, `fix/<short-description>`, `disclosure/HFA-YYYY-NNNN` for disclosure-related branches.

### Testing

- Every detector must have unit tests against both true-positive and known-good samples.
- A `tests/corpus/` directory holds intentionally malicious test samples (clearly labeled, contained, never executed outside sandboxed test runners). Do not commit these to the public repo; reference a private submodule or external URL.
- Integration tests run the full pipeline against the test corpus.
- Coverage target: 80%+ on detector modules, 60%+ overall.

### Logging and observability

- Structured logging (JSON) in scanner; human-readable in CLI mode.
- Every Finding object includes provenance (which rule fired, what evidence, what confidence).
- Supabase logs preserved for 90 days.

### Secrets handling

- No secrets in the repo, ever. `.env.example` files only.
- HuggingFace API tokens, Supabase service keys, sandbox API credentials go in environment variables or a secrets manager.
- Pre-commit hook with `gitleaks` or equivalent.

### Ethics and legal posture

- Respect HuggingFace rate limits and Terms of Service.
- Do not download full weights unnecessarily (bandwidth ethics + ToS).
- All sandbox execution happens in isolated infrastructure under the project lead's control. Never on shared infrastructure.
- If a finding implicates a real person beyond the model upload itself (e.g., evidence of broader campaign), that goes to HuggingFace and stops there — HFAudit does not do attribution research publicly.

---

## Current Focus

> **Update this section at the end of every working session. Claude Code reads this first to know what to work on next.**

**Current phase:** Phase 5 — Polish and deployment (complete).

**Completed:**
- [x] Phase 0: Repository scaffold, Python package, Next.js dashboard, Supabase schema, CI pipeline
- [x] Phase 1: HuggingFace fetcher with range-requests, pickle parser + 10 detection rules, SavedModel parser + 6 rules (including PrintV2 chain bypass), Keras parser + 5 Lambda layer rules, CLI wired end-to-end with JSON/SARIF output
- [x] Phase 2: Typosquatting detection (Levenshtein + homoglyph), account reputation signals, severity scoring engine (upgrade-only), Supabase persistence layer
- [x] Phase 3: gVisor sandbox runner, strace syscall tracing, malicious behavior detection (4 categories), Stage 3 trigger logic, per-format loader scripts, 318 tests passing
- [x] Phase 4: Observatory dashboard — lazy Supabase client, data-fetching layer (queries.ts), custom components (SeverityBadge, StatsGrid, FindingCard, RuleCard), home page with live stats, findings archive + detail pages, rules browser with category grouping, URL protocol validation on references, bounded evidence display
- [x] Phase 5: README (human-facing, security-researcher-oriented), COMPARISON.md updated from "Planned" to implemented status, deployment configs verified (.gitignore, .env.example, infra README)

**Next action:** Deployment — create Supabase project, set env vars, deploy to Vercel, run first scan against a real model, smoke test the live dashboard. Then seed scanner/rules into the rules table and run initial scans to populate scan_stats.

**Recent decisions logged:**
- License: Apache 2.0
- PyPI package name: `hfaudit`
- Severity rubric finalized (Critical/High/Medium/Low/Informational; only Critical/High named publicly post-disclosure)
- Disclosure window: 90 days default
- Sandbox: gVisor for v1, Firecracker reserved for future
- Supabase client: lazy singleton factory (returns null when env vars missing, build succeeds without Supabase)
- Finding detail 404: uses Next.js notFound() for proper HTTP status
- Evidence display: max-h-96 overflow-auto to prevent layout blowout from large attacker-controlled content
- Reference links: protocol-validated (https/http only) to prevent javascript: URI injection

---

## Working With Claude Code on This Project

Conventions for Claude Code sessions:

1. **Read this file first.** Treat decisions recorded here as authoritative.
2. **When uncertain, propose before building.** This project has security and legal implications. A bad detection rule is worse than no rule.
3. **Every detection rule needs adversarial review.** Before committing a rule, write the bypass: "If I were attacking this, how would I evade it?" That goes in `bypass_notes`.
4. **No false confidence.** If a detector might false-positive on legitimate models, say so in the rule's `false_positive_notes`. Severity assignments must be defensible.
5. **No public claims without evidence.** The dashboard, README, and blog posts must not claim findings that aren't backed by reproducible scans logged in Supabase.
6. **Disclosure-sensitive content stays out of public commits.** Specific malicious model identifiers under active disclosure go in `disclosure/ledger.json` which is `.gitignore`d. Public findings are only those past their disclosure window.
7. **Update `Current Focus` at the end of every session.** This is how state survives between Claude Code invocations.
8. **Maintain the comparison matrix honestly.** If ModelScan catches something HFAudit doesn't, that goes in `COMPARISON.md` immediately.

---

## References and Prior Art

- ProtectAI ModelScan — https://github.com/protectai/modelscan
- Project lead's ModelScan disclosure — GitHub issue #342 (PrintV2 SavedModel bypass)
- Trail of Bits Fickling — https://github.com/trailofbits/fickling
- HuggingFace Picklescan integration — https://huggingface.co/docs/hub/security-pickle
- JFrog research on malicious models on HuggingFace (multiple posts, 2024)
- Wiz Research on AI/ML supply chain attacks
- pickletools (Python stdlib documentation)

Add to this list as new prior art is reviewed.
