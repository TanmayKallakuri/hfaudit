# Contributing to HFAudit

Thank you for your interest in improving ML model security. This guide covers how to contribute to HFAudit.

## Contributing Detection Rules

Detection rules are the core of HFAudit. Rules live in `scanner/rules/` as YAML files.

### Required fields

Every rule must include:

```yaml
id: HFA-<FORMAT>-<NNN>       # e.g., HFA-PKL-001
severity: critical|high|medium|low|informational
category: <format>.<category>.<subcategory>
description: "What this rule detects"
references:
  - "URL to CVE, blog post, or prior disclosure"
false_positive_notes: "When this might fire on legitimate models"
bypass_notes: "How an attacker might evade this rule"
```

The `bypass_notes` field is mandatory. Before submitting a rule, ask: "If I were attacking this, how would I evade it?" That answer goes in `bypass_notes`.

### Testing requirements

Every detector must have:
- True-positive tests (the rule fires on a malicious sample)
- Known-good tests (the rule does NOT fire on legitimate models)

Tests go in `scanner/tests/`. Do not commit actual malicious model files to the repository.

## Code Style

### Python (scanner)

- Formatter/linter: `ruff` (line length 100)
- Type checker: `mypy --strict`
- No `Any` types without a justification comment
- All functions must have type hints

### TypeScript (web)

- Linter: `eslint`
- Formatter: `prettier`
- Strict mode enabled

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature or detection rule
- `fix:` Bug fix
- `refactor:` Code restructuring without behavior change
- `docs:` Documentation changes
- `chore:` Build, CI, dependency updates
- `security:` Security-related changes

## Branch Naming

- `feat/<short-description>` — new features
- `fix/<short-description>` — bug fixes
- `disclosure/HFA-YYYY-NNNN` — disclosure-related branches (maintainers only)

## Handling Malicious Samples

- **Never commit malicious model files to the public repository.**
- Test samples referenced by tests should use synthetic/crafted minimal payloads that demonstrate the detection pattern without containing a real exploit.
- If you need to reference a real-world malicious sample, use a hash or HuggingFace model ID, not the file itself.

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Ensure `ruff check`, `mypy --strict`, and `pytest` all pass
5. Submit a pull request with a clear description

## Code of Conduct

Be professional. This is a security research project. Treat all contributors, vendors, and affected parties with respect.
