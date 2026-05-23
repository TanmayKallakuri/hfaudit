---
id: HFA-YYYY-NNNN
severity: critical|high
model_id: org/model-name
rule_id: HFA-XXX-NNN
reported_date: YYYY-MM-DD
acknowledged_date: YYYY-MM-DD
fixed_date: YYYY-MM-DD
published_date: YYYY-MM-DD
---

# HFA-YYYY-NNNN: {Title}

## Summary

Brief description of the finding, what was detected, and the impact.

## Technical Analysis

Detailed breakdown of the malicious payload:
- Format and file analyzed
- Detection method (which stage, which rule)
- Payload behavior (what it does when the model is loaded)
- Code or opcode excerpts (sanitized as needed)

## Evidence

- Static analysis output
- Sandbox traces (if Stage 3 was invoked)
- Reproduction steps

## Impact

Who is affected and under what conditions. Scope of potential harm.

## Disclosure Timeline

| Event | Date |
|-------|------|
| Finding detected | YYYY-MM-DD |
| Internal validation complete | YYYY-MM-DD |
| Vendor notified | YYYY-MM-DD |
| Vendor acknowledged | YYYY-MM-DD |
| Fix confirmed | YYYY-MM-DD |
| Public disclosure | YYYY-MM-DD |

## Mitigations

What was done to address the finding. Actions taken by HuggingFace.

## Credits

- Detected by HFAudit automated scanning
- Coordinated disclosure with HuggingFace Security Team
