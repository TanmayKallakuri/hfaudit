# Responsible Disclosure Policy

HFAudit operates a coordinated vulnerability disclosure pipeline for malicious machine learning models discovered on HuggingFace. This document describes that process.

## Disclosure Workflow

### 1. Detection

HFAudit's multi-stage analysis pipeline identifies a model with severity **Critical** or **High**.

### 2. Internal Validation

Two independent reproductions are required before any disclosure. Each reproduction is logged with timestamps and analyst notes.

### 3. Disclosure ID Assignment

Every validated finding receives an identifier in the format `HFA-YYYY-NNNN` (e.g., `HFA-2026-0001`). This ID is tracked internally and used in all correspondence.

### 4. Vendor Notification

An email is sent to **security@huggingface.co** containing:

- Disclosure ID
- Model identifier and uploader account
- Technical analysis (the writeup that will eventually be published)
- Suggested mitigations (removal, quarantine, warning label)
- Disclosure timeline (default: 90 days)

### 5. Acknowledgment Window

HuggingFace has **7 days** to acknowledge receipt. If no response is received, we escalate via a secondary contact channel.

### 6. Coordination Period

The default coordination period is **90 days**, extensible by mutual agreement. During this window:

- No public mention of the specific model or uploader
- Aggregate statistics may be published (e.g., "N High-severity findings under coordinated disclosure")
- Detection methodology and rules may be discussed publicly

### 7. Publication

After the coordination window closes (or the fix is confirmed earlier), the full writeup is published at `findings/YYYY/HFA-YYYY-NNNN.md` and on the HFAudit dashboard.

## Hard Rules

- **No public naming before disclosure closes.** No exceptions.
- **No screenshots of malicious payloads on social media** before publication.
- **Credit HuggingFace security team** in every published writeup.
- **Honor reasonable vendor requests** for writeup changes that do not compromise technical accuracy.
- **Every published finding includes a disclosure timeline:** when found, when reported, when acknowledged, when fixed, when published.

## Disclosure Timeline Template

| Event | Date |
|-------|------|
| Finding detected | YYYY-MM-DD |
| Internal validation complete | YYYY-MM-DD |
| Vendor notified | YYYY-MM-DD |
| Vendor acknowledged | YYYY-MM-DD |
| Fix confirmed | YYYY-MM-DD |
| Public disclosure | YYYY-MM-DD |

## Reporting a Malicious Model

If you have independently discovered a malicious model on HuggingFace and would like HFAudit to assist with coordinated disclosure, contact us at **disclosure@hfaudit.dev** with:

- The model identifier (org/model-name)
- A brief description of the malicious behavior
- Any evidence you have collected

We will validate independently and, if confirmed, fold it into our disclosure pipeline with appropriate credit.
