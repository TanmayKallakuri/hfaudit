# Vendor Notification Template

**Subject:** [HFAudit] Coordinated Disclosure — {DISCLOSURE_ID}: Malicious payload in {MODEL_ID}

---

**Disclosure ID:** {DISCLOSURE_ID}

**Date:** {DATE}

**To:** HuggingFace Security Team (security@huggingface.co)

**From:** Tanmay Kallakuri, HFAudit Project Lead

---

## Summary

HFAudit has identified a malicious payload in the following model:

- **Model:** {MODEL_ID}
- **Uploader:** {UPLOADER}
- **File:** {FILE_PATH}
- **Severity:** {SEVERITY}
- **Category:** {CATEGORY}

## Technical Analysis

{TECHNICAL_ANALYSIS}

## Evidence

{EVIDENCE}

## Suggested Mitigations

- Remove or quarantine the model
- Flag the uploader account for review
- {ADDITIONAL_MITIGATIONS}

## Disclosure Timeline

- **Default coordination window:** 90 days from this notification
- **Proposed public disclosure date:** {DISCLOSURE_DATE}
- Extensions are available by mutual agreement

## Contact

- **Email:** disclosure@hfaudit.dev
- **Project:** https://github.com/TanmayKallakuri/hfaudit

We look forward to coordinating on this finding. Please acknowledge receipt within 7 days.
