---
description: Investigate a Kubernetes incident (read-only) and write an analysis report
argument-hint: <incident-file-or-id>  e.g. INC-2041
---

Investigate the incident: **$ARGUMENTS**

Follow the workflow in CLAUDE.md, strictly read-only:

1. Locate the incident report in `incidents/` matching `$ARGUMENTS` and read it.
2. Decide if it is a **reliability** or **security** incident (or both), then analyse `logs/<INCIDENT-ID>/`
   with the **log-inspector** subagent (reliability) and/or the **security-triage** subagent (security).
3. Use the **runbook-consultant** subagent with the symptoms and the failure mode or attack pattern found.
4. Correlate both results yourself. Challenge the hypothesis: list at least one alternative cause
   and the evidence that rules it in or out.
5. Write `reports/<INCIDENT-ID>-analysis.md` using this template, then give me a 5-line summary.

```markdown
# <INCIDENT-ID> – Analysis (AI-generated, read-only, NOT applied)

**Service / namespace:** …   **Severity:** …   **Analysed:** <UTC time>

## Summary
2–3 sentences: what broke, why, what to do.

## Root cause hypothesis
(For security incidents: how the credential or system was exposed, and what the attacker did.)
- Hypothesis: …  (confidence: high/medium/low)
- Evidence: bullets citing file:line / timestamps
- Alternatives considered: … (why less likely)

## Timeline (UTC)
| time | event | source |

## Recommended fix  (⚠️ a human reviews and applies – preferably via a Git PR / GitOps)
1. Immediate mitigation: …
2. Permanent fix: …
Commands/manifests shown as code blocks, never executed.

## Impact (security incidents)
What was accessed or changed, what was attempted and denied, any persistence. Notification duties if personal data was involved.

## Rollback plan
## Verification (read-only checks to confirm recovery)
## Runbook used
`runbooks/…` + any gaps found
## Open questions / missing evidence
```
