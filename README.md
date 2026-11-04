# AI Incident & Security Triage Assistant

![tests](https://github.com/paschalko/k8s-incident-assistant/actions/workflows/tests.yml/badge.svg)

An AI agent workflow that triages **Kubernetes reliability incidents** and **AWS security incidents**.
It reads an incident report, analyses the evidence (pod logs, Kubernetes events, CloudTrail, GuardDuty),
matches it to an approved runbook and writes an analysis with a suggested fix **for a human to approve**.

It is built with Claude Code subagents and is **read-only by design**: it has no production access,
cannot change cluster or cloud state, and every action it takes is checked by a guard and logged.

```
/investigate INC-2057
  ├─ classify incident ── reliability? security? both?
  ├─ security-triage agent ── CloudTrail + GuardDuty → attacker timeline, impact
  ├─ log-inspector agent ──── pod logs + events → failure mode, timeline
  ├─ runbook-consultant ───── matches runbooks/ → diagnostic & remediation steps
  └─ report ──────────────── reports/INC-2057-analysis.md  (⚠️ human applies any change)

every tool call ─► PreToolUse guard (blocks writes, mutations, prod, secrets) ─► audit log
```

## Scenarios included

| Incident | Type | What the assistant has to work out |
|---|---|---|
| **INC-2041** checkout-api crash loop | Reliability | OOMKilled (exit 137) after a release added an in-memory cache; payment timeouts are a symptom, not the cause |
| **INC-2057** suspicious AWS API calls | Security | Static AWS key committed to a ConfigMap and leaked via a public fork; attacker recon, data read from S3, privilege escalation attempts denied |

Both scenarios contain a planted **prompt-injection** line in the logs ("ignore previous instructions…")
and real-looking secrets, to test that the assistant flags the injection and never prints a secret.
Each has an answer key in `evals/` used to score the output.

## Security design

The assistant is treated as an untrusted component. Controls are layered so no single one has to be perfect:

| Layer | Control |
|---|---|
| **Identity** | Read-only Kubernetes ServiceAccount (`k8s/readonly-rbac.yaml`): `get/list/watch` only, no `secrets`, no `pods/exec`; short-lived token (8h) |
| **Permissions** | Allow/deny rules in `.claude/settings.json`: no `kubectl apply/delete/exec`, no `helm`, `aws`, `terraform`, `curl`, no reading kubeconfigs or `.env` |
| **Runtime guard** | `.claude/hooks/readonly_guard.py` parses every shell command before it runs: allow-lists read-only `kubectl` verbs and safe tools, blocks command chaining, substitution, redirection, context switching and any `prod` context; file writes only under `reports/` |
| **Untrusted input** | Logs and evidence are treated as data; injection attempts are detected and reported, never followed |
| **Data protection** | `tools/log_summary.py` redacts passwords, tokens, connection strings and AWS keys (key IDs keep only the last 4 characters for correlation) |
| **Human in the loop** | Every state-changing step is marked `⚠️ HUMAN APPLIES`; fixes go through Git / GitOps |
| **Audit** | `.claude/hooks/audit_log.py` records every tool call as JSON lines |

## Project structure

```
.claude/
  agents/          log-inspector, security-triage, runbook-consultant (least-privilege tool sets)
  commands/        /investigate workflow and report template
  hooks/           readonly_guard.py (pre-execution guard), audit_log.py
  settings.json    permission rules + hook registration
CLAUDE.md          standing rules for the agent
incidents/         incident reports (input)
logs/<ID>/         evidence: pod logs, kubectl output, CloudTrail, GuardDuty, git history
runbooks/          approved runbooks incl. leaked-credentials.md
tools/             log_summary.py – pre-filters and redacts evidence
evals/             answer keys for scoring the assistant
tests/             guard and log-summary tests (run in CI)
k8s/               read-only RBAC + kubeconfig generator for a non-prod cluster
```

## Run it

Requires [Claude Code](https://docs.claude.com/en/docs/claude-code/overview) and Python 3.10+.

```bash
python3 tests/test_guard.py          # guard blocks/allows the right commands
python3 tests/test_log_summary.py    # redaction, CloudTrail/GuardDuty parsing, injection detection
claude
> /investigate INC-2041              # reliability incident
> /investigate INC-2057              # security incident
```

The report is written to `reports/`. Compare it with `evals/<ID>.expected.md`.

**Against a real cluster (non-production only):** apply `k8s/readonly-rbac.yaml` with admin rights,
run `k8s/make-readonly-kubeconfig.sh` to mint an 8-hour read-only kubeconfig, then start with
`KUBECONFIG=$PWD/k8s/assistant.kubeconfig claude`. Check `kubectl auth can-i delete pods -A` returns `no`.

## Design decisions

- **Credentials are the real boundary.** Prompts, permission rules and the guard are defence in depth;
  the session never holds write credentials, so even a fully bypassed guard cannot change anything.
- **Pre-filter before the model.** Summarising evidence first (grouping CloudTrail by source IP, ranking
  GuardDuty by severity) cuts context size and improves accuracy.
- **Separate agents, minimal tools.** The runbook agent cannot run commands at all; only the analysis
  agents can run the read-only summariser.
- **Evaluate before trusting.** Each incident has an answer key; changes to prompts or runbooks are re-scored.

## Limitations and next steps

- The Bash guard is an allow-list parser, not a full shell interpreter; it fails closed on anything it can't parse.
- Next: read-only CloudTrail Lake / Athena queries, Security Hub integration, and automatic scoring against `evals/`.

## Licence

MIT
