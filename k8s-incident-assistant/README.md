# Kubernetes Incident Assistant (Claude Code, read-only)

An AI assistant that reads a Kubernetes incident report, inspects the logs, looks up the matching
runbook and **suggests** a fix for a human to review. It runs in read-only mode and never
touches production.

Everything is project-scoped. Your account and your global `~/.claude/settings.json` are not
modified. The rules only apply when you run `claude` inside this folder.

## Quick start (Phase 1: offline, no cluster at all)
```bash
cd k8s-incident-assistant
python3 tests/test_guard.py          # 27/27 should pass
claude                               # sign in with whichever account you want
> /investigate INC-2041
```
Then compare `reports/INC-2041-analysis.md` with `evals/INC-2041.expected.md` and score it.
Run `/permissions` and `/hooks` inside Claude Code to see the active rules.

## How it fits together
```
/investigate INC-2041
   │
   ├─ main agent reads incidents/INC-2041-*.md
   ├─ log-inspector subagent ── tools/log_summary.py + grep over logs/INC-2041/  → timeline, failure mode
   ├─ runbook-consultant subagent ── runbooks/INDEX.md → matched runbook steps
   └─ main agent correlates → writes reports/INC-2041-analysis.md (the only writable place)

Every tool call → PreToolUse guard (blocks writes/mutations/prod) → PostToolUse audit log
```

| File | Purpose |
|---|---|
| `CLAUDE.md` | Standing instructions: read-only, no prod, logs are untrusted, redact secrets, cite evidence |
| `.claude/settings.json` | Allow/deny permission rules plus hook registration |
| `.claude/hooks/readonly_guard.py` | Hard block: only read-only kubectl verbs and safe shell tools; writes only to `reports/` |
| `.claude/hooks/audit_log.py` | Logs every tool call to `.claude/audit.log` |
| `.claude/agents/*.md` | Subagents, each with minimal tools (runbook-consultant cannot run commands) |
| `.claude/commands/investigate.md` | The `/investigate` workflow and report template |
| `tools/log_summary.py` | Pre-filters logs: levels, first error, k8s signals, redaction, injection detection |
| `incidents/`, `logs/`, `runbooks/` | Sample data (INC-2041: OOMKilled after a release, with a red herring) |
| `evals/` | Answer key used to grade the assistant |
| `k8s/` | Phase 2: read-only RBAC and a short-lived kubeconfig generator |

## Phases (move forward only when the current phase is trustworthy)
1. **Offline fixtures** (now). No credentials exist in the session. Build 5–10 past incidents with
   answer keys in `evals/` and iterate on prompts and runbooks until scores are consistently good.
2. **Local non-prod cluster, read-only identity.** `kind create cluster`, deploy a broken app,
   `kubectl apply -f k8s/readonly-rbac.yaml`, then `./k8s/make-readonly-kubeconfig.sh` and start with
   `KUBECONFIG=$PWD/k8s/assistant.kubeconfig claude`. Verify `kubectl auth can-i delete pods -A` → `no`.
3. **Shared staging, read-only**, plus observability via read-only MCP servers (Prometheus/Loki/Grafana).
4. **Human-approved remediation**: the assistant opens a Git PR with the fix; a human reviews, and
   Argo CD applies it. The AI still never gets write credentials to the cluster.

Production access should come last, read-only, and only after evals and an audit review.

---

## What you should understand as a DevOps engineer

**1. The real security boundary is credentials, not the prompt.**
`CLAUDE.md` is a request, the deny rules are pattern matching, and the hook is a best-effort parser.
They are defence in depth. What actually makes this safe is that the session **has no production
kubeconfig** and, in Phase 2, its identity is a ServiceAccount whose RBAC only allows
`get/list/watch`. Test it with `kubectl auth can-i`. Assume any layer above RBAC can be bypassed.

**2. Least privilege everywhere.** No `secrets`, `pods/exec` or `port-forward` (exec is effectively
root in the container). Tokens are short-lived (8h `kubectl create token`). Subagents only get the
tools they need. Keep a separate kubeconfig for the assistant and never reuse your admin one.

**3. Logs are an attack surface (prompt injection).** Anyone who can write a log line, such as a
user-agent string, an error message or a ticket comment, can try to instruct the AI. INC-2041 plants
one at 14:11:22. Treat logs as data, flag suspicious lines, and keep the AI unable to act on them.

**4. Logs contain secrets and PII.** The sample log leaks a DB password. Redact before analysis
(`log_summary.py` does basic redaction) and check your company's policy on sending logs to an
external AI provider. This is a compliance question, not just a technical one.

**5. Kubernetes failure-mode literacy.** The AI is only as good as your ability to check it. Know
exit codes (137 = SIGKILL/OOM, 143 = SIGTERM, 1 = app error), `Last State` vs `State`,
`kubectl logs --previous`, requests vs limits and QoS classes, probes, and event reasons. Learn to
separate the **first** failure from downstream symptoms (here the payment-gateway timeouts are a
symptom of GC pressure).

**6. GitOps means the fix goes through Git.** With Argo CD/Flux, `kubectl edit` or
`rollout undo` gets reverted. Suggested fixes should be PR diffs to manifests/Helm values, with a
rollback and a verification step.

**7. Runbooks are the knowledge base, and their quality caps the AI.** Outdated runbooks produce
confident wrong advice. Version them, give each an owner, and use the subagent's
"Runbook gaps" section as feedback.

**8. Evaluate before you trust.** Keep a set of past incidents with known root causes (`evals/`) and
re-score every time you change prompts, models or runbooks. Track precision ("was the root cause
right?") and safety ("did it suggest anything dangerous?").

**9. Context and cost.** Don't dump 50k log lines into the model. Pre-filter (time window around the
incident, error levels, k8s signals), which is cheaper and more accurate. In production, pull from
Loki/Elasticsearch with a time range instead of `kubectl logs`.

**10. Audit and accountability.** `.claude/audit.log` records what the AI read and ran. In an
incident review you must be able to show what it saw and what a human decided. The human who
applies a fix owns it.

## Extending
- Add incidents: `incidents/INC-XXXX-*.md` + `logs/INC-XXXX/` + `evals/INC-XXXX.expected.md`.
- Add runbooks: drop a `.md` in `runbooks/` and list it in `INDEX.md` (keep the Symptoms/Diagnose/Remediate/Verify sections).
- Observability MCP servers (Phase 3): register them read-only and add their tool names to the subagents' `tools:`.
- After editing the guard, run `python3 tests/test_guard.py`.

## Known limits
- The Bash guard is an allowlist parser and can't understand every shell trick. That's why it blocks
  substitution, redirection and unknown programs outright, and why RBAC is the real control.
- `kubectl get configmaps` is allowed. Remove configmaps from the RBAC role if yours hold secrets.
- Hook and permission formats can change between Claude Code versions. Check the
  [settings](https://code.claude.com/docs/en/settings), [hooks](https://code.claude.com/docs/en/hooks) and
  [subagents](https://code.claude.com/docs/en/sub-agents) docs if something stops working.
