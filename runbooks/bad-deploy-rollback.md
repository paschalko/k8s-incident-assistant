# Runbook: Roll back a bad deploy (Argo CD / GitOps)

## Symptoms
- Errors, crashes or latency regressions that start within minutes of a release.

## Decide
Roll back first, debug later, if customer impact is ongoing and the fix is not a one-line config change.

## Steps  ⚠️ human applies
1. Identify the last good version: `argocd app history <app>` (read-only) or Git log of the app's values file.
2. Open a PR reverting the image tag/values change. Get one approval (SEV-1: approve after merge).
3. Merge; Argo CD syncs. Do **not** use `kubectl rollout undo` – Argo CD will re-sync the bad version.
4. Announce in #incidents with the PR link.

## Verify
- `kubectl rollout status deploy/<app> -n <ns>` (read-only) completes; error rate back under SLO for 15 min.
