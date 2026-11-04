# Runbook: OOMKilled (exit code 137)

## Symptoms
- `Last State: Terminated, Reason: OOMKilled, Exit Code: 137`
- Node events `OOMKilling ... Memory cgroup out of memory`
- Memory graph climbs then drops to zero at restart.

## Diagnose (read-only)
1. Confirm limit: `kubectl get deploy <app> -n <ns> -o jsonpath='{.spec.template.spec.containers[*].resources}'`
2. Usage trend: `kubectl top pod -n <ns> -l app=<app>` and the Grafana "Container memory working set" panel.
3. Decide which case applies:
   - **A. Leak / unbounded growth** – memory grows steadily without plateau → code or config issue.
   - **B. Limit too low for normal load** – memory plateaus just above the limit.
   - **C. New feature increased baseline** – started right after a release (cache, buffers, batch size).
4. For case C, find the config that sizes the feature (e.g. cache size env vars) in the release notes.

## Remediate  ⚠️ all changes go through Git (Argo CD will revert manual edits)
- **Immediate mitigation** (pick one):
  - Roll back to the last good version (`bad-deploy-rollback.md`) – preferred if customer impact is high.
  - Reduce the feature's sizing config (e.g. lower cache size) in the Helm values / manifest.
- **Permanent fix:**
  - Size limits from measured usage: limit ≈ p99 working set × 1.3. Requests ≈ p50.
  - For Go services set `GOMEMLIMIT` to ~90% of the container limit so GC works before the kernel OOM-kills.
  - Add an alert on `container_memory_working_set_bytes / limit > 0.9`.
- Do **not** simply remove the memory limit.

## Rollback
Revert the Git commit; Argo CD syncs the previous manifest.

## Verify
- `kubectl get pods -n <ns> -l app=<app>` → Running, restarts stop increasing for 15 min.
- Memory working set plateaus below 80% of limit.
