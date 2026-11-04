# Runbook: CrashLoopBackOff

## Symptoms
- Pod status `CrashLoopBackOff`; `Restart Count` increasing.
- Event: `Back-off restarting failed container`.

## Diagnose (read-only)
1. `kubectl get pods -n <ns> -l app=<app> -o wide`
2. `kubectl describe pod <pod> -n <ns>` – check **Last State → Reason and Exit Code**:
   | Exit code / reason | Meaning | Go to |
   |---|---|---|
   | 137 / `OOMKilled` | Killed for exceeding memory limit | `oomkilled.md` |
   | 137 without OOMKilled | Killed by liveness probe or SIGKILL | check probe events |
   | 1 / `Error` | App crashed (config, dependency, bug) | previous logs |
   | 143 | SIGTERM, graceful shutdown | probes / preemption |
3. `kubectl logs <pod> -n <ns> --previous` – read the last lines **before** termination.
4. Check whether a deploy/config change happened just before the first restart.

## Remediate
- Fix the cause identified above (follow the linked runbook).
- If a release caused it and the cause is not quickly fixable: see `bad-deploy-rollback.md`.

## Notes
- Downstream timeouts during crash loops are usually a **symptom** (cold/overloaded pods), not the cause.
