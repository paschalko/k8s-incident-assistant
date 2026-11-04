# INC-2057 – Suspicious AWS API activity from an unknown IP (possible leaked access key)

- **Severity:** SEV-1 (security)
- **Reported:** 2026-10-31 02:47 UTC by GuardDuty → Security Hub → PagerDuty
- **Account / region:** `shop-staging` (`111122223333`) / `eu-west-1` *(fixture data – no live account)*
- **Cluster / namespace:** `staging-eu-1` / `shop`
- **Related workload:** `reports-worker` (CronJob that uploads nightly sales reports to S3)

## Symptoms
- GuardDuty finding `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` and `Discovery:S3/AnomalousBehavior`
  for IAM user `svc-reports-uploader`.
- CloudTrail shows `ListBuckets`, `GetCallerIdentity` and repeated `GetObject` calls from IP `203.0.113.77`
  (not one of our NAT gateway IPs), plus a denied `CreateUser` attempt.
- GitHub secret scanning raised an alert on a public fork of `shop-infra` 6 hours earlier.

## Recent changes
- 2026-10-30 20:15 UTC – PR #482 "quick fix: reports-worker auth" merged to `shop-infra`; it added
  AWS credentials to a ConfigMap so the CronJob could reach S3.
- 2026-10-30 20:40 UTC – a contributor forked `shop-infra` to a **public** repository.

## Actions taken so far
- None. On-call requested an AI-assisted triage before acting. **Do not rotate or delete anything yet.**

## Attachments
- `logs/INC-2057/guardduty-findings.json`
- `logs/INC-2057/cloudtrail-events.jsonl`
- `logs/INC-2057/configmap-reports-worker.yaml` (`kubectl get configmap reports-worker -n shop -o yaml`)
- `logs/INC-2057/git-log-shop-infra.txt`
- `logs/INC-2057/reports-worker.log`
