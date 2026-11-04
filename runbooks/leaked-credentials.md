# Runbook: Leaked or compromised AWS credentials

## Symptoms
- GuardDuty findings such as `UnauthorizedAccess:IAMUser/*`, `Discovery:S3/*`, `Recon:IAMUser/*`,
  `PenTest:IAMUser/*` or `CredentialAccess:*` for an IAM user or access key.
- CloudTrail calls from an IP outside our NAT gateways / VPN, often starting with `GetCallerIdentity`
  then `List*` / `Describe*` (reconnaissance) and IAM changes (`CreateUser`, `AttachUserPolicy`, `CreateAccessKey`).
- A secret-scanning alert (GitHub, GitGuardian) for an `AKIA…` key.

## Treat as a security incident
- Page the security on-call. Keep a timeline. **Do not delete evidence** (logs, findings, the commit).
- Assume the key is compromised from the moment it was first exposed, not from the first alert.

## Investigate (read-only)
1. Identify the key and principal from the finding: `AccessKeyId`, `UserName`.
2. Find where the key was exposed: secret-scanning alert, `git log -S <key-id>`, ConfigMaps/env vars.
3. CloudTrail: every event for that `accessKeyId` since exposure. Separate:
   - **Expected** calls (our source IPs, normal workload pattern)
   - **Attacker** calls (unknown IPs, unusual user agents, recon, IAM changes)
4. For each attacker call, record whether it **succeeded** or was **denied** (`errorCode`).
5. Work out **impact**: data read (`GetObject`), data changed, persistence attempts (new users, keys, policies).
6. Check the principal's attached policies to confirm what the attacker *could* have done.

## Contain  ⚠️ human applies (security on-call approves)
1. **Deactivate** the access key first (reversible): `aws iam update-access-key --status Inactive …`.
2. If IAM changes **succeeded**: remove attacker-created users, keys and policies.
3. Block the attacker IP at the edge if useful (it will change; this is not a fix).

## Eradicate and recover  ⚠️ human applies, via Git
1. Remove the secret from the repo **and its history** (e.g. `git filter-repo`), and ask GitHub to
   purge caches/forks where possible. Rotating the key matters more than scrubbing history.
2. Replace static keys with **IAM Roles for Service Accounts (IRSA)** or AWS Secrets Manager.
   Never put credentials in a ConfigMap (ConfigMaps are not secret).
3. Scope the role to least privilege (e.g. `s3:PutObject` on one bucket prefix only).
4. Delete the old key once the workload runs on the new identity.

## Notify
- If personal or customer data was accessed, involve the DPO: **UK GDPR breach notification is 72 hours**.

## Prevent
- Pre-commit and CI secret scanning; block merges with secrets.
- SCP / permission boundary preventing IAM user access keys for workloads.
- Alert on any IAM write from a non-allow-listed IP.

## Verify
- Key shows `Inactive`/deleted; no further CloudTrail events for that key ID.
- Workload succeeds with the new role; GuardDuty findings archived with notes.
