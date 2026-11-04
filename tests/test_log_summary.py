#!/usr/bin/env python3
"""Run: python3 tests/test_log_summary.py   – checks redaction and security detection in tools/log_summary.py."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import log_summary as ls  # noqa: E402


def summary(path):
    return subprocess.run([sys.executable, os.path.join(ROOT, "tools", "log_summary.py"), os.path.join(ROOT, path)],
                          capture_output=True, text=True, encoding="utf-8", check=True).stdout


checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


# Redaction
check("AWS key ID keeps only last 4 chars", ls.redact("key=AKIAIOSFODNN7EXAMPLE") == "key=AKIA…MPLE")
check("AWS secret key is hidden",
      "wJalr" not in ls.redact("AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
check("DB password in URL is hidden",
      "S3cr3t" not in ls.redact("url=postgres://checkout:S3cr3tP@ss@pg:5432/db"))
check("password= is hidden", "hunter2" not in ls.redact("password=hunter2"))

# No full secrets anywhere in any summary
all_out = "".join(summary(os.path.join("logs", d, f))
                  for d in ("INC-2041", "INC-2057") for f in os.listdir(os.path.join(ROOT, "logs", d)))
check("no full AWS key ID in any summary", "AKIAIOSFODNN7EXAMPLE" not in all_out)
check("no AWS secret key in any summary", "wJalrXUtnFEMI" not in all_out)
check("no DB password in any summary", "S3cr3tP@ss" not in all_out)

# CloudTrail: attacker separated from legitimate use, denials surfaced
ct = summary("logs/INC-2057/cloudtrail-events.jsonl")
check("CloudTrail grouped by attacker IP", "### 203.0.113.77" in ct)
check("CloudTrail shows legitimate IP separately", "### 34.240.18.9" in ct)
check("CloudTrail lists denied privilege escalation", "iam:AttachUserPolicy (AccessDenied)" in ct)

# GuardDuty: highest severity first
gd = summary("logs/INC-2057/guardduty-findings.json")
check("GuardDuty sorted by severity", gd.index("sev 8.0") < gd.index("sev 5.0"))

# Prompt injection flagged in both scenarios
check("injection flagged in INC-2041", "SUSPICIOUS" in summary("logs/INC-2041/checkout-api-7d9f8b6c5-x2k4p.previous.log"))
check("injection flagged in INC-2057", "SUSPICIOUS" in summary("logs/INC-2057/reports-worker.log"))

# Kubernetes signals still work
check("OOMKilled detected", "OOMKilled" in summary("logs/INC-2041/describe-pod-checkout-api-7d9f8b6c5-x2k4p.txt"))

failed = 0
for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    failed += not ok
print(f"\n{len(checks) - failed}/{len(checks)} passed")
sys.exit(1 if failed else 0)
