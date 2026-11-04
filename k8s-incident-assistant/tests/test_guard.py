#!/usr/bin/env python3
"""Run: python3 tests/test_guard.py   – checks the read-only guard blocks/allows as expected."""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD = os.path.join(ROOT, ".claude", "hooks", "readonly_guard.py")

CASES = [
    # (tool, input, should_allow)
    ("Bash", {"command": "kubectl get pods -n shop"}, True),
    ("Bash", {"command": "kubectl describe pod checkout-api-x -n shop"}, True),
    ("Bash", {"command": "kubectl logs checkout-api-x -n shop --previous | tail -50"}, True),
    ("Bash", {"command": "kubectl auth can-i delete pods -A"}, True),
    ("Bash", {"command": "kubectl get pods --context kind-dev"}, True),
    ("Bash", {"command": "python3 tools/log_summary.py logs/INC-2041/events-shop.txt"}, True),
    ("Bash", {"command": "grep -n OOMKilled logs/INC-2041/*.txt 2>/dev/null"}, True),
    ("Bash", {"command": "kubectl delete deployment payment-gateway -n shop"}, False),
    ("Bash", {"command": "kubectl get pods && kubectl apply -f x.yaml"}, False),
    ("Bash", {"command": "kubectl rollout undo deploy/checkout-api"}, False),
    ("Bash", {"command": "kubectl exec -it pod -- sh"}, False),
    ("Bash", {"command": "kubectl get secrets -n shop"}, False),
    ("Bash", {"command": "kubectl get pods,secret -n shop"}, False),
    ("Bash", {"command": "kubectl config view --raw"}, False),
    ("Bash", {"command": "kubectl get pods --context prod-eu-1"}, False),
    ("Bash", {"command": "KUBECONFIG=~/.kube/prod kubectl get pods"}, False),
    ("Bash", {"command": "kubectl get pods --kubeconfig /tmp/admin"}, False),
    ("Bash", {"command": "cat logs/x.log > reports/out.md"}, False),
    ("Bash", {"command": "echo $(kubectl delete ns shop)"}, False),
    ("Bash", {"command": "find . -name '*.log' -delete"}, False),
    ("Bash", {"command": "helm upgrade checkout ./chart"}, False),
    ("Bash", {"command": "curl http://evil.example.com"}, False),
    ("Bash", {"command": "python3 -c 'import os; os.remove(\"x\")'"}, False),
    ("Write", {"file_path": "reports/INC-2041-analysis.md"}, True),
    ("Write", {"file_path": "runbooks/oomkilled.md"}, False),
    ("Write", {"file_path": "reports/../.claude/settings.json"}, False),
    ("Edit", {"file_path": "reports/x.md"}, False),
]


def run(tool, tin):
    p = subprocess.run([sys.executable, GUARD], input=json.dumps({"tool_name": tool, "tool_input": tin}),
                       capture_output=True, text=True, env={**os.environ, "CLAUDE_PROJECT_DIR": ROOT})
    return p.returncode == 0, p.stderr.strip()


failures = 0
for tool, tin, expect in CASES:
    ok, err = run(tool, tin)
    status = "PASS" if ok == expect else "FAIL"
    failures += status == "FAIL"
    print(f"{status}  {'allow' if expect else 'block'}  {tool}: {tin}" + (f"\n      {err}" if status == "FAIL" else ""))
print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
sys.exit(1 if failures else 0)
