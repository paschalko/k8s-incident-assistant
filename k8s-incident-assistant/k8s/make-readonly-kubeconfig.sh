#!/usr/bin/env bash
# Phase 2 helper – run by a HUMAN on a NON-PROD cluster after applying readonly-rbac.yaml.
# Produces ./k8s/assistant.kubeconfig that holds ONLY the read-only ServiceAccount token
# (short-lived, 8h). Start Claude Code with:  KUBECONFIG=$PWD/k8s/assistant.kubeconfig claude
set -euo pipefail

CTX="$(kubectl config current-context)"
if [[ "$CTX" =~ prod|prd|live ]]; then
  echo "Refusing: current context '$CTX' looks like production." >&2; exit 1
fi

SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CA="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
TOKEN="$(kubectl create token incident-assistant -n kube-system --duration=8h)"
OUT="$(dirname "$0")/assistant.kubeconfig"

cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: assistant-${CTX}
  cluster:
    server: ${SERVER}
    certificate-authority-data: ${CA}
users:
- name: incident-assistant
  user:
    token: ${TOKEN}
contexts:
- name: assistant-${CTX}
  context:
    cluster: assistant-${CTX}
    user: incident-assistant
current-context: assistant-${CTX}
EOF
chmod 600 "$OUT"
echo "Wrote $OUT (expires in 8h). Verify it is read-only:"
echo "  KUBECONFIG=$OUT kubectl auth can-i delete pods -A   # expect: no"
echo "  KUBECONFIG=$OUT kubectl auth can-i get secrets -A   # expect: no"
