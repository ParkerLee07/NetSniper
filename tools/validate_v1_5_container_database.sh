#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running compact v1.5 progress validator..."
./tools/validate_v1_5_classifier_progress.sh

echo "[*] Validating Container/Database classifier refinement..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "kube) CONTAINER_SCORE",
    'update_best_candidate "Container Infrastructure" "$CONTAINER_SCORE"',
    '{device_type: "Container Infrastructure", confidence: $container}',
    'add_classification_evidence "container" "port-combination" "k8s-api+kubelet"',
    'add_classification_evidence "container" "port-combination" "docker+admin-console"',
    'add_classification_evidence "database" "port-combination" "elasticsearch-http+transport"',
    'add_classification_evidence "database" "port-combination" "mysql+postgresql"',
    'add_classification_evidence "database" "port-combination" "rdbms+redis"',
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing Container/Database classifier content: {missing}")

for stale in [
    'update_best_candidate "Kubernetes Infrastructure" "$KUBE_SCORE"',
    '{device_type: "Kubernetes Infrastructure", confidence: $kube}',
]:
    if stale in text:
        raise SystemExit(f"[-] Stale Kubernetes standalone classifier content remains: {stale}")

print("[+] PASS: Container/Database classifier refinement is present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 Container/Database validation succeeded."
