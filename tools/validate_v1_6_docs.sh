#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Validating NetSniper v1.6 README/CHANGELOG freshness..."

grep -q 'Current release: \*\*NetSniper v1.6.0 — Intelligence Validation and Confidence Calibration' README.md
grep -q './tools/validate_v1_6_release_gate.sh' README.md
grep -q '## v1.6.0' CHANGELOG.md
grep -q 'tools/validate_v1_6_release_gate.sh' CHANGELOG.md

if grep -q 'validate_v1_5_release_gate.sh\|### What v1.5.0 adds\|Current release: \*\*NetSniper v1.6.0 — Classification Accuracy Expansion' README.md; then
  echo "[-] README still contains stale v1.5/v1.6 release wording."
  grep -n 'validate_v1_5_release_gate.sh\|### What v1.5.0 adds\|Classification Accuracy Expansion' README.md
  exit 1
fi

echo "[+] PASS: NetSniper v1.6 docs are fresh."
