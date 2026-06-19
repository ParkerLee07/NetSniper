#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] NetSniper v1.6 release gate"
echo

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking v1.6 version markers..."
grep -q 'SCANNER_VERSION="v1.6.0"' netsniper.sh
grep -q 'NETSNIPER v1.6' netsniper.sh
grep -q 'NetSniper v1.6.0' README.md
grep -q 'Current release: \*\*NetSniper v1.6.0' README.md
grep -q '## v1.6.0' CHANGELOG.md

if grep -q 'SCANNER_VERSION="v1.6.0-dev"' netsniper.sh; then
  echo "[-] Dev version marker still present."
  exit 1
fi

echo "[*] Running v1.6 docs validator..."
./tools/validate_v1_6_docs.sh

echo "[*] Running v1.6 intelligence gate..."
./tools/validate_v1_6_intelligence_gate.sh

echo "[*] Checking git state..."
if [ -n "$(git status --short)" ]; then
  echo "[*] Working tree has changes, which is expected before the release commit:"
  git status --short
fi

echo
echo "[+] PASS: NetSniper v1.6 release gate succeeded."
