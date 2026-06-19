#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] NetSniper v1.5 release gate"
echo

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking for leftover backup files..."
if find . -maxdepth 2 -type f -name '*.backup-*' | grep -q .; then
  echo "[-] Backup files remain:"
  find . -maxdepth 2 -type f -name '*.backup-*'
  exit 1
fi

echo "[*] Checking v1.5 version markers..."
grep -q 'SCANNER_VERSION="v1.5.0"' netsniper.sh
grep -q 'NETSNIPER v1.5' netsniper.sh
grep -q 'NETSNIPER_CLASSIFICATION_ENGINE_V150' netsniper.sh
grep -q 'NetSniper v1.5.0' README.md
grep -q 'Current release: \*\*NetSniper v1.5.0' README.md
if grep -A8 -i '^## Current Release' README.md | grep -q 'NetSniper v1.4'; then
  echo "[-] README Current Release section still references v1.4."
  exit 1
fi
grep -q '## v1.5.0' CHANGELOG.md

echo "[*] Checking required validators..."
required_validators=(
  tools/validate_v1_5_taxonomy.sh
  tools/validate_v1_5_fixtures.sh
  tools/validate_v1_5_classifier_progress.sh
  tools/validate_v1_5_behavior.sh
  tools/validate_v1_5_text_evidence.sh
)

for validator in "${required_validators[@]}"; do
  if [ ! -x "$validator" ]; then
    echo "[-] Missing or non-executable validator: $validator"
    exit 1
  fi
done

echo "[*] Running taxonomy validator..."
./tools/validate_v1_5_taxonomy.sh

echo "[*] Running fixture validator..."
./tools/validate_v1_5_fixtures.sh

echo "[*] Running cumulative classifier validator..."
./tools/validate_v1_5_classifier_progress.sh

echo "[*] Running behavior validator..."
./tools/validate_v1_5_behavior.sh

echo "[*] Running service-text validator..."
./tools/validate_v1_5_text_evidence.sh

echo "[*] Checking git state..."
if [ -n "$(git status --short)" ]; then
  echo "[-] Working tree is not clean:"
  git status --short
  exit 1
fi

echo
echo "[+] PASS: NetSniper v1.5 release gate succeeded."
