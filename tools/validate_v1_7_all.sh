#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"$ROOT_DIR/tools/validate_v1_7_taxonomy.sh"
"$ROOT_DIR/tools/validate_v1_7_evidence_profiles.sh"
"$ROOT_DIR/tools/validate_v1_7_fixtures.sh"
"$ROOT_DIR/tools/validate_v1_7_fixture_classifier.sh"
"$ROOT_DIR/tools/validate_v1_7_host_classifier.sh"
"$ROOT_DIR/tools/validate_v1_7_normalizer.sh"
"$ROOT_DIR/tools/validate_v1_7_analysis_enhancer.sh"
"$ROOT_DIR/tools/validate_v1_7_quality_report.sh"
"$ROOT_DIR/tools/validate_v1_7_run_artifacts.sh"

echo "[PASS] All NetSniper v1.7 device-intelligence validators passed"
