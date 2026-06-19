#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENHANCER="$ROOT_DIR/tools/enhance_v1_7_analysis.py"
REPORTER="$ROOT_DIR/tools/report_v1_7_quality.py"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'USAGE'
Usage:
  tools/generate_v1_7_run_artifacts.sh <run-directory-or-analysis-json>

Examples:
  tools/generate_v1_7_run_artifacts.sh runs/20260619-125200
  tools/generate_v1_7_run_artifacts.sh runs/20260619-125200/analysis.json
USAGE
}

[[ $# -eq 1 ]] || {
  usage
  exit 1
}

input="$1"

if [[ -d "$input" ]]; then
  run_dir="$input"
  analysis="$run_dir/analysis.json"
elif [[ -f "$input" ]]; then
  analysis="$input"
  run_dir="$(dirname "$analysis")"
else
  fail "Input is not a directory or file: $input"
fi

[[ -f "$analysis" ]] || fail "Missing analysis file: $analysis"
[[ -x "$ENHANCER" ]] || fail "Missing enhancer: tools/enhance_v1_7_analysis.py"
[[ -x "$REPORTER" ]] || fail "Missing reporter: tools/report_v1_7_quality.py"

enriched="$run_dir/analysis.enriched.json"
quality_json="$run_dir/classification_quality.json"
quality_md="$run_dir/classification_quality.md"

echo "[INFO] Input analysis: $analysis"
echo "[INFO] Output enriched analysis: $enriched"
echo "[INFO] Output quality JSON: $quality_json"
echo "[INFO] Output quality Markdown: $quality_md"

python3 "$ENHANCER" \
  --analysis "$analysis" \
  --output "$enriched" \
  >/dev/null

python3 "$REPORTER" \
  --analysis "$enriched" \
  --output-json "$quality_json" \
  --output-md "$quality_md" \
  >/dev/null

jq '{
  host_count,
  classified_count,
  possible_or_review_count,
  unknown_count,
  contradiction_host_count,
  false_confidence_candidate_count,
  review_queue_count,
  unknown_with_exposed_services_count,
  top_device_types,
  confidence_band_counts
}' "$quality_json"

echo "[PASS] NetSniper v1.7 run artifacts generated"
