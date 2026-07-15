#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh \
    || fail "netsniper.sh has a syntax error"

grep -Eq 'SCANNER_VERSION="v(2\.0\.0(-dev)?|2\.1\.0-dev)"' netsniper.sh \
    || fail "scanner version is not v2.0.0-dev, v2.0.0, or v2.1.0-dev"

grep -Fq 'HEADLESS_JSON_STATUS_FILE=""' netsniper.sh \
    || fail "missing HEADLESS_JSON_STATUS_FILE variable"

grep -Fq -- '--json-status-file' netsniper.sh \
    || fail "missing --json-status-file CLI support"

grep -Fq 'schema_version "netsniper-status-v1"' netsniper.sh \
    || fail "status schema version is missing"

grep -Fq 'requested_profile' netsniper.sh \
    || fail "status payload does not include requested_profile"

grep -Fq 'effective_profile' netsniper.sh \
    || fail "status payload does not include effective_profile"

grep -Fq 'handle_headless_interrupt' netsniper.sh \
    || fail "missing headless interruption handler"

tmp_dir="$(mktemp -d)"
status_file="$tmp_dir/status.json"
stdout_file="$tmp_dir/stdout.txt"
stderr_file="$tmp_dir/stderr.txt"

set +e
./netsniper.sh \
    --non-interactive \
    --target 8.8.8.0/24 \
    --greenbone no \
    --profile quick \
    --json-status-file "$status_file" \
    >"$stdout_file" 2>"$stderr_file"
rc=$?
set -e

[ "$rc" -eq 1 ] \
    || fail "invalid public target should return exit code 1, got $rc"

[ -s "$status_file" ] \
    || fail "status file was not written for failed headless validation"

python3 - "$status_file" <<'NETSNIPER_V2_PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))

assert data["schema_version"] == "netsniper-status-v1", data
assert data["scanner_version"] in {"v2.0.0-dev", "v2.0.0", "v2.1.0-dev"}, data
assert data["status"] == "failed", data
assert data["return_code"] == 1, data
assert data["target"] == "8.8.8.0/24", data
assert data["requested_profile"] == "quick", data
assert data["effective_profile"] == "quick", data
assert data["runtime_stage"] == "v1_8_compatible_tcp", data
assert "status_at" in data and data["status_at"], data
assert "run_dir" in data, data
assert "manifest_path" in data, data

print("[PASS] v2.0 status file failure contract JSON checks passed")
NETSNIPER_V2_PY

stdout_status_file="$tmp_dir/stdout-status.txt"

set +e
./netsniper.sh \
    --non-interactive \
    --target 8.8.8.0/24 \
    --greenbone no \
    --profile balanced \
    --json-status \
    >"$stdout_status_file" 2>"$tmp_dir/stdout-status.err"
rc=$?
set -e

[ "$rc" -eq 1 ] \
    || fail "invalid public target with --json-status should return exit code 1, got $rc"

python3 - "$stdout_status_file" <<'NETSNIPER_V2_STDOUT_PY'
import json
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
decoder = json.JSONDecoder()
best = None

index = text.find("{")
while index != -1:
    try:
        value, _ = decoder.raw_decode(text[index:])
    except json.JSONDecodeError:
        index = text.find("{", index + 1)
        continue

    if isinstance(value, dict):
        best = value

    index = text.find("{", index + 1)

assert best is not None, text
assert best["schema_version"] == "netsniper-status-v1", best
assert best["status"] == "failed", best
assert best["return_code"] == 1, best
assert best["requested_profile"] == "balanced", best
assert best["effective_profile"] == "balanced", best

print("[PASS] v2.0 stdout status contract JSON checks passed")
NETSNIPER_V2_STDOUT_PY

ok "NetSniper v2.0 status contract validation passed"
