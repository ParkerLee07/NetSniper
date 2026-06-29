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

root="examples/deltaaegis-fixtures"

[ -d "$root" ] \
    || fail "missing DeltaAegis fixture directory"

for fixture in quick-complete balanced-complete accurate-complete failed-quality; do
    [ -d "$root/$fixture" ] \
        || fail "missing fixture: $fixture"

    [ -s "$root/$fixture/manifest.json" ] \
        || fail "missing fixture manifest: $fixture"

    [ -s "$root/$fixture/bundle_quality.json" ] \
        || fail "missing fixture bundle_quality.json: $fixture"

    [ -s "$root/$fixture/hosts.txt" ] \
        || fail "missing fixture hosts.txt: $fixture"

    [ -s "$root/$fixture/analysis.json" ] \
        || fail "missing fixture analysis.json: $fixture"

    [ -s "$root/$fixture/analysis.enriched.json" ] \
        || fail "missing fixture analysis.enriched.json: $fixture"

    [ -s "$root/$fixture/classification_quality.json" ] \
        || fail "missing fixture classification_quality.json: $fixture"
done

for profile in quick balanced accurate; do
    fixture="$root/$profile-complete"
    manifest="$fixture/manifest.json"
    quality="$fixture/bundle_quality.json"

    jq -e --arg profile "$profile" '
      .schema_version == "netsniper-run-v3"
      and .manifest_contract == "netsniper-run-v3"
      and .legacy_schema_version == "netsniper-run-v2"
      and .scanner_version == "v2.0.0-fixture"
      and .target == "192.168.56.0/30"
      and .network_scope == .target
      and .status == "COMPLETE"
      and .requested_profile == $profile
      and .effective_profile == $profile
      and .scan_profile_requested == $profile
      and .scan_profile_effective == $profile
      and .profile_contract == "FAST_MONITORED_TCP"
      and .files.bundle_quality_json == "bundle_quality.json"
      and .files.hosts == "hosts.txt"
      and .quality.deltaaegis_ready == true
    ' "$manifest" >/dev/null \
        || {
            jq . "$manifest" >&2
            fail "$profile manifest does not satisfy v2.0 fixture contract"
        }

    jq -e --arg profile "$profile" '
      .schema_version == "netsniper-bundle-quality-v1"
      and .deltaaegis_ready == true
      and .manifest_valid == true
      and .required_files_present == true
      and .counts_valid == true
      and .classification_quality_valid == true
      and .profile_fields_valid == true
      and .target_scope_valid == true
      and .status_complete == true
      and .profile.effective_profile == $profile
      and (.errors | type == "array" and length == 0)
    ' "$quality" >/dev/null \
        || {
            jq . "$quality" >&2
            fail "$profile bundle quality does not satisfy fixture contract"
        }

    hosts_count="$(wc -l < "$fixture/hosts.txt" | tr -d ' ')"
    analysis_count="$(jq 'length' "$fixture/analysis.json")"
    enriched_count="$(jq '.hosts | length' "$fixture/analysis.enriched.json")"

    [ "$hosts_count" = "$analysis_count" ] \
        || fail "$profile hosts.txt count does not match analysis.json"

    [ "$hosts_count" = "$enriched_count" ] \
        || fail "$profile hosts.txt count does not match analysis.enriched.json"
done

[ -s "$root/accurate-complete/os_detection.xml" ] \
    || fail "accurate fixture missing os_detection.xml"

[ -s "$root/accurate-complete/udp_lite.xml" ] \
    || fail "accurate fixture missing udp_lite.xml"

jq -e '
  .schema_version == "netsniper-run-v3"
  and .status == "FAILED"
  and .quality.deltaaegis_ready == false
' "$root/failed-quality/manifest.json" >/dev/null \
    || fail "failed-quality manifest should remain non-ready"

jq -e '
  .schema_version == "netsniper-bundle-quality-v1"
  and .deltaaegis_ready == false
  and .required_files_present == false
  and .status_complete == false
  and (.errors | length > 0)
' "$root/failed-quality/bundle_quality.json" >/dev/null \
    || fail "failed-quality bundle_quality should remain non-ready"

ok "NetSniper v2.0 DeltaAegis fixture validation passed"
