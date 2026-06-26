#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

bash -n netsniper.sh || fail "netsniper.sh has shell syntax errors"

./tools/validate_v1_9_quick_balanced_runtime_planner.sh \
    || fail "quick/balanced runtime planner validator failed"

work_dir="$(mktemp -d)"
fake_bin="$work_dir/bin"
command_log="$work_dir/nmap-commands.log"

mkdir -p "$fake_bin"
: > "$command_log"

cat > "$fake_bin/nmap" <<'FAKENMAP'
#!/usr/bin/env bash
set -euo pipefail

log_file="${NETSNIPER_FAKE_NMAP_LOG:?missing NETSNIPER_FAKE_NMAP_LOG}"

printf '%q ' "$0" "$@" >> "$log_file"
printf '\n' >> "$log_file"

out_base=""
mode="scan"

args=("$@")

for ((i = 0; i < ${#args[@]}; i++)); do
    case "${args[$i]}" in
        -oA)
            out_base="${args[$((i + 1))]}"
            ;;
        -sn)
            mode="discovery"
            ;;
    esac
done

if [ -z "$out_base" ]; then
    echo "fake nmap expected -oA" >&2
    exit 2
fi

mkdir -p "$(dirname "$out_base")"

if [ "$mode" = "discovery" ]; then
    cat > "${out_base}.gnmap" <<'DISCOVERY_GNMAP'
# Nmap fake discovery
Host: 192.168.56.1 () Status: Up
Host: 192.168.56.2 () Status: Up
# Nmap done
DISCOVERY_GNMAP

    cat > "${out_base}.nmap" <<'DISCOVERY_NMAP'
Nmap fake discovery report
Host 192.168.56.1 is up
Host 192.168.56.2 is up
DISCOVERY_NMAP

    cat > "${out_base}.xml" <<'DISCOVERY_XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake discovery" start="1760000000">
  <host>
    <status state="up"/>
    <address addr="192.168.56.1" addrtype="ipv4"/>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.56.2" addrtype="ipv4"/>
  </host>
  <runstats>
    <finished time="1760000001" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
DISCOVERY_XML

    exit 0
fi

cat > "${out_base}.gnmap" <<'SCAN_GNMAP'
# Nmap fake service scan
Host: 192.168.56.1 () Ports: 22/open/tcp//ssh//OpenSSH fake/, 80/open/tcp//http//Fake HTTP/
Host: 192.168.56.2 () Ports: 443/open/tcp//https//Fake HTTPS/
# Nmap done
SCAN_GNMAP

cat > "${out_base}.nmap" <<'SCAN_NMAP'
Nmap fake service scan report
Host 192.168.56.1
22/tcp open ssh OpenSSH fake
80/tcp open http Fake HTTP
Host 192.168.56.2
443/tcp open https Fake HTTPS
SCAN_NMAP

cat > "${out_base}.xml" <<'SCAN_XML'
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="fake service scan" start="1760000002">
  <host>
    <status state="up"/>
    <address addr="192.168.56.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="fake"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Fake HTTP"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="192.168.56.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Fake HTTPS"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1760000004" exit="success"/>
    <hosts up="2" down="0" total="2"/>
  </runstats>
</nmaprun>
SCAN_XML

exit 0
FAKENMAP

chmod +x "$fake_bin/nmap"

before_marker="$(date +%s)"

run_profile() {
    local profile="$1"
    local output_file="$work_dir/${profile}.out"

    PATH="$fake_bin:$PATH" \
    NETSNIPER_FAKE_NMAP_LOG="$command_log" \
    ./netsniper.sh \
        --non-interactive \
        --target 192.168.56.0/30 \
        --greenbone no \
        --json-status \
        --profile "$profile" \
        > "$output_file" 2>&1 \
        || {
            cat "$output_file" >&2
            fail "$profile fake-nmap headless run failed"
        }

    grep -Eq '"status"[[:space:]]*:[[:space:]]*"completed"' "$output_file" \
        || {
            cat "$output_file" >&2
            fail "$profile run did not emit completed json-status"
        }
}

run_profile balanced
run_profile accurate

grep -F -- '-sV -T4 -p' "$command_log" >/dev/null \
    || {
        cat "$command_log" >&2
        fail "balanced runtime command did not include expected v1.8-compatible TCP args"
    }

grep -F -- '-sV -T4 --version-intensity 7 -p' "$command_log" >/dev/null \
    || {
        cat "$command_log" >&2
        fail "accurate runtime command did not include --version-intensity 7"
    }

grep -F -- '-O --osscan-limit' "$command_log" >/dev/null \
    || {
        cat "$command_log" >&2
        fail "accurate runtime command did not include non-fatal OS evidence pass"
    }

if grep -F -- ' -sU ' "$command_log" >/dev/null; then
    cat "$command_log" >&2
    fail "fake runtime unexpectedly used UDP-lite"
fi

latest_run="$(
    find runs -mindepth 1 -maxdepth 1 -type d -newermt "@$before_marker" -printf '%T@ %p\n' \
        | sort -nr \
        | head -1 \
        | awk '{print $2}'
)"

[ -n "$latest_run" ] || fail "could not locate fake-nmap run directory"

manifest="$latest_run/manifest.json"

[ -s "$manifest" ] || fail "fake-nmap run manifest missing"

jq -e '
  .scan_profile == "FAST_MONITORED_TCP"
  and .scan_profile_requested == "accurate"
  and .scan_profile_effective == "accurate"
  and .scan_profile_runtime_stage == "accurate_tcp_service_depth_os_evidence"
  and .scan_profile_contract_schema == "netsniper-scan-profiles-v1"
  and .os_detection_available == true
  and .files.os_detection_xml == "os_detection.xml"
  and .files.os_detection_gnmap == "os_detection.gnmap"
  and .files.os_detection_nmap == "os_detection.nmap"
' "$manifest" >/dev/null \
    || {
        jq . "$manifest" >&2
        fail "accurate fake-nmap manifest profile metadata is incorrect"
    }

./tools/validate_v1_8_full_inventory_bundle.sh "$latest_run" \
    || fail "fake-nmap accurate run failed full-inventory bundle validation"

pass "NetSniper v1.9 accurate TCP runtime fake-nmap validation passed"
pass "Fake run: $latest_run"
