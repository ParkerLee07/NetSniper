#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d -t netsniper-v2.2-runtime.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

for cmd in bash python3 jq sha256sum timeout tar; do
    command -v "$cmd" >/dev/null 2>&1 || fail "missing validator dependency: $cmd"
done

bash -n "$ROOT/netsniper.sh" "$ROOT/install.sh" || fail "Bash syntax"
python3 -m py_compile \
    "$ROOT/netsniper_core/scope.py" \
    "$ROOT/netsniper_core/pipeline.py" \
    "$ROOT/tools/validate_v2_2_scope.py" || fail "Python syntax"

grep -Fq 'SCANNER_VERSION="v2.2.0"' "$ROOT/netsniper.sh" || fail "v2.2 runtime version"
grep -Fq 'BUNDLE_STAGING_ROOT=' "$ROOT/netsniper.sh" || fail "bundle staging root"
grep -Fq 'prepare_headless_workspace' "$ROOT/netsniper.sh" || fail "private runtime workspace"
grep -Fq 'validate_discovered_scope' "$ROOT/netsniper.sh" || fail "scope containment wiring"
! grep -Fq -- '--gmp-password' "$ROOT/netsniper.sh" || fail "Greenbone password remains in argv"
! grep -Eq '\beval[[:space:]]+' "$ROOT/netsniper.sh" || fail "eval helper remains"
! grep -Eq 'v2\.1-dev|runtime execution is not enabled in NetSniper v2\.1\.0' "$ROOT/netsniper.sh" || fail "stale release strings remain"
for cmd in nmap jq base64 python3 sha256sum timeout; do
    grep -Fq "$cmd" "$ROOT/install.sh" || fail "installer does not name dependency $cmd"
done

python3 - "$ROOT" <<'PY'
from collections import defaultdict
from pathlib import Path
import sys
root = Path(sys.argv[1])
paths = [p.relative_to(root).as_posix() for p in root.rglob('*') if '.git' not in p.parts]
groups = defaultdict(list)
for value in paths:
    groups[value.casefold()].append(value)
collisions = [items for items in groups.values() if len(items) > 1]
if collisions:
    raise SystemExit(f"case-insensitive path collisions remain: {collisions}")
PY
pass "static v2.2 runtime safety boundaries"

python3 - "$ROOT" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
from netsniper_core.scope import ScopeValidationError, normalize_private_cidr, validate_host_inventory
from netsniper_core.pipeline import _neighbor_map

accepted = ["10.20.0.0/16", "10.20.30.7/24", "172.16.0.0/16", "172.31.255.0/24", "192.168.4.0/24"]
rejected = ["10.0.0.0/8", "127.0.0.0/24", "169.254.0.0/16", "100.64.0.0/16", "192.0.2.0/24", "198.18.0.0/16", "224.0.0.0/24", "2001:db8::/64"]
for value in accepted:
    normalize_private_cidr(value)
for value in rejected:
    try:
        normalize_private_cidr(value)
    except ScopeValidationError:
        pass
    else:
        raise SystemExit(f"unsafe target accepted: {value}")
try:
    validate_host_inventory("192.168.4.0/24", ["192.168.4.10", "192.168.5.10"])
except ScopeValidationError:
    pass
else:
    raise SystemExit("out-of-scope host inventory accepted")

import tempfile
with tempfile.TemporaryDirectory() as td:
    path = Path(td) / "neighbors.txt"
    path.write_text("192.168.4.1 dev eth0 lladdr zz:11:22:33:44:55 REACHABLE\n", encoding="utf-8")
    if _neighbor_map(path):
        raise SystemExit("malformed MAC was not ignored")
PY
pass "exact RFC1918, host containment, and malformed-MAC handling"

mkdir -p "$TMP/repo" "$TMP/fakebin"
tar --exclude='.git' --exclude='runs' --exclude='.runtime' --exclude='.bundle-staging' \
    -C "$ROOT" -cf - . | tar -C "$TMP/repo" -xf -

cat > "$TMP/fakebin/nmap" <<'FAKE_NMAP'
#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
args=("$@")
if [ "${1:-}" = "--version" ]; then echo "Nmap version 7.94 (NetSniper v2.2 fixture)"; exit 0; fi
mode=service; prefix=""; input_file=""; target=""
for ((i=0; i<${#args[@]}; i++)); do
    arg="${args[$i]}"
    case "$arg" in
        -sn) mode=discovery ;;
        -sU) mode=udp ;;
        -O|--osscan-limit) [ "$mode" = udp ] || mode=os ;;
        -oA) i=$((i+1)); prefix="${args[$i]}" ;;
        -iL) i=$((i+1)); input_file="${args[$i]}" ;;
        */*) [[ "$arg" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && target="$arg" ;;
    esac
done
[ -n "$prefix" ] || exit 2
host="${FAKE_HOST_OVERRIDE:-}"
if [ -z "$host" ] && [ -n "$input_file" ] && [ -s "$input_file" ]; then host="$(awk 'NF {print $1; exit}' "$input_file")"; fi
if [ -z "$host" ] && [ -n "$target" ]; then
    host="$(python3 - "$target" <<'PY'
import ipaddress, sys
n=ipaddress.ip_network(sys.argv[1], strict=False)
print(n.network_address + min(10, max(1, n.num_addresses-2)))
PY
)"
fi
host="${host:-192.168.50.10}"
case "$mode" in
 discovery) sleep "${FAKE_DISCOVERY_SLEEP:-0}" ;;
 service) sleep "${FAKE_SERVICE_SLEEP:-0}" ;;
 os) sleep "${FAKE_OS_SLEEP:-0}" ;;
 udp) sleep "${FAKE_UDP_SLEEP:-0}" ;;
esac
mkdir -p "$(dirname "$prefix")"
if [ "$mode" = discovery ]; then
    printf 'Host: %s () Status: Up\n' "$host" > "${prefix}.gnmap"
else
    protocol=tcp; port=22; service=ssh
    [ "$mode" = udp ] && protocol=udp && port=53 && service=domain
    printf 'Host: %s () Ports: %s/open/%s//%s//Synthetic///\n' "$host" "$port" "$protocol" "$service" > "${prefix}.gnmap"
fi
printf 'Nmap scan report for %s\nHost is up.\n' "$host" > "${prefix}.nmap"
completion=success
if [ "${FAKE_OPTIONAL_INVALID:-0}" = 1 ] && { [ "$mode" = os ] || [ "$mode" = udp ]; }; then completion=error; fi
protocol=tcp; port=22; service=ssh
[ "$mode" = udp ] && protocol=udp && port=53 && service=domain
cat > "${prefix}.xml" <<EOF
<?xml version="1.0"?>
<nmaprun start="1785283200"><host><status state="up"/><address addr="$host" addrtype="ipv4"/><hostnames><hostname name="fixture.local"/></hostnames><ports><port protocol="$protocol" portid="$port"><state state="open"/><service name="$service" product="Synthetic" version="1.0"/></port></ports><os><osmatch name="Synthetic Linux" accuracy="98"/></os></host><runstats><finished time="1785283260" exit="$completion"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>
EOF
exit 0
FAKE_NMAP
chmod +x "$TMP/fakebin/nmap"

run_scan() {
    local label="$1" target="$2" profile="$3"; shift 3
    env PATH="$TMP/fakebin:$PATH" "$@" \
        "$TMP/repo/netsniper.sh" --non-interactive --target "$target" \
        --profile "$profile" --greenbone no \
        --json-status-file "$TMP/$label.status.json" \
        >"$TMP/$label.out" 2>"$TMP/$label.err"
}

run_scan balanced 192.168.50.0/24 balanced
run_dir="$(jq -r .run_dir "$TMP/balanced.status.json")"
[ -f "$run_dir/manifest.json" ] || fail "balanced bundle missing"
jq -e '.scanner_version == "v2.2.0" and .schema_version == "netsniper-run-v3" and .contracts.capability_manifest_version == "netsniper-capability-manifest-v1" and .contracts.host_classification_version == "netsniper-host-classification-v2" and .quality.deltaaegis_ready == true' "$run_dir/manifest.json" >/dev/null || fail "v2.2 compatibility contract"
pass "balanced v2.2 bundle and compatibility contracts"

set +e
FAKE_HOST_OVERRIDE=10.99.0.10 run_scan cross_scope 192.168.50.0/24 balanced
cross_rc=$?
set -e
[ "$cross_rc" -ne 0 ] || fail "cross-scope discovery unexpectedly succeeded"
jq -e '.status == "failed" and .return_code != 0' "$TMP/cross_scope.status.json" >/dev/null || fail "cross-scope failure status"
pass "out-of-scope discovery fails closed"

FAKE_OPTIONAL_INVALID=1 FAKE_SERVICE_SLEEP=1 FAKE_OS_SLEEP=1 FAKE_UDP_SLEEP=1 \
    run_scan optional 192.168.51.0/24 accurate
optional_dir="$(jq -r .run_dir "$TMP/optional.status.json")"
jq -e '.profile_duration_seconds >= 3 and .os_detection_available == false and .udp_lite_available == false and .files.os_detection_xml == null and .files.udp_lite_xml == null' "$optional_dir/manifest.json" >/dev/null || fail "optional evidence or duration accounting"
[ ! -e "$optional_dir/os_detection.xml" ] && [ ! -e "$optional_dir/udp_lite.xml" ] || fail "unsuccessful optional XML published"
pass "optional evidence and full-profile duration"

FAKE_DISCOVERY_SLEEP=1 FAKE_SERVICE_SLEEP=1 run_scan concurrent_a 192.168.60.0/24 balanced & pid_a=$!
FAKE_DISCOVERY_SLEEP=1 FAKE_SERVICE_SLEEP=1 run_scan concurrent_b 192.168.70.0/24 balanced & pid_b=$!
wait "$pid_a"; wait "$pid_b"
a_dir="$(jq -r .run_dir "$TMP/concurrent_a.status.json")"
b_dir="$(jq -r .run_dir "$TMP/concurrent_b.status.json")"
[ "$a_dir" != "$b_dir" ] || fail "concurrent runs shared a run directory"
jq -e '.target == "192.168.60.0/24" and .network_scope == "192.168.60.0/24"' "$a_dir/manifest.json" >/dev/null || fail "concurrent A scope"
jq -e '.target == "192.168.70.0/24" and .network_scope == "192.168.70.0/24"' "$b_dir/manifest.json" >/dev/null || fail "concurrent B scope"
[ -z "$(find "$TMP/repo/.runtime" -mindepth 1 -maxdepth 1 -type d -print -quit)" ] || fail "private runtime workspace leaked"
pass "concurrent headless scans remain isolated"

rm -rf "$TMP/repo/runs"
mkdir -p "$TMP/repo/runs"
python3 - "$TMP/repo/tools/generate_v2_1_run_artifacts.py" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); t=p.read_text(); anchor='from __future__ import annotations\n'; assert t.count(anchor)==1
p.write_text(t.replace(anchor, anchor+'\nimport time\ntime.sleep(3)\n',1))
PY
FAKE_DISCOVERY_SLEEP=0 FAKE_SERVICE_SLEEP=0 run_scan publication 192.168.80.0/24 balanced & pub_pid=$!
partial=0
for _ in $(seq 1 60); do
    if ! kill -0 "$pub_pid" 2>/dev/null; then break; fi
    if find "$TMP/repo/runs" -mindepth 2 -maxdepth 2 -name manifest.json -print -quit | grep -q .; then partial=1; break; fi
    sleep 0.1
done
wait "$pub_pid"
[ "$partial" -eq 0 ] || fail "partial bundle became visible before finalization"
pass "atomic bundle publication"

NETSNIPER_TEST_MODE=1 PATH="$TMP/fakebin:$PATH" bash -c 'set -Eeuo pipefail; source "$1"; show_targets; echo survived' bash "$TMP/repo/netsniper.sh" | grep -Fq survived || fail "interactive missing-stage containment"
pass "interactive errors return control"

printf '[PASS] NetSniper v2.2 runtime safety gate complete\n'
