#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

NS_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
DA_ROOT="${1:-${DELTAAEGIS_ROOT:-$HOME/DeltaAegis}}"
TMP="$(mktemp -d -t netsniper-v2.2-deltaaegis.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

[ -f "$DA_ROOT/deltaaegis.py" ] || fail "DeltaAegis root not found: $DA_ROOT"
for cmd in bash python3 jq tar sha256sum timeout; do command -v "$cmd" >/dev/null 2>&1 || fail "missing dependency: $cmd"; done
mkdir -p "$TMP/ns" "$TMP/fakebin" "$TMP/home-accepted" "$TMP/home-tampered"
tar --exclude='.git' --exclude='runs' --exclude='.runtime' --exclude='.bundle-staging' -C "$NS_ROOT" -cf - . | tar -C "$TMP/ns" -xf -

cat > "$TMP/fakebin/nmap" <<'FAKE_NMAP'
#!/usr/bin/env bash
set -Eeuo pipefail
args=("$@")
if [ "${1:-}" = --version ]; then echo 'Nmap version 7.94 (v2.2 compatibility fixture)'; exit 0; fi
mode=service; prefix=""; input=""; target=""
for ((i=0;i<${#args[@]};i++)); do
 case "${args[$i]}" in
  -sn) mode=discovery ;;
  -oA) i=$((i+1)); prefix="${args[$i]}" ;;
  -iL) i=$((i+1)); input="${args[$i]}" ;;
  */*) [[ "${args[$i]}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] && target="${args[$i]}" ;;
 esac
done
[ -n "$prefix" ] || exit 2
host=""
[ -n "$input" ] && [ -s "$input" ] && host="$(awk 'NF{print $1;exit}' "$input")"
if [ -z "$host" ]; then host="$(python3 - "$target" <<'PY'
import ipaddress,sys
n=ipaddress.ip_network(sys.argv[1],strict=False); print(n.network_address+10)
PY
)"; fi
mkdir -p "$(dirname "$prefix")"
if [ "$mode" = discovery ]; then printf 'Host: %s () Status: Up\n' "$host" > "${prefix}.gnmap"; else printf 'Host: %s () Ports: 22/open/tcp//ssh//OpenSSH 9.0///\n' "$host" > "${prefix}.gnmap"; fi
printf 'Nmap scan report for %s\nHost is up.\n' "$host" > "${prefix}.nmap"
cat > "${prefix}.xml" <<EOF
<?xml version="1.0"?><nmaprun start="1785283200"><host><status state="up"/><address addr="$host" addrtype="ipv4"/><hostnames><hostname name="compat.local"/></hostnames><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0"/></port></ports></host><runstats><finished time="1785283260" exit="success"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>
EOF
FAKE_NMAP
chmod +x "$TMP/fakebin/nmap"

PATH="$TMP/fakebin:$PATH" "$TMP/ns/netsniper.sh" \
    --non-interactive --target 192.168.44.0/24 --profile balanced --greenbone no \
    --json-status-file "$TMP/status.json" >"$TMP/netsniper.out" 2>"$TMP/netsniper.err"
run_dir="$(jq -r .run_dir "$TMP/status.json")"
[ -f "$run_dir/manifest.json" ] || fail "fresh v2.2 runtime bundle missing"
jq -e '.scanner_version=="v2.2.0" and .schema_version=="netsniper-run-v3" and .quality.deltaaegis_ready==true' "$run_dir/manifest.json" >/dev/null || fail "fresh v2.2 manifest contract"
pass "fresh NetSniper v2.2 runtime bundle generated"

HOME="$TMP/home-accepted" python3 "$DA_ROOT/deltaaegis.py" \
    --db "$TMP/accepted.db" --runs-dir "$TMP/ns/runs" --events "$TMP/accepted-events.jsonl" ingest \
    >"$TMP/accepted.out" 2>"$TMP/accepted.err"
grep -Fq 'quality=ACCEPTED' "$TMP/accepted.out" || { cat "$TMP/accepted.out"; cat "$TMP/accepted.err" >&2; fail "DeltaAegis did not accept v2.2 bundle"; }
python3 - "$TMP/accepted.db" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); rows=c.execute("select scanner_version,quality_status from snapshots").fetchall(); c.close()
assert rows == [("v2.2.0","ACCEPTED")], rows
PY
pass "DeltaAegis accepted the exact v2.2 compatibility contracts"

mkdir -p "$TMP/tampered-runs"
cp -a "$run_dir" "$TMP/tampered-runs/"
tampered="$TMP/tampered-runs/$(basename "$run_dir")"
printf '\nTAMPER\n' >> "$tampered/bundle_quality.json"
HOME="$TMP/home-tampered" python3 "$DA_ROOT/deltaaegis.py" \
    --db "$TMP/tampered.db" --runs-dir "$TMP/tampered-runs" --events "$TMP/tampered-events.jsonl" ingest \
    >"$TMP/tampered.out" 2>"$TMP/tampered.err" || true
grep -Fq 'REJECT ' "$TMP/tampered.out" || fail "tampered v2.2 bundle was not rejected"
grep -Fq 'hash_mismatch' "$TMP/tampered.out" || fail "tampered rejection did not record hash_mismatch"
python3 - "$TMP/tampered.db" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); snapshots=c.execute('select count(*) from snapshots').fetchone()[0]; states=c.execute('select current_state from telemetry_quality_decisions').fetchall(); c.close()
assert snapshots == 0, snapshots
assert states == [('REJECTED',)], states
PY
pass "DeltaAegis rejects tampered v2.2 evidence fail-closed"

python3 "$DA_ROOT/tools/validate_v1_0_2_scan_orchestration.py"
pass "DeltaAegis scan serialization, schedule phasing, and TrueAegis correlation"
printf '[PASS] NetSniper v2.2 and DeltaAegis v1.0.2 compatibility gate complete\n'
