#!/bin/bash

# NetSniper - Network Recon & Exposure Intelligence Engine
# Author: Parker Lee
# License: MIT

# =========================
# NETSNIPER ENGINE v2.2.0
# NETSNIPER_CLASSIFICATION_ENGINE_V150
# Compatibility marker retained for v1.5 regression validators.
# NETSNIPER_CLASSIFICATION_ENGINE_V160
# TrueAegis-compatible telemetry output
# =========================

set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo -e "\n[ERROR] Failed at line $LINENO while executing $BASH_COMMAND"' ERR

print_usage() {
    cat <<'EOF'
NetSniper - Network Recon & Exposure Intelligence Engine

Usage:
  ./netsniper.sh
  ./netsniper.sh --non-interactive --target <private-cidr> [--greenbone no] [--json-status] [--json-status-file <path>] [--profile balanced]
  ./netsniper.sh --help

Interactive mode:
  Launches the normal NetSniper setup prompt and menu.

Headless mode:
  Runs the full NetSniper pipeline without prompting. This is intended for automation and DeltaAegis dashboard or schedule orchestration.

Options:
  --non-interactive        Run the full pipeline without the interactive menu.
  --target <CIDR>          Target private IPv4 subnet, such as 192.168.5.0/24.
  --greenbone yes|no       Optional Greenbone integration setting. Headless mode
                           currently supports no; use the interactive menu for Greenbone.
  --json-status            Print a final machine-readable status object.
  --json-status-file <path> Write the final machine-readable status object to a file.
  --profile <name>          Optional scan profile: quick, balanced, or accurate.
  --scan-profile <name>     Alias for --profile. Balanced remains the default.
  -h, --help               Show this help text.

Safety:
  Headless mode rejects non-private targets by default.
EOF
}

# Keep informational help available even when scan-time dependencies are absent.
case "${1:-}" in
    -h|--help)
        print_usage
        exit 0
        ;;
esac

for required_command in nmap jq base64 python3 sha256sum timeout; do
    command -v "$required_command" >/dev/null 2>&1 || {
        echo "$required_command required" >&2
        exit 1
    }
done
command -v gvm-cli >/dev/null 2>&1 || echo "[!] gvm-cli not installed (Greenbone disabled)"

# Colors
RED='\033[1;31m'
RESET='\033[0m'
PURPLE='\033[1;35m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
BLUE='\033[1;34m'

# =========================
# UI HELPERS
# =========================

INFO() {
    echo -e "${BLUE}[i]${RESET} $1"
}

SUCCESS() {
    echo -e "${GREEN}[+]${RESET} $1"
}

ERROR() {
    echo -e "${RED}[-]${RESET} $1"
}

WARN() {
    echo -e "${YELLOW}[!]${RESET} $1"
}

# =========================
# PATH CONFIGURATION
# =========================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE="${NETSNIPER_BASE:-$SCRIPT_DIR}"

DISCOVERY_DIR="$BASE/discovery"
TARGET_DIR="$BASE/targets"
SCAN_DIR="$BASE/scans"
REPORT_DIR="$BASE/reports"
ANALYSIS_DIR="$BASE/analysis"
CONFIG_DIR="$BASE/config"

CONFIG_FILE="$CONFIG_DIR/netsniper.conf"
RUN_DIR="$BASE/runs"
RUNTIME_ROOT="$BASE/.runtime"
BUNDLE_STAGING_ROOT="$BASE/.bundle-staging"
RUNTIME_WORKSPACE=""
CURRENT_BUNDLE_STAGING=""
SOCK="/run/gvmd/gvmd.sock"

SCANNER_VERSION="v2.2.0"
SCAN_PROFILE="${NETSNIPER_SCAN_PROFILE:-balanced}"
SCAN_PROFILE_RESOLVED_JSON=""
SCAN_PROFILE_EFFECTIVE="balanced"
SCAN_PROFILE_RUNTIME_STAGE="v1_8_compatible_tcp"
PROFILE_RUNTIME_BUDGET_SECONDS=0
PROFILE_HOST_TIMEOUT_SECONDS=0
PROFILE_DURATION_SECONDS=0
PROFILE_BUDGET_EXCEEDED=false
SCAN_PROFILE_CONFIG="$BASE/config/scan_profiles.json"

# TrueAegis-aligned scan ports.
# These are the ports NetSniper can reliably identify from nmap grepable output.
TRUEAEGIS_PORTS="21,22,23,25,53,80,88,389,110,139,143,443,445,465,554,587,631,993,995,1433,1521,1900,2375,2376,3000,3306,3389,5000,5432,5555,5601,5900,6379,6443,7547,8000,8080,8081,8443,8888,9000,9090,9100,9200,9300,9443,10250,10255,27017,3268,3269"

HIGH_RISK_PATTERN="21/open|22/open|23/open|25/open|53/open|80/open|88/open|110/open|111/open|135/open|139/open|143/open|161/open|389/open|443/open|445/open|465/open|500/open|554/open|587/open|631/open|993/open|995/open|1433/open|1521/open|1900/open|2049/open|2375/open|2376/open|3000/open|3268/open|3269/open|3306/open|3389/open|4500/open|5000/open|5060/open|5061/open|5432/open|5555/open|5601/open|5900/open|6379/open|6443/open|7547/open|8000/open|8006/open|8080/open|8081/open|8443/open|8888/open|9000/open|9090/open|9100/open|9200/open|9300/open|9443/open|10250/open|10255/open|27017/open"

# =========================
# HEADLESS CLI CONFIGURATION
# =========================

HEADLESS_MODE=0
HEADLESS_TARGET=""
HEADLESS_GREENBONE="no"
JSON_STATUS=0
HEADLESS_JSON_STATUS_FILE=""
LAST_BUNDLE_DIR=""

prepare_headless_workspace() {
    local token
    token="$(date -u +%Y%m%dT%H%M%S)-$$-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
    RUNTIME_WORKSPACE="$RUNTIME_ROOT/$token"
    DISCOVERY_DIR="$RUNTIME_WORKSPACE/discovery"
    TARGET_DIR="$RUNTIME_WORKSPACE/targets"
    SCAN_DIR="$RUNTIME_WORKSPACE/scans"
    REPORT_DIR="$RUNTIME_WORKSPACE/reports"
    ANALYSIS_DIR="$RUNTIME_WORKSPACE/analysis"
}

cleanup_headless_workspace() {
    if [ -n "${RUNTIME_WORKSPACE:-}" ] && [ -d "$RUNTIME_WORKSPACE" ]; then
        rm -rf -- "$RUNTIME_WORKSPACE"
    fi
    if [ -n "${CURRENT_BUNDLE_STAGING:-}" ]         && [ -d "$CURRENT_BUNDLE_STAGING" ]; then
        rm -rf -- "$CURRENT_BUNDLE_STAGING"
    fi
    RUNTIME_WORKSPACE=""
    CURRENT_BUNDLE_STAGING=""
}

resolve_selected_scan_profile() {
    local resolved_profile_json

    if ! resolved_profile_json="$(python3 "$BASE/tools/resolve_v1_9_scan_profile.py" "$SCAN_PROFILE" --profiles-file "$SCAN_PROFILE_CONFIG" 2>&1)"; then
        echo "[-] Invalid scan profile: $SCAN_PROFILE" >&2
        echo "$resolved_profile_json" >&2
        return 1
    fi

    SCAN_PROFILE_RESOLVED_JSON="$resolved_profile_json"
    SCAN_PROFILE_EFFECTIVE="$(printf '%s' "$SCAN_PROFILE_RESOLVED_JSON" | jq -r '.name')"

    case "$SCAN_PROFILE_EFFECTIVE" in
        quick|balanced)
            SCAN_PROFILE_RUNTIME_STAGE="v1_8_compatible_tcp"
            ;;
        accurate)
            SCAN_PROFILE_RUNTIME_STAGE="accurate_tcp_service_depth_os_udp_lite"
            ;;
        deep)
            echo "[-] Scan profile 'deep' is not supported in NetSniper v2.2.0." >&2
            echo "[-] Use quick, balanced, or accurate." >&2
            return 1
            ;;
        *)
            echo "[-] Unexpected resolved scan profile: $SCAN_PROFILE_EFFECTIVE" >&2
            return 1
            ;;
    esac
}

validate_private_cidr() {
    local target="$1"
    python3 "$BASE/tools/validate_v2_2_scope.py" --network "$target" >/dev/null
}

validate_discovered_scope() {
    python3 "$BASE/tools/validate_v2_2_scope.py" \
        --network "$NET" \
        --hosts "$TARGET_DIR/hosts.txt" \
        --rewrite-hosts \
        >/dev/null
}

emit_headless_status() {
    local status="$1"
    local return_code="$2"
    local run_dir="${3:-}"
    local manifest_path=""
    local status_at
    local status_payload
    local status_dir
    local tmp_status_file

    status_at=$(date --iso-8601=seconds)

    if [ -n "$run_dir" ]; then
        manifest_path="$run_dir/manifest.json"
    fi

    if ! status_payload="$(jq -n \
        --arg schema_version "netsniper-status-v1" \
        --arg scanner_version "$SCANNER_VERSION" \
        --arg status "$status" \
        --arg target "${NET:-$HEADLESS_TARGET}" \
        --arg requested_profile "${SCAN_PROFILE:-balanced}" \
        --arg effective_profile "${SCAN_PROFILE_EFFECTIVE:-balanced}" \
        --arg runtime_stage "${SCAN_PROFILE_RUNTIME_STAGE:-unknown}" \
        --argjson profile_runtime_budget_seconds "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" \
        --argjson profile_host_timeout_seconds "${PROFILE_HOST_TIMEOUT_SECONDS:-0}" \
        --argjson profile_duration_seconds "${PROFILE_DURATION_SECONDS:-0}" \
        --argjson profile_budget_exceeded "${PROFILE_BUDGET_EXCEEDED:-false}" \
        --arg run_dir "$run_dir" \
        --arg manifest_path "$manifest_path" \
        --arg status_at "$status_at" \
        --argjson return_code "$return_code" \
        '{
            schema_version: $schema_version,
            scanner_version: $scanner_version,
            status: $status,
            target: $target,
            requested_profile: $requested_profile,
            effective_profile: $effective_profile,
            runtime_stage: $runtime_stage,
            profile_runtime_budget_seconds: $profile_runtime_budget_seconds,
            profile_host_timeout_seconds: $profile_host_timeout_seconds,
            profile_duration_seconds: $profile_duration_seconds,
            profile_budget_exceeded: $profile_budget_exceeded,
            return_code: $return_code,
            run_dir: $run_dir,
            manifest_path: $manifest_path,
            status_at: $status_at
        }')"; then
        echo "[-] Failed to build headless status payload." >&2
        return 1
    fi

    if [ "$JSON_STATUS" = "1" ]; then
        printf '%s\n' "$status_payload"
    fi

    if [ -n "${HEADLESS_JSON_STATUS_FILE:-}" ]; then
        status_dir="$(dirname -- "$HEADLESS_JSON_STATUS_FILE")"
        mkdir -p "$status_dir"

        tmp_status_file="${HEADLESS_JSON_STATUS_FILE}.tmp.$$"
        printf '%s\n' "$status_payload" > "$tmp_status_file"
        mv "$tmp_status_file" "$HEADLESS_JSON_STATUS_FILE"
    fi
}

handle_headless_interrupt() {
    local rc=130

    echo "" >&2
    echo "[-] Headless pipeline interrupted." >&2
    emit_headless_status "interrupted" "$rc" "${LAST_BUNDLE_DIR:-}" || true
    cleanup_headless_workspace
    exit "$rc"
}
parse_cli_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            -h|--help)
                print_usage
                exit 0
                ;;
            --non-interactive)
                HEADLESS_MODE=1
                shift
                ;;
            --target)
                if [ "$#" -lt 2 ]; then
                    echo "[-] --target requires a CIDR value." >&2
                    exit 1
                fi
                HEADLESS_TARGET="$2"
                shift 2
                ;;
            --greenbone)
                if [ "$#" -lt 2 ]; then
                    echo "[-] --greenbone requires yes or no." >&2
                    exit 1
                fi
                case "$2" in
                    yes|no)
                        HEADLESS_GREENBONE="$2"
                        ;;
                    *)
                        echo "[-] --greenbone must be yes or no." >&2
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            --profile|--scan-profile)
                if [ $# -lt 2 ]; then
                    echo "[-] --profile requires quick, balanced, or accurate." >&2
                    exit 2
                fi
                SCAN_PROFILE="$2"
                shift 2
                ;;
            --json-status)
                JSON_STATUS=1
                shift
                ;;
            --json-status-file)
                if [ "$#" -lt 2 ]; then
                    echo "[-] --json-status-file requires a path." >&2
                    exit 1
                fi
                HEADLESS_JSON_STATUS_FILE="$2"
                shift 2
                ;;
            *)
                echo "[-] Unknown argument: $1" >&2
                echo "Use --help for usage." >&2
                exit 1
                ;;
        esac
    done

    if [ "$HEADLESS_MODE" = "1" ]; then
        if [ -z "$HEADLESS_TARGET" ]; then
            echo "[-] --non-interactive requires --target <private-cidr>." >&2
            emit_headless_status "failed" 1 ""
            exit 1
        fi

        if ! SCAN_PROFILE_RESOLVED_JSON="$(python3 "$BASE/tools/resolve_v1_9_scan_profile.py" "$SCAN_PROFILE" --profiles-file "$SCAN_PROFILE_CONFIG" 2>&1)"; then
            echo "[-] Invalid scan profile: $SCAN_PROFILE" >&2
            echo "$SCAN_PROFILE_RESOLVED_JSON" >&2
            emit_headless_status "failed" 2 ""
            exit 2
        fi

        SCAN_PROFILE_EFFECTIVE="$(printf '%s' "$SCAN_PROFILE_RESOLVED_JSON" | jq -r '.name')"
        case "$SCAN_PROFILE_EFFECTIVE" in
            quick|balanced)
                SCAN_PROFILE_RUNTIME_STAGE="v1_8_compatible_tcp"
                ;;
            accurate)
                SCAN_PROFILE_RUNTIME_STAGE="accurate_tcp_service_depth_os_udp_lite"
                echo "[!] Accurate profile enables TCP service-depth plus non-fatal OS and UDP-lite evidence." >&2
                ;;
            deep)
                echo "[-] Scan profile 'deep' is not supported in NetSniper v2.2.0." >&2
                echo "[-] Use --profile quick, --profile balanced, or --profile accurate until deep scan wiring is validated." >&2
                emit_headless_status "failed" 2 ""
                exit 2
                ;;
            *)
                echo "[-] Unexpected resolved scan profile: $SCAN_PROFILE_EFFECTIVE" >&2
                emit_headless_status "failed" 2 ""
                exit 2
                ;;
        esac


        if ! validate_private_cidr "$HEADLESS_TARGET"; then
            echo "[-] Invalid or unsafe target. Headless mode requires a private IPv4 CIDR with prefix /16 or smaller scope." >&2
            emit_headless_status "failed" 1 ""
            exit 1
        fi

        if [ "$HEADLESS_GREENBONE" = "yes" ]; then
            echo "[-] Headless Greenbone launch is not enabled in NetSniper v2.2.0. Use --greenbone no." >&2
            emit_headless_status "failed" 1 ""
            exit 1
        fi
    fi
}

run_headless_pipeline() {
    NET="$HEADLESS_TARGET"
    GREENBONE_USER=""
    GREENBONE_PASS=""
    prepare_headless_workspace

    trap 'handle_headless_interrupt' INT TERM

    echo "[*] Running NetSniper in headless mode."
    echo "[*] Target: $NET"

    init_workspace
    check_dirs

    local rc
    if run_full_pipeline; then
        if [ -z "$LAST_BUNDLE_DIR" ] || [ ! -f "$LAST_BUNDLE_DIR/manifest.json" ]; then
            echo "[-] Pipeline completed but manifest.json was not found." >&2
            emit_headless_status "failed" 4 "${LAST_BUNDLE_DIR:-}"
            cleanup_headless_workspace
            trap - INT TERM
            return 4
        fi
        echo "[+] Headless pipeline completed."
        echo "[+] Manifest: $LAST_BUNDLE_DIR/manifest.json"
        emit_headless_status "completed" 0 "$LAST_BUNDLE_DIR"
        cleanup_headless_workspace
        trap - INT TERM
        return 0
    else
        rc=$?
    fi

    echo "[-] Headless pipeline failed with return code $rc." >&2
    emit_headless_status "failed" "$rc" "${LAST_BUNDLE_DIR:-}"
    cleanup_headless_workspace
    trap - INT TERM
    return "$rc"
}

init_workspace() {
    mkdir -p "$BASE"
    mkdir -p "$DISCOVERY_DIR"
    mkdir -p "$TARGET_DIR"
    mkdir -p "$SCAN_DIR"
    mkdir -p "$REPORT_DIR"
    mkdir -p "$ANALYSIS_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$RUN_DIR" "$RUNTIME_ROOT" "$BUNDLE_STAGING_ROOT"

    echo "[+] NetSniper workspace initialized at: $BASE"
}

boot_screen() {
    clear

    echo -e "${GREEN}"

    for i in {1..25}; do
        line=$(head /dev/urandom | tr -dc '01' | head -c 80)
        echo "$line"
        sleep 0.03
    done

    sleep 0.3

    tput civis || true

    rows=$(tput lines || echo 25)

    for ((i=0; i<rows; i++)); do
        tput cup $i 0 || true
        printf "%*s" "$(tput cols || echo 80)" " "
        sleep 0.01
    done

    tput clear || clear
    tput cnorm || true

    echo -e "${RED}"
    echo '    _   _ _____ _____ ____  _   _ ___ ____  _____ ____  '
    echo '   | \ | | ____|_   _/ ___|| \ | |_ _|  _ \| ____|  _ \ '
    echo '   |  \| |  _|   | | \___ \|  \| || || |_) |  _| | |_) |'
    echo '   | |\  | |___  | |  ___) | |\  || ||  __/| |___|  _ < '
    printf '%s\n' $'   |_| \\_|_____| |_| |____/|_| \\_|___|_|   |_____|_| \\_\\'
    echo -e "${RESET}"

    echo ""

    messages=(
        "[SYS] Initializing NetSniper engine..."
        "[NET] Preparing discovery modules..."
        "[SCAN] Loading TrueAegis scan profile..."
        "[ANALYSIS] Activating exposure intelligence engine..."
        "[OK] System ready"
    )

    for msg in "${messages[@]}"; do
        echo -e "${GREEN}$msg${RESET}"
        sleep 0.2
    done

    echo ""
    echo -e "${GREEN}[+] NETSNIPER ONLINE${RESET}"
    echo ""
}

gvm_call() {
    local xml="$1"
    local out

    if ! command -v gvm-cli >/dev/null 2>&1; then
        echo "[-] gvm-cli is not installed"
        return 1
    fi
    if [ -z "${GREENBONE_USER:-}" ] || [ -z "${GREENBONE_PASS:-}" ]; then
        echo "[-] Greenbone credentials are not configured"
        return 1
    fi

    if ! out="$({
        set -Eeuo pipefail
        local_config="$(mktemp "${TMPDIR:-/tmp}/netsniper-gvm.XXXXXX")"
        trap 'rm -f -- "$local_config"' EXIT
        chmod 600 "$local_config"
        cat > "$local_config" <<EOF
[gmp]
username=$GREENBONE_USER
password=$GREENBONE_PASS
EOF
        gvm-cli \
            --config "$local_config" \
            socket \
            --socketpath "$SOCK" \
            --xml "$xml"
    })"; then
        echo "[-] gvm-cli failed"
        return 1
    fi

    echo "$out"
}

run_discovery() {
    echo -e "${RED}[1]${RESET} Discovering hosts on $NET..."
    mkdir -p "$DISCOVERY_DIR" "$TARGET_DIR"

    local attempt rc
    for attempt in 1 2; do
        rm -f \
            "$DISCOVERY_DIR/live.gnmap" \
            "$DISCOVERY_DIR/live.nmap" \
            "$DISCOVERY_DIR/live.xml" \
            "$TARGET_DIR/hosts.txt"

        set +e
        nmap -PR -sn "$NET" -oA "$DISCOVERY_DIR/live" > /dev/null 2>&1
        rc=$?
        set -e

        if [ "$rc" -eq 0 ] && [ -s "$DISCOVERY_DIR/live.gnmap" ]; then
            awk '/Up$/{print $2}' "$DISCOVERY_DIR/live.gnmap" | sort -u > "$TARGET_DIR/hosts.txt"
            if [ -s "$TARGET_DIR/hosts.txt" ]; then
                if ! validate_discovered_scope; then
                    echo -e "${RED}[-] Discovery emitted a host outside authorized scope; refusing to continue.${RESET}"
                    return 1
                fi
                echo -e "${GREEN}[+] Discovery complete${RESET}"
                return 0
            fi
        fi

        if [ "$attempt" -eq 1 ]; then
            echo -e "${YELLOW}[!] Discovery returned no usable hosts; retrying once with a clean private workspace.${RESET}" >&2
            sleep 2
        fi
    done

    echo -e "${YELLOW}[!] Discovery completed, but no live hosts were found after two attempts.${RESET}"
    return 1
}

run_scan() {
    if [ ! -s "$TARGET_DIR/hosts.txt" ]; then
        echo -e "${RED}[-] No hosts found. Run discovery first.${RESET}"
        return 1
    fi

    if ! resolve_selected_scan_profile; then
        return 1
    fi

    mkdir -p "$SCAN_DIR"

    # Remove previous outputs first so a failed scan cannot reuse stale evidence.
    rm -f \
        "$SCAN_DIR/fast_scan.gnmap" \
        "$SCAN_DIR/fast_scan.nmap" \
        "$SCAN_DIR/fast_scan.xml" \
        "$SCAN_DIR/os_detection.gnmap" \
        "$SCAN_DIR/os_detection.nmap" \
        "$SCAN_DIR/os_detection.xml" \
        "$SCAN_DIR/udp_lite.gnmap" \
        "$SCAN_DIR/udp_lite.nmap" \
        "$SCAN_DIR/udp_lite.xml"

    echo -e "${PURPLE}[2]${RESET} Running TrueAegis-aligned scan..."
    echo -e "${YELLOW}[*] Ports:${RESET} $TRUEAEGIS_PORTS"

    # v1.8-compatible quick/balanced planner emits: nmap -sV -T4 -p "$TRUEAEGIS_PORTS"
    if ! SCAN_PROFILE_PLAN_JSON="$(python3 "$BASE/tools/plan_v1_9_scan_command.py" "$SCAN_PROFILE_EFFECTIVE" --profiles-file "$SCAN_PROFILE_CONFIG" 2>&1)"; then
        echo -e "${RED}[-] Failed to build scan command plan for profile: $SCAN_PROFILE_EFFECTIVE${RESET}"
        echo "$SCAN_PROFILE_PLAN_JSON" >&2
        return 1
    fi

    PROFILE_RUNTIME_BUDGET_SECONDS="$(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.runtime.runtime_budget_seconds // 0')"
    PROFILE_HOST_TIMEOUT_SECONDS="$(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.runtime.host_timeout_seconds // 0')"
    PROFILE_DURATION_SECONDS=0
    PROFILE_BUDGET_EXCEEDED=false

    if [ "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" -gt 0 ]; then
        echo "[*] Profile runtime budget: ${PROFILE_RUNTIME_BUDGET_SECONDS}s"
    fi

    if [ "${PROFILE_HOST_TIMEOUT_SECONDS:-0}" -gt 0 ]; then
        echo "[*] Profile host-timeout guidance: ${PROFILE_HOST_TIMEOUT_SECONDS}s"
    fi

    mapfile -t TCP_SCAN_ARGS < <(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.tcp.args[]')

    if [ "${#TCP_SCAN_ARGS[@]}" -eq 0 ]; then
        echo -e "${RED}[-] Scan command planner produced no TCP scan arguments.${RESET}"
        return 1
    fi

    for arg_index in "${!TCP_SCAN_ARGS[@]}"; do
        if [ "${TCP_SCAN_ARGS[$arg_index]}" = "\$TRUEAEGIS_PORTS" ]; then
            TCP_SCAN_ARGS[arg_index]="$TRUEAEGIS_PORTS"
        fi
    done

    echo "[*] Using scan profile: $SCAN_PROFILE_EFFECTIVE"

    local scan_started_epoch scan_rc remaining_seconds optional_rc
    scan_started_epoch=$(date +%s)

    if [ "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" -gt 0 ] && command -v timeout >/dev/null 2>&1; then
        timeout "${PROFILE_RUNTIME_BUDGET_SECONDS}s" \
            nmap "${TCP_SCAN_ARGS[@]}" \
            -iL "$TARGET_DIR/hosts.txt" \
            -oA "$SCAN_DIR/fast_scan" \
            > /dev/null 2>&1 &
    else
        if [ "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" -gt 0 ]; then
            echo "[!] timeout command not available; runtime budget will be recorded but not enforced." >&2
        fi

        nmap "${TCP_SCAN_ARGS[@]}" \
            -iL "$TARGET_DIR/hosts.txt" \
            -oA "$SCAN_DIR/fast_scan" \
            > /dev/null 2>&1 &
    fi
    PID=$!

    spin=$'|/-\\'
    i=0
    while kill -0 "$PID" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] Scanning hosts..." "${spin:$i:1}"
        sleep 0.1
    done

    set +e
    wait "$PID"
    scan_rc=$?
    set -e

    if [ "$scan_rc" -ne 0 ]; then
        printf "\r"

        if [ "$scan_rc" -eq 124 ]; then
            PROFILE_BUDGET_EXCEEDED=true
            echo -e "${RED}[-] Service scan exceeded profile runtime budget (${PROFILE_RUNTIME_BUDGET_SECONDS}s).${RESET}"
        else
            echo -e "${RED}[-] Service scan failed.${RESET}"
        fi

        return 1
    fi
    printf "\r"

    if [ ! -s "$SCAN_DIR/fast_scan.gnmap" ] || [ ! -s "$SCAN_DIR/fast_scan.xml" ]; then
        echo -e "${RED}[-] Service scan evidence is missing or empty.${RESET}"
        return 1
    fi

    if ! grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/fast_scan.xml"; then
        echo -e "${RED}[-] Nmap XML did not report a successful completion.${RESET}"
        return 1
    fi

    if [ "$SCAN_PROFILE_EFFECTIVE" = "accurate" ]; then
        if [ "$(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.os_detection.enabled')" = "true" ]; then
            mapfile -t OS_DETECTION_ARGS < <(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.os_detection.args[]')

            if [ "${#OS_DETECTION_ARGS[@]}" -gt 0 ]; then
                echo "[*] Running non-fatal OS evidence pass for accurate profile..."

                remaining_seconds=$((PROFILE_RUNTIME_BUDGET_SECONDS - ($(date +%s) - scan_started_epoch)))
                optional_rc=0
                if [ "$remaining_seconds" -gt 0 ]; then
                    timeout "${remaining_seconds}s" nmap "${OS_DETECTION_ARGS[@]}" --osscan-limit \
                        -iL "$TARGET_DIR/hosts.txt" \
                        -oA "$SCAN_DIR/os_detection" \
                        > /dev/null 2>&1 || optional_rc=$?
                else
                    optional_rc=124
                fi

                if [ "$optional_rc" -eq 0 ] \
                    && [ -s "$SCAN_DIR/os_detection.xml" ] \
                    && grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/os_detection.xml"; then
                    echo "[+] OS evidence pass complete"
                else
                    [ "$optional_rc" -eq 124 ] && PROFILE_BUDGET_EXCEEDED=true
                    rm -f "$SCAN_DIR/os_detection.xml" "$SCAN_DIR/os_detection.gnmap" "$SCAN_DIR/os_detection.nmap"
                    echo "[!] OS evidence pass unavailable or unsuccessful; continuing without OS evidence." >&2
                fi
            fi
        fi
    fi

    if [ "$SCAN_PROFILE_EFFECTIVE" = "accurate" ]; then
        if [ "$(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.udp_lite.enabled')" = "true" ]; then
            mapfile -t UDP_LITE_ARGS < <(printf '%s' "$SCAN_PROFILE_PLAN_JSON" | jq -r '.udp_lite.args[]')

            if [ "${#UDP_LITE_ARGS[@]}" -gt 0 ]; then
                echo "[*] Running non-fatal UDP-lite evidence pass for accurate profile..."

                remaining_seconds=$((PROFILE_RUNTIME_BUDGET_SECONDS - ($(date +%s) - scan_started_epoch)))
                optional_rc=0
                if [ "$remaining_seconds" -gt 0 ]; then
                    timeout "${remaining_seconds}s" nmap "${UDP_LITE_ARGS[@]}" \
                        -iL "$TARGET_DIR/hosts.txt" \
                        -oA "$SCAN_DIR/udp_lite" \
                        > /dev/null 2>&1 || optional_rc=$?
                else
                    optional_rc=124
                fi

                if [ "$optional_rc" -eq 0 ] \
                    && [ -s "$SCAN_DIR/udp_lite.xml" ] \
                    && grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/udp_lite.xml"; then
                    echo "[+] UDP-lite evidence pass complete"
                else
                    [ "$optional_rc" -eq 124 ] && PROFILE_BUDGET_EXCEEDED=true
                    rm -f "$SCAN_DIR/udp_lite.xml" "$SCAN_DIR/udp_lite.gnmap" "$SCAN_DIR/udp_lite.nmap"
                    echo "[!] UDP-lite evidence pass unavailable or unsuccessful; continuing without UDP-lite evidence." >&2
                fi
            fi
        fi
    fi

    PROFILE_DURATION_SECONDS=$(($(date +%s) - scan_started_epoch))
    if [ "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" -gt 0 ] \
        && [ "$PROFILE_DURATION_SECONDS" -ge "$PROFILE_RUNTIME_BUDGET_SECONDS" ]; then
        PROFILE_BUDGET_EXCEEDED=true
    fi

    echo -e "${GREEN}[+] Scan complete${RESET}"
}


ensure_full_inventory_analysis_json() {
    local json_file="$1"
    local hosts_file="$TARGET_DIR/hosts.txt"
    local tmp_file

    if [ ! -s "$json_file" ]; then
        echo -e "${RED}[-] Analysis JSON is missing; cannot preserve full inventory.${RESET}"
        return 1
    fi

    if [ ! -s "$hosts_file" ]; then
        echo -e "${RED}[-] hosts.txt is missing; cannot preserve full inventory.${RESET}"
        return 1
    fi

    tmp_file="${json_file}.full_inventory.tmp"

    jq -n \
        --slurpfile existing "$json_file" \
        --rawfile hosts "$hosts_file" \
        --arg scanner_version "$SCANNER_VERSION" \
        --arg timestamp "$(date +%Y%m%d-%H%M%S)" '
        def host_key($item):
            ($item.host // $item.ip // $item.ip_address // $item.host_id // "");

        def unknown_host($ip):
            {
                host: $ip,
                device_type: "Unknown",
                device_type_confidence: 0,
                severity: "INFO",
                score: 0,
                scanner_version: $scanner_version,
                timestamp: $timestamp,
                classification: {
                    schema_version: "netsniper-classification-v1",
                    type: "Unknown / Ambiguous",
                    primary_type: "Unknown / Ambiguous",
                    confidence: 0,
                    confidence_label: "unknown",
                    confidence_band: "unknown",
                    calibrated_decision: "unknown",
                    siem_action: "no_action",
                    calibration_reason: "Host was discovered alive, but no monitored service evidence was observed during the service scan.",
                    validation_state: "not_applicable",
                    contradiction_count: 0,
                    decision: "unknown",
                    method: "full_inventory_preservation",
                    evidence: [],
                    validators: [],
                    validator_summary: {
                        total: 0,
                        confirmed: 0,
                        inconclusive: 0,
                        refuted: 0,
                        not_applicable: 0,
                        error: 0,
                        names: []
                    },
                    contradictions: [],
                    candidates: [],
                    secondary_candidates: []
                },
                findings: []
            };

        ($existing[0] // []) as $items
        | ($hosts
            | split("\n")
            | map(gsub("^\\s+|\\s+$"; ""))
            | map(select(length > 0))
          ) as $all_hosts
        | ($items | map(host_key(.))) as $seen
        | ($all_hosts | map(select(. as $ip | ($seen | index($ip) | not)))) as $missing
        | ($items + ($missing | map(unknown_host(.))))
        | sort_by(.host // .ip // .ip_address // .host_id)
        ' /dev/null > "$tmp_file"

    mv "$tmp_file" "$json_file"

    local total_count
    local missing_added
    total_count=$(jq 'length' "$json_file")
    missing_added=$(
        comm -23 \
            <(LC_ALL=C sort "$hosts_file") \
            <(jq -r '.[] | .host // .ip // .ip_address // .host_id // empty' "$json_file" | LC_ALL=C sort) \
            | wc -l
    )

    if [ "$missing_added" -ne 0 ]; then
        echo -e "${RED}[-] Full inventory preservation failed; hosts are still missing from analysis JSON.${RESET}"
        return 1
    fi

    echo -e "${GREEN}[+] Full inventory preserved in analysis JSON:${RESET} $total_count hosts"
}


extract_high_risk() {
    echo -e "${YELLOW}[3]${RESET} Extracting TrueAegis-relevant hosts..."

    INPUT="$SCAN_DIR/fast_scan.gnmap"
    OUTPUT="$TARGET_DIR/high_risk.txt"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found. Run scan first.${RESET}"
        return 1
    fi

    # Use token boundaries so 8080/open cannot be mistaken for 80/open.
    awk -v pattern="(^|[[:space:],])(${HIGH_RISK_PATTERN})/" \
        '$0 ~ pattern {print $2}' \
        "$INPUT" \
        | sort -u > "$OUTPUT"

    if [ ! -s "$OUTPUT" ]; then
        echo -e "${YELLOW}[!] No TrueAegis-relevant hosts found.${RESET}"
        return 0
    fi

    echo -e "${GREEN}[+] TrueAegis-relevant hosts:${RESET}"
    cat "$OUTPUT"
}

generate_target_name() {
    DATE=$(date +%Y%m%d-%H%M%S)
    RAND=$(head /dev/urandom | tr -dc a-f0-9 | head -c 4)
    echo "High Risk Internal Network - $DATE - $RAND"
}

import_greenbone() {
    echo -e "${GREEN}[4]${RESET} Importing into Greenbone + launching scan..."

    INPUT="$TARGET_DIR/high_risk.txt"

    if ! command -v gvm-cli >/dev/null 2>&1; then
        echo -e "${RED}[-] gvm-cli is not installed.${RESET}"
        return 1
    fi

    if [ -z "${GREENBONE_USER:-}" ] || [ -z "${GREENBONE_PASS:-}" ]; then
        echo -e "${RED}[-] Greenbone credentials are not configured.${RESET}"
        return 1
    fi

    if [ ! -s "$INPUT" ]; then
        echo -e "${RED}[-] No high-risk hosts found.${RESET}"
        return 1
    fi

    if [ ! -S "$SOCK" ]; then
        echo -e "${RED}[-] Greenbone socket not found.${RESET}"
        return 1
    fi

    HOSTS=$(tr '\n' ',' < "$INPUT" | sed 's/,$//')
    NAME=$(generate_target_name)

    echo "[*] Creating target: $NAME"
    XML="<create_target>
    <name>$NAME</name>
    <hosts>$HOSTS</hosts>
    <port_list id='33d0cd82-57c6-11e1-8ed1-406186ea4fc5'/>
</create_target>"

    TARGET_XML=$(gvm_call "$XML") || return 1
    TARGET_ID=$(echo "$TARGET_XML" | grep -oP 'id="\K[^"]+' | head -n 1)

    if [ -z "$TARGET_ID" ]; then
        echo "[-] Failed to create target"
        return 1
    fi

    echo "[+] Target ID: $TARGET_ID"
    echo "[*] Creating scan task..."

    XML="<create_task>
    <name>NETSNIPER Scan - $NAME</name>
    <config id='daba56c8-73ec-11df-a475-002264764cea'/>
    <target id='$TARGET_ID'/>
    <scanner id='08b69003-5fc2-4037-a479-93b440211c73'/>
</create_task>"

    TASK_XML=$(gvm_call "$XML") || return 1
    TASK_ID=$(echo "$TASK_XML" | grep -oP 'id=\"\K[^\"]+')

    if [ -z "$TASK_ID" ]; then
        echo "[-] Failed to create task"
        return 1
    fi

    echo "[+] Task ID: $TASK_ID"
    echo "[*] Starting scan..."

    if ! gvm_call "<start_task task_id='$TASK_ID'/>" >/dev/null; then
        echo "[-] Failed to start Greenbone task"
        return 1
    fi

    echo -e "${GREEN}[+] Scan launched successfully${RESET}"
}

b64_encode() {
    printf '%s' "$1" | base64 | tr -d '\n'
}

b64_decode() {
    printf '%s' "$1" | base64 --decode 2>/dev/null
}

read_config_value() {
    local key="$1"

    awk -F= -v key="$key" '
        $1 == key {
            print substr($0, index($0, "=") + 1)
            exit
        }
    ' "$CONFIG_FILE"
}

load_saved_config() {
    local format
    local net_b64
    local user_b64
    local pass_b64
    local profile_b64

    format=$(read_config_value "CONFIG_FORMAT")
    if [ "$format" != "NETSNIPER_CONFIG_V2" ]; then
        return 1
    fi

    net_b64=$(read_config_value "NET_B64")
    user_b64=$(read_config_value "GREENBONE_USER_B64")
    pass_b64=$(read_config_value "GREENBONE_PASS_B64")
    profile_b64=$(read_config_value "SCAN_PROFILE_B64")

    if [ -z "$net_b64" ]; then
        return 1
    fi

    NET=$(b64_decode "$net_b64") || return 1
    GREENBONE_USER=$(b64_decode "$user_b64") || return 1
    GREENBONE_PASS=$(b64_decode "$pass_b64") || return 1

    if [ -n "$profile_b64" ]; then
        SCAN_PROFILE=$(b64_decode "$profile_b64") || SCAN_PROFILE="${NETSNIPER_SCAN_PROFILE:-balanced}"
    else
        SCAN_PROFILE="${NETSNIPER_SCAN_PROFILE:-balanced}"
    fi

    resolve_selected_scan_profile || return 1
}

configure_scan_profile() {
    local choice
    local selected

    echo "[*] Select NetSniper scan profile:"
    echo "  1) quick    - TCP-only, fastest profile"
    echo "  2) balanced - default v1.8-compatible TCP profile"
    echo "  3) accurate - deeper TCP plus non-fatal OS and UDP-lite evidence"
    echo "  4) keep current (${SCAN_PROFILE:-balanced})"

    read -r -p "Scan profile [balanced]: " choice
    choice="$(printf '%s' "$choice" | tr '[:upper:]' '[:lower:]')"

    case "$choice" in
        ""|2|balanced|b)
            selected="balanced"
            ;;
        1|quick|q)
            selected="quick"
            ;;
        3|accurate|a)
            selected="accurate"
            ;;
        4|current|keep)
            selected="${SCAN_PROFILE:-balanced}"
            ;;
        deep|d)
            echo "[-] Deep profile is planned but not runtime-enabled in this release."
            echo "[-] Choose quick, balanced, or accurate."
            return 1
            ;;
        *)
            echo "[-] Invalid scan profile selection: $choice"
            return 1
            ;;
    esac

    SCAN_PROFILE="$selected"

    if ! resolve_selected_scan_profile; then
        return 1
    fi

    echo "[+] Scan profile set to: $SCAN_PROFILE_EFFECTIVE"
}

save_config() {
    local net_b64
    local user_b64
    local pass_b64
    local profile_b64

    mkdir -p "$CONFIG_DIR"
    umask 077

    net_b64=$(b64_encode "$NET")
    user_b64=$(b64_encode "$GREENBONE_USER")
    pass_b64=$(b64_encode "$GREENBONE_PASS")
    profile_b64=$(b64_encode "$SCAN_PROFILE")

    cat > "$CONFIG_FILE" <<EOF
CONFIG_FORMAT=NETSNIPER_CONFIG_V2
NET_B64=$net_b64
GREENBONE_USER_B64=$user_b64
GREENBONE_PASS_B64=$pass_b64
SCAN_PROFILE_B64=$profile_b64
EOF

    chmod 600 "$CONFIG_FILE"
    echo "[+] Config saved to $CONFIG_FILE"
    echo "[!] Credentials are permission-protected and Base64-encoded, not encrypted."
}

load_config() {
    local use_saved
    local configure_greenbone

    NET=""
    GREENBONE_USER=""
    GREENBONE_PASS=""

    if [ -f "$CONFIG_FILE" ]; then
        echo "[*] Found saved config."
        read -r -p "Use saved config? (y/n): " use_saved

        if [[ "$use_saved" =~ ^[Yy]$ ]]; then
            if load_saved_config; then
                echo "[+] Using saved configuration"
                return 0
            fi

            echo "[!] Existing config is legacy or invalid. Reconfiguration is required."
        fi
    fi

    echo "[*] NetSniper setup"
    read -r -p "Target network (e.g. 192.168.1.0/24): " NET

    if [ -z "$NET" ]; then
        echo "[-] Target network cannot be empty."
        return 1
    fi

    if ! configure_scan_profile; then
        return 1
    fi

    read -r -p "Configure optional Greenbone integration? (y/n): " configure_greenbone

    if [[ "$configure_greenbone" =~ ^[Yy]$ ]]; then
        read -r -p "Greenbone username: " GREENBONE_USER
        read -r -s -p "Greenbone password: " GREENBONE_PASS
        echo ""
    fi

    save_config
}

check_dirs() {
    for dir in "$BASE" "$DISCOVERY_DIR" "$TARGET_DIR" "$SCAN_DIR" "$REPORT_DIR"; do
        if [ ! -d "$dir" ]; then
            echo "[-] Missing required directory: $dir"
            echo "[*] Create it or check your installation."
            exit 1
        fi
    done
}

# NETSNIPER_RUN_BUNDLE_V1
# NETSNIPER_NEIGHBOR_TELEMETRY_V1
latest_analysis_file() {
    find "$TARGET_DIR" -maxdepth 1 -type f -name 'analysis_*.json' -printf '%T@ %p\n' \
        | sort -nr \
        | head -n 1 \
        | cut -d' ' -f2-
}

latest_analysis_text_file() {
    find "$TARGET_DIR" -maxdepth 1 -type f -name 'analysis_*.txt' -printf '%T@ %p\n' \
        | sort -nr \
        | head -n 1 \
        | cut -d' ' -f2-
}


write_bundle_quality_report() {
    local bundle_dir="$1"

    python3 - "$bundle_dir" <<'PY'
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

bundle_dir = Path(sys.argv[1]).resolve()
manifest_path = bundle_dir / "manifest.json"
quality_path = bundle_dir / "bundle_quality.json"

errors: list[str] = []
warnings: list[str] = []


def read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append(f"{label} is missing: {path.name}")
    except json.JSONDecodeError as exc:
        errors.append(f"{label} is invalid JSON: {exc}")
    return None


manifest = read_json(manifest_path, "manifest")
if not isinstance(manifest, dict):
    manifest = {}

manifest_files = manifest.get("files")
if not isinstance(manifest_files, dict):
    manifest_files = {}
    errors.append("manifest.files is missing or invalid")

required_file_names: list[str] = [
    "manifest.json",
    "hosts.txt",
]

for value in manifest_files.values():
    if isinstance(value, str) and value and value not in required_file_names:
        required_file_names.append(value)

required_file_records = []

for name in required_file_names:
    path = bundle_dir / name
    allow_empty = name == "neighbors.txt"
    exists = path.exists()
    non_empty = exists and path.is_file() and path.stat().st_size > 0

    if not exists:
        errors.append(f"required bundle file missing: {name}")
    elif not allow_empty and not non_empty:
        errors.append(f"required bundle file is empty: {name}")

    required_file_records.append(
        {
            "path": name,
            "exists": exists,
            "non_empty": bool(non_empty),
            "allow_empty": allow_empty,
        }
    )

required_files_present = all(
    item["exists"] and (item["allow_empty"] or item["non_empty"])
    for item in required_file_records
)

hosts_path = bundle_dir / "hosts.txt"
hosts_count = 0

if hosts_path.exists():
    hosts_count = len(
        [
            line
            for line in hosts_path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if line.strip()
        ]
    )

analysis_count = None
analysis = read_json(
    bundle_dir / str(manifest_files.get("analysis_json", "analysis.json")),
    "analysis",
)

if isinstance(analysis, list):
    analysis_count = len(analysis)
else:
    errors.append("analysis.json is not a JSON list")

enriched_count = None
enriched = read_json(
    bundle_dir / str(
        manifest_files.get("analysis_enriched_json", "analysis.enriched.json")
    ),
    "analysis.enriched",
)

if isinstance(enriched, dict) and isinstance(enriched.get("hosts"), list):
    enriched_count = len(enriched["hosts"])
elif isinstance(enriched, list):
    enriched_count = len(enriched)
else:
    errors.append("analysis.enriched.json is not a supported host collection")

counts_valid = (
    isinstance(analysis_count, int)
    and isinstance(enriched_count, int)
    and hosts_count == analysis_count
    and hosts_count == enriched_count
)

if not counts_valid:
    errors.append(
        "host count mismatch: "
        f"hosts.txt={hosts_count}, analysis.json={analysis_count}, "
        f"analysis.enriched.json={enriched_count}"
    )

classification_quality = read_json(
    bundle_dir / str(
        manifest_files.get(
            "classification_quality_json",
            "classification_quality.json",
        )
    ),
    "classification quality",
)

false_confidence_count = None
classification_quality_valid = False

if isinstance(classification_quality, dict):
    false_confidence_count = classification_quality.get(
        "false_confidence_candidate_count",
        0,
    )
    classification_quality_valid = false_confidence_count == 0
    if not classification_quality_valid:
        errors.append(
            "classification quality found false-confidence candidates: "
            f"{false_confidence_count}"
        )
else:
    errors.append("classification_quality.json is not a JSON object")

capability_manifest = read_json(
    bundle_dir / str(
        manifest_files.get("capability_manifest_json", "capability_manifest.json")
    ),
    "capability manifest",
)

host_classifications = read_json(
    bundle_dir / str(
        manifest_files.get("host_classifications_json", "host_classifications.json")
    ),
    "host classifications",
)

v2_1_contract_valid = True
if str(manifest.get("scanner_version", "")).startswith("v2.1"):
    v2_1_contract_valid = (
        isinstance(capability_manifest, dict)
        and capability_manifest.get("schema_version") == "netsniper-capability-manifest-v1"
        and capability_manifest.get("sensor", {}).get("host_classification_schema_version")
            == "netsniper-host-classification-v2"
        and capability_manifest.get("inventory", {}).get("discovered_host_count") == hosts_count
        and capability_manifest.get("inventory", {}).get("emitted_host_count") == enriched_count
        and capability_manifest.get("inventory", {}).get("omitted_host_count") == 0
        and capability_manifest.get("integrity", {}).get("host_inventory_preserved") is True
        and capability_manifest.get("integrity", {}).get("bundle_finalized") is True
        and capability_manifest.get("integrity", {}).get("manifest_complete") is True
        and isinstance(host_classifications, list)
        and len(host_classifications) == hosts_count
        and all(
            isinstance(item, dict)
            and item.get("schema_version") == "netsniper-host-classification-v2"
            for item in host_classifications
        )
    )
    if not v2_1_contract_valid:
        errors.append("v2.1 capability or host-classification contract is invalid")

allowed_profiles = {"quick", "balanced", "accurate"}

requested_profile = manifest.get("requested_profile")
effective_profile = manifest.get("effective_profile")
legacy_requested = manifest.get("scan_profile_requested")
legacy_effective = manifest.get("scan_profile_effective")
profile_contract = manifest.get("profile_contract")

profile_fields_valid = (
    requested_profile in allowed_profiles
    and effective_profile in allowed_profiles
    and profile_contract == "FAST_MONITORED_TCP"
    and requested_profile == legacy_requested
    and effective_profile == legacy_effective
)

if not profile_fields_valid:
    errors.append("profile fields are invalid or legacy aliases do not match")

target = manifest.get("target")
network_scope = manifest.get("network_scope")

target_scope_valid = isinstance(target, str) and bool(target) and target == network_scope

if not target_scope_valid:
    errors.append("target and network_scope are missing or inconsistent")

manifest_valid = (
    manifest.get("schema_version") == "netsniper-run-v3"
    and manifest.get("manifest_contract") == "netsniper-run-v3"
    and manifest.get("legacy_schema_version") == "netsniper-run-v2"
    and isinstance(manifest.get("scan_id"), str)
    and isinstance(manifest.get("scanner_version"), str)
)

if not manifest_valid:
    errors.append("manifest does not satisfy netsniper-run-v3 compatibility requirements")

status_complete = manifest.get("status") == "COMPLETE"

if not status_complete:
    errors.append(f"manifest status is not COMPLETE: {manifest.get('status')}")

budget_exceeded = bool(manifest.get("profile_budget_exceeded", False))

if budget_exceeded:
    warnings.append("profile runtime budget was exceeded")

deltaaegis_ready = all(
    [
        manifest_valid,
        required_files_present,
        counts_valid,
        classification_quality_valid,
        v2_1_contract_valid,
        profile_fields_valid,
        target_scope_valid,
        status_complete,
    ]
)

checked_at = datetime.now(timezone.utc).isoformat()

report = {
    "schema_version": "netsniper-bundle-quality-v1",
    "checked_at": checked_at,
    "bundle_path": str(bundle_dir),
    "manifest_path": str(manifest_path),
    "scan_id": manifest.get("scan_id"),
    "scanner_version": manifest.get("scanner_version"),
    "target": target,
    "network_scope": network_scope,
    "deltaaegis_ready": deltaaegis_ready,
    "manifest_valid": manifest_valid,
    "required_files_present": required_files_present,
    "counts_valid": counts_valid,
    "classification_quality_valid": classification_quality_valid,
    "v2_1_contract_valid": v2_1_contract_valid,
    "profile_fields_valid": profile_fields_valid,
    "target_scope_valid": target_scope_valid,
    "status_complete": status_complete,
    "required_files": required_file_records,
    "counts": {
        "hosts_txt": hosts_count,
        "analysis_json": analysis_count,
        "analysis_enriched_json": enriched_count,
        "classification_false_confidence_candidates": false_confidence_count,
    },
    "profile": {
        "requested_profile": requested_profile,
        "effective_profile": effective_profile,
        "profile_contract": profile_contract,
        "runtime_budget_seconds": manifest.get("profile_runtime_budget_seconds"),
        "host_timeout_seconds": manifest.get("profile_host_timeout_seconds"),
        "duration_seconds": manifest.get("profile_duration_seconds"),
        "budget_exceeded": budget_exceeded,
    },
    "warnings": warnings,
    "errors": errors,
}

quality_path.write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

if not deltaaegis_ready:
    print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
PY
}

# NETSNIPER_MANIFEST_V2
archive_deltaaegis_bundle() {
    local run_id bundle_dir publish_dir manifest_tmp analysis_json analysis_txt
    local archived_at neighbors_captured_at discovered_count relevant_count service_hosts_up
    local profile_ports_json profile_hash profile_fingerprint profile_contract nmap_version discovery_interface
    local service_started_epoch service_completed_epoch service_started_at service_completed_at
    local run_started_at run_completed_at duration_seconds network_scope
    local os_detection_available udp_lite_available

    if ! validate_discovered_scope; then
        echo -e "${RED}[-] Host inventory violates the authorized network scope; refusing to archive telemetry.${RESET}"
        return 1
    fi

    if [ ! -s "$DISCOVERY_DIR/live.xml" ]; then
        echo -e "${RED}[-] Discovery XML is missing; refusing to archive telemetry.${RESET}"
        return 1
    fi
    if [ ! -s "$SCAN_DIR/fast_scan.xml" ]; then
        echo -e "${RED}[-] Service XML is missing; refusing to archive telemetry.${RESET}"
        return 1
    fi
    if ! grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/fast_scan.xml"; then
        echo -e "${RED}[-] Service XML does not report a successful Nmap completion.${RESET}"
        return 1
    fi

    analysis_json=$(latest_analysis_file)
    analysis_txt=$(latest_analysis_text_file)
    if [ -z "$analysis_json" ] || [ ! -s "$analysis_json" ]; then
        echo -e "${RED}[-] Analysis JSON is missing; refusing to archive telemetry.${RESET}"
        return 1
    fi

    run_id="$(date +%Y%m%d-%H%M%S)-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
    publish_dir="$RUN_DIR/$run_id"
    bundle_dir="$BUNDLE_STAGING_ROOT/$run_id"
    if [ -e "$publish_dir" ] || [ -e "$bundle_dir" ]; then
        echo -e "${RED}[-] Collision-resistant run identifier already exists; refusing to overwrite telemetry.${RESET}"
        return 1
    fi
    mkdir -p "$bundle_dir"
    CURRENT_BUNDLE_STAGING="$bundle_dir"

    cp "$DISCOVERY_DIR/live.xml" "$bundle_dir/discovery.xml"
    [ -f "$DISCOVERY_DIR/live.gnmap" ] && cp "$DISCOVERY_DIR/live.gnmap" "$bundle_dir/discovery.gnmap"
    [ -f "$DISCOVERY_DIR/live.nmap" ] && cp "$DISCOVERY_DIR/live.nmap" "$bundle_dir/discovery.nmap"
    cp "$SCAN_DIR/fast_scan.xml" "$bundle_dir/services.xml"
    [ -f "$SCAN_DIR/fast_scan.gnmap" ] && cp "$SCAN_DIR/fast_scan.gnmap" "$bundle_dir/services.gnmap"
    [ -f "$SCAN_DIR/fast_scan.nmap" ] && cp "$SCAN_DIR/fast_scan.nmap" "$bundle_dir/services.nmap"
    os_detection_available=false
    if [ -s "$SCAN_DIR/os_detection.xml" ] \
        && grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/os_detection.xml"; then
        cp "$SCAN_DIR/os_detection.xml" "$bundle_dir/os_detection.xml"
        [ -f "$SCAN_DIR/os_detection.gnmap" ] && cp "$SCAN_DIR/os_detection.gnmap" "$bundle_dir/os_detection.gnmap"
        [ -f "$SCAN_DIR/os_detection.nmap" ] && cp "$SCAN_DIR/os_detection.nmap" "$bundle_dir/os_detection.nmap"
        os_detection_available=true
    fi
    udp_lite_available=false
    if [ -s "$SCAN_DIR/udp_lite.xml" ] \
        && grep -qE '<finished[^>]+exit="success"' "$SCAN_DIR/udp_lite.xml"; then
        cp "$SCAN_DIR/udp_lite.xml" "$bundle_dir/udp_lite.xml"
        [ -f "$SCAN_DIR/udp_lite.gnmap" ] && cp "$SCAN_DIR/udp_lite.gnmap" "$bundle_dir/udp_lite.gnmap"
        [ -f "$SCAN_DIR/udp_lite.nmap" ] && cp "$SCAN_DIR/udp_lite.nmap" "$bundle_dir/udp_lite.nmap"
        udp_lite_available=true
    fi
    cp "$analysis_json" "$bundle_dir/analysis.json"
    [ -n "$analysis_txt" ] && [ -f "$analysis_txt" ] && cp "$analysis_txt" "$bundle_dir/analysis.txt"

    # NetSniper v2.1 artifacts are mandatory and are generated by the same
    # authoritative classifier used by fixture replay. The v1.7 generator is
    # retained only as a historical compatibility tool and is not used here.
    [ -f "$TARGET_DIR/hosts.txt" ] && cp "$TARGET_DIR/hosts.txt" "$bundle_dir/hosts.txt"
    [ -f "$TARGET_DIR/high_risk.txt" ] && cp "$TARGET_DIR/high_risk.txt" "$bundle_dir/high_risk.txt"

    neighbors_captured_at=$(date --iso-8601=seconds)
    if command -v ip >/dev/null 2>&1; then
        ip neigh show > "$bundle_dir/neighbors.txt" 2>/dev/null || : > "$bundle_dir/neighbors.txt"
    else
        : > "$bundle_dir/neighbors.txt"
    fi

    archived_at=$(date --iso-8601=seconds)
    discovered_count=$(wc -l < "$TARGET_DIR/hosts.txt" 2>/dev/null || printf '0')
    relevant_count=$(wc -l < "$TARGET_DIR/high_risk.txt" 2>/dev/null || printf '0')
    service_hosts_up=$(sed -n 's/.*<hosts up="\([0-9][0-9]*\)".*/\1/p' "$SCAN_DIR/fast_scan.xml" | tail -n 1)
    service_hosts_up=${service_hosts_up:-0}
    nmap_version=$(nmap --version 2>/dev/null | awk 'NR == 1 {print $3}')
    discovery_interface=$(ip route show "$NET" 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i == "dev") {print $(i+1); exit}}')
    profile_ports_json=$(printf '%s' "$TRUEAEGIS_PORTS" | tr ',' '\n' | jq -R 'tonumber' | jq -s '.')
    profile_hash=$(printf '%s' "FAST_MONITORED_TCP|tcp|$TRUEAEGIS_PORTS" | sha256sum | awk '{print $1}')
    profile_fingerprint="sha256:$profile_hash"
    profile_contract="FAST_MONITORED_TCP"
    network_scope="$NET"
    service_started_epoch=$(sed -n 's/.*<nmaprun[^>]* start="\([0-9][0-9]*\)".*/\1/p' "$SCAN_DIR/fast_scan.xml" | head -n 1)
    service_completed_epoch=$(sed -n 's/.*<finished[^>]* time="\([0-9][0-9]*\)".*/\1/p' "$SCAN_DIR/fast_scan.xml" | tail -n 1)
    service_started_at=$(date --date="@${service_started_epoch:-0}" --iso-8601=seconds 2>/dev/null || printf '')
    service_completed_at=$(date --date="@${service_completed_epoch:-0}" --iso-8601=seconds 2>/dev/null || printf '')

    run_started_at="$archived_at"
    run_completed_at="$archived_at"
    duration_seconds=0

    if [[ "${service_started_epoch:-}" =~ ^[0-9]+$ ]] && [ "${service_started_epoch:-0}" -gt 0 ]; then
        run_started_at="$service_started_at"
    fi

    if [[ "${service_completed_epoch:-}" =~ ^[0-9]+$ ]] && [ "${service_completed_epoch:-0}" -gt 0 ]; then
        run_completed_at="$service_completed_at"
    fi

    if [[ "${service_started_epoch:-}" =~ ^[0-9]+$ ]] \
        && [[ "${service_completed_epoch:-}" =~ ^[0-9]+$ ]] \
        && [ "${service_completed_epoch:-0}" -ge "${service_started_epoch:-0}" ]; then
        duration_seconds=$((service_completed_epoch - service_started_epoch))
    fi

    manifest_tmp="$bundle_dir/manifest.json.tmp"

    jq -n \
        --arg schema_version "netsniper-run-v2" \
        --arg scan_id "$run_id" \
        --arg scanner_version "$SCANNER_VERSION" \
        --arg scan_profile "FAST_MONITORED_TCP" \
        --arg scan_profile_requested "$SCAN_PROFILE" \
        --arg scan_profile_effective "$SCAN_PROFILE_EFFECTIVE" \
        --arg scan_profile_runtime_stage "$SCAN_PROFILE_RUNTIME_STAGE" \
        --argjson os_detection_available "$os_detection_available" \
        --argjson udp_lite_available "$udp_lite_available" \
        --arg scan_profile_contract_schema "netsniper-scan-profiles-v1" \
        --arg target "$NET" \
        --arg status "COMPLETE" \
        --arg created_at "$archived_at" \
        --arg archived_at "$archived_at" \
        --arg neighbors_captured_at "$neighbors_captured_at" \
        --arg service_started_at "$service_started_at" \
        --arg service_completed_at "$service_completed_at" \
        --arg nmap_version "$nmap_version" \
        --arg discovery_interface "$discovery_interface" \
        --arg profile_fingerprint "$profile_fingerprint" \
        --argjson monitored_ports "$profile_ports_json" \
        --argjson discovered_count "$discovered_count" \
        --argjson relevant_count "$relevant_count" \
        --argjson service_hosts_up "$service_hosts_up" \
        '{
            schema_version: $schema_version,
            scan_id: $scan_id,
            scanner_version: $scanner_version,
            scan_profile: $scan_profile,
            scan_profile_requested: $scan_profile_requested,
            scan_profile_effective: $scan_profile_effective,
            scan_profile_runtime_stage: $scan_profile_runtime_stage,
            os_detection_available: $os_detection_available,
            udp_lite_available: $udp_lite_available,
            scan_profile_contract_schema: $scan_profile_contract_schema,
            target: $target,
            status: $status,
            created_at: $created_at,
            profile: {
                protocols: ["tcp"],
                monitored_ports: $monitored_ports,
                fingerprint: $profile_fingerprint
            },
            timestamps: {
                archived_at: $archived_at,
                neighbors_captured_at: $neighbors_captured_at,
                service_started_at: $service_started_at,
                service_completed_at: $service_completed_at
            },
            telemetry: {
                nmap_version: $nmap_version,
                discovery_interface: $discovery_interface
            },
            counts: {
                discovered_hosts: $discovered_count,
                service_hosts_up: $service_hosts_up,
                relevant_hosts: $relevant_count
            },
            files: {
                discovery_xml: "discovery.xml",
                services_xml: "services.xml",
                os_detection_xml: (if $os_detection_available then "os_detection.xml" else null end),
                os_detection_gnmap: (if $os_detection_available then "os_detection.gnmap" else null end),
                os_detection_nmap: (if $os_detection_available then "os_detection.nmap" else null end),
                udp_lite_xml: (if $udp_lite_available then "udp_lite.xml" else null end),
                udp_lite_gnmap: (if $udp_lite_available then "udp_lite.gnmap" else null end),
                udp_lite_nmap: (if $udp_lite_available then "udp_lite.nmap" else null end),
                analysis_json: "analysis.json",
                analysis_enriched_json: "analysis.enriched.json",
                classification_quality_json: "classification_quality.json",
                classification_quality_markdown: "classification_quality.md",
                capability_manifest_json: "capability_manifest.json",
                host_classifications_json: "host_classifications.json",
                neighbors: "neighbors.txt"
            }
        }' > "$manifest_tmp"

    if ! jq \
        --arg schema_version "netsniper-run-v3" \
        --arg manifest_contract "netsniper-run-v3" \
        --arg legacy_schema_version "netsniper-run-v2" \
        --arg network_scope "$network_scope" \
        --arg requested_profile "$SCAN_PROFILE" \
        --arg effective_profile "$SCAN_PROFILE_EFFECTIVE" \
        --arg profile_contract "$profile_contract" \
        --arg profile_fingerprint "$profile_fingerprint" \
        --arg run_dir "$publish_dir" \
        --arg started_at "$run_started_at" \
        --arg completed_at "$run_completed_at" \
        --argjson duration_seconds "$duration_seconds" \
        --argjson profile_runtime_budget_seconds "${PROFILE_RUNTIME_BUDGET_SECONDS:-0}" \
        --argjson profile_host_timeout_seconds "${PROFILE_HOST_TIMEOUT_SECONDS:-0}" \
        --argjson profile_duration_seconds "${PROFILE_DURATION_SECONDS:-0}" \
        --argjson profile_budget_exceeded "${PROFILE_BUDGET_EXCEEDED:-false}" \
        '
        .schema_version = $schema_version
        | .manifest_contract = $manifest_contract
        | .legacy_schema_version = $legacy_schema_version
        | .network_scope = $network_scope
        | .requested_profile = $requested_profile
        | .effective_profile = $effective_profile
        | .profile_contract = $profile_contract
        | .profile_fingerprint = $profile_fingerprint
        | .run_dir = $run_dir
        | .started_at = $started_at
        | .completed_at = $completed_at
        | .duration_seconds = $duration_seconds
        | .profile_runtime_budget_seconds = $profile_runtime_budget_seconds
        | .profile_host_timeout_seconds = $profile_host_timeout_seconds
        | .profile_duration_seconds = $profile_duration_seconds
        | .profile_budget_exceeded = $profile_budget_exceeded
        | .profile_runtime = {
            runtime_budget_seconds: $profile_runtime_budget_seconds,
            host_timeout_seconds: $profile_host_timeout_seconds,
            duration_seconds: $profile_duration_seconds,
            budget_exceeded: $profile_budget_exceeded
        }
        | .quality = {
            manifest_valid: true,
            required_files_present: true,
            deltaaegis_ready: true,
            warnings: [],
            errors: []
        }
        | .contracts = {
            capability_manifest_version: "netsniper-capability-manifest-v1",
            host_classification_version: "netsniper-host-classification-v2",
            classifier_version: "netsniper-classifier-v2",
            taxonomy_version: "netsniper-device-taxonomy-v2",
            evidence_profile_version: "netsniper-evidence-profiles-v2"
        }
        | .compatibility = {
            legacy_schema_versions: [$legacy_schema_version],
            legacy_scan_profile_field: "scan_profile",
            legacy_requested_profile_field: "scan_profile_requested",
            legacy_effective_profile_field: "scan_profile_effective"
        }
        ' "$manifest_tmp" > "$manifest_tmp.v3"; then
        echo -e "${RED}[-] Failed to enrich manifest with NetSniper v2.0 schema fields.${RESET}"
        return 1
    fi

    mv "$manifest_tmp.v3" "$manifest_tmp"
    mv "$manifest_tmp" "$bundle_dir/manifest.json"

    if [ ! -x "$BASE/tools/generate_v2_1_run_artifacts.py" ]; then
        echo -e "${RED}[-] NetSniper v2.1 artifact generator is missing or not executable.${RESET}"
        return 1
    fi

    local source_commit privilege_context configuration_fingerprint
    source_commit=$(git -C "$BASE" rev-parse HEAD 2>/dev/null || printf '0000000')
    if [ "$(id -u)" -eq 0 ]; then
        privilege_context="privileged"
    else
        privilege_context="unprivileged"
    fi
    configuration_fingerprint=${profile_fingerprint#sha256:}

    echo "[*] Generating mandatory NetSniper v2.1 capability and classification artifacts..."
    if ! python3 "$BASE/tools/generate_v2_1_run_artifacts.py" \
        --bundle-dir "$bundle_dir" \
        --run-id "$run_id" \
        --scanner-version "$SCANNER_VERSION" \
        --source-commit "$source_commit" \
        --target "$NET" \
        --requested-profile "$SCAN_PROFILE" \
        --effective-profile "$SCAN_PROFILE_EFFECTIVE" \
        --started-at "$run_started_at" \
        --completed-at "$run_completed_at" \
        --configuration-fingerprint "$configuration_fingerprint" \
        --privilege-context "$privilege_context" \
        >/dev/null; then
        echo -e "${RED}[-] NetSniper v2.1 artifact generation failed; refusing to finalize telemetry bundle.${RESET}"
        return 1
    fi
    echo "[+] NetSniper v2.1 capability and classification artifacts generated."

    if ! write_bundle_quality_report "$bundle_dir"; then
        echo -e "${RED}[-] Bundle quality validation failed; refusing to finalize telemetry bundle.${RESET}"
        return 1
    fi

    local manifest_quality_tmp
    manifest_quality_tmp="$bundle_dir/manifest.json.quality.tmp"

    if ! jq \
        --slurpfile bundle_quality "$bundle_dir/bundle_quality.json" \
        '.files.hosts = "hosts.txt"
         | .files.bundle_quality_json = "bundle_quality.json"
         | .quality = $bundle_quality[0]' \
        "$bundle_dir/manifest.json" > "$manifest_quality_tmp"; then
        echo -e "${RED}[-] Failed to attach bundle quality report to manifest.${RESET}"
        return 1
    fi

    mv "$manifest_quality_tmp" "$bundle_dir/manifest.json"

    if [ ! -x "$BASE/tools/finalize_v2_1_bundle_integrity.py" ]; then
        echo -e "${RED}[-] NetSniper v2.1 bundle-integrity finalizer is missing or not executable.${RESET}"
        return 1
    fi
    if ! python3 "$BASE/tools/finalize_v2_1_bundle_integrity.py" \
        --bundle-dir "$bundle_dir" \
        >/dev/null; then
        echo -e "${RED}[-] Final bundle-integrity validation failed; refusing to publish telemetry bundle.${RESET}"
        return 1
    fi

    if [ -e "$publish_dir" ]; then
        echo -e "${RED}[-] Final run directory appeared before publication; refusing to overwrite it.${RESET}"
        return 1
    fi
    if ! mv "$bundle_dir" "$publish_dir"; then
        echo -e "${RED}[-] Atomic bundle publication failed.${RESET}"
        return 1
    fi
    CURRENT_BUNDLE_STAGING=""

    LAST_BUNDLE_DIR="$publish_dir"
    echo -e "${GREEN}[+] DeltaAegis telemetry bundle archived:${RESET}"
    echo "$publish_dir"
}

run_full_pipeline() {
    echo ""
    echo "=============================="
    echo " NETSNIPER PIPELINE"
    echo "=============================="

    INFO "Stage 1/5 - Discovery"
    run_discovery || return 1

    INFO "Stage 2/5 - Scanning"
    run_scan || return 1

    INFO "Stage 3/5 - Extracting relevant hosts"
    extract_high_risk || return 1

    INFO "Stage 4/5 - Analysis"
    analyze_hosts || return 1

    INFO "Stage 5/5 - Reporting"
    generate_report || return 1
    archive_deltaaegis_bundle || return 1

    SUCCESS "Pipeline complete"
}

show_targets() {
    echo -e "${BLUE}[*] High Risk Targets:${RESET}"
    if [ ! -f "$TARGET_DIR/high_risk.txt" ]; then
        echo "[!] No high-risk target file exists. Run discovery, scanning, and extraction first."
        return 0
    fi
    cat "$TARGET_DIR/high_risk.txt"
}

analyze_hosts() {
    echo -e "${PURPLE}[*] Running NetSniper v2.2 authoritative exposure and classification analysis...${RESET}"

    local input timestamp analysis_file json_file
    input="$SCAN_DIR/fast_scan.gnmap"

    if [ ! -f "$input" ]; then
        echo -e "${RED}[-] Scan file not found.${RESET}"
        return 1
    fi

    if [ ! -x "$BASE/tools/analyze_v2_1_gnmap.py" ]; then
        echo -e "${RED}[-] NetSniper v2.1 analysis helper is missing or not executable.${RESET}"
        return 1
    fi

    timestamp=$(date +%Y%m%d-%H%M%S)
    analysis_file="$TARGET_DIR/analysis_$timestamp.txt"
    json_file="$TARGET_DIR/analysis_$timestamp.json"

    local args=(
        --gnmap "$input"
        --hosts "$TARGET_DIR/hosts.txt"
        --analysis-json "$json_file"
        --analysis-text "$analysis_file"
        --services-xml "$SCAN_DIR/fast_scan.xml"
        --scanner-version "$SCANNER_VERSION"
        --network "$NET"
        --timestamp "$timestamp"
    )

    local route_context_available=false
    local target_route_address="${NET%%/*}"
    if command -v ip >/dev/null 2>&1; then
        route_context_available=true
        args+=(--route-context -)
    fi

    if [ -s "$SCAN_DIR/os_detection.xml" ]; then
        args+=(--os-xml "$SCAN_DIR/os_detection.xml")
    fi

    if [ -s "$SCAN_DIR/udp_lite.xml" ]; then
        args+=(--udp-xml "$SCAN_DIR/udp_lite.xml")
    fi

    if [ "$route_context_available" = true ]; then
        if ! {
            printf '%s\n' 'NETSNIPER_ROUTE_CONTEXT_V1'
            printf '%s\n' '[target]'
            ip -4 route get "$target_route_address" 2>/dev/null || :
            printf '%s\n' '[default]'
            ip -4 route show default table main 2>/dev/null || :
        } | python3 "$BASE/tools/analyze_v2_1_gnmap.py" "${args[@]}" >/dev/null; then
            echo -e "${RED}[-] NetSniper v2.1 analysis failed.${RESET}"
            return 1
        fi
    elif ! python3 "$BASE/tools/analyze_v2_1_gnmap.py" "${args[@]}" >/dev/null; then
        echo -e "${RED}[-] NetSniper v2.1 analysis failed.${RESET}"
        return 1
    fi

    if ! ensure_full_inventory_analysis_json "$json_file"; then
        return 1
    fi

    echo -e "${GREEN}[+] Analysis complete${RESET}"
    echo -e "${YELLOW}[*] TXT Report:${RESET} $analysis_file"
    echo -e "${YELLOW}[*] JSON Report:${RESET} $json_file"
}

generate_report() {
    echo -e "${BLUE}[*] Generating report...${RESET}"

    mkdir -p "$REPORT_DIR"

    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    REPORT_FILE="$REPORT_DIR/report_$TIMESTAMP.md"

    HOSTS_FILE="$TARGET_DIR/hosts.txt"
    HIGH_RISK_FILE="$TARGET_DIR/high_risk.txt"
    SCAN_FILE="$SCAN_DIR/fast_scan.gnmap"

    if [ ! -f "$HOSTS_FILE" ]; then
        echo -e "${RED}[-] hosts.txt not found${RESET}"
        return 1
    fi

    if [ ! -f "$SCAN_FILE" ]; then
        echo -e "${RED}[-] fast_scan.gnmap not found${RESET}"
        return 1
    fi

    HOST_COUNT=$(wc -l < "$HOSTS_FILE")

    if [ -f "$HIGH_RISK_FILE" ]; then
        HIGH_RISK_COUNT=$(wc -l < "$HIGH_RISK_FILE")
    else
        HIGH_RISK_COUNT=0
    fi

    PORT_SUMMARY=$(
        grep -oE '[0-9]+/open' "$SCAN_FILE" 2>/dev/null \
            | sort \
            | uniq -c \
            | sort -nr \
            || true
    )

    HOST_DETAILS=""

    while read -r line; do
        HOST=$(echo "$line" | awk '{print $2}')

        PORTS=$(echo "$line" \
            | grep -oE '[0-9]+/open/[^,]+' || true)

        FORMATTED_PORTS=$(echo "$PORTS" \
            | sed 's#/tcp##g' \
            | sed 's#//.*##g')

        HOST_DETAILS+="
### $HOST

$FORMATTED_PORTS

"

    done < <(grep "Ports:" "$SCAN_FILE")

    cat > "$REPORT_FILE" <<EOF
# NETSNIPER REPORT

Generated: $TIMESTAMP

Scanner Version: $SCANNER_VERSION

Target Network: $NET

---

## SUMMARY

Hosts Discovered: $HOST_COUNT

TrueAegis-Relevant Hosts: $HIGH_RISK_COUNT

---

## TRUEAEGIS-RELEVANT HOSTS

$(cat "$HIGH_RISK_FILE" 2>/dev/null || echo "No TrueAegis-relevant hosts found.")

---

## OPEN PORT SUMMARY

$PORT_SUMMARY

---

## HOST DETAILS

$HOST_DETAILS

---

## RAW SCAN FILE

$SCAN_FILE

EOF

    echo -e "${GREEN}[+] Report generated successfully${RESET}"
    echo -e "${YELLOW}[*] Report saved to:${RESET}"
    echo "$REPORT_FILE"
}

# =========================
# MENU LOOP
# =========================

# Allows validators to source this file without launching the interactive menu.
if [ "${NETSNIPER_TEST_MODE:-0}" = "1" ]; then
    if [ "${BASH_SOURCE[0]}" != "$0" ]; then
        return 0
    fi
    exit 0
fi

parse_cli_args "$@"

if [ "$HEADLESS_MODE" = "1" ]; then
    run_headless_pipeline
    exit $?
fi

boot_screen
init_workspace
check_dirs
load_config

: "${NET:?Missing NET}"

while true; do
    echo ""
    echo "================================"
    echo "        NETSNIPER v2.2.0"
    echo "        Profile: $SCAN_PROFILE_EFFECTIVE"
    echo "================================"
    echo "  1) Discover Hosts"
    echo "  2) TrueAegis-Aligned Scan"
    echo "  3) Extract TrueAegis-Relevant Hosts"
    echo "  4) Import to Greenbone"
    echo "  5) Run FULL Pipeline"
    echo "  6) Show TrueAegis-Relevant Targets"
    echo "  7) Generate Report"
    echo "  8) Analyze Hosts"
    echo "  9) Change Scan Profile"
    echo "  0) Exit"
    echo "================================"

    read -r -p "netsniper> " opt

    case $opt in
        1) run_discovery || WARN "Discovery did not complete." ;;
        2) run_scan || WARN "Scan did not complete." ;;
        3) extract_high_risk || WARN "Target extraction did not complete." ;;
        4) import_greenbone || WARN "Greenbone import did not complete." ;;
        5) run_full_pipeline || WARN "Pipeline did not complete." ;;
        6) show_targets || WARN "Targets could not be displayed." ;;
        7) generate_report || WARN "Report generation did not complete." ;;
        8) analyze_hosts || WARN "Analysis did not complete." ;;
        9) configure_scan_profile && save_config ;;
        0) echo "Goodbye"; exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
