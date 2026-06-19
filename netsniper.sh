#!/bin/bash

# NetSniper - Network Recon & Exposure Intelligence Engine
# Author: Parker Lee
# License: MIT

# =========================
# NETSNIPER ENGINE v1.5.0
# NETSNIPER_CLASSIFICATION_ENGINE_V150
# TrueAegis-compatible telemetry output
# =========================

set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo -e "\n[ERROR] Failed at line $LINENO while executing $BASH_COMMAND"' ERR

command -v nmap >/dev/null 2>&1 || { echo "nmap required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v base64 >/dev/null 2>&1 || { echo "base64 required"; exit 1; }
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
SOCK="/run/gvmd/gvmd.sock"

SCANNER_VERSION="v1.6.0-dev"

# TrueAegis-aligned scan ports.
# These are the ports NetSniper can reliably identify from nmap grepable output.
TRUEAEGIS_PORTS="21,22,23,25,53,80,88,389,110,139,143,443,445,465,554,587,631,993,995,1433,1521,1900,2375,2376,3000,3306,3389,5000,5432,5555,5601,5900,6379,6443,7547,8000,8080,8081,8443,8888,9000,9090,9100,9200,9300,9443,10250,10255,27017,3268,3269"

HIGH_RISK_PATTERN="21/open|22/open|23/open|25/open|53/open|80/open|88/open|110/open|111/open|135/open|139/open|143/open|161/open|389/open|443/open|445/open|465/open|500/open|554/open|587/open|631/open|993/open|995/open|1433/open|1521/open|1900/open|2049/open|2375/open|2376/open|3000/open|3268/open|3269/open|3306/open|3389/open|4500/open|5000/open|5060/open|5061/open|5432/open|5555/open|5601/open|5900/open|6379/open|6443/open|7547/open|8000/open|8006/open|8080/open|8081/open|8443/open|8888/open|9000/open|9090/open|9100/open|9200/open|9300/open|9443/open|10250/open|10255/open|27017/open"

# =========================
# FUNCTIONS
# =========================

init_workspace() {
    mkdir -p "$BASE"
    mkdir -p "$DISCOVERY_DIR"
    mkdir -p "$TARGET_DIR"
    mkdir -p "$SCAN_DIR"
    mkdir -p "$REPORT_DIR"
    mkdir -p "$ANALYSIS_DIR"
    mkdir -p "$CONFIG_DIR"

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
    echo '   |_| \_|_____| |_| |____/|_| \_|___|_|   |_____|_| \_\'
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

    out=$(gvm-cli \
        --gmp-username "$GREENBONE_USER" \
        --gmp-password "$GREENBONE_PASS" \
        socket \
        --socketpath "$SOCK" \
        --xml "$xml") || {
        echo "[-] gvm-cli failed"
        return 1
    }

    echo "$out"
}

run_with_spinner() {
    local cmd="$1"
    local msg="$2"

    eval "$cmd" &
    PID=$!

    spin='|/-\'
    i=0

    while kill -0 $PID 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] %s" "${spin:$i:1}" "$msg"
        sleep 0.1
    done

    wait $PID
    printf "\r"
}

run_discovery() {
    echo -e "${RED}[1]${RESET} Discovering hosts on $NET..."
    mkdir -p "$DISCOVERY_DIR" "$TARGET_DIR"

    # Remove previous outputs first so a failed scan cannot reuse stale evidence.
    rm -f \
        "$DISCOVERY_DIR/live.gnmap" \
        "$DISCOVERY_DIR/live.nmap" \
        "$DISCOVERY_DIR/live.xml" \
        "$TARGET_DIR/hosts.txt"

    # -oA preserves grepable, normal and XML discovery evidence.
    nmap -PR -sn "$NET" -oA "$DISCOVERY_DIR/live" \
        > /dev/null 2>&1 &
    PID=$!

    spin='|/-\'
    i=0
    while kill -0 "$PID" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] Scanning network..." "${spin:$i:1}"
        sleep 0.1
    done

    if ! wait "$PID"; then
        printf "\r"
        echo -e "${RED}[-] Discovery scan failed.${RESET}"
        return 1
    fi
    printf "\r"

    if [ ! -s "$DISCOVERY_DIR/live.gnmap" ]; then
        echo -e "${RED}[-] Discovery output was not created.${RESET}"
        return 1
    fi

    awk '/Up$/{print $2}' "$DISCOVERY_DIR/live.gnmap" > "$TARGET_DIR/hosts.txt"

    if [ ! -s "$TARGET_DIR/hosts.txt" ]; then
        echo -e "${YELLOW}[!] Discovery completed, but no live hosts were found.${RESET}"
        return 1
    fi

    echo -e "${GREEN}[+] Discovery complete${RESET}"
}

run_scan() {
    if [ ! -s "$TARGET_DIR/hosts.txt" ]; then
        echo -e "${RED}[-] No hosts found. Run discovery first.${RESET}"
        return 1
    fi

    mkdir -p "$SCAN_DIR"

    # Remove previous outputs first so a failed scan cannot reuse stale evidence.
    rm -f \
        "$SCAN_DIR/fast_scan.gnmap" \
        "$SCAN_DIR/fast_scan.nmap" \
        "$SCAN_DIR/fast_scan.xml"

    echo -e "${PURPLE}[2]${RESET} Running TrueAegis-aligned scan..."
    echo -e "${YELLOW}[*] Ports:${RESET} $TRUEAEGIS_PORTS"

    nmap -sV -T4 -p "$TRUEAEGIS_PORTS" \
        -iL "$TARGET_DIR/hosts.txt" \
        -oA "$SCAN_DIR/fast_scan" \
        > /dev/null 2>&1 &
    PID=$!

    spin='|/-\'
    i=0
    while kill -0 "$PID" 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] Scanning hosts..." "${spin:$i:1}"
        sleep 0.1
    done

    if ! wait "$PID"; then
        printf "\r"
        echo -e "${RED}[-] Service scan failed.${RESET}"
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

    echo -e "${GREEN}[+] Scan complete${RESET}"
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

    gvm-cli \
        --gmp-username "$GREENBONE_USER" \
        --gmp-password "$GREENBONE_PASS" \
        socket \
        --socketpath "$SOCK" \
        --xml "<start_task task_id='$TASK_ID'/>" \
        >/dev/null

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

    format=$(read_config_value "CONFIG_FORMAT")
    if [ "$format" != "NETSNIPER_CONFIG_V2" ]; then
        return 1
    fi

    net_b64=$(read_config_value "NET_B64")
    user_b64=$(read_config_value "GREENBONE_USER_B64")
    pass_b64=$(read_config_value "GREENBONE_PASS_B64")

    if [ -z "$net_b64" ]; then
        return 1
    fi

    NET=$(b64_decode "$net_b64") || return 1
    GREENBONE_USER=$(b64_decode "$user_b64") || return 1
    GREENBONE_PASS=$(b64_decode "$pass_b64") || return 1
}

save_config() {
    local net_b64
    local user_b64
    local pass_b64

    mkdir -p "$CONFIG_DIR"
    umask 077

    net_b64=$(b64_encode "$NET")
    user_b64=$(b64_encode "$GREENBONE_USER")
    pass_b64=$(b64_encode "$GREENBONE_PASS")

    cat > "$CONFIG_FILE" <<EOF
CONFIG_FORMAT=NETSNIPER_CONFIG_V2
NET_B64=$net_b64
GREENBONE_USER_B64=$user_b64
GREENBONE_PASS_B64=$pass_b64
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

# NETSNIPER_MANIFEST_V2
archive_deltaaegis_bundle() {
    local run_id bundle_dir manifest_tmp analysis_json analysis_txt
    local archived_at neighbors_captured_at discovered_count relevant_count service_hosts_up
    local profile_ports_json profile_hash nmap_version discovery_interface
    local service_started_epoch service_completed_epoch service_started_at service_completed_at

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

    run_id=$(date +%Y%m%d-%H%M%S)
    bundle_dir="$RUN_DIR/$run_id"
    if [ -e "$bundle_dir" ]; then
        run_id="${run_id}-$$"
        bundle_dir="$RUN_DIR/$run_id"
    fi
    mkdir -p "$bundle_dir"

    cp "$DISCOVERY_DIR/live.xml" "$bundle_dir/discovery.xml"
    [ -f "$DISCOVERY_DIR/live.gnmap" ] && cp "$DISCOVERY_DIR/live.gnmap" "$bundle_dir/discovery.gnmap"
    [ -f "$DISCOVERY_DIR/live.nmap" ] && cp "$DISCOVERY_DIR/live.nmap" "$bundle_dir/discovery.nmap"
    cp "$SCAN_DIR/fast_scan.xml" "$bundle_dir/services.xml"
    [ -f "$SCAN_DIR/fast_scan.gnmap" ] && cp "$SCAN_DIR/fast_scan.gnmap" "$bundle_dir/services.gnmap"
    [ -f "$SCAN_DIR/fast_scan.nmap" ] && cp "$SCAN_DIR/fast_scan.nmap" "$bundle_dir/services.nmap"
    cp "$analysis_json" "$bundle_dir/analysis.json"
    [ -n "$analysis_txt" ] && [ -f "$analysis_txt" ] && cp "$analysis_txt" "$bundle_dir/analysis.txt"
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
    service_started_epoch=$(sed -n 's/.*<nmaprun[^>]* start="\([0-9][0-9]*\)".*/\1/p' "$SCAN_DIR/fast_scan.xml" | head -n 1)
    service_completed_epoch=$(sed -n 's/.*<finished[^>]* time="\([0-9][0-9]*\)".*/\1/p' "$SCAN_DIR/fast_scan.xml" | tail -n 1)
    service_started_at=$(date --date="@${service_started_epoch:-0}" --iso-8601=seconds 2>/dev/null || printf '')
    service_completed_at=$(date --date="@${service_completed_epoch:-0}" --iso-8601=seconds 2>/dev/null || printf '')
    manifest_tmp="$bundle_dir/manifest.json.tmp"

    jq -n \
        --arg schema_version "netsniper-run-v2" \
        --arg scan_id "$run_id" \
        --arg scanner_version "$SCANNER_VERSION" \
        --arg scan_profile "FAST_MONITORED_TCP" \
        --arg target "$NET" \
        --arg status "COMPLETE" \
        --arg created_at "$archived_at" \
        --arg archived_at "$archived_at" \
        --arg neighbors_captured_at "$neighbors_captured_at" \
        --arg service_started_at "$service_started_at" \
        --arg service_completed_at "$service_completed_at" \
        --arg nmap_version "$nmap_version" \
        --arg discovery_interface "$discovery_interface" \
        --arg profile_fingerprint "sha256:$profile_hash" \
        --argjson monitored_ports "$profile_ports_json" \
        --argjson discovered_count "$discovered_count" \
        --argjson relevant_count "$relevant_count" \
        --argjson service_hosts_up "$service_hosts_up" \
        '{
            schema_version: $schema_version,
            scan_id: $scan_id,
            scanner_version: $scanner_version,
            scan_profile: $scan_profile,
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
                analysis_json: "analysis.json",
                neighbors: "neighbors.txt"
            }
        }' > "$manifest_tmp"

    mv "$manifest_tmp" "$bundle_dir/manifest.json"
    echo -e "${GREEN}[+] DeltaAegis telemetry bundle archived:${RESET}"
    echo "$bundle_dir"
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
    cat "$TARGET_DIR/high_risk.txt" 2>/dev/null
}

analyze_hosts() {
    echo -e "${PURPLE}[*] Running TrueAegis-compatible exposure analysis...${RESET}"

    INPUT="$SCAN_DIR/fast_scan.gnmap"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found.${RESET}"
        return 1
    fi

    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    ANALYSIS_FILE="$TARGET_DIR/analysis_$TIMESTAMP.txt"
    JSON_FILE="$TARGET_DIR/analysis_$TIMESTAMP.json"

    : > "$JSON_FILE.tmp"
    : > "$ANALYSIS_FILE"

    {
        echo "========================================="
        echo "         NETSNIPER ANALYSIS"
        echo "========================================="
        echo "Scanner Version: $SCANNER_VERSION"
        echo "Timestamp: $TIMESTAMP"
        echo "Network: $NET"
        echo "Scan File: $INPUT"
        echo "========================================="
        echo ""
    } >> "$ANALYSIS_FILE"

    while read -r line; do
        HOST=$(echo "$line" | awk '{print $2}')

        SCORE=0
        DEVICE_TYPE="Unknown"
        FINDINGS_JSON="[]"

        CLASSIFICATION_EVIDENCE="[]"
        CLASSIFICATION_CONTRADICTIONS="[]"
        CLASSIFICATION_SECONDARY="[]"
        CLASSIFICATION_VALIDATORS="[]"
        CLASSIFICATION_PRIMARY="Unknown / Ambiguous"
        CLASSIFICATION_CONFIDENCE=0
        CLASSIFICATION_LABEL="unknown"
        CLASSIFICATION_BAND="unknown"
        CLASSIFICATION_CALIBRATED_DECISION="unknown"
        CLASSIFICATION_SIEM_ACTION="no_action"
        CLASSIFICATION_CALIBRATION_REASON="No useful classification evidence was found."

        AD_SCORE=0
        CONTAINER_SCORE=0
        ROUTER_GATEWAY_SCORE=0
        AP_SCORE=0
        SWITCH_SCORE=0
        NAS_SCORE=0
        VOIP_SCORE=0
        UPS_SCORE=0
        SECURITY_SCORE=0
        HYPERVISOR_SCORE=0
        WINDOWS_SCORE=0
        WINDOWS_SERVER_SCORE=0
        WINDOWS_WORKSTATION_SCORE=0
        DATABASE_SCORE=0
        PRINTER_SCORE=0
        CAMERA_SCORE=0
        LINUX_WEB_SCORE=0
        LINUX_SERVER_SCORE=0
        DEV_ADMIN_SCORE=0
        IOT_SCORE=0
        WEB_SCORE=0
        NETWORK_SCORE=0
        MAIL_SCORE=0

        has_port() {
            local port="$1"
            local pattern="(^|[[:space:],])${port}/open/"
            [[ "$line" =~ $pattern ]]
        }

        line_has() {
            local pattern="$1"
            printf '%s\n' "$line" | grep -Eiq "$pattern"
        }

        add_finding() {
            local id="$1"
            local name="$2"
            local service="$3"
            local port="$4"
            local score="$5"
            local evidence="$6"

            SCORE=$((SCORE + score))

            FINDINGS_JSON=$(echo "$FINDINGS_JSON" | jq \
                --arg id "$id" \
                --arg name "$name" \
                --arg service "$service" \
                --arg port "$port" \
                --arg score "$score" \
                --arg evidence "$evidence" \
                '. += [{
                    id: $id,
                    name: $name,
                    service: $service,
                    port: ($port | tonumber),
                    score: ($score | tonumber),
                    evidence: $evidence
                }]')
        }

        evidence_reliability() {
            local source="$1"
            local points="$2"

            case "$source" in
                service-text)
                    printf 'high'
                    return
                    ;;
                port-combination)
                    if [ "$points" -ge 35 ]; then
                        printf 'high'
                    elif [ "$points" -ge 20 ]; then
                        printf 'medium'
                    else
                        printf 'low'
                    fi
                    return
                    ;;
            esac

            if [ "$points" -ge 45 ]; then
                printf 'high'
            elif [ "$points" -ge 20 ]; then
                printf 'medium'
            else
                printf 'low'
            fi
        }

        add_classification_evidence() {
            local candidate="$1"
            local source="$2"
            local value="$3"
            local points="$4"
            local reason="$5"
            local reliability

            reliability="$(evidence_reliability "$source" "$points")"

            CLASSIFICATION_EVIDENCE=$(echo "$CLASSIFICATION_EVIDENCE" | jq \
                --arg candidate "$candidate" \
                --arg source "$source" \
                --arg value "$value" \
                --arg points "$points" \
                --arg reason "$reason" \
                --arg reliability "$reliability" \
                '. += [{
                    candidate: $candidate,
                    source: $source,
                    value: $value,
                    points: ($points | tonumber),
                    reliability: $reliability,
                    reason: $reason
                }]')

            case "$candidate" in
                ad) AD_SCORE=$((AD_SCORE + points)) ;;
                kube) CONTAINER_SCORE=$((CONTAINER_SCORE + points)) ;;
                container) CONTAINER_SCORE=$((CONTAINER_SCORE + points)) ;;
                router_gateway) ROUTER_GATEWAY_SCORE=$((ROUTER_GATEWAY_SCORE + points)) ;;
                wireless_ap) AP_SCORE=$((AP_SCORE + points)) ;;
                managed_switch) SWITCH_SCORE=$((SWITCH_SCORE + points)) ;;
                nas) NAS_SCORE=$((NAS_SCORE + points)) ;;
                voip) VOIP_SCORE=$((VOIP_SCORE + points)) ;;
                ups) UPS_SCORE=$((UPS_SCORE + points)) ;;
                security_appliance) SECURITY_SCORE=$((SECURITY_SCORE + points)) ;;
                hypervisor) HYPERVISOR_SCORE=$((HYPERVISOR_SCORE + points)) ;;
                windows) WINDOWS_SCORE=$((WINDOWS_SCORE + points)) ;;
                windows_server) WINDOWS_SERVER_SCORE=$((WINDOWS_SERVER_SCORE + points)) ;;
                windows_workstation) WINDOWS_WORKSTATION_SCORE=$((WINDOWS_WORKSTATION_SCORE + points)) ;;
                database) DATABASE_SCORE=$((DATABASE_SCORE + points)) ;;
                printer) PRINTER_SCORE=$((PRINTER_SCORE + points)) ;;
                camera) CAMERA_SCORE=$((CAMERA_SCORE + points)) ;;
                linux_web) LINUX_WEB_SCORE=$((LINUX_WEB_SCORE + points)) ;;
                linux_server) LINUX_SERVER_SCORE=$((LINUX_SERVER_SCORE + points)) ;;
                dev_admin) DEV_ADMIN_SCORE=$((DEV_ADMIN_SCORE + points)) ;;
                iot) IOT_SCORE=$((IOT_SCORE + points)) ;;
                web) WEB_SCORE=$((WEB_SCORE + points)) ;;
                network) NETWORK_SCORE=$((NETWORK_SCORE + points)) ;;
                mail) MAIL_SCORE=$((MAIL_SCORE + points)) ;;
            esac
        }

        add_classification_contradiction() {
            local value="$1"
            local reason="$2"

            CLASSIFICATION_CONTRADICTIONS=$(echo "$CLASSIFICATION_CONTRADICTIONS" | jq \
                --arg value "$value" \
                --arg reason "$reason" \
                '. += [{
                    value: $value,
                    reason: $reason
                }]')
        }

        confidence_label() {
            local confidence="$1"

            if [ "$confidence" -ge 80 ]; then
                printf 'confirmed'
            elif [ "$confidence" -ge 60 ]; then
                printf 'likely'
            elif [ "$confidence" -ge 40 ]; then
                printf 'possible'
            elif [ "$confidence" -gt 0 ]; then
                printf 'weak'
            else
                printf 'unknown'
            fi
        }

        confidence_band() {
            confidence_label "$1"
        }

        calibrated_decision() {
            local confidence="$1"

            if [ "$confidence" -ge 80 ]; then
                printf 'classified'
            elif [ "$confidence" -ge 60 ]; then
                printf 'likely'
            elif [ "$confidence" -ge 40 ]; then
                printf 'possible'
            elif [ "$confidence" -gt 0 ]; then
                printf 'review_only'
            else
                printf 'unknown'
            fi
        }

        siem_action() {
            local confidence="$1"

            if [ "$confidence" -ge 80 ]; then
                printf 'alert_eligible'
            elif [ "$confidence" -ge 60 ]; then
                printf 'risk_context'
            elif [ "$confidence" -ge 40 ]; then
                printf 'review_queue'
            elif [ "$confidence" -gt 0 ]; then
                printf 'display_only'
            else
                printf 'no_action'
            fi
        }

        calibration_reason() {
            local confidence="$1"

            if [ "$confidence" -ge 80 ]; then
                printf 'Strong evidence supports this classification.'
            elif [ "$confidence" -ge 60 ]; then
                printf 'Multiple or moderately strong evidence supports this classification, but it should still be reviewed.'
            elif [ "$confidence" -ge 40 ]; then
                printf 'Some evidence supports this classification, but it should be treated as possible context only.'
            elif [ "$confidence" -gt 0 ]; then
                printf 'Weak evidence was observed, but there is not enough support to classify the device.'
            else
                printf 'No useful classification evidence was found.'
            fi
        }

        add_classification_validator() {
            local name="$1"
            local status="$2"
            local candidate="$3"
            local confidence_delta="$4"
            local reason="$5"

            CLASSIFICATION_VALIDATORS=$(echo "$CLASSIFICATION_VALIDATORS" | jq \
                --arg name "$name" \
                --arg status "$status" \
                --arg candidate "$candidate" \
                --arg confidence_delta "$confidence_delta" \
                --arg reason "$reason" \
                '. += [{
                    name: $name,
                    status: $status,
                    candidate: $candidate,
                    confidence_delta: ($confidence_delta | tonumber),
                    reason: $reason
                }]')
        }

        # -------------------------
        # TrueAegis Finding Checks
        # -------------------------

        has_port 21 && add_finding "FTP_EXPOSED" "FTP service exposed" "ftp" 21 6 "Port 21 open"
        has_port 22 && add_finding "SSH_EXPOSED" "SSH service exposed" "ssh" 22 3 "Port 22 open"
        has_port 23 && add_finding "TELNET_EXPOSED" "Telnet service exposed" "telnet" 23 10 "Port 23 open"
        has_port 25 && add_finding "SMTP_EXPOSED" "SMTP service exposed" "smtp" 25 4 "Port 25 open"
        has_port 53 && add_finding "DNS_EXPOSED" "DNS service exposed" "dns" 53 4 "Port 53 open"
        has_port 80 && add_finding "HTTP_EXPOSED" "HTTP service exposed" "http" 80 2 "Port 80 open"
        has_port 88 && add_finding "KERBEROS_EXPOSED" "Kerberos service exposed" "kerberos" 88 7 "Port 88 open"
        has_port 389 && add_finding "LDAP_EXPOSED" "LDAP service exposed" "ldap" 389 6 "Port 389 open"
        has_port 110 && add_finding "POP3_EXPOSED" "POP3 service exposed" "pop3" 110 4 "Port 110 open"
        has_port 139 && add_finding "NETBIOS_SMB_EXPOSED" "NetBIOS/SMB service exposed" "netbios-ssn" 139 5 "Port 139 open"
        has_port 143 && add_finding "IMAP_EXPOSED" "IMAP service exposed" "imap" 143 4 "Port 143 open"
        has_port 443 && add_finding "HTTPS_EXPOSED" "HTTPS service exposed" "https" 443 2 "Port 443 open"
        has_port 445 && add_finding "SMB_EXPOSED" "SMB service exposed" "smb" 445 8 "Port 445 open"
        has_port 465 && add_finding "SMTPS_EXPOSED" "SMTPS service exposed" "smtps" 465 3 "Port 465 open"
        has_port 554 && add_finding "RTSP_EXPOSED" "RTSP camera/service exposed" "rtsp" 554 5 "Port 554 open"
        has_port 587 && add_finding "SMTP_SUBMISSION_EXPOSED" "SMTP submission service exposed" "smtp-submission" 587 3 "Port 587 open"
        has_port 631 && add_finding "IPP_EXPOSED" "IPP printing service exposed" "ipp" 631 4 "Port 631 open"
        has_port 993 && add_finding "IMAPS_EXPOSED" "IMAPS service exposed" "imaps" 993 3 "Port 993 open"
        has_port 995 && add_finding "POP3S_EXPOSED" "POP3S service exposed" "pop3s" 995 3 "Port 995 open"
        has_port 1433 && add_finding "MSSQL_EXPOSED" "Microsoft SQL Server exposed" "mssql" 1433 8 "Port 1433 open"
        has_port 1521 && add_finding "ORACLE_EXPOSED" "Oracle database service exposed" "oracle" 1521 8 "Port 1521 open"
        has_port 1900 && add_finding "UPNP_EXPOSED" "UPnP service exposed" "upnp" 1900 5 "Port 1900 open"
        has_port 2375 && add_finding "DOCKER_API_EXPOSED" "Docker API exposed" "docker-api" 2375 10 "Port 2375 open"
        has_port 2376 && add_finding "DOCKER_TLS_EXPOSED" "Docker TLS API exposed" "docker-api-tls" 2376 8 "Port 2376 open"
        has_port 3000 && add_finding "GRAFANA_EXPOSED" "Grafana or web dashboard service exposed" "grafana" 3000 6 "Port 3000 open"
        has_port 3306 && add_finding "MYSQL_EXPOSED" "MySQL database service exposed" "mysql" 3306 8 "Port 3306 open"
        has_port 3389 && add_finding "RDP_EXPOSED" "RDP service exposed" "rdp" 3389 8 "Port 3389 open"
        has_port 5000 && add_finding "DOCKER_REGISTRY_EXPOSED" "Docker Registry or web service exposed" "docker-registry" 5000 7 "Port 5000 open"
        has_port 5432 && add_finding "POSTGRES_EXPOSED" "PostgreSQL database service exposed" "postgresql" 5432 8 "Port 5432 open"
        has_port 5555 && add_finding "ADB_EXPOSED" "Android Debug Bridge exposed" "adb" 5555 9 "Port 5555 open"
        has_port 5601 && add_finding "KIBANA_EXPOSED" "Kibana service exposed" "kibana" 5601 7 "Port 5601 open"
        has_port 5900 && add_finding "VNC_EXPOSED" "VNC service exposed" "vnc" 5900 8 "Port 5900 open"
        has_port 6379 && add_finding "REDIS_EXPOSED" "Redis service exposed" "redis" 6379 9 "Port 6379 open"
        has_port 6443 && add_finding "KUBERNETES_API_EXPOSED" "Kubernetes API exposed" "kubernetes-api" 6443 9 "Port 6443 open"
        has_port 7547 && add_finding "TR069_EXPOSED" "TR-069/CPE management service exposed" "tr-069" 7547 7 "Port 7547 open"
        has_port 8000 && add_finding "HTTP_ALT_EXPOSED" "Alternate HTTP service exposed" "http-alt" 8000 3 "Port 8000 open"
        has_port 8080 && add_finding "HTTP_ALT_EXPOSED" "Alternate HTTP service exposed" "http-alt" 8080 3 "Port 8080 open"
        has_port 8081 && add_finding "JENKINS_EXPOSED" "Jenkins or alternate web service exposed" "jenkins" 8081 8 "Port 8081 open"
        has_port 8443 && add_finding "HTTPS_ALT_EXPOSED" "Alternate HTTPS service exposed" "https-alt" 8443 3 "Port 8443 open"
        has_port 8888 && add_finding "HTTP_ALT_EXPOSED" "Alternate HTTP service exposed" "http-alt" 8888 3 "Port 8888 open"
        has_port 9000 && add_finding "PORTAINER_CANDIDATE" "Possible Portainer or alternate TCP 9000 service" "portainer-candidate" 9000 2 "Port 9000 open; Portainer fingerprint validation required"
        has_port 9090 && add_finding "PROMETHEUS_EXPOSED" "Prometheus service exposed" "prometheus" 9090 6 "Port 9090 open"
        has_port 9100 && add_finding "PRINTER_9100_EXPOSED" "Raw printer service exposed" "printer-raw" 9100 4 "Port 9100 open"
        has_port 9200 && add_finding "ELASTICSEARCH_EXPOSED" "Elasticsearch service exposed" "elasticsearch" 9200 8 "Port 9200 open"
        has_port 9300 && add_finding "ELASTICSEARCH_TRANSPORT_EXPOSED" "Elasticsearch transport service exposed" "elasticsearch-transport" 9300 7 "Port 9300 open"
        has_port 9443 && add_finding "PORTAINER_CANDIDATE" "Possible Portainer or alternate HTTPS 9443 service" "portainer-candidate" 9443 3 "Port 9443 open; Portainer fingerprint validation required"
        has_port 10250 && add_finding "KUBELET_EXPOSED" "Kubelet service exposed" "kubelet" 10250 10 "Port 10250 open"
        has_port 10255 && add_finding "KUBELET_READONLY_EXPOSED" "Kubelet read-only service exposed" "kubelet-readonly" 10255 9 "Port 10255 open"
        has_port 27017 && add_finding "MONGODB_EXPOSED" "MongoDB service exposed" "mongodb" 27017 8 "Port 27017 open"
        has_port 3268 && add_finding "LDAP_GLOBAL_CATALOG_EXPOSED" "LDAP Global Catalog exposed" "ldap-gc" 3268 7 "Port 3268 open"
        has_port 3269 && add_finding "LDAPS_GLOBAL_CATALOG_EXPOSED" "LDAPS Global Catalog exposed" "ldaps-gc" 3269 7 "Port 3269 open"

        # -------------------------
        # Device Classification
        # -------------------------

        # Weighted evidence-based classification.
        # This preserves broad compatibility while adding explainable classification data.

        # v1.5 service-text classification evidence.
        # These checks use nmap service/version strings when available.
        line_has 'synology|diskstation|qnap|truenas|freenas|openmediavault' && add_classification_evidence "nas" "service-text" "storage-product" 45 "Storage appliance product text suggests NAS/File Server role"
        line_has 'hp laserjet|jetdirect|brother|canon|epson|xerox|printer|ipp|cups' && add_classification_evidence "printer" "service-text" "printer-product" 45 "Printer product or protocol text suggests network printer role"
        line_has 'reolink|hikvision|dahua|axis|amcrest|onvif|nvr|dvr|ip camera' && add_classification_evidence "camera" "service-text" "camera-product" 45 "Camera/NVR product text suggests IP Camera or NVR role"
        line_has 'ubiquiti|unifi|aruba|ruckus|meraki|access point|wireless ap' && add_classification_evidence "wireless_ap" "service-text" "ap-product" 45 "Wireless/AP product text suggests wireless access point role"
        line_has 'cisco|procurve|edgeswitch|switch device|managed switch' && add_classification_evidence "managed_switch" "service-text" "switch-product" 40 "Switch product text suggests managed network infrastructure"
        line_has 'apc|eaton|cyberpower|tripplite|ups|pdu|network management card' && add_classification_evidence "ups" "service-text" "power-product" 45 "Power-management product text suggests UPS or PDU role"
        line_has 'pfsense|fortinet|sonicwall|palo alto|sophos|watchguard|firewall|vpn gateway' && add_classification_evidence "security_appliance" "service-text" "security-product" 45 "Firewall/VPN product text suggests security appliance role"
        line_has 'proxmox|vmware|esxi|vcenter|hyper-v|xenserver|virtual environment' && add_classification_evidence "hypervisor" "service-text" "hypervisor-product" 50 "Virtualization product text suggests hypervisor role"
        line_has 'jenkins|grafana|prometheus|kibana|gitlab|gitea|jupyter|webmin|cockpit|phpmyadmin|adminer' && add_classification_evidence "dev_admin" "service-text" "admin-tool" 45 "Admin/development tool text suggests development or admin interface"
        line_has 'esp32|espressif|arduino|embedded|iot device|microcontroller' && add_classification_evidence "iot" "service-text" "embedded-product" 45 "Embedded product text suggests IoT or embedded device role"
        line_has 'nginx|apache httpd|tomcat|iis|gunicorn|node.js|express' && add_classification_evidence "web" "service-text" "web-server-product" 35 "Web server product text strengthens web application host role"
        line_has 'microsoft windows server|active directory|domain controller' && add_classification_evidence "windows_server" "service-text" "windows-server-product" 45 "Windows Server or directory-service text strengthens server classification"
        line_has 'ubuntu|debian|centos|red hat|rocky linux|alma linux|openssh' && add_classification_evidence "linux_server" "service-text" "linux-unix-product" 25 "Linux/Unix service text strengthens Linux server classification"

        if has_port 88 && has_port 389 && has_port 445; then
            add_classification_evidence "windows_server" "port-combination" "tcp/88+389+445" 95 "Kerberos, LDAP, and SMB together strongly suggest Windows Server or domain controller infrastructure"
        fi
        if has_port 53 && has_port 88; then
            add_classification_evidence "windows_server" "port-combination" "tcp/53+88" 30 "DNS plus Kerberos suggests Windows Server infrastructure"
        fi
        has_port 389 && add_classification_evidence "windows_server" "port" "tcp/389" 25 "LDAP service may indicate server directory role"
        has_port 3268 && add_classification_evidence "windows_server" "port" "tcp/3268" 35 "Active Directory Global Catalog service detected"
        has_port 3269 && add_classification_evidence "windows_server" "port" "tcp/3269" 35 "Active Directory LDAPS Global Catalog service detected"

        has_port 6443 && add_classification_evidence "kube" "port" "tcp/6443" 55 "Kubernetes API service detected"
        has_port 10250 && add_classification_evidence "kube" "port" "tcp/10250" 45 "Kubelet service detected"
        has_port 10255 && add_classification_evidence "kube" "port" "tcp/10255" 35 "Kubelet read-only service detected"

        has_port 2375 && add_classification_evidence "container" "port" "tcp/2375" 60 "Docker API service detected"
        has_port 2376 && add_classification_evidence "container" "port" "tcp/2376" 50 "Docker TLS API service detected"
        has_port 5000 && add_classification_evidence "container" "port" "tcp/5000" 35 "Docker Registry or container-adjacent web service detected"
        has_port 9000 && add_classification_evidence "container" "port" "tcp/9000" 25 "Container/admin console candidate detected"
        has_port 9443 && add_classification_evidence "container" "port" "tcp/9443" 25 "Container/admin TLS console candidate detected"

        if has_port 6443 && (has_port 10250 || has_port 10255); then
            add_classification_evidence "container" "port-combination" "k8s-api+kubelet" 30 "Kubernetes API plus kubelet service strongly suggests container infrastructure"
        fi
        if (has_port 2375 || has_port 2376) && (has_port 9000 || has_port 9443); then
            add_classification_evidence "container" "port-combination" "docker+admin-console" 25 "Docker API plus admin console strengthens container infrastructure likelihood"
        fi

        has_port 445 && add_classification_evidence "windows_workstation" "port" "tcp/445" 25 "SMB service is commonly associated with Windows hosts and file sharing"
        has_port 3389 && add_classification_evidence "windows_workstation" "port" "tcp/3389" 25 "RDP service is commonly associated with Windows hosts"
        has_port 139 && add_classification_evidence "windows_workstation" "port" "tcp/139" 10 "NetBIOS/SMB service detected"
        has_port 135 && add_classification_evidence "windows_workstation" "port" "tcp/135" 15 "Microsoft RPC service detected"
        if has_port 445 && has_port 3389 && ! has_port 88 && ! has_port 389; then
            add_classification_evidence "windows_workstation" "port-combination" "tcp/445+3389" 20 "SMB plus RDP without directory services suggests Windows workstation or standalone Windows host"
        fi

        has_port 1433 && add_classification_evidence "database" "port" "tcp/1433" 45 "Microsoft SQL Server port detected"
        has_port 1521 && add_classification_evidence "database" "port" "tcp/1521" 45 "Oracle database port detected"
        has_port 3306 && add_classification_evidence "database" "port" "tcp/3306" 45 "MySQL database port detected"
        has_port 5432 && add_classification_evidence "database" "port" "tcp/5432" 45 "PostgreSQL database port detected"
        has_port 6379 && add_classification_evidence "database" "port" "tcp/6379" 40 "Redis service detected"
        has_port 9200 && add_classification_evidence "database" "port" "tcp/9200" 45 "Elasticsearch HTTP service detected"
        has_port 9300 && add_classification_evidence "database" "port" "tcp/9300" 35 "Elasticsearch transport service detected"
        has_port 27017 && add_classification_evidence "database" "port" "tcp/27017" 45 "MongoDB database port detected"

        if has_port 9200 && has_port 9300; then
            add_classification_evidence "database" "port-combination" "elasticsearch-http+transport" 25 "Elasticsearch HTTP plus transport ports strongly suggest database/search infrastructure"
        fi
        if has_port 3306 && has_port 5432; then
            add_classification_evidence "database" "port-combination" "mysql+postgresql" 25 "Multiple relational database services suggest database server role"
        fi
        if (has_port 3306 || has_port 5432) && has_port 6379; then
            add_classification_evidence "database" "port-combination" "rdbms+redis" 20 "Relational database plus Redis suggests database or application data host"
        fi

        has_port 9100 && add_classification_evidence "printer" "port" "tcp/9100" 55 "Raw JetDirect-style printer service detected"
        has_port 631 && add_classification_evidence "printer" "port" "tcp/631" 40 "IPP printing service detected"

        has_port 554 && add_classification_evidence "camera" "port" "tcp/554" 60 "RTSP service commonly indicates camera, NVR, DVR, or media streaming device"
        if has_port 554 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "camera" "port-combination" "tcp/554+web" 20 "RTSP plus web management surface strengthens camera/NVR likelihood"
        fi

        has_port 22 && add_classification_evidence "linux_server" "port" "tcp/22" 20 "SSH service commonly indicates Linux, Unix, network appliance, or administrative endpoint"
        has_port 111 && add_classification_evidence "linux_server" "port" "tcp/111" 25 "rpcbind service suggests Unix/Linux service role"
        if has_port 22 && has_port 2049; then
            add_classification_evidence "linux_server" "port-combination" "ssh+nfs" 45 "SSH plus NFS suggests Linux or Unix server role"
        fi
        if has_port 22 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "linux_server" "port-combination" "ssh+web" 20 "SSH plus web service suggests Linux server, Unix server, or web appliance"
        fi


        # v1.5 Development/Admin Interface evidence.
        has_port 3000 && add_classification_evidence "dev_admin" "port" "tcp/3000" 25 "Common development, dashboard, or admin web service detected"
        has_port 5601 && add_classification_evidence "dev_admin" "port" "tcp/5601" 45 "Kibana-style admin or observability service detected"
        has_port 9090 && add_classification_evidence "dev_admin" "port" "tcp/9090" 35 "Prometheus-style monitoring or admin service detected"
        if has_port 3000 && has_port 9090; then
            add_classification_evidence "dev_admin" "port-combination" "tcp/3000+9090" 25 "Grafana/Prometheus-style combination suggests development or admin interface"
        fi
        if has_port 5601 && (has_port 9200 || has_port 9300); then
            add_classification_evidence "dev_admin" "port-combination" "kibana+elasticsearch" 25 "Kibana plus Elasticsearch ports suggest observability or admin stack"
        fi

        # v1.5 IoT/Embedded Device evidence.
        has_port 5555 && add_classification_evidence "iot" "port" "tcp/5555" 35 "ADB-like or embedded debug service detected"
        if has_port 1900 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "iot" "port-combination" "upnp+web" 25 "UPnP/SSDP-like service plus web management can indicate embedded or IoT appliance behavior"
        fi
        if has_port 7547 && (has_port 80 || has_port 443); then
            add_classification_evidence "iot" "port-combination" "tr069+web" 15 "TR-069 plus web management can indicate embedded CPE or managed appliance behavior"
        fi

        has_port 80 && add_classification_evidence "web" "port" "tcp/80" 10 "HTTP service detected; treated as weak web-interface evidence"
        has_port 443 && add_classification_evidence "web" "port" "tcp/443" 10 "HTTPS service detected; treated as weak web-interface evidence"
        has_port 8000 && add_classification_evidence "web" "port" "tcp/8000" 8 "Alternate HTTP service detected; treated as weak web-interface evidence"
        has_port 8080 && add_classification_evidence "web" "port" "tcp/8080" 8 "Alternate HTTP service detected; treated as weak web-interface evidence"
        has_port 8443 && add_classification_evidence "web" "port" "tcp/8443" 8 "Alternate HTTPS service detected; treated as weak web-interface evidence"
        has_port 8888 && add_classification_evidence "web" "port" "tcp/8888" 8 "Alternate HTTP service detected; treated as weak web-interface evidence"


        # v1.5 Router/Gateway evidence.
        has_port 7547 && add_classification_evidence "router_gateway" "port" "tcp/7547" 60 "TR-069/CPE management service suggests router, gateway, modem, or ISP-managed device"
        if has_port 53 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "router_gateway" "port-combination" "dns+web" 30 "DNS plus web management suggests gateway or network appliance"
        fi
        if has_port 1900 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "router_gateway" "port-combination" "upnp+web" 25 "UPnP/SSDP-like service plus web management suggests gateway, router, or embedded network appliance"
        fi


        # v1.5 Wireless AP and Managed Switch evidence.
        has_port 161 && add_classification_evidence "managed_switch" "port" "tcp-or-udp/161" 25 "SNMP service suggests managed switch, network infrastructure, UPS, printer, router, or appliance"
        if has_port 161 && has_port 22; then
            add_classification_evidence "managed_switch" "port-combination" "snmp+ssh" 35 "SNMP plus SSH strongly suggests managed network infrastructure"
        fi
        if has_port 161 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "managed_switch" "port-combination" "snmp+web" 25 "SNMP plus web management suggests managed network infrastructure"
        fi
        if has_port 1900 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "wireless_ap" "port-combination" "upnp+web" 25 "UPnP/SSDP-like service plus web management can indicate wireless AP or embedded network infrastructure"
        fi

        # v1.5 NAS/File Server evidence.
        has_port 2049 && add_classification_evidence "nas" "port" "tcp/2049" 55 "NFS service suggests NAS, file server, or Unix file-sharing role"
        if has_port 445 && has_port 2049; then
            add_classification_evidence "nas" "port-combination" "smb+nfs" 40 "SMB plus NFS strongly suggests NAS or file server"
        fi
        if has_port 445 && has_port 5000 && ! has_port 2375 && ! has_port 2376; then
            add_classification_evidence "nas" "port-combination" "smb+tcp/5000" 20 "SMB plus TCP/5000 may indicate NAS management when Docker API is absent"
        fi


        # v1.5 VoIP/PBX evidence.
        has_port 5060 && add_classification_evidence "voip" "port" "tcp-or-udp/5060" 65 "SIP service suggests VoIP endpoint or PBX"
        has_port 5061 && add_classification_evidence "voip" "port" "tcp-or-udp/5061" 65 "SIP TLS service suggests VoIP endpoint or PBX"
        if (has_port 5060 || has_port 5061) && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            add_classification_evidence "voip" "port-combination" "sip+web" 20 "SIP plus web management strengthens VoIP phone or PBX likelihood"
        fi

        # v1.5 UPS/Power Device evidence.
        has_port 161 && add_classification_evidence "ups" "port" "tcp-or-udp/161" 20 "SNMP service may indicate UPS, PDU, switch, router, printer, or managed appliance"
        if has_port 161 && (has_port 80 || has_port 443); then
            add_classification_evidence "ups" "port-combination" "snmp+web" 25 "SNMP plus web management may indicate UPS, PDU, or managed power device, but requires vendor/title confirmation"
        fi


        # v1.5 Security Appliance evidence.
        has_port 500 && add_classification_evidence "security_appliance" "port" "udp-or-tcp/500" 40 "IKE/IPsec service suggests VPN or security gateway"
        has_port 4500 && add_classification_evidence "security_appliance" "port" "udp-or-tcp/4500" 40 "IPsec NAT traversal service suggests VPN or security gateway"
        if (has_port 500 || has_port 4500) && (has_port 443 || has_port 8443); then
            add_classification_evidence "security_appliance" "port-combination" "vpn+https" 35 "VPN-related service plus HTTPS management suggests security appliance"
        fi

        # v1.5 Hypervisor/Virtualization evidence.
        has_port 8006 && add_classification_evidence "hypervisor" "port" "tcp/8006" 65 "Proxmox management port detected"
        has_port 5900 && add_classification_evidence "hypervisor" "port" "tcp/5900" 25 "VNC console service may indicate virtualization or remote console role"
        if has_port 8006 && has_port 22; then
            add_classification_evidence "hypervisor" "port-combination" "tcp/8006+22" 25 "Hypervisor management plus SSH strengthens virtualization host likelihood"
        fi

        has_port 53 && add_classification_evidence "network" "port" "tcp/53" 35 "DNS service suggests infrastructure or DNS server role"
        has_port 1900 && add_classification_evidence "network" "port" "tcp/1900" 20 "UPnP/SSDP service suggests infrastructure, embedded, or appliance behavior"
        has_port 7547 && add_classification_evidence "network" "port" "tcp/7547" 45 "TR-069/CPE management service suggests router, gateway, or ISP-managed device"

        has_port 25 && add_classification_evidence "mail" "port" "tcp/25" 35 "SMTP service detected"
        has_port 465 && add_classification_evidence "mail" "port" "tcp/465" 25 "SMTPS service detected"
        has_port 587 && add_classification_evidence "mail" "port" "tcp/587" 25 "SMTP submission service detected"
        has_port 110 && add_classification_evidence "mail" "port" "tcp/110" 20 "POP3 service detected"
        has_port 143 && add_classification_evidence "mail" "port" "tcp/143" 20 "IMAP service detected"
        has_port 993 && add_classification_evidence "mail" "port" "tcp/993" 20 "IMAPS service detected"
        has_port 995 && add_classification_evidence "mail" "port" "tcp/995" 20 "POP3S service detected"

        if (has_port 9100 || has_port 631) && has_port 3389; then
            add_classification_contradiction "printer+rDP" "Printer-like services detected, but RDP is also open; classification confidence should be reviewed"
        fi

        if has_port 554 && (has_port 445 || has_port 3389); then
            add_classification_contradiction "camera+windows-services" "Camera/RTSP-like service detected with SMB or RDP; this may indicate misclassification or risky service exposure"
        fi

        if has_port 53 && (has_port 1433 || has_port 3306 || has_port 5432 || has_port 27017); then
            add_classification_contradiction "infrastructure+database" "Infrastructure-like DNS service detected with database exposure; review asset role"
        fi

        CLASSIFICATION_PRIMARY="Unknown / Ambiguous"
        CLASSIFICATION_CONFIDENCE=0

        update_best_candidate() {
            local label="$1"
            local confidence="$2"

            if [ "$confidence" -gt "$CLASSIFICATION_CONFIDENCE" ]; then
                CLASSIFICATION_PRIMARY="$label"
                CLASSIFICATION_CONFIDENCE="$confidence"
            fi
        }

        update_best_candidate "Windows Server" "$WINDOWS_SERVER_SCORE"
        update_best_candidate "Container Infrastructure" "$CONTAINER_SCORE"
        update_best_candidate "Router / Gateway" "$ROUTER_GATEWAY_SCORE"
        update_best_candidate "Wireless Access Point" "$AP_SCORE"
        update_best_candidate "Managed Switch / Network Infrastructure" "$SWITCH_SCORE"
        update_best_candidate "NAS / File Server" "$NAS_SCORE"
        update_best_candidate "VoIP Phone / PBX" "$VOIP_SCORE"
        update_best_candidate "UPS / Power Device" "$UPS_SCORE"
        update_best_candidate "Security Appliance" "$SECURITY_SCORE"
        update_best_candidate "Hypervisor / Virtualization Host" "$HYPERVISOR_SCORE"
        update_best_candidate "Windows Workstation" "$WINDOWS_WORKSTATION_SCORE"
        update_best_candidate "Database Server" "$DATABASE_SCORE"
        update_best_candidate "Network Printer / Multifunction Printer" "$PRINTER_SCORE"
        update_best_candidate "IP Camera / NVR" "$CAMERA_SCORE"
        update_best_candidate "Linux Server" "$LINUX_SERVER_SCORE"
        update_best_candidate "Development / Admin Interface" "$DEV_ADMIN_SCORE"
        update_best_candidate "IoT / Embedded Device" "$IOT_SCORE"
        update_best_candidate "Web Server / Web Application Host" "$WEB_SCORE"
        update_best_candidate "Network Infrastructure / Router" "$NETWORK_SCORE"
        update_best_candidate "Mail Server" "$MAIL_SCORE"

        if [ "$CLASSIFICATION_CONFIDENCE" -gt 100 ]; then
            CLASSIFICATION_CONFIDENCE=100
        fi

        CLASSIFICATION_LABEL=$(confidence_label "$CLASSIFICATION_CONFIDENCE")
        CLASSIFICATION_BAND=$(confidence_band "$CLASSIFICATION_CONFIDENCE")
        CLASSIFICATION_CALIBRATED_DECISION=$(calibrated_decision "$CLASSIFICATION_CONFIDENCE")
        CLASSIFICATION_SIEM_ACTION=$(siem_action "$CLASSIFICATION_CONFIDENCE")
        CLASSIFICATION_CALIBRATION_REASON=$(calibration_reason "$CLASSIFICATION_CONFIDENCE")

        if [ "$CLASSIFICATION_CONFIDENCE" -ge 40 ]; then
            DEVICE_TYPE="$CLASSIFICATION_PRIMARY"
        fi

        CLASSIFICATION_SECONDARY=$(jq -n \
            --arg primary "$CLASSIFICATION_PRIMARY" \
            --argjson windows_server "$WINDOWS_SERVER_SCORE" \
            --argjson container "$CONTAINER_SCORE" \
            --argjson router_gateway "$ROUTER_GATEWAY_SCORE" \
            --argjson ap "$AP_SCORE" \
            --argjson switch_score "$SWITCH_SCORE" \
            --argjson nas "$NAS_SCORE" \
            --argjson voip "$VOIP_SCORE" \
            --argjson ups "$UPS_SCORE" \
            --argjson security "$SECURITY_SCORE" \
            --argjson hypervisor "$HYPERVISOR_SCORE" \
            --argjson windows_workstation "$WINDOWS_WORKSTATION_SCORE" \
            --argjson database "$DATABASE_SCORE" \
            --argjson printer "$PRINTER_SCORE" \
            --argjson camera "$CAMERA_SCORE" \
            --argjson linux_server "$LINUX_SERVER_SCORE" \
            --argjson dev_admin "$DEV_ADMIN_SCORE" \
            --argjson iot "$IOT_SCORE" \
            --argjson web "$WEB_SCORE" \
            --argjson network "$NETWORK_SCORE" \
            --argjson mail "$MAIL_SCORE" \
            '[
                {device_type: "Windows Server", confidence: $windows_server},
                {device_type: "Container Infrastructure", confidence: $container},
                {device_type: "Router / Gateway", confidence: $router_gateway},
                {device_type: "Wireless Access Point", confidence: $ap},
                {device_type: "Managed Switch / Network Infrastructure", confidence: $switch_score},
                {device_type: "NAS / File Server", confidence: $nas},
                {device_type: "VoIP Phone / PBX", confidence: $voip},
                {device_type: "UPS / Power Device", confidence: $ups},
                {device_type: "Security Appliance", confidence: $security},
                {device_type: "Hypervisor / Virtualization Host", confidence: $hypervisor},
                {device_type: "Windows Workstation", confidence: $windows_workstation},
                {device_type: "Database Server", confidence: $database},
                {device_type: "Network Printer / Multifunction Printer", confidence: $printer},
                {device_type: "IP Camera / NVR", confidence: $camera},
                {device_type: "Linux Server", confidence: $linux_server},
                {device_type: "Development / Admin Interface", confidence: $dev_admin},
                {device_type: "IoT / Embedded Device", confidence: $iot},
                {device_type: "Web Server / Web Application Host", confidence: $web},
                {device_type: "Network Infrastructure / Router", confidence: $network},
                {device_type: "Mail Server", confidence: $mail}
            ]
            | map(if .confidence > 100 then .confidence = 100 else . end)
            | map(select(.confidence > 0 and .device_type != $primary))
            | sort_by(.confidence)
            | reverse
            | .[:3]')

        # -------------------------
        # Severity Classification
        # -------------------------

        if [ "$SCORE" -ge 20 ]; then
            SEVERITY="CRITICAL"
        elif [ "$SCORE" -ge 12 ]; then
            SEVERITY="HIGH"
        elif [ "$SCORE" -ge 5 ]; then
            SEVERITY="MEDIUM"
        else
            SEVERITY="LOW"
        fi

        jq -n \
            --arg host "$HOST" \
            --arg device "$DEVICE_TYPE" \
            --arg severity "$SEVERITY" \
            --arg score "$SCORE" \
            --arg scanner_version "$SCANNER_VERSION" \
            --arg timestamp "$TIMESTAMP" \
            --arg classification_primary "$CLASSIFICATION_PRIMARY" \
            --arg classification_confidence "$CLASSIFICATION_CONFIDENCE" \
            --arg classification_label "$CLASSIFICATION_LABEL" \
            --arg classification_band "$CLASSIFICATION_BAND" \
            --arg classification_calibrated_decision "$CLASSIFICATION_CALIBRATED_DECISION" \
            --arg classification_siem_action "$CLASSIFICATION_SIEM_ACTION" \
            --arg classification_calibration_reason "$CLASSIFICATION_CALIBRATION_REASON" \
            --argjson findings "$FINDINGS_JSON" \
            --argjson classification_evidence "$CLASSIFICATION_EVIDENCE" \
            --argjson classification_contradictions "$CLASSIFICATION_CONTRADICTIONS" \
            --argjson classification_secondary "$CLASSIFICATION_SECONDARY" \
            --argjson classification_validators "$CLASSIFICATION_VALIDATORS" \
            '{
                host: $host,
                device_type: $device,
                device_type_confidence: ($classification_confidence | tonumber),
                severity: $severity,
                score: ($score | tonumber),
                scanner_version: $scanner_version,
                timestamp: $timestamp,
                classification: {
                    schema_version: "netsniper-classification-v1",

                    # Compatibility aliases for downstream tools.
                    # primary_type/secondary_candidates remain the canonical v1.4 names.
                    # type/candidates are easier for DeltaAegis and other parsers to consume.
                    type: $classification_primary,
                    primary_type: $classification_primary,

                    confidence: ($classification_confidence | tonumber),
                    confidence_label: $classification_label,
                    confidence_band: $classification_band,
                    calibrated_decision: $classification_calibrated_decision,
                    siem_action: $classification_siem_action,
                    calibration_reason: $classification_calibration_reason,

                    # Legacy decision retained for v1.x compatibility.
                    decision: (
                        if ($classification_confidence | tonumber) >= 40 then
                            "classified"
                        elif ($classification_confidence | tonumber) > 0 then
                            "possible"
                        else
                            "unknown"
                        end
                    ),
                    method: "weighted_evidence",

                    evidence: $classification_evidence,
                    validators: $classification_validators,
                    contradictions: $classification_contradictions,

                    candidates: $classification_secondary,
                    secondary_candidates: $classification_secondary
                },
                findings: $findings
            }' >> "$JSON_FILE.tmp"

        {
            echo "HOST: $HOST"
            echo "SCORE: $SCORE"
            echo "DEVICE TYPE: $DEVICE_TYPE"
            echo "DEVICE TYPE CONFIDENCE: $CLASSIFICATION_CONFIDENCE ($CLASSIFICATION_LABEL)"
            echo "CLASSIFICATION CONTRADICTIONS:"
            echo "$CLASSIFICATION_CONTRADICTIONS" | jq -r '.[]? | "- " + .reason'
            echo "SEVERITY: $SEVERITY"
            echo "FINDINGS:"
            echo "$FINDINGS_JSON" | jq -r '.[] | "- [" + .id + "] " + .name + " (" + .evidence + ")"'
            echo "-----------------------------------"
        } >> "$ANALYSIS_FILE"

    done < <(grep "Ports:" "$INPUT")

    jq -s '.' "$JSON_FILE.tmp" > "$JSON_FILE"
    rm "$JSON_FILE.tmp"

    echo -e "${GREEN}[+] Analysis complete${RESET}"
    echo -e "${YELLOW}[*] TXT Report:${RESET} $ANALYSIS_FILE"
    echo -e "${YELLOW}[*] JSON Report:${RESET} $JSON_FILE"
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
    return 0 2>/dev/null || exit 0
fi

boot_screen
init_workspace
check_dirs
load_config

: "${NET:?Missing NET}"

while true; do
    echo ""
    echo "================================"
    echo "        NETSNIPER v1.6"
    echo "================================"
    echo "  1) Discover Hosts"
    echo "  2) TrueAegis-Aligned Scan"
    echo "  3) Extract TrueAegis-Relevant Hosts"
    echo "  4) Import to Greenbone"
    echo "  5) Run FULL Pipeline"
    echo "  6) Show TrueAegis-Relevant Targets"
    echo "  7) Generate Report"
    echo "  8) Analyze Hosts"
    echo "  0) Exit"
    echo "================================"

    read -r -p "netsniper> " opt

    case $opt in
        1) run_discovery ;;
        2) run_scan ;;
        3) extract_high_risk ;;
        4) import_greenbone ;;
        5) run_full_pipeline ;;
        6) show_targets ;;
        7) generate_report ;;
        8) analyze_hosts ;;
        0) echo "Goodbye"; exit 0 ;;
        *) echo "Invalid option" ;;
    esac
done
