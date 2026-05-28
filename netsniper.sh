#!/bin/bash

# NetSniper - Network Recon & Exposure Intelligence Engine
# Author: Parker Lee
# License: MIT

# =========================
# NETSNIPER ENGINE v1.1
# =========================

set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo -e "\n[ERROR] Failed at line $LINENO while executing $BASH_COMMAND"' ERR

command -v nmap >/dev/null 2>&1 || { echo "nmap required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v gvm-cli >/dev/null 2>&1 || echo "[!] gvm-cli not installed (Greenbone disabled)"

NETSNIPER_VERSION="v1.1"

# High-value exposure ports scanned by NetSniper v1.1
RISK_PORTS="21,22,23,80,81,161,389,443,445,554,631,636,1433,1521,1900,2375,2376,3268,3306,3389,5000,5432,5555,5601,5900,5985,5986,6379,6443,7547,8080,8081,8443,9000,9200,10250,27017,37777,9100"
HIGH_RISK_REGEX="21/open|22/open|23/open|80/open|81/open|161/open|389/open|443/open|445/open|554/open|631/open|636/open|1433/open|1521/open|1900/open|2375/open|2376/open|3268/open|3306/open|3389/open|5000/open|5432/open|5555/open|5601/open|5900/open|5985/open|5986/open|6379/open|6443/open|7547/open|8080/open|8081/open|8443/open|9000/open|9200/open|10250/open|27017/open|37777/open|9100/open"

# Colors
RED='\033[1;31m'
BRIGHT_RED='\033[1;3;91m'
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

# Root workspace (can be overridden)
BASE="${NETSNIPER_BASE:-$HOME/netsniper}"

# Subdirectories
DISCOVERY_DIR="$BASE/discovery"
TARGET_DIR="$BASE/targets"
SCAN_DIR="$BASE/scans"
REPORT_DIR="$BASE/reports"
ANALYSIS_DIR="$BASE/analysis"
CONFIG_DIR="$BASE/config"

CONFIG_FILE="$CONFIG_DIR/netsniper.conf"

# External services
SOCK="/run/gvmd/gvmd.sock"

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

# =========================
# PHASE 1: MATRIX RAIN FILL
# =========================

echo -e "${GREEN}"

for i in {1..25}; do
    line=$(head /dev/urandom | tr -dc '01' | head -c 80)
    echo "$line"
    sleep 0.03
done

sleep 0.3

# =========================
# PHASE 2: CURTAIN DROP
# =========================

tput civis  # hide cursor

rows=$(tput lines)

for ((i=0; i<rows; i++)); do
    tput cup $i 0
    printf "%*s" "$(tput cols)" " "
    sleep 0.01
done

tput clear
tput cnorm  # show cursor again

# =========================
# PHASE 3: REVEAL BANNER
# =========================

echo -e "${RED}"
echo '    _   _ _____ _____ ____  _   _ ___ ____  _____ ____  '
echo '   | \ | | ____|_   _/ ___|| \ | |_ _|  _ \| ____|  _ \ '
echo '   |  \| |  _|   | | \___ \|  \| || || |_) |  _| | |_) |'
echo '   | |\  | |___  | |  ___) | |\  || ||  __/| |___|  _ < '
echo '   |_| \_|_____| |_| |____/|_| \_|___|_|   |_____|_| \_\'
echo -e "${RESET}"

echo ""

messages=(
"[SYS] Initializing NetSniper engine $NETSNIPER_VERSION..."
"[NET] Preparing discovery modules..."
"[SCAN] Loading expanded v1.1 port intelligence..."
"[ANALYSIS] Activating structured risk engine..."
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
    out=$(gvm-cli \
        --gmp-username "$USER" \
        --gmp-password "$PASS" \
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

    nmap -PR -sn "$NET" -oG "$DISCOVERY_DIR/live.gnmap" \
        > /dev/null 2>&1 &

    PID=$!

    spin='|/-\'
    i=0

    while kill -0 $PID 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] Scanning network..." "${spin:$i:1}"
        sleep 0.1
    done

    wait $PID

    printf "\r"

    awk '/Up$/{print $2}' "$DISCOVERY_DIR/live.gnmap" > "$TARGET_DIR/hosts.txt"

    echo -e "${GREEN}[+] Discovery complete${RESET}"
}

run_scan() {

    if [ ! -s "$TARGET_DIR/hosts.txt" ]; then
        echo -e "${RED}[-] No hosts found. Run discovery first.${RESET}"
        return
    fi

    mkdir -p "$SCAN_DIR"

    echo -e "${PURPLE}[2]${RESET} Running NetSniper $NETSNIPER_VERSION exposure scan..."
    INFO "Scanning expanded high-risk port set: $RISK_PORTS"

    nmap -sV -T4 -p "$RISK_PORTS" -iL "$TARGET_DIR/hosts.txt" -oA "$SCAN_DIR/fast_scan" \
        > /dev/null 2>&1 &

    PID=$!

    spin='|/-\'
    i=0

    while kill -0 $PID 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r[%c] Scanning hosts..." "${spin:$i:1}"
        sleep 0.1
    done

    wait $PID

    printf "\r"

    echo -e "${GREEN}[+] Scan completed${RESET}"
}

extract_high_risk() {
    echo -e "${YELLOW}[3]${RESET} Extracting high-risk hosts..."

    INPUT="$SCAN_DIR/fast_scan.gnmap"
    OUTPUT="$TARGET_DIR/high_risk.txt"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found. Run scan first.${RESET}"
        return
    fi

    grep -E "$HIGH_RISK_REGEX" "$INPUT" \
    | awk '{print $2}' \
    | sort -u > "$OUTPUT"

    echo -e "${GREEN}[+] High-risk hosts:${RESET}"
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

    if [ ! -s "$INPUT" ]; then
        echo -e "${RED}[-] No high-risk hosts found.${RESET}"
        return
    fi

    if [ ! -S "$SOCK" ]; then
        echo -e "${RED}[-] Greenbone socket not found.${RESET}"
        return
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
        return
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
        return
    fi

    echo "[+] Task ID: $TASK_ID"

    echo "[*] Starting scan..."

    gvm-cli \
        --gmp-username "$USER" \
        --gmp-password "$PASS" \
        socket \
        --socketpath "$SOCK" \
        --xml "<start_task task_id='$TASK_ID'/>"

    echo -e "${GREEN}[+] Scan launched successfully${RESET}"
}

load_config() {

    if [ -f "$CONFIG_FILE" ]; then
        echo "[*] Found saved config."

        source "$CONFIG_FILE"

        read -p "Use saved config? (y/n): " use_saved

        if [[ "$use_saved" == "y" ]]; then
            echo "[+] Using saved configuration"
            return
        fi
    fi

    echo "[*] First-time setup"

    read -p "Greenbone username: " USER
    read -s -p "Greenbone password: " PASS
    echo ""

    read -p "Target network (e.g. 192.168.1.0/24): " NET

    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF
USER="$USER"
PASS="$PASS"
NET="$NET"
EOF

    echo "[+] Config saved to $CONFIG_FILE"
}

check_dirs() {
    for dir in "$BASE" "$DISCOVERY_DIR" "$TARGET_DIR" "$SCAN_DIR" "$REPORT_DIR" "$ANALYSIS_DIR" "$CONFIG_DIR"; do
        if [ ! -d "$dir" ]; then
            echo "[-] Missing required directory: $dir"
            echo "[*] Create it or check your installation."
            exit 1
        fi
    done
}

run_full_pipeline() {

    echo ""
    echo "=============================="
    echo "   NETSNIPER PIPELINE $NETSNIPER_VERSION"
    echo "=============================="

    INFO "Stage 1/4 - Discovery"
    run_discovery || return 1

    INFO "Stage 2/4 - Scanning"
    run_scan || return 1

    INFO "Stage 3/4 - Analysis"
    analyze_hosts || return 1

    INFO "Stage 4/4 - Reporting"
    generate_report || return 1

    SUCCESS "Pipeline complete"
}

show_targets() {
    echo -e "${BLUE}[*] High Risk Targets:${RESET}"
    cat "$TARGET_DIR/high_risk.txt" 2>/dev/null
}

add_finding() {
    local id="$1"
    local name="$2"
    local service="$3"
    local port="$4"
    local weight="$5"
    local evidence="$6"

    SCORE=$((SCORE + weight))

    FINDINGS_JSON=$(echo "$FINDINGS_JSON" | jq -c \
        --arg id "$id" \
        --arg name "$name" \
        --arg service "$service" \
        --argjson port "$port" \
        --argjson score "$weight" \
        --arg evidence "$evidence" \
        '. += [{
            id: $id,
            name: $name,
            service: $service,
            port: $port,
            score: $score,
            evidence: $evidence
        }]')
}

classify_device() {
    local line="$1"

    DEVICE_TYPE="Unknown"

    if [[ "$line" == *"445/open"* && "$line" == *"3389/open"* ]]; then
        DEVICE_TYPE="Windows Host"
    elif [[ "$line" == *"2375/open"* || "$line" == *"2376/open"* || "$line" == *"5000/open"* || "$line" == *"6443/open"* || "$line" == *"10250/open"* || "$line" == *"8081/open"* || "$line" == *"9000/open"* || "$line" == *"5601/open"* ]]; then
        DEVICE_TYPE="DevOps / Infrastructure Host"
    elif [[ "$line" == *"1433/open"* || "$line" == *"1521/open"* || "$line" == *"3306/open"* || "$line" == *"5432/open"* || "$line" == *"6379/open"* || "$line" == *"9200/open"* || "$line" == *"27017/open"* ]]; then
        DEVICE_TYPE="Database / Data Service"
    elif [[ "$line" == *"389/open"* || "$line" == *"636/open"* || "$line" == *"3268/open"* ]]; then
        DEVICE_TYPE="Directory Service Host"
    elif [[ "$line" == *"9100/open"* || "$line" == *"631/open"* ]]; then
        DEVICE_TYPE="Network Printer"
    elif [[ "$line" == *"554/open"* || "$line" == *"37777/open"* || "$line" == *"7547/open"* || "$line" == *"5555/open"* || "$line" == *"1900/open"* ]]; then
        DEVICE_TYPE="IoT / Camera / Embedded Device"
    elif [[ "$line" == *"22/open"* && "$line" == *"80/open"* ]]; then
        DEVICE_TYPE="Linux/Web Server"
    elif [[ "$line" == *"80/open"* || "$line" == *"443/open"* || "$line" == *"8080/open"* || "$line" == *"8443/open"* ]]; then
        DEVICE_TYPE="Web Server"
    fi
}

analyze_hosts() {

    echo -e "${PURPLE}[*] Running NetSniper $NETSNIPER_VERSION exposure analysis...${RESET}"

    INPUT="$SCAN_DIR/fast_scan.gnmap"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found.${RESET}"
        return
    fi

    TIMESTAMP=$(date +%Y%m%d-%H%M%S)

    ANALYSIS_FILE="$TARGET_DIR/analysis_$TIMESTAMP.txt"
    JSON_FILE="$TARGET_DIR/analysis_$TIMESTAMP.json"

    > "$JSON_FILE.tmp"
    > "$ANALYSIS_FILE"

    {
        echo "========================================="
        echo "         NETSNIPER ANALYSIS $NETSNIPER_VERSION"
        echo "========================================="
        echo "Timestamp: $TIMESTAMP"
        echo "Network: $NET"
        echo "Scan File: $INPUT"
        echo "Output Schema: AegisCore-ready structured JSON"
        echo "========================================="
        echo ""
    } >> "$ANALYSIS_FILE"

    while read -r line; do

        HOST=$(echo "$line" | awk '{print $2}')

        SCORE=0
        FINDINGS_JSON="[]"
        classify_device "$line"

        # -------------------------
        # Critical / High-Risk Remote Access
        # -------------------------

        if [[ "$line" == *"21/open"* ]]; then
            add_finding "FTP_EXPOSED" "FTP exposed" "ftp" 21 6 "Port 21 open"
        fi

        if [[ "$line" == *"22/open"* ]]; then
            add_finding "SSH_EXPOSED" "SSH exposed" "ssh" 22 3 "Port 22 open"
        fi

        if [[ "$line" == *"23/open"* ]]; then
            add_finding "TELNET_EXPOSED" "Telnet exposed" "telnet" 23 10 "Port 23 open"
        fi

        if [[ "$line" == *"445/open"* ]]; then
            add_finding "SMB_EXPOSED" "SMB exposed" "smb" 445 8 "Port 445 open"
        fi

        if [[ "$line" == *"3389/open"* ]]; then
            add_finding "RDP_EXPOSED" "RDP exposed" "rdp" 3389 8 "Port 3389 open"
        fi

        if [[ "$line" == *"5900/open"* ]]; then
            add_finding "VNC_EXPOSED" "VNC exposed" "vnc" 5900 8 "Port 5900 open"
        fi

        if [[ "$line" == *"5985/open"* ]]; then
            add_finding "WINRM_HTTP_EXPOSED" "WinRM HTTP exposed" "winrm" 5985 7 "Port 5985 open"
        fi

        if [[ "$line" == *"5986/open"* ]]; then
            add_finding "WINRM_HTTPS_EXPOSED" "WinRM HTTPS exposed" "winrm" 5986 7 "Port 5986 open"
        fi

        # -------------------------
        # Directory / Enumeration Services
        # -------------------------

        if [[ "$line" == *"161/open"* ]]; then
            add_finding "SNMP_EXPOSED" "SNMP exposed" "snmp" 161 5 "Port 161 open"
        fi

        if [[ "$line" == *"389/open"* ]]; then
            add_finding "LDAP_EXPOSED" "LDAP exposed" "ldap" 389 5 "Port 389 open"
        fi

        if [[ "$line" == *"636/open"* ]]; then
            add_finding "LDAPS_EXPOSED" "LDAPS exposed" "ldaps" 636 4 "Port 636 open"
        fi

        if [[ "$line" == *"3268/open"* ]]; then
            add_finding "GLOBAL_CATALOG_EXPOSED" "Active Directory Global Catalog exposed" "ldap-gc" 3268 5 "Port 3268 open"
        fi

        # -------------------------
        # Database / Data Services
        # -------------------------

        if [[ "$line" == *"1433/open"* ]]; then
            add_finding "MSSQL_EXPOSED" "Microsoft SQL Server exposed" "mssql" 1433 6 "Port 1433 open"
        fi

        if [[ "$line" == *"1521/open"* ]]; then
            add_finding "ORACLE_DB_EXPOSED" "Oracle database exposed" "oracle" 1521 6 "Port 1521 open"
        fi

        if [[ "$line" == *"3306/open"* ]]; then
            add_finding "MYSQL_EXPOSED" "MySQL exposed" "mysql" 3306 6 "Port 3306 open"
        fi

        if [[ "$line" == *"5432/open"* ]]; then
            add_finding "POSTGRES_EXPOSED" "PostgreSQL exposed" "postgresql" 5432 6 "Port 5432 open"
        fi

        if [[ "$line" == *"6379/open"* ]]; then
            add_finding "REDIS_EXPOSED" "Redis exposed" "redis" 6379 9 "Port 6379 open"
        fi

        if [[ "$line" == *"9200/open"* ]]; then
            add_finding "ELASTICSEARCH_EXPOSED" "Elasticsearch exposed" "elasticsearch" 9200 9 "Port 9200 open"
        fi

        if [[ "$line" == *"27017/open"* ]]; then
            add_finding "MONGODB_EXPOSED" "MongoDB exposed" "mongodb" 27017 9 "Port 27017 open"
        fi

        # -------------------------
        # DevOps / Cloud / Container Infrastructure
        # -------------------------

        if [[ "$line" == *"2375/open"* ]]; then
            add_finding "DOCKER_API_EXPOSED" "Docker API exposed without TLS" "docker" 2375 10 "Port 2375 open"
        fi

        if [[ "$line" == *"2376/open"* ]]; then
            add_finding "DOCKER_TLS_API_EXPOSED" "Docker TLS API exposed" "docker" 2376 7 "Port 2376 open"
        fi

        if [[ "$line" == *"5000/open"* ]]; then
            add_finding "DOCKER_REGISTRY_EXPOSED" "Docker registry exposed" "docker-registry" 5000 7 "Port 5000 open"
        fi

        if [[ "$line" == *"6443/open"* ]]; then
            add_finding "KUBERNETES_API_EXPOSED" "Kubernetes API exposed" "kubernetes" 6443 10 "Port 6443 open"
        fi

        if [[ "$line" == *"10250/open"* ]]; then
            add_finding "KUBELET_EXPOSED" "Kubernetes kubelet exposed" "kubelet" 10250 10 "Port 10250 open"
        fi

        if [[ "$line" == *"8081/open"* ]]; then
            add_finding "JENKINS_OR_DEVOPS_UI_EXPOSED" "Jenkins or DevOps web UI exposed" "jenkins/devops-ui" 8081 6 "Port 8081 open"
        fi

        if [[ "$line" == *"9000/open"* ]]; then
            add_finding "PORTAINER_EXPOSED" "Portainer or container management UI exposed" "portainer" 9000 7 "Port 9000 open"
        fi

        if [[ "$line" == *"5601/open"* ]]; then
            add_finding "KIBANA_EXPOSED" "Kibana exposed" "kibana" 5601 7 "Port 5601 open"
        fi

        # -------------------------
        # Web / Admin Panels
        # -------------------------

        if [[ "$line" == *"80/open"* ]]; then
            add_finding "HTTP_EXPOSED" "HTTP service exposed" "http" 80 2 "Port 80 open"
        fi

        if [[ "$line" == *"443/open"* ]]; then
            add_finding "HTTPS_EXPOSED" "HTTPS service exposed" "https" 443 2 "Port 443 open"
        fi

        if [[ "$line" == *"81/open"* ]]; then
            add_finding "ALT_HTTP_PANEL_EXPOSED" "Alternate HTTP admin panel exposed" "http-alt" 81 4 "Port 81 open"
        fi

        if [[ "$line" == *"8080/open"* ]]; then
            add_finding "HTTP_ALT_EXPOSED" "Alternate HTTP service or admin panel exposed" "http-alt" 8080 4 "Port 8080 open"
        fi

        if [[ "$line" == *"8443/open"* ]]; then
            add_finding "HTTPS_ALT_EXPOSED" "Alternate HTTPS service or admin panel exposed" "https-alt" 8443 4 "Port 8443 open"
        fi

        # -------------------------
        # IoT / Camera / Embedded / Printer Services
        # -------------------------

        if [[ "$line" == *"554/open"* ]]; then
            add_finding "RTSP_EXPOSED" "RTSP camera/service exposed" "rtsp" 554 3 "Port 554 open"
        fi

        if [[ "$line" == *"37777/open"* ]]; then
            add_finding "DAHUA_DVR_EXPOSED" "Dahua DVR/camera service exposed" "dahua-dvr" 37777 7 "Port 37777 open"
        fi

        if [[ "$line" == *"7547/open"* ]]; then
            add_finding "TR069_EXPOSED" "TR-069 router management service exposed" "tr-069" 7547 7 "Port 7547 open"
        fi

        if [[ "$line" == *"5555/open"* ]]; then
            add_finding "ADB_EXPOSED" "Android Debug Bridge exposed" "adb" 5555 8 "Port 5555 open"
        fi

        if [[ "$line" == *"1900/open"* ]]; then
            add_finding "UPNP_EXPOSED" "UPnP exposed" "upnp" 1900 4 "Port 1900 open"
        fi

        if [[ "$line" == *"9100/open"* ]]; then
            add_finding "PRINTER_9100_EXPOSED" "Printer RAW service exposed" "printer" 9100 2 "Port 9100 open"
        fi

        if [[ "$line" == *"631/open"* ]]; then
            add_finding "IPP_EXPOSED" "IPP printing service exposed" "ipp" 631 2 "Port 631 open"
        fi

        # -------------------------
        # Severity Classification
        # -------------------------

        if [ "$SCORE" -ge 10 ]; then
            SEVERITY="CRITICAL"
        elif [ "$SCORE" -ge 7 ]; then
            SEVERITY="HIGH"
        elif [ "$SCORE" -ge 4 ]; then
            SEVERITY="MEDIUM"
        elif [ "$SCORE" -ge 1 ]; then
            SEVERITY="LOW"
        else
            SEVERITY="INFO"
        fi

        # -------------------------
        # JSON Output
        # -------------------------

        jq -n \
            --arg host "$HOST" \
            --arg device "$DEVICE_TYPE" \
            --arg severity "$SEVERITY" \
            --argjson score "$SCORE" \
            --arg version "$NETSNIPER_VERSION" \
            --arg timestamp "$TIMESTAMP" \
            --argjson findings "$FINDINGS_JSON" \
            '{
                host: $host,
                device_type: $device,
                severity: $severity,
                score: $score,
                scanner_version: $version,
                timestamp: $timestamp,
                findings: $findings
            }' >> "$JSON_FILE.tmp"

        # -------------------------
        # TXT Output
        # -------------------------

        {
            echo "HOST: $HOST"
            echo "SCORE: $SCORE"
            echo "DEVICE TYPE: $DEVICE_TYPE"
            echo "SEVERITY: $SEVERITY"
            echo "FINDINGS:"

            if [ "$(echo "$FINDINGS_JSON" | jq 'length')" -eq 0 ]; then
                echo "- No high-risk exposure findings matched."
            else
                echo "$FINDINGS_JSON" | jq -r '.[] | "- [" + .id + "] " + .name + " | Port: " + (.port|tostring) + " | Score: " + (.score|tostring) + " | Evidence: " + .evidence'
            fi

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
        return
    fi

    if [ ! -f "$SCAN_FILE" ]; then
        echo -e "${RED}[-] fast_scan.gnmap not found${RESET}"
        return
    fi

    HOST_COUNT=$(wc -l < "$HOSTS_FILE")

    if [ -f "$HIGH_RISK_FILE" ]; then
        HIGH_RISK_COUNT=$(wc -l < "$HIGH_RISK_FILE")
    else
        HIGH_RISK_COUNT=0
    fi

    PORT_SUMMARY=$(grep -oE '[0-9]+/open' "$SCAN_FILE" \
        | sort \
        | uniq -c \
        | sort -nr)

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
# NETSNIPER REPORT $NETSNIPER_VERSION

Generated: $TIMESTAMP

Target Network: $NET

---

## SUMMARY

Hosts Discovered: $HOST_COUNT

High Risk Hosts: $HIGH_RISK_COUNT

Scanner Version: $NETSNIPER_VERSION

---

## HIGH RISK HOSTS

$(cat "$HIGH_RISK_FILE" 2>/dev/null || echo "No high-risk hosts found.")

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

boot_screen
init_workspace
check_dirs
load_config

: "${USER:?Missing USER}"
: "${PASS:?Missing PASS}"
: "${NET:?Missing NET}"

while true; do
echo ""
echo "================================"
echo "        NETSNIPER $NETSNIPER_VERSION"
echo "================================"
echo "  1) Discover Hosts"
echo "  2) Exposure Scan"
echo "  3) Extract High Risk"
echo "  4) Import to Greenbone"
echo "  5) Run FULL Pipeline"
echo "  6) Show High Risk Targets"
echo "  7) Generate Report"
echo "  8) Analyze Hosts"
echo "  0) Exit"
echo "================================"

    read -p "netsniper> " opt

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
