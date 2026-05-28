#!/bin/bash

# NetSniper - Network Recon & Exposure Intelligence Engine
# Author: Parker Lee
# License: MIT

# =========================
# NETSNIPER ENGINE v1.2
# TrueAegis-compatible telemetry output
# =========================

set -Eeuo pipefail
IFS=$'\n\t'
trap 'echo -e "\n[ERROR] Failed at line $LINENO while executing $BASH_COMMAND"' ERR

command -v nmap >/dev/null 2>&1 || { echo "nmap required"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq required"; exit 1; }
command -v gvm-cli >/dev/null 2>&1 || echo "[!] gvm-cli not installed (Greenbone disabled)"

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

BASE="${NETSNIPER_BASE:-$HOME/netsniper}"

DISCOVERY_DIR="$BASE/discovery"
TARGET_DIR="$BASE/targets"
SCAN_DIR="$BASE/scans"
REPORT_DIR="$BASE/reports"
ANALYSIS_DIR="$BASE/analysis"
CONFIG_DIR="$BASE/config"

CONFIG_FILE="$CONFIG_DIR/netsniper.conf"
SOCK="/run/gvmd/gvmd.sock"

SCANNER_VERSION="v1.2"

# TrueAegis-aligned scan ports.
# These are the ports NetSniper can reliably identify from nmap grepable output.
TRUEAEGIS_PORTS="21,22,23,25,53,80,88,110,139,143,443,445,465,554,587,631,993,995,1433,1521,1900,2375,2376,3000,3306,3389,5000,5432,5555,5601,5900,6379,6443,7547,8000,8080,8081,8443,8888,9000,9090,9100,9200,9300,9443,10250,10255,27017,3268,3269"

HIGH_RISK_PATTERN="21/open|22/open|23/open|25/open|53/open|80/open|88/open|110/open|139/open|143/open|443/open|445/open|465/open|554/open|587/open|631/open|993/open|995/open|1433/open|1521/open|1900/open|2375/open|2376/open|3000/open|3306/open|3389/open|5000/open|5432/open|5555/open|5601/open|5900/open|6379/open|6443/open|7547/open|8000/open|8080/open|8081/open|8443/open|8888/open|9000/open|9090/open|9100/open|9200/open|9300/open|9443/open|10250/open|10255/open|27017/open|3268/open|3269/open"

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

    echo -e "${PURPLE}[2]${RESET} Running TrueAegis-aligned scan..."
    echo -e "${YELLOW}[*] Ports:${RESET} $TRUEAEGIS_PORTS"

    nmap -sV -T4 -p "$TRUEAEGIS_PORTS" -iL "$TARGET_DIR/hosts.txt" -oA "$SCAN_DIR/fast_scan" \
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

    echo -e "${GREEN}[+] Scan complete${RESET}"
}

extract_high_risk() {
    echo -e "${YELLOW}[3]${RESET} Extracting TrueAegis-relevant hosts..."

    INPUT="$SCAN_DIR/fast_scan.gnmap"
    OUTPUT="$TARGET_DIR/high_risk.txt"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found. Run scan first.${RESET}"
        return
    fi

    grep -E "$HIGH_RISK_PATTERN" "$INPUT" \
        | awk '{print $2}' \
        | sort -u > "$OUTPUT"

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
    for dir in "$BASE" "$DISCOVERY_DIR" "$TARGET_DIR" "$SCAN_DIR" "$REPORT_DIR"; do
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
    echo "   NETSNIPER PIPELINE"
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

analyze_hosts() {
    echo -e "${PURPLE}[*] Running TrueAegis-compatible exposure analysis...${RESET}"

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

        has_port() {
            local port="$1"
            [[ "$line" == *"$port/open"* ]]
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
        has_port 9000 && add_finding "PORTAINER_EXPOSED" "Portainer service exposed" "portainer" 9000 8 "Port 9000 open"
        has_port 9090 && add_finding "PROMETHEUS_EXPOSED" "Prometheus service exposed" "prometheus" 9090 6 "Port 9090 open"
        has_port 9100 && add_finding "PRINTER_9100_EXPOSED" "Raw printer service exposed" "printer-raw" 9100 4 "Port 9100 open"
        has_port 9200 && add_finding "ELASTICSEARCH_EXPOSED" "Elasticsearch service exposed" "elasticsearch" 9200 8 "Port 9200 open"
        has_port 9300 && add_finding "ELASTICSEARCH_TRANSPORT_EXPOSED" "Elasticsearch transport service exposed" "elasticsearch-transport" 9300 7 "Port 9300 open"
        has_port 9443 && add_finding "PORTAINER_HTTPS_EXPOSED" "Portainer HTTPS service exposed" "portainer-https" 9443 8 "Port 9443 open"
        has_port 10250 && add_finding "KUBELET_EXPOSED" "Kubelet service exposed" "kubelet" 10250 10 "Port 10250 open"
        has_port 10255 && add_finding "KUBELET_READONLY_EXPOSED" "Kubelet read-only service exposed" "kubelet-readonly" 10255 9 "Port 10255 open"
        has_port 27017 && add_finding "MONGODB_EXPOSED" "MongoDB service exposed" "mongodb" 27017 8 "Port 27017 open"
        has_port 3268 && add_finding "LDAP_GLOBAL_CATALOG_EXPOSED" "LDAP Global Catalog exposed" "ldap-gc" 3268 7 "Port 3268 open"
        has_port 3269 && add_finding "LDAPS_GLOBAL_CATALOG_EXPOSED" "LDAPS Global Catalog exposed" "ldaps-gc" 3269 7 "Port 3269 open"

        # -------------------------
        # Device Classification
        # -------------------------

        if has_port 88 && has_port 389 && has_port 445; then
            DEVICE_TYPE="Likely Active Directory / Domain Controller"
        elif has_port 6443 || has_port 10250 || has_port 10255; then
            DEVICE_TYPE="Kubernetes Infrastructure"
        elif has_port 2375 || has_port 2376 || has_port 9000 || has_port 9443; then
            DEVICE_TYPE="Container Infrastructure"
        elif has_port 445 || has_port 3389 || has_port 139; then
            DEVICE_TYPE="Windows Host"
        elif has_port 1433 || has_port 1521 || has_port 3306 || has_port 5432 || has_port 6379 || has_port 9200 || has_port 27017; then
            DEVICE_TYPE="Database Server"
        elif has_port 9100 || has_port 631; then
            DEVICE_TYPE="Network Printer"
        elif has_port 554; then
            DEVICE_TYPE="IP Camera / RTSP Device"
        elif has_port 22 && (has_port 80 || has_port 443 || has_port 8080 || has_port 8443); then
            DEVICE_TYPE="Linux/Web Server"
        elif has_port 80 || has_port 443 || has_port 8080 || has_port 8443 || has_port 8000 || has_port 8888; then
            DEVICE_TYPE="Web Server"
        elif has_port 25 || has_port 465 || has_port 587 || has_port 110 || has_port 143 || has_port 993 || has_port 995; then
            DEVICE_TYPE="Mail Server"
        elif has_port 53; then
            DEVICE_TYPE="DNS Server"
        fi

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
            --argjson findings "$FINDINGS_JSON" \
            '{
                host: $host,
                device_type: $device,
                severity: $severity,
                score: ($score | tonumber),
                scanner_version: $scanner_version,
                timestamp: $timestamp,
                findings: $findings
            }' >> "$JSON_FILE.tmp"

        {
            echo "HOST: $HOST"
            echo "SCORE: $SCORE"
            echo "DEVICE TYPE: $DEVICE_TYPE"
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
    echo "        NETSNIPER v1.2"
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
