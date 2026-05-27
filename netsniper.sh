#!/bin/bash

# NetSniper - Network Recon & Exposure Intelligence Engine
# Author: Parker Lee
# License: MIT

# =========================
# NETSNIPER ENGINE v1.0
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
# (clear line-by-line)
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

# =========================
# STARTUP TEXT
# =========================

messages=(
"[SYS] Initializing NetSniper engine..."
"[NET] Preparing discovery modules..."
"[SCAN] Loading scan pipeline..."
"[ANALYSIS] Activating risk engine..."
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

    # Run nmap silently in background
    nmap -PR -sn "$NET" -oG "$DISCOVERY_DIR/live.gnmap" \
        > /dev/null 2>&1 &
    
    PID=$!

    # Spinner animation
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

    echo -e "${PURPLE}[2]${RESET} Running fast scan..."

nmap -F -sV -T4 -iL "$TARGET_DIR/hosts.txt" -oA "$SCAN_DIR/fast_scan" \
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
    echo -e "${YELLOW}[3]${RESET} Extracting high-risk hosts..."

    INPUT="$SCAN_DIR/fast_scan.gnmap"
    OUTPUT="$TARGET_DIR/high_risk.txt"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found. Run scan first.${RESET}"
        return
    fi

    grep -E "22/open|80/open|443/open|445/open|554/open|631/open|9100/open|3389/open" "$INPUT" \
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

    # Save config
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

    echo -e "${PURPLE}[*] Running exposure analysis...${RESET}"

    INPUT="$SCAN_DIR/fast_scan.gnmap"

    if [ ! -f "$INPUT" ]; then
        echo -e "${RED}[-] Scan file not found.${RESET}"
        return
    fi

    TIMESTAMP=$(date +%Y%m%d-%H%M%S)

	ANALYSIS_FILE="$TARGET_DIR/analysis_$TIMESTAMP.txt"
	
	JSON_FILE="$TARGET_DIR/analysis_$TIMESTAMP.json"

	echo "[]" > "$JSON_FILE"
    > "$JSON_FILE.tmp"
    > "$ANALYSIS_FILE"
    {
    echo "========================================="
    echo "         NETSNIPER ANALYSIS"
    echo "========================================="
    echo "Timestamp: $TIMESTAMP"
    echo "Network: $NET"
    echo "Scan File: $INPUT"
    echo "========================================="
    echo ""
} >> "$ANALYSIS_FILE"
    

    while read -r line; do

        HOST=$(echo "$line" | awk '{print $2}')

        SCORE=0
        FINDINGS=""
        DEVICE_TYPE="Unknown"

        # -------------------------
        # Exposure Checks
        # -------------------------

        if [[ "$line" == *"445/open"* ]]; then
            SCORE=$((SCORE + 5))
            FINDINGS+="SMB exposed\n"
        fi

        if [[ "$line" == *"3389/open"* ]]; then
            SCORE=$((SCORE + 5))
            FINDINGS+="RDP exposed\n"
        fi

        if [[ "$line" == *"23/open"* ]]; then
            SCORE=$((SCORE + 10))
            FINDINGS+="Telnet exposed\n"
        fi

        if [[ "$line" == *"554/open"* ]]; then
            SCORE=$((SCORE + 3))
            FINDINGS+="RTSP camera/service exposed\n"
        fi

        if [[ "$line" == *"9100/open"* ]]; then
            SCORE=$((SCORE + 1))
            FINDINGS+="Printer service exposed\n"
        fi

        if [[ "$line" == *"631/open"* ]]; then
            SCORE=$((SCORE + 1))
            FINDINGS+="IPP printing service exposed\n"
        fi

        if [[ "$line" == *"22/open"* ]]; then
            SCORE=$((SCORE + 2))
            FINDINGS+="SSH exposed\n"
        fi
        
        # -------------------------
	# Device Classification
	# -------------------------

	if [[ "$line" == *"445/open"* && "$line" == *"3389/open"* ]]; then
	    DEVICE_TYPE="Windows Host"
	fi

	if [[ "$line" == *"22/open"* && "$line" == *"80/open"* ]]; then
	    DEVICE_TYPE="Linux/Web Server"
	fi

	if [[ "$line" == *"9100/open"* || "$line" == *"631/open"* ]]; then
	    DEVICE_TYPE="Network Printer"
	fi

	if [[ "$line" == *"554/open"* ]]; then
	    DEVICE_TYPE="IP Camera / RTSP Device"
	fi

	if [[ "$line" == *"80/open"* && "$line" == *"443/open"* ]]; then
	    DEVICE_TYPE="Web Server"
	fi
        

        # -------------------------
        # Severity Classification
        # -------------------------

        if [ "$SCORE" -ge 10 ]; then
            SEVERITY="CRITICAL"
        elif [ "$SCORE" -ge 6 ]; then
            SEVERITY="HIGH"
        elif [ "$SCORE" -ge 3 ]; then
            SEVERITY="MEDIUM"
        else
            SEVERITY="LOW"
        fi
        
        jq -n \
	  --arg host "$HOST" \
	  --arg device "$DEVICE_TYPE" \
	  --arg severity "$SEVERITY" \
	  --arg score "$SCORE" \
	  --arg findings "$FINDINGS" \
	  '{host: $host, device_type: $device, severity: $severity, score: ($score|tonumber), findings: $findings}' \
	>> "$JSON_FILE.tmp"
	
        # -------------------------
        # Save Results
        # -------------------------

        {
            echo "HOST: $HOST"
            echo "SCORE: $SCORE"
            echo "DEVICE TYPE: $DEVICE_TYPE"
            echo "SEVERITY: $SEVERITY"
            echo -e "FINDINGS:\n$FINDINGS"
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

    # -------------------------
    # Validate required files
    # -------------------------

    if [ ! -f "$HOSTS_FILE" ]; then
        echo -e "${RED}[-] hosts.txt not found${RESET}"
        return
    fi

    if [ ! -f "$SCAN_FILE" ]; then
        echo -e "${RED}[-] fast_scan.gnmap not found${RESET}"
        return
    fi

    # -------------------------
    # Count statistics
    # -------------------------

    HOST_COUNT=$(wc -l < "$HOSTS_FILE")

    if [ -f "$HIGH_RISK_FILE" ]; then
        HIGH_RISK_COUNT=$(wc -l < "$HIGH_RISK_FILE")
    else
        HIGH_RISK_COUNT=0
    fi

    # -------------------------
    # Open port summary
    # -------------------------

    PORT_SUMMARY=$(grep -oE '[0-9]+/open' "$SCAN_FILE" \
        | sort \
        | uniq -c \
        | sort -nr)
     
# -------------------------
# Host-by-host breakdown
# -------------------------

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
    # -------------------------
    # Generate markdown report
    # -------------------------

    cat > "$REPORT_FILE" <<EOF
# NETSNIPER REPORT

Generated: $TIMESTAMP

Target Network: $NET

---

## SUMMARY

Hosts Discovered: $HOST_COUNT

High Risk Hosts: $HIGH_RISK_COUNT

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
#Loading Config & Directory

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
echo "        NETSNIPER v1.0"
echo "================================"
echo "  1) Discover Hosts"
echo "  2) Fast Scan"
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
