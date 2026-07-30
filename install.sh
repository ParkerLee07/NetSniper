#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

# ============================================================
# NetSniper Installer
#
# Usage:
#   git clone https://github.com/ParkerLee07/NetSniper.git
#   cd NetSniper
#   chmod +x install.sh
#   ./install.sh
#
# Optional environment variables:
#   NETSNIPER_BASE=/custom/path
#   BIN_DIR=/custom/bin
# ============================================================

log() {
    printf '\n[+] %s\n' "$*"
}

warn() {
    printf '\n[!] %s\n' "$*" >&2
}

die() {
    printf '\n[ERROR] %s\n' "$*" >&2
    exit 1
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BASE="${NETSNIPER_BASE:-$SCRIPT_DIR}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

[[ -f "$BASE/netsniper.sh" ]] || die "Could not find netsniper.sh in $BASE"

log "Checking required dependencies"

missing=0

for cmd in nmap jq base64 python3 sha256sum timeout; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "Missing required dependency: $cmd"
        missing=1
    fi
done

if [[ "$missing" -eq 1 ]]; then
    echo
    echo "Install required packages with:"
    echo "  sudo apt update"
    echo "  sudo apt install -y nmap jq coreutils python3"
    exit 1
fi

if ! command -v gvm-cli >/dev/null 2>&1; then
    warn "gvm-cli not found. Greenbone integration will be disabled."
fi

log "Initializing NetSniper workspace"

mkdir -p \
    "$BASE/discovery" \
    "$BASE/targets" \
    "$BASE/scans" \
    "$BASE/reports" \
    "$BASE/analysis" \
    "$BASE/config" \
    "$BASE/runs" \
    "$BASE/.runtime" \
    "$BASE/.bundle-staging" \
    "$BIN_DIR"

chmod +x "$BASE/netsniper.sh"

log "Installing netsniper launcher"

cat > "$BIN_DIR/netsniper" <<EOF
#!/usr/bin/env bash
export NETSNIPER_BASE="$BASE"
exec bash "$BASE/netsniper.sh" "\$@"
EOF

chmod +x "$BIN_DIR/netsniper"

case ":$PATH:" in
    *":$BIN_DIR:"*)
        ;;
    *)
        warn "$BIN_DIR is not currently in your PATH."
        echo "Add this to your shell config if needed:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        ;;
esac

log "NetSniper installation complete"

cat <<EOF

Installed at:
  $BASE

Launcher:
  $BIN_DIR/netsniper

Try:
  netsniper

Runtime folders:
  $BASE/discovery
  $BASE/scans
  $BASE/targets
  $BASE/reports
  $BASE/analysis
  $BASE/config
  $BASE/runs
  $BASE/.runtime
  $BASE/.bundle-staging

EOF
