#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

NETSNIPER_HOME="${NETSNIPER_HOME:-$HOME/NetSniper}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
PURGE=0

for arg in "$@"; do
    case "$arg" in
        --purge)
            PURGE=1
            ;;
        -h|--help)
            echo "Usage: ./uninstall.sh [--purge]"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done

echo "[+] Removing NetSniper launchers"

rm -f "$BIN_DIR/netsniper"
sudo rm -f /usr/local/bin/netsniper 2>/dev/null || true

if [[ "$PURGE" -eq 1 ]]; then
    echo "[+] Removing NetSniper project directory: $NETSNIPER_HOME"
    rm -rf "$NETSNIPER_HOME"
else
    echo "[!] NetSniper project files and scan outputs were not deleted."
    echo "    To remove everything, run:"
    echo "    ./uninstall.sh --purge"
fi

echo "[+] NetSniper uninstall complete"
