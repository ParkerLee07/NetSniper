#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh || fail "netsniper.sh has shell syntax errors"

grep -Fq 'resolve_selected_scan_profile()' netsniper.sh \
    || fail "shared scan profile resolver is missing"

grep -Fq 'configure_scan_profile()' netsniper.sh \
    || fail "interactive scan profile configuration function is missing"

grep -Fq 'SCAN_PROFILE_B64=' netsniper.sh \
    || fail "saved config does not persist scan profile"

grep -Fq 'SCAN_PROFILE=$(b64_decode "$profile_b64")' netsniper.sh \
    || fail "saved config does not load scan profile"

grep -Fq 'Profile: $SCAN_PROFILE_EFFECTIVE' netsniper.sh \
    || fail "interactive menu does not display current scan profile"

grep -Fq '9) Change Scan Profile' netsniper.sh \
    || fail "interactive menu does not expose profile selection"

grep -Fq '9) configure_scan_profile && save_config ;;' netsniper.sh \
    || fail "interactive menu option does not save selected profile"

grep -Fq 'Deep profile is planned but not runtime-enabled' netsniper.sh \
    || fail "interactive profile selector should block deep"

NETSNIPER_TEST_MODE=1 bash -c '
    source ./netsniper.sh

    SCAN_PROFILE=balanced
    resolve_selected_scan_profile >/tmp/netsniper-profile-balanced.out
    test "$SCAN_PROFILE_EFFECTIVE" = "balanced"
    test "$SCAN_PROFILE_RUNTIME_STAGE" = "v1_8_compatible_tcp"

    SCAN_PROFILE=accurate
    resolve_selected_scan_profile >/tmp/netsniper-profile-accurate.out
    test "$SCAN_PROFILE_EFFECTIVE" = "accurate"
    test "$SCAN_PROFILE_RUNTIME_STAGE" = "accurate_tcp_service_depth_os_udp_lite"

    SCAN_PROFILE=deep
    ! resolve_selected_scan_profile >/tmp/netsniper-profile-deep.out 2>&1
' || fail "profile resolver behavior is incorrect under NETSNIPER_TEST_MODE"

tmp_backup="$(mktemp)"
had_config=0
if [ -f config/netsniper.conf ]; then
    cp config/netsniper.conf "$tmp_backup"
    had_config=1
fi

cleanup() {
    if [ "$had_config" = "1" ]; then
        cp "$tmp_backup" config/netsniper.conf
    else
        rm -f config/netsniper.conf
    fi
    rm -f "$tmp_backup"
}
trap cleanup EXIT

NETSNIPER_TEST_MODE=1 bash -c '
    source ./netsniper.sh

    NET="192.168.56.0/30"
    GREENBONE_USER=""
    GREENBONE_PASS=""
    SCAN_PROFILE="accurate"

    save_config >/tmp/netsniper-save-config.out
    SCAN_PROFILE="balanced"
    load_saved_config

    test "$NET" = "192.168.56.0/30"
    test "$SCAN_PROFILE" = "accurate"
    test "$SCAN_PROFILE_EFFECTIVE" = "accurate"
    test "$SCAN_PROFILE_RUNTIME_STAGE" = "accurate_tcp_service_depth_os_udp_lite"
' || fail "saved config did not preserve and restore scan profile"

pass "NetSniper v1.9 interactive profile config validation passed"
