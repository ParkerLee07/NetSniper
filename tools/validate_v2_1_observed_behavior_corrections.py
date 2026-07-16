#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.classifier import classify_host
from netsniper_core.contracts import load_json

FIXED_TIME = "2026-07-16T00:00:00Z"
PROFILES_PATH = ROOT / "classification/evidence_profiles.json"
ANALYZER = ROOT / "tools/analyze_v2_1_gnmap.py"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def role(result: dict[str, Any], label: str) -> dict[str, Any] | None:
    return next(
        (item for item in result.get("roles", []) if item.get("label") == label),
        None,
    )


def validate_specialized_role_evidence(profiles: dict[str, Any]) -> None:
    profiles_by_label = {
        (item["axis"], item["label"]): item
        for item in profiles["axis_profiles"]
    }
    security = profiles_by_label[("role", "security_gateway")]
    hypervisor = profiles_by_label[("role", "hypervisor")]
    security_ports = next(
        item for item in security["positive_evidence"]
        if item["id"] == "security_ports"
    )
    vcenter_port = next(
        item for item in hypervisor["positive_evidence"]
        if item["id"] == "vcenter_port"
    )
    assert_true(
        security_ports["value"] == "udp/500|udp/4500",
        "security-gateway port evidence is not limited to IKE/IPsec",
    )
    assert_true(
        vcenter_port["value"] == "tcp/9443",
        "hypervisor management evidence still includes generic HTTPS",
    )

    https_only = classify_host(
        {"host": "192.0.2.10", "ports": [{"port": 443, "protocol": "tcp"}]},
        profiles,
        generated_at=FIXED_TIME,
    )
    assert_true(role(https_only, "security_gateway") is None, "HTTPS-only host became a security gateway")
    assert_true(role(https_only, "hypervisor") is None, "HTTPS-only host became a hypervisor")
    web = role(https_only, "web_server")
    assert_true(web is not None and web["decision"] == "review", "HTTPS endpoint visibility was lost")

    printer = classify_host(
        {
            "host": "192.0.2.20",
            "ports": [
                {"port": 80, "protocol": "tcp"},
                {"port": 443, "protocol": "tcp"},
                {"port": 631, "protocol": "tcp"},
                {"port": 9100, "protocol": "tcp"},
            ],
        },
        profiles,
        generated_at=FIXED_TIME,
    )
    assert_true(printer["device_family"]["label"] == "printer", "printer family candidate disappeared")
    assert_true(printer["device_family"]["confidence"] == 39, "printer port-only cap changed")
    assert_true(printer["device_family"]["decision"] == "review", "printer port-only decision changed")
    assert_true(role(printer, "print_service") is not None, "print-service role disappeared")
    assert_true(role(printer, "web_server") is not None, "weak web-endpoint visibility disappeared")
    assert_true(role(printer, "security_gateway") is None, "printer retained false security-gateway role")
    assert_true(role(printer, "hypervisor") is None, "printer retained false hypervisor role")

    legitimate_security = classify_host(
        {
            "host": "192.0.2.30",
            "service_hints": ["pfSense firewall VPN gateway"],
            "http_titles": ["pfSense Firewall"],
            "ports": [{"port": 443, "protocol": "tcp"}],
        },
        profiles,
        generated_at=FIXED_TIME,
    )
    security_role = role(legitimate_security, "security_gateway")
    assert_true(
        security_role is not None and security_role["decision"] == "classified",
        "distinctive security-gateway evidence no longer classifies",
    )

    legitimate_hypervisor = classify_host(
        {
            "host": "192.0.2.40",
            "service_hints": ["Proxmox VE hypervisor"],
            "ports": [{"port": 8006, "protocol": "tcp"}],
        },
        profiles,
        generated_at=FIXED_TIME,
    )
    hypervisor_role = role(legitimate_hypervisor, "hypervisor")
    assert_true(
        hypervisor_role is not None and hypervisor_role["decision"] == "classified",
        "distinctive hypervisor evidence no longer classifies",
    )
    passed("generic HTTPS no longer creates specialized security-gateway or hypervisor roles")
    passed("printer confidence and weak web-endpoint behavior remain conservative")
    passed("distinctive security-gateway and hypervisor evidence remains effective")


def validate_platform_boundary(profiles: dict[str, Any]) -> None:
    hostname_only = classify_host(
        {"host": "192.0.2.50", "hostname": "gateway-lab"},
        profiles,
        generated_at=FIXED_TIME,
    )
    platform = hostname_only["platform"]
    assert_true(platform["label"] == "unknown", "hostname-only evidence became the canonical platform")
    assert_true(platform["confidence"] == 0 and platform["decision"] == "unknown", "unknown platform contract mismatch")
    assert_true("hostname_only_evidence" in platform["uncertainty_reasons"], "hostname-only reason was lost")
    secondary = platform["secondary_candidates"]
    assert_true(
        secondary and secondary[0]["label"] == "network_os" and secondary[0]["confidence"] == 20,
        "weak network_os candidate was not preserved as secondary evidence",
    )

    endpoint = classify_host(
        {"host": "192.0.2.60", "ports": []},
        profiles,
        generated_at=FIXED_TIME,
    )
    assert_true(endpoint["device_family"]["label"] == "unknown", "evidence-free endpoint family changed")
    assert_true(endpoint["platform"]["label"] == "unknown", "evidence-free endpoint platform changed")
    assert_true(not endpoint["roles"], "evidence-free endpoint gained a role")
    passed("sub-threshold hostname-only platform evidence remains a secondary candidate")
    passed("evidence-free endpoints remain unknown")


def route_context_text(target_line: str, default_lines: list[str]) -> str:
    return "\n".join([
        "NETSNIPER_ROUTE_CONTEXT_V1",
        "[target]",
        target_line,
        "[default]",
        *default_lines,
        "",
    ])


def write_route_context(path: Path, target_line: str, default_lines: list[str]) -> None:
    path.write_text(
        route_context_text(target_line, default_lines),
        encoding="utf-8",
    )


def analyze_with_route_context(
    temporary: Path,
    *,
    target: str,
    target_line: str,
    default_lines: list[str],
    stream: bool = False,
) -> list[dict[str, Any]]:
    temporary.mkdir(parents=True, exist_ok=True)
    gnmap = temporary / "services.gnmap"
    hosts = temporary / "hosts.txt"
    route_context = temporary / "route-context.txt"
    analysis_json = temporary / "analysis.json"
    analysis_text = temporary / "analysis.txt"
    gnmap.write_text(
        "Host: 192.0.2.1 () Ports: 80/open/tcp//http///\n",
        encoding="utf-8",
    )
    hosts.write_text("192.0.2.1\n192.0.2.60\n", encoding="utf-8")
    context_text = route_context_text(target_line, default_lines)
    if not stream:
        write_route_context(route_context, target_line, default_lines)
    command = [
        sys.executable,
        str(ANALYZER),
        "--gnmap", str(gnmap),
        "--hosts", str(hosts),
        "--analysis-json", str(analysis_json),
        "--analysis-text", str(analysis_text),
        "--scanner-version", "v2.1.0-dev",
        "--network", target,
        "--timestamp", "20260716-000000",
        "--route-context", "-" if stream else str(route_context),
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        input=context_text if stream else None,
    )
    if completed.returncode != 0:
        print(completed.stdout)
        print(completed.stderr, file=sys.stderr)
        fail("route-context analyzer regression failed")
    return json.loads(analysis_json.read_text(encoding="utf-8"))


def validate_route_context() -> None:
    with tempfile.TemporaryDirectory(prefix="netsniper-v21-route-") as directory:
        root = Path(directory)
        unique = analyze_with_route_context(
            root / "unique",
            target="192.0.2.0/24",
            target_line="192.0.2.1 dev eth0 src 192.0.2.60",
            default_lines=["default via 192.0.2.1 dev eth0 metric 100"],
            stream=True,
        )
        gateway = next(item for item in unique if item["host"] == "192.0.2.1")
        other = next(item for item in unique if item["host"] == "192.0.2.60")
        assert_true(
            gateway["scan_observation"].get("network_roles") == ["default_gateway"],
            "unique default-gateway observation was not attached to the matching host",
        )
        assert_true(
            gateway["classification_v2_1"]["device_family"]["label"] == "network_infrastructure"
            and gateway["classification_v2_1"]["device_family"]["decision"] == "possible",
            "default-gateway family result is not conservative possible evidence",
        )
        gateway_role = role(gateway["classification_v2_1"], "gateway")
        assert_true(
            gateway_role is not None and gateway_role["decision"] == "possible",
            "default-gateway role result is not conservative possible evidence",
        )
        assert_true(
            "default_gateway" not in other["scan_observation"].get("network_roles", []),
            "gateway evidence leaked to a different host",
        )

        ambiguous_dir = root / "ambiguous"
        ambiguous = analyze_with_route_context(
            ambiguous_dir,
            target="192.0.2.0/24",
            target_line="192.0.2.60 dev eth0 src 192.0.2.60",
            default_lines=[
                "default via 192.0.2.1 dev eth0 metric 100",
                "default via 192.0.2.254 dev eth0 metric 100",
            ],
        )
        ambiguous_gateway = next(item for item in ambiguous if item["host"] == "192.0.2.1")
        assert_true(
            "default_gateway" not in ambiguous_gateway["scan_observation"].get("network_roles", []),
            "ambiguous equal-metric gateways produced classification evidence",
        )

        outside_dir = root / "outside"
        outside = analyze_with_route_context(
            outside_dir,
            target="192.0.2.60/32",
            target_line="192.0.2.60 dev eth0 src 192.0.2.60",
            default_lines=["default via 192.0.2.1 dev eth0 metric 100"],
        )
        outside_gateway = next(item for item in outside if item["host"] == "192.0.2.1")
        assert_true(
            "default_gateway" not in outside_gateway["scan_observation"].get("network_roles", []),
            "out-of-scope default gateway produced classification evidence",
        )

        mismatch_dir = root / "mismatch"
        mismatch = analyze_with_route_context(
            mismatch_dir,
            target="192.0.2.0/24",
            target_line="192.0.2.60 dev eth0 src 192.0.2.60",
            default_lines=["default via 192.0.2.1 dev wlan0 metric 100"],
        )
        mismatch_gateway = next(item for item in mismatch if item["host"] == "192.0.2.1")
        assert_true(
            "default_gateway" not in mismatch_gateway["scan_observation"].get("network_roles", []),
            "default route on a different interface produced classification evidence",
        )

        multiple_target = analyze_with_route_context(
            root / "multiple-target-interfaces",
            target="192.0.2.0/24",
            target_line=(
                "192.0.2.60 dev eth0 src 192.0.2.60\n"
                "192.0.2.60 dev wlan0 src 192.0.2.61"
            ),
            default_lines=["default via 192.0.2.1 dev eth0 metric 100"],
        )
        multiple_target_gateway = next(
            item for item in multiple_target if item["host"] == "192.0.2.1"
        )
        assert_true(
            "default_gateway" not in multiple_target_gateway["scan_observation"].get(
                "network_roles", []
            ),
            "multiple target-route interfaces produced classification evidence",
        )

        malformed_metric = analyze_with_route_context(
            root / "malformed-metric",
            target="192.0.2.0/24",
            target_line="192.0.2.60 dev eth0 src 192.0.2.60",
            default_lines=["default via 192.0.2.1 dev eth0 metric invalid"],
        )
        malformed_gateway = next(
            item for item in malformed_metric if item["host"] == "192.0.2.1"
        )
        assert_true(
            "default_gateway" not in malformed_gateway["scan_observation"].get(
                "network_roles", []
            ),
            "malformed route metric produced classification evidence",
        )

        multipath = analyze_with_route_context(
            root / "multipath",
            target="192.0.2.0/24",
            target_line="192.0.2.60 dev eth0 src 192.0.2.60",
            default_lines=[
                (
                    "default metric 100 "
                    "nexthop via 192.0.2.1 dev eth0 weight 1 "
                    "nexthop via 192.0.2.254 dev eth0 weight 1"
                )
            ],
        )
        multipath_gateway = next(
            item for item in multipath if item["host"] == "192.0.2.1"
        )
        assert_true(
            "default_gateway" not in multipath_gateway["scan_observation"].get(
                "network_roles", []
            ),
            "ambiguous multipath default route produced classification evidence",
        )
    passed("unique in-scope route context supports only the matching default-gateway host")
    passed(
        "ambiguous, out-of-scope, interface-mismatched, malformed, and "
        "multipath routes fail closed"
    )


def validate_wiring() -> None:
    shell = (ROOT / "netsniper.sh").read_text(encoding="utf-8")
    required_shell_markers = (
        "NETSNIPER_ROUTE_CONTEXT_V1",
        "ip -4 route get",
        "ip -4 route show default table main",
        "args+=(--route-context -)",
        '} | python3 "$BASE/tools/analyze_v2_1_gnmap.py"',
    )
    for marker in required_shell_markers:
        assert_true(marker in shell, f"live route-context wiring is missing: {marker}")
    assert_true("nmap -O" not in shell, "route-context correction introduced OS probing")
    assert_true("netsniper-route-context" not in shell, "route context is written to disk")
    analyze_section = shell[
        shell.index("analyze_hosts()") : shell.index("generate_report()")
    ]
    assert_true(
        "mktemp" not in analyze_section,
        "analysis route context uses a temporary file",
    )

    complete_gate = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    validator_name = "validate_v2_1_observed_behavior_corrections.py"
    assert_true(validator_name in complete_gate, "complete gate omits observed-behavior validator")
    assert_true(validator_name in ci, "CI syntax list omits observed-behavior validator")
    passed("local route context adds no scan and is wired through the authoritative analyzer")
    passed("observed-behavior regression is wired into CI and the complete gate")


def main() -> int:
    profiles = load_json(PROFILES_PATH)
    validate_specialized_role_evidence(profiles)
    validate_platform_boundary(profiles)
    validate_route_context()
    validate_wiring()
    passed("NetSniper v2.1 observed-behavior correction validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
