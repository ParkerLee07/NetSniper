#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running shell syntax check..."
bash -n netsniper.sh

echo "[*] Running taxonomy validator..."
./tools/validate_v1_5_taxonomy.sh

echo "[*] Running fixture validator..."
./tools/validate_v1_5_fixtures.sh

echo "[*] Validating cumulative NetSniper v1.5 classifier progress..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

checks = {
    "web_demotion": [
        "# NETSNIPER_CLASSIFICATION_ENGINE_V150_DEV",
        "HTTP service detected; treated as weak web-interface evidence",
        "HTTPS service detected; treated as weak web-interface evidence",
        'update_best_candidate "Web Server / Web Application Host" "$WEB_SCORE"',
    ],
    "router_nas": [
        "ROUTER_GATEWAY_SCORE=0",
        "NAS_SCORE=0",
        "router_gateway) ROUTER_GATEWAY_SCORE",
        "nas) NAS_SCORE",
        'update_best_candidate "Router / Gateway" "$ROUTER_GATEWAY_SCORE"',
        'update_best_candidate "NAS / File Server" "$NAS_SCORE"',
        "SMB plus NFS strongly suggests NAS or file server",
    ],
    "voip_ups": [
        "VOIP_SCORE=0",
        "UPS_SCORE=0",
        "voip) VOIP_SCORE",
        "ups) UPS_SCORE",
        'update_best_candidate "VoIP Phone / PBX" "$VOIP_SCORE"',
        'update_best_candidate "UPS / Power Device" "$UPS_SCORE"',
        "SIP service suggests VoIP endpoint or PBX",
        "SNMP plus web management may indicate UPS",
    ],
    "security_hypervisor": [
        "SECURITY_SCORE=0",
        "HYPERVISOR_SCORE=0",
        "security_appliance) SECURITY_SCORE",
        "hypervisor) HYPERVISOR_SCORE",
        'update_best_candidate "Security Appliance" "$SECURITY_SCORE"',
        'update_best_candidate "Hypervisor / Virtualization Host" "$HYPERVISOR_SCORE"',
        "IKE/IPsec service suggests VPN or security gateway",
        "Proxmox management port detected",
    ],
    "windows_linux": [
        "WINDOWS_SERVER_SCORE=0",
        "WINDOWS_WORKSTATION_SCORE=0",
        "LINUX_SERVER_SCORE=0",
        "windows_server) WINDOWS_SERVER_SCORE",
        "windows_workstation) WINDOWS_WORKSTATION_SCORE",
        "linux_server) LINUX_SERVER_SCORE",
        'update_best_candidate "Windows Server" "$WINDOWS_SERVER_SCORE"',
        'update_best_candidate "Windows Workstation" "$WINDOWS_WORKSTATION_SCORE"',
        'update_best_candidate "Linux Server" "$LINUX_SERVER_SCORE"',
        "SMB plus RDP without directory services suggests Windows workstation",
        "SSH plus NFS suggests Linux or Unix server role",
    ],
    "ap_switch": [
        "AP_SCORE=0",
        "SWITCH_SCORE=0",
        "wireless_ap) AP_SCORE",
        "managed_switch) SWITCH_SCORE",
        'update_best_candidate "Wireless Access Point" "$AP_SCORE"',
        'update_best_candidate "Managed Switch / Network Infrastructure" "$SWITCH_SCORE"',
        'add_classification_evidence "managed_switch" "port-combination" "snmp+ssh"',
        'add_classification_evidence "managed_switch" "port-combination" "snmp+web"',
        'add_classification_evidence "wireless_ap" "port-combination" "upnp+web"',
    ],
    "dev_iot": [
        "DEV_ADMIN_SCORE=0",
        "IOT_SCORE=0",
        "dev_admin) DEV_ADMIN_SCORE",
        "iot) IOT_SCORE",
        'update_best_candidate "Development / Admin Interface" "$DEV_ADMIN_SCORE"',
        'update_best_candidate "IoT / Embedded Device" "$IOT_SCORE"',
        'add_classification_evidence "dev_admin" "port-combination" "tcp/3000+9090"',
        'add_classification_evidence "iot" "port-combination" "upnp+web"',
    ],
    "container_database_refinement": [
        "kube) CONTAINER_SCORE",
        'update_best_candidate "Container Infrastructure" "$CONTAINER_SCORE"',
        'add_classification_evidence "container" "port-combination" "k8s-api+kubelet"',
        'add_classification_evidence "container" "port-combination" "docker+admin-console"',
        'add_classification_evidence "database" "port-combination" "elasticsearch-http+transport"',
        'add_classification_evidence "database" "port-combination" "mysql+postgresql"',
        'add_classification_evidence "database" "port-combination" "rdbms+redis"',
    ],
    "service_text_evidence": [
        "line_has()",
        "v1.5 service-text classification evidence",
        'add_classification_evidence "nas" "service-text" "storage-product"',
        'add_classification_evidence "printer" "service-text" "printer-product"',
        'add_classification_evidence "camera" "service-text" "camera-product"',
        'add_classification_evidence "wireless_ap" "service-text" "ap-product"',
        'add_classification_evidence "managed_switch" "service-text" "switch-product"',
        'add_classification_evidence "ups" "service-text" "power-product"',
        'add_classification_evidence "security_appliance" "service-text" "security-product"',
        'add_classification_evidence "hypervisor" "service-text" "hypervisor-product"',
        'add_classification_evidence "dev_admin" "service-text" "admin-tool"',
        'add_classification_evidence "iot" "service-text" "embedded-product"',
        'add_classification_evidence "web" "service-text" "web-server-product"',
    ],
}

failed = False

for group, required in checks.items():
    missing = [item for item in required if item not in text]

    if missing:
        failed = True
        print(f"[-] {group} missing expected item(s):")
        for item in missing:
            print(f"    {item}")
    else:
        print(f"[+] {group}: present")

stale_forbidden = [
    'update_best_candidate "Web Server" "$WEB_SCORE"',
    'update_best_candidate "Windows Host" "$WINDOWS_SCORE"',
    'update_best_candidate "Linux / Web Server" "$LINUX_WEB_SCORE"',
    'update_best_candidate "Likely Active Directory / Domain Controller" "$AD_SCORE"',
    '{device_type: "Web Server", confidence: $web}',
    '{device_type: "Windows Host", confidence: $windows}',
    '{device_type: "Linux / Web Server", confidence: $linux_web}',
    'update_best_candidate "Kubernetes Infrastructure" "$KUBE_SCORE"',
    '{device_type: "Kubernetes Infrastructure", confidence: $kube}',
]

stale_found = [item for item in stale_forbidden if item in text]

if stale_found:
    failed = True
    print("[-] Stale broad classifier labels remain:")
    for item in stale_found:
        print(f"    {item}")

if failed:
    raise SystemExit("[-] NetSniper v1.5 classifier progress validation failed.")

print("[+] PASS: cumulative NetSniper v1.5 classifier progress is valid.")
PY

echo
echo "[+] PASS: NetSniper v1.5 cumulative classifier validation succeeded."
