#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.classifier import classify_host
from netsniper_core.contracts import load_json, write_json
from netsniper_core.legacy import compatibility_classification
from netsniper_core.normalization import merge_host_records, parse_gnmap_line, parse_nmap_xml

FINDINGS = {
    21: ("FTP_EXPOSED", "FTP service exposed", "ftp", 6),
    22: ("SSH_EXPOSED", "SSH service exposed", "ssh", 3),
    23: ("TELNET_EXPOSED", "Telnet service exposed", "telnet", 10),
    25: ("SMTP_EXPOSED", "SMTP service exposed", "smtp", 4),
    53: ("DNS_EXPOSED", "DNS service exposed", "dns", 4),
    80: ("HTTP_EXPOSED", "HTTP service exposed", "http", 2),
    88: ("KERBEROS_EXPOSED", "Kerberos service exposed", "kerberos", 7),
    110: ("POP3_EXPOSED", "POP3 service exposed", "pop3", 4),
    135: ("MSRPC_EXPOSED", "Microsoft RPC service exposed", "msrpc", 5),
    139: ("NETBIOS_SMB_EXPOSED", "NetBIOS/SMB service exposed", "netbios-ssn", 5),
    143: ("IMAP_EXPOSED", "IMAP service exposed", "imap", 4),
    389: ("LDAP_EXPOSED", "LDAP service exposed", "ldap", 6),
    443: ("HTTPS_EXPOSED", "HTTPS service exposed", "https", 2),
    445: ("SMB_EXPOSED", "SMB service exposed", "smb", 8),
    465: ("SMTPS_EXPOSED", "SMTPS service exposed", "smtps", 3),
    515: ("LPD_EXPOSED", "LPD printing service exposed", "lpd", 4),
    554: ("RTSP_EXPOSED", "RTSP camera/service exposed", "rtsp", 5),
    587: ("SMTP_SUBMISSION_EXPOSED", "SMTP submission service exposed", "smtp-submission", 3),
    631: ("IPP_EXPOSED", "IPP printing service exposed", "ipp", 4),
    993: ("IMAPS_EXPOSED", "IMAPS service exposed", "imaps", 3),
    995: ("POP3S_EXPOSED", "POP3S service exposed", "pop3s", 3),
    1433: ("MSSQL_EXPOSED", "Microsoft SQL Server exposed", "mssql", 8),
    1521: ("ORACLE_EXPOSED", "Oracle database service exposed", "oracle", 8),
    1900: ("UPNP_EXPOSED", "UPnP service exposed", "upnp", 5),
    2049: ("NFS_EXPOSED", "NFS service exposed", "nfs", 6),
    2375: ("DOCKER_API_EXPOSED", "Docker API exposed", "docker-api", 10),
    2376: ("DOCKER_TLS_EXPOSED", "Docker TLS API exposed", "docker-api-tls", 8),
    3000: ("DASHBOARD_EXPOSED", "Dashboard or development service exposed", "dashboard", 6),
    3268: ("LDAP_GLOBAL_CATALOG_EXPOSED", "LDAP Global Catalog exposed", "ldap-gc", 7),
    3269: ("LDAPS_GLOBAL_CATALOG_EXPOSED", "LDAPS Global Catalog exposed", "ldaps-gc", 7),
    3306: ("MYSQL_EXPOSED", "MySQL database service exposed", "mysql", 8),
    3389: ("RDP_EXPOSED", "RDP service exposed", "rdp", 8),
    5000: ("REGISTRY_OR_WEB_EXPOSED", "Registry or web service exposed", "registry-web", 7),
    5432: ("POSTGRES_EXPOSED", "PostgreSQL database service exposed", "postgresql", 8),
    5555: ("ADB_EXPOSED", "Android Debug Bridge exposed", "adb", 9),
    5601: ("KIBANA_EXPOSED", "Kibana service exposed", "kibana", 7),
    5900: ("VNC_EXPOSED", "VNC service exposed", "vnc", 8),
    6379: ("REDIS_EXPOSED", "Redis service exposed", "redis", 9),
    6443: ("KUBERNETES_API_EXPOSED", "Kubernetes API exposed", "kubernetes-api", 9),
    7547: ("TR069_EXPOSED", "TR-069/CPE management service exposed", "tr-069", 7),
    8000: ("HTTP_ALT_EXPOSED", "Alternate HTTP service exposed", "http-alt", 3),
    8006: ("HYPERVISOR_ADMIN_EXPOSED", "Hypervisor administration service exposed", "hypervisor-admin", 8),
    8080: ("HTTP_ALT_EXPOSED", "Alternate HTTP service exposed", "http-alt", 3),
    8081: ("CI_OR_WEB_EXPOSED", "CI or alternate web service exposed", "ci-web", 8),
    8443: ("HTTPS_ALT_EXPOSED", "Alternate HTTPS service exposed", "https-alt", 3),
    8554: ("RTSP_ALT_EXPOSED", "Alternate RTSP service exposed", "rtsp-alt", 5),
    8888: ("HTTP_ALT_EXPOSED", "Alternate HTTP service exposed", "http-alt", 3),
    9000: ("ADMIN_SERVICE_CANDIDATE", "Possible administration service exposed", "admin-candidate", 2),
    9090: ("PROMETHEUS_EXPOSED", "Prometheus service exposed", "prometheus", 6),
    9100: ("PRINTER_9100_EXPOSED", "Raw printer service exposed", "printer-raw", 4),
    9200: ("ELASTICSEARCH_EXPOSED", "Elasticsearch service exposed", "elasticsearch", 8),
    9300: ("ELASTICSEARCH_TRANSPORT_EXPOSED", "Elasticsearch transport service exposed", "elasticsearch-transport", 7),
    9443: ("ADMIN_TLS_CANDIDATE", "Possible administration TLS service exposed", "admin-tls", 3),
    10250: ("KUBELET_EXPOSED", "Kubelet service exposed", "kubelet", 10),
    10255: ("KUBELET_READONLY_EXPOSED", "Kubelet read-only service exposed", "kubelet-readonly", 9),
    27017: ("MONGODB_EXPOSED", "MongoDB service exposed", "mongodb", 8),
}


def severity(score: int) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def findings_for(record: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    score = 0
    for port_record in record.get("ports", []):
        try:
            port = int(port_record.get("port", 0))
        except (TypeError, ValueError):
            continue
        if port not in FINDINGS:
            continue
        finding_id, name, service, points = FINDINGS[port]
        score += points
        findings.append(
            {
                "id": finding_id,
                "name": name,
                "service": service,
                "port": port,
                "score": points,
                "evidence": f"Port {port} open",
            }
        )
    return findings, score


def main() -> int:
    parser = argparse.ArgumentParser(description="Create NetSniper v2.1 analysis from Nmap evidence.")
    parser.add_argument("--gnmap", required=True)
    parser.add_argument("--hosts", required=True)
    parser.add_argument("--analysis-json", required=True)
    parser.add_argument("--analysis-text", required=True)
    parser.add_argument("--services-xml")
    parser.add_argument("--os-xml")
    parser.add_argument("--udp-xml")
    parser.add_argument("--profiles", default=str(ROOT / "classification/evidence_profiles.json"))
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--timestamp", required=True)
    args = parser.parse_args()

    profiles = load_json(Path(args.profiles))
    if not isinstance(profiles, dict):
        raise SystemExit("profiles must be a JSON object")

    xml_maps = []
    for value in (args.services_xml, args.os_xml, args.udp_xml):
        xml_maps.append(parse_nmap_xml(Path(value)) if value else {})

    by_host: dict[str, dict[str, Any]] = {}
    for line in Path(args.gnmap).read_text(encoding="utf-8", errors="replace").splitlines():
        parsed = parse_gnmap_line(line)
        if parsed:
            by_host[str(parsed["host"])] = parsed

    all_hosts = [line.strip() for line in Path(args.hosts).read_text(encoding="utf-8").splitlines() if line.strip()]
    generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    output: list[dict[str, Any]] = []
    text_lines = [
        "=========================================",
        "         NETSNIPER ANALYSIS",
        "=========================================",
        f"Scanner Version: {args.scanner_version}",
        f"Timestamp: {args.timestamp}",
        f"Network: {args.network}",
        f"Scan File: {args.gnmap}",
        "=========================================",
        "",
    ]

    for host in all_hosts:
        record = by_host.get(host, {"host": host, "ip": host, "ports": []})
        for xml_map in xml_maps:
            record = merge_host_records(record, xml_map.get(host))
        record["observation_quality"] = {
            "scan_completeness": "complete",
            "requested_collectors": ["discovery", "tcp_services"],
            "completed_collectors": ["discovery", "tcp_services"],
            "failed_collectors": [],
            "unavailable_collectors": [],
            "inventory_complete": True,
            "reasons": [],
        }
        classification = classify_host(record, profiles, generated_at=generated_at)
        compatible = compatibility_classification(classification)
        findings, score = findings_for(record)
        host_record = {
            "host": host,
            "ip": host,
            "device_type": compatible["primary_type"],
            "device_type_confidence": compatible["confidence"],
            "severity": severity(score),
            "score": score,
            "scanner_version": args.scanner_version,
            "timestamp": args.timestamp,
            "classification": compatible,
            "classification_v2_1": classification,
            "findings": findings,
            "scan_observation": record,
        }
        output.append(host_record)
        text_lines.extend(
            [
                f"HOST: {host}",
                f"SCORE: {score}",
                f"DEVICE TYPE: {compatible['primary_type']}",
                f"DEVICE TYPE CONFIDENCE: {compatible['confidence']} ({compatible['confidence_label']})",
                f"FAMILY: {classification['device_family']['label']} ({classification['device_family']['decision']})",
                "ROLES: " + ", ".join(role["label"] for role in classification["roles"]) if classification["roles"] else "ROLES: none",
                f"PLATFORM: {classification['platform']['label']} ({classification['platform']['decision']})",
                f"SEVERITY: {severity(score)}",
                "FINDINGS:",
                *[f"- [{item['id']}] {item['name']} ({item['evidence']})" for item in findings],
                "-----------------------------------",
            ]
        )

    write_json(Path(args.analysis_json), output)
    Path(args.analysis_text).write_text("\n".join(text_lines) + "\n", encoding="utf-8")
    print(json.dumps({"host_count": len(output), "analysis_json": args.analysis_json}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
