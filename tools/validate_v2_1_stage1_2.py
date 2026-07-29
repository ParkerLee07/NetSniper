#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.classifier import classify_host
from netsniper_core.contracts import (
    CAPABILITY_SCHEMA_VERSION,
    CLASSIFIER_VERSION,
    EVIDENCE_PROFILE_VERSION,
    HOST_CLASSIFICATION_SCHEMA_VERSION,
    TAXONOMY_VERSION,
    load_json,
)


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def validate_source_boundaries() -> None:
    shell = (ROOT / "netsniper.sh").read_text(encoding="utf-8")
    assert_true('SCANNER_VERSION="v2.1.1"' in shell, "scanner version is not v2.1.1")
    assert_true("analyze_v2_1_gnmap.py" in shell, "live analysis does not delegate to v2.1 Python runtime")
    assert_true("generate_v2_1_run_artifacts.py" in shell, "bundle finalization does not invoke v2.1 generator")
    assert_true("NETSNIPER_ROUTE_CONTEXT_V1" in shell, "local route context is not captured")
    assert_true("--route-context" in shell, "local route context is not passed to analysis")
    assert_true("netsniper-capability-manifest-v1" in shell, "manifest lacks capability-contract version")
    assert_true("netsniper-host-classification-v2" in shell, "manifest lacks host-classification version")
    forbidden = [
        "add_classification_evidence()",
        "update_best_candidate()",
        "WINDOWS_SERVER_SCORE=0",
        "CLASSIFICATION_PRIMARY=\"Unknown / Ambiguous\"",
    ]
    for marker in forbidden:
        assert_true(marker not in shell, f"retired shell scoring authority remains: {marker}")
    passed("netsniper.sh is orchestration-only for v2.1 classification")


def validate_data_contracts() -> tuple[dict, dict, dict, dict]:
    profiles = load_json(ROOT / "classification/evidence_profiles.json")
    taxonomy = load_json(ROOT / "classification/device_taxonomy.json")
    capability_schema = load_json(ROOT / "contracts/v2.1/capability-manifest.schema.json")
    host_schema = load_json(ROOT / "contracts/v2.1/host-classification.schema.json")
    assert_true(profiles["schema_version"] == EVIDENCE_PROFILE_VERSION, "evidence profile version mismatch")
    assert_true(taxonomy["schema_version"] == TAXONOMY_VERSION, "taxonomy version mismatch")
    assert_true(len(profiles.get("axis_profiles", [])) >= 30, "too few v2.1 axis profiles")
    scoring_policy = profiles.get("scoring_policy", {})
    assert_true(
        scoring_policy.get("minimum_possible_score") == 40,
        "possible threshold must remain 40",
    )
    assert_true(
        scoring_policy.get("minimum_classified_score") == 70,
        "classified threshold must remain 70",
    )
    assert_true(
        scoring_policy.get("port_only_cap") == 39
        and scoring_policy.get("vendor_only_cap") == 39
        and scoring_policy.get("hostname_only_cap") == 39,
        "weak-evidence confidence caps mismatch",
    )
    axes = {item["axis"] for item in profiles["axis_profiles"]}
    assert_true(axes == {"device_family", "role", "platform"}, "axis profile vocabulary mismatch")
    by_label = {
        (item["axis"], item["label"]): item
        for item in profiles["axis_profiles"]
    }
    security_ports = next(
        item
        for item in by_label[("role", "security_gateway")]["positive_evidence"]
        if item["id"] == "security_ports"
    )
    hypervisor_tls = next(
        item
        for item in by_label[("role", "hypervisor")]["positive_evidence"]
        if item["id"] == "vcenter_port"
    )
    assert_true(
        security_ports["value"] == "udp/500|udp/4500",
        "generic HTTPS still supports security_gateway",
    )
    assert_true(
        hypervisor_tls["value"] == "tcp/9443",
        "generic HTTPS still supports hypervisor",
    )
    assert_true(capability_schema["properties"]["schema_version"]["const"] == CAPABILITY_SCHEMA_VERSION, "capability schema mismatch")
    assert_true(host_schema["properties"]["schema_version"]["const"] == HOST_CLASSIFICATION_SCHEMA_VERSION, "host schema mismatch")
    passed("taxonomy, evidence profiles, and contract versions agree")
    return profiles, taxonomy, capability_schema, host_schema


def validate_classifier(profiles: dict, host_schema: dict) -> None:
    timestamp = "2026-07-15T00:00:00Z"
    multi = classify_host(
        {
            "host": "192.0.2.10",
            "hostname": "lab-server",
            "os_hints": ["Linux Ubuntu"],
            "ports": [
                {"port": 22, "service": "ssh", "product": "OpenSSH Ubuntu"},
                {"port": 443, "service": "https", "product": "nginx"},
                {"port": 5432, "service": "postgresql", "product": "PostgreSQL"},
                {"port": 2376, "service": "docker", "product": "Docker API"},
            ],
        },
        profiles,
        generated_at=timestamp,
    )
    assert_true(multi["schema_version"] == HOST_CLASSIFICATION_SCHEMA_VERSION, "host result schema mismatch")
    assert_true(multi["device_family"]["label"] == "compute_host", "multi-role host family mismatch")
    labels = {item["label"] for item in multi["roles"] if item["decision"] == "classified"}
    assert_true({"web_server", "database_server", "container_host"} <= labels, "multi-role classifier missed expected roles")
    assert_true(multi["platform"]["label"] == "linux", "Linux platform classification missing")

    port_only = classify_host(
        {"host": "192.0.2.20", "ports": [{"port": 80, "service": "http"}]},
        profiles,
        generated_at=timestamp,
    )
    web = next(item for item in port_only["roles"] if item["label"] == "web_server")
    assert_true(web["confidence"] <= 39, "port-only evidence exceeded confidence cap")
    assert_true(web["decision"] == "review", "weak port-only evidence must require review")
    assert_true("port_only_evidence" in web["uncertainty_reasons"], "port-only uncertainty reason missing")
    assert_true(port_only["device_family"]["label"] == "unknown", "web role improperly inferred a device family")
    assert_true(
        port_only["legacy_projection"]["primary_type"] == "Unknown / Ambiguous"
        and port_only["legacy_projection"]["decision"] == "review",
        "weak port-only legacy projection mismatch",
    )

    vendor_only = classify_host(
        {
            "host": "192.0.2.21",
            "vendor": "Hikvision",
        },
        profiles,
        generated_at=timestamp,
    )
    assert_true(
        vendor_only["device_family"]["label"] == "surveillance_device",
        "vendor-only camera family candidate missing",
    )
    assert_true(
        vendor_only["device_family"]["confidence"] <= 39
        and vendor_only["device_family"]["decision"] == "review",
        "vendor-only evidence must remain weak review",
    )
    assert_true(
        "vendor_only_evidence"
        in vendor_only["device_family"]["uncertainty_reasons"],
        "vendor-only uncertainty reason missing",
    )

    conflict = classify_host(
        {
            "host": "192.0.2.30",
            "ports": [
                {"port": 631, "service": "ipp", "product": "HP LaserJet printer"},
                {"port": 9100, "service": "jetdirect", "product": "HP printer"},
                {"port": 88, "service": "kerberos", "product": "Microsoft Windows Server"},
                {"port": 389, "service": "ldap", "product": "Active Directory"},
                {"port": 445, "service": "microsoft-ds", "product": "Windows Server SMB"},
            ],
            "os_hints": ["Microsoft Windows Server"],
        },
        profiles,
        generated_at=timestamp,
    )
    assert_true(conflict["device_family"]["decision"] == "review", "strong family contradiction did not force review")
    assert_true(conflict["legacy_projection"]["decision"] == "contradiction_review", "legacy contradiction projection mismatch")

    partial = classify_host(
        {
            "host": "192.0.2.35",
            "vendor": "HP",
            "ports": [
                {
                    "port": 631,
                    "service": "ipp",
                    "product": "HP LaserJet printer",
                }
            ],
            "observation_quality": {
                "scan_completeness": "partial",
                "requested_collectors": [
                    "discovery",
                    "tcp_services",
                    "os_detection",
                    "passive_neighbors",
                ],
                "completed_collectors": [
                    "discovery",
                    "os_detection",
                    "passive_neighbors",
                ],
                "failed_collectors": ["tcp_services"],
                "unavailable_collectors": [],
                "inventory_complete": True,
            },
        },
        profiles,
        generated_at=timestamp,
    )
    for axis_result in [
        partial["device_family"],
        partial["platform"],
        *partial["roles"],
    ]:
        assert_true(
            "partial_scan" in axis_result["uncertainty_reasons"],
            "partial-scan uncertainty reason missing",
        )
        assert_true(
            "collector_failed" in axis_result["uncertainty_reasons"],
            "collector-failed uncertainty reason missing",
        )

    unknown = classify_host({"host": "192.0.2.40", "ports": []}, profiles, generated_at=timestamp)
    assert_true(unknown["device_family"]["label"] == "unknown", "empty evidence did not remain unknown")
    assert_true(unknown["device_family"]["confidence"] == 0, "empty evidence has nonzero confidence")

    hostname_platform = classify_host(
        {"host": "192.0.2.41", "hostname": "gateway-lab"},
        profiles,
        generated_at=timestamp,
    )
    assert_true(
        hostname_platform["platform"]["label"] == "unknown",
        "hostname-only evidence became the canonical platform",
    )
    assert_true(
        hostname_platform["platform"]["secondary_candidates"]
        and hostname_platform["platform"]["secondary_candidates"][0]["label"] == "network_os",
        "hostname-only platform candidate was not preserved for review",
    )

    if importlib.util.find_spec("jsonschema") is not None:
        import jsonschema
        for item in (multi, port_only, conflict, unknown):
            jsonschema.validate(item, host_schema)
        passed("classifier cases validate against host-classification JSON Schema")
    else:
        passed("classifier semantic cases passed without optional jsonschema")
    passed(
        "multi-axis, threshold, confidence-cap, contradiction, "
        "partial-scan, and unknown behavior"
    )


def validate_corpus_policy_alignment() -> None:
    manifest = load_json(ROOT / "fixtures/device-corpus/manifest.json")
    fixtures = {
        item["fixture_id"]: item
        for item in manifest.get("fixtures", [])
    }
    assert_true(len(fixtures) == 18, "deterministic corpus must contain 18 fixtures")
    assert_true("evaluation_policy" not in manifest, "formal evaluation policy remains in manifest")
    assert_true("metric_gates" not in manifest, "statistical metric gates remain in manifest")

    weak_camera = fixtures["synthetic-vendor-only-camera-01"]
    assert_true(
        weak_camera["expectations"]["family"]["decision"] == "review",
        "vendor-only corpus family decision must be review",
    )
    assert_true(
        all(
            item["decision"] == "review"
            for item in weak_camera["expectations"]["roles"]
        ),
        "vendor-only corpus role decision must be review",
    )
    assert_true(
        weak_camera["expectations"]["platform"]["decision"] == "review",
        "vendor-only corpus platform decision must be review",
    )

    port_web = fixtures["synthetic-port-only-web-01"]
    web_expectation = next(
        item
        for item in port_web["expectations"]["roles"]
        if item["role"] == "web_server"
    )
    assert_true(
        web_expectation["decision"] == "review",
        "port-only web role must require review",
    )

    partial = fixtures["synthetic-partial-printer-scan-01"]
    possible_expectations = [
        partial["expectations"]["family"],
        partial["expectations"]["platform"],
        *partial["expectations"]["roles"],
    ]
    assert_true(
        all(
            item["decision"] != "possible"
            or int(item["minimum_confidence"]) >= 40
            for item in possible_expectations
        ),
        "possible corpus outcomes must begin at confidence 40",
    )

    split_counts: dict[str, int] = {}
    for item in fixtures.values():
        assert_true(item["status"] == "active", "remaining corpus fixture is not active")
        split = item["dataset_split"]
        assert_true(split in {"development", "regression"}, "unsupported corpus split remains")
        split_counts[split] = split_counts.get(split, 0) + 1
    assert_true(
        split_counts == {"development": 14, "regression": 4},
        "deterministic corpus split changed",
    )
    assert_true(
        not (ROOT / "fixtures/device-corpus/evaluation").exists(),
        "formal evaluation tree remains",
    )
    passed(
        "corpus expectations align with the frozen confidence policy and "
        "the simplified deterministic test framework"
    )

def validate_bundle_generator(profiles: dict, capability_schema: dict, host_schema: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="netsniper-v21-") as temporary:
        bundle = Path(temporary)
        write(bundle / "hosts.txt", "192.0.2.10\n192.0.2.20\n192.0.2.30\n")
        analysis = [
            {
                "host": "192.0.2.10",
                "ports": [
                    {"port": 22, "service": "ssh", "product": "OpenSSH Ubuntu"},
                    {"port": 443, "service": "https", "product": "nginx"},
                    {"port": 5432, "service": "postgresql", "product": "PostgreSQL"},
                ],
            },
            {
                "host": "192.0.2.20",
                "ports": [
                    {"port": 631, "service": "ipp", "product": "HP LaserJet printer"},
                    {"port": 9100, "service": "jetdirect", "product": "HP printer"},
                ],
            },
            {"host": "192.0.2.30", "ports": []},
        ]
        (bundle / "analysis.json").write_text(json.dumps(analysis, indent=2) + "\n", encoding="utf-8")
        write(bundle / "discovery.xml", "<?xml version='1.0'?><nmaprun><runstats><finished exit='success'/><hosts up='3'/></runstats></nmaprun>\n")
        write(bundle / "services.xml", "<?xml version='1.0'?><nmaprun><runstats><finished exit='success'/><hosts up='3'/></runstats></nmaprun>\n")
        write(bundle / "neighbors.txt", "192.0.2.10 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n")

        command = [
            sys.executable,
            str(ROOT / "tools/generate_v2_1_run_artifacts.py"),
            "--bundle-dir", str(bundle),
            "--run-id", "validator-run",
            "--scanner-version", "v2.1.1",
            "--source-commit", "cdbfa8e966f96a26941c1ba6a219984ea00732e4",
            "--target", "192.0.2.0/24",
            "--requested-profile", "accurate",
            "--effective-profile", "accurate",
            "--started-at", "2026-07-15T00:00:00Z",
            "--completed-at", "2026-07-15T00:01:00Z",
            "--configuration-fingerprint", "a" * 64,
            "--privilege-context", "unprivileged",
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if completed.returncode != 0:
            print(completed.stdout)
            print(completed.stderr, file=sys.stderr)
            fail("v2.1 bundle generator failed")

        required = {
            "analysis.enriched.json",
            "host_classifications.json",
            "classification_quality.json",
            "classification_quality.md",
            "capability_manifest.json",
        }
        missing = [name for name in required if not (bundle / name).is_file()]
        assert_true(not missing, f"bundle generator missed artifacts: {missing}")

        capability = load_json(bundle / "capability_manifest.json")
        classifications = load_json(bundle / "host_classifications.json")
        quality = load_json(bundle / "classification_quality.json")
        assert_true(capability["schema_version"] == CAPABILITY_SCHEMA_VERSION, "generated capability version mismatch")
        assert_true(capability["inventory"] == {
            "discovered_host_count": 3,
            "emitted_host_count": 3,
            "omitted_host_count": 0,
        }, "generated inventory counts mismatch")
        assert_true(capability["integrity"]["host_inventory_preserved"] is True, "host inventory not preserved")
        assert_true(capability["execution"]["status"] == "partial", "accurate run without OS/UDP evidence should be partial")
        assert_true(len(classifications) == 3, "one host classification per discovered host was not emitted")
        assert_true(quality["false_confidence_candidate_count"] == 0, "quality report found false high-confidence results")
        artifact_ids = [item["artifact_id"] for item in capability["artifacts"]]
        assert_true(len(artifact_ids) == len(set(artifact_ids)), "capability artifact IDs are not unique")

        if importlib.util.find_spec("jsonschema") is not None:
            import jsonschema
            jsonschema.validate(capability, capability_schema)
            for classification in classifications:
                jsonschema.validate(classification, host_schema)
            passed("generated capability and host objects validate against JSON Schemas")
        else:
            passed("generated bundle semantic validation passed without optional jsonschema")
    passed("mandatory capability, host-classification, quality, and inventory artifacts")


def main() -> int:
    validate_source_boundaries()
    profiles, _, capability_schema, host_schema = validate_data_contracts()
    validate_classifier(profiles, host_schema)
    validate_corpus_policy_alignment()
    validate_bundle_generator(profiles, capability_schema, host_schema)
    passed("NetSniper v2.1 Stages 1-2 implementation validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
