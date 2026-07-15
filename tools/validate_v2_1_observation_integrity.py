#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures/observation-integrity/duplicate-service-records"
ANALYZER = ROOT / "tools/analyze_v2_1_gnmap.py"
PROFILES = ROOT / "classification/evidence_profiles.json"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def load_analyzer() -> Any:
    spec = importlib.util.spec_from_file_location("netsniper_v2_1_analyzer", ANALYZER)
    if spec is None or spec.loader is None:
        fail("unable to load v2.1 analyzer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_sanitized() -> None:
    allowed = {"192.0.2.10", "192.0.2.0/24"}
    prohibited_fragments = (
        "192.168.",
        "10.",
        "172.16.",
        "meraki",
        "ec:71:db",
        "cc:9c:3e",
        ".devices.",
    )
    for path in sorted(FIXTURE.rglob("*")):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for fragment in prohibited_fragments:
            if fragment.casefold() in text.casefold():
                fail(f"fixture contains prohibited reference-scan fragment {fragment!r}: {path}")
        for token in allowed:
            text = text.replace(token, "")
        if "192.0.2." in text:
            fail(f"fixture contains an unexpected documentation address: {path}")
    passed("sanitized regression fixture contains no reference-network identifiers")


def finding_key(item: dict[str, Any]) -> str:
    return f"{item['id']}|{item.get('protocol', 'tcp')}|{item['port']}"


def main() -> int:
    for path in (
        FIXTURE / "hosts.txt",
        FIXTURE / "services.gnmap",
        FIXTURE / "services.xml",
        FIXTURE / "expected.json",
        ANALYZER,
        PROFILES,
    ):
        if not path.is_file():
            fail(f"missing required file: {path.relative_to(ROOT)}")

    assert_sanitized()
    expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
    analyzer = load_analyzer()

    gnmap_line = (FIXTURE / "services.gnmap").read_text(encoding="utf-8").strip()
    gnmap_record = analyzer.parse_gnmap_line(gnmap_line)
    xml_record = analyzer.parse_nmap_xml(FIXTURE / "services.xml").get("192.0.2.10")
    merged = analyzer.merge_host_records(gnmap_record, xml_record)
    canonical = analyzer.canonicalize_port_observations(merged)

    ports = canonical.get("ports", [])
    if len(ports) != expected["canonical_port_count"]:
        fail(f"expected two canonical ports, found {len(ports)}")
    by_port = {(item["protocol"], item["port"], item["state"]): item for item in ports}
    for identity in expected["ports"]:
        key = (identity["protocol"], identity["port"], identity["state"])
        if key not in by_port:
            fail(f"missing canonical port identity: {key}")
    for port in (80, 443):
        item = by_port[("tcp", port, "open")]
        if "Sanitized Embedded Administration" not in str(item.get("product", "")):
            fail(f"rich product metadata was not retained for tcp/{port}")
        if not item.get("servicefp"):
            fail(f"service fingerprint metadata was not retained for tcp/{port}")
    passed("duplicate GNMAP/XML observations merge into two metadata-rich ports")

    duplicated = dict(canonical)
    duplicated["ports"] = [*ports, *ports]
    findings, score = analyzer.findings_for(duplicated)
    keys = [finding_key(item) for item in findings]
    if keys != expected["finding_keys"]:
        fail(f"unexpected canonical findings: {keys}")
    if score != expected["score"] or analyzer.severity(score) != expected["severity"]:
        fail("deduplicated finding score or severity is incorrect")
    passed("findings and risk are scored once per finding ID, protocol, and port")

    with tempfile.TemporaryDirectory(prefix="netsniper-v2.1-observation-integrity-") as temp_raw:
        temp = Path(temp_raw)
        analysis_json = temp / "analysis.json"
        analysis_text = temp / "analysis.txt"
        command = [
            sys.executable,
            str(ANALYZER),
            "--gnmap", str(FIXTURE / "services.gnmap"),
            "--hosts", str(FIXTURE / "hosts.txt"),
            "--analysis-json", str(analysis_json),
            "--analysis-text", str(analysis_text),
            "--services-xml", str(FIXTURE / "services.xml"),
            "--profiles", str(PROFILES),
            "--scanner-version", "v2.1.0-test",
            "--network", "192.0.2.0/24",
            "--timestamp", "sanitized-fixture",
        ]
        subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        analysis = json.loads(analysis_json.read_text(encoding="utf-8"))
        if len(analysis) != expected["host_count"]:
            fail("CLI did not preserve fixture host inventory")
        host = analysis[0]
        if len(host["scan_observation"]["ports"]) != expected["canonical_port_count"]:
            fail("analysis.json retained duplicate port observations")
        if [finding_key(item) for item in host["findings"]] != expected["finding_keys"]:
            fail("analysis.json retained duplicate findings")
        if host["score"] != expected["score"] or host["severity"] != expected["severity"]:
            fail("analysis.json score or severity differs from the canonical expectation")

        text = analysis_text.read_text(encoding="utf-8")
        if text.count("[HTTP_EXPOSED]") != 1 or text.count("[HTTPS_EXPOSED]") != 1:
            fail("analysis.txt does not contain exactly one line per finding")
        if f"SCORE: {expected['score']}" not in text or f"SEVERITY: {expected['severity']}" not in text:
            fail("analysis.txt score or severity differs from analysis.json")

        from netsniper_core.pipeline import enrich_bundle_analysis
        profiles = json.loads(PROFILES.read_text(encoding="utf-8"))
        (temp / "services.xml").write_bytes((FIXTURE / "services.xml").read_bytes())
        enriched, _, _ = enrich_bundle_analysis(analysis, temp, profiles)
        enriched_host = enriched["hosts"][0]
        if enriched_host["findings"] != host["findings"]:
            fail("analysis.enriched.json projection changed the canonical findings")
        if enriched_host["score"] != host["score"] or enriched_host["severity"] != host["severity"]:
            fail("analysis.enriched.json projection changed score or severity")
    passed("analysis.json, analysis.txt, and enriched projection agree")

    seal = json.loads((ROOT / "fixtures/device-corpus/evaluation/seal.json").read_text(encoding="utf-8"))
    if "tools/analyze_v2_1_gnmap.py" in seal.get("runtime_fingerprints", {}):
        fail("observation analyzer unexpectedly belongs to the sealed classifier fingerprint set")
    passed("classifier profiles, thresholds, expectations, and sealed fingerprints remain outside this fix")

    all_gate = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    marker = "validate_v2_1_observation_integrity.py"
    if marker not in all_gate or marker not in ci:
        fail("observation-integrity validator is not wired into CI and the complete gate")
    passed("observation-integrity regression is wired into CI and the complete gate")
    passed("NetSniper v2.1 observation and risk integrity validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
