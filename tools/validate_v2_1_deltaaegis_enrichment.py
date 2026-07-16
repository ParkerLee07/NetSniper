#!/usr/bin/env python3
from __future__ import annotations

import copy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netsniper_core.deltaaegis_enrichment import enrich_legacy_projection
from netsniper_core.legacy import compatibility_classification


def fail(message: str) -> None:
    print(f"[FAIL] {message}")
    raise SystemExit(1)


def passed(message: str) -> None:
    print(f"[PASS] {message}")


class LegacyFixture(dict):
    """Contract-complete test fixture for direct legacy adapter access."""

    def __missing__(self, key):
        if key in {
            "evidence",
            "contradictions",
            "secondary_candidates",
            "validators",
        }:
            return []
        if key in {
            "confidence",
            "raw_confidence",
            "candidate_count",
        }:
            return 0
        if key in {
            "validated",
        }:
            return False
        defaults = {
            "schema_version": "netsniper-classification-v1",
            "primary_type": "Unknown / Ambiguous",
            "type": "Unknown / Ambiguous",
            "confidence_label": "unknown",
            "confidence_band": "unknown",
            "decision": "unknown",
            "calibrated_decision": "unknown",
            "calibration_reason": "Synthetic validator fixture.",
            "siem_action": "no_action",
            "validation_state": "unknown",
            "method": "weighted_evidence",
            "explanation": "",
        }
        return defaults.get(key)


sample = {
    "schema_version": "netsniper-host-classification-v2",
    "classifier_version": "netsniper-classifier-v2",
    "taxonomy_version": "netsniper-device-taxonomy-v2",
    "evidence_profile_version": "netsniper-evidence-profiles-v2",
    "identity": {
        "decision": "provisional",
        "confidence": 20,
        "observed_keys": [{"kind": "ip", "value": "192.0.2.10", "stable": False}],
        "evidence_ids": [],
        "uncertainty_reasons": [],
    },
    "device_family": {
        "label": "compute_host",
        "confidence": 30,
        "confidence_band": "weak",
        "decision": "review",
        "evidence_ids": ["family-evidence"],
        "contradictions": [],
        "secondary_candidates": [],
        "uncertainty_reasons": ["insufficient_evidence_diversity"],
        "explanation": "Compute-host evidence is present.",
    },
    "roles": [{
        "label": "web_server",
        "confidence": 40,
        "confidence_band": "possible",
        "decision": "possible",
        "evidence_ids": ["role-evidence"],
        "contradictions": [],
        "secondary_candidates": [],
        "uncertainty_reasons": [],
        "explanation": "Web-server evidence is present.",
    }],
    "platform": {
        "label": "linux",
        "confidence": 40,
        "confidence_band": "possible",
        "decision": "possible",
        "evidence_ids": ["platform-evidence"],
        "contradictions": [],
        "secondary_candidates": [],
        "uncertainty_reasons": [],
        "explanation": "Linux evidence is present.",
    },
    "observation_quality": {
        "scan_completeness": "complete",
        "coverage_score": 100,
        "requested_collectors": ["discovery", "tcp_services"],
        "completed_collectors": ["discovery", "tcp_services"],
        "failed_collectors": [],
        "unavailable_collectors": [],
        "inventory_complete": True,
        "negative_evidence_allowed": True,
        "reasons": [],
    },
    "network_roles": ["default_gateway"],
    "evidence": [],
    "legacy_projection": LegacyFixture({
        "schema_version": "netsniper-classification-v1",
        "primary_type": "Compute Host",
        "type": "Compute Host",
        "confidence": 30,
        "raw_confidence": 30,
        "confidence_label": "weak",
        "confidence_band": "weak",
        "decision": "review",
        "calibrated_decision": "review_only",
        "calibration_reason": "Synthetic validator fixture.",
        "siem_action": "display_only",
        "validation_state": "unvalidated",
        "method": "weighted_evidence",
        "evidence": ["family-evidence"],
        "contradictions": [],
        "secondary_candidates": [],
        "validators": [],
    }),
}

actual = compatibility_classification(sample)
if actual.get("schema_version") != "netsniper-classification-v1":
    fail("legacy schema version changed")
context = actual.get("deltaaegis_context")
if not isinstance(context, dict):
    fail("DeltaAegis context missing")
if context.get("schema_version") != "netsniper-deltaaegis-evidence-context-v1":
    fail("context schema mismatch")
if context.get("operator_disposition") != "review":
    fail("review semantics were not preserved")
if context.get("network_roles") != ["default_gateway"]:
    fail("network role missing")
if set(context.get("evidence_ids", [])) != {
    "family-evidence", "role-evidence", "platform-evidence"
}:
    fail("axis evidence attribution incomplete")
if "insufficient_evidence_diversity" not in context.get("uncertainty_reasons", []):
    fail("uncertainty reason missing")
if not str(context.get("semantic_fingerprint", "")).startswith("sha256:"):
    fail("semantic fingerprint missing")
passed("structured DeltaAegis context is emitted")

base = {"schema_version": "netsniper-classification-v1", "sentinel": 1}
first = enrich_legacy_projection(base, sample)
changed = copy.deepcopy(sample)
changed["generated_at"] = "2099-01-01T00:00:00Z"
changed["evidence"] = [{"observed_at": "2099-01-01T00:00:00Z"}]
second = enrich_legacy_projection(base, changed)
if first["semantic_fingerprint"] != second["semantic_fingerprint"]:
    fail("fingerprint depends on volatile timestamps")
if first["sentinel"] != 1:
    fail("pre-existing legacy value changed")
passed("enrichment is additive and fingerprint is stable")

legacy_source = (ROOT / "netsniper_core/legacy.py").read_text(encoding="utf-8")
if "NETSNIPER_DELTAAEGIS_ENRICHMENT_V1" not in legacy_source:
    fail("legacy wrapper marker missing")
gate = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
if "validate_v2_1_deltaaegis_enrichment.py" not in gate:
    fail("complete gate wiring missing")
passed("authoritative projection and complete gate are wired")

print("[PASS] NetSniper v2.1 DeltaAegis evidence enrichment validator complete")
