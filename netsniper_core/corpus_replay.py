from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .contracts import (
    DECISIONS,
    FAMILIES,
    HOST_CLASSIFICATION_SCHEMA_VERSION,
    PLATFORMS,
    ROLES,
    UNCERTAINTY_REASONS,
    load_json,
)
from .corpus import classify_corpus_payload

REPLAY_SCHEMA_VERSION = "netsniper-corpus-replay-v1"
FIXED_REPLAY_TIME = "2026-07-15T00:00:00Z"


class CorpusReplayError(ValueError):
    pass


def _confined_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    resolved_root = root.resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise CorpusReplayError(f"corpus path escapes repository: {relative}") from exc
    return candidate


def _axis_reasons(result: dict[str, Any]) -> set[str]:
    reasons: set[str] = set()
    for item in [
        result.get("device_family", {}),
        result.get("platform", {}),
        result.get("identity", {}),
        *result.get("roles", []),
    ]:
        reasons.update(str(value) for value in item.get("uncertainty_reasons", []))
    return reasons


def _validate_axis_shape(item: dict[str, Any], vocabulary: set[str]) -> list[str]:
    errors: list[str] = []
    if item.get("label") not in vocabulary:
        errors.append(f"invalid axis label: {item.get('label')!r}")
    try:
        confidence = int(item.get("confidence"))
    except (TypeError, ValueError):
        errors.append("axis confidence is not an integer")
        confidence = -1
    if not 0 <= confidence <= 100:
        errors.append(f"axis confidence out of range: {confidence}")
    if item.get("decision") not in DECISIONS:
        errors.append(f"invalid axis decision: {item.get('decision')!r}")
    for reason in item.get("uncertainty_reasons", []):
        if reason not in UNCERTAINTY_REASONS:
            errors.append(f"invalid uncertainty reason: {reason!r}")
    return errors


def validate_result_shape(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "classifier_version",
        "taxonomy_version",
        "evidence_profile_version",
        "host_id",
        "generated_at",
        "identity",
        "device_family",
        "roles",
        "platform",
        "observation_quality",
        "evidence",
        "missing_evidence",
        "legacy_projection",
    }
    missing = sorted(required - set(result))
    if missing:
        errors.append(f"missing result fields: {missing}")
        return errors
    if result.get("schema_version") != HOST_CLASSIFICATION_SCHEMA_VERSION:
        errors.append("unexpected host-classification schema version")
    errors.extend(_validate_axis_shape(result["device_family"], FAMILIES))
    errors.extend(_validate_axis_shape(result["platform"], PLATFORMS))
    if not isinstance(result.get("roles"), list):
        errors.append("roles is not an array")
    else:
        for role in result["roles"]:
            errors.extend(_validate_axis_shape(role, ROLES))
    evidence = result.get("evidence", [])
    if not isinstance(evidence, list):
        errors.append("evidence is not an array")
        evidence = []
    evidence_ids = [item.get("evidence_id") for item in evidence if isinstance(item, dict)]
    if len(evidence_ids) != len(set(evidence_ids)):
        errors.append("evidence IDs are not unique")
    known_ids = set(evidence_ids)
    for item in [result["device_family"], result["platform"], *result.get("roles", [])]:
        for evidence_id in item.get("evidence_ids", []):
            if evidence_id not in known_ids:
                errors.append(f"axis references missing evidence ID: {evidence_id}")
    return errors


def _check_expectation(
    name: str,
    actual: dict[str, Any],
    expected: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    confidence = int(actual.get("confidence", 0))
    if actual.get("decision") != expected.get("decision"):
        errors.append(
            f"{name} decision {actual.get('decision')!r} != {expected.get('decision')!r}"
        )
    minimum = int(expected.get("minimum_confidence", 0))
    maximum = int(expected.get("maximum_confidence", 100))
    if not minimum <= confidence <= maximum:
        errors.append(
            f"{name} confidence {confidence} outside [{minimum}, {maximum}]"
        )
    return errors


def _validate_identity(
    fixture: dict[str, Any],
    result: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    expected = fixture["ground_truth"]["identity_stability"]
    actual = result["identity"]
    reasons = set(actual.get("uncertainty_reasons", []))
    if expected == "stable_mac" and actual.get("decision") != "stable":
        errors.append("stable-MAC fixture did not produce stable identity")
    elif expected in {"randomized_mac", "ephemeral_local_mac"}:
        if actual.get("decision") != "provisional":
            errors.append("unstable-MAC fixture did not produce provisional identity")
        if "identity_instability" not in reasons:
            errors.append("unstable-MAC fixture lacks identity_instability")
    elif expected == "hostname_only" and actual.get("decision") not in {"provisional", "unknown"}:
        errors.append("hostname-only fixture produced an invalid identity decision")
    return errors


def validate_fixture_result(
    fixture: dict[str, Any],
    result: dict[str, Any],
) -> list[str]:
    errors = validate_result_shape(result)
    expectations = fixture["expectations"]
    truth = fixture["ground_truth"]

    family = result["device_family"]
    errors.extend(_check_expectation("family", family, expectations["family"]))
    expected_family = truth["device_family"]
    allowed_families = {expected_family, *truth.get("acceptable_family_alternatives", [])}
    if expectations["family"]["decision"] == "unknown":
        if family.get("label") != "unknown":
            errors.append(f"unknown family fixture emitted {family.get('label')!r}")
    elif expected_family != "unknown" and family.get("label") not in allowed_families:
        errors.append(
            f"family label {family.get('label')!r} does not match ground truth {sorted(allowed_families)}"
        )
    elif expected_family == "unknown" and family.get("decision") == "classified":
        errors.append("unknown-ground-truth fixture emitted a classified family")

    platform = result["platform"]
    errors.extend(_check_expectation("platform", platform, expectations["platform"]))
    expected_platform = truth["platform"]
    if expectations["platform"]["decision"] == "unknown":
        if platform.get("label") != "unknown":
            errors.append(f"unknown platform fixture emitted {platform.get('label')!r}")
    elif expected_platform != "unknown" and platform.get("label") != expected_platform:
        errors.append(
            f"platform label {platform.get('label')!r} != ground truth {expected_platform!r}"
        )
    elif expected_platform == "unknown" and platform.get("decision") == "classified":
        errors.append("unknown-ground-truth fixture emitted a classified platform")

    roles_by_label = {item.get("label"): item for item in result.get("roles", [])}
    expected_roles = {item["role"] for item in expectations["roles"]}
    for role_expectation in expectations["roles"]:
        label = role_expectation["role"]
        actual = roles_by_label.get(label)
        if actual is None:
            errors.append(f"missing expected role {label!r}")
            continue
        errors.extend(_check_expectation(f"role {label}", actual, role_expectation))
    for role in result.get("roles", []):
        if role.get("decision") == "classified" and role.get("label") not in set(truth["roles"]):
            errors.append(f"unexpected classified role {role.get('label')!r}")

    reasons = _axis_reasons(result)
    required_reasons = set(expectations["required_uncertainty_reasons"])
    missing_reasons = sorted(required_reasons - reasons)
    if missing_reasons:
        errors.append(f"missing required uncertainty reasons: {missing_reasons}")

    for forbidden in expectations["forbidden_classified_families"]:
        if family.get("label") == forbidden and family.get("decision") == "classified":
            errors.append(f"forbidden family classified: {forbidden}")

    legacy_expected = expectations["legacy_projection"]
    legacy = result["legacy_projection"]
    if legacy.get("primary_type") != legacy_expected.get("primary_type"):
        errors.append(
            f"legacy primary_type {legacy.get('primary_type')!r} != {legacy_expected.get('primary_type')!r}"
        )
    if legacy.get("decision") != legacy_expected.get("decision"):
        errors.append(
            f"legacy decision {legacy.get('decision')!r} != {legacy_expected.get('decision')!r}"
        )

    errors.extend(_validate_identity(fixture, result))
    return errors


def _confidence_cap_errors(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for item in [result["device_family"], result["platform"], *result.get("roles", [])]:
        confidence = int(item.get("confidence", 0))
        decision = item.get("decision")
        reasons = set(item.get("uncertainty_reasons", []))
        if reasons & {"port_only_evidence", "vendor_only_evidence", "hostname_only_evidence"}:
            if confidence > 39:
                errors.append("weak-source-only candidate exceeded confidence 39")
        if decision == "possible" and not 40 <= confidence <= 69:
            errors.append("possible candidate outside confidence 40-69")
        if decision == "classified" and confidence < 70:
            errors.append("classified candidate below confidence 70")
        if "strong_contradiction" in reasons and decision == "classified":
            errors.append("strong contradiction remained classified")
    return errors


def _false_high_confidence_count(
    fixture: dict[str, Any],
    result: dict[str, Any],
) -> int:
    truth = fixture["ground_truth"]
    count = 0
    family = result["device_family"]
    family_allowed = {truth["device_family"], *truth.get("acceptable_family_alternatives", [])}
    if (
        family.get("decision") == "classified"
        and int(family.get("confidence", 0)) >= 90
        and family.get("label") not in family_allowed
    ):
        count += 1
    platform = result["platform"]
    if (
        platform.get("decision") == "classified"
        and int(platform.get("confidence", 0)) >= 90
        and platform.get("label") != truth["platform"]
    ):
        count += 1
    expected_roles = set(truth["roles"])
    for role in result.get("roles", []):
        if (
            role.get("decision") == "classified"
            and int(role.get("confidence", 0)) >= 90
            and role.get("label") not in expected_roles
        ):
            count += 1
    return count


def replay_corpus(
    repository_root: Path,
    *,
    splits: set[str] | None = None,
    generated_at: str = FIXED_REPLAY_TIME,
) -> dict[str, Any]:
    root = repository_root.resolve()
    manifest_path = root / "fixtures/device-corpus/manifest.json"
    profiles_path = root / "classification/evidence_profiles.json"
    manifest = load_json(manifest_path)
    profiles = load_json(profiles_path)

    fixtures = manifest.get("fixtures", [])
    if not isinstance(fixtures, list):
        raise CorpusReplayError("corpus manifest fixtures must be an array")

    selected: list[dict[str, Any]] = []
    for fixture in fixtures:
        if fixture.get("status") != "active":
            continue
        if splits and fixture.get("dataset_split") not in splits:
            continue
        selected.append(fixture)

    selected.sort(key=lambda item: item["fixture_id"])
    fixture_results: list[dict[str, Any]] = []
    deterministic_passes = 0
    schema_passes = 0
    uncertainty_passes = 0
    cap_passes = 0
    contradiction_passes = 0
    legacy_passes = 0
    expectation_passes = 0
    false_high_confidence_count = 0
    false_classified_unknown_count = 0

    try:
        import jsonschema  # type: ignore
    except ImportError:
        jsonschema = None
    host_schema = load_json(root / "contracts/v2.1/host-classification.schema.json")

    for fixture in selected:
        fixture_id = fixture["fixture_id"]
        errors: list[str] = []
        for relative in fixture.get("source_artifacts", []):
            path = _confined_path(root, relative)
            if not path.is_file():
                errors.append(f"missing source artifact: {relative}")
        normalized_relative = fixture.get("normalized_evidence_path")
        if not isinstance(normalized_relative, str):
            errors.append("active fixture lacks normalized_evidence_path")
            fixture_results.append(
                {"fixture_id": fixture_id, "passed": False, "errors": errors, "result": None}
            )
            continue
        normalized_path = _confined_path(root, normalized_relative)
        if not normalized_path.is_file():
            errors.append(f"missing normalized evidence: {normalized_relative}")
            fixture_results.append(
                {"fixture_id": fixture_id, "passed": False, "errors": errors, "result": None}
            )
            continue
        payload = load_json(normalized_path)
        first = classify_corpus_payload(payload, profiles, generated_at=generated_at)
        second = classify_corpus_payload(payload, profiles, generated_at=generated_at)
        first_bytes = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        second_bytes = json.dumps(second, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        deterministic = first_bytes == second_bytes
        if deterministic:
            deterministic_passes += 1
        else:
            errors.append("replay result is not deterministic")

        shape_errors = validate_result_shape(first)
        if jsonschema is not None:
            try:
                jsonschema.validate(first, host_schema)
            except Exception as exc:  # pragma: no cover - optional dependency
                shape_errors.append(f"JSON Schema validation failed: {exc}")
        if not shape_errors:
            schema_passes += 1
        errors.extend(shape_errors)

        expectation_errors = validate_fixture_result(fixture, first)
        if not expectation_errors:
            expectation_passes += 1
        errors.extend(expectation_errors)

        reasons = _axis_reasons(first)
        required = set(fixture["expectations"]["required_uncertainty_reasons"])
        if required <= reasons:
            uncertainty_passes += 1

        cap_errors = _confidence_cap_errors(first)
        if not cap_errors:
            cap_passes += 1
        errors.extend(cap_errors)

        contradiction_required = "strong_contradiction" in required
        contradiction_ok = (
            not contradiction_required
            or first["legacy_projection"].get("decision") == "contradiction_review"
        )
        if contradiction_ok:
            contradiction_passes += 1
        else:
            errors.append("strong-contradiction fixture lacks contradiction_review projection")

        legacy_expected = fixture["expectations"]["legacy_projection"]
        legacy = first["legacy_projection"]
        legacy_ok = (
            legacy.get("primary_type") == legacy_expected.get("primary_type")
            and legacy.get("decision") == legacy_expected.get("decision")
        )
        if legacy_ok:
            legacy_passes += 1

        false_high_confidence_count += _false_high_confidence_count(fixture, first)
        if (
            fixture["ground_truth"]["device_family"] == "unknown"
            and first["device_family"].get("decision") == "classified"
            and first["device_family"].get("label") != "unknown"
        ):
            false_classified_unknown_count += 1

        fixture_results.append(
            {
                "fixture_id": fixture_id,
                "dataset_split": fixture["dataset_split"],
                "passed": not errors,
                "errors": list(dict.fromkeys(errors)),
                "result": first,
            }
        )

    count = len(selected)
    denominator = max(1, count)
    output_count = sum(1 for item in fixture_results if item.get("result") is not None)
    metrics = {
        "active_fixture_count": count,
        "output_fixture_count": output_count,
        "deterministic_replay_rate": deterministic_passes / denominator,
        "host_retention_rate": output_count / denominator,
        "schema_validity_rate": schema_passes / denominator,
        "uncertainty_reason_compliance_rate": uncertainty_passes / denominator,
        "confidence_cap_compliance_rate": cap_passes / denominator,
        "contradiction_review_rate": contradiction_passes / denominator,
        "legacy_projection_match_rate": legacy_passes / denominator,
        "fixture_expectation_pass_rate": expectation_passes / denominator,
        "false_high_confidence_count": false_high_confidence_count,
        "false_classified_unknown_count": false_classified_unknown_count,
    }
    split_counts = Counter(item["dataset_split"] for item in selected)
    return {
        "schema_version": REPLAY_SCHEMA_VERSION,
        "generated_at": generated_at,
        "manifest_schema_version": manifest.get("schema_version"),
        "policy_version": manifest.get("policy_version"),
        "selected_splits": sorted(splits) if splits else sorted(split_counts),
        "split_counts": dict(sorted(split_counts.items())),
        "metrics": metrics,
        "passed": all(item["passed"] for item in fixture_results),
        "fixtures": fixture_results,
        "jsonschema_available": jsonschema is not None,
    }
