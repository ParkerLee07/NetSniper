## v1.7.0 - 2026-06-19

### Added

- Added formal device taxonomy for NetSniper v1.7 device intelligence.
- Added evidence profiles with reliability levels, point weights, contradiction rules, and SIEM actions.
- Added synthetic classification fixtures for camera, printer, container infrastructure, domain controller, database, router/gateway, generic web, and contradiction cases.
- Added reusable v1.7 host classifier.
- Added host normalizer for current and legacy NetSniper host record shapes.
- Added safe analysis enhancer that writes enriched classification output without modifying the original `analysis.json`.
- Added run artifacts:
  - `analysis.enriched.json`
  - `classification_quality.json`
  - `classification_quality.md`
- Added bundle manifest references for v1.7 classification artifacts.
- Added `tools/validate_v1_7_release_gate.sh` as the v1.7 release validation gate.

### Improved

- Improved classification explainability with evidence IDs, matched values, reliability levels, point values, confidence bands, decisions, SIEM actions, contradictions, and secondary candidates.
- Improved handling for real NetSniper analysis output by preserving host identity in enriched records.
- Improved weak web/dashboard detection, including Grafana-style dashboard services, without overclassifying them.
- Improved DeltaAegis readiness by making v1.7 artifacts stable and manifest-addressable.

### Validation

- Latest release-gate bundle validation passed with classified hosts present, no false-confidence candidates, and no unknown hosts with exposed services.
- `analysis.json` remains the original compatibility artifact.
- v1.7 enrichment artifacts are generated non-fatally during bundle finalization.

### Notes

NetSniper v1.7.0 does not add exploit checks or aggressive active probing. It improves local classification intelligence, explainability, and downstream SIEM readiness while preserving the existing scan workflow.


## v1.6.0 - 2026-06-19

### Added

- Added calibrated classification confidence fields for SIEM consumers.
- Added `confidence_band`, `calibrated_decision`, `siem_action`, and `calibration_reason`.
- Added passive classification validators that summarize whether evidence is confirmed, inconclusive, contradictory, or not applicable.
- Added contradiction-aware classification gating through `validation_state`, `contradiction_count`, and `siem_action: "contradiction_review"`.
- Added service-text product validators for stronger product/vendor-backed classification evidence.
- Added `validator_summary` with total, confirmed, inconclusive, refuted, not applicable, error, and validator name counts.
- Added `tools/validate_v1_6_intelligence_gate.sh` as the v1.6 release validation gate.

### Changed

- Updated scanner version to `v1.6.0`.
- Preserved legacy v1.x classification fields for compatibility with DeltaAegis and other downstream tools.
- Improved SIEM suitability by separating weak evidence, possible evidence, likely classifications, confirmed classifications, and contradictory classifications.

### Validation

Validated with:

- `tools/validate_v1_6_calibration.sh`
- `tools/validate_v1_6_passive_validators.sh`
- `tools/validate_v1_6_contradiction_gating.sh`
- `tools/validate_v1_6_service_text_validators.sh`
- `tools/validate_v1_6_validator_summary.sh`
- `tools/validate_v1_6_intelligence_gate.sh`
- `tools/validate_v1_6_release_gate.sh`
- `tools/validate_v1_5_behavior.sh`

### Notes

NetSniper v1.6.0 does not add aggressive active probing. It improves intelligence calibration and validation while preserving the existing scanning behavior.


## v1.5.0 - 2026-06-19

### Added

- Expanded NetSniper classification taxonomy for device-role accuracy.
- Added synthetic v1.5 classification fixtures covering 20 device categories.
- Added weak generic web-interface scoring to prevent HTTP-only hosts from becoming overconfident web-server classifications.
- Added Router/Gateway, NAS/File Server, VoIP/PBX, UPS/Power Device, Security Appliance, Hypervisor, Windows Server, Windows Workstation, Linux Server, Wireless AP, Managed Switch, Development/Admin Interface, IoT/Embedded Device, Container Infrastructure, and Database Server classification evidence.
- Added service-text evidence for common products and platforms.
- Added source-safe NETSNIPER_TEST_MODE for validator harnesses.
- Added v1.5 synthetic behavior smoke validation.
- Added v1.5 release gate validator.

### Changed

- SCANNER_VERSION is now v1.5.0.
- Menu banner now reports NETSNIPER v1.5.
- Kubernetes evidence is folded into Container Infrastructure instead of producing a standalone taxonomy label.

### Validation

- tools/validate_v1_5_release_gate.sh
- tools/validate_v1_5_behavior.sh
- tools/validate_v1_5_classifier_progress.sh
- tools/validate_v1_5_fixtures.sh
- tools/validate_v1_5_taxonomy.sh


# Changelog

<!-- NETSNIPER_V140_CHANGELOG_START -->
## v1.4.0 - 2026-06-18

### Added

- Evidence-based device classification engine.
- Weighted classification evidence model.
- Classification schema version: `netsniper-classification-v1`.
- Per-host classification object with:
  - `type`
  - `primary_type`
  - `confidence`
  - `confidence_label`
  - `decision`
  - `method`
  - `evidence`
  - `contradictions`
  - `candidates`
  - `secondary_candidates`
- Compatibility fields for DeltaAegis and other downstream parsers.
- Classification scoring support for:
  - web servers
  - Linux/web hosts
  - Windows hosts
  - Active Directory/domain-controller candidates
  - network printers and multifunction printers
  - IP cameras and NVRs
  - databases
  - container infrastructure
  - Kubernetes services
  - mail services
  - network infrastructure
- Contradiction detection for suspicious or ambiguous service combinations.
- Immutable bundle validation for v1.4 classification intelligence.
- Analysis validation for v1.4 classification intelligence.

### Changed

- `SCANNER_VERSION` finalized as `v1.4.0`.
- Device type confidence now reflects the v1.4 weighted classification result.
- Weak or uncertain classifications can remain `Unknown` while still exposing a possible classification candidate.
- DeltaAegis telemetry bundles now carry richer classification intelligence for downstream historical comparison.

### Validation

Validated with:

- `tools/validate_v1_4_analysis.sh`
- `tools/validate_v1_4_bundle.sh`

### Notes

- NetSniper v1.4.0 does not claim perfect device identification. It exposes evidence, confidence, contradictions, and secondary candidates so downstream tools and operators can review uncertain classifications.
<!-- NETSNIPER_V140_CHANGELOG_END -->


## [v1.3.1] - 2026-06-12

### Added
- Immutable `netsniper-run-v2` telemetry bundles for DeltaAegis ingestion.
- Archived discovery XML and neighbor-table telemetry for MAC-backed identity correlation.
- Exact monitored-port profile fingerprints and versioned telemetry manifests.
- Discovery interface, scan timing, Nmap version, and host-count metadata.
- LDAP `389/tcp` coverage for Active Directory classification.

### Fixed
- Prevented `8080/tcp` from incorrectly matching `80/tcp` and similar substring collisions.
- Prevented stale scan outputs from being reused after failed Nmap executions.
- Required successful Nmap XML completion before downstream analysis and archival.
- Restored relevant-host extraction inside the full pipeline.
- Treated an empty relevant-host result as a valid outcome.
- Replaced executable config sourcing with non-executable parsing.
- Made Greenbone credentials optional and protected saved configuration permissions.

### Compatibility
- Preserved the existing legacy analysis JSON format consumed by TrueAegis.

## NetSniper v1.3

NetSniper v1.3 improves exposure accuracy, reduces false positives, and strengthens compatibility with TrueAegis validation workflows.

### Added

* `PORTAINER_CANDIDATE` findings for services detected on TCP ports `9000` and `9443`
* Evidence messages explaining when Portainer fingerprint validation is required
* Improved compatibility with the TrueAegis v1.1 structured validation engine
* More accurate downstream handling of services that share commonly reused ports

### Changed

* Open TCP ports `9000` and `9443` are no longer automatically treated as confirmed Portainer exposures
* Hosts are no longer classified as container infrastructure solely because TCP ports `9000` or `9443` are open
* Container-infrastructure classification now relies on stronger Docker-oriented signals such as TCP ports `2375` and `2376`
* Portainer-related findings now remain candidates until protocol and product fingerprinting confirms the service
* Scanner version updated to `v1.3`

### Improved

* Reduced false positives caused by cameras, management interfaces, and unrelated applications using TCP port `9000`
* More accurate device classification
* Cleaner risk scoring for downstream analysis
* Better interoperability with TrueAegis service validation and remediation reporting

### Notes

NetSniper remains a standalone network reconnaissance and exposure-intelligence engine. TrueAegis integration is optional and provides additional validation, remediation guidance, and reporting capabilities.

NetSniper is intended for authorized security assessments only. Use the tool only on systems and networks where you have explicit permission.
