## NetSniper v1.7.0 — Device Intelligence Expansion

NetSniper v1.7.0 expands the scanner from calibrated classification into a stronger device-intelligence producer for DeltaAegis and other downstream tools.

Current release: **NetSniper v1.7.0 — Device Intelligence Expansion**

### What v1.7.0 adds

- Formal device taxonomy under `classification/device_taxonomy.json`.
- Evidence-profile map under `classification/evidence_profiles.json`.
- Reusable v1.7 host classifier for normalized host records.
- Host normalizer for current and legacy NetSniper analysis shapes.
- Safe analysis enhancer that writes `analysis.enriched.json` without overwriting `analysis.json`.
- Classification quality reports:
  - `classification_quality.json`
  - `classification_quality.md`
- Bundle manifest references for v1.7 artifacts.
- Release gate validation through `tools/validate_v1_7_release_gate.sh`.

### v1.7 Bundle Artifacts

Each finalized run bundle can now include:

```text
analysis.json
analysis.enriched.json
classification_quality.json
classification_quality.md
manifest.json
```

`analysis.json` remains the original compatibility artifact. `analysis.enriched.json` contains v1.7 classification details, evidence, contradictions, confidence bands, SIEM actions, and secondary candidates.

### v1.7 Classification Quality

The quality report summarizes:

- host count
- classified count
- possible/review count
- unknown count
- contradiction host count
- confidence-band distribution
- top device types
- review queue sample
- false-confidence candidates
- unknown hosts with exposed services
- sample explanations by device type

NetSniper v1.7.0 is intentionally conservative. A weak or generic service should remain `possible` or `review_queue` instead of becoming a confident but unreliable classification.

### v1.7 Validation

Run:

```bash
./tools/validate_v1_7_release_gate.sh
```

The release gate checks shell syntax, taxonomy, evidence profiles, fixtures, reusable host classification, normalization, analysis enhancement, run artifact generation, manifest awareness, latest bundle artifacts, and false-confidence review metrics.

---
## NetSniper v1.6.0 — Intelligence Validation and Confidence Calibration

NetSniper v1.6.0 improves classification intelligence for SIEM ingestion by adding calibrated confidence fields, validator-style evidence checks, contradiction-aware gating, service-text product validation, and validator summaries.

### Highlights

- Adds calibrated confidence fields: `confidence_band`, `calibrated_decision`, `siem_action`, and `calibration_reason`.
- Adds passive classification validators for confirmed, inconclusive, contradictory, and not-applicable evidence states.
- Adds contradiction-aware gating with `validation_state`, `contradiction_count`, and `siem_action: "contradiction_review"`.
- Adds service-text product validators for product/vendor-backed classification evidence.
- Adds `validator_summary` so downstream SIEM tools can quickly evaluate validation status.
- Preserves legacy v1.x classification fields for DeltaAegis compatibility.

### Validation

Run:

    ./tools/validate_v1_6_release_gate.sh

# NetSniper

<!-- NETSNIPER_V140_README_START -->
## NetSniper v1.6.0 Current Capabilities

NetSniper v1.6.0 expands the scanner from evidence-based classification into a broader device-role identification sensor for DeltaAegis and other downstream tools.

### What v1.6.0 adds

- **Evidence-based classification** — assigns suspected device roles using weighted service evidence instead of one-off static port assumptions.
- **Classification confidence** — records numeric confidence, confidence labels, and classification decisions such as `classified`, `possible`, and `unknown`.
- **Explainable evidence** — stores evidence entries with candidate role, source, value, points, and reason.
- **Contradiction tracking** — records conflicting signals when a host exposes service combinations that do not cleanly match one role.
- **Secondary candidates** — preserves alternate likely roles for downstream review.
- **DeltaAegis-ready schema aliases** — includes both canonical and compatibility fields such as `primary_type`, `type`, `secondary_candidates`, and `candidates`.
- **Expanded monitored TCP profile** — scans a broader set of security-relevant ports for web, printer, camera/NVR, database, Windows, Active Directory, container, Kubernetes, mail, and network infrastructure signals.
- **v1.5 validators** — includes taxonomy, fixture, classifier-progress, service-text, behavior, and release-gate validators.

### Classification schema

NetSniper v1.6.0 uses the classification schema version `netsniper-classification-v1`.

Each analyzed host now includes a `classification` object with:

- `schema_version`
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

NetSniper keeps legacy compatibility fields such as `device_type` and `device_type_confidence` so existing downstream tooling can continue to consume results.

### Intended use

NetSniper is still a sensor, not a full SIEM and not an exploit framework. Its job is to observe, classify, score, and package network telemetry. DeltaAegis then stores, compares, correlates, and explains changes across accepted snapshots.
<!-- NETSNIPER_V140_README_END -->


**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs host discovery, scans a curated set of security-relevant TCP ports, classifies likely device types, scores exposed services, and writes structured analysis files for downstream tooling.

NetSniper is also the active network sensor for **DeltaAegis**. Each completed full-pipeline run creates an immutable telemetry bundle containing raw Nmap XML, discovery evidence, neighbor-table enrichment, interpreted findings, and a versioned manifest.

## Current Release

Current release: **NetSniper v1.7.0 — Device Intelligence Expansion**

NetSniper v1.6.0 expands device classification accuracy with a broader taxonomy, weaker generic web-interface scoring, service-text evidence, synthetic classification fixtures, and behavior validation.

Recommended validation before release or demo use:

    ./tools/validate_v1_6_release_gate.sh


## NetSniper v1.6.0 Intelligence Validation

NetSniper v1.6.0 improves classification intelligence for SIEM ingestion by adding calibrated confidence fields, validator results, contradiction-aware gating, service-text product validation, and validator summaries.

### v1.6 Intelligence Fields

Each host classification now keeps the legacy v1.x fields while adding safer SIEM-oriented fields:

- `confidence_band`
- `calibrated_decision`
- `siem_action`
- `calibration_reason`
- `validation_state`
- `contradiction_count`
- `validators`
- `validator_summary`

Legacy fields such as `classification.decision`, `classification.primary_type`, `classification.confidence`, `device_type`, and `device_type_confidence` remain available for downstream compatibility.

### Confidence Calibration

NetSniper v1.6.0 uses calibrated confidence bands:

- `unknown`: no useful classification evidence.
- `weak`: weak evidence only; display/review context.
- `possible`: some supporting evidence; review queue context.
- `likely`: stronger evidence; can inform risk context.
- `confirmed`: strong validated evidence; eligible for stronger SIEM use.

### SIEM Behavior

NetSniper v1.6.0 is designed to reduce alert fatigue. Weak classifications are not treated as confirmed identity. Contradictory classifications are routed to review through `siem_action: "contradiction_review"` even when legacy compatibility fields still show a classified decision.

### Validators

v1.6.0 adds validator-style intelligence records:

- passive evidence validators
- high-reliability evidence validator
- weak evidence validator
- contradiction validator
- generic web interface validator
- service-text product validator
- validator summary counts

This gives DeltaAegis and other SIEM consumers a clearer distinction between observed evidence, validated identity, weak guesses, and conflicting signals.


## Features

- Local-subnet host discovery with Nmap.
- Curated TCP service scanning aligned with TrueAegis validation workflows.
- Device classification and exposure scoring.
- Structured JSON analysis output for automation.
- Optional Greenbone integration for deeper assessment.
- Immutable `netsniper-run-v2` telemetry bundles for DeltaAegis.
- Exact monitored-port profile fingerprinting to prevent false historical deltas after scan-profile changes.
- Archived discovery XML and neighbor-table telemetry for MAC-backed identity correlation.

## Requirements

```bash
sudo apt update
sudo apt install nmap jq -y
```

Optional Greenbone integration requires a configured GVM installation and `gvm-cli`.

## Installation

Install required packages:

```bash
sudo apt update
sudo apt install -y nmap jq coreutils
git clone https://github.com/ParkerLee07/NetSniper.git
cd NetSniper
chmod +x install.sh
./install.sh
```
## After Installation

Run:

```bash
netsniper
```

## Uninstall

Run:

```bash
./uninstall.sh
./uninstall.sh --purge
```

## Pipeline

```text
Discovery
  ↓
Curated service scan
  ↓
Relevant-host extraction
  ↓
Exposure analysis
  ↓
Report generation
  ↓
Immutable DeltaAegis telemetry bundle
```

## Runtime Outputs

Runtime output is intentionally excluded from Git.

```text
~/NetSniper/
├── discovery/                 # latest discovery evidence
├── scans/                     # latest service-scan evidence
├── targets/                   # latest analysis files
├── reports/                   # generated reports
├── runs/                      # immutable DeltaAegis telemetry bundles
└── config/                    # local runtime configuration
```

A finalized `runs/<scan_id>/manifest.json` file marks a telemetry bundle as ready for downstream ingestion.

## DeltaAegis Telemetry Contract

Current immutable bundles use:

```text
netsniper-run-v2
```

The versioned manifest records:

- Exact monitored TCP ports.
- SHA-256 scan-profile fingerprint.
- NetSniper and Nmap versions.
- Target subnet.
- Discovery interface.
- Scan timestamps and host counts.
- Paths to archived discovery XML, service XML, findings JSON, and neighbor telemetry.

See [`Docs/deltaaegis-integration.md`](Docs/deltaaegis-integration.md).

## Scope and Limitations

NetSniper is a focused sensor, not a full SIEM and not an exploit framework. It reports observations from its configured TCP profile. It does not claim to scan every possible TCP or UDP port.

## Authorized Use Only

NetSniper is provided for educational use and authorized security testing. Use it only on systems and networks for which you have explicit permission.

## License

MIT License. See [`LICENSE`](LICENSE).
