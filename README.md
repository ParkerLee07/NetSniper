# NetSniper

**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs local-subnet host discovery, scans a curated set of security-relevant TCP ports, classifies likely device roles, scores exposed services, and writes structured telemetry for downstream tools such as DeltaAegis.

## Current Release

Current release: **NetSniper v1.7.0 — Device Intelligence Expansion**

NetSniper v1.7.0 expands the scanner from calibrated scan analysis into a stronger device-intelligence producer. It adds a formal taxonomy, evidence-profile scoring, reusable classification tooling, enriched run artifacts, classification quality reporting, and release-gated validation for device identity confidence.

## v1.7.0 Highlights

- Formal device taxonomy under `classification/device_taxonomy.json`.
- Evidence-profile scoring under `classification/evidence_profiles.json`.
- Reusable v1.7 host classifier.
- Host normalizer for current and legacy NetSniper analysis shapes.
- Safe analysis enrichment through `analysis.enriched.json`.
- Run-level classification quality reports:
  - `classification_quality.json`
  - `classification_quality.md`
- Manifest-addressable v1.7 artifacts for downstream tools.
- Conservative dashboard/web evidence handling, including Grafana-style dashboard services, without overclassifying them.
- Full v1.7 release gate validation.

## Bundle Artifacts

Finalized NetSniper run bundles can include:

    analysis.json
    analysis.enriched.json
    classification_quality.json
    classification_quality.md
    manifest.json

`analysis.json` remains the compatibility artifact.

`analysis.enriched.json` contains v1.7 classification details, evidence, contradictions, confidence bands, SIEM actions, secondary candidates, and explanations.

`classification_quality.json` and `classification_quality.md` summarize classification quality, review-queue items, false-confidence candidates, unknown hosts with exposed services, top device types, confidence-band distribution, and sample explanations.

## Classification Philosophy

NetSniper v1.7.0 is intentionally conservative.

A weak or generic service should remain `possible` or `review_queue` instead of becoming a confident but unreliable classification. The goal is to produce explainable network intelligence for review, not pretend that every open port proves device identity.

## Recommended Validation

Before release, demo use, or downstream DeltaAegis ingestion, run:

    ./tools/validate_v1_7_release_gate.sh

The v1.7 release gate checks:

- shell syntax
- taxonomy contract
- evidence profiles
- synthetic fixtures
- reusable host classification
- host normalization
- safe analysis enhancement
- quality report generation
- run artifact generation
- bundle manifest awareness
- docs/version markers
- latest bundle artifacts
- false-confidence review metrics

## Features

- Local-subnet host discovery with Nmap.
- Curated TCP service scanning aligned with TrueAegis and DeltaAegis workflows.
- Device classification and exposure scoring.
- Structured JSON analysis output for automation.
- Optional Greenbone integration for deeper assessment.
- Immutable `netsniper-run-v2` telemetry bundles for DeltaAegis.
- Exact monitored-port profile fingerprinting to prevent false historical deltas after scan-profile changes.
- Archived discovery XML and neighbor-table telemetry for MAC-backed identity correlation.
- v1.7 enriched classification and quality-report artifacts.

## Requirements

Install required packages:

    sudo apt update
    sudo apt install -y nmap jq coreutils

Optional Greenbone integration requires a configured GVM installation and `gvm-cli`.

## Installation

Clone and install:

    git clone https://github.com/ParkerLee07/NetSniper.git
    cd NetSniper
    chmod +x install.sh
    ./install.sh

## Usage

After installation, run:

    netsniper

Or run from the repository:

    ./netsniper.sh

## Pipeline

    Discovery
      ↓
    Curated service scan
      ↓
    Relevant-host extraction
      ↓
    Exposure analysis
      ↓
    Bundle finalization
      ↓
    v1.7 enrichment and quality artifacts
      ↓
    Immutable DeltaAegis telemetry bundle

## Runtime Outputs

Runtime output is intentionally excluded from Git.

    ~/NetSniper/
    ├── discovery/                 # latest discovery evidence
    ├── scans/                     # latest service-scan evidence
    ├── targets/                   # latest analysis files
    ├── reports/                   # generated reports
    ├── runs/                      # immutable DeltaAegis telemetry bundles
    └── config/                    # local runtime configuration

A finalized `runs/<scan_id>/manifest.json` file marks a telemetry bundle as ready for downstream ingestion.

## DeltaAegis Telemetry Contract

Current immutable bundles use:

    netsniper-run-v2

The versioned manifest records:

- exact monitored TCP ports
- SHA-256 scan-profile fingerprint
- NetSniper and Nmap versions
- target subnet
- discovery interface
- scan timestamps and host counts
- archived discovery XML
- archived service XML
- findings JSON
- neighbor telemetry
- v1.7 enriched analysis artifact paths
- v1.7 classification quality report paths

See [`Docs/deltaaegis-integration.md`](Docs/deltaaegis-integration.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for previous release history, including v1.6.0 and earlier.

## Scope and Limitations

NetSniper is a focused sensor, not a full SIEM and not an exploit framework.

It reports observations from its configured TCP profile. It does not claim to scan every possible TCP or UDP port, and it does not perform exploit checks or aggressive active probing.

## Authorized Use Only

NetSniper is provided for educational use and authorized security testing. Use it only on systems and networks for which you have explicit permission.

## License

MIT License. See [`LICENSE`](LICENSE).
