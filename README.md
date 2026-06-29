# NetSniper

**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs local-subnet host discovery, scans a curated set of security-relevant TCP ports, classifies likely device roles, scores exposed services, and writes structured telemetry for downstream tools such as DeltaAegis.

## Current Release

Current release: **NetSniper v2.0.0 — Reliable Telemetry Sensor for DeltaAegis**

NetSniper v2.0.0 promotes NetSniper from a scan-output generator into a stable
telemetry sensor for DeltaAegis and other defensive consumers. The release adds
machine-readable headless status, a v3 bundle manifest contract, profile runtime
budgets, bundle quality reports, and synthetic DeltaAegis fixture bundles while
preserving the v1.9 accuracy-profile behavior.

## v2.0.0 Highlights

- Added `--json-status-file <path>` for machine-readable headless orchestration.
- Added the `netsniper-status-v1` status contract.
- Added the `netsniper-run-v3` manifest contract with v2 compatibility aliases.
- Preserved legacy manifest fields such as `scan_profile_requested` and `scan_profile_effective`.
- Added profile runtime budget metadata for `quick`, `balanced`, and `accurate`.
- Added budget duration tracking and budget-exceeded reporting.
- Added `bundle_quality.json` using the `netsniper-bundle-quality-v1` schema.
- Embedded the bundle quality report into `manifest.quality`.
- Added synthetic DeltaAegis fixture bundles for complete and failed-quality ingestion tests.
- Added `tools/validate_v2_0_all.sh` and `tools/validate_v2_0_release_gate.sh`.
- Preserved v1.9 compatibility validators and profile behavior.

## Bundle Artifacts

Finalized NetSniper v2.0 run bundles can include:

    analysis.json
    analysis.enriched.json
    bundle_quality.json
    classification_quality.json
    classification_quality.md
    manifest.json
    os_detection.xml / os_detection.gnmap / os_detection.nmap
    udp_lite.xml / udp_lite.gnmap / udp_lite.nmap

`analysis.json` remains the compatibility artifact. OS and UDP-lite evidence are archived as
separate artifacts when produced by the `accurate` profile; they should be treated as supporting
evidence, not standalone device identity.

`bundle_quality.json` tells downstream tools whether the bundle is safe to ingest. DeltaAegis
should treat `deltaaegis_ready: false` as a rejection or quarantine condition, not as valid telemetry.

## Classification Philosophy

NetSniper v2.0.0 remains intentionally conservative.

A weak or generic service should remain `possible` or `review_queue` instead of becoming a
confident but unreliable classification. The goal is to produce explainable network intelligence
for review, not pretend that every open port proves device identity.

## Recommended Validation

For quick local iteration, run:

    ./tools/validate_v2_0_fast.sh

Before release, demo use, or downstream DeltaAegis ingestion, run:

    ./tools/validate_v2_0_release_gate.sh

The v2.0 release gate checks:

- shell syntax
- finalized v2.0 version and README/CHANGELOG metadata
- status contract compatibility
- manifest v3 compatibility
- profile runtime budget metadata
- bundle quality reports
- DeltaAegis fixture bundles
- v1.9 compatibility validators

## Features

- Local-subnet host discovery with Nmap.
- Curated TCP service scanning aligned with TrueAegis and DeltaAegis workflows.
- Device classification and exposure scoring.
- Structured JSON analysis output for automation.
- Optional Greenbone integration for deeper assessment.
- Immutable `netsniper-run-v3` telemetry bundles for DeltaAegis with v2 compatibility aliases.
- Exact monitored-port profile fingerprinting to prevent false historical deltas after scan-profile changes.
- Archived discovery XML and neighbor-table telemetry for MAC-backed identity correlation.
- v1.7 enriched classification and quality-report artifacts.
- v1.9 profile-aware scan planning with conservative accuracy-focused evidence passes.
- Interactive mode shows the active scan profile and can save profile changes to the local config.
- v2.0 machine-readable headless status and bundle quality reports for DeltaAegis orchestration.
- Synthetic DeltaAegis fixture bundles under `examples/deltaaegis-fixtures/`.

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

    netsniper-run-v3

The v3 manifest records:

- machine-readable status compatibility through `netsniper-status-v1`
- exact monitored TCP ports
- SHA-256 scan-profile fingerprint
- requested and effective scan profiles
- profile runtime budgets and measured duration
- NetSniper and Nmap versions
- target subnet and network scope
- discovery interface
- scan timestamps and host counts
- archived discovery XML
- archived service XML
- findings JSON
- neighbor telemetry
- v1.7 enriched analysis artifact paths
- v1.7 classification quality report paths
- `bundle_quality.json` readiness and diagnostic fields

Compatibility aliases from `netsniper-run-v2` are intentionally preserved for downstream migration.

See [`docs/V2_0_TELEMETRY_CONTRACT.md`](docs/V2_0_TELEMETRY_CONTRACT.md).

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for full release history.

## Scope and Limitations

NetSniper is a focused sensor, not a full SIEM and not an exploit framework.

It reports observations from its configured TCP profile. It does not claim to scan every possible TCP or UDP port, and it does not perform exploit checks or aggressive active probing.

## Authorized Use Only

NetSniper is provided for educational use and authorized security testing. Use it only on systems and networks for which you have explicit permission.

## License

MIT License. See [`LICENSE`](LICENSE).
