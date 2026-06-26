# NetSniper

**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs local-subnet host discovery, scans a curated set of security-relevant TCP ports, classifies likely device roles, scores exposed services, and writes structured telemetry for downstream tools such as DeltaAegis.

## Current Release

Current release: **NetSniper v1.9.0 — Accuracy Profiles and Evidence Passes**

NetSniper v1.9.0 adds profile-aware scan planning for safer accuracy control while preserving
NetSniper's lightweight CLI/headless role. The default `balanced` profile remains compatible with
the v1.8 monitored TCP workflow. The `accurate` profile adds deeper TCP service probing plus
non-fatal OS and UDP-lite evidence passes, archived separately for downstream tools such as
DeltaAegis.

## v1.9.0 Highlights

- Added scan profiles: `quick`, `balanced`, `accurate`, and planned/manual `deep`.
- Kept `balanced` as the default v1.8-compatible TCP profile.
- Added `--profile` and `--scan-profile` CLI options for headless profile selection.
- Added profile-aware scan command planning from `config/scan_profiles.json`.
- Added accurate TCP service-depth probing with `--version-intensity 7`.
- Added non-fatal OS evidence capture for the `accurate` profile.
- Added non-fatal UDP-lite evidence capture for selected discovery-oriented UDP ports.
- Archived `os_detection.*` and `udp_lite.*` evidence artifacts when available.
- Added manifest metadata for requested/effective scan profile, runtime stage, OS evidence availability, and UDP-lite availability.
- Added fake-Nmap runtime validators so profile behavior can be tested without sending packets.
- Preserved full-inventory bundle compatibility for DeltaAegis ingestion.

## Bundle Artifacts

Finalized NetSniper run bundles can include:

    analysis.json
    analysis.enriched.json
    classification_quality.json
    classification_quality.md
    manifest.json
    os_detection.xml / os_detection.gnmap / os_detection.nmap
    udp_lite.xml / udp_lite.gnmap / udp_lite.nmap

`analysis.json` remains the compatibility artifact. OS and UDP-lite evidence are archived as separate artifacts when produced by the `accurate` profile; they should be treated as supporting evidence, not standalone device identity.

`analysis.enriched.json` contains v1.7 classification details, evidence, contradictions, confidence bands, SIEM actions, secondary candidates, and explanations.

`classification_quality.json` and `classification_quality.md` summarize classification quality, review-queue items, false-confidence candidates, unknown hosts with exposed services, top device types, confidence-band distribution, and sample explanations.

## Classification Philosophy

NetSniper v1.9.0 remains intentionally conservative.

A weak or generic service should remain `possible` or `review_queue` instead of becoming a confident but unreliable classification. The goal is to produce explainable network intelligence for review, not pretend that every open port proves device identity.

## Recommended Validation

Before release, demo use, or downstream DeltaAegis ingestion, run:

    ./tools/validate_v1_9_release.sh

The v1.9 release gate checks:

- shell syntax
- finalized v1.9 version and banner markers
- v1.9 README and CHANGELOG release metadata
- scan profile contract and CLI parsing
- profile-aware scan command planning
- accurate TCP, OS evidence, and UDP-lite fake-Nmap runtime behavior
- v1.8 headless/full-inventory compatibility behavior
- v1.7 device-intelligence artifact compatibility

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
- v1.9 profile-aware scan planning with conservative accuracy-focused evidence passes.

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
