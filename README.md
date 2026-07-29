# NetSniper

**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs local-subnet host discovery, scans a curated set of security-relevant TCP ports, classifies likely device roles, scores exposed services, and writes structured telemetry for downstream tools such as DeltaAegis.

## Current Release

Current release: **NetSniper v2.1.1 — Bundle Integrity Hotfix**

NetSniper v2.1.1 corrects the v2.1 bundle-finalization sequence so
`bundle_quality.json` is recorded as a required, size-bound, SHA-256-bound
artifact before a telemetry bundle is published. The release preserves the
v2.1 classification contracts, CLI/headless architecture, v2.0 telemetry
compatibility, and v1.9 scan-profile behavior.

## v2.1.1 Highlights
- Integrity-binds `bundle_quality.json` in `capability_manifest.json`.
- Adds a fail-closed post-quality finalization pass for every outer-manifest artifact.
- Rejects missing, duplicated, size-mismatched, or SHA-256-mismatched bundle artifacts.
- Adds direct, tamper, and actual `archive_deltaaegis_bundle` runtime regressions.
- Preserves full inventory, conservative unknown/review classifications, and DeltaAegis compatibility.

## v2.1.0 Highlights

- Added canonical device-family, role, capability, and uncertainty contracts.
- Added deterministic v2.1 classification and bundle-generation tooling.
- Activated 14 development and 4 regression fixtures with exact replay gates.
- Prevented duplicate GNMAP/XML observations from inflating findings or risk.
- Kept embedded administration interfaces review-only without independent server evidence.
- Corrected generic HTTPS, printer, gateway, hypervisor, hostname-only, and route-context behavior conservatively.
- Added measurement-only empirical calibration files without unsupported accuracy claims.
- Added stable, additive `deltaaegis_context` evidence for downstream review.
- Added `tools/validate_v2_1_release_gate.sh` as the final release-candidate gate.
- Preserved v2.0 status, manifest, runtime-budget, bundle-quality, and DeltaAegis fixture compatibility.

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

NetSniper v2.1.1 remains intentionally conservative.

A weak or generic service should remain `possible` or `review_queue` instead of becoming a
confident but unreliable classification. The goal is to produce explainable network intelligence
for review, not pretend that every open port proves device identity.

## Recommended Validation

For focused classifier development and pre-commit review, run:

    ./tools/validate_v2_1_stage1_2_all.sh
    python3 tools/validate_v2_1_release_metadata.py

Review the exact release-finalization diff before requesting approval to stage and
commit it. After separate approval to stage and commit, run the authoritative
release gate from the clean committed feature branch:

    ./tools/validate_v2_1_release_gate.sh

Rerun the same clean-tree gate after an approved merge and before creating or
moving the `v2.1.1` tag or publishing the GitHub Release.

The v2.1 release gate checks:

- finalized v2.1.1 scanner, README, CHANGELOG, maintenance checklist, and CI metadata;
- Bash and Python syntax;
- deterministic classification and corpus behavior;
- observation and risk integrity;
- embedded-administration and observed-behavior boundaries;
- measurement-only empirical calibration safeguards;
- additive DeltaAegis evidence enrichment; and
- complete v1.9 and v2.0 compatibility suites.

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
