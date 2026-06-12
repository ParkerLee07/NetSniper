# NetSniper

**Network reconnaissance and exposure-intelligence sensor for authorized security assessments.**

NetSniper is a Bash-based network discovery and service-enumeration pipeline. It performs host discovery, scans a curated set of security-relevant TCP ports, classifies likely device types, scores exposed services, and writes structured analysis files for downstream tooling.

NetSniper is also the active network sensor for **DeltaAegis**. Each completed full-pipeline run creates an immutable telemetry bundle containing raw Nmap XML, discovery evidence, neighbor-table enrichment, interpreted findings, and a versioned manifest.

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

```bash
git clone https://github.com/ParkerLee07/NetSniper.git
cd NetSniper
chmod +x netsniper.sh
./netsniper.sh
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
