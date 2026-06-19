## NetSniper v1.5.0 — Classification Accuracy Expansion

NetSniper v1.5.0 expands the evidence-based device classification engine with a broader device taxonomy, weaker generic web-interface scoring, service-text evidence, and synthetic behavior validation.

### Highlights

- Adds v1.5 classification categories for routers, access points, managed switches, NAS/file servers, VoIP devices, UPS/power devices, security appliances, hypervisors, Windows Server, Windows Workstation, Linux Server, development/admin interfaces, IoT/embedded devices, and web application hosts.
- Treats generic HTTP/HTTPS as weak web-interface evidence instead of automatically labeling a device as a web server.
- Adds service-text evidence for products such as Synology, Reolink, UniFi, APC, Proxmox, Kibana, Grafana, nginx, Windows Server, and Linux/OpenSSH.
- Adds synthetic classification fixtures and behavior validation using generated .gnmap input.
- Adds a v1.5 release gate validator.

### Validation

Run:

    ./tools/validate_v1_5_release_gate.sh


# NetSniper

<!-- NETSNIPER_V140_README_START -->
## NetSniper v1.5.0 Current Capabilities

NetSniper v1.5.0 expands the scanner from evidence-based classification into a broader device-role identification sensor for DeltaAegis and other downstream tools.

### What v1.5.0 adds

- **Evidence-based classification** — assigns suspected device roles using weighted service evidence instead of one-off static port assumptions.
- **Classification confidence** — records numeric confidence, confidence labels, and classification decisions such as `classified`, `possible`, and `unknown`.
- **Explainable evidence** — stores evidence entries with candidate role, source, value, points, and reason.
- **Contradiction tracking** — records conflicting signals when a host exposes service combinations that do not cleanly match one role.
- **Secondary candidates** — preserves alternate likely roles for downstream review.
- **DeltaAegis-ready schema aliases** — includes both canonical and compatibility fields such as `primary_type`, `type`, `secondary_candidates`, and `candidates`.
- **Expanded monitored TCP profile** — scans a broader set of security-relevant ports for web, printer, camera/NVR, database, Windows, Active Directory, container, Kubernetes, mail, and network infrastructure signals.
- **v1.5 validators** — includes taxonomy, fixture, classifier-progress, service-text, behavior, and release-gate validators.

### Classification schema

NetSniper v1.5.0 uses the classification schema version `netsniper-classification-v1`.

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

Current release: **NetSniper v1.5.0 — Classification Accuracy Expansion**

NetSniper v1.5.0 expands device classification accuracy with a broader taxonomy, weaker generic web-interface scoring, service-text evidence, synthetic classification fixtures, and behavior validation.

Recommended validation before release or demo use:

    ./tools/validate_v1_5_release_gate.sh

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
