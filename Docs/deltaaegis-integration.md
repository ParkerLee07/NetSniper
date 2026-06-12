# DeltaAegis Integration

NetSniper full-pipeline runs emit immutable telemetry bundles under `runs/`.

## Bundle Layout

```text
runs/<scan_id>/
├── manifest.json
├── discovery.xml
├── discovery.gnmap
├── discovery.nmap
├── services.xml
├── services.gnmap
├── services.nmap
├── analysis.json
├── analysis.txt
├── hosts.txt
├── high_risk.txt
└── neighbors.txt
```

Only bundles containing a finalized `manifest.json` file should be ingested.

## Data Responsibilities

- `discovery.xml`: raw discovery evidence and MAC addresses when available.
- `neighbors.txt`: archived IP-to-MAC fallback enrichment captured at scan time.
- `services.xml`: authoritative neutral service observations.
- `analysis.json`: NetSniper's interpreted exposure findings and classifications.
- `manifest.json`: schema, scan profile, profile fingerprint, timestamps, counts, and file pointers.

DeltaAegis preserves historical bundles and compares only compatible scan profiles.
