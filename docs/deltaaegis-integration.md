# NetSniper DeltaAegis Integration

NetSniper is the active network telemetry sensor for DeltaAegis. It performs host discovery, service scanning, exposure analysis, device classification, and immutable bundle generation. DeltaAegis ingests those bundles to preserve network state, compare accepted snapshots, and explain meaningful changes over time.

## NetSniper v1.4.0 DeltaAegis Classification Contract

NetSniper v1.4.0 telemetry bundles expose richer classification intelligence for DeltaAegis.

### Bundle schema

Full pipeline runs archive immutable telemetry bundles under:

    runs/<scan_id>/

Each completed bundle should include:

- `manifest.json`
- `analysis.json`
- `analysis.txt`
- discovery evidence
- service scan evidence
- host lists
- optional neighbor telemetry

The manifest uses the `netsniper-run-v2` bundle schema and records the scanner version, scan profile, monitored ports, timestamps, counts, and archived file paths.

### Per-host classification object

Each host in `analysis.json` includes a `classification` object using schema:

    netsniper-classification-v1

Expected fields:

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

### Compatibility fields

NetSniper also keeps top-level compatibility fields:

- `device_type`
- `device_type_confidence`
- `scanner_version`
- `severity`
- `score`
- `findings`

DeltaAegis can ingest both the legacy fields and the v1.4 classification object.

### Decision model

NetSniper v1.4.0 uses weighted evidence to classify hosts:

- `classified` means the confidence reached the classification threshold.
- `possible` means evidence exists, but the role should be reviewed.
- `unknown` means no useful classification evidence was found.

DeltaAegis should treat NetSniper classification intelligence as explainable context, not automatic truth. Evidence, confidence, contradictions, and secondary candidates should remain visible to the operator.
