# NetSniper v2.0 Telemetry Contract

NetSniper v2.0 defines a stable telemetry contract for DeltaAegis and other defensive consumers.

## Status Contract

Headless runs can emit machine-readable status through:

- `--json-status`
- `--json-status-file <path>`

The status object uses:

- `schema_version: netsniper-status-v1`
- `scanner_version`
- `status`
- `target`
- `requested_profile`
- `effective_profile`
- `runtime_stage`
- `profile_runtime_budget_seconds`
- `profile_host_timeout_seconds`
- `profile_duration_seconds`
- `profile_budget_exceeded`
- `return_code`
- `run_dir`
- `manifest_path`
- `status_at`

This allows orchestrators to distinguish failed, interrupted, and complete runs without parsing terminal output.

## Manifest Contract

Run bundles use:

- `schema_version: netsniper-run-v3`
- `manifest_contract: netsniper-run-v3`
- `legacy_schema_version: netsniper-run-v2`

Compatibility aliases are intentionally preserved:

- `scan_profile`
- `scan_profile_requested`
- `scan_profile_effective`
- `scan_profile_runtime_stage`
- `scan_profile_contract_schema`

DeltaAegis should prefer the v3 fields but may continue reading the legacy aliases during migration.

## Profile Runtime Metadata

Each bundle includes profile runtime budget fields:

- `profile_runtime_budget_seconds`
- `profile_host_timeout_seconds`
- `profile_duration_seconds`
- `profile_budget_exceeded`
- `profile_runtime`

The supported scheduled/runtime profiles remain:

- `quick`
- `balanced`
- `accurate`

The `deep` profile remains blocked for non-interactive DeltaAegis-style runs.

## Bundle Quality Contract

Each finalized bundle includes:

- `bundle_quality.json`
- `manifest.files.bundle_quality_json`
- `manifest.quality`

The bundle quality object uses:

- `schema_version: netsniper-bundle-quality-v1`
- `deltaaegis_ready`
- `manifest_valid`
- `required_files_present`
- `counts_valid`
- `classification_quality_valid`
- `profile_fields_valid`
- `target_scope_valid`
- `status_complete`
- `warnings`
- `errors`

DeltaAegis should reject or quarantine bundles when `deltaaegis_ready` is false.

## Fixture Bundles

Synthetic fixtures live under:

- `examples/deltaaegis-fixtures/quick-complete`
- `examples/deltaaegis-fixtures/balanced-complete`
- `examples/deltaaegis-fixtures/accurate-complete`
- `examples/deltaaegis-fixtures/failed-quality`

These fixtures provide stable test inputs for DeltaAegis ingestion, rejection handling, profile display, and compatibility checks.
