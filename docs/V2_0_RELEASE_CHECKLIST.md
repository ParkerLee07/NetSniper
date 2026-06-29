# NetSniper v2.0 Release Checklist

For quick local iteration, run the fast structural gate:

```bash
tools/validate_v2_0_fast.sh
```

Before publishing NetSniper v2.0.0, run the complete gate:

```bash
tools/validate_v2_0_release_gate.sh
```

The release gate uses a deduplicated validator chain so expensive fake-Nmap compatibility checks run once instead of being repeated by nested validators.

The release gate includes:

- `tools/validate_v2_0_status_contract.sh`
- `tools/validate_v2_0_manifest_v3.sh`
- `tools/validate_v2_0_profile_budgets.sh`
- `tools/validate_v2_0_bundle_quality.sh`
- `tools/validate_v2_0_deltaaegis_fixtures.sh`
- `tools/validate_v1_9_all.sh`

## Required Release Assets

The release should include documentation for:

- `netsniper-status-v1`
- `netsniper-run-v3`
- `netsniper-bundle-quality-v1`
- `examples/deltaaegis-fixtures`

## Final Metadata Steps

Before tagging:

1. Confirm the working tree is clean.
2. Confirm `SCANNER_VERSION` is finalized as `v2.0.0`.
3. Update README release references.
4. Update changelog or release notes.
5. Run `tools/validate_v2_0_release_gate.sh`.
6. Merge to `main`.
7. Create and publish the `v2.0.0` GitHub Release.

## Release Theme

NetSniper v2.0.0 is the reliable telemetry-sensor release for DeltaAegis. It focuses on machine-readable status, stable manifest contracts, profile runtime budgets, bundle quality reports, and reusable DeltaAegis fixture bundles.
