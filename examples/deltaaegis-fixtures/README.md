# DeltaAegis Fixture Bundles

These synthetic bundles exercise the NetSniper v2.0 telemetry contract without running a real scan.

## Fixtures

- `quick-complete/` — complete quick-profile bundle.
- `balanced-complete/` — complete balanced-profile bundle.
- `accurate-complete/` — complete accurate-profile bundle with OS and UDP-lite evidence files.
- `failed-quality/` — intentionally non-ready bundle for DeltaAegis rejection/diagnostic tests.

Complete fixtures should have:

- `manifest.schema_version == "netsniper-run-v3"`
- `bundle_quality.schema_version == "netsniper-bundle-quality-v1"`
- `bundle_quality.deltaaegis_ready == true`
- matching `requested_profile`, `effective_profile`, and legacy scan-profile aliases

The failed fixture should remain `deltaaegis_ready == false`.
