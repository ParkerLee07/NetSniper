# NetSniper v1.9 Accuracy Guidelines

NetSniper v1.9 focuses on scan accuracy, evidence calibration, and safer uncertainty reporting while preserving NetSniper's role as a lightweight CLI/headless telemetry tool.

## Product boundary

NetSniper remains:

- CLI-first.
- Headless-compatible.
- Lightweight.
- Scriptable.
- Suitable for DeltaAegis orchestration.
- Focused on producing telemetry bundles and exiting.

NetSniper must not add:

- Web dashboards.
- Flask/FastAPI servers.
- Browser UI.
- Login/session systems.
- Long-running dashboard services.
- Scheduler UI.

DeltaAegis owns dashboards, orchestration, scheduled workflows, and investigation views.

## Accuracy principles

NetSniper should prefer honest uncertainty over fake precision.

Rules:

- Port 80 alone does not prove a host is a web server.
- Port 443 alone does not prove a host is a server.
- Nmap OS guesses are evidence, not truth.
- Service banners are supporting evidence, not final proof.
- Conflicting evidence should produce review/ambiguous outcomes.
- Unknown is acceptable when evidence is weak.
- Strong classifications require multiple supporting signals or highly specific evidence.

## Scan profile principles

Profiles control scan cost and evidence depth.

Required profiles:

- `quick`: fastest safe inventory-oriented profile.
- `balanced`: default profile and v1.8-compatible behavior target.
- `accurate`: stronger service evidence without becoming intrusive.
- `deep`: slow/manual profile for explicit operator use only.

Default behavior must remain lightweight. More expensive probes must be opt-in through profiles or explicit flags.

## Profile safety boundaries

The following must not be default:

- Full TCP port scan.
- Full UDP scan.
- Aggressive NSE script usage.
- Public Internet scanning assumptions.
- OS detection treated as final truth.
- Credential checks.
- Exploit checks.
- Default password checks.

## DeltaAegis compatibility

NetSniper v1.9 may add fields, but it must preserve existing DeltaAegis ingestion compatibility.

Required bundle expectations:

- `manifest.json` remains present.
- Bundle schema remains compatible with `netsniper-run-v2`.
- `analysis.json` remains present.
- `analysis.enriched.json` remains generated when classification tooling is available.
- `classification_quality.json` and `classification_quality.md` remain generated when classification tooling is available.
- `scanner_version` remains present.
- Full discovered inventory remains preserved.
- Existing DeltaAegis-compatible host fields remain available.

## Validator strategy

NetSniper v1.9 uses DeltaAegis-style intelligent validators:

- Fast feature validators for each stage.
- Behavioral checks over grep-only checks.
- Synthetic fixtures for accuracy and false-confidence protection.
- Compatibility checks for prior behavior.
- Release metadata validators.
- One consolidated release gate.

New release gates should validate prior behavioral compatibility without requiring stale older README "current release" text.
