# NetSniper v2.1.0 Release Checklist

Status: release-candidate procedure. Each consequential step requires separate operator approval.

## Source identity

- Branch: `feature/v2.1-evidence-calibration` before merge, or `main` after an approved merge.
- Final scanner version: `v2.1.0`.
- Working tree must be clean before the release gate is considered authoritative.

## Validation

### Pre-commit review

Before requesting approval to stage and commit the release-finalization changes:

1. review the exact approved 12-file inventory and diff;
2. run `./tools/validate_v2_1_stage1_2_all.sh`; and
3. run `python3 tools/validate_v2_1_release_metadata.py`.

These checks do not authorize staging or committing.

### Clean-tree release gate

After separate approval to stage and commit, run the authoritative gate from the
clean committed feature branch:

```bash
./tools/validate_v2_1_release_gate.sh
```

The gate must pass final metadata, deterministic v2.1 behavior,
empirical-calibration safeguards, DeltaAegis enrichment, and v1.9/v2.0
compatibility. Rerun it after an approved merge and before tagging or publishing.

## Approval holds

Validation does not authorize later steps automatically. Obtain separate explicit approval before each of the following:

1. staging and committing release-finalization changes;
2. pushing the feature branch;
3. opening a pull request;
4. merging a pull request;
5. creating or moving the `v2.1.0` tag;
6. publishing the GitHub Release;
7. deleting the feature branch.

## Pre-tag verification

Before tagging, verify that `main`, `origin/main`, and the intended release commit agree, rerun the release gate from a clean checkout, and confirm that no runtime output, scan bundle, raw network evidence, or private empirical capture is included.

## Release summary

NetSniper v2.1.0 finalizes evidence-calibrated device intelligence while preserving its CLI/headless architecture, conservative uncertainty policy, v2.0 telemetry contracts, and v1.9 scan-profile compatibility.
