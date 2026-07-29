# NetSniper v2.1.1 Maintenance Release Checklist

Status: approved maintenance-release procedure.

## Source identity

- Branch: `hotfix/v2.1.1-bundle-quality-integrity` before merge, or `main` after the approved merge.
- Final scanner version: `v2.1.1`.
- Working tree must be clean before the release gate is authoritative.

## Validation

### Pre-commit review

Before staging and committing:

1. review the exact bundle-integrity implementation and regression inventory;
2. run `./tools/validate_v2_1_bundle_integrity_hotfix_all.sh`;
3. run `./tools/validate_v2_1_stage1_2_all.sh`; and
4. run `python3 tools/validate_v2_1_release_metadata.py`.

### Clean-tree release gate

After staging and committing, run:

```bash
./tools/validate_v2_1_release_gate.sh
```

The gate must pass from the clean committed hotfix branch and again from clean
`main` before creating the annotated `v2.1.1` tag.

## Authorized finalization

The repository owner provided explicit approval for:

1. staging and committing the maintenance release;
2. pushing the hotfix branch;
3. opening a pull request;
4. merging the pull request with a merge commit;
5. creating the annotated `v2.1.1` tag;
6. publishing the GitHub Release; and
7. preserving all development and release branches.

## Pre-tag verification

Before tagging, verify that `main`, `origin/main`, and the intended merge commit
agree; verify that the merge tree equals the reviewed hotfix tree; rerun the
release gate; and confirm no runtime output, raw scan evidence, or private
network data is tracked.

## Release summary

NetSniper v2.1.1 integrity-binds `bundle_quality.json`, validates every
outer-manifest artifact fail-closed, and preserves the v2.1 classifier,
v2.0 telemetry contracts, v1.9 scan profiles, and CLI/headless architecture.
