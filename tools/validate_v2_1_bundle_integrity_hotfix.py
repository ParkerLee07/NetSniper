#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.capabilities import build_capability_manifest
from netsniper_core.contracts import write_json
from tools.finalize_v2_1_bundle_integrity import (
    BundleIntegrityError,
    finalize_bundle_integrity,
    validate_outer_manifest_integrity,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def validate_shell_archive_path() -> None:
    with tempfile.TemporaryDirectory(
        prefix="netsniper-v2.1-shell-finalization-"
    ) as temporary:
        workspace = Path(temporary)
        discovery = workspace / "discovery"
        scans = workspace / "scans"
        targets = workspace / "targets"
        runs = workspace / "runs"
        fake_bin = workspace / "bin"

        for directory in (
            discovery,
            scans,
            targets,
            runs,
            fake_bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        write_text(
            discovery / "live.xml",
            (
                '<?xml version="1.0"?>\n'
                '<nmaprun start="1785283200">'
                '<runstats>'
                '<finished time="1785283260" exit="success"/>'
                '<hosts up="1"/>'
                '</runstats>'
                '</nmaprun>\n'
            ),
        )
        write_text(
            scans / "fast_scan.xml",
            (
                '<?xml version="1.0"?>\n'
                '<nmaprun start="1785283200">'
                '<runstats>'
                '<finished time="1785283260" exit="success"/>'
                '<hosts up="1"/>'
                '</runstats>'
                '</nmaprun>\n'
            ),
        )
        require(
            'exit="success"' in (
                scans / "fast_scan.xml"
            ).read_text(encoding="utf-8"),
            "synthetic service XML does not satisfy NetSniper's "
            "existing successful-Nmap archive guard",
        )

        write_text(
            targets / "hosts.txt",
            "192.0.2.10\n",
        )
        write_text(
            targets / "high_risk.txt",
            "",
        )
        write_json(
            targets / "analysis_20260729-000000.json",
            [
                {
                    "host": "192.0.2.10",
                    "ports": [
                        {
                            "port": 22,
                            "service": "ssh",
                            "product": "OpenSSH",
                        }
                    ],
                }
            ],
        )

        fake_nmap = fake_bin / "nmap"
        fake_nmap.write_text(
            (
                "#!/usr/bin/env bash\n"
                "if [ \"${1:-}\" = \"--version\" ]; then\n"
                "    echo 'Nmap version 7.94'\n"
                "fi\n"
                "exit 0\n"
            ),
            encoding="utf-8",
        )
        fake_ip = fake_bin / "ip"
        fake_ip.write_text(
            (
                "#!/usr/bin/env bash\n"
                "case \"${1:-}\" in\n"
                "    -Version)\n"
                "        echo 'ip utility, iproute2-6.1.0'\n"
                "        ;;\n"
                "    neigh)\n"
                "        exit 0\n"
                "        ;;\n"
                "    route)\n"
                "        echo '192.0.2.0/24 dev eth0 scope link'\n"
                "        ;;\n"
                "esac\n"
                "exit 0\n"
            ),
            encoding="utf-8",
        )
        fake_nmap.chmod(0o755)
        fake_ip.chmod(0o755)

        result_path = workspace / "last-bundle-path.txt"
        shell = f"""
set -Eeuo pipefail
export NETSNIPER_TEST_MODE=1
export PATH={shlex.quote(str(fake_bin))}:$PATH
source {shlex.quote(str(ROOT / "netsniper.sh"))}

BASE={shlex.quote(str(ROOT))}
DISCOVERY_DIR={shlex.quote(str(discovery))}
SCAN_DIR={shlex.quote(str(scans))}
TARGET_DIR={shlex.quote(str(targets))}
RUN_DIR={shlex.quote(str(runs))}
NET="192.0.2.0/24"
SCAN_PROFILE="balanced"
SCAN_PROFILE_EFFECTIVE="balanced"
SCAN_PROFILE_RUNTIME_STAGE="v1_8_compatible_tcp"
PROFILE_RUNTIME_BUDGET_SECONDS=0
PROFILE_HOST_TIMEOUT_SECONDS=0
PROFILE_DURATION_SECONDS=0
PROFILE_BUDGET_EXCEEDED=false

archive_deltaaegis_bundle >/dev/null
printf '%s\n' "$LAST_BUNDLE_DIR" > {shlex.quote(str(result_path))}
"""

        environment = os.environ.copy()
        environment["PATH"] = (
            f"{fake_bin}:{environment.get('PATH', '')}"
        )
        completed = subprocess.run(
            ["bash", "-lc", shell],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            print(completed.stdout)
            print(completed.stderr, file=sys.stderr)
            raise AssertionError(
                "actual archive_deltaaegis_bundle path failed"
            )

        require(
            result_path.is_file(),
            "shell archive path did not report its finalized bundle",
        )
        bundle = Path(
            result_path.read_text(encoding="utf-8").strip()
        )
        require(
            bundle.is_dir(),
            "shell archive path did not create a bundle directory",
        )

        manifest = json.loads(
            (bundle / "manifest.json").read_text(encoding="utf-8")
        )
        capability = json.loads(
            (bundle / "capability_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        quality = json.loads(
            (bundle / "bundle_quality.json").read_text(encoding="utf-8")
        )

        require(
            manifest.get("files", {}).get("bundle_quality_json")
            == "bundle_quality.json",
            "actual outer manifest does not reference bundle_quality.json",
        )
        require(
            quality.get("deltaaegis_ready") is True,
            "actual bundle quality report is not DeltaAegis-ready",
        )

        records = [
            record
            for record in capability.get("artifacts", [])
            if record.get("path") == "bundle_quality.json"
        ]
        require(
            len(records) == 1,
            "actual shell bundle does not integrity-bind "
            "bundle_quality.json exactly once",
        )
        record = records[0]
        require(
            record.get("required") is True,
            "actual shell bundle does not mark bundle_quality.json required",
        )
        require(
            record.get("size_bytes")
            == (bundle / "bundle_quality.json").stat().st_size,
            "actual shell bundle records the wrong bundle-quality size",
        )
        require(
            record.get("sha256")
            == sha256_file(bundle / "bundle_quality.json"),
            "actual shell bundle records the wrong bundle-quality hash",
        )

        verified = validate_outer_manifest_integrity(
            bundle,
            manifest,
            capability,
        )
        require(
            "bundle_quality.json" in verified,
            "actual shell bundle skipped bundle-quality verification",
        )

    print(
        "[PASS] actual archive_deltaaegis_bundle finalization path "
        "integrity-binds bundle_quality.json"
    )


def main() -> int:
    shell = (ROOT / "netsniper.sh").read_text(encoding="utf-8")
    require(
        "finalize_v2_1_bundle_integrity.py" in shell,
        "netsniper.sh does not invoke the final integrity pass",
    )

    with tempfile.TemporaryDirectory(
        prefix="netsniper-v2.1-integrity-hotfix-"
    ) as temporary:
        bundle = Path(temporary)

        write_json(
            bundle / "analysis.json",
            [{"host": "192.0.2.10", "ports": []}],
        )
        write_json(
            bundle / "analysis.enriched.json",
            [{"host": "192.0.2.10", "ports": []}],
        )
        write_json(
            bundle / "host_classifications.json",
            [{"host": "192.0.2.10", "classification": "unknown"}],
        )
        write_json(
            bundle / "classification_quality.json",
            {"false_confidence_candidate_count": 0},
        )
        write_text(bundle / "classification_quality.md", "# Quality\n")
        write_text(bundle / "hosts.txt", "192.0.2.10\n")
        write_text(bundle / "neighbors.txt", "")
        write_text(
            bundle / "discovery.xml",
            "<?xml version='1.0'?><nmaprun></nmaprun>\n",
        )
        write_text(
            bundle / "services.xml",
            "<?xml version='1.0'?><nmaprun></nmaprun>\n",
        )

        preliminary = build_capability_manifest(
            bundle,
            run_id="validator-run",
            scanner_version="v2.1.1",
            source_commit="0" * 40,
            target="192.0.2.0/24",
            requested_profile="balanced",
            effective_profile="balanced",
            started_at="2026-07-29T00:00:00Z",
            completed_at="2026-07-29T00:01:00Z",
            configuration_fingerprint="a" * 64,
            privilege_context="unprivileged",
            discovered_count=1,
            emitted_count=1,
        )
        preliminary["integrity"]["bundle_finalized"] = True
        preliminary["integrity"]["manifest_complete"] = True
        write_json(bundle / "capability_manifest.json", preliminary)

        write_json(
            bundle / "bundle_quality.json",
            {
                "schema_version": "netsniper-bundle-quality-v1",
                "deltaaegis_ready": True,
                "errors": [],
                "warnings": [],
            },
        )

        manifest = {
            "schema_version": "netsniper-run-v3",
            "manifest_contract": "netsniper-run-v3",
            "legacy_schema_version": "netsniper-run-v2",
            "scan_id": "validator-run",
            "scanner_version": "v2.1.1",
            "target": "192.0.2.0/24",
            "network_scope": "192.0.2.0/24",
            "requested_profile": "balanced",
            "effective_profile": "balanced",
            "scan_profile_requested": "balanced",
            "scan_profile_effective": "balanced",
            "files": {
                "analysis_json": "analysis.json",
                "analysis_enriched_json": "analysis.enriched.json",
                "bundle_quality_json": "bundle_quality.json",
                "capability_manifest_json": "capability_manifest.json",
                "classification_quality_json": "classification_quality.json",
                "classification_quality_markdown": "classification_quality.md",
                "discovery_xml": "discovery.xml",
                "host_classifications_json": "host_classifications.json",
                "hosts": "hosts.txt",
                "neighbors": "neighbors.txt",
                "services_xml": "services.xml",
                "os_detection_xml": None,
                "udp_lite_xml": None,
            },
        }
        write_json(bundle / "manifest.json", manifest)

        preliminary_paths = {
            record["path"] for record in preliminary["artifacts"]
        }
        require(
            "bundle_quality.json" not in preliminary_paths,
            "regression setup did not reproduce the original omission",
        )

        result = finalize_bundle_integrity(bundle)
        require(
            result["bundle_quality_integrity_bound"] is True,
            "finalizer did not report bundle-quality integrity binding",
        )

        capability = json.loads(
            (bundle / "capability_manifest.json").read_text(encoding="utf-8")
        )
        records = [
            record
            for record in capability["artifacts"]
            if record["path"] == "bundle_quality.json"
        ]
        require(
            len(records) == 1,
            "bundle_quality.json must appear exactly once",
        )
        record = records[0]
        require(
            record["required"] is True,
            "bundle_quality.json is not marked required",
        )
        require(
            record["size_bytes"]
            == (bundle / "bundle_quality.json").stat().st_size,
            "bundle_quality.json size is incorrect",
        )
        require(
            record["sha256"] == sha256_file(bundle / "bundle_quality.json"),
            "bundle_quality.json hash is incorrect",
        )

        verified = validate_outer_manifest_integrity(
            bundle,
            manifest,
            capability,
        )
        require(
            "bundle_quality.json" in verified,
            "final integrity validation skipped bundle_quality.json",
        )

        with (bundle / "bundle_quality.json").open("ab") as handle:
            handle.write(b"\n")

        try:
            validate_outer_manifest_integrity(
                bundle,
                manifest,
                capability,
            )
        except BundleIntegrityError as exc:
            require(
                "bundle_quality.json" in str(exc),
                "tamper rejection did not identify bundle_quality.json",
            )
        else:
            raise AssertionError(
                "one-byte bundle_quality.json tamper was not detected"
            )

    validate_shell_archive_path()

    print(
        "[PASS] v2.1 bundle_quality.json is integrity-bound after finalization"
    )
    print("[PASS] every outer-manifest artifact is size/hash verified")
    print("[PASS] bundle_quality.json tampering is rejected")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        raise SystemExit(1)
