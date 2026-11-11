import hashlib
import re
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.metal.metal_core_aot_receipt_lib import (
    ANCHOR,
    BUILD_CHECKS,
    BUILD_SCHEMA,
    DEVICE_CHECKS,
    DEVICE_SCHEMA,
    FILES,
    FORMAT,
    MANIFEST,
    ReceiptError,
    checksum_path,
    load_bundle,
    main,
    recorded_bundle_identity,
    require_hosted_ci_identity,
    require_reproducible,
    write_receipt,
)


COMMIT = "a" * 40


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_bundle(path: Path, *, metallib: bytes = b"metallib") -> None:
    source = b"kernel source"
    air = b"compiled air"
    manifest = {
        "format": FORMAT,
        "toolchain": {"xcode_version": "16.0"},
        "source": {
            "path": "stwo_zig_core.metal",
            "sha256": digest(source),
            "bytes": len(source),
        },
        "artifacts": {
            "air": {
                "path": "stwo_zig_core.air",
                "sha256": digest(air),
                "bytes": len(air),
            },
            "metallib": {
                "path": "stwo_zig_core.metallib",
                "sha256": digest(metallib),
                "bytes": len(metallib),
            },
        },
    }
    path.mkdir()
    (path / "stwo_zig_core.metal").write_bytes(source)
    (path / "stwo_zig_core.air").write_bytes(air)
    (path / "stwo_zig_core.metallib").write_bytes(metallib)
    encoded = (json.dumps(manifest, sort_keys=True) + "\n").encode()
    (path / MANIFEST).write_bytes(encoded)
    (path / ANCHOR).write_text(f"{digest(encoded)}  {MANIFEST}\n", encoding="utf-8")


def command_evidence(command: list[str]) -> dict[str, object]:
    return {
        "argv": command,
        "returncode": 0,
        "stdout_sha256": digest(b""),
        "stderr_sha256": digest(b"accepted"),
    }


def write_executable(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o755)


def write_hosted_fixture(root: Path) -> tuple[Path, Path, Path, str]:
    bundle_a = root / "build-a"
    bundle_b = root / "build-b"
    write_bundle(bundle_a)
    write_bundle(bundle_b)
    receipt_path = root / "hosted-build.json"
    receipt = {
        "schema": BUILD_SCHEMA,
        "phase": "hosted_build",
        "repository_commit": COMMIT,
        "build_mode": "ReleaseSafe",
        "checks": BUILD_CHECKS,
        "executables": {"builder": {"path": "/hosted/builder"}},
        "commands": [],
        "bundles": {
            "build-a": recorded_bundle_identity(load_bundle(bundle_a), "build-a"),
            "build-b": recorded_bundle_identity(load_bundle(bundle_b), "build-b"),
        },
        "host": {"platform": "hosted"},
        "ci": {
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_JOB": "metal-acceptance",
        },
    }
    receipt_sha256 = write_receipt(receipt_path, receipt)
    return receipt_path, bundle_a, bundle_b, receipt_sha256


def admission_argv(
    receipt: Path,
    bundle_a: Path,
    bundle_b: Path,
    probe: Path,
    output: Path,
    *,
    commit: str = COMMIT,
) -> list[str]:
    return [
        "admit",
        "--build-receipt",
        str(receipt),
        "--bundle-a",
        str(bundle_a),
        "--bundle-b",
        str(bundle_b),
        "--probe",
        str(probe),
        "--receipt-out",
        str(output),
        "--commit",
        commit,
    ]


class MetalCoreAotReceiptTests(unittest.TestCase):
    def test_probe_local_headers_resolve_from_the_moved_tool_owner(self):
        probe = Path(__file__).resolve().parents[2] / "src/backends/metal/tools/core_aot/probe.m"
        headers = re.findall(r'^#(?:import|include) "([^"\n]+)"', probe.read_text(), re.M)
        self.assertTrue(headers)
        for header in headers:
            self.assertTrue((probe.parent / header).resolve().is_file(), header)

    def test_bundle_validation_and_reproducibility_bind_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bundle(root / "first")
            write_bundle(root / "second")
            first = load_bundle(root / "first")
            second = load_bundle(root / "second")
            require_reproducible(first, second)
            self.assertEqual(set(FILES), set(first["files"]))

    def test_independent_build_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_bundle(root / "first")
            write_bundle(root / "second", metallib=b"different metallib")
            with self.assertRaisesRegex(ReceiptError, "independent AOT builds differ"):
                require_reproducible(load_bundle(root / "first"), load_bundle(root / "second"))

    def test_manifest_measurement_and_anchor_drift_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bundle"
            write_bundle(root)
            (root / "stwo_zig_core.air").write_bytes(b"mutated")
            with self.assertRaisesRegex(ReceiptError, "measurement mismatch"):
                load_bundle(root)

            anchor_root = Path(temporary) / "anchor"
            write_bundle(anchor_root)
            (anchor_root / ANCHOR).write_text("0" * 64 + f"  {MANIFEST}\n")
            with self.assertRaisesRegex(ReceiptError, "trust anchor mismatch"):
                load_bundle(anchor_root)

    def test_receipt_write_is_canonical_and_hashes_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            receipt = {"z": 1, "a": {"accepted": True}}
            recorded = write_receipt(path, receipt)
            self.assertEqual(recorded, digest(path.read_bytes()))
            self.assertEqual(
                f"{recorded}  receipt.json\n",
                checksum_path(path).read_text(encoding="utf-8"),
            )

    def test_build_phase_records_reproducibility_without_device_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            builder = root / "builder"
            write_executable(builder, b"hosted builder")
            output_dir = root / "artifact"
            receipt_out = output_dir / "hosted-build.json"

            compiler_paths: list[Path] = []

            def fake_run(command: list[str], **_: object) -> dict[str, object]:
                self.assertEqual("build", command[1])
                compiler_path = Path(command[3])
                compiler_paths.append(compiler_path)
                write_bundle(compiler_path)
                return command_evidence(command)

            with (
                mock.patch(
                    "scripts.metal.metal_core_aot_receipt_lib.controller.run",
                    side_effect=fake_run,
                ),
                mock.patch(
                    "scripts.metal.metal_core_aot_receipt_lib.environment.command_output",
                    return_value="host",
                ),
                mock.patch.dict(
                    "os.environ",
                    {
                        "GITHUB_ACTIONS": "true",
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "2",
                        "GITHUB_JOB": "metal-acceptance",
                    },
                ),
            ):
                self.assertEqual(
                    0,
                    main(
                        [
                            "build",
                            "--builder",
                            str(builder),
                            "--output-dir",
                            str(output_dir),
                            "--receipt-out",
                            str(receipt_out),
                            "--commit",
                            COMMIT,
                        ]
                    ),
                )

            receipt = json.loads(receipt_out.read_bytes())
            self.assertEqual(BUILD_SCHEMA, receipt["schema"])
            self.assertEqual(BUILD_CHECKS, receipt["checks"])
            self.assertEqual({"build-a", "build-b"}, set(receipt["bundles"]))
            self.assertEqual(2, len(compiler_paths))
            self.assertEqual(compiler_paths[0], compiler_paths[1])
            self.assertFalse(compiler_paths[0].exists())
            self.assertNotIn("probe", receipt["executables"])
            self.assertNotIn("metal_device", receipt["host"])
            for device_claim in (
                "authenticated_bundle_admission",
                "aot_jit_transcript_output_parity",
                "exact_export_set_and_function_constants",
            ):
                self.assertNotIn(device_claim, receipt["checks"])

    def test_hosted_identity_requires_exact_actions_run_and_job(self) -> None:
        valid = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_JOB": "metal-acceptance",
        }
        require_hosted_ci_identity(valid)
        invalid_values = (
            {**valid, "GITHUB_ACTIONS": "false"},
            {**valid, "GITHUB_RUN_ID": ""},
            {**valid, "GITHUB_RUN_ID": "12a"},
            {**valid, "GITHUB_RUN_ATTEMPT": ""},
            {**valid, "GITHUB_JOB": "release-gate"},
        )
        for invalid in invalid_values:
            with self.subTest(ci=invalid):
                with self.assertRaises(ReceiptError):
                    require_hosted_ci_identity(invalid)

    def test_device_admission_binds_parent_and_probes_both_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, bundle_a, bundle_b, parent_sha256 = write_hosted_fixture(root)
            probe = root / "probe"
            write_executable(probe, b"device probe")
            output = root / "device.json"
            commands: list[list[str]] = []

            def fake_run(command: list[str], **_: object) -> dict[str, object]:
                commands.append(command)
                return command_evidence(command)

            with (
                mock.patch(
                    "scripts.metal.metal_core_aot_receipt_lib.controller.run",
                    side_effect=fake_run,
                ),
                mock.patch(
                    "scripts.metal.metal_core_aot_receipt_lib.environment.command_output",
                    return_value="device",
                ),
            ):
                self.assertEqual(
                    0,
                    main(admission_argv(receipt, bundle_a, bundle_b, probe, output)),
                )

            admitted = json.loads(output.read_bytes())
            self.assertEqual(DEVICE_SCHEMA, admitted["schema"])
            self.assertEqual(DEVICE_CHECKS, admitted["checks"])
            self.assertEqual(parent_sha256, admitted["parent"]["receipt_sha256"])
            self.assertEqual(COMMIT, admitted["parent"]["repository_commit"])
            self.assertEqual(2, len(commands))
            self.assertEqual(str(bundle_a.resolve()), commands[0][2])
            self.assertEqual(str(bundle_b.resolve()), commands[1][2])
            self.assertEqual(
                digest(output.read_bytes()),
                checksum_path(output).read_text().split()[0],
            )

    def test_admission_rejects_checksum_schema_and_commit_drift_before_probe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            probe = root / "probe"
            write_executable(probe, b"device probe")

            checksum_root = root / "checksum"
            checksum_root.mkdir()
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(checksum_root)
            receipt.write_bytes(receipt.read_bytes() + b" ")
            with self.assertRaisesRegex(ReceiptError, "receipt checksum mismatch"):
                main(admission_argv(receipt, bundle_a, bundle_b, probe, root / "checksum.json"))

            schema_root = root / "schema"
            schema_root.mkdir()
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(schema_root)
            document = json.loads(receipt.read_bytes())
            document["schema"] = DEVICE_SCHEMA
            write_receipt(receipt, document)
            with self.assertRaisesRegex(ReceiptError, "receipt schema mismatch"):
                main(admission_argv(receipt, bundle_a, bundle_b, probe, root / "schema.json"))

            commit_root = root / "commit"
            commit_root.mkdir()
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(commit_root)
            with self.assertRaisesRegex(ReceiptError, "receipt commit mismatch"):
                main(
                    admission_argv(
                        receipt,
                        bundle_a,
                        bundle_b,
                        probe,
                        root / "commit.json",
                        commit="b" * 40,
                    )
                )

    def test_admission_rejects_bundle_drift_and_false_hosted_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            probe = root / "probe"
            write_executable(probe, b"device probe")

            bundle_root = root / "bundle-drift"
            bundle_root.mkdir()
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(bundle_root)
            shutil.rmtree(bundle_a)
            write_bundle(bundle_a, metallib=b"valid but different")
            with self.assertRaisesRegex(ReceiptError, "bundle identity mismatch"):
                main(admission_argv(receipt, bundle_a, bundle_b, probe, root / "bundle.json"))

            claims_root = root / "false-claims"
            claims_root.mkdir()
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(claims_root)
            document = json.loads(receipt.read_bytes())
            document["checks"]["aot_jit_transcript_output_parity"] = True
            write_receipt(receipt, document)
            with self.assertRaisesRegex(ReceiptError, "receipt checks mismatch"):
                main(admission_argv(receipt, bundle_a, bundle_b, probe, root / "claims.json"))

    def test_admission_requires_canonical_paths_and_both_successful_probes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt, bundle_a, bundle_b, _ = write_hosted_fixture(root)
            probe = root / "probe"
            write_executable(probe, b"device probe")

            with self.assertRaisesRegex(ReceiptError, "canonical receipt layout"):
                main(
                    admission_argv(
                        receipt,
                        bundle_b,
                        bundle_a,
                        probe,
                        root / "swapped.json",
                    )
                )

            output = root / "failed-probe.json"
            successful = command_evidence(["probe-a"])
            with mock.patch(
                "scripts.metal.metal_core_aot_receipt_lib.controller.run",
                side_effect=[successful, ReceiptError("second probe failed")],
            ) as run_probe:
                with self.assertRaisesRegex(ReceiptError, "second probe failed"):
                    main(admission_argv(receipt, bundle_a, bundle_b, probe, output))
            self.assertEqual(2, run_probe.call_count)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
