from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))

from stwo_perf import manifest as manifest_mod
from stwo_perf import metal_calibration as calibration
from stwo_perf import metal_calibration_runner as calibration_runner


ROOT = Path(__file__).resolve().parents[2]


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True,
    ).stdout.strip()


def _identity_digest(identity: dict) -> str:
    payload = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    return calibration.sha256(b"stwo-perf-metal-runtime-identity-v2\0" + payload)


def _reset_pending_authority(manifest_doc: dict, epochs_doc: dict) -> None:
    """Build a pending fixture independently of the repository's live freeze."""
    freeze_fields = (
        "artifact_sha256", "measured_commit", "policy_sha256",
        "runtime_identity_sha256", "source_sha256", "runtime_manifest_sha256",
        "runtime_objc_sha256", "platform_identity_sha256",
    )
    manifest_freeze = manifest_doc["harness"]["metal_calibration"]
    epoch = epochs_doc["epochs"][-1]
    epoch_freeze = epoch["metal_calibration"]
    for authority in (manifest_freeze, epoch_freeze):
        authority["status"] = "pending"
        for field in freeze_fields:
            authority[field] = None
    for field in ("anchor_prove_ms", "anchor_request_ms", "anchor_resources"):
        for workload_class in manifest_doc["harness"][field]["core_metal"]:
            manifest_doc["harness"][field]["core_metal"][workload_class] = None
    for workload_class in epoch["aa_dispersion"]["core_metal"]:
        epoch["aa_dispersion"]["core_metal"][workload_class] = None
        epoch_freeze["aa_dispersion"][workload_class] = None
        epoch_freeze["anchors"][workload_class] = None


class MetalCalibrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        (self.repo / "autoresearch/ledger").mkdir(parents=True)
        manifest_doc = json.loads((ROOT / "autoresearch/MANIFEST.json").read_text())
        manifest_doc["workload_registry"]["groups"].pop("cuda")
        epochs_doc = json.loads((ROOT / "autoresearch/ledger/epochs.json").read_text())
        _reset_pending_authority(manifest_doc, epochs_doc)
        (self.repo / "autoresearch/MANIFEST.json").write_text(
            json.dumps(manifest_doc, indent=2) + "\n"
        )
        (self.repo / "autoresearch/ledger/epochs.json").write_text(
            json.dumps(epochs_doc, indent=2) + "\n"
        )
        _git(self.repo, "init", "-b", "main")
        _git(self.repo, "config", "user.name", "Test")
        _git(self.repo, "config", "user.email", "test@example.test")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "calibration target")
        self.manifest = manifest_mod.load(self.repo)
        self.document = self._document()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _document(self) -> dict:
        commit = _git(self.repo, "rev-parse", "HEAD")
        tree = _git(self.repo, "rev-parse", "HEAD^{tree}")
        source_sha = "2" * 64
        objc_sha = "3" * 64
        runtime_manifest = (
            "metal-runtime-v2:mode=source-jit;"
            f"shader-amalgamation-sha256={source_sha};"
            f"runtime-objc-sha256={objc_sha}"
        )
        sdk_manifest = "apple-metal-sdk-v2:sdk-version=fixture"
        platform_identity = "runtime-v1|fixture"
        runtime_payload = {
            "runtime_manifest": runtime_manifest,
            "runtime_manifest_sha256": calibration.sha256(runtime_manifest.encode()),
            "sdk_manifest": sdk_manifest,
            "sdk_manifest_sha256": calibration.sha256(sdk_manifest.encode()),
            "source_sha256": source_sha,
            "shader_amalgamation_sha256": source_sha,
            "runtime_objc_sha256": objc_sha,
            "platform_identity": platform_identity,
            "platform_identity_sha256": calibration.sha256(platform_identity.encode()),
        }
        classes = {}
        for index, name in enumerate(self.manifest.class_names(
            board="core_metal", scored_only=True,
        ), start=1):
            classes[name] = {
                "classification": "neutral",
                "aa_r": 1.0,
                "ci": [0.99, 1.01],
                "dispersion": 0.01 + index / 1000,
                "anchor": {
                    "prove_ms": 10.0 * index,
                    "request_ms": 11.0 * index,
                    "peak_rss_mib": 100.0 * index,
                    "energy_j": 1.0 * index,
                    "proof_bytes": 1000 * index,
                },
                "measurement_rounds": 3,
                "measurement_seconds": 12.5 * index,
                "report_sha256s": [f"{index:x}" * 64],
            }
        return {
            "schema": calibration.SCHEMA,
            "board": calibration.BOARD,
            "epoch": 2,
            "repository": {"commit": commit, "tree": tree, "dirty": False},
            "policy_sha256": calibration.policy_sha256(self.manifest),
            "runtime_mode": calibration.RUNTIME_MODE,
            "host": {
                "schema": "native_matrix_host_environment_v1",
                "platform": {},
                "hardware": {"chip": "Apple M5 Max", "logical_cpu_count": 18},
                "metal_device": {"name": "Apple M5 Max", "metal_family": "Metal 4"},
                "toolchain": {},
                "randomness": {},
                "complete": True,
                "blockers": [],
            },
            "runtime_identity": {
                "identity_sha256": _identity_digest(runtime_payload),
                **runtime_payload,
            },
            "classes": classes,
        }

    def test_complete_document_validates(self) -> None:
        self.assertIs(
            calibration.validate_document(self.document, self.manifest),
            self.document,
        )

    def test_null_resource_and_non_neutral_aa_fail_closed(self) -> None:
        broken = copy.deepcopy(self.document)
        broken["classes"]["huge"]["anchor"]["energy_j"] = None
        with self.assertRaisesRegex(calibration.CalibrationError, "energy_j"):
            calibration.validate_document(broken, self.manifest)
        broken = copy.deepcopy(self.document)
        broken["classes"]["wide"]["ci"] = [1.01, 1.02]
        with self.assertRaisesRegex(calibration.CalibrationError, "does not contain 1"):
            calibration.validate_document(broken, self.manifest)

    def test_mismatched_runtime_and_stale_policy_fail_closed(self) -> None:
        broken = copy.deepcopy(self.document)
        broken["runtime_identity"]["source_sha256"] = "8" * 64
        payload = dict(broken["runtime_identity"])
        del payload["identity_sha256"]
        broken["runtime_identity"]["identity_sha256"] = _identity_digest(payload)
        with self.assertRaisesRegex(calibration.CalibrationError, "executed shader source"):
            calibration.validate_document(broken, self.manifest)

        stale_raw = copy.deepcopy(self.manifest.raw)
        stale_raw["workload_registry"]["groups"]["metal"]["workloads"][
            "mwf_log10x8"
        ]["args"] += " --profile"
        stale = manifest_mod.Manifest(self.repo, stale_raw)
        with self.assertRaisesRegex(calibration.CalibrationError, "policy is stale"):
            calibration.validate_document(self.document, stale)

    def test_pending_state_rejects_judged_use(self) -> None:
        with self.assertRaisesRegex(calibration.CalibrationError, "not frozen"):
            calibration.require_frozen(self.manifest, "small")

    def test_v1_aot_contract_is_rejected_instead_of_silently_migrated(self) -> None:
        legacy = copy.deepcopy(self.document)
        legacy["schema"] = "stwo_perf_metal_calibration_v1"
        legacy["aot"] = {"format": "stwo-zig-metal-core-aot-v2"}
        with self.assertRaisesRegex(calibration.CalibrationError, "fields differ"):
            calibration.validate_document(legacy, self.manifest)

        raw = copy.deepcopy(self.manifest.raw)
        config = raw["harness"]["metal_calibration"]
        config["schema"] = "stwo_perf_metal_calibration_freeze_v1"
        (self.repo / "autoresearch/MANIFEST.json").write_text(json.dumps(raw))
        with self.assertRaisesRegex(manifest_mod.ManifestError, "unsupported"):
            manifest_mod.load(self.repo)

    def test_measurement_projection_uses_real_source_jit_product(self) -> None:
        measured = calibration_runner._measurement_manifest(self.manifest)
        for workload in measured.workloads("small", board="core_metal"):
            self.assertIn("--metal-runtime source-jit", workload.args)
            self.assertNotIn("--metal-aot-bundle", workload.args)

    def test_raw_reports_bind_one_runtime_identity(self) -> None:
        raw = Path(self.temp.name) / "raw"
        raw.mkdir()
        report = {
            "schema_version": 7,
            "product_identity": {
                "backend": "metal",
                "implementation_commit": self.document["repository"]["commit"],
                "implementation_tree": self.document["repository"]["tree"],
                "implementation_dirty": False,
                "runtime_manifest": self.document["runtime_identity"]["runtime_manifest"],
                "sdk_manifest": self.document["runtime_identity"]["sdk_manifest"],
                "aot_manifest": "none",
            },
            "runtime_admission": {
                "origin": "diagnostic_source_jit",
                "initialized": True,
                "source_sha256": "2" * 64,
                "manifest_sha256": None,
                "metallib_sha256": None,
                "platform_identity": "runtime-v1|fixture",
            },
            "resources": {"complete": True},
        }
        for index in range(2):
            (raw / f"r{index}.json").write_text(json.dumps(report) + "\n")
        digests, identity = calibration_runner._runtime_evidence(
            raw, self.document["repository"]["commit"],
            self.document["repository"]["tree"],
        )
        self.assertEqual(len(digests), 1)
        self.assertEqual(identity["source_sha256"], "2" * 64)
        report["runtime_admission"]["platform_identity"] = "runtime-v1|changed"
        (raw / "r1.json").write_text(json.dumps(report) + "\n")
        with self.assertRaisesRegex(calibration.CalibrationError, "changed during"):
            calibration_runner._runtime_evidence(
                raw, self.document["repository"]["commit"],
                self.document["repository"]["tree"],
            )

    def test_freeze_updates_both_authorities_and_revalidates(self) -> None:
        source = Path(self.temp.name) / "calibration.json"
        source.write_text(json.dumps(self.document, indent=2) + "\n")
        installed = calibration.freeze(self.manifest, source)
        self.assertEqual(
            installed,
            (self.repo / "autoresearch/reference/metal-calibration-epoch-2.json").resolve(),
        )
        frozen = manifest_mod.load(self.repo)
        actual = calibration.require_frozen(frozen)
        self.assertEqual(actual["repository"]["commit"], _git(self.repo, "rev-parse", "HEAD"))
        epoch = json.loads(
            (self.repo / "autoresearch/ledger/epochs.json").read_text()
        )["epochs"][-1]
        self.assertEqual(
            epoch["aa_dispersion"]["core_metal"]["huge"],
            self.document["classes"]["huge"]["dispersion"],
        )

    def test_tampered_frozen_artifact_is_rejected(self) -> None:
        source = Path(self.temp.name) / "calibration.json"
        source.write_text(json.dumps(self.document) + "\n")
        installed = calibration.freeze(self.manifest, source)
        installed.write_text(installed.read_text() + "\n")
        with self.assertRaisesRegex(calibration.CalibrationError, "digest mismatch"):
            calibration.require_frozen(manifest_mod.load(self.repo))


class MetalCalibrationWorkflowTest(unittest.TestCase):
    def test_installed_workflow_is_bounded_and_mirrored(self) -> None:
        installed = ROOT / ".github/workflows/metal-calibration.yml"
        source = ROOT / "autoresearch/workflows/metal-calibration.yml"
        self.assertEqual(installed.read_bytes(), source.read_bytes())
        text = installed.read_text()
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("schedule:", text)
        self.assertIn("timeout-minutes: 75", text)
        self.assertIn("runs-on: [self-hosted, macOS, stwo-judge]", text)
        self.assertIn("calibrate-metal measure", text)
        self.assertIn("calibrate-metal validate", text)
        self.assertNotIn("calibrate-metal freeze", text)
        self.assertNotIn("metal-core-aot", text)
        self.assertNotIn("--aot-bundle", text)
        self.assertNotIn("--find metal\n", text)

    def test_module_cli_is_hermetic_outside_repository_root(self) -> None:
        result = subprocess.run(
            [
                sys.executable, "-m", "stwo_perf", "calibrate-metal", "measure",
                "--help",
            ],
            cwd=self.tempdir(),
            env={"PYTHONPATH": str(ROOT / "autoresearch/cli")},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("aot-bundle", result.stdout)

    def tempdir(self) -> str:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return temporary.name


if __name__ == "__main__":
    unittest.main()
