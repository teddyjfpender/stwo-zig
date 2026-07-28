from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from scripts.architecture_host_gate_lib import capture, controller, plan, preimages, validators
from scripts.architecture_host_gate_lib import performance_readiness
from scripts.build_architecture_receipt_lib.protocol import load_protocol
from scripts import performance_epoch_gate


SHA = "1" * 40
TREE = "2" * 40


def wait_for_exit(pid: int, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.01)
    return False


def protocol() -> dict[str, object]:
    return {
        "checkpoint_order": ["BG-00", "BG-15"],
        "host_roles": {
            "linux": {
                "allocated_checkpoints": ["BG-00"],
                "required_products": ["product"],
            }
        },
        "limits": {"max_json_bytes": 1_000_000},
    }


def architecture_plan() -> dict[str, object]:
    return {
        "evidence_phases": {name: ["BG-00"] for name in controller.EVIDENCE_NAMES},
        "roles": {
            "linux": {
                "commands": [{
                    "id": "gate", "phase": "BG-00",
                    "argv": ["gate", "generated/result.json"],
                    "required_inputs": ["authority.json"],
                    "generated_outputs": ["generated/result.json"],
                }],
                "products": [{
                    "product_id": "product", "phase": "BG-00",
                    "identity_path": "identity.json", "identity_command": None,
                    "artifact_path": None,
                }],
            }
        },
    }


def product(status: str = "PASS") -> dict[str, object]:
    return {
        "product_id": "product",
        "product_identity_sha256": "3" * 64 if status == "PASS" else None,
        "artifact_sha256": "4" * 64 if status == "PASS" else None,
        "executable_sha256": None,
        "status": status,
        "reason": "fixture",
    }


class ArchitectureHostGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "generated").mkdir()
        (self.root / "generated/result.json").write_text('{"status":"stale"}')
        (self.root / "authority.json").write_text('{"schema":"authority-v1"}')
        (self.root / "plan.json").write_text('{"schema":"fixture"}')

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_gate(self, executor, *, clean=True, product_status="PASS"):
        git_values = {
            ("rev-parse", f"{SHA}^{{tree}}"): TREE,
            ("rev-parse", "HEAD"): SHA,
        }
        output = self.root / "evidence"
        def validate_outputs(_command_id, outputs, _inputs, *, root, candidate, host_role=None):
            del candidate
            del host_role
            result = {}
            for path in outputs:
                if not path.is_file():
                    raise controller.ReceiptError(f"missing fixture output: {path}")
                result[path.relative_to(root).as_posix()] = capture.sha256_file(path)
            return result
        with (
            mock.patch.object(controller, "load_protocol", return_value=(protocol(), "x")),
            mock.patch.object(controller.plan, "load", return_value=architecture_plan()),
            mock.patch.object(controller, "_git", side_effect=lambda _root, *args: git_values[args]),
            mock.patch.object(controller, "_clean", return_value=clean),
            mock.patch.object(controller.products, "collect", return_value=product(product_status)),
            mock.patch.object(
                controller.validators, "validate_outputs", side_effect=validate_outputs,
            ),
            mock.patch.object(controller, "validate_evidence_manifest"),
        ):
            return controller.execute(
                root=self.root, role="linux", plan_path=self.root / "plan.json",
                protocol_path=self.root / "protocol.json",
                output_dir=output, candidate=SHA,
                timeout=1.0, run_id="7", run_attempt="1", repository="owner/repo",
                repository_id="8", workflow_sha=SHA,
                native_oracle_bundle=self.root / "native-oracle-bundle",
                native_oracle_trust=self.root / "native-oracle-trust.json",
                executor=executor,
            )

    def test_removes_stale_output_before_real_command_and_passes_fresh_output(self) -> None:
        def execute(argv, root, timeout):
            del timeout
            result = root / argv[1]
            self.assertFalse(result.exists())
            result.write_text('{"status":"PASS"}')
            return 0, b"ok", b"", 2_000_000

        _, manifest = self.run_gate(execute)
        self.assertEqual("PASS", manifest["checkpoints"]["BG-00"]["status"])
        self.assertEqual(1, len(manifest["commands"]))
        self.assertTrue((self.root / "authority.json").is_file())

    def test_rejects_required_input_mutation_without_deleting_it(self) -> None:
        def execute(argv, root, timeout):
            del timeout
            (root / "authority.json").write_text('{"schema":"substituted"}')
            (root / argv[1]).write_text('{"status":"PASS"}')
            return 0, b"ok", b"", 1

        _, manifest = self.run_gate(execute)
        self.assertEqual("NO-GO", manifest["checkpoints"]["BG-00"]["status"])
        self.assertTrue((self.root / "authority.json").is_file())

    def test_missing_required_input_never_invokes_expensive_command(self) -> None:
        (self.root / "authority.json").unlink()
        executor = mock.Mock()
        _, manifest = self.run_gate(executor)
        executor.assert_not_called()
        self.assertEqual("NO-GO", manifest["checkpoints"]["BG-00"]["status"])
        self.assertEqual(125, manifest["commands"][0]["exit_code"])
        self.assertIn(
            "required input admission failed",
            (self.root / "evidence/commands/000-gate.stderr").read_text(),
        )

    def test_missing_output_or_skipped_test_is_no_go(self) -> None:
        _, missing = self.run_gate(lambda *_: (0, b"ok", b"", 1))
        self.assertEqual("NO-GO", missing["checkpoints"]["BG-00"]["status"])
        (self.root / "evidence").rename(self.root / "old-evidence")

        def skipped(argv, root, timeout):
            del timeout
            (root / argv[1]).write_text('{"status":"PASS"}')
            return 0, b"1 skipped", b"", 1

        _, skipped_manifest = self.run_gate(skipped)
        self.assertEqual("NO-GO", skipped_manifest["checkpoints"]["BG-00"]["status"])

    def test_dirty_source_executes_nothing_and_is_no_go(self) -> None:
        executor = mock.Mock()
        _, manifest = self.run_gate(executor, clean=False)
        executor.assert_not_called()
        self.assertEqual([], manifest["commands"])
        self.assertEqual("NO-GO", manifest["checkpoints"]["BG-00"]["status"])

    def test_skip_parser_counts_once(self) -> None:
        self.assertEqual(3, capture.skipped_tests(b"3 tests skipped", b""))
        self.assertEqual(2, capture.skipped_tests(b"skipped=2", b""))


class ArchitectureCaptureIsolationTest(unittest.TestCase):
    def background_command(self, pid_path: Path, *, parent_sleeps: bool) -> list[str]:
        script = f"""
import os
import time
from pathlib import Path

pid = os.fork()
if pid == 0:
    os.close(1)
    os.close(2)
    Path({str(pid_path)!r}).write_text(str(os.getpid()), encoding="utf-8")
    time.sleep(60)
    os._exit(0)
while not Path({str(pid_path)!r}).exists():
    time.sleep(0.001)
{"time.sleep(60)" if parent_sleeps else ""}
"""
        return [sys.executable, "-c", script]

    def test_successful_parent_exit_terminates_background_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pid_path = root / "child.pid"
            code, _, _, _ = capture.run(
                self.background_command(pid_path, parent_sleeps=False), root, 2.0,
            )
            self.assertEqual(0, code)
            self.assertTrue(wait_for_exit(int(pid_path.read_text(encoding="utf-8"))))

    def test_timeout_terminates_background_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            pid_path = root / "child.pid"
            code, _, stderr, _ = capture.run(
                self.background_command(pid_path, parent_sleeps=True), root, 0.1,
            )
            self.assertEqual(124, code)
            self.assertIn(b"timed out", stderr)
            self.assertTrue(wait_for_exit(int(pid_path.read_text(encoding="utf-8"))))

    def test_candidate_environment_excludes_authority_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with mock.patch.dict(os.environ, {
                "GITHUB_TOKEN": "secret",
                "STWO_ARCHITECTURE_SESSION_NONCE": "nonce",
            }):
                code, stdout, _, _ = capture.run(
                    [sys.executable, "-c", "import os; print(sorted(os.environ))"],
                    root,
                    2.0,
                )
            self.assertEqual(0, code)
            self.assertNotIn(b"GITHUB_TOKEN", stdout)
            self.assertNotIn(b"STWO_ARCHITECTURE_SESSION_NONCE", stdout)
            self.assertIn(b"PYTHONDONTWRITEBYTECODE", stdout)


class ArchitecturePlanTest(unittest.TestCase):
    def test_checked_in_plan_exactly_covers_protocol_allocations(self) -> None:
        root = Path(__file__).resolve().parents[2]
        receipt_protocol, _ = load_protocol(
            root / "conformance/build-architecture-receipt-protocol-v1.json"
        )
        value = plan.load(
            root / "conformance/build-architecture-ci-plan-v1.json", receipt_protocol,
        )
        for role, policy in receipt_protocol["host_roles"].items():
            phases = {item["phase"] for item in value["roles"][role]["commands"]}
            self.assertEqual(set(policy["allocated_checkpoints"]), phases)

    def test_native_metal_correctness_uses_backend_capable_focused_products(self) -> None:
        root = Path(__file__).resolve().parents[2]
        receipt_protocol, _ = load_protocol(
            root / "conformance/build-architecture-receipt-protocol-v1.json"
        )
        value = plan.load(
            root / "conformance/build-architecture-ci-plan-v1.json", receipt_protocol,
        )
        commands = {
            item["id"]: item for item in value["roles"]["macos"]["commands"]
        }
        command = commands["native-metal-correctness"]
        self.assertIn("--cpu-cli", command["argv"])
        self.assertIn("zig-out/bin/stwo-zig-native-cpu", command["required_inputs"])
        self.assertIn("--metal-cli", command["argv"])
        self.assertIn("zig-out/bin/stwo-zig-native-metal", command["required_inputs"])
        self.assertNotIn("--cli", command["argv"])

    def test_authoritative_plan_rejects_noop_launcher_substitution(self) -> None:
        root = Path(__file__).resolve().parents[2]
        receipt_protocol, _ = load_protocol(
            root / "conformance/build-architecture-receipt-protocol-v1.json"
        )
        value = json.loads(
            (root / "conformance/build-architecture-ci-plan-v1.json").read_text()
        )
        value["roles"]["linux"]["commands"][0]["argv"] = ["true"]
        with tempfile.TemporaryDirectory() as raw:
            changed = Path(raw) / "plan.json"
            changed.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(controller.ReceiptError, "launcher contract"):
                plan.load(changed, receipt_protocol)

    def test_unknown_output_authority_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            output = root / "result.json"
            output.write_text('{"status":"PASS"}')
            with self.assertRaises(controller.ReceiptError):
                validators.validate_outputs(
                    "unknown-evidence", [output], [], root=root, candidate=SHA,
                )


class PerformanceReadinessTest(unittest.TestCase):
    def test_checked_in_contract_is_explicitly_non_operable(self) -> None:
        root = Path(__file__).resolve().parents[2]
        value = performance_readiness.inspect(
            root,
            root / "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json",
        )
        self.assertEqual("DEFERRED", value["status"])
        self.assertEqual("PASS", value["architecture_status"])
        self.assertFalse(value["performance_promotion_enabled"])

    def test_rejects_enabled_promotion_marker(self) -> None:
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as raw:
            copy = Path(raw)
            for relative in (
                ".github/workflows/ci.yml",
                "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json",
                "conformance/2026-07-21-performance-authority-epoch-3-amendment.md",
                "conformance/build-monorepo-baseline-v1.json",
                "conformance/performance-authority/epoch-3/runner.py.txt",
                "conformance/performance-authority/epoch-3/stats.py",
                "conformance/performance-authority/epoch-3/MANIFEST.json",
                *performance_readiness.REQUIRED_TESTS,
            ):
                target = copy / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((root / relative).read_bytes())
            state = json.loads(
                (root / performance_readiness.STATE_PATH).read_text(encoding="utf-8")
            )
            state["performance_promotion_enabled"] = True
            target = copy / performance_readiness.STATE_PATH
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(
                performance_readiness.ReadinessError, "deferral marker drifted",
            ):
                performance_readiness.inspect(
                    copy,
                    copy / "conformance/build-monorepo-performance-baseline-v2-protocol-v2.json",
                )

    def test_top_level_performance_promotion_is_fail_closed_while_deferred(self) -> None:
        with mock.patch.object(performance_epoch_gate.controller, "main") as delegated:
            self.assertEqual(2, performance_epoch_gate.main(["capture-host"]))
            self.assertEqual(2, performance_epoch_gate.main(["validate-receipt"]))
            delegated.assert_not_called()

    def test_non_promotion_epoch_commands_remain_available(self) -> None:
        with mock.patch.object(
            performance_epoch_gate.controller, "main", return_value=0,
        ) as delegated:
            self.assertEqual(0, performance_epoch_gate.main(["validate-plan", "--plan", "x"]))
            delegated.assert_called_once()

    def test_performance_admission_rejects_missing_and_accepts_only_true(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "state.json"
            with self.assertRaises(OSError):
                performance_epoch_gate.promotion_enabled(path)
            for enabled in (False, True):
                path.write_text(json.dumps({
                    "schema": "build-architecture-performance-state-v1",
                    "performance_promotion_enabled": enabled,
                }))
                self.assertEqual(enabled, performance_epoch_gate.promotion_enabled(path))


class ArchitecturePreimageTest(unittest.TestCase):
    def test_rejects_duplicate_members_and_duplicate_index_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive_path = root / "bad.zip"
            for index_bytes, duplicate_member, message in (
                (b'{"schema":"x"}', True, "duplicate members"),
                (b'{"schema":"x","schema":"y"}', False, "duplicate architecture"),
            ):
                with self.subTest(message=message):
                    with zipfile.ZipFile(archive_path, "w") as archive:
                        archive.writestr("index.json", index_bytes)
                        if duplicate_member:
                            archive.writestr("index.json", index_bytes)
                    with self.assertRaisesRegex(controller.ReceiptError, message):
                        preimages._extract(archive_path, root / "out")

    def test_rejects_unknown_file_metadata_and_content_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            archive_path = root / "bad.zip"
            payload = b"payload"
            digest = capture.sha256_bytes(payload)
            base = {
                "schema": "build-architecture-evidence-preimages-v1",
                "role": "linux", "candidate": SHA, "tree": TREE,
                "plan_sha256": "3" * 64, "details": {}, "host_evidence": {},
                "path_map": {"file": "file"},
                "files": {"file": {"sha256": digest, "size": len(payload), "executable": False}},
            }
            for mutate, message in (
                (lambda value: value["files"]["file"].update(extra=True), "metadata"),
                (lambda value: value["files"]["file"].update(size=len(payload) + 1), "content digest"),
            ):
                value = json.loads(json.dumps(base))
                mutate(value)
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("index.json", json.dumps(value))
                    archive.writestr(f"files/{digest}", payload)
                with self.assertRaisesRegex(controller.ReceiptError, message):
                    preimages._extract(archive_path, root / "out")


if __name__ == "__main__":
    unittest.main()
