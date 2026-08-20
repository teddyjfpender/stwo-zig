from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib import contract as r006_contract
from scripts.typed_air_r006_capture_lib import orchestration
from scripts.typed_air_r006_capture_lib.codec import canonical_bytes, content_digest
from scripts.typed_air_r006_capture_lib.controller import ProcessResult
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import (
    INSTALL_SCHEMA,
    SNAPSHOT_CLASSIFICATION,
    SmokeSettings,
    host_preflight,
    install_candidate,
    installed_v4_smoke,
)
from scripts.typed_air_r006_capture_lib.preflight import validate_host_preflight
from scripts.tests.test_typed_air_r006_capture import (
    R006Fixture,
    preflight_host,
    quiet_evidence,
)


class OrchestrationTests(R006Fixture):
    @staticmethod
    def diagnostic_source(_: Path) -> dict[str, object]:
        return {
            "classification": SNAPSHOT_CLASSIFICATION,
            "commit": "6" * 40,
            "tree": "7" * 40,
            "clean": True,
            "ephemeral": True,
            "source_closure_files": 321,
            "source_closure_sha256": "8" * 64,
        }

    def build_environment(self) -> tuple[dict[str, str], dict[str, object], Path]:
        zig = self.scratch / "pinned-zig"
        zig.write_bytes(b"fixture-zig")
        zig.chmod(0o700)
        environment = {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/fixture/bin",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
            "ZIG_LOCAL_CACHE_DIR": str(self.scratch / "local-cache"),
            "ZIG_GLOBAL_CACHE_DIR": str(self.scratch / "global-cache"),
        }
        evidence = {
            "policy": "r006_releasefast_install_sanitized_v1",
            "variables": dict(environment),
            "admitted_inherited_names": ["PATH"],
            "removed_stwo_names": ["STWO_ZIG_WORKERS"],
            "cache_isolation": {
                "local": environment["ZIG_LOCAL_CACHE_DIR"],
                "global": environment["ZIG_GLOBAL_CACHE_DIR"],
            },
            "secret_values_recorded": False,
        }
        return environment, evidence, zig

    def install(
        self,
        *,
        source_provider=None,
        binary_payload: bytes | None = None,
    ) -> tuple[Path, Path, dict[str, object]]:
        prefix = self.scratch / "candidate"
        receipt = self.scratch / "install.json"
        markers = (
            b"fixture\0riscv_profiled_proof_v4\0"
            b"riscv_verified_request_attempt_v3\0"
            b"stwo.prover.logical-work-profile.v2\0"
        )

        def runner(command, cwd, environment, timeout):
            del cwd, timeout
            self.assertEqual(environment["LANG"], "C")
            self.assertEqual(environment["PYTHONHASHSEED"], "0")
            self.assertNotIn("STWO_ZIG_WORKERS", environment)
            if command[1] == "build":
                self.assertEqual(
                    command[2:4],
                    ("stwo-zig-riscv-cpu", "stwo-riscv-metal"),
                )
                (prefix / "bin").mkdir(parents=True)
                for lane in ("cpu-native", "metal-hybrid"):
                    path = prefix / "bin" / (
                        "stwo-zig-riscv-cpu"
                        if lane == "cpu-native"
                        else "stwo-zig-riscv-metal"
                    )
                    path.write_bytes(markers if binary_payload is None else binary_payload)
                    path.chmod(0o700)
                return subprocess.CompletedProcess(command, 0, b"build", b"")
            self.assertEqual(command[1], "version")
            return subprocess.CompletedProcess(command, 0, b"0.15.2\n", b"")

        with mock.patch.object(
            orchestration,
            "_snapshot_build_environment",
            return_value=self.build_environment(),
        ):
            result = install_candidate(
                self.repository,
                prefix,
                receipt,
                execute_releasefast_build=True,
                command_runner=runner,
                source_provider=source_provider or self.diagnostic_source,
            )
        return prefix, receipt, result

    def smoke_runner(self, plan, attempt, proof, *, mutation=None):
        calls = 0

        def runner(command, cwd, timeout, environment):
            nonlocal calls
            del timeout, environment
            calls += 1
            if command[1] == "bench":
                proof_path = Path(cwd) / command[command.index("--proof-out") + 1]
                proof_path.write_bytes(proof)
                return ProcessResult(0, self.report(plan, attempt, proof), b"", 123)
            if mutation is not None:
                mutation()
            return ProcessResult(0, b"", b"", 45)

        return runner, lambda: calls

    def test_install_seals_sanitized_environment_and_marker_only_claim(self) -> None:
        prefix, receipt, result = self.install()
        self.assertEqual(result["schema"], INSTALL_SCHEMA)
        self.assertTrue(result["required_exact_work_markers_present"])
        self.assertNotIn("exact_work_v4_installed", result)
        self.assertEqual(
            result["build_environment"]["policy"],
            "r006_releasefast_install_sanitized_v1",
        )
        self.assertEqual(result["toolchain"], "zig:0.15.2")
        self.assertEqual(
            result["toolchain_binary"]["path"],
            str((self.scratch / "pinned-zig").resolve()),
        )
        self.assertEqual(result["install_prefix"], str(prefix.resolve()))
        self.assertEqual(receipt.read_bytes(), canonical_bytes(result))

    def test_build_environment_preserves_only_explicit_toolchain_context(self) -> None:
        zig = self.scratch / "zig"
        inherited = {
            "PATH": "/fixture/bin",
            "SDKROOT": "/fixture/sdk",
            "DEVELOPER_DIR": "/fixture/xcode",
            "MACOSX_DEPLOYMENT_TARGET": "15.0",
            "STWO_ZIG_WORKERS": "99",
            "STWO_PRIVATE_TUNING": "secret",
            "ZIG_LOCAL_CACHE_DIR": "/shared/local",
            "ZIG_GLOBAL_CACHE_DIR": "/shared/global",
            "AWS_SECRET_ACCESS_KEY": "must-not-be-recorded",
        }
        with mock.patch.object(orchestration.shutil, "which", return_value=str(zig)):
            environment, evidence, resolved = orchestration._snapshot_build_environment(
                self.scratch,
                inherited,
            )
        self.assertEqual(resolved, zig.resolve())
        self.assertEqual(environment["PATH"], "/fixture/bin")
        self.assertEqual(environment["SDKROOT"], "/fixture/sdk")
        self.assertEqual(environment["PYTHONHASHSEED"], "0")
        self.assertNotIn("STWO_ZIG_WORKERS", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertEqual(
            evidence["removed_stwo_names"],
            ["STWO_PRIVATE_TUNING", "STWO_ZIG_WORKERS"],
        )
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", json.dumps(evidence))

    def test_ephemeral_snapshot_is_diagnostic_but_never_normative(self) -> None:
        def normative_git(command, repository):
            del repository
            arguments = tuple(command[1:])
            if arguments == ("rev-parse", "HEAD"):
                return b"1" * 40 + b"\n"
            if arguments == ("rev-parse", "HEAD^{tree}"):
                return b"2" * 40 + b"\n"
            if arguments[:2] == ("status", "--porcelain=v1"):
                return b""
            if arguments == ("log", "-1", "--format=%B"):
                return b"benchmark: ephemeral typed-air source snapshot\n"
            if arguments == ("ls-tree", "-r", "--full-tree", "HEAD"):
                return b"100644 blob " + b"3" * 40 + b"\tfile\n"
            raise AssertionError(arguments)

        with mock.patch.object(r006_contract, "_run", side_effect=normative_git):
            with self.assertRaisesRegex(CaptureError, "rejects diagnostic ephemeral"):
                r006_contract.source_identity(self.repository)

        def diagnostic_git(repository, *arguments):
            del repository
            if arguments == ("rev-parse", "HEAD"):
                return b"1" * 40 + b"\n"
            if arguments == ("rev-parse", "HEAD^{tree}"):
                return b"2" * 40 + b"\n"
            if arguments[:2] == ("status", "--porcelain=v1"):
                return b""
            if arguments == ("log", "-1", "--format=%B"):
                return b"benchmark: ephemeral typed-air source snapshot\n"
            if arguments == ("ls-tree", "-r", "--full-tree", "HEAD"):
                return b"100644 blob " + b"3" * 40 + b"\tfile\n"
            raise AssertionError(arguments)

        with mock.patch.object(orchestration, "_git", side_effect=diagnostic_git):
            identity = orchestration.diagnostic_source_identity(self.repository)
        self.assertTrue(identity["ephemeral"])
        self.assertEqual(identity["classification"], SNAPSHOT_CLASSIFICATION)

    def test_install_rejects_stale_markers_and_source_drift(self) -> None:
        with self.assertRaisesRegex(CaptureError, "exact-work production schema"):
            self.install(binary_payload=b"riscv_profiled_proof_v3")

        self.scratch = self.scratch / "source-drift-case"
        self.scratch.mkdir()
        stable = self.diagnostic_source(self.repository)
        changed = dict(stable)
        changed["tree"] = "9" * 40
        identities = iter((stable, changed))
        with self.assertRaisesRegex(CaptureError, "source drifted"):
            self.install(source_provider=lambda _: next(identities))

    def test_install_rejects_binary_hash_drift_during_marker_authentication(self) -> None:
        original = orchestration._require_binary_markers

        def mutate_after_marker(path):
            original(path)
            path.write_bytes(path.read_bytes() + b"drift")

        with mock.patch.object(
            orchestration,
            "_require_binary_markers",
            side_effect=mutate_after_marker,
        ):
            with self.assertRaisesRegex(CaptureError, "changed while it was authenticated"):
                self.install()

    def test_installed_v4_smoke_is_the_exact_work_proof_gate(self) -> None:
        prefix, receipt, _ = self.install()
        executable = prefix / "bin/stwo-zig-riscv-cpu"
        settings = SmokeSettings(
            repository=self.repository,
            lane="cpu-native",
            executable=executable,
            install_receipt=receipt,
            elf=self.workloads["multi_shard_addi"].elf,
            input_path=None,
            bundle=self.scratch / "smoke-bundle",
            session_id="fixture-installed-v4",
            execute_installed_v4_smoke=True,
            timeout_seconds=10,
        )
        plan, attempt, _ = orchestration._smoke_plan(
            settings,
            source_provider=self.diagnostic_source,
        )
        runner, calls = self.smoke_runner(plan, attempt, b"installed-v4-proof")
        result = installed_v4_smoke(
            settings,
            child_runner=runner,
            source_provider=self.diagnostic_source,
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["independent_verification"], "verified")
        self.assertEqual(
            result["work_disclosure"]["schema"],
            "stwo.prover.logical-work-profile.v2",
        )
        self.assertFalse(result["normative_performance_receipt"])
        self.assertEqual(calls(), 2)

    def test_smoke_rejects_binary_receipt_and_source_drift(self) -> None:
        prefix, receipt, _ = self.install()
        executable = prefix / "bin/stwo-zig-riscv-cpu"

        def settings(name):
            return SmokeSettings(
                repository=self.repository,
                lane="cpu-native",
                executable=executable,
                install_receipt=receipt,
                elf=self.workloads["multi_shard_addi"].elf,
                input_path=None,
                bundle=self.scratch / name,
                session_id=name,
                execute_installed_v4_smoke=True,
                timeout_seconds=10,
            )

        binary_settings = settings("binary-drift")
        plan, attempt, _ = orchestration._smoke_plan(
            binary_settings,
            source_provider=self.diagnostic_source,
        )
        runner, _ = self.smoke_runner(
            plan,
            attempt,
            b"proof",
            mutation=lambda: executable.write_bytes(executable.read_bytes() + b"drift"),
        )
        with self.assertRaisesRegex(CaptureError, "executable drifted"):
            installed_v4_smoke(
                binary_settings,
                child_runner=runner,
                source_provider=self.diagnostic_source,
            )

        # Reinstall in a distinct prefix because the prior adversarial run
        # deliberately invalidated its create-only candidate.
        self.scratch = self.scratch / "source-case"
        self.scratch.mkdir()
        prefix, receipt, _ = self.install()
        executable = prefix / "bin/stwo-zig-riscv-cpu"
        source_settings = settings("source-drift")
        stable = self.diagnostic_source(self.repository)
        changed = dict(stable)
        changed["tree"] = "9" * 40
        identities = iter((stable, stable, changed))
        plan, attempt, _ = orchestration._smoke_plan(
            source_settings,
            source_provider=self.diagnostic_source,
        )
        runner, _ = self.smoke_runner(plan, attempt, b"proof")
        with self.assertRaisesRegex(CaptureError, "source drifted"):
            installed_v4_smoke(
                source_settings,
                child_runner=runner,
                source_provider=lambda _: next(identities),
            )

    def test_host_preflight_fails_closed_for_power_low_power_and_thermal(self) -> None:
        host = preflight_host(
            power_source="Battery Power",
            low_power_mode=True,
        )
        quiet = quiet_evidence(host, thermal_clear=False)
        result = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet,
        )
        self.assertFalse(result["admissible"])
        joined = "\n".join(result["reasons"])
        self.assertIn("AC Power", joined)
        self.assertIn("Low Power Mode", joined)
        self.assertIn("thermal", joined)

    def test_host_preflight_accepts_only_complete_quiet_metal_authority(self) -> None:
        host = preflight_host()
        quiet = quiet_evidence(host)
        result = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet,
        )
        self.assertTrue(result["admissible"])
        self.assertEqual(result["classification"], "normative-capture-host-admitted")

    def test_host_preflight_replay_recomputes_quiet_evidence(self) -> None:
        host = preflight_host()
        receipt = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet_evidence(host),
        )
        self.assertEqual(
            validate_host_preflight(receipt, require_admitted=True),
            receipt,
        )

        mutations = []
        changed = copy.deepcopy(receipt)
        changed["quiet_host"]["admissible"] = False
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["quiet_host"]["observed"]["idle_percent"][0] = 0.0
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["quiet_host"]["thresholds"]["minimum_idle_percent"] = 0.0
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["quiet_host"]["observed"].pop("median_idle_percent")
        mutations.append(changed)

        for index, mutation in enumerate(mutations):
            mutation["content_sha256"] = content_digest(mutation)
            with self.subTest(index=index), self.assertRaises(CaptureError):
                validate_host_preflight(mutation, require_admitted=False)

    def test_host_preflight_cli_replays_rejected_receipt(self) -> None:
        host = preflight_host(power_source="Battery Power")
        receipt = host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet_evidence(host),
        )
        path = self.scratch / "host-preflight.json"
        path.write_bytes(canonical_bytes(receipt))
        command = (
            "python3",
            "scripts/typed_air_r006_capture.py",
            "validate-host-preflight",
            str(path),
        )
        replay = subprocess.run(
            command,
            cwd=self.repository,
            capture_output=True,
            check=False,
        )
        self.assertEqual(replay.returncode, 0, replay.stderr.decode())
        self.assertEqual(
            json.loads(replay.stdout)["status"],
            "VALID_REJECTED_HOST",
        )
        required = subprocess.run(
            (*command, "--require-admitted"),
            cwd=self.repository,
            capture_output=True,
            check=False,
        )
        self.assertEqual(required.returncode, 1)
        self.assertIn(b"normative capture host is inadmissible", required.stderr)
