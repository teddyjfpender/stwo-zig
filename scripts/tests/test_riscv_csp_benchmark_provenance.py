"""Provenance validators for the executables a CSP measurement depends on.

These cover the validators themselves: the prover CLI's compiled build
identity, the host architecture the identity is judged against, and the trace
dumper's published provenance.  That the harness *calls* them is a separate
question, pinned by ``test_riscv_csp_benchmark_wiring``.
"""

from __future__ import annotations

import json
import platform
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_cli_admission
from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib import build_identity as csp_build_identity
from scripts.riscv_csp_benchmark_lib import host as csp_host
from scripts.tests.riscv_csp_provenance_fixture import (
    FOREIGN_COMMIT,
    HEAD,
    STAND_IN_TRACE,
    TARGET,
    public_values,
)


class BuildIdentityTests(unittest.TestCase):
    @staticmethod
    def registry(**overrides: object) -> bytes:
        product = {
            "schema_version": 2,
            "name": "stwo-riscv-cpu",
            "frontend": "sail-rv32im-zkvm",
            "backend": "cpu",
            "target": {
                "arch": "aarch64",
                "os": "macos",
                "abi": "none",
                "cpu_model": "apple_m1",
                "cpu_features_sha256": "0" * 64,
            },
            "optimize": "ReleaseFast",
        }
        product["target"].update(overrides.pop("target", {}))
        product.update(overrides)
        return json.dumps({"schema_version": 1, "product": product}).encode()

    def validate(self, raw: bytes) -> dict:
        identity = csp_build_identity.parse_build_identity(raw)
        csp_build_identity.validate_build_identity(
            identity,
            host_arch="arm64",
            system="Darwin",
        )
        return identity

    def test_optimize_mode_is_recoverable_from_the_admitted_identity(self) -> None:
        # The check reads the same focused-product surface admission already
        # authenticates, rather than a second provenance channel.
        self.assertLessEqual(
            {"target", "optimize"},
            riscv_cli_admission.FOCUSED_PRODUCT_FIELDS,
        )

    def test_release_fast_host_binary_is_admitted(self) -> None:
        self.assertEqual(
            {
                "arch": "aarch64",
                "os": "macos",
                "abi": "none",
                "cpu_model": "apple_m1",
                "optimize": "ReleaseFast",
            },
            self.validate(self.registry()),
        )

    def test_debug_binary_is_refused(self) -> None:
        for mode in ("Debug", "ReleaseSafe", "ReleaseSmall"):
            with self.subTest(optimize=mode):
                with self.assertRaisesRegex(
                    csp.BenchmarkError,
                    "require -Doptimize=ReleaseFast",
                ):
                    self.validate(self.registry(optimize=mode))

    def test_translated_foreign_architecture_binary_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "targets x86_64-macos"):
            self.validate(self.registry(target={"arch": "x86_64"}))

    def test_foreign_operating_system_binary_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "targets aarch64-linux"):
            self.validate(self.registry(target={"os": "linux"}))

    def test_unmappable_host_fails_closed(self) -> None:
        identity = csp_build_identity.parse_build_identity(self.registry())
        with self.assertRaisesRegex(csp.BenchmarkError, "cannot map host"):
            csp_build_identity.validate_build_identity(
                identity,
                host_arch="riscv64",
                system="Darwin",
            )

    def test_undetermined_host_architecture_fails_closed(self) -> None:
        # ``host_architecture`` returns None when the hardware cannot be
        # established; publishing timings against an unknown host is refused
        # rather than assumed to be whatever the interpreter reports.
        identity = csp_build_identity.parse_build_identity(self.registry())
        with self.assertRaisesRegex(
            csp.BenchmarkError,
            "undetermined architecture",
        ):
            with mock.patch.object(
                csp_build_identity,
                "host_architecture",
                lambda: None,
            ):
                csp_build_identity.validate_build_identity(
                    identity,
                    system="Darwin",
                )

    def test_registry_without_a_build_identity_fails_closed(self) -> None:
        aggregate = json.dumps(
            {
                "schema_version": 1,
                "backend_availability": {"cpu": True, "metal-hybrid": False},
                "product_matrix": {},
            }
        ).encode()
        with self.assertRaisesRegex(
            csp.BenchmarkError,
            "publishes no build identity",
        ):
            csp_build_identity.parse_build_identity(aggregate)

    def test_partial_build_identity_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "identity is incomplete"):
            csp_build_identity.parse_build_identity(
                self.registry(target={"cpu_model": None})
            )

    def test_registry_rejects_duplicate_json_fields(self) -> None:
        raw = b'{"schema_version":1,"product":{},"product":{}}'
        with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
            csp_build_identity.parse_build_identity(raw)

    def test_unexecutable_binary_names_the_architecture_hypothesis(self) -> None:
        def run(command, **_: object):
            raise OSError(8, "Exec format error")

        with mock.patch.object(csp_build_identity.subprocess, "run", run):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "built for another architecture",
            ):
                csp_build_identity.read_build_identity(Path("/opt/example/prover"))


class HostArchitectureTests(unittest.TestCase):
    """The architecture that decides admission is the hardware's, not Python's."""

    @staticmethod
    def sysctl(readings: dict[str, str]):
        return lambda name: readings.get(name)

    def test_translated_interpreter_still_reports_apple_silicon(self) -> None:
        # A translated x86_64 interpreter: platform.machine() says x86_64 and
        # Rosetta 2 exists only on Apple Silicon, so the hardware is arm64.
        self.assertEqual(
            "arm64",
            csp_host.host_architecture(
                system="Darwin",
                machine="x86_64",
                sysctl=self.sysctl({"sysctl.proc_translated": "1"}),
            ),
        )

    def test_hardware_flag_alone_establishes_apple_silicon(self) -> None:
        self.assertEqual(
            "arm64",
            csp_host.host_architecture(
                system="Darwin",
                machine="x86_64",
                sysctl=self.sysctl({"hw.optional.arm64": "1"}),
            ),
        )

    def test_native_interpreter_answers_for_its_own_host(self) -> None:
        self.assertEqual(
            "x86_64",
            csp_host.host_architecture(
                system="Darwin",
                machine="x86_64",
                sysctl=self.sysctl({"sysctl.proc_translated": "0"}),
            ),
        )

    def test_silent_sysctl_fails_closed_instead_of_assuming_native(self) -> None:
        self.assertIsNone(
            csp_host.host_architecture(
                system="Darwin",
                machine="x86_64",
                sysctl=self.sysctl({}),
            )
        )

    def test_non_darwin_host_takes_the_kernel_answer(self) -> None:
        self.assertEqual(
            "x86_64",
            csp_host.host_architecture(
                system="Linux",
                machine="x86_64",
                sysctl=self.sysctl({}),
            ),
        )

    def test_rosetta_prover_is_refused_where_platform_machine_admitted_it(self) -> None:
        # The regression this exists for: under a translated interpreter
        # platform.machine() returns "x86_64", so comparing the binary's target
        # to it admitted the Rosetta build the check was written to catch.
        identity = {
            "arch": "x86_64",
            "os": "macos",
            "abi": "none",
            "cpu_model": "skylake",
            "optimize": "ReleaseFast",
        }
        interpreter = "x86_64"
        rosetta = self.sysctl({"sysctl.proc_translated": "1"})
        self.assertEqual(interpreter, identity["arch"])
        with self.assertRaisesRegex(csp.BenchmarkError, "targets x86_64-macos"):
            csp_build_identity.validate_build_identity(
                identity,
                host_arch=csp_host.host_architecture(
                    system="Darwin",
                    machine=interpreter,
                    sysctl=rosetta,
                ),
                system="Darwin",
            )

    def test_default_path_refuses_a_rosetta_build_end_to_end(self) -> None:
        # The full scenario with nothing injected: a translated interpreter
        # (platform.machine() == x86_64) on Apple Silicon must refuse an
        # x86_64 build, which is precisely what comparing against
        # platform.machine() admitted.
        readings = {"sysctl.proc_translated": "1"}
        identity = {
            "arch": "x86_64",
            "os": "macos",
            "abi": "none",
            "cpu_model": "skylake",
            "optimize": "ReleaseFast",
        }
        with mock.patch.object(
            csp_host, "sysctl_value", lambda name: readings.get(name)
        ):
            with mock.patch.object(csp_host.platform, "machine", lambda: "x86_64"):
                with self.assertRaisesRegex(
                    csp.BenchmarkError,
                    "targets x86_64-macos but this host is aarch64-macos",
                ):
                    csp_build_identity.validate_build_identity(
                        identity,
                        system="Darwin",
                    )

    def test_validation_reads_the_hardware_by_default(self) -> None:
        # Pins the wiring: the default comparison comes from
        # ``host_architecture``, so a host answering x86_64 refuses an
        # aarch64 build without the caller passing anything.
        identity = {
            "arch": "aarch64",
            "os": "macos",
            "abi": "none",
            "cpu_model": "apple_m1",
            "optimize": "ReleaseFast",
        }
        with mock.patch.object(
            csp_build_identity,
            "host_architecture",
            lambda: "x86_64",
        ):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "targets aarch64-macos but this host is x86_64-macos",
            ):
                csp_build_identity.validate_build_identity(
                    identity,
                    system="Darwin",
                )

    def test_collected_host_publishes_both_architectures(self) -> None:
        host = csp_host.collect_host()
        self.assertEqual(platform.machine(), host["architecture"])
        self.assertEqual(csp_host.host_architecture(), host["host_architecture"])


class TraceProvenanceTests(unittest.TestCase):
    """The trace dumper produces every cycle count, so it is validated too."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.case = next(
            case for case in csp.validate_manifest()[1] if case.target == TARGET
        )

    def parse(self, raw: bytes) -> dict:
        return csp_build_identity.parse_trace_provenance(
            raw,
            guest_sha256=self.case.guest_sha256,
            input_sha256=self.case.input_sha256,
        )

    def read(self, raw: bytes, *, returncode: int = 0) -> dict:
        def run(command, **_: object):
            return subprocess.CompletedProcess(command, returncode, raw, b"")

        with mock.patch.object(csp_build_identity.subprocess, "run", run):
            return csp_build_identity.read_trace_provenance(
                STAND_IN_TRACE,
                self.case,
                repository_head=HEAD,
                max_steps=csp.MAX_EXECUTION_STEPS,
                timeout=30,
            )

    def test_head_built_dumper_is_admitted(self) -> None:
        provenance = self.parse(public_values(self.case))
        self.assertEqual(HEAD, provenance["implementation_commit"])
        self.assertFalse(provenance["implementation_dirty"])
        csp_build_identity.validate_trace_provenance(
            provenance,
            repository_head=HEAD,
        )

    def test_stale_dumper_is_refused(self) -> None:
        with self.assertRaisesRegex(
            csp.BenchmarkError,
            "trace executable was built at commit",
        ):
            csp_build_identity.validate_trace_provenance(
                self.parse(public_values(self.case, commit=FOREIGN_COMMIT)),
                repository_head=HEAD,
            )

    def test_dirty_dumper_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "dirty worktree"):
            csp_build_identity.validate_trace_provenance(
                self.parse(public_values(self.case, dirty=True)),
                repository_head=HEAD,
            )

    def test_dump_of_another_program_cannot_carry_the_provenance(self) -> None:
        for field in ("elf_sha256", "input_sha256"):
            with self.subTest(field=field):
                source = {
                    "elf_sha256": self.case.guest_sha256,
                    "input_sha256": self.case.input_sha256,
                    field: "f" * 64,
                }
                with self.assertRaisesRegex(
                    csp.BenchmarkError,
                    "not bound to the authenticated fixture",
                ):
                    self.parse(public_values(self.case, source=source))

    def test_schema_and_derivation_drift_are_refused(self) -> None:
        for field, pattern in (
            ("schema", "schema drifted"),
            ("derivation", "derivation drifted"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(csp.BenchmarkError, pattern):
                    self.parse(public_values(self.case, **{field: "substituted"}))

    def test_absent_provenance_block_is_refused(self) -> None:
        with self.assertRaisesRegex(
            csp.BenchmarkError,
            "publishes no provenance block",
        ):
            self.parse(public_values(self.case, provenance=None))

    def test_incomplete_provenance_is_refused(self) -> None:
        for provenance in (
            {"implementation_commit": "not-a-commit", "implementation_dirty": False,
             "oracle_commit": "c" * 40, "witness_layout_sha256": "d" * 64},
            {"implementation_commit": HEAD, "implementation_dirty": "false",
             "oracle_commit": "c" * 40, "witness_layout_sha256": "d" * 64},
            {"implementation_commit": HEAD, "implementation_dirty": False,
             "oracle_commit": "", "witness_layout_sha256": "d" * 64},
            {"implementation_commit": HEAD, "implementation_dirty": False,
             "oracle_commit": "c" * 40, "witness_layout_sha256": "short"},
        ):
            with self.subTest(provenance=provenance):
                with self.assertRaisesRegex(
                    csp.BenchmarkError,
                    "provenance is incomplete",
                ):
                    self.parse(public_values(self.case, provenance=provenance))

    def test_duplicate_json_fields_are_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "repeats field"):
            self.parse(b'{"schema":"a","schema":"b"}')

    def test_probe_reports_what_the_dumper_cannot_be_held_to(self) -> None:
        # The dumper has no `applications` registry, so its target and optimize
        # mode are unavailable rather than checked-and-fine. The report says so.
        provenance = self.read(public_values(self.case))
        self.assertIs(False, provenance["build_identity_published"])
        self.assertEqual(
            list(csp_build_identity.TRACE_UNVALIDATED),
            provenance["unvalidated"],
        )
        self.assertIn("optimize mode", provenance["unvalidated"][-1])
        self.assertIn("applications", provenance["unvalidated_reason"])

    def test_failed_probe_is_refused(self) -> None:
        with self.assertRaisesRegex(csp.BenchmarkError, "probe .* exited 1"):
            self.read(public_values(self.case), returncode=1)

    def test_unexecutable_dumper_names_the_architecture_hypothesis(self) -> None:
        def run(command, **_: object):
            raise OSError(8, "Exec format error")

        with mock.patch.object(csp_build_identity.subprocess, "run", run):
            with self.assertRaisesRegex(
                csp.BenchmarkError,
                "built for another architecture",
            ):
                csp_build_identity.read_trace_provenance(
                    STAND_IN_TRACE,
                    self.case,
                    repository_head=HEAD,
                    max_steps=csp.MAX_EXECUTION_STEPS,
                    timeout=30,
                )



if __name__ == "__main__":
    unittest.main()
