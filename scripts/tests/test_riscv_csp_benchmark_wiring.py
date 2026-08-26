"""Gates must be reachable from ``main``, not merely implemented somewhere.

A unit test over a validator proves the validator works.  It does not prove the
harness calls it: a gate can be deleted from ``main`` outright and leave a suite
of passing unit tests behind.  These tests therefore drive
``riscv_csp_benchmark.main`` itself, faking only process boundaries -- the git
rev-parse, executables' published registries, host capture, and per-case
prove/verify -- so every production gate runs its real implementation over the
real committed fixtures and a deleted call turns a test red. Legacy Stark-V
timing comparisons live under ``autoresearch/`` and have their own optional
test suite.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_csp_benchmark as csp
from scripts.riscv_csp_benchmark_lib import build_identity as csp_build_identity
from scripts.riscv_csp_benchmark_lib import host as csp_host
from scripts.tests.riscv_csp_provenance_fixture import (
    FOREIGN_COMMIT,
    HEAD,
    STAND_IN_CLI,
    STAND_IN_TRACE,
    TARGET,
    admission_resolve,
    public_values,
)


class PowerEvidenceTests(unittest.TestCase):
    """The production CSP harness records and classifies power evidence."""

    def test_one_implementation_feeds_both_report_shapes(self) -> None:
        with mock.patch.object(
            csp_host,
            "power_evidence",
            lambda: ("Battery Power", True),
        ):
            csp_view = csp_host.collect_host()
            sibling = csp_host.power_evidence_block()
        for view in (csp_view, sibling):
            self.assertEqual("Battery Power", view["power_source"])
            self.assertIs(True, view["low_power_mode"])
        self.assertIs(False, sibling["admissible"])
        self.assertEqual(2, len(sibling["reasons"]))
        self.assertEqual(
            csp.power_conditions_admissible(csp_view),
            (sibling["admissible"], sibling["reasons"]),
        )

class HarnessWiringTests(unittest.TestCase):
    """Every gate must be reachable from ``main``, not merely implemented."""

    @classmethod
    def setUpClass(cls) -> None:
        _, cases, negatives = csp.validate_manifest()
        cls.case = next(case for case in cases if case.target == TARGET)
        cls.negative = next(case for case in negatives if case.target == TARGET)

    def setUp(self) -> None:
        self.arch = csp_build_identity.HOST_ARCHITECTURES.get(
            csp_host.host_architecture() or ""
        )
        self.system = csp_build_identity.HOST_OPERATING_SYSTEMS.get(
            platform.system()
        )
        self.assertIsNotNone(self.arch, "this host's architecture is unverifiable")
        self.assertIsNotNone(self.system, "this host's operating system is unmapped")
        for executable in (STAND_IN_CLI, STAND_IN_TRACE):
            self.assertTrue(os.access(executable, os.X_OK), executable)

    def identity(self, **overrides: object) -> dict:
        identity = {
            "arch": self.arch,
            "os": self.system,
            "abi": "none",
            "cpu_model": "host",
            "optimize": "ReleaseFast",
        }
        identity.update(overrides)
        return identity

    def registry(self, **overrides: object) -> bytes:
        identity = self.identity(**overrides)
        product = {
            "schema_version": 2,
            "name": "stwo-riscv-cpu",
            "target": {
                key: identity[key] for key in ("arch", "os", "abi", "cpu_model")
            },
            "optimize": identity["optimize"],
        }
        return json.dumps({"schema_version": 1, "product": product}).encode()

    @staticmethod
    def host(**overrides: object) -> dict:
        host: dict = {
            "cpu": "Apple M1",
            "logical_cpu_count": 8,
            "memory_bytes": 16 * 1024 * 1024 * 1024,
            "gpu": {
                "name": "Apple M1",
                "core_count": 8,
                "metal_support": "spdisplays_metal3",
                "unified_memory": True,
            },
            "power_source": "AC Power",
            "low_power_mode": False,
        }
        host.update(overrides)
        return host

    @staticmethod
    def fake_benchmark_case(case, cli, trace_cli, **_: object):
        return (
            {
                "target": case.target,
                "input_size": case.input_size,
                "recursion_enabled": False,
                "proof_duration": 1,
                "verify_duration": 1,
                "proof_size": 1,
                "peak_memory": 1,
                "evidence": {
                    "status": "verified",
                    "output_digest": case.expected_digest,
                    "expected_output_digest": case.expected_digest,
                },
            },
            HEAD,
        )

    @staticmethod
    def argv(report_out: Path) -> list[str]:
        return [
            "--cli", str(STAND_IN_CLI),
            "--trace-cli", str(STAND_IN_TRACE),
            "--report-out", str(report_out),
            "--targets", TARGET,
            "--sizes", "32",
            "--warmups", "0",
            "--samples", "1",
        ]

    @contextlib.contextmanager
    def harness(
        self,
        *,
        host: dict | None = None,
        registry: bytes | None = None,
        trace: bytes | None = None,
        benchmark_case=None,
    ):
        """Fake only the process boundaries; every gate runs for real."""
        registry = self.registry() if registry is None else registry
        trace = public_values(self.case) if trace is None else trace

        # `subprocess` is one module object, so this patch also intercepts the
        # host-architecture readings; those are delegated to the real host,
        # which is what the admitted registry below is built from.
        real_run = subprocess.run

        def provenance_run(command, **kwargs: object):
            argv = [os.fspath(value) for value in command]
            if argv[0] == "sysctl":
                return real_run(command, **kwargs)
            if argv[1:2] == ["applications"]:
                return subprocess.CompletedProcess(argv, 0, registry, b"")
            if "--public-values" in argv:
                return subprocess.CompletedProcess(argv, 0, trace, b"")
            raise AssertionError(f"unexpected provenance probe: {argv}")

        def harness_run(argv, **_: object):
            command = [os.fspath(value) for value in argv]
            if command[0] == "git":
                return subprocess.CompletedProcess(
                    command, 0, f"{HEAD}\n".encode(), b""
                )
            if command[0] == "zig":
                return subprocess.CompletedProcess(command, 0, b"0.15.2\n", b"")
            if "--public-values" in command:
                return subprocess.CompletedProcess(
                    command, 0, public_values(self.negative), b""
                )
            raise AssertionError(f"unexpected command: {command}")

        observed = self.host() if host is None else host
        with tempfile.TemporaryDirectory() as raw:
            with contextlib.ExitStack() as stack:
                stack.enter_context(mock.patch.object(csp, "_run", harness_run))
                stack.enter_context(
                    mock.patch.object(
                        csp_build_identity.subprocess, "run", provenance_run
                    )
                )
                stack.enter_context(
                    mock.patch.object(csp, "collect_host", lambda: observed)
                )
                stack.enter_context(
                    mock.patch.object(
                        csp,
                        "benchmark_case",
                        self.fake_benchmark_case
                        if benchmark_case is None
                        else benchmark_case,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        csp.riscv_cli_admission, "resolve", admission_resolve
                    )
                )
                yield Path(raw) / "report.json"

    def report(self, **kwargs: object) -> dict:
        with self.harness(**kwargs) as report_out:
            self.assertEqual(0, csp.main(self.argv(report_out)))
            return json.loads(report_out.read_text(encoding="utf-8"))

    def refusal(self, pattern: str, **kwargs: object) -> None:
        with self.harness(**kwargs) as report_out:
            with self.assertRaisesRegex(csp.BenchmarkError, pattern):
                csp.main(self.argv(report_out))
            self.assertFalse(report_out.exists(), "a refused run wrote evidence")

    def test_admitted_run_publishes_the_identity_it_validated(self) -> None:
        self.assertEqual(
            self.identity(),
            self.report()["identities"]["prover_build_identity"],
        )

    def test_debug_prover_build_never_reaches_a_measurement(self) -> None:
        self.refusal(
            "require -Doptimize=ReleaseFast",
            registry=self.registry(optimize="Debug"),
        )

    def test_foreign_target_prover_build_never_reaches_a_measurement(self) -> None:
        foreign = "x86_64" if self.arch != "x86_64" else "aarch64"
        self.refusal(
            "cannot produce comparable timings",
            registry=self.registry(arch=foreign),
        )

    def test_trace_executable_must_be_built_at_head(self) -> None:
        self.refusal(
            "trace executable was built at commit",
            trace=public_values(self.case, commit=FOREIGN_COMMIT),
        )

    def test_dirty_trace_executable_never_reaches_a_measurement(self) -> None:
        self.refusal(
            "dirty worktree",
            trace=public_values(self.case, dirty=True),
        )

    def test_trace_provenance_is_published_with_its_known_gaps(self) -> None:
        provenance = self.report()["identities"]["trace_provenance"]
        self.assertEqual(HEAD, provenance["implementation_commit"])
        self.assertIs(False, provenance["implementation_dirty"])
        self.assertIs(False, provenance["build_identity_published"])
        self.assertEqual(
            list(csp_build_identity.TRACE_UNVALIDATED),
            provenance["unvalidated"],
        )

    def test_battery_run_is_classed_non_publishable(self) -> None:
        report = self.report(host=self.host(power_source="Battery Power"))
        self.assertIs(False, report["power_conditions_admissible"])
        self.assertEqual(
            ["CSP-comparable timings require AC power (observed: Battery Power)"],
            report["power_condition_reasons"],
        )
        self.assertEqual("power-condition-non-publishable", report["result_class"])
        self.assertTrue(
            any("not publishable" in text for text in report["limitations"]),
            report["limitations"],
        )

    def test_certified_power_conditions_are_the_only_difference(self) -> None:
        # The control for the battery case above: the same run on AC power is
        # admissible, so the refusal there is attributable to the power gate.
        report = self.report()
        self.assertIs(True, report["power_conditions_admissible"])
        self.assertEqual([], report["power_condition_reasons"])
        self.assertEqual("host-qualified-non-comparable", report["result_class"])
        self.assertFalse(
            any("not publishable" in text for text in report["limitations"]),
            report["limitations"],
        )

    def test_written_report_declares_the_bumped_schema(self) -> None:
        report = self.report()
        self.assertEqual("stwo_riscv_csp_benchmark_v4", report["schema"])
        self.assertEqual(csp.SCHEMA, report["schema"])
        self.assertNotIn(report["schema"], csp.SUPERSEDED_SCHEMAS)

    def test_written_report_attests_native_recursion_isolation(self) -> None:
        report = self.report()
        self.assertIs(False, report["run"]["recursion_enabled"])
        self.assertEqual("STWO_RECURSION_", report["run"]["recursion_environment_prefix"])
        self.assertEqual([], report["run"]["removed_recursion_environment_variables"])
        self.assertTrue(report["summary"]["all_recursion_disabled"])
        self.assertTrue(
            all(row["recursion_enabled"] is False for row in report["measurements"])
        )

    def test_recursive_measurement_row_is_refused_before_publication(self) -> None:
        def contaminated(case, cli, trace_cli, **kwargs):
            row, commit = self.fake_benchmark_case(case, cli, trace_cli, **kwargs)
            row["recursion_enabled"] = True
            return row, commit

        self.refusal(
            "recursive or unauthenticated execution row",
            benchmark_case=contaminated,
        )

if __name__ == "__main__":
    unittest.main()
