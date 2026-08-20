from __future__ import annotations

import argparse
import unittest
from pathlib import Path

from scripts import riscv_cli_admission
from scripts import riscv_csp_benchmark as csp


class NativeRecursionIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case = csp.validate_manifest()[1][0]
        cls.admission = riscv_cli_admission.Admission(
            "promoted", "release_gated", False
        )

    def child_report(self) -> dict[str, object]:
        return {
            "schema": "riscv_proof_v3",
            "mode": "bench",
            "release_status": self.admission.release_status,
            "experimental": self.admission.experimental,
            "recursion_enabled": False,
            "warmups": 1,
            "samples": 3,
            "verified_samples": 3,
            "total_steps": self.case.expected_cycles,
            "implementation_commit": "a" * 40,
            "implementation_dirty": False,
            "statement_sha256": "b" * 64,
        }

    def validate_child(self, report: dict[str, object]) -> None:
        csp.validate_benchmark_report(
            report,
            self.case,
            warmups=1,
            samples=3,
            admission=self.admission,
        )

    def test_product_report_must_attest_recursion_disabled(self) -> None:
        self.validate_child(self.child_report())
        for contaminated in (True, None):
            with self.subTest(recursion_enabled=contaminated):
                report = self.child_report()
                if contaminated is None:
                    report.pop("recursion_enabled")
                else:
                    report["recursion_enabled"] = contaminated
                with self.assertRaisesRegex(csp.BenchmarkError, "contract drifted"):
                    self.validate_child(report)

    def test_native_environment_removes_every_recursion_gate(self) -> None:
        inherited = {
            "PATH": "/bin",
            "STWO_RECURSION_ACTIVE_FRI_OUTER": "1",
            "STWO_RECURSION_OUTER_STAGE_TELEMETRY": "1",
            "STWO_ZIG_WORKERS": "3",
        }
        env, overrides, removed = csp.native_benchmark_environment(inherited, 7)
        self.assertEqual("/bin", env["PATH"])
        self.assertEqual("7", env["STWO_ZIG_WORKERS"])
        self.assertEqual("7", env["STWO_ZIG_MERKLE_WORKERS"])
        self.assertEqual(
            {
                "STWO_ZIG_WORKERS": "7",
                "STWO_ZIG_MERKLE_WORKERS": "7",
            },
            overrides,
        )
        self.assertEqual(
            [
                "STWO_RECURSION_ACTIVE_FRI_OUTER",
                "STWO_RECURSION_OUTER_STAGE_TELEMETRY",
            ],
            removed,
        )
        self.assertFalse(
            any(name.startswith(csp.RECURSION_ENV_PREFIX) for name in env)
        )

    def test_summary_fails_closed_on_recursive_row(self) -> None:
        row = {
            "backend": "cpu",
            "recursion_enabled": False,
            "target": "sha256",
            "evidence": {
                "status": "verified",
                "output_digest": "00",
                "expected_output_digest": "00",
            },
            "peak_memory": 1,
        }
        self.assertTrue(csp._summary([row], [])["all_recursion_disabled"])
        row["recursion_enabled"] = True
        self.assertFalse(csp._summary([row], [])["all_recursion_disabled"])

    def test_standard_build_step_has_no_recursive_producer_dependency(self) -> None:
        product = (
            csp.ROOT / "build_support" / "products" / "riscv_cpu.zig"
        ).read_text(encoding="utf-8")
        start = product.index("    const csp_benchmark =")
        end = product.index("    const closure_check =", start)
        registration = product[start:end]
        self.assertIn('"scripts/riscv_csp_benchmark.py"', registration)
        self.assertIn("&install_host.step", registration)
        self.assertIn("&install_host_trace.step", registration)
        self.assertNotIn("recursive_csp", registration.casefold())
        self.assertNotIn("recursion", registration.casefold())

    def test_standard_cli_command_selects_only_native_bench_mode(self) -> None:
        source = csp.inspect.getsource(csp.benchmark_case)
        self.assertIn('"bench"', source)
        for forbidden in (
            "--recursive",
            "--outer",
            "collect-canonical-outer",
            "STWO_RECURSION_",
        ):
            self.assertNotIn(forbidden, source)


class BackendResolutionTests(unittest.TestCase):
    @staticmethod
    def arguments(
        backend: str,
        cli: Path | None = None,
        report_out: Path | None = None,
    ) -> argparse.Namespace:
        return argparse.Namespace(backend=backend, cli=cli, report_out=report_out)

    def test_cpu_defaults_are_the_committed_evidence_paths(self) -> None:
        cli, report_out = csp._resolve_backend_paths(self.arguments("cpu"))
        self.assertEqual(csp.DEFAULT_CLI.resolve(), cli)
        self.assertEqual(csp.DEFAULT_REPORT.resolve(), report_out)

    def test_metal_defaults_never_clobber_cpu_evidence(self) -> None:
        cli, report_out = csp._resolve_backend_paths(self.arguments("metal"))
        self.assertEqual(
            (csp.ROOT / "zig-out" / "bin" / "stwo-zig-riscv-metal").resolve(),
            cli,
        )
        self.assertEqual(
            (
                csp.ROOT
                / "vectors"
                / "reports"
                / "riscv_csp_benchmark_report.metal.json"
            ).resolve(),
            report_out,
        )
        self.assertNotEqual(csp.DEFAULT_REPORT.resolve(), report_out)

    def test_explicit_paths_win_for_every_backend(self) -> None:
        explicit_cli = Path("/opt/example/prover")
        explicit_report = Path("/opt/example/report.json")
        for backend in csp.BACKENDS:
            with self.subTest(backend=backend):
                cli, report_out = csp._resolve_backend_paths(
                    self.arguments(backend, explicit_cli, explicit_report)
                )
                self.assertEqual(explicit_cli, cli)
                self.assertEqual(explicit_report, report_out)
