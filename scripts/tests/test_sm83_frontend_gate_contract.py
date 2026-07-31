from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest import mock

from scripts import sm83_frontend_gate


ROOT = Path(__file__).resolve().parents[2]


class Sm83FrontendGateContractTests(unittest.TestCase):
    def test_run_is_fail_closed_and_never_prints_false_pass(self) -> None:
        output = io.StringIO()
        failure = subprocess.CalledProcessError(1, ["false"])
        with (
            mock.patch.object(
                sm83_frontend_gate.subprocess,
                "run",
                side_effect=failure,
            ) as subprocess_run,
            contextlib.redirect_stdout(output),
            self.assertRaises(subprocess.CalledProcessError),
        ):
            sm83_frontend_gate.run("negative control", ["false"])
        subprocess_run.assert_called_once_with(
            ["false"],
            cwd=sm83_frontend_gate.ROOT,
            check=True,
        )
        self.assertIn("[sm83] START negative control", output.getvalue())
        self.assertNotIn("[sm83] PASS", output.getvalue())

    def test_run_prints_positive_completion_evidence(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(
                sm83_frontend_gate.subprocess,
                "run",
            ) as subprocess_run,
            contextlib.redirect_stdout(output),
        ):
            sm83_frontend_gate.run("positive control", ["true"])
        subprocess_run.assert_called_once_with(
            ["true"],
            cwd=sm83_frontend_gate.ROOT,
            check=True,
        )
        self.assertIn("[sm83] PASS  positive control", output.getvalue())

    def assert_integration_gate(
        self,
        *,
        invoke: Callable[[], None],
        backend: str,
        build_file: str,
        optimize: str,
    ) -> None:
        with mock.patch.object(sm83_frontend_gate, "run") as run:
            invoke()
        self.assertEqual(
            [
                mock.call(
                    f"{backend} package proof suite",
                    [
                        "zig",
                        "build",
                        "test",
                        "--build-file",
                        build_file,
                        f"-Doptimize={optimize}",
                        "-j2",
                    ],
                ),
                mock.call(
                    f"{backend} machine-environment proof and adversarial mutations",
                    [
                        "zig",
                        "build",
                        "test-machine-environment",
                        "--build-file",
                        build_file,
                        f"-Doptimize={optimize}",
                        "-j2",
                    ],
                ),
            ],
            run.call_args_list,
        )

    def test_cpu_gate_runs_broad_then_focused_proofs(self) -> None:
        self.assert_integration_gate(
            invoke=sm83_frontend_gate.proof_gate,
            backend="CPU/SIMD",
            build_file="src/integrations/sm83_cpu/build.zig",
            optimize="ReleaseFast",
        )

    def test_metal_gate_runs_broad_then_focused_proofs(self) -> None:
        self.assert_integration_gate(
            invoke=sm83_frontend_gate.metal_gate,
            backend="Metal",
            build_file="src/integrations/sm83_metal/build.zig",
            optimize="ReleaseSafe",
        )

    def test_broad_build_steps_exclude_the_focused_proof(self) -> None:
        cases = (
            (
                "src/integrations/sm83_cpu/build.zig",
                '"cartridge CPU proof"',
                '"environment CPU proof binds"',
            ),
            (
                "src/integrations/sm83_metal/build.zig",
                '"cartridge Metal proof"',
                '"environment Metal proof binds"',
            ),
        )
        for relative, first_filter, second_filter in cases:
            with self.subTest(build_file=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                broad = source[
                    source.index("const tests =") :
                    source.index("const machine_environment_tests =")
                ]
                self.assertIn(".filters = &.{", broad)
                self.assertIn('"SM83"', broad)
                self.assertIn(first_filter, broad)
                self.assertIn(second_filter, broad)
                self.assertNotIn('"machine environment', broad)

    def test_package_contracts_keep_focused_invariants_explicit(self) -> None:
        policy = json.loads(
            (ROOT / "conformance/ci-touchpoints-v1.json").read_text(
                encoding="utf-8"
            )
        )
        cases = (
            (
                "src/integrations/sm83_cpu/package.contract.json",
                "machine_environment_test.zig::machine environment CPU proof "
                "roundtrip and adversarial mutations",
            ),
            (
                "src/integrations/sm83_metal/package.contract.json",
                "machine_environment.zig::machine environment Metal proves "
                "verifies and rejects mutations",
            ),
        )
        for relative, invariant in cases:
            with self.subTest(contract=relative):
                contract = json.loads(
                    (ROOT / relative).read_text(encoding="utf-8")
                )
                lane = policy["lanes"][contract["ci"]["lane"]]["commands"]
                self.assertIn(invariant, contract["api_contract"]["invariant_tests"])
                self.assertEqual(contract["ci"]["command"], lane[0])
                self.assertEqual("test-machine-environment", lane[1][2])
                self.assertEqual(contract["ci"]["command"][4], lane[1][4])

    def test_ci_owns_live_ppu_exact_positive_counts(self) -> None:
        policy = json.loads(
            (ROOT / "conformance/ci-touchpoints-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            [
                "python3",
                "scripts/sm83_frontend_gate.py",
                "--mooneye-ppu-live",
            ],
            policy["lanes"]["sm83_frontend"]["commands"],
        )
        source = (
            ROOT / "src/frontends/sm83/mooneye_ppu_gate.zig"
        ).read_text(encoding="utf-8")
        self.assertIn("expectEqual(@as(usize, 2), roms.len)", source)
        self.assertIn(
            "passed != roms.len or controls_rejected != roms.len",
            source,
        )
        self.assertIn("selected={d} pass={d}", source)
        self.assertIn("detached_controls_rejected={d}", source)

    def test_ci_owns_live_dma_exact_positive_counts(self) -> None:
        policy = json.loads(
            (ROOT / "conformance/ci-touchpoints-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(
            [
                "python3",
                "scripts/sm83_frontend_gate.py",
                "--mooneye-dma-live",
            ],
            policy["lanes"]["sm83_frontend"]["commands"],
        )
        source = (
            ROOT / "src/frontends/sm83/mooneye_dma_gate.zig"
        ).read_text(encoding="utf-8")
        self.assertIn("LIVE_INSTRUCTIONS: usize = 103_142", source)
        self.assertIn("LIVE_MCYCLES: usize = 183_761", source)
        self.assertIn("DetachedDmaControlFailed", source)
        self.assertIn("DmaMutationControlFailed", source)


if __name__ == "__main__":
    unittest.main()
