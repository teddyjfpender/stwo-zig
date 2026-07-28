import unittest
from pathlib import Path

from scripts.interop_cli_command import build_command, installed_binary, run_command

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_CALLERS = (
    "benchmark_full_lib/controller.py",
    "benchmark_smoke_lib/controller.py",
    "e2e_interop_lib/controller.py",
    "profile_smoke_lib/controller.py",
)
COMPATIBILITY_CALLERS = (
    "merkle_worker_stress.py",
    "prove_checkpoints.py",
    "std_shims_behavior.py",
)


class InteropCliCommandTests(unittest.TestCase):
    def test_build_command_preserves_optimization_and_optional_cpu(self) -> None:
        self.assertEqual(
            ["zig", "build", "interop-cli", "-Doptimize=ReleaseFast"],
            build_command("ReleaseFast"),
        )
        self.assertEqual(
            ["zig", "build", "interop-cli", "-Doptimize=ReleaseSafe", "-Dcpu=apple_m1"],
            build_command("ReleaseSafe", "apple_m1"),
        )

    def test_installed_binary_and_one_shot_module_graph_are_stable(self) -> None:
        self.assertEqual(Path("/repo/zig-out/bin/interop_cli"), installed_binary(Path("/repo")))
        command = run_command("--mode", "verify", "--artifact", "proof.json")
        self.assertEqual("zig", command[0])
        self.assertIn("-lc", command)
        self.assertIn("-Mroot=src/tools/interop/main.zig", command)
        self.assertIn("-Mstwo=src/stwo.zig", command)
        self.assertIn("-Mstwo_core=src/core/mod.zig", command)
        self.assertIn("-Mstwo_backend_contracts=src/backend/mod.zig", command)
        self.assertIn("-Mstwo_prover_impl=src/prover/mod.zig", command)
        self.assertIn(
            "-Mstwo_riscv_frontend=src/frontends/riscv/mod.zig",
            command,
        )
        self.assertIn(
            "-Mstwo_cairo_frontend=src/frontends/cairo/mod.zig",
            command,
        )
        self.assertEqual(["--mode", "verify", "--artifact", "proof.json"], command[-4:])

    def test_callers_use_the_shared_command_boundary(self) -> None:
        for filename in PACKAGE_CALLERS:
            source = (ROOT / "scripts" / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("interop_cli_lib.command import", source)
                self.assertNotIn("interop_cli_command import", source)
                self.assertNotIn("src/interop_cli.zig", source)
                self.assertNotIn('"build-exe"', source)
        for filename in COMPATIBILITY_CALLERS:
            source = (ROOT / "scripts" / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("interop_cli_command import", source)
                self.assertNotIn("src/interop_cli.zig", source)
                self.assertNotIn('"build-exe"', source)
