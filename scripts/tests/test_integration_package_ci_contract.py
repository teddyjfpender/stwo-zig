from __future__ import annotations

import unittest

from scripts import ci_scope_plan
from scripts.tests.test_focused_ci_contract import ROOT, catalog_fixture


class IntegrationPackageCiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = ci_scope_plan.strict_json(
            ROOT / "conformance/ci-touchpoints-v1.json"
        )
        cls.catalog = catalog_fixture()

    def assert_package_lane(
        self,
        *,
        path: str,
        lane: str,
        build_file: str,
        consumers: set[str],
        steps: tuple[str, ...] = ("test",),
    ) -> None:
        selected, _ = ci_scope_plan.select_lanes(
            [path],
            self.catalog,
            self.policy,
        )
        self.assertTrue(
            {"static", lane, "package", *consumers}.issubset(selected)
        )
        commands = self.policy["lanes"][lane]["commands"]
        self.assertEqual(len(steps), len(commands))
        for step, command in zip(steps, commands, strict=True):
            self.assertEqual(["zig", "build", step], command[:3])
            self.assertIn(build_file, command)

    def test_riscv_cpu_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/riscv_cpu/mod.zig",
            lane="riscv_cpu_integration",
            build_file="src/integrations/riscv_cpu/build.zig",
            consumers={"riscv_cpu", "aggregate_cpu", "aggregate_metal"},
        )

    def test_cairo_cpu_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/cairo_cpu/mod.zig",
            lane="cairo_cpu_integration",
            build_file="src/integrations/cairo_cpu/build.zig",
            consumers={"cairo_cpu", "cairo_metal"},
        )

    def test_sm83_cpu_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/sm83_cpu/mod.zig",
            lane="sm83_cpu_integration",
            build_file="src/integrations/sm83_cpu/build.zig",
            consumers=set(),
            steps=("test", "test-machine-environment"),
        )

    def test_sm83_metal_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/sm83_metal/mod.zig",
            lane="sm83_metal_integration",
            build_file="src/integrations/sm83_metal/build.zig",
            consumers=set(),
            steps=("test", "test-machine-environment"),
        )
        self.assertEqual(
            "macos",
            self.policy["lanes"]["sm83_metal_integration"]["host"],
        )

    def test_riscv_metal_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/riscv_metal/mod.zig",
            lane="riscv_metal_integration",
            build_file="src/integrations/riscv_metal/build.zig",
            consumers={"riscv_metal"},
        )
        self.assertEqual(
            "macos",
            self.policy["lanes"]["riscv_metal_integration"]["host"],
        )

    def test_cairo_metal_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/cairo_metal/mod.zig",
            lane="cairo_metal_integration",
            build_file="src/integrations/cairo_metal/build.zig",
            consumers={
                "cairo_metal",
                "metal_compile",
            },
        )
        self.assertEqual(
            "macos",
            self.policy["lanes"]["cairo_metal_integration"]["host"],
        )

    def test_metal_session_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/tools/metal_session/mod.zig",
            lane="metal_session",
            build_file="src/tools/metal_session/build.zig",
            consumers={
                "cairo_metal",
                "metal_compile",
            },
        )

    def test_proof_wire_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/interop/proof_wire/mod.zig",
            lane="proof_wire",
            build_file="src/interop/proof_wire/build.zig",
            consumers={
                "aggregate_cpu",
                "aggregate_metal",
                "metal_compile",
                "native_cpu",
                "native_cuda_device",
                "native_cuda_static",
                "native_metal",
                "native_oracle",
                "riscv_cpu",
            },
        )

    def test_native_examples_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/examples/poseidon.zig",
            lane="native_examples",
            build_file="src/examples/build.zig",
            consumers={
                "aggregate_cpu",
                "aggregate_metal",
                "metal_compile",
                "native_cpu",
                "native_cuda_device",
                "native_cuda_static",
                "native_metal",
                "native_oracle",
            },
        )

    def test_native_cuda_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/native_cuda/poseidon/program.zig",
            lane="native_cuda_integration",
            build_file="src/integrations/native_cuda/build.zig",
            consumers={
                "native_cuda_device",
                "native_cuda_static",
            },
        )

    def test_cairo_cuda_integration_has_an_independent_package_lane(self) -> None:
        self.assert_package_lane(
            path="src/integrations/cairo_cuda/program.zig",
            lane="cairo_cuda_integration",
            build_file="src/integrations/cairo_cuda/build.zig",
            consumers={"native_cuda_static"},
        )
        self.assertEqual(
            "linux",
            self.policy["lanes"]["cairo_cuda_integration"]["host"],
        )

    def test_submission_diff_selects_only_the_link_reach(self) -> None:
        # Submission metadata is externally validated; only the prover edits
        # should expand this diff beyond the always-on lane.
        changed = [
            "autoresearch/submissions/2026-07-20-x/delta.json",
            "autoresearch/submissions/2026-07-20-x/note.md",
            "autoresearch/submissions/2026-07-20-x/verdict.json",
            "src/prover/pcs/quotient_tile_executor.zig",
            "src/prover/vcs_lifted/prover.zig",
        ]
        lanes, _ = ci_scope_plan.select_lanes(
            changed,
            self.catalog,
            self.policy,
        )
        self.assertEqual(
            sorted(lanes),
            [
                "aggregate_cpu", "aggregate_metal", "cairo_cpu",
                "cairo_cpu_integration", "cairo_cuda_integration",
                "cairo_frontend", "cairo_metal",
                "cairo_metal_integration", "cpu_backend", "metal_backend", "native_cpu",
                "native_cuda_device", "native_cuda_integration", "native_cuda_static",
                "native_examples", "native_metal",
                "native_oracle", "package", "prover", "riscv_cpu",
                "riscv_cpu_integration", "riscv_cuda_integration",
                "riscv_frontend", "riscv_metal",
                "riscv_metal_integration", "sm83_cpu_integration",
                "sm83_frontend", "sm83_metal_integration", "static",
            ],
        )


if __name__ == "__main__":
    unittest.main()
