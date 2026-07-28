from __future__ import annotations

import unittest

from scripts import ci_scope_plan
from scripts.tests.test_focused_ci_contract import ROOT, catalog_fixture


class ProverApiCiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = ci_scope_plan.strict_json(
            ROOT / "conformance/ci-touchpoints-v1.json"
        )
        cls.catalog = catalog_fixture()

    def test_prover_api_has_an_independent_package_lane(self) -> None:
        selected, _ = ci_scope_plan.select_lanes(
            ["src/prover_api/engine.zig"],
            self.catalog,
            self.policy,
        )
        self.assertTrue(
            {
                "static",
                "prover_api",
                "prover",
                "riscv_frontend",
                "cairo_frontend",
                "cpu_backend",
                "metal_backend",
                "package",
                "native_cpu",
                "riscv_cpu",
                "cairo_cpu",
                "aggregate_cpu",
                "aggregate_metal",
            }.issubset(selected)
        )
        commands = self.policy["lanes"]["prover_api"]["commands"]
        self.assertEqual(1, len(commands))
        self.assertIn("src/prover_api/build.zig", commands[0])


if __name__ == "__main__":
    unittest.main()
