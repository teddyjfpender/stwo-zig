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
        self.assertEqual(1, len(commands))
        self.assertIn(build_file, commands[0])

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


if __name__ == "__main__":
    unittest.main()
