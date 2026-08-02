"""The top-level tools directory is a closed, bounded production surface."""

from __future__ import annotations

import unittest
from pathlib import Path

from scripts import ci_scope_plan

from scripts.tests.test_focused_ci_contract import catalog_fixture


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
INVENTORY = ROOT / "conformance" / "tooling-surface-v1.json"
CI_POLICY = ROOT / "conformance" / "ci-touchpoints-v1.json"
ROLES = {
    "execution-sidecar",
    "fixture-generator",
    "independent-proof-oracle",
    "independent-vector-generator",
    "legacy-proof-oracle",
    "qualification-adapter",
}


class ToolingSurfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inventory = ci_scope_plan.strict_json(INVENTORY)
        cls.policy = ci_scope_plan.strict_json(CI_POLICY)
        cls.catalog = catalog_fixture()

    def test_inventory_is_exactly_the_tracked_top_level_surface(self) -> None:
        self.assertEqual("stwo-zig-tooling-surface-v1", self.inventory["schema"])
        actual = {path.name for path in TOOLS.iterdir() if path.is_dir()}
        self.assertEqual(set(self.inventory["roots"]), actual)

    def test_every_retained_root_has_live_production_callers(self) -> None:
        for name, item in self.inventory["roots"].items():
            with self.subTest(tool=name):
                self.assertIsInstance(item["owner"], str)
                self.assertTrue(item["owner"])
                self.assertIn(item["role"], ROLES)
                self.assertTrue(item["required_for"])
                self.assertTrue(item["extraction"])
                callers = item["live_callers"]
                self.assertTrue(callers)
                for caller in callers:
                    self.assertFalse(caller.startswith("autoresearch/"))
                    self.assertTrue((ROOT / caller).is_file(), caller)

    def test_every_tool_change_has_one_bounded_pr_plan(self) -> None:
        every_lane = set(self.policy["lanes"])
        for name, item in self.inventory["roots"].items():
            with self.subTest(tool=name):
                selected, _ = ci_scope_plan.select_lanes(
                    [f"tools/{name}/Cargo.toml"],
                    self.catalog,
                    self.policy,
                )
                self.assertEqual(set(item["pr_lanes"]), set(selected))
                self.assertNotEqual(every_lane, set(selected))


if __name__ == "__main__":
    unittest.main()
