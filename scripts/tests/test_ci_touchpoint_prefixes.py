"""CI touchpoint rule prefixes must name paths that exist.

A rule prefix is a trigger, matched against changed paths by `owns`, which
accepts a path only when it equals the prefix or descends from it. A prefix
naming a path that cannot exist therefore matches nothing, and every lane the
rule was written to summon silently stops being summoned. Relocating a tree
without updating its touchpoint is exactly how that happens, and the shipped
policy had accumulated four such dead triggers before this check existed.

Kept out of `test_focused_ci_contract.py` because that file sits against the
850-line manual-source ceiling.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import ci_scope_plan
from scripts.tests.test_focused_ci_contract import ROOT, catalog_fixture


class TouchpointPrefixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = ci_scope_plan.strict_json(
            ROOT / "conformance/ci-touchpoints-v1.json"
        )
        cls.catalog = catalog_fixture()

    def lanes_for(self, *paths: str) -> set[str]:
        lanes, _ = ci_scope_plan.select_lanes(paths, self.catalog, self.policy)
        return set(lanes)


    def test_every_shipped_rule_prefix_names_a_path_that_exists(self) -> None:
        # A rule prefix that matches no possible path is a trigger that never
        # fires, so the lanes behind it stop running without anything going red.
        ci_scope_plan.validate_rule_prefixes_exist(self.policy, ROOT)

    def test_a_relocated_tree_leaves_its_rule_prefix_dead(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["rules"].append(
            {"prefixes": ["src/backends/metal/cairo"], "lanes": ["cairo_metal"]}
        )
        with self.assertRaisesRegex(ci_scope_plan.PlanError, "do not exist"):
            ci_scope_plan.validate_rule_prefixes_exist(policy, ROOT)

    def test_rule_prefixes_must_stay_inside_the_repository(self) -> None:
        for prefix in ("../outside", "/absolute/path", "src/core/../../outside"):
            with self.subTest(prefix=prefix):
                policy = json.loads(json.dumps(self.policy))
                policy["rules"].append({"prefixes": [prefix], "lanes": ["core"]})
                with self.assertRaisesRegex(ci_scope_plan.PlanError, "unsafe"):
                    ci_scope_plan.validate_rule_prefixes_exist(policy, ROOT)

    def test_restored_rule_prefixes_select_the_lanes_they_name(self) -> None:
        # These prefixes were written as bare stems that `owns` can never match,
        # so their rules never fired. Asserting only "lane is selected" would not
        # catch that: an unmatched path falls through to the fail-closed
        # fallback, which selects every lane and so contains the lane anyway.
        # Assert the rule itself matches, and that the result is a scoped
        # selection rather than the fallback.
        every_lane = set(self.policy["lanes"])
        for path, lane in (
            ("build_support/products/catalog.zig", "build_graph"),
            ("build_support/products/catalog_manifest.zig", "build_graph"),
            ("scripts/metal_core_aot_receipt.py", "metal_aot"),
            ("scripts/metal_core_aot_receipt_lib/receipt.py", "metal_aot"),
            ("scripts/cuda_build.py", "native_cuda_static"),
            ("scripts/cuda_device_smoke.py", "native_cuda_device"),
        ):
            with self.subTest(path=path):
                matching = [
                    rule
                    for rule in self.policy["rules"]
                    if any(
                        ci_scope_plan.owns(path, prefix) for prefix in rule["prefixes"]
                    )
                ]
                self.assertTrue(matching, f"no touchpoint rule matches {path}")
                self.assertTrue(any(lane in rule["lanes"] for rule in matching))
                selected = self.lanes_for(path)
                self.assertIn(lane, selected)
                self.assertNotEqual(every_lane, selected)

    def test_metal_aot_and_cuda_script_touchpoints_stay_narrowly_scoped(self) -> None:
        self.assertEqual(
            {"static", "metal_aot"},
            self.lanes_for("scripts/metal_core_aot_receipt.py"),
        )
        self.assertEqual(
            {
                "static",
                "package",
                "native_cuda_static",
                "native_cuda_device",
                "native_cuda_integration",
                "cairo_cuda_integration",
            },
            self.lanes_for("scripts/cuda_build.py"),
        )

    def test_plan_entrypoint_refuses_a_policy_with_a_dead_rule_prefix(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["rules"].append(
            {"prefixes": ["src/backends/metal/cairo"], "lanes": ["cairo_metal"]}
        )
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            policy_path = directory / "policy.json"
            catalog_path = directory / "catalog.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            catalog_path.write_text(json.dumps(self.catalog), encoding="utf-8")
            argv = [
                "--root", str(ROOT),
                "--policy", str(policy_path),
                "--catalog", str(catalog_path),
                "--changed-file", "src/core/fields/m31.zig",
                "--output", str(directory / "plan.json"),
            ]
            stderr = io.StringIO()
            with mock.patch.object(sys, "stderr", stderr):
                self.assertEqual(2, ci_scope_plan.main(argv))
            self.assertIn("do not exist", stderr.getvalue())
            self.assertFalse((directory / "plan.json").exists())

    def test_dead_skip_allowlist_entries_stay_admissible(self) -> None:
        # Unlike a rule prefix, a documentation prefix that matches nothing
        # skips nothing: the unmatched path falls through to the full-lane
        # fallback, so forward-looking entries here are safe by construction.
        policy = json.loads(json.dumps(self.policy))
        policy["documentation_prefixes"].append("tree/that/does/not/exist")
        ci_scope_plan.validate_rule_prefixes_exist(policy, ROOT)


if __name__ == "__main__":
    unittest.main()
