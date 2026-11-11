"""OP tooling must have real gates without selecting unrelated device builds."""

import unittest

from scripts.repo import ci_scope_plan
from scripts.tests.test_focused_ci_contract import ROOT, catalog_fixture


class OpStackScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = ci_scope_plan.strict_json(
            ROOT / "conformance/ci-touchpoints-v1.json"
        )
        cls.catalog = catalog_fixture()

    def lanes(self, path):
        lanes, _ = ci_scope_plan.select_lanes([path], self.catalog, self.policy)
        return set(lanes)

    def test_op_tooling_runs_its_tests_without_gpu_or_cairo_builds(self):
        for path in (
            "opstack/cpu.py",
            "opstack/process_metrics.py",
            "opstack/tests/test_cpu.py",
        ):
            with self.subTest(path=path):
                self.assertEqual({"static", "opstack_python"}, self.lanes(path))

    def test_kona_changes_run_tooling_and_pinned_semantic_tests(self):
        for path in ("opstack/kona/Cargo.lock", "opstack/kona/src/transition.rs"):
            with self.subTest(path=path):
                self.assertEqual(
                    {"static", "opstack_python", "opstack_kona"},
                    self.lanes(path),
                )
        commands = self.policy["lanes"]["opstack_kona"]["commands"]
        self.assertTrue(any("--locked" in command for command in commands))
        self.assertTrue(
            any(
                "host,transition-program,pairing-hints,bn254-glv" in command
                for command in commands
            )
        )

    def test_shared_guest_patches_include_kona_regressions(self):
        self.assertIn(
            "opstack_kona",
            self.lanes(
                "guests/ethereum/rv64/vendor/k256/src/lib.rs"
            ),
        )

    def test_shared_engine_and_unknown_paths_keep_their_broad_coverage(self):
        shared = self.lanes("src/waist/core/fields/m31.zig")
        self.assertTrue(
            {"core", "prover", "cpu_backend", "riscv_cpu_integration"} <= shared
        )
        self.assertEqual(
            set(self.policy["lanes"]), self.lanes("new-unowned-product/code.rs")
        )
