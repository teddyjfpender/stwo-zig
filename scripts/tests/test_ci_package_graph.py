"""Contract tests for graph-derived focused CI lane selection.

Two layers are asserted here:

* the resolver's behaviour on synthetic graphs, where the expected closure is
  small enough to state by hand; and
* the live repository's contracts and CI touchpoint policy, so the real graph
  cannot drift away from the lanes it must select.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts import ci_package_graph as graph
from scripts import ci_scope_plan


ROOT = Path(__file__).resolve().parents[2]
POLICY = json.loads((ROOT / "conformance/ci-touchpoints-v1.json").read_text(encoding="utf-8"))

# The workspace validator's edge count. A change here means a real dependency
# was added or removed; update the number deliberately, with the closure
# consequences reviewed.
EXPECTED_PACKAGES = 21
EXPECTED_EDGES = 70


def contract(package: str, dependencies: dict[str, str]) -> str:
    return json.dumps(
        {
            "schema": "stwo-zig-package-contract-v1",
            "package": package,
            "owner": "test",
            "public_modules": {package: "mod.zig"},
            "dependencies": dependencies,
            "injected_modules": [],
            "api_surface": [],
            "ci": {"host": "any", "command": ["zig", "build", "test"]},
        }
    )


def write_workspace(root: Path, layout: dict[str, dict[str, str]]) -> None:
    """Materialise ``{directory: {dependency_name: relative_path}}`` contracts."""
    for directory, dependencies in layout.items():
        target = root / directory
        target.mkdir(parents=True, exist_ok=True)
        package = directory.rsplit("/", 1)[-1]
        (target / graph.CONTRACT_NAME).write_text(
            contract(package, dependencies), encoding="utf-8"
        )


def lane(build_file: str) -> dict[str, object]:
    return {
        "host": "linux",
        "description": "test lane",
        "commands": [["zig", "build", "test", "--build-file", build_file]],
    }


class SyntheticGraphTest(unittest.TestCase):
    """A diamond graph: leaf <- middle_a, middle_b <- top."""

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)
        write_workspace(
            self.root,
            {
                "src/leaf": {},
                "src/middle_a": {"leaf": "../leaf"},
                "src/middle_b": {"leaf": "../leaf"},
                "src/top": {"middle_a": "../middle_a", "middle_b": "../middle_b"},
                "src/detached": {},
            },
        )
        self.packages = graph.load_packages(self.root)
        self.policy = {
            "lanes": {
                name: lane(f"src/{name}/build.zig")
                for name in ("leaf", "middle_a", "middle_b", "top", "detached")
            }
        }
        self.bindings = graph.lane_packages(self.policy, self.packages)

    def test_edges_resolve_to_package_names(self) -> None:
        self.assertEqual(self.packages["top"].dependencies, frozenset({"middle_a", "middle_b"}))
        self.assertEqual(graph.edge_count(self.packages), 4)

    def test_leaf_change_selects_every_dependent_lane(self) -> None:
        lanes, unowned = graph.selection(["src/leaf/mod.zig"], self.packages, self.bindings)
        self.assertEqual(lanes, frozenset({"leaf", "middle_a", "middle_b", "top"}))
        self.assertEqual(unowned, frozenset())

    def test_sibling_change_does_not_select_the_other_branch(self) -> None:
        lanes, _ = graph.selection(["src/middle_a/mod.zig"], self.packages, self.bindings)
        self.assertEqual(lanes, frozenset({"middle_a", "top"}))

    def test_top_change_selects_only_itself(self) -> None:
        lanes, _ = graph.selection(["src/top/mod.zig"], self.packages, self.bindings)
        self.assertEqual(lanes, frozenset({"top"}))

    def test_detached_package_is_isolated(self) -> None:
        lanes, _ = graph.selection(["src/detached/mod.zig"], self.packages, self.bindings)
        self.assertEqual(lanes, frozenset({"detached"}))

    def test_unowned_path_is_reported_rather_than_ignored(self) -> None:
        lanes, unowned = graph.selection(
            ["scripts/anything.py", "src/leaf/mod.zig"], self.packages, self.bindings
        )
        self.assertEqual(unowned, frozenset({"scripts/anything.py"}))
        self.assertIn("leaf", lanes)

    def test_selection_is_deterministic_and_order_independent(self) -> None:
        forward, _ = graph.selection(
            ["src/leaf/a.zig", "src/middle_b/b.zig"], self.packages, self.bindings
        )
        reverse, _ = graph.selection(
            ["src/middle_b/b.zig", "src/leaf/a.zig"], self.packages, self.bindings
        )
        self.assertEqual(forward, reverse)

    def test_nested_package_wins_over_its_parent(self) -> None:
        write_workspace(self.root, {"src/leaf/inner": {}})
        packages = graph.load_packages(self.root)
        self.assertEqual(graph.owning_package("src/leaf/inner/mod.zig", packages), "inner")
        self.assertEqual(graph.owning_package("src/leaf/mod.zig", packages), "leaf")

    def test_cycle_terminates(self) -> None:
        write_workspace(
            self.root,
            {"src/leaf": {"top": "../top"}},
        )
        packages = graph.load_packages(self.root)
        self.assertEqual(
            graph.reverse_closure(packages, ["src/leaf"]),
            frozenset(),
            "unknown seeds contribute nothing",
        )
        self.assertEqual(
            graph.reverse_closure(packages, ["leaf"]),
            frozenset({"leaf", "middle_a", "middle_b", "top"}),
        )

    def test_lane_building_an_unowned_file_is_rejected(self) -> None:
        policy = {"lanes": {"stray": lane("src/absent/build.zig")}}
        with self.assertRaises(graph.GraphError):
            graph.lane_packages(policy, self.packages)

    def test_unresolvable_dependency_is_rejected(self) -> None:
        write_workspace(self.root, {"src/broken": {"absent": "../absent"}})
        with self.assertRaises(graph.GraphError):
            graph.load_packages(self.root)

    def test_empty_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            with self.assertRaises(graph.GraphError):
                graph.load_packages(Path(empty))


class RepositoryGraphTest(unittest.TestCase):
    def setUp(self) -> None:
        self.packages = graph.load_packages(ROOT)
        self.bindings = graph.lane_packages(POLICY, self.packages)

    def test_workspace_shape_is_pinned(self) -> None:
        self.assertEqual(len(self.packages), EXPECTED_PACKAGES)
        self.assertEqual(graph.edge_count(self.packages), EXPECTED_EDGES)

    def test_every_package_has_exactly_one_focused_lane(self) -> None:
        bound = sorted(self.bindings.values())
        self.assertEqual(bound, sorted(self.packages))

    def test_core_change_selects_every_dependent_package_lane(self) -> None:
        lanes, _ = graph.selection(["src/core/fields/m31.zig"], self.packages, self.bindings)
        # Every package except the two with no path to stwo_core.
        detached = {"metal_session"}
        self.assertEqual(lanes, frozenset(set(self.bindings) - detached))

    def test_cairo_only_change_avoids_riscv_and_native_lanes(self) -> None:
        lanes, _ = graph.selection(["src/frontends/cairo/air.zig"], self.packages, self.bindings)
        self.assertEqual(
            lanes,
            frozenset(
                {
                    "cairo_frontend",
                    "cairo_cpu_integration",
                    "cairo_metal_integration",
                    "cairo_cuda_integration",
                }
            ),
        )
        self.assertNotIn("riscv_frontend", lanes)
        self.assertNotIn("riscv_cpu_integration", lanes)
        self.assertNotIn("riscv_metal_integration", lanes)
        self.assertNotIn("cuda_backend", lanes)
        self.assertNotIn("native_examples", lanes)

    def test_riscv_frontend_change_avoids_cairo_and_cuda_lanes(self) -> None:
        lanes, _ = graph.selection(["src/frontends/riscv/air.zig"], self.packages, self.bindings)
        self.assertEqual(
            lanes,
            frozenset({"riscv_frontend", "riscv_cpu_integration", "riscv_metal_integration"}),
        )

    def test_sm83_frontend_change_selects_its_backend_integrations(self) -> None:
        lanes, _ = graph.selection(["src/frontends/sm83/air.zig"], self.packages, self.bindings)
        self.assertEqual(
            lanes,
            frozenset({
                "sm83_frontend",
                "sm83_cpu_integration",
                "sm83_metal_integration",
            }),
        )

    def test_backend_contracts_reach_transitive_integration_lanes(self) -> None:
        """The drift this resolver removes: these three reach src/backend only
        through cpu_backend or metal_backend, and the superseded hand-written
        rule omitted them."""
        lanes, _ = graph.selection(["src/backend/mod.zig"], self.packages, self.bindings)
        for expected in ("riscv_cpu_integration", "cairo_cpu_integration", "riscv_metal_integration"):
            self.assertIn(expected, lanes)

    def test_policy_carries_no_hand_written_package_lane_for_owned_prefixes(self) -> None:
        """Package-owned prefixes must not restate lanes the graph derives."""
        package_lanes = set(self.bindings)
        for rule in POLICY["rules"]:
            for prefix in rule["prefixes"]:
                if graph.owning_package(prefix, self.packages) is None:
                    continue
                derived, _ = graph.selection([prefix], self.packages, self.bindings)
                restated = (set(rule["lanes"]) & package_lanes) & derived
                self.assertEqual(
                    restated,
                    set(),
                    f"{prefix} restates graph-derived lanes {sorted(restated)}",
                )


class PlanIntegrationTest(unittest.TestCase):
    """The graph must reach the plan, and the fail-open bias must survive it."""

    def setUp(self) -> None:
        self.packages = graph.load_packages(ROOT)
        self.catalog = {
            "schema": "stwo-product-catalog-v2",
            "products": [
                {
                    "scope": scope,
                    "state": "released",
                    "module_roots": [],
                    "allowed_files": [],
                    "configure_allowed_files": [],
                    "allowed_prefixes": [],
                    "configure_allowed_prefixes": [],
                }
                for scope in POLICY["product_scope_lanes"]
            ],
        }

    def select(self, *paths: str) -> set[str]:
        lanes, _ = ci_scope_plan.select_lanes(paths, self.catalog, POLICY, self.packages)
        return set(lanes)

    def test_always_lanes_are_the_documentation_floor(self) -> None:
        self.assertEqual(self.select("README.md"), set(POLICY["always_lanes"]))
        self.assertEqual(
            self.select("autoresearch/notes/2026-07-28-x/note.md"),
            set(POLICY["always_lanes"]),
        )
        self.assertEqual(self.select("docs/deep/nested/page.md"), set(POLICY["always_lanes"]))

    def test_static_floor_is_fast_and_complete_script_tests_are_separate(self) -> None:
        static = POLICY["lanes"]["static"]["commands"]
        scripts = POLICY["lanes"]["script_contracts"]["commands"]
        self.assertIn(["python3", "scripts/ci.py", "--fast"], static)
        self.assertFalse(any("discover" in command for command in static))
        self.assertEqual(
            [[
                "python3", "-m", "unittest", "discover", "-s",
                "scripts/tests", "-p", "test_*.py",
            ]],
            scripts,
        )

    def test_unmapped_path_fails_open_to_the_full_matrix(self) -> None:
        self.assertEqual(self.select("scripts/riscv_poseidon_table_uniqueness.py"), set(POLICY["lanes"]))
        self.assertEqual(self.select("build_support/anything_new.zig"), set(POLICY["lanes"]))
        self.assertEqual(self.select("third_party/vendored.c"), set(POLICY["lanes"]))

    def test_workflow_change_fails_open_to_the_full_matrix(self) -> None:
        self.assertEqual(self.select(".github/workflows/ci.yml"), set(POLICY["lanes"]))

    def test_independent_workflow_change_runs_only_its_script_contracts(self) -> None:
        for path in (
            ".github/workflows/benchmark-pages.yml",
            ".githooks/pre-commit",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    {"static", "script_contracts"},
                    self.select(path),
                )

    def test_package_change_selects_graph_lanes_through_the_plan(self) -> None:
        selected = self.select("src/frontends/cairo/air.zig")
        self.assertIn("cairo_frontend", selected)
        self.assertIn("cairo_metal_integration", selected)
        self.assertNotIn("riscv_frontend", selected)
        self.assertNotIn("native_cuda_device", selected)

    def test_core_change_selects_more_lanes_than_a_leaf_change(self) -> None:
        self.assertGreater(
            len(self.select("src/core/fields/m31.zig")),
            len(self.select("src/integrations/cairo_cpu/mod.zig")),
        )

    def test_scheduled_full_matrix_selects_every_hosted_lane(self) -> None:
        lanes, reasons = ci_scope_plan.select_lanes(
            ["autoresearch/notes/x/note.md"],
            self.catalog,
            POLICY,
            self.packages,
            full_matrix=True,
        )
        hosted = {
            lane
            for lane in POLICY["lanes"]
            if POLICY["lanes"][lane].get("hosted", True)
        }
        self.assertEqual(set(lanes), hosted)
        self.assertEqual(reasons["static"], ["full-matrix"])

    def test_scheduled_full_matrix_spares_unselected_self_hosted_lanes(self) -> None:
        lanes, reasons = ci_scope_plan.select_lanes(
            ["autoresearch/notes/x/note.md"],
            self.catalog,
            POLICY,
            self.packages,
            full_matrix=True,
        )
        for lane in lanes:
            if not POLICY["lanes"][lane].get("hosted", True):
                self.fail(
                    f"self-hosted lane {lane} entered the scheduled full matrix "
                    "on a notes-only diff"
                )

    def test_scheduled_full_matrix_keeps_diff_selected_self_hosted_lanes(self) -> None:
        self_hosted = {
            lane
            for lane in POLICY["lanes"]
            if not POLICY["lanes"][lane].get("hosted", True)
        }
        if not self_hosted:
            self.skipTest("policy declares no self-hosted lanes")
        scoped, _ = ci_scope_plan.select_lanes(
            ["build.zig"], self.catalog, POLICY, self.packages, full_matrix=False
        )
        expected = self_hosted & set(scoped)
        if not expected:
            self.skipTest("fail-open selection reaches no self-hosted lane")
        lanes, reasons = ci_scope_plan.select_lanes(
            ["build.zig"], self.catalog, POLICY, self.packages, full_matrix=True
        )
        for lane in expected:
            self.assertIn(lane, lanes)
            self.assertNotEqual(reasons[lane], ["full-matrix"])

    def test_full_matrix_survives_an_empty_diff(self) -> None:
        lanes, _ = ci_scope_plan.select_lanes(
            [], self.catalog, POLICY, self.packages, full_matrix=True
        )
        hosted = {
            lane
            for lane in POLICY["lanes"]
            if POLICY["lanes"][lane].get("hosted", True)
        }
        self.assertEqual(set(lanes), hosted)

    def test_summary_lists_every_lane_as_selected_or_skipped(self) -> None:
        lanes, reasons = ci_scope_plan.select_lanes(
            ["src/frontends/cairo/air.zig"], self.catalog, POLICY, self.packages
        )
        plan = {"lanes": lanes, "reasons": reasons}
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            ci_scope_plan.emit_github_summary(summary, plan, POLICY)
            text = summary.read_text(encoding="utf-8")
        for name in POLICY["lanes"]:
            self.assertIn(f"`{name}`", text, f"{name} is absent from the summary")
        self.assertIn("| selected |", text)
        self.assertIn("| skipped |", text)

    def test_plan_is_deterministic(self) -> None:
        first = ci_scope_plan.select_lanes(
            ["src/core/a.zig", "README.md"], self.catalog, POLICY, self.packages
        )
        second = ci_scope_plan.select_lanes(
            ["README.md", "src/core/a.zig"], self.catalog, POLICY, self.packages
        )
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
