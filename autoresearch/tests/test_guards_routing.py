"""TRACKS §8: per-group guard registries, per-track impact maps and editable
paths, frontend-aware board routing, the mechanism gate, and per-track TASK.md.

These are contract tests: they assert the shapes the runner and the site bind
to, and they assert the fail-closed direction of every ambiguity.
"""

import contextlib
import copy
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))
sys.path.insert(0, str(ROOT))

from stwo_perf import __main__ as cli  # noqa: E402
from stwo_perf import feed, ledger, runner, track_task  # noqa: E402
from stwo_perf import manifest as manifest_mod  # noqa: E402
from stwo_perf.manifest import Manifest, ManifestError  # noqa: E402


def load_manifest() -> Manifest:
    return manifest_mod.load(ROOT)


class PerGroupGuardRegistryTest(unittest.TestCase):
    """A track's guards come from ITS registry, on ITS binary."""

    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def test_every_group_declares_a_registry_or_says_why_not(self):
        for group in self.m.groups():
            if group.guard_registry is None:
                self.assertTrue(
                    (group.guard_registry_absent_reason or "").strip(),
                    f"{group.group_id} is silently unguarded",
                )
            else:
                self.assertIn(
                    group.guard_registry,
                    self.m.raw["workload_registry"]["guards"]["registries"],
                )

    def test_native_groups_keep_the_twelve_guard_portfolio(self):
        for group_id in ("native", "metal"):
            registry = self.m.guard_registry(group_id)
            self.assertEqual(len(registry["workloads"]), 12)
            self.assertIn("guard_blake_10x10", registry["workloads"])

    def test_cairo_guards_are_the_committed_cairo_statements(self):
        registry = self.m.guard_registry("cairo_cpu")
        self.assertEqual(
            sorted(registry["workloads"]),
            ["guard_cairo_all_builtins", "guard_cairo_all_opcodes"],
        )
        # The guard replays the same committed prover input the scored basket
        # uses; nothing is invented to widen the surface.
        scored = self.m.group("cairo_cpu").workloads
        scored_args = {w.args for w in scored}
        for spec in registry["workloads"].values():
            self.assertIn(spec["args"], scored_args)

    def test_cairo_and_riscv_guards_never_carry_native_example_args(self):
        for group_id in ("cairo_cpu", "cairo_metal", "riscv"):
            for gid, spec in self.m.guard_registry(group_id)["workloads"].items():
                self.assertNotIn(
                    "--example", spec["args"],
                    f"{group_id}/{gid} binds a native AIR statement to a "
                    "product CLI that cannot parse it",
                )

    def test_riscv_guards_come_from_its_own_basket(self):
        registry = self.m.guard_registry("riscv")
        basket = {w.workload_id: w.args for w in self.m.group("riscv").workloads}
        self.assertTrue(registry["workloads"])
        for gid, spec in registry["workloads"].items():
            self.assertEqual(spec["args"], basket[gid.removeprefix("guard_")])

    def test_registry_policy_overrides_the_global_fallback(self):
        cairo = self.m.guard_registry("cairo_cpu")["policy"]
        native = self.m.guard_registry("native")["policy"]
        # Inherited from the global block by both.
        self.assertEqual(cairo["budget_upper"], native["budget_upper"])
        # Overridden: a Cairo guard proves one statement per cold process.
        self.assertGreater(cairo["wall_clock_cap_seconds"], 300)
        self.assertNotIn("wall_clock_cap_seconds", native)

    def test_groups_without_a_registry_select_no_guards(self):
        for group_id in ("cuda", "pr6_supremacy"):
            registry = self.m.guard_registry(group_id)
            self.assertEqual(registry["workloads"], {})
            selected = runner.select_guards(
                self.m, ["src/prover/fri.zig"], self.m.group(group_id)
            )
            self.assertEqual(selected, [])

    def test_guards_bind_to_the_objective_groups_binary(self):
        selected = runner.select_guards(
            self.m, ["src/frontends/cairo/mod.zig"], self.m.group("cairo_metal")
        )
        self.assertTrue(selected)
        for workload in selected:
            self.assertEqual(workload.group_id, "cairo_metal")
            self.assertEqual(workload.workload_class, "guard")

    def test_run_guards_uses_the_groups_own_wall_and_timeout_budget(self):
        workload = self.m.group("cairo_cpu").workloads[0]
        score = mock.Mock(r=1.0, ci=(0.9, 1.0), ratios=[1.0], proof_digest="a" * 64)
        with mock.patch.object(runner, "paired_rounds", return_value=score) as paired:
            runner.run_guards(
                Path("/a"), Path("/b"), self.m, [workload], Path("/tmp"),
                objective_group=self.m.group("cairo_cpu"),
            )
        policy = paired.call_args.args[4]
        self.assertEqual(policy["wall_clock_cap_seconds"]["guard"], 3600.0)
        self.assertEqual(policy["command_timeout_seconds"], 3600.0)

    def test_native_guard_policy_is_byte_for_byte_the_pre_tracks_behaviour(self):
        workload = self.m.group("native").workloads[0]
        score = mock.Mock(r=1.0, ci=(0.9, 1.0), ratios=[1.0], proof_digest="a" * 64)
        with mock.patch.object(runner, "paired_rounds", return_value=score) as paired:
            runner.run_guards(
                Path("/a"), Path("/b"), self.m, [workload], Path("/tmp"),
                objective_group=self.m.group("native"),
            )
        policy = paired.call_args.args[4]
        self.assertEqual(policy["warmups"], 5)
        self.assertEqual(policy["samples_per_round"], 2)
        self.assertEqual(policy["min_rounds"], 3)
        self.assertEqual(policy["max_rounds"], 8)
        self.assertEqual(policy["wall_clock_cap_seconds"], {"guard": 300.0})
        self.assertEqual(policy["command_timeout_seconds"], 300.0)

    def test_a_flat_pre_tracks_manifest_still_resolves_for_every_group(self):
        raw = {
            "workload_registry": {
                "guards": {"workloads": {"guard_x": {"args": "--example x"}}},
                "groups": {"native": {"board": "core_cpu"}},
            }
        }
        for group_id in (None, "native", "anything"):
            resolved = manifest_mod.resolve_guard_registry(raw, group_id)
            self.assertEqual(sorted(resolved["workloads"]), ["guard_x"])


class ImpactMapSelectionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def _ids(self, board, paths):
        group = self.m.group_for_board(board)
        return sorted(
            w.workload_id for w in runner.select_guards(self.m, paths, group)
        )

    def test_generic_prover_paths_select_every_guard_in_each_registry(self):
        for board in ("core_cpu", "cairo_cpu", "riscv"):
            group = self.m.group_for_board(board)
            selected = runner.select_guards(
                self.m, ["src/prover/fri.zig"], group,
            )
            self.assertEqual(
                len(selected),
                len(self.m.guard_registry(group.group_id)["workloads"]),
                board,
            )

    def test_cairo_frontend_paths_select_cairo_guards(self):
        selected = self._ids("cairo_cpu", ["src/frontends/cairo/vm/mod.zig"])
        self.assertEqual(
            selected, ["guard_cairo_all_builtins", "guard_cairo_all_opcodes"],
        )

    def test_riscv_frontend_and_integration_paths_select_riscv_guards(self):
        for path in (
            "src/frontends/riscv/decode.zig",
            "src/integrations/riscv_cpu/adapter.zig",
            "src/integrations/riscv_metal/adapter.zig",
        ):
            selected = self._ids("riscv", [path])
            self.assertEqual(
                len(selected),
                len(self.m.guard_registry("riscv")["workloads"]),
                path,
            )

    def test_metal_paths_are_board_scoped_per_track(self):
        # The metal-sparing rule must not spare the Metal board itself.
        self.assertEqual(self._ids("cairo_cpu", ["src/backends/metal/x.metal"]), [])
        self.assertEqual(
            len(self._ids("cairo_metal", ["src/backends/metal/x.metal"])), 2,
        )
        self.assertEqual(self._ids("riscv", ["src/backends/metal/x.metal"]), [])
        self.assertEqual(self._ids("core_cpu", ["src/backends/metal/x.metal"]), [])
        self.assertEqual(
            len(self._ids("core_metal", ["src/backends/metal/x.metal"])), 12,
        )

    def test_unmatched_source_path_fails_closed_to_the_whole_registry(self):
        for board in ("core_cpu", "cairo_cpu", "riscv"):
            group = self.m.group_for_board(board)
            selected = runner.select_guards(
                self.m, ["src/mystery/new_area.zig"], group,
            )
            self.assertEqual(
                len(selected),
                len(self.m.guard_registry(group.group_id)["workloads"]),
                board,
            )

    def test_non_source_paths_select_nothing(self):
        self.assertEqual(
            self._ids("cairo_cpu", ["autoresearch/notes/n.md"]), [],
        )

    def test_impact_map_rules_only_name_guards_from_their_own_registry(self):
        registries = self.m.raw["workload_registry"]["guards"]["registries"]
        for name, spec in registries.items():
            known = set(spec["workloads"])
            for rule in spec.get("impact_map", {}).get("rules", []):
                guards = rule.get("guards")
                if guards == "all":
                    continue
                self.assertEqual(set(guards) - known, set(), name)


class EditablePathScopingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def test_frontend_paths_are_editable_only_by_their_own_track(self):
        cairo = "src/frontends/cairo/vm/mod.zig"
        riscv = "src/frontends/riscv/decode.zig"
        self.assertTrue(self.m.is_editable(cairo, board="cairo_cpu"))
        self.assertTrue(self.m.is_editable(cairo, board="cairo_metal"))
        self.assertFalse(self.m.is_editable(cairo, board="core_cpu"))
        self.assertFalse(self.m.is_editable(cairo, board="riscv"))
        self.assertTrue(self.m.is_editable(riscv, board="riscv"))
        self.assertFalse(self.m.is_editable(riscv, board="cairo_cpu"))
        self.assertFalse(self.m.is_editable(riscv, board="core_cpu"))

    def test_cairo_metal_integration_is_not_editable_by_cairo_cpu(self):
        path = "src/integrations/cairo_metal/adapter.zig"
        self.assertTrue(self.m.is_editable(path, board="cairo_metal"))
        self.assertFalse(self.m.is_editable(path, board="cairo_cpu"))

    def test_boardless_callers_keep_the_global_set(self):
        # The workflow policy checker and the submitter pass no board.
        self.assertFalse(self.m.is_editable("src/frontends/cairo/vm/mod.zig"))
        self.assertTrue(self.m.is_editable("src/prover/fri.zig"))
        self.assertEqual(
            self.m.editable_for_board(None),
            [dict(e) for e in self.m.raw["editable_paths"]],
        )

    def test_shared_backend_paths_stay_editable_on_every_track(self):
        for board in ("core_cpu", "core_metal", "cairo_cpu", "riscv"):
            self.assertTrue(
                self.m.is_editable("src/backends/metal/kernel.metal", board=board),
                board,
            )

    def test_classify_touched_makes_a_foreign_frontend_edit_a_stray(self):
        touched = ["src/frontends/cairo/vm/mod.zig"]
        self.assertEqual(
            self.m.classify_touched(touched, board="core_cpu"), ([], touched),
        )
        self.assertEqual(
            self.m.classify_touched(touched, board="cairo_cpu"), ([], []),
        )

    def test_g2_fails_when_a_native_run_edits_the_cairo_frontend(self):
        touched = ["src/frontends/cairo/vm/mod.zig"]
        with mock.patch.object(runner, "changed_paths", return_value=touched):
            native = runner._gates(
                ROOT, self.m, [], {"targeted_class_budget": 1.02}, False, None,
                "small", "core_cpu",
            )
            cairo = runner._gates(
                ROOT, self.m, [], {"targeted_class_budget": 1.02}, False, None,
                "small", "cairo_cpu",
            )
        self.assertFalse(native["G2"]["pass"])
        self.assertIn("outside editable set", native["G2"]["detail"])
        self.assertTrue(cairo["G2"]["pass"])

    def test_path_rung_and_judged_rung_respect_the_track(self):
        path = "src/frontends/cairo/vm/mod.zig"
        self.assertEqual(self.m.path_rung(path, board="cairo_cpu"), "s3")
        self.assertIsNone(self.m.path_rung(path, board="core_cpu"))
        self.assertEqual(self.m.judged_rung("s3", [path], board="cairo_cpu"), "s3")

    def test_a_per_track_entry_can_never_reopen_a_locked_path(self):
        raw = copy.deepcopy(self.m.raw)
        raw["workload_registry"]["groups"]["cairo_cpu"]["editable_paths"].append(
            {"glob": "vectors/cairo/**", "min_rung": "s3"}
        )
        with self.assertRaisesRegex(ManifestError, "locked"):
            manifest_mod._validate(raw)


class GuardManifestValidationTest(unittest.TestCase):
    def setUp(self):
        self.raw = copy.deepcopy(load_manifest().raw)

    def _refuse(self, pattern):
        return self.assertRaisesRegex(ManifestError, pattern)

    def test_group_without_a_guard_registry_key_is_refused(self):
        del self.raw["workload_registry"]["groups"]["native"]["guard_registry"]
        with self._refuse("declares no guard_registry"):
            manifest_mod._validate(self.raw)

    def test_null_registry_without_a_reason_is_refused(self):
        group = self.raw["workload_registry"]["groups"]["cuda"]
        group["guard_registry_absent_reason"] = "  "
        with self._refuse("guard_registry_absent_reason"):
            manifest_mod._validate(self.raw)

    def test_unknown_registry_reference_is_refused(self):
        self.raw["workload_registry"]["groups"]["native"]["guard_registry"] = "nope"
        with self._refuse("unknown guard registry"):
            manifest_mod._validate(self.raw)

    def test_registry_bound_to_no_group_is_refused(self):
        self.raw["workload_registry"]["guards"]["registries"]["orphan"] = {
            "workloads": {"guard_x": {"args": "--example x"}},
        }
        with self._refuse("bound to no workload group"):
            manifest_mod._validate(self.raw)

    def test_impact_map_naming_a_foreign_guard_is_refused(self):
        registry = self.raw["workload_registry"]["guards"]["registries"]["cairo"]
        registry["impact_map"]["rules"][0]["guards"] = ["guard_blake_10x10"]
        with self._refuse("absent from this registry"):
            manifest_mod._validate(self.raw)

    def test_impact_map_naming_an_unknown_board_is_refused(self):
        registry = self.raw["workload_registry"]["guards"]["registries"]["cairo"]
        registry["impact_map"]["rules"][2]["board"] = "not_a_board"
        with self._refuse("unknown board"):
            manifest_mod._validate(self.raw)

    def test_empty_registry_is_refused(self):
        self.raw["workload_registry"]["guards"]["registries"]["cairo"]["workloads"] = {}
        with self._refuse("non-empty object"):
            manifest_mod._validate(self.raw)

    def test_a_flat_portfolio_beside_registries_is_refused(self):
        self.raw["workload_registry"]["guards"]["workloads"] = {
            "guard_x": {"args": "--example x"},
        }
        with self._refuse("pre-TRACKS-§8 shape"):
            manifest_mod._validate(self.raw)

    def test_duplicate_per_track_glob_is_refused(self):
        group = self.raw["workload_registry"]["groups"]["cairo_cpu"]
        group["editable_paths"].append(dict(group["editable_paths"][0]))
        with self._refuse("twice"):
            manifest_mod._validate(self.raw)


class BoardAutoRoutingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def _route(self, paths):
        args = SimpleNamespace(board=None)
        with mock.patch.object(runner, "changed_paths", return_value=paths):
            return cli._resolve_board(args, self.m)

    def test_cairo_frontend_routes_to_cairo_cpu(self):
        self.assertEqual(self._route(["src/frontends/cairo/vm/mod.zig"]), "cairo_cpu")

    def test_cairo_frontend_with_metal_routes_to_cairo_metal(self):
        self.assertEqual(
            self._route([
                "src/frontends/cairo/vm/mod.zig",
                "src/backends/metal/fft.metal",
            ]),
            "cairo_metal",
        )

    def test_cairo_integrations_route_to_cairo(self):
        self.assertEqual(self._route(["src/integrations/cairo_cpu/a.zig"]), "cairo_cpu")
        self.assertEqual(
            self._route(["src/integrations/cairo_metal/a.zig"]), "cairo_metal",
        )

    def test_riscv_frontend_and_integration_route_to_riscv(self):
        self.assertEqual(self._route(["src/frontends/riscv/decode.zig"]), "riscv")
        self.assertEqual(self._route(["src/integrations/riscv_cpu/a.zig"]), "riscv")

    def test_an_integration_path_names_its_backend_lane(self):
        # src/integrations/cairo_metal/ is the Cairo frontend on Metal, so it
        # must not route to the CPU board just because no kernel was touched.
        self.assertEqual(
            self._route(["src/integrations/cairo_metal/a.zig"]), "cairo_metal",
        )
        # RISC-V on Metal is the same shape and now HAS a board: the wave-2
        # riscv_metal group landed, and routing resolved it by convention the
        # moment it did. It must never fall back to the CPU board.
        self.assertEqual(
            self._route(["src/integrations/riscv_metal/a.zig"]), "riscv_metal",
        )
        # The fail-closed path still has a live case: Cairo on CUDA is a real
        # integration lane with no board, so it refuses rather than guessing.
        with self.assertRaisesRegex(ManifestError, "declares no board"):
            self._route(["src/integrations/cairo_cuda/a.zig"])

    def test_native_defaults_are_unchanged(self):
        self.assertEqual(self._route(["src/prover/fri.zig"]), "core_cpu")
        self.assertEqual(self._route(["src/backends/metal/fft.metal"]), "core_metal")
        self.assertEqual(self._route(["src/backends/cuda/rt.zig"]), "core_cuda")
        self.assertEqual(
            self._route(["src/integrations/native_cuda/wf/mod.zig"]), "core_cuda",
        )

    def test_a_diff_spanning_two_frontends_fails_closed(self):
        with self.assertRaisesRegex(ManifestError, "more than one frontend"):
            self._route([
                "src/frontends/cairo/vm/mod.zig",
                "src/frontends/riscv/decode.zig",
            ])

    def test_a_track_with_no_board_fails_closed(self):
        # Cairo on CUDA has no board in the manifest today. (RISC-V on Metal
        # used to be this case; the wave-2 riscv_metal group gave it a board,
        # and the frontend+backend coordinates now resolve it — see
        # test_riscv_frontend_with_metal_routes_to_riscv_metal.)
        with self.assertRaisesRegex(ManifestError, "declares no board"):
            self._route([
                "src/frontends/cairo/vm/mod.zig",
                "src/backends/cuda/rt.zig",
            ])

    def test_riscv_frontend_with_metal_routes_to_riscv_metal(self):
        self.assertEqual(
            self._route([
                "src/frontends/riscv/decode.zig",
                "src/backends/metal/fft.metal",
            ]),
            "riscv_metal",
        )

    def test_explicit_board_bypasses_routing_entirely(self):
        args = SimpleNamespace(board="cairo_metal")
        with mock.patch.object(runner, "changed_paths") as changed:
            self.assertEqual(cli._resolve_board(args, self.m), "cairo_metal")
            changed.assert_not_called()

    def test_every_manifest_board_is_decomposable_or_deliberately_not(self):
        # pr6_supremacy is an objective board and is deliberately unroutable;
        # every other group's board must decompose into a track.
        for group in self.m.groups():
            track = cli._track_of_board(group.board)
            if group.board == "pr6_supremacy":
                self.assertIsNone(track)
            else:
                self.assertIsNotNone(track, group.board)


class BoardChoicesTest(unittest.TestCase):
    def test_every_ledger_board_is_accepted_by_run_and_setup(self):
        parser = cli.build_parser()
        for board in ledger.BOARDS:
            for argv in (
                ["run", "--board", board, "--predecessor", "/tmp/a"],
                ["setup", "--board", board],
            ):
                args = parser.parse_args(argv)
                self.assertEqual(args.board, board, argv)

    def test_task_accepts_every_ledger_board(self):
        parser = cli.build_parser()
        for board in ledger.BOARDS:
            self.assertEqual(
                parser.parse_args(["task", "--board", board]).board, board,
            )

    def test_board_choices_are_exactly_ledger_boards(self):
        parser = cli.build_parser()
        seen = 0
        for action in parser._subparsers._group_actions[0].choices.values():
            for arg in action._actions:
                if arg.dest == "board" and arg.choices is not None:
                    self.assertEqual(list(arg.choices), list(ledger.BOARDS))
                    seen += 1
        self.assertGreaterEqual(seen, 3)


class MechanismGateTest(unittest.TestCase):
    """G3 gates every schema with a cross-arm mechanism contract."""

    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def _gates(self, board, group_id, verified):
        workload = self.m.group(group_id).workloads[0]
        score = SimpleNamespace(
            workload=workload,
            mechanism_verified=verified,
            request_ratio=None,
            rss_ratio=None,
            b_median_ms=1.0,
            ci=(1.0, 1.0),
        )
        with mock.patch.object(runner, "changed_paths", return_value=[]):
            return runner._gates(
                ROOT, self.m, [score],
                {"targeted_class_budget": 1.02, "matrix_row_budget": 1.02},
                False, None, "small", board,
            )

    def test_cairo_score_without_verified_mechanism_fails_g3(self):
        for board, group_id in (
            ("cairo_cpu", "cairo_cpu"), ("cairo_metal", "cairo_metal"),
        ):
            gates = self._gates(board, group_id, False)
            self.assertFalse(gates["G3"]["pass"], board)
            self.assertIn("Cairo", gates["G3"]["detail"])
            self.assertIn("0/1 workloads", gates["G3"]["detail"])

    def test_cairo_score_with_verified_mechanism_passes_g3(self):
        gates = self._gates("cairo_cpu", "cairo_cpu", True)
        self.assertTrue(gates["G3"]["pass"])
        self.assertIn("1/1 workloads", gates["G3"]["detail"])

    def test_an_unset_mechanism_flag_still_fails_closed(self):
        gates = self._gates("cairo_cpu", "cairo_cpu", None)
        self.assertFalse(gates["G3"]["pass"])

    def test_riscv_gating_is_unchanged(self):
        gates = self._gates("riscv", "riscv", False)
        self.assertFalse(gates["G3"]["pass"])
        self.assertIn("RISC-V", gates["G3"]["detail"])

    def test_native_schemas_carry_no_mechanism_contract(self):
        gates = self._gates("core_cpu", "native", None)
        self.assertTrue(gates["G3"]["pass"])
        self.assertEqual(
            gates["G3"]["detail"], "native mechanism telemetry policy unchanged",
        )

    def test_every_schema_with_stable_fields_is_gated(self):
        # The gate reads the same table paired_rounds computes the flag from,
        # so a new mechanism-bearing schema can never land ungated.
        for schema in runner.STABLE_MECHANISM_FIELDS_BY_SCHEMA:
            groups = [g for g in self.m.groups() if g.report_schema == schema]
            self.assertTrue(groups, schema)
            group = groups[0]
            gates = self._gates(group.board, group.group_id, False)
            self.assertFalse(gates["G3"]["pass"], schema)


class TaskGenerationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()

    def test_generation_is_deterministic(self):
        first = track_task.generate(self.m)
        second = track_task.generate(load_manifest())
        self.assertEqual(first, second)

    def test_committed_briefs_match_the_manifest_and_epochs(self):
        self.assertEqual(track_task.stale(self.m), [])

    def test_one_brief_per_board_that_owns_a_group(self):
        owned = {group.board for group in self.m.groups()}
        self.assertEqual(set(track_task.track_boards(self.m)), owned)
        for board in track_task.track_boards(self.m):
            self.assertTrue((ROOT / track_task.brief_path(board)).is_file())

    def test_root_task_md_is_an_index_over_the_briefs(self):
        index = (ROOT / track_task.INDEX_PATH).read_text(encoding="utf-8")
        for board in track_task.track_boards(self.m):
            self.assertIn(f"tasks/TASK.{board}.md", index)

    def test_a_brief_names_only_its_own_tracks_guards(self):
        brief = track_task.render_brief(self.m, "cairo_cpu")
        self.assertIn("guard_cairo_all_opcodes", brief)
        self.assertNotIn("guard_blake_10x10", brief)
        native = track_task.render_brief(self.m, "core_cpu")
        self.assertIn("guard_blake_10x10", native)
        self.assertNotIn("guard_cairo_all_opcodes", native)

    def test_a_brief_names_only_its_own_tracks_frontend_paths(self):
        cairo = track_task.render_brief(self.m, "cairo_cpu")
        self.assertIn("src/frontends/cairo/**", cairo)
        self.assertNotIn("src/frontends/riscv/**", cairo)

    def test_an_unguarded_track_states_its_reason(self):
        brief = track_task.render_brief(self.m, "core_cuda")
        self.assertIn("no guard registry", brief)
        self.assertIn(
            self.m.group("cuda").guard_registry_absent_reason.split(":")[1].strip()[:40],
            brief,
        )

    def test_a_blocked_track_says_it_cannot_promote(self):
        self.assertIn(
            "cannot promote today", track_task.render_brief(self.m, "cairo_cpu"),
        )

    def test_briefs_carry_no_wall_clock_state(self):
        for text in track_task.generate(self.m).values():
            self.assertNotIn("Generated at", text)

    def _run_task(self, argv):
        args = cli.build_parser().parse_args(argv)
        out = io.StringIO()
        with mock.patch.object(cli.manifest_mod, "load", return_value=self.m):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                return cli.cmd_task(args), out.getvalue()

    def test_cli_prints_the_brief_it_generates(self):
        code, printed = self._run_task(["task", "--board", "riscv"])
        self.assertEqual(code, 0)
        self.assertEqual(printed, track_task.render_brief(self.m, "riscv"))

    def test_cli_prints_the_index_without_a_board(self):
        code, printed = self._run_task(["task"])
        self.assertEqual(code, 0)
        self.assertEqual(printed, track_task.render_index(self.m))

    def test_cli_check_passes_against_the_committed_briefs(self):
        code, _ = self._run_task(["task", "--check"])
        self.assertEqual(code, 0)

    def test_cli_refuses_a_board_with_no_track(self):
        code, printed = self._run_task(["task", "--board", "stream"])
        self.assertEqual(code, 1)
        self.assertIn("owns no workload group", printed)


class FeedExportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = load_manifest()
        cls.boards = feed.build_feed(cls.m, allow_dirty=True)["boards"]

    def test_schema_version_is_unchanged(self):
        self.assertEqual(feed.FEED_SCHEMA_VERSION, 4)

    def test_every_board_carries_both_new_keys(self):
        for board in ledger.BOARDS:
            self.assertIn("supremacy", self.boards[board])
            self.assertIn("task", self.boards[board])

    def test_supremacy_is_published_only_for_objective_boards(self):
        for board in ledger.BOARDS:
            supremacy = self.boards[board]["supremacy"]
            if board == "pr6_supremacy":
                self.assertIsNotNone(supremacy)
            else:
                self.assertIsNone(supremacy, board)

    def test_supremacy_pins_are_copied_from_the_manifest(self):
        supremacy = self.boards["pr6_supremacy"]["supremacy"]
        self.assertEqual(
            sorted(supremacy),
            ["activated_utc", "activation_state_path", "board", "peer_commit",
             "peer_repository", "reason", "state", "toolchain"],
        )
        oracle = self.m.group("pr6_supremacy").correctness_oracle
        self.assertEqual(supremacy["state"], "not_achieved")
        self.assertEqual(supremacy["board"], "pr6_supremacy")
        self.assertEqual(
            supremacy["peer_repository"], oracle["performance_peer_repository"],
        )
        self.assertEqual(supremacy["peer_commit"], oracle["performance_peer_commit"])
        self.assertEqual(supremacy["toolchain"], oracle["rust_toolchain"])
        self.assertIsNone(supremacy["activated_utc"])

    def test_a_peer_pin_never_travels_without_its_toolchain_field(self):
        for board in ledger.BOARDS:
            supremacy = self.boards[board]["supremacy"]
            if supremacy is None:
                continue
            if supremacy["peer_commit"] is not None:
                self.assertIn("toolchain", supremacy)

    def test_task_export_shape(self):
        task = self.boards["cairo_cpu"]["task"]
        self.assertEqual(
            sorted(task),
            ["editable_paths", "markdown", "objective", "path", "title"],
        )
        self.assertEqual(task["path"], "autoresearch/tasks/TASK.cairo_cpu.md")
        self.assertEqual(task["title"], "TASK — the `cairo_cpu` track")
        self.assertEqual(
            task["editable_paths"], self.m.editable_for_board("cairo_cpu"),
        )

    def test_task_markdown_is_the_committed_brief_verbatim(self):
        for board in track_task.track_boards(self.m):
            committed = (ROOT / track_task.brief_path(board)).read_text(
                encoding="utf-8"
            )
            self.assertEqual(self.boards[board]["task"]["markdown"], committed)

    def test_boards_without_a_group_publish_a_null_task(self):
        for board in ledger.BOARDS:
            if board in track_task.track_boards(self.m):
                continue
            self.assertIsNone(self.boards[board]["task"], board)

    def test_the_feed_stays_json_serialisable(self):
        json.dumps(self.boards)


if __name__ == "__main__":
    unittest.main()
