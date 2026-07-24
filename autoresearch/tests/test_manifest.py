import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import manifest as manifest_mod

REPO_ROOT = Path(__file__).resolve().parents[2]


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.m = manifest_mod.load(REPO_ROOT)

    def test_locked_paths(self):
        self.assertTrue(self.m.is_locked("autoresearch/ledger/promotions.tsv"))
        self.assertTrue(self.m.is_locked("scripts/ci.py"))
        self.assertTrue(self.m.is_locked("build.zig"))
        self.assertFalse(self.m.is_locked("src/prover/fri.zig"))

    def test_editable_rungs(self):
        self.assertEqual(self.m.path_rung("src/backends/cpu_scalar/mod.zig"), "s3")
        self.assertEqual(self.m.path_rung("src/backends/cuda/runtime.zig"), "s3")
        self.assertEqual(
            self.m.path_rung("src/backend/proof_program.zig"), "s4",
        )
        self.assertEqual(self.m.path_rung("src/prover/work_pool.zig"), "s4")
        self.assertIsNone(self.m.path_rung("README.md"))

    def test_judged_rung_is_mechanical_max(self):
        rung = self.m.judged_rung("s3", ["src/prover/work_pool.zig"])
        self.assertEqual(rung, "s4")
        rung = self.m.judged_rung("s1", ["src/core/fields/m31.zig"])
        self.assertEqual(rung, "s3")  # acceptance floor

    def test_classify_touched(self):
        violations, strays = self.m.classify_touched(
            ["vectors/reports/x.json", "src/prover/fri.zig", "docs/random.md"]
        )
        self.assertEqual(violations, ["vectors/reports/x.json"])
        self.assertEqual(strays, ["docs/random.md"])

    def test_workload_registry(self):
        small = self.m.workloads("small", board="core_cpu")
        self.assertTrue(small)
        self.assertTrue(all(w.workload_class == "small" for w in small))

    def test_manifest_owns_scored_class_order_and_board_exposure(self):
        self.assertEqual(
            self.m.class_names(scored_only=True),
            ["small", "wide", "deep", "xlarge", "huge"],
        )
        self.assertEqual(
            self.m.class_names(
                board="core_cpu", scored_only=True, include_disabled=True,
            ),
            ["small", "wide", "deep", "xlarge", "huge"],
        )
        self.assertEqual(
            self.m.class_names(
                board="core_metal", scored_only=True, include_disabled=True,
            ),
            ["small", "wide", "deep", "xlarge", "huge"],
        )
        self.assertEqual(
            self.m.class_names(
                board="riscv", scored_only=True, include_disabled=True,
            ),
            ["small", "wide", "deep"],
        )
        with self.assertRaisesRegex(manifest_mod.ManifestError, "does not expose"):
            self.m.workloads("huge", board="riscv", include_disabled=True)
        with self.assertRaisesRegex(manifest_mod.ManifestError, "unknown workload class"):
            self.m.workloads("invented", board="core_cpu")
        self.m.validate_workload_class("small", board="riscv")
        self.m.validate_workload_class(
            "small", board="riscv", include_disabled=True,
        )

    def test_large_classes_have_bounded_sampling_and_explicit_resource_args(self):
        xlarge = self.m.workload_class("xlarge")
        huge = self.m.workload_class("huge")
        self.assertEqual((xlarge.resource_profile, huge.resource_profile), ("large", "large"))
        self.assertLessEqual(huge.sampling["max_rounds"], 5)
        self.assertLessEqual(
            2 * huge.sampling["max_rounds"]
            * (huge.sampling["warmups"] + huge.sampling["samples_per_round"]),
            20,
        )
        for board in ("core_cpu", "core_metal"):
            for workload_class in ("xlarge", "huge"):
                workloads = self.m.workloads(workload_class, board=board)
                self.assertEqual(len(workloads), 1)
                self.assertIn("--resource-profile large", workloads[0].args)

    def test_pr6_supremacy_board_is_complete_and_fail_closed(self):
        group = self.m.group_for_board("pr6_supremacy")
        self.assertFalse(group.enabled)
        self.assertFalse(group.promotion_eligible)
        self.assertTrue(group.disabled_reason)
        self.assertEqual(group.report_schema, "pr6_supremacy_v1")
        expected = {
            *(f"pr6_wide_fibonacci_log{log_size}" for log_size in (14, 16, 18, 20, 22)),
            *(f"pr6_blake_log{log_size}" for log_size in (10, 12, 14, 16)),
            *(f"pr6_plonk_log{log_size}" for log_size in (12, 14, 16)),
            *(f"pr6_fixed_wide_fibonacci_log{log_size}" for log_size in range(4, 9)),
            "pr6_state_machine_log8",
        }
        self.assertEqual({workload.workload_id for workload in group.workloads}, expected)
        self.assertEqual(len(group.workloads), 18)
        self.assertEqual(self.m.workloads(board="pr6_supremacy"), [])
        self.assertEqual(
            len(self.m.workloads(board="pr6_supremacy", include_disabled=True)), 18,
        )
        log22 = next(
            workload for workload in group.workloads
            if workload.workload_id == "pr6_wide_fibonacci_log22"
        )
        self.assertEqual(log22.workload_class, "extreme")
        self.assertIn("--width 100", log22.args)
        self.assertIn("--resource-profile extreme", log22.args)
        raw = self.m.raw["workload_registry"]["groups"]["pr6_supremacy"]
        self.assertEqual(
            raw["correctness_oracle"]["performance_peer_commit"],
            "07ea1ccca13351028da94e66babf79e7ce91437f",
        )
        self.assertEqual(
            raw["correctness_oracle"]["rust_toolchain"], "nightly-2025-07-14",
        )
        self.assertEqual(group.mechanism_telemetry, manifest_mod.PR6_MECHANISM_TELEMETRY)
        self.assertEqual(group.resource_telemetry, manifest_mod.PR6_RESOURCE_TELEMETRY)

    def test_cuda_board_is_staged_and_fail_closed(self):
        group = self.m.group_for_board("core_cuda")
        self.assertFalse(group.enabled)
        self.assertFalse(group.promotion_eligible)
        self.assertIn("six Native AIR", group.disabled_reason)
        self.assertEqual(group.report_schema, "native_cuda_product_v4")
        self.assertEqual(group.correctness_oracle["authority"], "pinned-rust-stwo")
        self.assertTrue(group.correctness_oracle["final_validator"])
        self.assertEqual(self.m.workloads(board="core_cuda"), [])
        staged = self.m.workloads(board="core_cuda", include_disabled=True)
        self.assertEqual(len(staged), 8)
        self.assertIn(
            "cuda_wf_log22x100",
            {workload.workload_id for workload in staged},
        )
        self.assertIn(
            "--resource-profile extreme",
            next(
                workload.args
                for workload in staged
                if workload.workload_id == "cuda_wf_log22x100"
            ),
        )

    def test_extreme_profile_does_not_change_live_scored_classes(self):
        extreme = self.m.workload_class("extreme")
        self.assertFalse(extreme.scored)
        self.assertEqual(extreme.resource_profile, "extreme")
        self.assertEqual(
            self.m.class_names(scored_only=True),
            ["small", "wide", "deep", "xlarge", "huge"],
        )

    def test_native_and_riscv_groups_are_enabled(self):
        by_id = {g.group_id: g for g in self.m.groups()}
        self.assertIn("native", by_id)
        self.assertIn("riscv", by_id)
        native, riscv = by_id["native"], by_id["riscv"]
        self.assertTrue(native.enabled)
        self.assertTrue(native.promotion_eligible)
        self.assertEqual(native.board, "core_cpu")
        self.assertEqual(native.binary, "zig-out/bin/native-proof-bench-cpu")
        self.assertEqual(native.report_schema, "native_proof_v7")
        self.assertEqual(len(native.workloads), 5)
        self.assertTrue(riscv.enabled)
        self.assertTrue(riscv.promotion_eligible)
        self.assertEqual(riscv.board, "riscv")
        self.assertIsNone(riscv.disabled_reason)
        self.assertEqual(riscv.binary, "zig-out/bin/stwo-zig")
        self.assertEqual(riscv.build_step, "zig build stwo-zig -Doptimize=ReleaseFast")
        self.assertEqual(riscv.report_schema, "riscv_proof_v2")
        self.assertEqual(
            riscv.resource_telemetry, manifest_mod.RISCV_RESOURCE_TELEMETRY,
        )
        self.assertEqual(len(riscv.workloads), 20)
        self.assertEqual(
            {name: sum(w.workload_class == name for w in riscv.workloads)
             for name in ("small", "wide", "deep")},
            {"small": 6, "wide": 7, "deep": 7},
        )
        self.assertIn("riscv_branch_fib", {w.workload_id for w in riscv.workloads})
        self.assertIn("riscv_keccak_128b", {w.workload_id for w in riscv.workloads})
        self.assertIn("riscv_sha2_2048b", {w.workload_id for w in riscv.workloads})
        self.assertTrue(all(w.args.startswith("bench --elf ") for w in riscv.workloads))
        self.assertTrue(all("--backend cpu" in w.args for w in riscv.workloads))
        self.assertTrue(all("{admission}" in w.args for w in riscv.workloads))

    def test_disabled_group_workloads_excluded_by_default(self):
        default_ids = {w.workload_id for w in self.m.workloads(board="core_cpu")}
        self.assertNotIn("riscv_branch_fib", default_ids)
        self.assertNotIn("riscv_alu_test", default_ids)
        all_ids = {
            w.workload_id
            for w in self.m.workloads(include_disabled=True, board="riscv")
        }
        self.assertIn("riscv_branch_fib", all_ids)
        self.assertIn("riscv_alu_test", all_ids)
        # every default workload comes from an enabled group
        enabled = {g.group_id for g in self.m.groups() if g.enabled}
        self.assertTrue(all(
            w.group_id in enabled for w in self.m.workloads(board="core_cpu")
        ))

    def test_workload_selection_requires_board(self):
        with self.assertRaises(manifest_mod.ManifestError):
            self.m.workloads("small")

    def test_unknown_group_raises(self):
        with self.assertRaises(manifest_mod.ManifestError):
            self.m.group("does-not-exist")

    def test_board_selection_never_pools_groups(self):
        self.assertEqual(
            {w.group_id for w in self.m.workloads("small", board="core_cpu")},
            {"native"},
        )
        self.assertEqual(
            {w.group_id for w in self.m.workloads("small", board="riscv")},
            {"riscv"},
        )


class RegistryValidationTest(unittest.TestCase):
    def _base_raw(self) -> dict:
        return {
            "manifest_version": 2,
            "harness": {"anchor_commit": None},
            "editable_paths": [],
            "locked_paths": [],
            "gates_policy": {
                "max_rounds": 15,
                "search_health": {
                    "trailing_window": 8,
                    "gradient_snr_threshold": 2.0,
                    "auto_boost_rounds": 5,
                    "maximum_rounds": 25,
                },
            },
            "qualification_policy": {
                "required_checks": ["allowed_diff"],
                "max_active_per_user": 1,
            },
            "workload_registry": {
                "classes": {
                    "small": {
                        "scored": True,
                        "resource": {
                            "profile": "standard",
                            "command_timeout_seconds": 60,
                            "wall_clock_cap_seconds": 60,
                        },
                        "sampling": {
                            "warmups": 1,
                            "samples_per_round": 1,
                            "min_rounds": 1,
                            "max_rounds": 1,
                        },
                    },
                },
                "groups": {
                    "native": {
                        "enabled": True,
                        "promotion_eligible": True,
                        "board": "core_cpu",
                        "build_step": "true",
                        "binary": "bin/bench",
                        "report_schema": "native_proof_v7",
                        "workloads": {
                            "wf": {"class": "small", "args": "--x", "native_unit": "rows"},
                        },
                    },
                },
            },
        }

    def test_grouped_registry_validates(self):
        manifest_mod._validate(self._base_raw())  # must not raise

    def test_flat_v1_registry_rejected_with_migration_hint(self):
        raw = self._base_raw()
        raw["workload_registry"] = {
            "build_step": "true", "binary": "bin/bench", "workloads": {},
        }
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("groups", str(ctx.exception))

    def test_disabled_group_without_reason_rejected(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["riscv"] = {
            "enabled": False,
            "promotion_eligible": False,
            "board": "riscv",
            "build_step": "true",
            "binary": "bin/riscv",
            "report_schema": "riscv_proof_v2",
            "resource_telemetry": manifest_mod.RISCV_RESOURCE_TELEMETRY,
            "workloads": {},
        }
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("disabled_reason", str(ctx.exception))

    def test_group_missing_required_key_rejected(self):
        raw = self._base_raw()
        del raw["workload_registry"]["groups"]["native"]["report_schema"]
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("report_schema", str(ctx.exception))

    def test_invalid_workload_class_rejected(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["native"]["workloads"]["wf"]["class"] = "invented"
        with self.assertRaises(manifest_mod.ManifestError):
            manifest_mod._validate(raw)

    def test_unknown_report_schema_rejected(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["native"]["report_schema"] = "made_up_v99"
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("unsupported report_schema", str(ctx.exception))

    def test_nonstandard_resource_class_requires_matching_explicit_arg(self):
        raw = self._base_raw()
        raw["workload_registry"]["classes"]["extreme"] = {
            "scored": False,
            "resource": {
                "profile": "extreme",
                "command_timeout_seconds": 60,
                "wall_clock_cap_seconds": 60,
            },
            "sampling": {
                "warmups": 1,
                "samples_per_round": 1,
                "min_rounds": 1,
                "max_rounds": 1,
            },
        }
        workload = raw["workload_registry"]["groups"]["native"]["workloads"]["wf"]
        workload["class"] = "extreme"
        with self.assertRaisesRegex(manifest_mod.ManifestError, "resource-profile extreme"):
            manifest_mod._validate(raw)
        workload["args"] += " --resource-profile extreme"
        manifest_mod._validate(raw)

    def test_legacy_riscv_report_schema_is_rejected(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["native"]["report_schema"] = \
            "riscv_proof_v1"
        with self.assertRaisesRegex(manifest_mod.ManifestError, "unsupported report_schema"):
            manifest_mod._validate(raw)

    def test_riscv_v2_requires_exact_resource_policy(self):
        raw = self._base_raw()
        group = raw["workload_registry"]["groups"]["native"]
        group["report_schema"] = "riscv_proof_v2"
        group["mechanism_telemetry"] = {
            "fail_closed": True,
            "required_fields": sorted(manifest_mod.RISCV_MECHANISM_FIELDS),
        }
        group["resource_telemetry"] = {
            **manifest_mod.RISCV_RESOURCE_TELEMETRY,
            "source": "getrusage",
        }
        with self.assertRaisesRegex(manifest_mod.ManifestError, "resource_telemetry"):
            manifest_mod._validate(raw)

    def test_duplicate_board_ownership_rejected(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["other"] = {
            "enabled": True,
            "promotion_eligible": True,
            "board": "core_cpu",
            "build_step": "true",
            "binary": "bin/other",
            "report_schema": "native_proof_v7",
            "workloads": {},
        }
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("cross-group workload pooling", str(ctx.exception))

    def test_promotion_eligibility_is_typed_and_disabled_groups_fail_closed(self):
        for enabled, eligible in ((True, "true"), (False, True)):
            with self.subTest(enabled=enabled, eligible=eligible):
                raw = self._base_raw()
                group = raw["workload_registry"]["groups"]["native"]
                group["enabled"] = enabled
                group["promotion_eligible"] = eligible
                if not enabled:
                    group["disabled_reason"] = "staged"
                with self.assertRaises(manifest_mod.ManifestError):
                    manifest_mod._validate(raw)

    def test_group_gates_policy_merges_bounded_measurement_overrides(self):
        raw = self._base_raw()
        raw["gates_policy"] = {
            "warmups": 10,
            "samples_per_round": 3,
            "min_rounds": 7,
            "max_rounds": 15,
            "theta_floor": 0.01,
            "search_health": {
                "trailing_window": 8,
                "gradient_snr_threshold": 2.0,
                "auto_boost_rounds": 5,
                "maximum_rounds": 25,
            },
            "wall_clock_cap_seconds": {"small": 240, "wide": 600, "deep": 600},
        }
        raw["workload_registry"]["groups"]["native"]["gates_policy"] = {
            "warmups": 1,
            "samples_per_round": 1,
            "min_rounds": 3,
            "max_rounds": 5,
            "wall_clock_cap_seconds": {"small": 120},
        }
        manifest_mod._validate(raw)
        manifest = manifest_mod.Manifest(REPO_ROOT, raw)
        policy = manifest.gates_for_workload("native", "small")
        self.assertEqual(
            (policy["warmups"], policy["samples_per_round"],
             policy["min_rounds"], policy["max_rounds"]),
            (1, 1, 3, 5),
        )
        self.assertEqual(policy["wall_clock_cap_seconds"], {"small": 120})
        self.assertEqual(policy["theta_floor"], 0.01)

    def test_group_gates_policy_rejects_unknown_or_unbounded_values(self):
        cases = [
            {"theta_floor": 0.5},
            {"samples_per_round": 0},
            {"warmups": -1},
            {"max_rounds": 51},
            {"wall_clock_cap_seconds": {"wide": 7201}},
            {"wall_clock_cap_seconds": {"unknown": 10}},
        ]
        for override in cases:
            with self.subTest(override=override):
                raw = self._base_raw()
                raw["workload_registry"]["groups"]["native"]["gates_policy"] = override
                with self.assertRaises(manifest_mod.ManifestError):
                    manifest_mod._validate(raw)

    def test_group_gates_policy_rejects_inverted_round_bounds(self):
        raw = self._base_raw()
        raw["workload_registry"]["groups"]["native"]["gates_policy"] = {
            "min_rounds": 5,
            "max_rounds": 3,
        }
        with self.assertRaisesRegex(manifest_mod.ManifestError, "min_rounds"):
            manifest_mod._validate(raw)

    def test_search_health_policy_is_manifest_owned_and_bounded(self):
        raw = self._base_raw()
        manifest_mod._validate(raw)
        self.assertEqual(
            manifest_mod.Manifest(REPO_ROOT, raw).search_health_policy[
                "gradient_snr_threshold"
            ],
            2.0,
        )
        for override in (
            {"maximum_rounds": 14},
            {"auto_boost_rounds": 0},
            {"trailing_window": 0},
            {"gradient_snr_threshold": float("inf")},
        ):
            with self.subTest(override=override):
                invalid = self._base_raw()
                invalid["gates_policy"]["search_health"].update(override)
                with self.assertRaises(manifest_mod.ManifestError):
                    manifest_mod._validate(invalid)

    def test_seeded_holdout_pool_rejects_unknown_or_wrong_class_ids(self):
        raw = self._base_raw()
        native = raw["workload_registry"]["groups"]["native"]
        native["workloads"]["other"] = {
            "class": "wide", "args": "--other", "native_unit": "rows",
        }
        for pools in ({"small": ["missing"]}, {"small": ["other"]}):
            with self.subTest(pools=pools):
                native["holdout_generator"] = {
                    "strategy": "seeded_workload_pool_v1", "pools": pools,
                }
                with self.assertRaises(manifest_mod.ManifestError):
                    manifest_mod._validate(raw)


if __name__ == "__main__":
    unittest.main()
