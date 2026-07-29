"""Confirmation ladder: sequential stopping, fast boundary, proxies, T0.

Contract: TRACKS §3.5 (ladder tiers and devices) and §3.6 (acceptance).
"""

import hashlib
import json
import math
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from stwo_perf import manifest as manifest_mod, runner
from stwo_perf.manifest import Manifest, ManifestError

# W1's committed Cairo fixtures: the ladder reads the same evidence the
# cairo_proof_v1 parser produces, so T0 is tested against a real envelope.
from test_cairo_boards import (  # noqa: E402
    FAKE_PRODUCT,
    load_profile,
    load_report,
    raw_manifest as cairo_raw_manifest,
)

LADDER = {
    "schema": manifest_mod.CONFIRMATION_LADDER_SCHEMA,
    "sequential_stop": {
        "enabled": False,
        "rule": manifest_mod.SEQUENTIAL_STOP_RULE,
        "alpha": 0.05,
        "stop_on_decisive_miss": True,
    },
    "tiers": {
        "T0": {
            "cost_target_seconds": 30,
            # One warmup is the floor: the Cairo arm records its mandatory
            # phase profile on a discarded warmup.
            "warmups": 1,
            "samples": 1,
            "min_phase_move": 0.02,
            "note": "smoke plus one stage-profiled sample",
        },
        "T1": {"cost_target_seconds": 300, "note": "iterate"},
        "T2": {"cost_target_seconds": 2700, "note": "claimed"},
        "T3": {"cost_target_seconds": None, "note": "judge-scheduled"},
    },
    "proxy_validity": {
        "receipt_schema": manifest_mod.PROXY_VALIDITY_RECEIPT_SCHEMA,
        "receipt_dir": "autoresearch/reference/proxy_validity",
        "min_correlation": 0.8,
        "min_observations": 5,
    },
    "cost_telemetry": {"statistic": "median", "window": 5},
    "note": "test ladder",
}

PROXY_FIXTURE = {
    "proxy_id": "small_proxy",
    "args": "--warmups {warmups} --samples {samples} --log-n-rows 12",
    "native_unit": "trace rows",
    "official_params": True,
    "target_workload_ids": ["wf_small"],
    "note": "scaled geometry at official parameters",
}


def legacy_policy(**overrides) -> dict:
    """A resolved gate policy from a manifest that predates the ladder."""
    policy = {
        "ci_level": 0.95,
        "theta_floor": 0.01,
        "dispersion_multiplier": 2.0,
        "targeted_class_budget": 1.02,
        "matrix_row_budget": 1.05,
        "warmups": 0,
        "samples_per_round": 1,
        "min_rounds": 3,
        "max_rounds": 9,
        "command_timeout_seconds": 60,
        "wall_clock_cap_seconds": {"small": 600},
    }
    policy.update(overrides)
    return policy


def base_policy(**overrides) -> dict:
    """A resolved gate policy carrying the registered (but idle) ladder."""
    policy = legacy_policy(confirmation_ladder=LADDER)
    policy.update(overrides)
    return policy


def make_raw(*, ladder: dict | None = None, proxy: dict | None = None) -> dict:
    small = {
        "scored": True,
        "resource": {
            "profile": "standard",
            "command_timeout_seconds": 60,
            "wall_clock_cap_seconds": 600,
        },
        "sampling": {
            "warmups": 1,
            "samples_per_round": 1,
            "min_rounds": 3,
            "max_rounds": 9,
        },
    }
    if proxy is not None:
        small["proxy_fixture"] = proxy
    gates = {
        "ci_level": 0.95,
        "theta_floor": 0.01,
        "dispersion_multiplier": 2.0,
        "targeted_class_budget": 1.02,
        "matrix_row_budget": 1.05,
        "search_health": {
            "trailing_window": 4,
            "gradient_snr_threshold": 2.0,
            "auto_boost_rounds": 2,
            "maximum_rounds": 9,
        },
    }
    if ladder is not None:
        gates["confirmation_ladder"] = ladder
    return {
        "manifest_version": 2,
        "harness": {"anchor_commit": None},
        "editable_paths": [],
        "locked_paths": [],
        "gates_policy": gates,
        "qualification_policy": {
            "required_checks": ["allowed_diff"],
            "max_active_per_user": 1,
        },
        "workload_registry": {
            "classes": {"small": small},
            "groups": {
                "native": {
                    "enabled": True,
                    "promotion_eligible": True,
                    "board": "core_cpu",
                    "build_step": "true",
                    "binary": "bin/fakebench",
                    "report_schema": "native_proof_v7",
                    "workloads": {
                        "wf_small": {
                            "class": "small",
                            "args": "--warmups {warmups} --samples {samples}",
                            "native_unit": "trace rows",
                        },
                    },
                },
            },
        },
    }


class LadderTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out_dir = self.root / "runs"

    def manifest(self, **kwargs) -> Manifest:
        raw = make_raw(**kwargs)
        manifest_mod._validate(raw)
        return Manifest(root=self.root, raw=raw)

    def workload(self, group_id: str = "native"):
        return manifest_mod.Workload(
            "wf_small", "small", "--warmups {warmups} --samples {samples}",
            "trace rows", group_id,
        )

    def fake_bench(self, ratio_for_round, *, pow_ms=None, request_scale=1.0,
                   phases=None):
        """Deterministic stand-in for one paired bench invocation."""
        calls: list[str] = []

        def bench(arm_root, manifest, workload, warmups, samples, out_dir, tag,
                  **_kwargs):
            calls.append(tag)
            out_dir.mkdir(parents=True, exist_ok=True)
            path = out_dir / f"{workload.workload_id}.{tag}.json"
            # Paired rounds tag as "<arm><round>"; T0 tags as "t0<arm>".
            if tag.startswith("t0"):
                arm, round_no = tag[-1], 1
            else:
                arm, round_no = tag[0], int(tag[1:])
            ratio = 1.0 if arm == "a" else ratio_for_round(round_no)
            prove_ms = 100.0 * ratio
            document = {"tag": tag, "prove_ms": prove_ms}
            if phases is not None:
                document.update(phases(arm))
            path.write_text(json.dumps(document))
            return runner.ArmResult(
                prove_ms=prove_ms,
                proof_verified=samples,
                byte_identical=True,
                peak_rss_mib=None,
                report_path=str(path),
                proof_digest="d" * 64,
                proof_bytes=1024,
                request_ms=prove_ms * request_scale,
                pow_ms=pow_ms,
            )

        return bench, calls

    def run_rounds(self, bench, policy, **kwargs):
        manifest = kwargs.pop("manifest", None) or self.manifest(ladder=LADDER)
        with mock.patch.object(runner, "bench_once", bench):
            return runner.paired_rounds(
                self.root, self.root, manifest, self.workload(), policy,
                self.out_dir, **kwargs,
            )


class SequentialStopTest(LadderTestCase):
    """Pre-registered group-sequential spending (TRACKS §3.5)."""

    NOISY_WIN = staticmethod(lambda round_no: 0.50 if round_no % 2 else 0.62)
    BORDERLINE = staticmethod(lambda round_no: 0.97 if round_no % 2 else 1.01)
    NOISY_LOSS = staticmethod(lambda round_no: 1.05 if round_no % 2 else 1.20)

    def test_absent_config_is_exactly_todays_behavior(self):
        """No ladder block, no ladder behavior: the back-compat contract."""
        bench, _ = self.fake_bench(self.NOISY_WIN)
        legacy = self.run_rounds(
            bench, legacy_policy(), manifest=self.manifest(),
        )
        bench2, _ = self.fake_bench(self.NOISY_WIN)
        registered_but_off = self.run_rounds(bench2, base_policy())
        self.assertIsNone(legacy.sequential_stop)
        self.assertIsNone(registered_but_off.sequential_stop)
        self.assertEqual(runner.FULL_BOUNDARY, legacy.boundary)
        self.assertEqual(len(legacy.ratios), len(registered_but_off.ratios))
        self.assertEqual(legacy.r, registered_but_off.r)
        self.assertEqual(legacy.ci, registered_but_off.ci)
        # A large-but-noisy effect burns the whole round budget without the rule.
        self.assertEqual(9, len(legacy.ratios))

    def test_decisive_clear_stops_at_the_minimum_round_floor(self):
        bench, calls = self.fake_bench(self.NOISY_WIN)
        score = self.run_rounds(
            bench, base_policy(), sequential_stop=True,
        )
        self.assertEqual(3, len(score.ratios))
        self.assertEqual(6, len(calls))  # two arms per round, min_rounds honored
        evidence = score.sequential_stop
        self.assertEqual("decisive_clear", evidence["decision"])
        self.assertEqual(manifest_mod.SEQUENTIAL_STOP_RULE, evidence["rule"])
        self.assertEqual(7, evidence["planned_looks"])  # max 9 - min 3 + 1
        self.assertEqual(1, evidence["look"])
        self.assertAlmostEqual(1.0 - 0.05 / 7.0, evidence["adjusted_ci_level"])
        # The stricter boundary implies the nominal gate: upper < 1 - theta.
        self.assertLess(evidence["adjusted_ci"][1], evidence["theta_bar"])
        self.assertLess(score.ci[1], evidence["theta_bar"])

    def test_borderline_effect_pays_full_power(self):
        bench, _ = self.fake_bench(self.BORDERLINE)
        score = self.run_rounds(bench, base_policy(), sequential_stop=True)
        self.assertEqual(9, len(score.ratios))
        self.assertEqual("budget_exhausted", score.sequential_stop["decision"])

    def test_decisive_miss_stops_early_only_when_registered(self):
        bench, _ = self.fake_bench(self.NOISY_LOSS)
        stopped = self.run_rounds(bench, base_policy(), sequential_stop=True)
        self.assertEqual("decisive_miss", stopped.sequential_stop["decision"])
        self.assertLess(len(stopped.ratios), 9)

        ladder = json.loads(json.dumps(LADDER))
        ladder["sequential_stop"]["stop_on_decisive_miss"] = False
        bench2, _ = self.fake_bench(self.NOISY_LOSS)
        full = self.run_rounds(
            bench2, base_policy(confirmation_ladder=ladder),
            sequential_stop=True,
            manifest=self.manifest(ladder=ladder),
        )
        self.assertEqual(9, len(full.ratios))
        self.assertEqual("budget_exhausted", full.sequential_stop["decision"])

    def test_manifest_enabled_flag_arms_scored_runs(self):
        ladder = json.loads(json.dumps(LADDER))
        ladder["sequential_stop"]["enabled"] = True
        bench, _ = self.fake_bench(self.NOISY_WIN)
        score = self.run_rounds(
            bench, base_policy(confirmation_ladder=ladder),
            manifest=self.manifest(ladder=ladder),
        )
        self.assertEqual(3, len(score.ratios))
        self.assertEqual("decisive_clear", score.sequential_stop["decision"])

    def test_arming_without_registration_fails_closed(self):
        bench, _ = self.fake_bench(self.NOISY_WIN)
        with self.assertRaises(runner.RunError) as caught:
            self.run_rounds(
                bench, legacy_policy(), sequential_stop=True,
                manifest=self.manifest(),
            )
        self.assertIn("pre-registered", str(caught.exception))

    def test_unknown_rule_is_refused(self):
        policy = legacy_policy(confirmation_ladder={
            "sequential_stop": {"enabled": True, "rule": "made_up_v9", "alpha": 0.05},
        })
        with self.assertRaises(runner.RunError):
            runner.sequential_stop_policy(policy)

    def test_adjusted_level_is_stricter_than_the_nominal_gate(self):
        policy = runner.SequentialStopPolicy(
            manifest_mod.SEQUENTIAL_STOP_RULE, 0.05, True,
        )
        self.assertGreater(policy.adjusted_level(7), 0.95)
        self.assertLess(policy.adjusted_level(7), 1.0)


class FastBoundaryTest(LadderTestCase):
    """PoW-excluded boundary: T0/T1 only, fail-closed everywhere else."""

    def test_ranked_evaluation_refuses_the_flag(self):
        with self.assertRaises(runner.RunError) as caught:
            runner.evaluate(
                self.root, self.root, self.manifest(ladder=LADDER), "small",
                "time", "s3", False, self.out_dir, board="core_cpu",
                fast_boundary=True,
            )
        message = str(caught.exception)
        self.assertIn("full dual boundary", message)
        self.assertIn("never excludes anything", message)

    def test_judged_evaluation_refuses_the_flag(self):
        with self.assertRaises(runner.RunError):
            runner.evaluate(
                self.root, self.root, self.manifest(ladder=LADDER), "small",
                "time", "s3", True, self.out_dir, board="core_cpu",
                fast_boundary=True,
            )

    def test_cli_run_refuses_the_flag(self):
        from stwo_perf.__main__ import main
        self.assertEqual(1, main(["run", "--fast-boundary", "--predecessor", "/tmp/x"]))

    def test_group_without_a_measured_pow_phase_fails_closed(self):
        bench, calls = self.fake_bench(lambda _round: 0.9)
        with self.assertRaises(runner.RunError) as caught:
            self.run_rounds(bench, base_policy(), fast_boundary=True)
        self.assertIn("no proof-of-work cutpoint", str(caught.exception))
        self.assertEqual([], calls)  # refused before a single measurement

    def test_registered_schema_reports_both_boundaries(self):
        bench, _ = self.fake_bench(
            lambda round_no: 0.90 if round_no % 2 else 0.94,
            pow_ms=40.0, request_scale=1.5,
        )
        with mock.patch.dict(
            runner.POW_PHASE_SECONDS_FIELDS,
            {"native_proof_v7": ("timing", "pow_seconds", "median")},
            clear=False,
        ):
            score = self.run_rounds(
                bench, base_policy(), fast_boundary=True, sequential_stop=None,
            )
        self.assertEqual(runner.FAST_BOUNDARY, score.boundary)
        # Full boundary: request scales with prove, so the ratio is the raw one.
        self.assertAlmostEqual(0.90, score.request_ratio, places=6)
        # PoW-excluded: (0.9*150 - 40) / (150 - 40) = 95/110.
        self.assertAlmostEqual(95.0 / 110.0, score.fast_request_ratio, places=6)
        self.assertIn("fast_request_ms", score.candidate_resources)

    def test_pow_extraction_reads_only_measured_seconds(self):
        group = self.manifest(ladder=LADDER).group("native")
        report = {"timing": {"pow_seconds": {"median": 0.25}}}
        self.assertIsNone(runner._pow_ms(report, group))
        with mock.patch.dict(
            runner.POW_PHASE_SECONDS_FIELDS,
            {"native_proof_v7": ("timing", "pow_seconds", "median")},
            clear=False,
        ):
            self.assertAlmostEqual(250.0, runner._pow_ms(report, group))
            with self.assertRaises(runner.RunError):
                runner._pow_ms({"timing": {}}, group)

    def test_shipped_registry_is_empty_so_the_flag_is_universally_refused(self):
        # No product emits a PoW cutpoint yet; the harness must not pretend.
        self.assertEqual({}, runner.POW_PHASE_SECONDS_FIELDS)


class PhaseAttributionTest(LadderTestCase):
    """T0 phase prefilter over whatever phases a schema provides (§3.2/§3.5)."""

    def test_native_schema_phases(self):
        group = self.manifest(ladder=LADDER).group("native")
        phases = runner.report_phases({
            "timing": {
                "input_seconds": {"median": 0.1},
                "prove_seconds": {"median": 1.0},
                "proof_encode_seconds": {"median": 0.2},
                "verify_seconds": {"median": 0.3},
                "request_seconds": {"median": 1.6},
            },
        }, group)
        self.assertEqual(
            {"input", "prove", "serialize", "verify", "request"}, set(phases),
        )
        self.assertAlmostEqual(1.0, phases["prove"])

    def test_stage_profiles_flatten_into_dotted_phase_names(self):
        group = self.manifest(ladder=LADDER).group("native")
        phases = runner.report_phases({
            "timing": {
                "stage_profiles": [{
                    "schema_version": 1,
                    "stages": [{
                        "id": "commit", "label": "commit", "seconds": 2.0,
                        "children": [
                            {"id": "merkle", "label": "merkle", "seconds": 1.25},
                        ],
                    }],
                }],
            },
        }, group)
        self.assertAlmostEqual(2.0, phases["stage:commit"])
        self.assertAlmostEqual(1.25, phases["stage:commit.merkle"])
        self.assertEqual("stage:commit.merkle", runner.resolve_phase(phases, "merkle"))

    def test_bare_stage_profile_document_is_accepted(self):
        group = self.manifest(ladder=LADDER).group("native")
        phases = runner.report_phases(
            {"schema_version": 1, "runtime": "cpu", "example": "x",
             "stages": [{"id": "fri", "label": "FRI", "seconds": 0.5}]},
            group,
        )
        self.assertAlmostEqual(0.5, phases["stage:fri"])

    def test_unknown_phase_names_fail_closed(self):
        with self.assertRaises(runner.RunError) as caught:
            runner.resolve_phase({"prove": 1.0}, "fri")
        self.assertIn("not reported by this group", str(caught.exception))

    def test_ambiguous_phase_names_fail_closed(self):
        phases = {"stage:a.commit": 1.0, "stage:b.commit": 2.0}
        with self.assertRaises(runner.RunError) as caught:
            runner.resolve_phase(phases, "commit")
        self.assertIn("ambiguous", str(caught.exception))

    def _prefilter(self, prove_by_arm, phase="prove", proxy=PROXY_FIXTURE):
        def phases(arm):
            return {"timing": {
                "input_seconds": {"median": 0.1},
                "prove_seconds": {"median": prove_by_arm[arm]},
                "proof_encode_seconds": {"median": 0.2},
                "verify_seconds": {"median": 0.3},
                "request_seconds": {"median": 1.6},
            }}

        bench, calls = self.fake_bench(lambda _round: 1.0, phases=phases)
        manifest = self.manifest(ladder=LADDER, proxy=proxy)
        with mock.patch.object(runner, "bench_once", bench), \
                mock.patch.object(runner, "build_arm", lambda *a, **k: None):
            result = runner.phase_prefilter(
                self.root, self.root, manifest, "small", self.out_dir,
                board="core_cpu", phase=phase, era=3,
            )
        return result, calls

    def test_claimed_phase_that_moves_passes_and_names_the_proxy(self):
        result, calls = self._prefilter({"a": 1.0, "b": 0.8})
        self.assertTrue(result["pass"])
        self.assertTrue(result["phase_moved"])
        self.assertAlmostEqual(0.2, result["relative_move"])
        self.assertEqual("small_proxy", result["workload"])
        self.assertFalse(result["ranks"])
        self.assertEqual(["t0a", "t0b"], calls)  # exactly one sample per arm
        self.assertEqual(30, result["cost_target_seconds"])

    def test_claimed_phase_that_does_not_move_fails_before_t1(self):
        result, _ = self._prefilter({"a": 1.0, "b": 0.999})
        self.assertFalse(result["pass"])
        self.assertFalse(result["phase_moved"])

    def test_unvalidated_proxy_is_marked_not_hidden(self):
        result, _ = self._prefilter({"a": 1.0, "b": 0.8})
        self.assertFalse(result["proxy_validity"]["validated"])
        self.assertTrue(
            any(marker.startswith("proxy unvalidated") for marker in result["markers"])
        )

    def test_class_without_a_proxy_says_so(self):
        result, _ = self._prefilter({"a": 1.0, "b": 0.8}, proxy=None)
        self.assertIsNone(result["proxy"])
        self.assertEqual("wf_small", result["workload"])
        self.assertTrue(
            any("no proxy fixture declared" in marker for marker in result["markers"])
        )


class CairoPhaseAttributionTest(unittest.TestCase):
    """T0 on the wave-1 Cairo track, over a real cairo_proof_v1 envelope."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out_dir = self.root / "runs"
        raw = cairo_raw_manifest()
        raw["gates_policy"]["confirmation_ladder"] = LADDER
        manifest_mod._validate(raw)
        self.manifest = Manifest(root=self.root, raw=raw)
        self.workload = self.manifest.workloads(board="cairo_cpu")[0]
        binary = self.root / "bin" / "stwo-cairo-cpu"
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text(
            FAKE_PRODUCT
            .replace("REPORT_JSON", repr(json.dumps(load_report())))
            .replace("PROFILE_JSON", repr(json.dumps(load_profile())))
            .replace("PROOF_PAYLOAD", repr(b"proof-bytes"))
            .replace("MUTATE", "pass")
        )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)

    def envelope(self) -> dict:
        result = runner.bench_once(
            self.root, self.manifest, self.workload, 1, 1, self.out_dir, "a1",
        )
        # The Cairo arm returns early from bench_once; ladder telemetry must
        # still ride along (None here: no schema registers a PoW cutpoint).
        self.assertIsNone(result.pow_ms)
        return json.loads(Path(result.report_path).read_text(encoding="utf-8"))

    def test_named_cutpoints_are_readable_for_t0(self):
        group = self.manifest.group("cairo_cpu")
        phases = runner.report_phases(self.envelope(), group)
        instrumented = set(manifest_mod.CAIRO_PHASE_NAMES) - {"serialize"}
        self.assertEqual(instrumented, set(phases))
        for name in set(runner.CAIRO_PHASE_STAGES) | {"verify"}:
            self.assertGreater(phases[name], 0.0)
        # A prove-only workload never runs the VM: execute is honestly zero,
        # which is a measured value, not a missing one.
        self.assertEqual(0.0, phases["execute"])

    def test_a_claim_on_a_zero_baseline_phase_fails_closed(self):
        with mock.patch.object(runner, "build_arm", lambda *a, **k: None):
            with self.assertRaises(runner.RunError) as caught:
                runner.phase_prefilter(
                    self.root, self.root, self.manifest, "small", self.out_dir,
                    board="cairo_cpu", phase="execute", era=3,
                )
        self.assertIn("not a positive duration", str(caught.exception))

    def test_uninstrumented_serialize_claim_fails_closed(self):
        group = self.manifest.group("cairo_cpu")
        phases = runner.report_phases(self.envelope(), group)
        with self.assertRaises(runner.RunError) as caught:
            runner.resolve_phase(phases, "serialize")
        self.assertIn("not reported by this group", str(caught.exception))

    def test_registry_row_tracks_the_canonical_cutpoint_names(self):
        self.assertEqual(
            set(manifest_mod.CAIRO_PHASE_NAMES),
            set(runner.PHASE_SECONDS_FIELDS["cairo_proof_v1"]),
        )

    def test_t0_prefilter_runs_end_to_end_on_cairo(self):
        moved = json.loads(json.dumps(load_report()))
        # A candidate whose FRI phase halved: every stage that composes the
        # phase moves, and nothing else does.
        fri_stages = set(runner.CAIRO_PHASE_STAGES["fri"][0])
        profile = json.loads(json.dumps(load_profile()))
        for node in profile["stages"]:
            if node["id"] in fri_stages:
                node["seconds"] = node["seconds"] / 2.0
        candidate = self.root / "candidate"
        (candidate / "bin").mkdir(parents=True)
        binary = candidate / "bin" / "stwo-cairo-cpu"
        binary.write_text(
            FAKE_PRODUCT
            .replace("REPORT_JSON", repr(json.dumps(moved)))
            .replace("PROFILE_JSON", repr(json.dumps(profile)))
            .replace("PROOF_PAYLOAD", repr(b"proof-bytes"))
            .replace("MUTATE", "pass")
        )
        binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
        with mock.patch.object(runner, "build_arm", lambda *a, **k: None):
            result = runner.phase_prefilter(
                self.root, candidate, self.manifest, "small", self.out_dir,
                board="cairo_cpu", phase="fri", era=3,
            )
        self.assertTrue(result["pass"], result)
        self.assertEqual("fri", result["resolved_phase"])
        self.assertGreater(result["relative_move"], 0.4)
        self.assertTrue(result["correctness_smoke"]["pass"])
        self.assertFalse(result["ranks"])

    def test_t0_rejects_a_claim_on_a_phase_that_did_not_move(self):
        with mock.patch.object(runner, "build_arm", lambda *a, **k: None):
            result = runner.phase_prefilter(
                self.root, self.root, self.manifest, "small", self.out_dir,
                board="cairo_cpu", phase="fri", era=3,
            )
        self.assertFalse(result["pass"])
        self.assertFalse(result["phase_moved"])


class ProxyFixtureManifestTest(LadderTestCase):
    """Per-class proxy fixtures: scaled shape, OFFICIAL params (§3.3)."""

    def _validate(self, fixture):
        manifest_mod._validate(make_raw(ladder=LADDER, proxy=fixture))

    def test_valid_fixture_is_accepted(self):
        self._validate(PROXY_FIXTURE)

    def test_absent_fixture_is_legal(self):
        manifest_mod._validate(make_raw(ladder=LADDER))

    def test_weakened_parameters_are_refused(self):
        fixture = dict(PROXY_FIXTURE, official_params=False)
        with self.assertRaises(ManifestError) as caught:
            self._validate(fixture)
        self.assertIn("official_params must be true", str(caught.exception))

    def test_security_parameters_may_not_be_restated(self):
        for token in ("--pow-bits 8", "--n-queries 4", "--protocol functional"):
            fixture = dict(PROXY_FIXTURE, args=PROXY_FIXTURE["args"] + " " + token)
            with self.assertRaises(ManifestError) as caught:
                self._validate(fixture)
            self.assertIn("scales geometry only", str(caught.exception))

    def test_unknown_keys_are_refused(self):
        fixture = dict(PROXY_FIXTURE, sneaky=True)
        with self.assertRaises(ManifestError):
            self._validate(fixture)

    def test_target_workloads_are_required(self):
        fixture = dict(PROXY_FIXTURE, target_workload_ids=[])
        with self.assertRaises(ManifestError):
            self._validate(fixture)

    def test_unknown_class_keys_are_refused(self):
        raw = make_raw(ladder=LADDER)
        raw["workload_registry"]["classes"]["small"]["surprise"] = 1
        with self.assertRaises(ManifestError):
            manifest_mod._validate(raw)

    def test_manifest_exposes_the_fixture(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        self.assertEqual(PROXY_FIXTURE, manifest.proxy_fixture("small"))
        self.assertIsNone(self.manifest(ladder=LADDER).proxy_fixture("small"))


class LadderRegistrationTest(LadderTestCase):
    """The ladder block is all-or-nothing (§3.5 pre-registration)."""

    def test_absent_block_is_valid(self):
        manifest_mod._validate(make_raw())

    def test_partial_block_is_refused(self):
        ladder = json.loads(json.dumps(LADDER))
        del ladder["proxy_validity"]
        with self.assertRaises(ManifestError):
            manifest_mod._validate(make_raw(ladder=ladder))

    def test_unregistered_rule_is_refused(self):
        ladder = json.loads(json.dumps(LADDER))
        ladder["sequential_stop"]["rule"] = "sequential_probability_ratio_v1"
        with self.assertRaises(ManifestError):
            manifest_mod._validate(make_raw(ladder=ladder))

    def test_alpha_bounds(self):
        for alpha in (0.0, -0.1, 0.75):
            ladder = json.loads(json.dumps(LADDER))
            ladder["sequential_stop"]["alpha"] = alpha
            with self.assertRaises(ManifestError):
                manifest_mod._validate(make_raw(ladder=ladder))

    def test_targets_must_increase_down_the_ladder(self):
        ladder = json.loads(json.dumps(LADDER))
        ladder["tiers"]["T1"]["cost_target_seconds"] = 10
        with self.assertRaises(ManifestError) as caught:
            manifest_mod._validate(make_raw(ladder=ladder))
        self.assertIn("increase strictly", str(caught.exception))

    def test_repository_manifest_registers_the_contract_targets(self):
        live = manifest_mod.load(Path(__file__).resolve().parents[2])
        self.assertEqual(30, live.tier_cost_target_seconds("T0"))
        self.assertEqual(300, live.tier_cost_target_seconds("T1"))
        self.assertEqual(2700, live.tier_cost_target_seconds("T2"))
        self.assertIsNone(live.tier_cost_target_seconds("T3"))
        ladder = live.confirmation_ladder
        self.assertEqual(
            manifest_mod.SEQUENTIAL_STOP_RULE, ladder["sequential_stop"]["rule"],
        )
        # Ranked runs keep their fixed design until an era boundary says otherwise.
        self.assertFalse(ladder["sequential_stop"]["enabled"])


def observation(proxy_ln: float, class_ln: float) -> dict:
    return {
        "proxy_ln_ratio": proxy_ln,
        "class_ln_ratio": class_ln,
        "proxy_evidence_sha256": "a" * 64,
        "class_evidence_sha256": "b" * 64,
    }


def receipt(observations: list[dict], **overrides) -> dict:
    correlation = manifest_mod.pearson_correlation(
        [item["proxy_ln_ratio"] for item in observations],
        [item["class_ln_ratio"] for item in observations],
    )
    document = {
        "schema": manifest_mod.PROXY_VALIDITY_RECEIPT_SCHEMA,
        "board": "core_cpu",
        "era": 3,
        "workload_class": "small",
        "proxy": {
            "proxy_id": PROXY_FIXTURE["proxy_id"],
            "args": PROXY_FIXTURE["args"],
            "native_unit": PROXY_FIXTURE["native_unit"],
            "official_params": True,
        },
        "target": {"workload_ids": ["wf_small"]},
        "measured_at_utc": "2026-07-29T12:00:00Z",
        "host": {
            "identity_sha256": "c" * 64,
            "chip": "Apple M5",
            "logical_cpu_count": 10,
        },
        "harness_commit": "0123456789ab",
        "measurement": {
            "method": manifest_mod.PROXY_VALIDITY_METHOD,
            "observations": observations,
            "observation_count": len(observations),
            "correlation": correlation,
            "min_correlation": 0.8,
            "min_observations": 5,
            "valid": correlation >= 0.8 and len(observations) >= 5,
        },
        "artifact_sha256": hashlib.sha256(
            json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    document.update(overrides)
    return document


CORRELATED = [
    observation(-0.10, -0.09),
    observation(-0.20, -0.19),
    observation(-0.05, -0.04),
    observation(-0.30, -0.32),
    observation(-0.15, -0.14),
]


class ProxyValidityReceiptTest(LadderTestCase):
    """Era receipts: measured, recomputable, never asserted (§3.6)."""

    def test_valid_receipt_round_trips(self):
        document = manifest_mod.validate_proxy_validity_receipt(
            receipt(CORRELATED), board="core_cpu", workload_class="small", era=3,
            policy=LADDER["proxy_validity"], proxy_fixture=PROXY_FIXTURE,
        )
        self.assertTrue(document["measurement"]["valid"])
        self.assertGreater(document["measurement"]["correlation"], 0.8)

    def test_asserted_correlation_must_match_its_own_evidence(self):
        tampered = receipt(CORRELATED)
        tampered["measurement"]["correlation"] = 0.999999
        with self.assertRaises(ManifestError) as caught:
            manifest_mod.validate_proxy_validity_receipt(tampered)
        self.assertIn("not the Pearson correlation", str(caught.exception))

    def test_validity_flag_must_match_the_thresholds(self):
        lying = receipt(CORRELATED)
        lying["measurement"]["valid"] = False
        with self.assertRaises(ManifestError) as caught:
            manifest_mod.validate_proxy_validity_receipt(lying)
        self.assertIn("validity flag disagrees", str(caught.exception))

    def test_receipt_may_not_weaken_the_registered_floor(self):
        weak = receipt(CORRELATED)
        weak["measurement"]["min_correlation"] = 0.5
        weak["measurement"]["min_observations"] = 3
        with self.assertRaises(ManifestError) as caught:
            manifest_mod.validate_proxy_validity_receipt(
                weak, policy=LADDER["proxy_validity"],
            )
        self.assertIn("weakens the registered", str(caught.exception))

    def test_two_observations_are_not_evidence(self):
        with self.assertRaises(ManifestError):
            manifest_mod.validate_proxy_validity_receipt(receipt(CORRELATED[:2]))

    def test_binding_to_another_board_or_era_is_refused(self):
        document = receipt(CORRELATED)
        with self.assertRaises(ManifestError):
            manifest_mod.validate_proxy_validity_receipt(document, board="riscv")
        with self.assertRaises(ManifestError):
            manifest_mod.validate_proxy_validity_receipt(document, era=4)

    def test_receipt_identity_must_match_the_manifest_fixture(self):
        document = receipt(CORRELATED)
        document["proxy"]["args"] = "--log-n-rows 24"
        with self.assertRaises(ManifestError):
            manifest_mod.validate_proxy_validity_receipt(
                document, proxy_fixture=PROXY_FIXTURE,
            )

    def test_unknown_schema_is_refused(self):
        with self.assertRaises(ManifestError):
            manifest_mod.validate_proxy_validity_receipt(
                receipt(CORRELATED, schema="stwo_perf_proxy_validity_receipt_v2"),
            )

    def test_missing_receipt_marks_the_proxy_unvalidated(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        state = manifest.proxy_validity_state("core_cpu", "small", 3)
        self.assertFalse(state["validated"])
        self.assertIn("proxy unvalidated", state["reason"])

    def test_committed_receipt_validates_the_proxy(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        path = (
            self.root / LADDER["proxy_validity"]["receipt_dir"]
            / manifest_mod.proxy_receipt_filename("core_cpu", "small", 3)
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(receipt(CORRELATED)))
        state = manifest.proxy_validity_state("core_cpu", "small", 3)
        self.assertTrue(state["validated"], state["reason"])
        self.assertGreater(state["correlation"], 0.8)

    def test_decayed_receipt_asks_for_rotation(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        decayed = [
            observation(-0.10, 0.05),
            observation(-0.20, -0.01),
            observation(-0.05, 0.02),
            observation(-0.30, 0.04),
            observation(-0.15, -0.02),
        ]
        path = (
            self.root / LADDER["proxy_validity"]["receipt_dir"]
            / manifest_mod.proxy_receipt_filename("core_cpu", "small", 3)
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(receipt(decayed)))
        state = manifest.proxy_validity_state("core_cpu", "small", 3)
        self.assertFalse(state["validated"])
        self.assertIn("rotate the proxy", state["reason"])


class ProxyReceiptBuilderTest(LadderTestCase):
    """The M5 receipt command reads measurements; it never makes them."""

    def _write_pair(self, index: int, proxy_r: float, class_r: float,
                    board: str = "core_cpu") -> tuple[Path, Path]:
        proxy_path = self.root / f"proxy-{index}.json"
        class_path = self.root / f"class-{index}.json"
        proxy_path.write_text(json.dumps({
            "schema": runner.LADDER_T1_SCHEMA,
            "board": board,
            "workload_class": "small",
            "r_geomean": proxy_r,
        }))
        class_path.write_text(json.dumps({
            "schema_version": 1,
            "kind": "claimed",
            "declared_objective": {
                "board": board, "workload_class": "small", "dimension": "time",
            },
            "score": {"R_geomean": class_r},
        }))
        return proxy_path, class_path

    def _observations(self, count: int = 5, board: str = "core_cpu"):
        pairs = [(0.90, 0.91), (0.80, 0.82), (0.95, 0.96), (0.70, 0.68), (0.85, 0.86)]
        return [
            self._write_pair(index, *pairs[index % len(pairs)], board=board)
            for index in range(count)
        ]

    def test_receipt_is_assembled_from_measured_documents(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        # The repository root is the harness identity the receipt must bind.
        document = runner.build_proxy_validity_receipt(
            Path(__file__).resolve().parents[2], manifest, board="core_cpu",
            workload_class="small", era=3, observations=self._observations(),
            measured_at_utc="2026-07-29T12:00:00Z",
        )
        manifest_mod.validate_proxy_validity_receipt(
            document, board="core_cpu", workload_class="small", era=3,
            policy=LADDER["proxy_validity"], proxy_fixture=PROXY_FIXTURE,
        )
        measurement = document["measurement"]
        self.assertEqual(5, measurement["observation_count"])
        self.assertTrue(measurement["valid"])
        self.assertAlmostEqual(
            math.log(0.90), measurement["observations"][0]["proxy_ln_ratio"],
        )
        # Every observation binds the bytes it was read from.
        self.assertNotEqual(
            measurement["observations"][0]["proxy_evidence_sha256"],
            measurement["observations"][0]["class_evidence_sha256"],
        )

    def test_too_few_observations_are_refused(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        with self.assertRaises(runner.RunError) as caught:
            runner.build_proxy_validity_receipt(
                self.root, manifest, board="core_cpu", workload_class="small",
                era=3, observations=self._observations(3),
            )
        self.assertIn("registered minimum is 5", str(caught.exception))

    def test_documents_from_another_board_are_refused(self):
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        with self.assertRaises(runner.RunError) as caught:
            runner.build_proxy_validity_receipt(
                self.root, manifest, board="core_cpu", workload_class="small",
                era=3, observations=self._observations(board="riscv"),
            )
        self.assertIn("expected core_cpu/small", str(caught.exception))

    def test_class_without_a_proxy_cannot_be_certified(self):
        manifest = self.manifest(ladder=LADDER)
        with self.assertRaises(runner.RunError) as caught:
            runner.build_proxy_validity_receipt(
                self.root, manifest, board="core_cpu", workload_class="small",
                era=3, observations=self._observations(),
            )
        self.assertIn("nothing to certify", str(caught.exception))


class IterateEstimateTest(LadderTestCase):
    """T1 emits an estimate, never a verdict (§3.5b local-vs-ranked)."""

    def _estimate(self, **kwargs):
        bench, _ = self.fake_bench(lambda round_no: 0.50 if round_no % 2 else 0.62)
        manifest = self.manifest(ladder=LADDER, proxy=PROXY_FIXTURE)
        with mock.patch.object(runner, "bench_once", bench), \
                mock.patch.object(runner, "build_arm", lambda *a, **k: None), \
                mock.patch.object(runner.ledger, "aa_dispersion", lambda *a: None):
            return runner.iterate_estimate(
                self.root, self.root, manifest, "small", self.out_dir,
                board="core_cpu", era=3, **kwargs,
            )

    def test_estimate_document_never_ranks(self):
        result = self._estimate()
        self.assertEqual(runner.LADDER_T1_SCHEMA, result["schema"])
        self.assertFalse(result["ranks"])
        self.assertNotIn("gates", result)
        self.assertEqual(runner.FULL_BOUNDARY, result["boundary"])
        self.assertEqual(300, result["cost_target_seconds"])

    def test_sequential_stop_is_armed_at_t1(self):
        result = self._estimate()
        entry = result["per_workload"]["small_proxy"]
        self.assertEqual(3, entry["rounds"])
        self.assertEqual("decisive_clear", entry["sequential_stop"]["decision"])

    def test_fast_boundary_without_pow_telemetry_fails_closed(self):
        with self.assertRaises(runner.RunError):
            self._estimate(fast_boundary=True)


if __name__ == "__main__":
    unittest.main()
