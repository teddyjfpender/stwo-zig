import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import ledger, promotion  # noqa: E402

HEADER = "\t".join(ledger.COLUMNS)


def claimed_verdict(**overrides) -> dict:
    verdict = {
        "schema_version": 1,
        "kind": "claimed",
        "harness_commit": "abc123",
        "repo_commit": "31a3132ef2e6",
        "predecessor_commit": "31a3132ef2e6",
        "scope": "s3",
        "search_health": {"measurement_wall_seconds": 25.0},
        "declared_objective": {"board": "core_cpu", "workload_class": "wide",
                               "dimension": "time"},
        "gates": {g: {"pass": True} for g in ("G1", "G2", "G3", "G4", "G5")},
        "holdout": None,
        "score": {
            "R_geomean": 0.9631,
            "significant": True,
            "neutral": False,
            "resource_portfolio": {
                "peak_rss_mib": {"candidate_geomean": 24.5},
                "energy_j": {"candidate_geomean": 0.25},
                "proof_bytes": {"candidate_geomean": 4096.0},
            },
            "per_workload": {"wf_log14x32": {
                "b_median_ms": 95.1, "ci": [0.955, 0.972], "rounds": 9,
                "proof_bytes": 4096, "measurement_seconds": 12.5,
            }},
        },
    }
    verdict.update(overrides)
    return verdict


class PromoteClaimedTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self._git("init", "-q", "-b", "main")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "test")
        (self.repo / "autoresearch" / "ledger").mkdir(parents=True)
        (self.repo / "autoresearch" / "ledger" / "promotions.tsv").write_text(HEADER + "\n")
        (self.repo / "autoresearch" / "ledger" / "epochs.json").write_text(
            json.dumps({"epochs": [{"epoch": 1}]})
        )
        (self.repo / "autoresearch" / "MANIFEST.json").write_text(json.dumps({
            "manifest_version": 2,
            "harness": {"anchor_commit": None},
            "editable_paths": [],
            "locked_paths": [],
            "gates_policy": {
                "max_rounds": 1,
                "search_health": {
                    "trailing_window": 1,
                    "gradient_snr_threshold": 2.0,
                    "auto_boost_rounds": 1,
                    "maximum_rounds": 2,
                },
            },
            "qualification_policy": {
                "required_checks": ["allowed_diff"],
                "max_active_per_user": 1,
            },
            "workload_registry": {
                "classes": {
                    name: {
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
                    }
                    for name in ("small", "wide", "deep")
                },
                "groups": {
                    "native": {
                    "enabled": True,
                    "promotion_eligible": True,
                    "board": "core_cpu",
                    "build_step": "true",
                    "binary": "bin/native",
                    "report_schema": "native_proof_v7",
                    "workloads": {
                        "wf": {
                            "class": "small", "args": "--x", "native_unit": "rows",
                        },
                        "wf_wide": {
                            "class": "wide", "args": "--x", "native_unit": "rows",
                        },
                        "wf_deep": {
                            "class": "deep", "args": "--x", "native_unit": "rows",
                        },
                    },
                },
                    "riscv": {
                    "enabled": True,
                    "promotion_eligible": False,
                    "board": "riscv",
                    "build_step": "true",
                    "binary": "bin/riscv",
                    "report_schema": "riscv_proof_v3",
                    "mechanism_telemetry": {
                        "fail_closed": True,
                        "required_fields": [
                            "n_components",
                            "statement_sha256",
                            "total_steps",
                            "transcript_state_blake2s",
                        ],
                    },
                    "resource_telemetry": {
                        "fail_closed": True,
                        "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
                        "scope": "self_process_lifetime",
                        "sampling_points": [
                            "before_warmups", "after_verified_samples",
                        ],
                        "fields": [
                            "lifetime_max_phys_footprint_bytes", "energy_nj",
                            "instructions", "cycles",
                        ],
                    },
                    "workloads": {"rv": {
                        "class": "wide", "args": "--x", "native_unit": "cycles",
                    }},
                },
                },
            },
        }))
        self._commit("Harness scaffolding")

    def _git(self, *args):
        subprocess.run(["git", *args], cwd=self.repo, check=True, capture_output=True)

    def _commit(self, message):
        self._git("add", "-A")
        self._git("commit", "-q", "-m", message)

    def _land_submission(self, name, verdict):
        sub = self.repo / "autoresearch" / "submissions" / name
        sub.mkdir(parents=True)
        (sub / "verdict.json").write_text(json.dumps(verdict))
        (sub / "note.md").write_text("# note\n")
        self._commit(f"Merge submission {name}")

    def test_records_claimed_row_with_landing_commit(self):
        self._land_submission("2026-07-20-packed", claimed_verdict())
        row = promotion.promote_claimed(self.repo, "2026-07-20-packed")
        self.assertEqual(row["verdict_kind"], "claimed")
        self.assertEqual(row["schema_version"], 3)
        self.assertEqual(row["evidence_kind"], "promotion")
        self.assertEqual(row["covers"], [])
        self.assertEqual(row["credit_replaces"], [])
        self.assertEqual(row["row_id"], ledger.compute_row_id(row))
        self.assertEqual(
            row["observation_id"],
            ledger.observation_id("2026-07-20-packed", "core_cpu", "wide"),
        )
        self.assertEqual(row["outcome"], "promoted")
        rows = ledger.load(self.repo)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].verdict_kind, "claimed")
        landing = subprocess.run(
            ["git", "log", "--reverse", "--format=%H", "--",
             "autoresearch/submissions/2026-07-20-packed"],
            cwd=self.repo, capture_output=True, text=True, check=True,
        ).stdout.strip().splitlines()[0]
        self.assertEqual(rows[0].commit, landing)
        head_message = subprocess.run(
            ["git", "log", "-1", "--format=%s"], cwd=self.repo,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        self.assertIn("claimed", head_message)

    def test_refuses_double_record(self):
        self._land_submission("2026-07-20-packed", claimed_verdict())
        promotion.promote_claimed(self.repo, "2026-07-20-packed")
        with self.assertRaises(promotion.PromotionError):
            promotion.promote_claimed(self.repo, "2026-07-20-packed")

    def test_refuses_judged_verdict(self):
        self._land_submission("2026-07-20-packed", claimed_verdict(kind="judged"))
        with self.assertRaises(promotion.PromotionError):
            promotion.promote_claimed(self.repo, "2026-07-20-packed")

    def test_refuses_dirty_tree(self):
        self._land_submission("2026-07-20-packed", claimed_verdict())
        (self.repo / "loose.txt").write_text("dirty")
        with self.assertRaises(promotion.PromotionError):
            promotion.promote_claimed(self.repo, "2026-07-20-packed")

    def test_multi_class_verdicts_record_one_row_each(self):
        sub = self.repo / "autoresearch" / "submissions" / "2026-07-20-multi"
        sub.mkdir(parents=True)
        (sub / "verdict.json").write_text(json.dumps(claimed_verdict()))
        deep = claimed_verdict()
        deep["declared_objective"]["workload_class"] = "deep"
        deep["score"]["per_workload"] = {"plonk_log14": {
            "b_median_ms": 8.5, "ci": [0.85, 0.87], "rounds": 9,
            "proof_bytes": 4096, "measurement_seconds": 12.5,
        }}
        (sub / "verdict-deep.json").write_text(json.dumps(deep))
        (sub / "note.md").write_text("# note\n")
        self._commit("Merge submission 2026-07-20-multi")

        from stwo_perf.promotion import claimed_verdict_files
        files = [p.name for p in claimed_verdict_files(sub)]
        self.assertEqual(files, ["verdict.json", "verdict-deep.json"])

        row_wide = promotion.promote_claimed(self.repo, "2026-07-20-multi")
        row_deep = promotion.promote_claimed(self.repo, "2026-07-20-multi", "verdict-deep.json")
        self.assertEqual(row_wide["workload_class"], "wide")
        self.assertEqual(row_deep["workload_class"], "deep")
        rows = [r for r in ledger.load(self.repo) if r.submission_id == "2026-07-20-multi"]
        self.assertEqual(len(rows), 2)
        with self.assertRaisesRegex(promotion.PromotionError, "core_cpu/deep"):
            promotion.promote_claimed(self.repo, "2026-07-20-multi", "verdict-deep.json")

    def test_insignificant_result_records_neutral(self):
        verdict = claimed_verdict()
        verdict["score"]["significant"] = False
        verdict["score"]["neutral"] = True
        self._land_submission("2026-07-20-neutral", verdict)
        row = promotion.promote_claimed(self.repo, "2026-07-20-neutral")
        self.assertEqual(row["outcome"], "neutral")

    def test_multi_workload_row_uses_portfolio_ci_and_latency_summary(self):
        verdict = claimed_verdict()
        verdict["score"]["per_workload"] = {
            "fast_first": {"b_median_ms": 1.0, "ci": [0.40, 0.60]},
            "slow_second": {"b_median_ms": 100.0, "ci": [1.10, 1.30]},
        }
        verdict["score"]["portfolio"] = {
            "ci_method": "independent_workload_round_bootstrap_percentile_v1",
            "ci_level": 0.95,
            "bootstrap_iterations": 4000,
            "seed": 17,
            "ci": [0.81, 0.89],
            "prove_ms_method": "geometric_mean_candidate_workload_medians_ms_v1",
            "b_median_ms_geomean": 10.0,
            "proof_bytes_method": "rounded_geometric_mean_candidate_proof_bytes_v1",
            "proof_bytes": 4096,
            "measurement_seconds": 25.0,
            "measurement_rounds": 18,
        }
        row = promotion.row_from_verdict(
            "portfolio", verdict, 1, "promoted", "G1..G5:pass", "claimed"
        )
        self.assertEqual((row["ci_low"], row["ci_high"]), (0.81, 0.89))
        self.assertEqual(row["prove_ms"], 10.0)
        self.assertEqual(row["peak_rss_mib"], 24.5)
        self.assertEqual(row["energy_j"], 0.25)

    def test_invalid_resource_portfolio_candidate_fails_closed(self):
        verdict = claimed_verdict()
        verdict["score"]["resource_portfolio"]["energy_j"][
            "candidate_geomean"
        ] = 0.0
        with self.assertRaisesRegex(promotion.PromotionError, "energy_j"):
            promotion.row_from_verdict(
                "bad-resource", verdict, 2, "rejected", "G5:fail", "claimed"
            )

    def test_verdict_without_resource_portfolio_stays_incomplete(self):
        verdict = claimed_verdict()
        verdict["score"].pop("resource_portfolio")
        row = promotion.row_from_verdict(
            "legacy", verdict, 1, "promoted", "G1..G5:pass", "claimed"
        )
        self.assertEqual(row["peak_rss_mib"], 0.0)
        self.assertIsNone(row["energy_j"])

    def test_multi_workload_row_without_portfolio_statistics_fails_closed(self):
        verdict = claimed_verdict()
        verdict["score"]["per_workload"]["second"] = {
            "b_median_ms": 8.0,
            "ci": [0.9, 1.1],
        }
        with self.assertRaisesRegex(promotion.PromotionError, "portfolio"):
            promotion.row_from_verdict(
                "portfolio", verdict, 1, "promoted", "G1..G5:pass", "claimed"
            )

    def test_span_verdict_requires_explicit_metrics_v2_evidence(self):
        verdict = claimed_verdict()
        verdict["span_constituents"] = ["one", "two"]
        with self.assertRaisesRegex(promotion.PromotionError, "explicit Metrics-v2"):
            promotion.row_from_verdict(
                "span", verdict, 2, "promoted", "G1..G5:pass", "claimed"
            )

    def test_v3_row_requires_total_evaluation_wall_time(self):
        verdict = claimed_verdict()
        verdict.pop("search_health")
        with self.assertRaisesRegex(promotion.PromotionError, "measurement_wall_seconds"):
            promotion.row_from_verdict(
                "missing-wall", verdict, 2, "promoted", "G1..G5:pass", "claimed"
            )

    def test_explicit_direct_audit_row_preserves_replacement_set(self):
        replaced = "sha256:" + "a" * 64
        verdict = claimed_verdict(ledger_evidence={
            "evidence_kind": "direct_audit",
            "covers": [],
            "credit_replaces": [replaced],
            "supersedes": "",
        })
        row = promotion.row_from_verdict(
            "audit", verdict, 2, "rejected", "G1..G5:pass", "claimed"
        )
        self.assertEqual(row["evidence_kind"], "direct_audit")
        self.assertEqual(row["credit_replaces"], [replaced])
        self.assertEqual(row["row_id"], ledger.compute_row_id(row))

    def test_fabricated_riscv_verdict_cannot_create_a_ledger_row(self):
        verdict = claimed_verdict()
        verdict["declared_objective"]["board"] = "riscv"
        self._land_submission("2026-07-20-riscv", verdict)
        with self.assertRaisesRegex(promotion.PromotionError, "not promotion eligible"):
            promotion.promote_claimed(self.repo, "2026-07-20-riscv")
        self.assertEqual(ledger.load(self.repo), [])


if __name__ == "__main__":
    unittest.main()
