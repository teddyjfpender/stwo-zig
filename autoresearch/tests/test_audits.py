import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))

from stwo_perf import audits, ledger, manifest as manifest_mod, metrics, search_health  # noqa: E402
from test_ledger_v3 import HEADER, v3_values  # noqa: E402

ANCHOR = "8e58d7015e28a312eddc6f1eacc10e0c08ea85cc"
CANDIDATE = "f" * 40


def parsed(*values: dict) -> list[ledger.Row]:
    text = HEADER + "\n" + "\n".join(ledger.serialize_row(value) for value in values)
    return ledger.parse(text + "\n")


def promotion(name: str, index: int, **overrides) -> dict:
    values = {
        "submission_id": name,
        "judged_at_utc": f"2026-07-21T16:{index:02d}:00Z",
        "commit": f"{index:040x}",
        "predecessor": ANCHOR if index == 1 else f"{index - 1:040x}",
    }
    values.update(overrides)
    return v3_values(**values)


def evidence(name: str, index: int, kind: str, **overrides) -> dict:
    return promotion(name, index, evidence_kind=kind, **overrides)


def plan(values: list[dict]) -> dict:
    def resolve(value: str) -> str:
        return ANCHOR if value.endswith("^1") else value

    return audits.build_plan(
        manifest_mod.load(ROOT),
        parsed(*values),
        epoch=2,
        candidate_commit=CANDIDATE,
        source={"fixture": True, "ledger_sha256": "sha256:" + "a" * 64},
        board="core_cpu",
        workload_class="small",
        commit_resolver=resolve,
    )


class AuditPlanningTest(unittest.TestCase):
    def test_significant_span_is_planned_once(self):
        neutral = [
            promotion(
                f"neutral-{index}", index, outcome="neutral",
                judged_r=0.995, ci_low=0.98, ci_high=1.01,
            )
            for index in range(1, 5)
        ]
        first = plan(neutral)
        self.assertEqual(len(first["items"]), 1)
        item = first["items"][0]
        self.assertEqual(item["evidence_kind"], "span_audit")
        self.assertEqual(item["predecessor_commit"], ANCHOR)
        self.assertEqual(
            item["covers"], [value["observation_id"] for value in neutral]
        )
        span = evidence(
            "span", 5, "span_audit", covers=item["covers"],
            judged_r=0.94, ci_low=0.92, ci_high=0.97,
        )
        self.assertEqual(plan([*neutral, span])["items"], [])

    def test_null_span_consumes_once_and_contributes_zero(self):
        neutral = [
            promotion(
                f"neutral-{index}", index, outcome="neutral",
                judged_r=0.999, ci_low=0.98, ci_high=1.01,
            )
            for index in range(1, 5)
        ]
        covers = [value["observation_id"] for value in neutral]
        span = evidence(
            "span", 5, "span_audit", outcome="neutral", covers=covers,
            judged_r=1.0, ci_low=0.98, ci_high=1.02,
        )
        all_rows = parsed(*neutral, span)
        score = metrics.score_class(
            all_rows, 2, "core_cpu", "small", shrinkage_lambda=1.0,
            audit_anchor_commit=ANCHOR,
        )
        self.assertEqual(score.ratio, 1.0)
        self.assertEqual(plan([*neutral, span])["items"], [])

    def test_failed_span_guards_consume_no_audit_slot(self):
        neutral = [
            promotion(
                f"neutral-{index}", index, outcome="neutral",
                judged_r=0.999, ci_low=0.98, ci_high=1.01,
            )
            for index in range(1, 5)
        ]
        failed = evidence(
            "failed-span", 5, "span_audit", outcome="rejected",
            gates="G3:fail",
            covers=[value["observation_id"] for value in neutral],
        )
        retry = plan([*neutral, failed])
        self.assertEqual(len(retry["items"]), 1)
        self.assertEqual(retry["items"][0]["evidence_kind"], "span_audit")

    def test_span_through_interleaved_promotion_is_blocked(self):
        neutral = [
            promotion(
                f"neutral-{index}", index, outcome="neutral",
                judged_r=0.999, ci_low=0.98, ci_high=1.01,
            )
            for index in range(1, 5)
        ]
        interleaved = promotion("promoted", 3)
        values = [neutral[0], neutral[1], interleaved, neutral[2], neutral[3]]
        result = plan(values)
        self.assertEqual(len(result["items"]), 1)
        self.assertFalse(result["items"][0]["runnable"])
        self.assertEqual(
            result["items"][0]["blocked_reason"],
            "span constituents are not the contiguous promotion tail",
        )

    def test_direct_plan_replaces_exact_active_credit_set(self):
        promotions = [promotion(f"p-{index}", index) for index in range(1, 13)]
        result = plan(promotions)
        self.assertEqual(len(result["items"]), 1)
        item = result["items"][0]
        self.assertEqual(item["evidence_kind"], "direct_audit")
        self.assertEqual(item["predecessor_commit"], ANCHOR)
        self.assertEqual(
            item["credit_replaces"], [value["row_id"] for value in promotions]
        )

    def test_failed_direct_guards_consume_no_audit_slot(self):
        promotions = [promotion(f"p-{index}", index) for index in range(1, 13)]
        failed = evidence(
            "failed-direct", 13, "direct_audit", outcome="rejected",
            gates="G1:fail", predecessor=ANCHOR, credit_replaces=[],
        )
        retry = plan([*promotions, failed])
        self.assertEqual(len(retry["items"]), 1)
        self.assertEqual(retry["items"][0]["evidence_kind"], "direct_audit")
        self.assertEqual(
            retry["items"][0]["credit_replaces"],
            [value["row_id"] for value in promotions],
        )

    def test_plan_contract_cannot_select_guards_none(self):
        promotions = [promotion(f"p-{index}", index) for index in range(1, 13)]
        result = plan(promotions)
        contract = result["items"][0]["execution_contract"]
        self.assertEqual(contract["guards_mode"], "all")
        self.assertTrue(contract["judged"])
        self.assertTrue(contract["oracle_required"])
        self.assertNotIn('"guards_mode":"none"', str(result))

    def test_authority_recomputation_rejects_forged_due_item(self):
        source = audits.source_binding(ROOT)
        result = audits.build_plan(
            manifest_mod.load(ROOT),
            ledger.load(ROOT),
            epoch=2,
            candidate_commit=source["candidate_commit"],
            source=source,
        )
        forged = {
            "epoch": 2,
            "board": "core_cpu",
            "workload_class": "small",
            "evidence_kind": "direct_audit",
            "predecessor_commit": ANCHOR,
            "candidate_commit": result["source"]["candidate_commit"],
            "authority_ledger_sha256": result["source"]["ledger_sha256"],
            "covers": [],
            "credit_replaces": [],
            "span_reasons": [],
            "runnable": True,
            "blocked_reason": None,
            "execution_contract": {
                "judged": True,
                "guards_mode": "all",
                "oracle_required": True,
                "audit_power": "required_bounded_boost",
                "scope": "s5",
                "dimension": "time",
            },
        }
        forged = {"item_id": audits._canonical_digest(forged), **forged}
        tampered = copy.deepcopy(result)
        tampered["items"] = [forged]
        body = {key: value for key, value in tampered.items() if key != "plan_sha256"}
        tampered["plan_sha256"] = audits._canonical_digest(body)
        with self.assertRaisesRegex(audits.AuditError, "not currently due"):
            audits.validate_plan(ROOT, tampered)


class AuditPowerTest(unittest.TestCase):
    def test_sparse_history_still_gets_bounded_audit_boost(self):
        decision = search_health.decide_rounds(
            board="core_cpu",
            workload_class="small",
            configured_rounds=5,
            minimum_rounds=3,
            workload_count=1,
            class_wall_deadline_seconds=60.0,
            policy={
                "trailing_window": 8,
                "gradient_snr_threshold": 2.0,
                "auto_boost_rounds": 5,
                "maximum_rounds": 25,
            },
            history=[],
        )
        boosted = search_health.require_audit_power(decision)
        self.assertEqual(boosted.target_rounds, 10)
        self.assertEqual(boosted.auto_boost_reason, "required_audit_power")
        self.assertTrue(boosted.auto_boost_applied)


class AuditExecutionTest(unittest.TestCase):
    @staticmethod
    def _git(repo: Path, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=repo, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def _audit_repo(self, root: Path) -> tuple[Path, str, str]:
        repo = root / "repo"
        repo.mkdir()
        self._git(repo, "init", "-q")
        self._git(repo, "config", "maintenance.auto", "false")
        self._git(repo, "config", "user.name", "Audit Test")
        self._git(repo, "config", "user.email", "audit@example.com")
        shutil.copytree(ROOT / "autoresearch", repo / "autoresearch")
        manifest_path = repo / "autoresearch" / "MANIFEST.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["workload_registry"]["groups"].pop("cuda")
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        shutil.copy2(ROOT / ".gitignore", repo / ".gitignore")
        self._git(repo, "add", ".")
        self._git(repo, "commit", "-qm", "base")
        anchor = self._git(repo, "rev-parse", "HEAD")

        epochs_path = ledger.epochs_path(repo)
        epochs = json.loads(epochs_path.read_text())
        epoch = next(item for item in epochs["epochs"] if item["epoch"] == 2)
        epoch["metrics_v2"]["audit_anchor_commit"] = anchor
        epochs_path.write_text(json.dumps(epochs, indent=2) + "\n")
        values = [
            promotion(
                f"audit-fixture-{index}", index,
                predecessor=anchor if index == 1 else f"{index - 1:040x}",
            )
            for index in range(1, 13)
        ]
        ledger.ledger_path(repo).write_text(
            HEADER + "\n"
            + "".join(ledger.serialize_row(value) + "\n" for value in values)
        )
        self._git(repo, "add", "autoresearch/ledger")
        self._git(repo, "commit", "-qm", "make direct audit due")
        return repo, anchor, self._git(repo, "rev-parse", "HEAD")

    @staticmethod
    def _verdict(repo: Path, item: dict) -> dict:
        manifest = manifest_mod.load(repo)
        workload = manifest.workloads(
            item["workload_class"], board=item["board"],
        )[0]
        guards = {
            name: {"pass": True}
            for name in audits.runner.guard_registry(manifest)["workloads"]
        }
        return {
            "kind": "judged",
            "audit_mode": True,
            "harness_commit": item["candidate_commit"],
            "repo_commit": item["candidate_commit"],
            "predecessor_commit": item["predecessor_commit"],
            "scope": "s5",
            "declared_objective": {
                "board": item["board"],
                "workload_class": item["workload_class"],
                "dimension": "time",
            },
            "environment": {"judge_lock_held": True},
            "gates": {f"G{index}": {"pass": True} for index in range(1, 6)},
            "guards": guards,
            "rust_oracle": [{"verified": True}],
            "holdout": None,
            "score": {
                "R_geomean": 0.9,
                "significant": True,
                "neutral": False,
                "per_workload": {
                    workload.workload_id: {
                        "ci": [0.88, 0.92],
                        "b_median_ms": 2.5,
                        "proof_bytes": 4096,
                        "rounds": 10,
                    },
                },
            },
            "search_health": {
                "decision": {"configured_rounds": 5, "target_rounds": 10},
                "measurement_wall_seconds": 12.5,
            },
        }

    def test_blocked_head_is_reported_while_later_due_cell_executes(self):
        blocked = {
            "item_id": "sha256:" + "1" * 64,
            "board": "core_cpu",
            "workload_class": "small",
            "evidence_kind": "span_audit",
            "runnable": False,
            "blocked_reason": "span is not runnable",
        }
        runnable = {
            "item_id": "sha256:" + "2" * 64,
            "board": "core_cpu",
            "workload_class": "wide",
            "evidence_kind": "direct_audit",
            "runnable": True,
            "blocked_reason": None,
        }
        deferred = {
            **runnable,
            "item_id": "sha256:" + "3" * 64,
            "workload_class": "deep",
        }
        plan_fixture = {"items": [blocked, runnable, deferred]}
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "judge.lock"
            lock.write_text("held\n")
            with (
                mock.patch.object(audits, "validate_plan"),
                mock.patch.object(audits, "load_manifest", return_value=object()),
                mock.patch.object(
                    audits.runner, "acquire_judge_lock", return_value=lock,
                ),
                mock.patch.object(
                    audits, "_execute_item", return_value={"verdict": True},
                ) as execute,
            ):
                result = audits.execute_plan(
                    ROOT, plan_fixture, Path(raw) / "runs", max_items=1,
                )

        execute.assert_called_once_with(
            ROOT, mock.ANY, runnable, mock.ANY,
        )
        self.assertEqual(result["executed_item_ids"], [runnable["item_id"]])
        self.assertEqual(result["verdicts"], [{"verdict": True}])
        self.assertEqual(result["blocked_items"], [{
            "item_id": blocked["item_id"],
            "board": "core_cpu",
            "workload_class": "small",
            "evidence_kind": "span_audit",
            "blocked_reason": "span is not runnable",
        }])

    def test_execute_finalize_and_replay_validated_append(self):
        with tempfile.TemporaryDirectory() as raw:
            repo, anchor, candidate = self._audit_repo(Path(raw))
            plan_fixture = audits.plan_repository(
                repo, board="core_cpu", workload_class="small",
            )
            self.assertEqual(len(plan_fixture["items"]), 1)
            item = plan_fixture["items"][0]
            self.assertEqual(item["predecessor_commit"], anchor)
            self.assertEqual(item["candidate_commit"], candidate)

            predecessor_checkout = None

            def evaluate(candidate_repo, predecessor_repo, *_args, **_kwargs):
                nonlocal predecessor_checkout
                self.assertEqual(candidate_repo, repo)
                predecessor_checkout = predecessor_repo
                self.assertEqual(
                    self._git(predecessor_repo, "rev-parse", "HEAD"), anchor,
                )
                return self._verdict(repo, item)

            lock = Path(raw) / "judge.lock"
            lock.write_text("held\n")
            with (
                mock.patch.object(audits.runner, "evaluate", side_effect=evaluate),
                mock.patch.object(
                    audits.runner, "acquire_judge_lock", return_value=lock,
                ),
                mock.patch.dict(os.environ, {"JUDGE_HMAC_SECRET": "audit-secret"}),
            ):
                unsigned = audits.execute_plan(
                    repo, plan_fixture, Path(raw) / "runs", max_items=1,
                )
                self.assertEqual(unsigned["executed_item_ids"], [item["item_id"]])
                self.assertEqual(unsigned["blocked_items"], [])
                self.assertIsNotNone(predecessor_checkout)
                self.assertFalse(predecessor_checkout.exists())

                bundle = audits.finalize(repo, unsigned)
                self.assertEqual(bundle["blocked_items"], [])
                self.assertEqual(len(bundle["evidence"]), 1)
                audits.signing.verify(bundle["evidence"][0]["signed_verdict"])

                before = ledger.ledger_path(repo).read_text()
                invalid = copy.deepcopy(bundle)
                invalid_row = invalid["evidence"][0]["ledger_row"]
                invalid_row["credit_replaces"] = invalid_row["credit_replaces"][:-1]
                invalid_row["row_id"] = ledger.compute_row_id(invalid_row)
                invalid["evidence"][0]["ledger_tsv"] = ledger.serialize_row(invalid_row)
                invalid_body = {
                    key: value for key, value in invalid.items()
                    if key != "bundle_sha256"
                }
                invalid["bundle_sha256"] = audits._canonical_digest(invalid_body)
                with self.assertRaisesRegex(
                    metrics.MetricsError, "credit_replaces is not the exact active set",
                ):
                    audits.append_signed(repo, invalid)
                self.assertEqual(ledger.ledger_path(repo).read_text(), before)

                self.assertEqual(audits.append_signed(repo, bundle), 1)

            appended = ledger.load(repo)[-1]
            self.assertEqual(appended.evidence_kind, "direct_audit")
            self.assertEqual(appended.predecessor, anchor)
            self.assertEqual(tuple(appended.credit_replaces), tuple(item["credit_replaces"]))


if __name__ == "__main__":
    unittest.main()
