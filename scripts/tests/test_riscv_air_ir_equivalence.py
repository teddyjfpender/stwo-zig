"""Fail-closed tests for symbolic AIR polynomial-equivalence receipts."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_air_ir_equivalence as equivalence


def _air(family: str = "div") -> dict:
    return {
        "family": family,
        "modulus": 2_147_483_647,
        "notes": "test fixture",
        "unmodelled_bus_requests": 1,
        "columns": [
            {"name": "x", "role": "input"},
            {"name": "y", "role": "output"},
        ],
        "nodes": [
            {"op": "col", "name": "x"},
            {"op": "col", "name": "y"},
            {"op": "add", "args": [0, 1]},
            {"op": "mul", "args": [2, 2]},
        ],
        "constraints": [3],
        "lookups": [{
            "label": "request",
            "domain": "range_check_20",
            "numerator": 2,
            "tuple": [3],
        }],
    }


def _reordered_air(family: str = "div") -> dict:
    payload = _air(family)
    payload["nodes"] = [
        {"op": "col", "name": "x"},
        {"op": "col", "name": "y"},
        {"op": "add", "args": [1, 0]},
        {"op": "mul", "args": [2, 0]},
        {"op": "mul", "args": [2, 1]},
        {"op": "add", "args": [3, 4]},
    ]
    payload["constraints"] = [5]
    payload["lookups"] = [{
        "label": "request",
        "domain": "range_check_20",
        "numerator": 2,
        "tuple": [5],
    }]
    return payload


class PolynomialProjectionTest(unittest.TestCase):
    def test_dag_order_and_distributive_shape_do_not_change_semantics(self):
        self.assertNotEqual(_air()["nodes"], _reordered_air()["nodes"])
        self.assertEqual(
            equivalence.semantic_projection(_air()),
            equivalence.semantic_projection(_reordered_air()),
        )
        self.assertEqual(
            equivalence.semantic_digest(_air()),
            equivalence.semantic_digest(_reordered_air()),
        )

    def test_constraint_polynomial_drift_is_detected(self):
        mutated = _reordered_air()
        mutated["constraints"] = [2]
        self.assertNotEqual(
            equivalence.semantic_digest(_air()),
            equivalence.semantic_digest(mutated),
        )

    def test_lookup_role_tuple_and_order_are_semantic(self):
        for mutation in ("label", "domain", "tuple"):
            mutated = copy.deepcopy(_air())
            if mutation == "label":
                mutated["lookups"][0]["label"] = "consume"
            elif mutation == "domain":
                mutated["lookups"][0]["domain"] = "program_access"
            else:
                mutated["lookups"][0]["tuple"] = [2]
            with self.subTest(mutation=mutation):
                self.assertNotEqual(
                    equivalence.semantic_digest(_air()),
                    equivalence.semantic_digest(mutated),
                )

    def test_non_topological_and_unknown_nodes_fail_closed(self):
        for node in (
            {"op": "add", "args": [0, 4]},
            {"op": "inverse", "args": [0]},
        ):
            mutated = _air()
            mutated["nodes"].append(node)
            with self.subTest(node=node):
                with self.assertRaises(equivalence.EquivalenceError):
                    equivalence.semantic_projection(mutated)


class ReceiptFixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.baseline = self.root / "baseline"
        self.candidate = self.root / "candidate"
        self.baseline.mkdir()
        self.candidate.mkdir()
        for family in equivalence.TEAM_B_FAMILIES:
            (self.baseline / f"{family}.json").write_text(
                json.dumps(_air(family)), encoding="utf-8"
            )
            (self.candidate / f"{family}.json").write_text(
                json.dumps(_reordered_air(family)), encoding="utf-8"
            )
        self.sources = self.root / "sources"
        self.sources.mkdir()
        for relative in equivalence.SOURCE_PATHS:
            path = self.sources / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(relative, encoding="utf-8")

    def _receipt(self) -> dict:
        with mock.patch.object(equivalence, "REPOSITORY_ROOT", self.sources):
            return equivalence.build_receipt(self.baseline, self.candidate)

    def _receipt_path(self, receipt: dict) -> Path:
        path = self.root / "receipt.json"
        equivalence.write_receipt(receipt, path)
        return path


class ReceiptTest(ReceiptFixture):
    def test_receipt_binds_all_six_families_and_current_candidate(self):
        receipt = self._receipt()
        report = equivalence.check_receipt(
            self._receipt_path(receipt), self.candidate
        )
        self.assertIn("6 raw exports preserve exact", report)

    def test_semantic_drift_refuses_capture(self):
        mutated = _reordered_air("div")
        mutated["constraints"] = [2]
        (self.candidate / "div.json").write_text(
            json.dumps(mutated), encoding="utf-8"
        )
        with mock.patch.object(equivalence, "REPOSITORY_ROOT", self.sources):
            with self.assertRaisesRegex(
                equivalence.EquivalenceError, "semantic projection drifted"
            ):
                equivalence.build_receipt(self.baseline, self.candidate)

    def test_tampered_receipt_and_candidate_fail_closed(self):
        receipt = self._receipt()
        receipt["families"][0]["candidate_semantic_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            equivalence.EquivalenceError, "receipt digest mismatch"
        ):
            equivalence.check_receipt(
                self._receipt_path(receipt), self.candidate
            )

        receipt = self._receipt()
        mutated = _reordered_air("div")
        mutated["lookups"][0]["tuple"] = [2]
        (self.candidate / "div.json").write_text(
            json.dumps(mutated), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            equivalence.EquivalenceError, "raw AIR digest drifted"
        ):
            equivalence.check_receipt(
                self._receipt_path(receipt), self.candidate
            )


class ReviewedRevisionTest(ReceiptFixture):
    def _revision(self):
        history = self._receipt_path(self._receipt())
        previous = next(r for r in json.loads(history.read_text())["families"]
                        if r["family"] == "load_store")
        path = self.candidate / "load_store.json"
        changed = json.loads(path.read_text())
        changed["constraints"] = [2]
        path.write_text(json.dumps(changed))
        raw = equivalence.sha256_file(path)
        polynomial = equivalence.semantic_digest(changed, "load_store")
        capsule = self.root / "LoadStore.lean"
        capsule.write_text(f'def loadStoreIrDigest : String := "{raw}"\n'
                           f'def loadStorePolynomialDigest : String := "{polynomial}"\n')
        revision = {
            "schema_version": 1, "kind": equivalence.REVISION_KIND,
            "reason": equivalence.REVISION_REASON, "family": "load_store",
            "historical_receipt_sha256": equivalence.sha256_file(history),
            "previous_raw_sha256": previous["candidate_raw_sha256"],
            "previous_semantic_sha256": previous["candidate_semantic_sha256"],
            "current_raw_sha256": raw, "current_semantic_sha256": polynomial,
            "capsule_sha256": equivalence.sha256_file(capsule),
            "current_geometry": {
                "column_count": len(changed["columns"]),
                "constraint_count": len(changed["constraints"]),
                "lookup_count": len(changed["lookups"]),
                "unmodelled_bus_requests": changed["unmodelled_bus_requests"],
            },
            "claim_boundary": {
                "equivalent_to_historical_air": False,
                "reviewed_capsule_binds_current_export": True,
                "lean_proofs_checked_by_this_receipt": False,
                "cross_row_or_multiset_closure": False,
                "witness_generation_equivalence": False,
            },
        }
        return history, capsule, revision

    def _check_revision(self, history, capsule, revision):
        revision["canonical_digest"] = equivalence.canonical_digest(revision)
        path = self.root / "revision.json"
        equivalence.write_receipt(revision, path)
        return equivalence.check_reviewed_revision(history, path, self.candidate, capsule)

    def test_revision_accepts_changed_equations_but_historical_gate_rejects(self):
        history, capsule, revision = self._revision()
        self.assertIn("not equivalent", self._check_revision(history, capsule, revision))
        with self.assertRaisesRegex(equivalence.EquivalenceError, "load_store typed raw"):
            equivalence.check_receipt(history, self.candidate)

    def test_revision_cannot_claim_equivalence_or_replace_another_family(self):
        history, capsule, revision = self._revision()
        for mutate in (
            lambda r: r["claim_boundary"].update(equivalent_to_historical_air=True),
            lambda r: r.update(family="div"),
            lambda r: r.update(previous_raw_sha256="0" * 64),
            lambda r: r.update(historical_receipt_sha256="0" * 64),
            lambda r: r["current_geometry"].update(column_count=999),
        ):
            changed = copy.deepcopy(revision)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(equivalence.EquivalenceError):
                self._check_revision(history, capsule, changed)
        path = self.candidate / "div.json"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(equivalence.EquivalenceError, "div typed raw"):
            self._check_revision(history, capsule, revision)

    def test_revision_binds_export_and_reviewed_capsule_independently(self):
        history, capsule, revision = self._revision()
        capsule.write_text(capsule.read_text().replace("loadStoreIrDigest", "wrongDigest"))
        with self.assertRaisesRegex(equivalence.EquivalenceError, "capsule drifted"):
            self._check_revision(history, capsule, revision)
        revision["capsule_sha256"] = equivalence.sha256_file(capsule)
        with self.assertRaisesRegex(equivalence.EquivalenceError, "capsule export binding"):
            self._check_revision(history, capsule, revision)
        path = self.candidate / "load_store.json"
        path.write_text(path.read_text() + "\n")
        with self.assertRaisesRegex(equivalence.EquivalenceError, "export drifted"):
            self._check_revision(history, capsule, revision)


if __name__ == "__main__":
    unittest.main()
