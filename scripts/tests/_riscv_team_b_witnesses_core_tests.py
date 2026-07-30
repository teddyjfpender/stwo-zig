"""Evaluator, schema, mutation, and provenance witness tests."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_team_b_witnesses as witnesses
from scripts.tests._riscv_team_b_witnesses_support import export_air


class EvaluatorTest(unittest.TestCase):
    def _payload(self) -> dict:
        return {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "col", "name": "a"},
                {"op": "const", "value": 1},
                {"op": "sub", "args": [0, 1]},
            ],
            "constraints": [2],
            "lookups": [],
        }

    def _directory(self, payload: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "toy.json").write_text(json.dumps(payload))
        return root

    def test_unassigned_column_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "unassigned"):
            witnesses.check_witness(root, "toy", {})

    def test_unknown_column_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "does not declare"):
            witnesses.check_witness(root, "toy", {"a": 1, "b": 2})

    def test_unsupported_node_operation_fails_closed(self):
        payload = self._payload()
        payload["nodes"].append({"op": "sqrt", "args": [0]})
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "unsupported AIR node"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_absent_family_fails_closed(self):
        root = self._directory(self._payload())
        with self.assertRaisesRegex(witnesses.WitnessError, "is absent"):
            witnesses.check_witness(root, "nonexistent", {"a": 1})

    def test_inactive_range_request_asserts_nothing(self):
        payload = self._payload()
        payload["nodes"].extend(
            [
                {"op": "const", "value": 0},
                {"op": "const", "value": 999999999},
            ]
        )
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_20",
                "numerator": 3,
                "tuple": [4],
            }
        ]
        root = self._directory(payload)
        report = witnesses.check_witness(root, "toy", {"a": 1})
        self.assertIn("0 active range requests", report)

    def test_active_out_of_range_request_fails_closed(self):
        payload = self._payload()
        payload["nodes"].extend(
            [
                {"op": "const", "value": 1},
                {"op": "const", "value": 999999999},
            ]
        )
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_20",
                "numerator": 3,
                "tuple": [4],
            }
        ]
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "outside the 20-bit"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_an_unknown_domain_is_an_error_even_when_inactive(self):
        # Classification is a property of the AIR's shape, not of one row: a
        # numerator of zero must not turn an unknown domain into a silent skip.
        payload = self._payload()
        payload["nodes"].append({"op": "const", "value": 0})
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_13",
                "numerator": 3,
                "tuple": [0],
            }
        ]
        root = self._directory(payload)
        with self.assertRaisesRegex(witnesses.WitnessError, "does not know"):
            witnesses.check_witness(root, "toy", {"a": 1})

    def test_column_drift_reports_new_renamed_and_removed(self):
        payload = self._payload()
        payload["columns"] = [
            {"name": "alpha", "role": "witness"},
            {"name": "beta_v2", "role": "witness"},
            {"name": "delta", "role": "witness"},
        ]
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.evaluate(payload, {"alpha": 1, "beta_v1": 2, "gamma": 3})
        message = str(caught.exception)
        self.assertIn("likely NEW in the AIR: delta", message)
        self.assertIn("likely RENAMED: beta_v1 -> beta_v2", message)
        self.assertIn("likely REMOVED from the AIR: gamma", message)
        # The message must also carry the exact re-derivation command.
        self.assertIn("zig build riscv-refinement-ir", message)

    def test_column_drift_still_names_both_raw_column_sets(self):
        # The heuristic classification is advice; the raw diff is the record.
        payload = self._payload()
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.evaluate(payload, {"b": 1})
        message = str(caught.exception)
        self.assertIn("unassigned: a", message)
        self.assertIn("does not declare: b", message)

    def test_every_supported_operation_actually_evaluates(self):
        # Guards SUPPORTED_OPERATIONS against drifting from the dispatch: each
        # advertised operation must evaluate, and this test must exercise the
        # whole advertised set.
        payload = {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "const", "value": 5},
                {"op": "col", "name": "a"},
                {"op": "neg", "args": [0]},
                {"op": "add", "args": [0, 1]},
                {"op": "sub", "args": [0, 1]},
                {"op": "mul", "args": [0, 1]},
            ],
            "constraints": [],
            "lookups": [],
        }
        exercised = {node["op"] for node in payload["nodes"]}
        self.assertEqual(exercised, set(witnesses.SUPPORTED_OPERATIONS))
        values = witnesses.evaluate(payload, {"a": 3})
        self.assertEqual(values, [5, 3, witnesses.M31 - 5, 8, 2, 15])


class SchemaAuditTest(unittest.TestCase):
    """The family-agnostic audit of whatever the export happens to contain."""

    def _directory(self, payload: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / f"{payload['family']}.json").write_text(json.dumps(payload))
        return root

    def _payload(self) -> dict:
        return {
            "family": "toy",
            "columns": [{"name": "a", "role": "witness"}],
            "nodes": [
                {"op": "col", "name": "a"},
                {"op": "const", "value": 0},
            ],
            "constraints": [],
            "lookups": [],
        }

    def test_the_full_production_export_passes_the_audit(self):
        try:
            air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            self.skipTest(f"production AIR export unavailable: {error}")
        report = witnesses.audit_exported_families(air_ir_dir)
        self.assertIn("only supported node operations", report)
        self.assertIn("none ignored", report)

    def test_the_witness_gate_actually_runs_the_audit(self):
        # The audit only closes the new-domain gap if the CI entry point runs
        # it before the per-family witness checks; provenance runs first of
        # all so every later verdict is about a digested, fresh export.
        order = list(witnesses.CHECKS)
        self.assertIs(order[0], witnesses.check_export_provenance)
        audit_at = order.index(witnesses.audit_exported_families)
        for family_check in (
            witnesses.check_lh_witnesses,
            witnesses.check_load_witnesses,
            witnesses.check_div_witnesses,
            witnesses.check_rem_witnesses,
            witnesses.check_multiply_witnesses,
            witnesses.check_shift_witnesses,
            witnesses.check_register_shift_witnesses,
            witnesses.check_store_witnesses,
            witnesses.check_mutation_refusals,
        ):
            self.assertLess(audit_at, order.index(family_check))

    def test_an_unknown_lookup_domain_is_an_error(self):
        payload = self._payload()
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "range_check_640k",
                "numerator": 1,
                "tuple": [0],
            }
        ]
        with self.assertRaises(witnesses.WitnessError) as caught:
            witnesses.audit_exported_families(self._directory(payload))
        message = str(caught.exception)
        self.assertIn("range_check_640k", message)
        self.assertIn("RANGE_DOMAINS or", message)
        self.assertIn("SKIPPED_DOMAINS", message)

    def test_a_known_bus_domain_is_deliberately_skipped_not_ignored(self):
        payload = self._payload()
        payload["lookups"] = [
            {
                "label": "request",
                "domain": "memory_access",
                "numerator": 1,
                "tuple": [0],
            }
        ]
        report = witnesses.audit_exported_families(self._directory(payload))
        self.assertIn("1 deliberately skipped bus domains", report)

    def test_an_unsupported_node_operation_is_an_error(self):
        payload = self._payload()
        payload["nodes"].append({"op": "pow", "args": [0, 1]})
        with self.assertRaisesRegex(witnesses.WitnessError, "does not implement"):
            witnesses.audit_exported_families(self._directory(payload))

    def test_an_empty_export_directory_is_an_error(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        with self.assertRaisesRegex(witnesses.WitnessError, "no exported AIR"):
            witnesses.audit_exported_families(Path(directory.name))

    def test_range_and_skipped_domains_are_disjoint(self):
        # A domain in both sets would make "range-checked" ambiguous.
        overlap = set(witnesses.RANGE_DOMAINS) & set(witnesses.SKIPPED_DOMAINS)
        self.assertEqual(overlap, set())


class MutationBatteryTest(unittest.TestCase):
    """The CLI-invocable battery of rows production must refuse."""

    @classmethod
    def setUpClass(cls):
        try:
            cls.air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"production AIR export unavailable: {error}")

    def test_every_mutation_is_refused_by_production(self):
        report = witnesses.check_mutation_refusals(self.air_ir_dir)
        self.assertIn("all refused", report)

    def test_the_battery_is_wired_into_the_cli_gate(self):
        # The coverage ledger says this script checks "witnesses and their
        # mutations"; that wording is only true if the CLI entry point runs
        # the mutation battery, not just the unittest module.
        self.assertIn(witnesses.check_mutation_refusals, witnesses.CHECKS)

    def test_every_witnessed_family_has_a_mutation_counter_check(self):
        families = {family for _, family, _ in witnesses.mutation_counter_cases()}
        self.assertEqual(
            families, {"load_store", "div", "mulh", "shifts_imm", "shifts_reg"}
        )

    def test_the_required_counter_checks_are_present_by_name(self):
        names = {name for name, _, _ in witnesses.mutation_counter_cases()}
        self.assertIn("sb-clobbered-unselected-byte", names)
        self.assertIn("sb-byte-at-wrong-offset", names)
        self.assertIn("sll-reg-unmasked-shift-amount", names)
        # The per-opcode load and remainder counter-checks (issue #137 F4):
        # a flipped LB sign, a zero-extending LHU claiming a sign, a REM row
        # retiring the quotient, a remainder not below its divisor.
        self.assertIn("lb-flipped-sign-witness", names)
        self.assertIn("lb-zero-extended-negative-byte", names)
        self.assertIn("lhu-claimed-sign-extension", names)
        self.assertIn("rem-retired-the-quotient", names)
        self.assertIn("remu-remainder-not-below-divisor", names)

    def test_mutation_names_are_unique(self):
        names = [name for name, _, _ in witnesses.mutation_counter_cases()]
        self.assertEqual(len(names), len(set(names)))

    def test_an_accepted_mutation_fails_the_gate(self):
        # Feed the battery a family whose constraints accept anything; the
        # gate must fail loudly rather than count it as refused.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for family in ("load_store", "div", "mulh", "shifts_imm", "shifts_reg"):
            sample = next(
                assignment
                for _, fam, assignment in witnesses.mutation_counter_cases()
                if fam == family
            )
            (root / f"{family}.json").write_text(
                json.dumps(
                    {
                        "family": family,
                        "columns": [{"name": name} for name in sample],
                        "nodes": [{"op": "const", "value": 0}],
                        "constraints": [],
                        "lookups": [],
                    }
                )
            )
        with self.assertRaisesRegex(witnesses.WitnessError, "ACCEPTED"):
            witnesses.check_mutation_refusals(root)


class ExportProvenanceTest(unittest.TestCase):
    """The gate digests what it evaluates and refuses a stale export."""

    def _export(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        export = root / "export"
        export.mkdir()
        (export / "toy.json").write_text(
            json.dumps(
                {
                    "family": "toy",
                    "columns": [{"name": "a"}],
                    "nodes": [{"op": "col", "name": "a"}],
                    "constraints": [],
                    "lookups": [],
                }
            )
        )
        return root

    def test_a_fresh_export_reports_its_digest(self):
        root = self._export()
        source = root / "src"
        source.mkdir()
        (source / "air.zig").write_text("// air")
        # Make the source strictly older than the export.
        old = (root / "export" / "toy.json").stat().st_mtime_ns - 10**9
        os.utime(source / "air.zig", ns=(old, old))
        report = witnesses.check_export_provenance(
            root / "export", source_root=source
        )
        self.assertIn("sha256", report)
        self.assertIn("no production AIR source is newer", report)

    def test_a_stale_export_is_refused_with_the_re_derivation_command(self):
        root = self._export()
        source = root / "src"
        source.mkdir()
        (source / "air.zig").write_text("// air")
        new = (root / "export" / "toy.json").stat().st_mtime_ns + 10**9
        os.utime(source / "air.zig", ns=(new, new))
        with self.assertRaisesRegex(witnesses.WitnessError, "STALE") as caught:
            witnesses.check_export_provenance(root / "export", source_root=source)
        self.assertIn("zig build riscv-refinement-ir", str(caught.exception))

    def test_an_absent_source_tree_fails_closed(self):
        root = self._export()
        with self.assertRaisesRegex(witnesses.WitnessError, "freshness"):
            witnesses.check_export_provenance(
                root / "export", source_root=root / "nonexistent"
            )

    def test_the_digest_is_stable_and_content_sensitive(self):
        root = self._export()
        first = witnesses.export_digest(root / "export")
        self.assertEqual(first, witnesses.export_digest(root / "export"))
        (root / "export" / "toy.json").write_text("{}")
        self.assertNotEqual(first, witnesses.export_digest(root / "export"))

    def test_the_real_export_passes_provenance(self):
        try:
            air_ir_dir = export_air()
        except (OSError, subprocess.SubprocessError) as error:
            self.skipTest(f"production AIR export unavailable: {error}")
        report = witnesses.check_export_provenance(air_ir_dir)
        self.assertIn("sha256", report)
