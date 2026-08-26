"""Focused contracts for infrastructure row uniqueness and recurrence lemmas."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_infrastructure_uniqueness as uniqueness
from scripts.air_satisfaction_lib import infrastructure
from scripts.air_satisfaction_lib.dump import Component
from scripts.air_satisfaction_lib.field import P


ROOT = Path(__file__).resolve().parents[2]


def dense_component(kind: str, row: tuple[int, ...]) -> Component:
    log_size = 2
    rows = (row,) + ((0,) * len(row),) * ((1 << log_size) - 1)
    return Component(
        family=kind,
        index=0,
        log_size=log_size,
        n_rows=1,
        n_columns=len(row),
        rows=rows,
        class_="infra",
    )


def independent_requests(
    kind: str,
    row: tuple[int, ...],
) -> tuple[uniqueness.RelationRequest, ...]:
    violations, _, requests = infrastructure.check_component(
        dense_component(kind, row)
    )
    if violations:
        raise AssertionError(violations)
    return tuple(
        uniqueness.RelationRequest(item.domain, item.numerator, item.values)
        for item in requests
    )


class ProgramRowTests(unittest.TestCase):
    def test_program_address_radix_is_injective_and_nonwrapping(self) -> None:
        certificate = uniqueness.program_address_certificate()

        self.assertEqual(1 << 28, certificate.represented_values)
        self.assertEqual((1 << 30) - 4, certificate.maximum_integer_recomposition)
        self.assertTrue(certificate.decomposition_injective_mod_field)
        self.assertTrue(certificate.integer_recomposition_does_not_wrap)

        analogue = uniqueness.exhaust_radix_uniqueness(
            radix=4,
            high_bound_exclusive=3,
            multiplier=4,
            modulus=17,
        )
        self.assertEqual(12, analogue.represented_pairs)
        self.assertEqual(1, analogue.maximum_decompositions_per_residue)
        self.assertTrue(analogue.unique)

        # The checker reports collisions rather than applying the theorem
        # outside its hypotheses.
        self.assertEqual(
            ((1, 0), (2, 4)),
            uniqueness.radix_decompositions(
                1,
                radix=4,
                high_bound_exclusive=5,
                multiplier=1,
                modulus=17,
            ),
        )

    def test_program_relation_matches_independent_infrastructure_transcription(self) -> None:
        row = uniqueness.ProgramRow.from_word(
            0x1234_5000,
            (10, 11, 12, 13),
            3,
            99,
        )
        self.assertEqual((), uniqueness.program_row_violations(row))
        expected = independent_requests(
            "program",
            (
                1,
                row.addr,
                *row.values,
                row.multiplicity,
                row.root,
                row.low20,
                row.high8,
            ),
        )
        self.assertEqual(expected, uniqueness.program_requests(row))

        bad = uniqueness.ProgramRow(
            row.addr,
            row.values,
            row.multiplicity,
            row.root,
            row.low20 + 1,
            row.high8,
        )
        self.assertIn(
            "byte address does not equal four times the decomposed word address",
            uniqueness.program_row_violations(bad),
        )

    def test_program_binding_is_conditional_on_all_three_global_premises(self) -> None:
        first = uniqueness.ProgramRow.from_word(0x1000, (1, 2, 3, 4), 2, 77)
        second = uniqueness.ProgramRow.from_word(0x1004, (5, 6, 7, 8), 1, 77)
        fetches = (
            first.program_tuple(),
            second.program_tuple(),
            first.program_tuple(),
        )
        result = uniqueness.verify_program_binding(
            (first, second),
            fetches,
            public_root=77,
        )
        self.assertTrue(result.valid)
        self.assertTrue(result.exact_program_multiset)
        self.assertTrue(result.common_public_root)
        self.assertTrue(result.canonical_leaf_map)
        self.assertTrue(result.field_coefficient_lift_safe)

        wrong_root = uniqueness.verify_program_binding(
            (first, second),
            fetches,
            public_root=78,
        )
        self.assertFalse(wrong_root.valid)
        self.assertIn("public program root", wrong_root.reason)

        duplicate_leaf = uniqueness.verify_program_binding(
            (first, first),
            (first.program_tuple(),) * 4,
            public_root=77,
        )
        self.assertFalse(duplicate_leaf.valid)
        self.assertIn("same leaf address", duplicate_leaf.reason)

        wrong_multiset = uniqueness.verify_program_binding(
            (first, second),
            fetches[:-1],
            public_root=77,
        )
        self.assertFalse(wrong_multiset.valid)
        self.assertIn("program_access", wrong_multiset.reason)

    def test_program_overclaims_have_concrete_admissible_pairs(self) -> None:
        counterexamples = uniqueness.program_counterexamples()
        self.assertEqual(2, len(counterexamples))
        self.assertTrue(all(item.both_row_local_admissible for item in counterexamples))
        self.assertEqual(("root",), counterexamples[0].differing_fields)
        self.assertEqual(("multiplicity",), counterexamples[1].differing_fields)


class MemoryBoundaryAndChainTests(unittest.TestCase):
    def test_memory_boundary_relation_matches_independent_transcription(self) -> None:
        row = uniqueness.MemoryBoundaryRow(
            0x1000,
            9,
            (1, 2, 3, 4),
            -1,
            99,
        )
        self.assertEqual((), uniqueness.memory_boundary_row_violations(row))
        expected = independent_requests(
            "memory",
            (row.addr, row.clock, *row.values, P - 1, row.root),
        )
        self.assertEqual(expected, uniqueness.memory_boundary_requests(row))

        bad_byte = uniqueness.MemoryBoundaryRow(
            row.addr,
            row.clock,
            (1, 2, 3, 256),
            row.sign,
            row.root,
        )
        self.assertIn(
            "value[3] is outside its byte lookup",
            uniqueness.memory_boundary_row_violations(bad_byte),
        )

    def test_boundary_sign_and_root_are_explicit_nonuniqueness(self) -> None:
        counterexamples = uniqueness.memory_boundary_counterexamples()
        self.assertEqual(2, len(counterexamples))
        self.assertTrue(all(item.both_row_local_admissible for item in counterexamples))
        self.assertEqual(("sign",), counterexamples[0].differing_fields)
        self.assertEqual(("root",), counterexamples[1].differing_fields)

    def test_exact_balance_and_strict_clocks_force_one_value_chain(self) -> None:
        initial = uniqueness.MemoryState(1, 0x1000, 0, (1, 2, 3, 4))
        bridged = uniqueness.MemoryState(1, 0x1000, 7, (1, 2, 3, 4))
        written = uniqueness.MemoryState(1, 0x1000, 9, (5, 6, 7, 8))
        transitions = (
            uniqueness.MemoryTransition(initial, bridged, "clock_update"),
            uniqueness.MemoryTransition(bridged, written, "opcode"),
        )
        result = uniqueness.verify_offline_memory_chain(
            initial, written, transitions
        )
        self.assertTrue(result.valid)
        self.assertEqual((0, 7, 9), result.ordered_clocks)
        self.assertEqual(
            (initial.values, bridged.values, written.values),
            result.ordered_values,
        )

        forged_previous = uniqueness.MemoryState(
            1, 0x1000, 7, (9, 2, 3, 4)
        )
        forged = uniqueness.verify_offline_memory_chain(
            initial,
            written,
            (
                transitions[0],
                uniqueness.MemoryTransition(forged_previous, written, "opcode"),
            ),
        )
        self.assertFalse(forged.valid)
        self.assertFalse(forged.exact_relation_balance)
        self.assertIn("net coefficient", forged.reason)

    def test_closure_alone_admits_a_detached_cycle_but_clock_order_rejects_it(self) -> None:
        counterexample = uniqueness.detached_memory_cycle_counterexample()

        self.assertTrue(counterexample.exact_relation_balance)
        self.assertTrue(counterexample.rejected_by_strict_clock_lemma)
        result = uniqueness.verify_offline_memory_chain(
            counterexample.initial,
            counterexample.final,
            counterexample.transitions,
        )
        self.assertFalse(result.valid)
        self.assertIn("not strictly increasing", result.reason)

    def test_integer_graph_model_rejects_noncanonical_field_aliases(self) -> None:
        initial = uniqueness.MemoryState(1, 7, 0, (1, 2, 3, 4))
        final = uniqueness.MemoryState(1, 7, P, (1, 2, 3, 4))

        result = uniqueness.verify_offline_memory_chain(
            initial,
            final,
            (uniqueness.MemoryTransition(initial, final),),
        )

        self.assertFalse(result.valid)
        self.assertIn("not a canonical field element", result.reason)

    def test_derived_subclocks_reject_the_old_self_cancelling_alias_forgery(self) -> None:
        counterexample = uniqueness.same_clock_alias_counterexample()

        self.assertEqual("ADD x3, x1, x1", counterexample.architectural_scenario)
        self.assertTrue(counterexample.legacy_exact_relation_balance)
        self.assertFalse(counterexample.derived_subclock_exact_relation_balance)
        self.assertTrue(counterexample.forged_value_differs_from_honest_value)
        self.assertTrue(
            counterexample.legacy_second_source_term_is_identically_zero
        )
        self.assertFalse(
            counterexample.derived_second_source_term_is_identically_zero
        )
        self.assertTrue(counterexample.derived_forgery_rejected)
        self.assertEqual(
            counterexample.legacy_transitions[1].previous,
            counterexample.legacy_transitions[1].next,
        )
        self.assertNotEqual(
            counterexample.derived_subclock_transitions[1].previous,
            counterexample.derived_subclock_transitions[1].next,
        )
        self.assertIn("no longer balances", counterexample.consequence)

    def test_small_offline_memory_graph_is_exhausted(self) -> None:
        certificate = uniqueness.exhaustive_offline_memory_analogue()

        self.assertEqual(12, certificate.candidate_edges)
        self.assertEqual(8_192, certificate.cases_checked)
        self.assertEqual(6, certificate.exactly_balanced_cases)
        self.assertEqual(0, certificate.balanced_cases_rejected_by_path_lemma)


class MerkleNodeTests(unittest.TestCase):
    def test_merkle_relation_matches_independent_transcription(self) -> None:
        row = uniqueness.MerkleNodeRow(18, 9, 10, 11, 12, 1, 2, 1, 99)
        self.assertEqual((), uniqueness.merkle_row_violations(row))
        expected = independent_requests(
            "merkle",
            (
                1,
                row.index,
                row.depth,
                row.lhs,
                row.rhs,
                row.current,
                row.lhs_multiplicity,
                row.rhs_multiplicity,
                row.current_multiplicity,
                row.root,
            ),
        )
        self.assertEqual(expected, uniqueness.merkle_requests(row))

    def test_even_index_has_integer_parent_while_odd_index_is_only_field_half(self) -> None:
        even = uniqueness.merkle_row_certificate(
            uniqueness.MerkleNodeRow(18, 9, 1, 2, 3, 1, 1, 1, 7)
        )
        odd = uniqueness.merkle_row_certificate(
            uniqueness.MerkleNodeRow(19, 9, 1, 2, 3, 1, 1, 1, 7)
        )

        self.assertEqual(9, even.field_parent_index)
        self.assertTrue(even.integer_parent_is_floor_half)
        self.assertTrue(even.left_parity_zero)
        self.assertTrue(even.right_parity_one)
        self.assertTrue(odd.field_left_recurrence)
        self.assertFalse(odd.canonical_even_base_index)
        self.assertFalse(odd.integer_parent_is_floor_half)

    def test_root_connected_paths_force_index_parity_and_exclude_depth_cycles(self) -> None:
        certificate = uniqueness.merkle_connectivity_certificate()

        self.assertEqual(30, certificate.path_depth)
        self.assertEqual(1 << 12, certificate.exhaustive_paths_checked)
        self.assertEqual(12 * (1 << 12), certificate.exhaustive_edges_checked)
        self.assertEqual((1 << 30) - 1, certificate.maximum_leaf_index)
        self.assertTrue(certificate.every_connected_base_index_even)
        self.assertTrue(certificate.every_leaf_index_is_unique_binary_path)
        self.assertTrue(certificate.every_connected_path_keeps_one_root)
        self.assertTrue(certificate.detached_cycle_excluded)
        self.assertTrue(certificate.detached_depth_cycle_excluded)
        self.assertEqual(P - 1, certificate.maximum_all_source_side_coefficient)
        self.assertEqual(3, certificate.maximum_public_root_coefficient)
        self.assertTrue(certificate.every_coefficient_side_below_field)
        self.assertTrue(certificate.field_balance_lifts_to_integer_balance)
        self.assertTrue(certificate.all_detached_components_excluded)
        self.assertTrue(certificate.conditional_on_integer_coefficient_lift)

    def test_legacy_merkle_wrap_witness_is_rejected_by_production_guard(self) -> None:
        production = uniqueness.merkle_field_coefficient_wrap_counterexample()
        self.assertEqual(P, production.ordinary_coefficient)
        self.assertEqual(0, production.field_coefficient)
        self.assertEqual((P + 1) // 2, production.active_rows)
        self.assertTrue(production.admitted_by_rows_less_than_modulus)
        self.assertFalse(production.admitted_by_production_node_guard)
        self.assertFalse(production.depth_cycle_present)

        analogue = uniqueness.merkle_field_coefficient_wrap_counterexample(17)
        self.assertEqual(8, analogue.coefficient_two_rows)
        self.assertEqual(1, analogue.coefficient_one_rows)
        self.assertEqual(9, analogue.active_rows)
        self.assertEqual(17, 2 * analogue.coefficient_two_rows + 1)
        self.assertEqual(0, analogue.field_coefficient)
        self.assertFalse(analogue.admitted_by_production_node_guard)

    def test_merkle_overclaims_have_concrete_admissible_pairs(self) -> None:
        counterexamples = uniqueness.merkle_counterexamples()
        self.assertEqual(3, len(counterexamples))
        self.assertTrue(all(item.both_row_local_admissible for item in counterexamples))
        self.assertEqual(
            {("index",), ("current",), ("root",)},
            {item.differing_fields for item in counterexamples},
        )


class ClockUpdateTests(unittest.TestCase):
    def test_clock_relation_matches_independent_transcription(self) -> None:
        row = uniqueness.ClockUpdateRow.from_previous(
            1,
            0x1000,
            (15 << 20) + 7,
            (1, 2, 3, 4),
        )
        self.assertEqual((), uniqueness.clock_update_row_violations(row))
        expected = independent_requests(
            "clock_update",
            (
                1,
                row.addr_space,
                row.addr,
                row.previous_clock,
                *row.values,
                row.low20,
                row.high6,
            ),
        )
        self.assertEqual(expected, uniqueness.clock_update_requests(row))
        self.assertEqual(
            row.previous_clock + uniqueness.MAX_CLOCK_DIFF,
            uniqueness.clock_update_requests(row)[1].values[2],
        )

    def test_clock_predecessor_decomposition_and_successor_are_unique(self) -> None:
        certificate = uniqueness.clock_row_certificate()
        self.assertEqual(1 << 26, certificate.predecessor_bound_exclusive)
        self.assertEqual((1 << 26) - 1, certificate.maximum_predecessor)
        self.assertEqual(
            (1 << 26) - 1 + (1 << 20) - 1,
            certificate.maximum_output_clock,
        )
        self.assertTrue(certificate.predecessor_decomposition_unique)
        self.assertTrue(certificate.output_does_not_wrap_field)
        self.assertTrue(certificate.address_and_value_preserved)

        analogue = uniqueness.exhaust_radix_uniqueness(
            radix=4,
            high_bound_exclusive=3,
            multiplier=1,
            modulus=17,
        )
        self.assertTrue(analogue.unique)

    def test_clock_row_does_not_locally_range_carried_memory_fields(self) -> None:
        counterexamples = uniqueness.clock_counterexamples()
        self.assertEqual(2, len(counterexamples))
        self.assertTrue(all(item.both_row_local_admissible for item in counterexamples))
        self.assertEqual(
            {("addr_space",), ("values",)},
            {item.differing_fields for item in counterexamples},
        )

    def test_existing_wrapped_attack_is_the_counterexample_to_unbounded_clocks(self) -> None:
        attack = uniqueness.riscv_state_chain_recurrence.old_wrapped_cycle_counterexample()
        self.assertTrue(attack.closes_mod_field)
        self.assertTrue(attack.every_gap_was_in_old_window)
        self.assertEqual(65, attack.first_rejected_row_zero_based)
        self.assertGreaterEqual(
            attack.first_rejected_predecessor,
            uniqueness.CLOCK_PREDECESSOR_BOUND,
        )


class ProductionBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        for relative in uniqueness.PRODUCTION_PATHS:
            target = self.repo / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text((ROOT / relative).read_text(encoding="utf-8"), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def mutate(self, relative: Path, old: str, new: str) -> None:
        path = self.repo / relative
        source = path.read_text(encoding="utf-8")
        self.assertIn(old, source)
        path.write_text(source.replace(old, new, 1), encoding="utf-8")

    def test_contract_is_bound_to_all_four_infrastructure_relations(self) -> None:
        contract = uniqueness.check_production_contract(self.repo)
        self.assertEqual(P, contract.source_modulus)
        self.assertEqual(uniqueness.INV2, contract.source_inverse_two)
        self.assertEqual(30, contract.source_merkle_depth)
        self.assertEqual(20, contract.source_clock_low_bits)
        self.assertEqual(6, contract.source_clock_high_bits)
        self.assertEqual(len(uniqueness.SOURCE_BINDINGS), contract.bindings_checked)
        self.assertGreaterEqual(contract.bindings_checked, 66)
        self.assertIn("memory rows", contract.memory_coefficient_rule)

    def test_every_declared_source_binding_is_unique_and_fails_closed(self) -> None:
        for label, relative, fragment in uniqueness.SOURCE_BINDINGS:
            with self.subTest(binding=label):
                path = self.repo / relative
                original = path.read_text(encoding="utf-8")
                compact = uniqueness._compact(original)
                self.assertEqual(
                    1,
                    compact.count(fragment),
                    f"{label} must identify exactly one production fragment",
                )
                path.write_text(
                    compact.replace(fragment, "/* mutated premise */", 1),
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(AssertionError) as raised:
                        uniqueness.check_production_contract(self.repo)
                    self.assertIn(label, str(raised.exception))
                finally:
                    path.write_text(original, encoding="utf-8")
                path.write_text(
                    compact.replace(fragment, f"{fragment} {fragment}", 1),
                    encoding="utf-8",
                )
                try:
                    with self.assertRaises(AssertionError) as raised:
                        uniqueness.check_production_contract(self.repo)
                    self.assertIn(label, str(raised.exception))
                    self.assertIn("found 2", str(raised.exception))
                finally:
                    path.write_text(original, encoding="utf-8")

    def test_parsed_production_constants_fail_closed_under_mutation(self) -> None:
        cases = (
            (
                uniqueness.M31_PATH,
                "pub const Modulus: u32 = 0x7fffffff;",
                "pub const Modulus: u32 = 0x7ffffffd;",
                "modulus drifted",
            ),
            (
                uniqueness.MERKLE_NODE_PATH,
                "M31.fromU64(1073741824)",
                "M31.fromU64(1073741823)",
                "INV2 drifted",
            ),
            (
                uniqueness.SPARSE_MERKLE_PATH,
                "pub const LEAF_DEPTH: u32 = 30;",
                "pub const LEAF_DEPTH: u32 = 29;",
                "Merkle depth drifted",
            ),
            (
                uniqueness.STATE_CHAIN_PATH,
                "pub const CLOCK_PREV_HIGH_BITS: u5 = 6;",
                "pub const CLOCK_PREV_HIGH_BITS: u5 = 5;",
                "clock radix drifted",
            ),
            (
                uniqueness.STATE_CHAIN_PATH,
                "pub const MAX_CLOCK_DIFF: u32 = (1 << 20) - 1;",
                "pub const MAX_CLOCK_DIFF: u32 = (1 << 19) - 1;",
                "maximum clock gap",
            ),
        )
        for relative, old, new, error in cases:
            with self.subTest(path=str(relative), mutation=old):
                path = self.repo / relative
                original = path.read_text(encoding="utf-8")
                self.mutate(relative, old, new)
                try:
                    with self.assertRaisesRegex(AssertionError, error):
                        uniqueness.check_production_contract(self.repo)
                finally:
                    path.write_text(original, encoding="utf-8")

        modulus_path = self.repo / uniqueness.M31_PATH
        original = modulus_path.read_text(encoding="utf-8")
        declaration = "pub const Modulus: u32 = 0x7fffffff;"
        modulus_path.write_text(
            original.replace(declaration, f"{declaration}\n{declaration}", 1),
            encoding="utf-8",
        )
        try:
            with self.assertRaisesRegex(
                AssertionError,
                "uniquely locate the production M31 modulus: found 2",
            ):
                uniqueness.check_production_contract(self.repo)
        finally:
            modulus_path.write_text(original, encoding="utf-8")

    def test_program_relation_mutation_fails_closed(self) -> None:
        self.mutate(
            uniqueness.PROGRAM_INTERACTION_PATH,
            "appendGeneric(S, &list, .program_access, main[6],",
            "appendGeneric(S, &list, .memory_access, main[6],",
        )
        with self.assertRaisesRegex(AssertionError, "program tuple emission"):
            uniqueness.check_production_contract(self.repo)

    def test_memory_transition_and_boundary_mutations_fail_closed(self) -> None:
        self.mutate(
            uniqueness.MEMORY_INTERACTION_PATH,
            "const multiplicity_squared = multiplicity.square();",
            "const multiplicity_squared = multiplicity;",
        )
        with self.assertRaisesRegex(
            AssertionError, "memory multiplicity square definition"
        ):
            uniqueness.check_production_contract(self.repo)

    def test_memory_second_range_mutation_fails_closed(self) -> None:
        self.mutate(
            uniqueness.MEMORY_INTERACTION_PATH,
            "appendGeneric(S, &list, .range_check_8_8, enabler.neg(), .{ values[2], values[3] });",
            "appendGeneric(S, &list, .range_check_8_8, enabler.neg(), .{ values[2], values[2] });",
        )
        with self.assertRaisesRegex(
            AssertionError, "memory second byte range pair"
        ):
            uniqueness.check_production_contract(self.repo)

    def test_merkle_parent_mutation_fails_closed(self) -> None:
        self.mutate(
            uniqueness.MERKLE_NODE_PATH,
            "depth.sub(one), cur, root",
            "depth.add(one), cur, root",
        )
        with self.assertRaisesRegex(AssertionError, "Merkle parent"):
            uniqueness.check_production_contract(self.repo)

    def test_clock_successor_mutation_fails_closed(self) -> None:
        self.mutate(
            uniqueness.CLOCK_INTERACTION_PATH,
            "row.clock_prev.add(qGeneric(S, state_chain.MAX_CLOCK_DIFF))",
            "row.clock_prev.sub(qGeneric(S, state_chain.MAX_CLOCK_DIFF))",
        )
        with self.assertRaisesRegex(AssertionError, "clock next tuple"):
            uniqueness.check_production_contract(self.repo)

    def test_offline_memory_transition_mutation_fails_closed(self) -> None:
        self.mutate(
            uniqueness.MEMORY_LOGUP_PATH,
            "self.previous_clock,",
            "self.clock,",
        )
        with self.assertRaisesRegex(AssertionError, "offline memory previous tuple"):
            uniqueness.check_production_contract(self.repo)


class ReportTests(unittest.TestCase):
    def test_cli_emits_reviewable_claims_counterexamples_and_scope(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                0,
                uniqueness.main(["--repo-root", str(ROOT)]),
            )
        payload = json.loads(output.getvalue())

        self.assertEqual(
            "stwo-riscv-infrastructure-uniqueness-v1",
            payload["schema"],
        )
        self.assertTrue(
            payload["tier_2_row_local"]["program"]["address"][
                "decomposition_injective_mod_field"
            ]
        )
        self.assertTrue(
            payload["tier_3_cross_row"]["offline_memory_path"]["valid"]
        )
        self.assertTrue(
            payload["tier_3_cross_row"]["closure_only_counterexample"][
                "exact_relation_balance"
            ]
        )
        self.assertTrue(
            payload["tier_3_cross_row"]["same_clock_alias_counterexample"][
                "derived_forgery_rejected"
            ]
        )
        self.assertTrue(
            payload["tier_3_cross_row"]["merkle_connectivity"][
                "all_detached_components_excluded"
            ]
        )
        self.assertEqual(
            0,
            payload["tier_3_cross_row"][
                "merkle_field_coefficient_wrap_counterexample"
            ]["field_coefficient"],
        )
        self.assertIn("assumes", payload["scope"])
        self.assertIn("field-to-integer", payload["scope"]["proves"])
        self.assertIn("does_not_prove", payload["scope"])


if __name__ == "__main__":
    unittest.main()
