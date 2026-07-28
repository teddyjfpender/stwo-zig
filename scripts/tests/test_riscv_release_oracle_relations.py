"""Fail-closed tests for CP-11 relation evidence parsing and comparison."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from riscv_release_oracle_lib import relations  # noqa: E402
from riscv_release_oracle_lib import superseded_air  # noqa: E402
from riscv_release_oracle_lib import nonempty_relations  # noqa: E402
from riscv_release_oracle_lib import public_input_fixture  # noqa: E402


EMPTY = relations.EMPTY_TUPLE_DIGEST
FULL = "1" * 64
ZERO = "2" * 64
NONZERO = "3" * 64
P = relations.M31_MODULUS


def binding_line() -> str:
    return (
        "binding=zig_diagnostic challenge_mode=pinned_default_blake2s_v1 "
        f"implementation_commit={'a' * 40} implementation_dirty=false "
        f"oracle_commit={'b' * 40} elf_sha256={'4' * 64} "
        f"input_sha256={relations.EMPTY_INPUT_DIGEST} "
        f"witness_layout_sha256={'5' * 64} "
        f"diagnostic_preprocessed_commitment={'6' * 64} "
        f"diagnostic_main_commitment={'7' * 64} "
        f"diagnostic_interaction_commitment={'8' * 64}"
    )


def stream_line(
    identity: str,
    name: str,
    zero_count: int,
    active: bool,
    active_digest: str = NONZERO,
) -> str:
    nonzero_count = int(active)
    entries = zero_count + nonzero_count
    return (
        f"{identity}={name} entries={entries} digest={FULL if entries else EMPTY} "
        f"zero_entries={zero_count} zero_digest={ZERO if zero_count else EMPTY} "
        f"nonzero_entries={nonzero_count} "
        f"nonzero_digest={active_digest if nonzero_count else EMPTY}"
    )


def tuple_dump(
    padding: int = 1,
    active_digest: str = NONZERO,
    *,
    bound: bool = True,
) -> str:
    lines = [
        "schema=riscv-relation-tuples-v3"
        if bound else "schema=riscv-relation-tuples-v2"
    ]
    if bound:
        lines.append(binding_line())
    aggregate_zero = 0
    for component_index, component in enumerate(relations.COMPONENTS):
        active = component_index == 0
        zero_count = padding
        aggregate_zero += zero_count
        lines.append(stream_line(
            "component", component, zero_count, active, active_digest
        ))
        for relation_index, relation in enumerate(relations.RELATIONS):
            lines.append(stream_line(
                "component_relation",
                f"{component}/{relation}",
                zero_count if relation_index == 0 else 0,
                active and relation_index == 0,
                active_digest,
            ))
    lines.append(stream_line(
        "aggregate", "all_components", aggregate_zero, True, active_digest
    ))
    for relation_index, relation in enumerate(relations.RELATIONS):
        lines.append(stream_line(
            "aggregate_relation",
            relation,
            aggregate_zero if relation_index == 0 else 0,
            relation_index == 0,
            active_digest,
        ))
    return "\n".join(lines) + "\n"


def qm31(value: tuple[int, int, int, int]) -> str:
    return ",".join(str(limb) for limb in value)


def add(lhs: tuple[int, int, int, int], rhs: tuple[int, int, int, int]):
    return tuple((a + b) % P for a, b in zip(lhs, rhs))


def sum_dump(
    claim_delta: int = 0,
    corrupt_prefix: bool = False,
    unbalanced: bool = False,
    *,
    bound: bool = True,
) -> str:
    lines = [
        "schema=riscv-relation-sums-v2"
        if bound else "schema=riscv-relation-sums-v1"
    ]
    if bound:
        lines.append(binding_line())
    for index, relation in enumerate(relations.RELATIONS):
        lines.append(f"challenge={relation} signature={qm31((index + 1, 0, 0, 0))}")
    prefix = (0, 0, 0, 0)
    claims = []
    for index, component in enumerate(relations.COMPONENTS):
        claim = (1 + (claim_delta if index == 0 else 0), 0, 0, 0)
        claims.append(claim)
        prefix = add(prefix, claim)
        rendered_prefix = add(prefix, (1, 0, 0, 0)) if corrupt_prefix and index == 4 else prefix
        lines.append(
            f"component={component} claim={qm31(claim)} prefix={qm31(rendered_prefix)}"
        )
    for index, relation in enumerate(relations.RELATIONS):
        value = prefix if index == 0 else (0, 0, 0, 0)
        lines.append(f"relation={relation} sum={qm31(value)}")
    compensation = tuple((-limb) % P for limb in prefix)
    if unbalanced:
        compensation = add(compensation, (1, 0, 0, 0))
    public_values = {
        "registers_state": compensation,
        "merkle": (0, 0, 0, 0),
        "memory_access": (0, 0, 0, 0),
    }
    for relation in relations.PUBLIC_RELATIONS:
        lines.append(f"public={relation} sum={qm31(public_values[relation])}")
    public = compensation
    lines.append(
        f"aggregate=native sum={qm31(prefix)} public_sum={qm31(public)} "
        f"balanced_sum={qm31(add(prefix, public))}"
    )
    return "\n".join(lines) + "\n"


class RelationEvidenceTest(unittest.TestCase):
    def test_nonempty_fixture_is_deterministic_and_partial_word_shaped(self) -> None:
        payload = public_input_fixture.build_elf()
        self.assertEqual(707, len(payload))
        self.assertEqual(9, len(public_input_fixture.INPUT))
        self.assertEqual(
            public_input_fixture.ELF_SHA256,
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(
            public_input_fixture.INPUT_SHA256,
            hashlib.sha256(public_input_fixture.INPUT).hexdigest(),
        )

    def test_nonempty_comparison_runs_every_oracle_with_input_and_fails_on_drift(self) -> None:
        public = {
            field: None for field in nonempty_relations.PUBLIC_DATA_FIELDS
        }
        public["io_entries"] = {
            "input_len": 9,
            "input_words": [0x04030201, 0x08070605, 9],
        }
        binding = {
            "implementation_commit": "a" * 40,
            "implementation_dirty": False,
            "oracle_commit": "b" * 40,
            "elf_sha256": public_input_fixture.ELF_SHA256,
            "input_sha256": public_input_fixture.INPUT_SHA256,
            "witness_layout_sha256": "5" * 64,
        }
        calls = []

        def run(command, _cwd):
            calls.append(command)
            return '{"public_data":{}}' if "--relation-tuples" not in command and \
                "--relation-sums" not in command and "--public-values" not in command \
                else "diagnostic"

        tuple_compare = mock.Mock(return_value={
            "agree": True, "first_divergence": None, "binding": dict(binding),
        })
        sum_compare = mock.Mock(return_value={
            "agree": True, "first_divergence": None, "binding": dict(binding),
        })
        parsed_sum = {
            "public": {"memory_access": (1, 0, 0, 0)},
            "aggregate": {"balanced": (0, 0, 0, 0)},
        }
        with mock.patch.object(nonempty_relations, "_run", side_effect=run), \
                mock.patch.object(
                    nonempty_relations, "validate_public_data_shape", return_value=public
                ), mock.patch.object(
                    nonempty_relations, "parse_public_values_diagnostic", return_value=public
                ):
            tuple_case, sum_case = nonempty_relations.compare_or_failure(
                Path("rust"), Path("zig"),
                {"candidate_commit": "a" * 40, "witness_layout_digest_sha256": "5" * 64},
                ROOT, "b" * 40, tuple_compare, sum_compare,
                mock.Mock(return_value=parsed_sum), mock.Mock(return_value=None),
            )
        self.assertTrue(tuple_case["agree"])
        self.assertTrue(sum_case["agree"])
        self.assertEqual(6, len(calls))
        self.assertTrue(all("--input" in command for command in calls))

        tuple_compare.return_value = {
            "agree": False,
            "first_divergence": {"path": "/components/load_store"},
            "binding": dict(binding),
        }
        with mock.patch.object(nonempty_relations, "_run", side_effect=run), \
                mock.patch.object(
                    nonempty_relations, "validate_public_data_shape", return_value=public
                ), mock.patch.object(
                    nonempty_relations, "parse_public_values_diagnostic", return_value=public
                ):
            tuple_case, _ = nonempty_relations.compare_or_failure(
                Path("rust"), Path("zig"),
                {"candidate_commit": "a" * 40, "witness_layout_digest_sha256": "5" * 64},
                ROOT, "b" * 40, tuple_compare, sum_compare,
                mock.Mock(return_value=parsed_sum), mock.Mock(return_value=None),
            )
        self.assertFalse(tuple_case["agree"])

    def compare_with(self, tuple_case: dict, sum_case: dict) -> dict:
        receipt = {"boundaries": {}}
        with mock.patch.object(
            relations, "load_trace_vectors", return_value={"vectors": []}
        ), mock.patch.object(
            nonempty_relations,
            "compare_or_failure",
            return_value=(tuple_case, sum_case),
        ):
            relations.compare_relation_boundaries(
                Path("rust"), receipt, ROOT, "b" * 40
            )
        return receipt["boundaries"]

    def test_nonempty_comparison_controls_boundary_status(self) -> None:
        tuple_case = {
            "agree": False,
            "first_divergence": {"path": "/components/lw"},
            "divergence_paths": ["/components/lw/stream"],
        }
        sum_case = {"agree": True, "first_divergence": None}
        boundaries = self.compare_with(tuple_case, sum_case)
        tuples = boundaries["relation_tuples"]
        self.assertEqual(superseded_air.DIVERGENCE_STATUS, tuples["status"])
        self.assertEqual(superseded_air.LEDGER_REFERENCE, tuples["superseded_by"])
        self.assertEqual(["/components/lw/stream"], tuples["divergence_paths"])
        self.assertEqual(
            superseded_air.shape_digest(["/components/lw/stream"]),
            tuples["divergence_shape_sha256"],
        )
        self.assertEqual(
            {"agree": True, "comparison": relations.RELATION_LINEAGE},
            tuples["lineage"],
        )
        self.assertEqual(tuple_case, tuples["nonempty_public_input"])
        self.assertEqual("pass", boundaries["relation_sums"]["status"])

    def test_unparsable_evidence_clears_the_lineage_verdict(self) -> None:
        """A parse failure is not a layout-lineage agreement, so it cannot pass."""
        boundaries = self.compare_with(
            {"agree": False, "evidence_error": "tuple dump has 3 lines"},
            {"agree": True, "first_divergence": None},
        )
        tuples = boundaries["relation_tuples"]
        self.assertIs(False, tuples["lineage"]["agree"])
        self.assertEqual([], tuples["divergence_paths"])

    def test_tuple_parser_requires_complete_canonical_evidence(self) -> None:
        parsed = relations.parse_tuple_dump(tuple_dump())
        self.assertEqual(1, parsed["aggregate"]["nonzero_entries"])
        lines = tuple_dump().splitlines()
        lines[2], lines[15] = lines[15], lines[2]
        with self.assertRaisesRegex(relations.EvidenceError, "expected component=auipc"):
            relations.parse_tuple_dump("\n".join(lines) + "\n")

    def test_tuple_comparison_ignores_padding_but_localizes_active_drift(self) -> None:
        self.assertTrue(
            relations.compare_tuple_dumps(
                tuple_dump(1, bound=False), tuple_dump(7)
            )["agree"]
        )
        result = relations.compare_tuple_dumps(
            tuple_dump(bound=False), tuple_dump(active_digest="4" * 64)
        )
        self.assertFalse(result["agree"])
        self.assertIn("/components/auipc", result["first_divergence"]["path"])

    def test_sum_parser_checks_prefixes_domain_totals_and_balance(self) -> None:
        parsed = relations.parse_sum_dump(sum_dump())
        self.assertEqual((27, 0, 0, 0), parsed["aggregate"]["native"])
        with self.assertRaisesRegex(relations.EvidenceError, "cumulative prefix drifted"):
            relations.parse_sum_dump(sum_dump(corrupt_prefix=True))
        with self.assertRaisesRegex(
            relations.EvidenceError,
            "relation registers_state is not independently balanced",
        ):
            relations.parse_sum_dump(sum_dump(unbalanced=True))

        lines = sum_dump().splitlines()
        register_index = next(
            index for index, line in enumerate(lines)
            if line.startswith("relation=registers_state ")
        )
        program_index = next(
            index for index, line in enumerate(lines)
            if line.startswith("relation=program_access ")
        )
        lines[register_index] = f"relation=registers_state sum={qm31((28, 0, 0, 0))}"
        lines[program_index] = f"relation=program_access sum={qm31((P - 1, 0, 0, 0))}"
        with self.assertRaisesRegex(
            relations.EvidenceError,
            "relation registers_state is not independently balanced",
        ):
            relations.parse_sum_dump("\n".join(lines) + "\n")

    def test_sum_comparison_localizes_first_component_claim_drift(self) -> None:
        result = relations.compare_sum_dumps(
            sum_dump(bound=False), sum_dump(claim_delta=1)
        )
        self.assertFalse(result["agree"])
        self.assertEqual(
            "/components/auipc/claim",
            result["first_divergence"]["path"],
        )

    def test_comparison_requires_root_bound_zig_evidence(self) -> None:
        with self.assertRaisesRegex(relations.EvidenceError, "root-bound schema v3"):
            relations.compare_tuple_dumps(
                tuple_dump(bound=False), tuple_dump(bound=False)
            )
        with self.assertRaisesRegex(relations.EvidenceError, "root-bound schema v2"):
            relations.compare_sum_dumps(sum_dump(bound=False), sum_dump(bound=False))

    def test_binding_rejects_zero_root_and_bad_challenge_mode(self) -> None:
        tuples = tuple_dump().replace(
            f"diagnostic_main_commitment={'7' * 64}",
            f"diagnostic_main_commitment={'0' * 64}",
        )
        with self.assertRaisesRegex(relations.EvidenceError, "unbound zero digest"):
            relations.parse_tuple_dump(tuples, require_binding=True)
        sums = sum_dump().replace(
            "challenge_mode=pinned_default_blake2s_v1",
            "challenge_mode=production",
        )
        with self.assertRaisesRegex(relations.EvidenceError, "challenge mode"):
            relations.parse_sum_dump(sums, require_binding=True)

    def test_divergence_paths_enumerate_every_difference_not_only_the_first(self) -> None:
        """A pinned divergence shape must see the whole difference set."""
        rust = {"a": {"x": 1, "y": 2}, "b": 3, "only_rust": 4}
        zig = {"a": {"x": 9, "y": 2}, "b": 9, "only_zig": 4}
        self.assertEqual(
            ["/a/x", "/b", "/only_rust", "/only_zig"],
            superseded_air.divergence_paths(rust, zig),
        )
        self.assertEqual([], superseded_air.divergence_paths(rust, dict(rust)))

    def test_shape_digest_is_set_valued_and_order_insensitive(self) -> None:
        self.assertEqual(
            superseded_air.shape_digest(["/b", "/a", "/a"]),
            superseded_air.shape_digest(["/a", "/b"]),
        )
        self.assertNotEqual(
            superseded_air.shape_digest(["/a"]),
            superseded_air.shape_digest(["/a", "/b"]),
        )

    def test_witness_row_divergence_separates_lineage_from_row_content(self) -> None:
        rust = "family=jalr columns=13\nnames=a,b\nrow=1\nfamily=lui columns=4\nnames=c\nrow=2\n"
        rows_differ = rust.replace("row=1", "row=7")
        paths, lineage = superseded_air.witness_row_divergence(rust, rows_differ)
        self.assertEqual(["/jalr/rows"], paths)
        self.assertTrue(lineage)

        columns_differ = rust.replace("names=a,b", "names=a,b,extra")
        paths, lineage = superseded_air.witness_row_divergence(rust, columns_differ)
        self.assertEqual(["/jalr/columns"], paths)
        self.assertFalse(lineage)

        family_missing = "family=jalr columns=13\nnames=a,b\nrow=1\n"
        paths, lineage = superseded_air.witness_row_divergence(rust, family_missing)
        self.assertEqual(["/families/lui"], paths)
        self.assertFalse(lineage)

    def test_witness_row_sections_reject_malformed_dumps(self) -> None:
        with self.assertRaisesRegex(ValueError, "before its first family header"):
            superseded_air.witness_row_sections("row=1\n")
        with self.assertRaisesRegex(ValueError, "duplicate family"):
            superseded_air.witness_row_sections(
                "family=jalr columns=1\nnames=a\nfamily=jalr columns=1\nnames=a\n"
            )
        with self.assertRaisesRegex(ValueError, "no family layouts"):
            superseded_air.witness_row_sections("")


if __name__ == "__main__":
    unittest.main()
