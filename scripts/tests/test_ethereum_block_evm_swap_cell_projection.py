from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_evm_swap_cell_projection as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def _swap_symbol(index: int) -> str:
    return (
        f"{subject.swap_v1.SWAP_PREFIX}{index}, "
        "revm_interpreter::interpreter::EthInterpreter>"
    )


class EvmSwapCellProjectionTests(unittest.TestCase):
    def test_raw_pc_nm_rows_recompute_exact_family_mix(self) -> None:
        families = subject.FAMILY_ORDER
        members = []
        per_pc = []
        nm_lines = []
        expected = {family: 0 for family in families}
        for index in range(1, 17):
            pc = 0x1000 + index * 0x10
            count = index * 3
            family = families[(index - 1) % len(families)]
            name = _swap_symbol(index)
            nm_lines.append(f"{pc:08x} T {name}\n")
            per_pc.append({
                "count": count,
                "opcode_family": family,
                "pc": pc,
            })
            members.append({"observed_rows": count, "symbol": name})
            expected[family] += count
        with tempfile.TemporaryDirectory() as directory:
            nm_path = Path(directory) / "nm.stdout"
            nm_path.write_text(
                "00000400 T _start\n" + "".join(nm_lines), encoding="utf-8",
            )
            actual = subject.derive_family_rows(
                {"per_pc": per_pc},
                nm_path,
                {
                    "members": members,
                    "totals": {"total_observed_rows": sum(expected.values())},
                },
            )
        self.assertEqual(actual, expected)

    def test_raw_pc_family_or_member_mutation_rejects(self) -> None:
        name = _swap_symbol(1)
        workload = {
            "members": [
                {"observed_rows": 1, "symbol": name},
                *[
                    {"observed_rows": 1, "symbol": _swap_symbol(index)}
                    for index in range(2, 17)
                ],
            ],
            "totals": {"total_observed_rows": 16},
        }
        with tempfile.TemporaryDirectory() as directory:
            nm_path = Path(directory) / "nm.stdout"
            nm_path.write_text(
                "00000400 T _start\n" + "".join(
                    f"{0x1000 + index * 0x10:08x} T {_swap_symbol(index)}\n"
                    for index in range(1, 17)
                ),
                encoding="utf-8",
            )
            rows = [
                {
                    "count": 1,
                    "opcode_family": subject.FAMILY_ORDER[
                        (index - 1) % len(subject.FAMILY_ORDER)
                    ],
                    "pc": 0x1000 + index * 0x10,
                }
                for index in range(1, 17)
            ]
            changed = copy.deepcopy(rows)
            changed[0]["opcode_family"] = "mul"
            with self.assertRaises(subject.EvmSwapCellProjectionError):
                subject.derive_family_rows(
                    {"per_pc": changed}, nm_path, workload,
                )
            changed = copy.deepcopy(rows)
            changed[0]["count"] = 2
            with self.assertRaises(subject.EvmSwapCellProjectionError):
                subject.derive_family_rows(
                    {"per_pc": changed}, nm_path, workload,
                )

    def test_production_and_candidate_geometry_sources_are_pinned(self) -> None:
        widths, identities = subject._production_widths()
        self.assertEqual(widths["load_store"]["main_columns"], 50)
        self.assertEqual(widths["load_store"]["interaction_columns"], 36)
        self.assertEqual(widths["base_alu_reg"]["total_active_columns"], 71)
        self.assertIn("opcode_composition_manifest", identities)
        geometry, candidate_identities, per_call = subject._candidate_geometry()
        self.assertEqual(geometry["caller"]["main_columns"], 37)
        self.assertEqual(geometry["word"]["lane_count"], 8)
        self.assertEqual(per_call["load_store"], 130)
        self.assertIn("relations", candidate_identities)

    @staticmethod
    def fixture() -> dict:
        identity = {
            "bytes": 1,
            "path": "/private/tmp/source",
            "sha256": "1" * 64,
        }
        families = [
            ("base_alu_imm", 130_368, 35, 16, 2, 32),
            ("base_alu_reg", 43_456, 35, 18, 2, 36),
            ("branch_lt", 43_456, 37, 11, 2, 24),
            ("jalr", 43_456, 41, 18, 2, 36),
            ("load_store", 5_649_280, 50, 17, 2, 36),
            ("shifts_imm", 43_456, 51, 16, 2, 32),
        ]
        current = []
        for family, rows, main, events, batch, interaction in families:
            columns = main + interaction
            current.append({
                "active_cells": rows * columns,
                "active_rows": rows,
                "family": family,
                "interaction_columns": interaction,
                "lookup_batch_size": batch,
                "lookup_events": events,
                "main_columns": main,
                "total_active_columns": columns,
            })
        components = [
            {
                "active_rows": 43_456,
                "all_committed_columns": 72,
                "component": "caller",
                "interaction_columns": 32,
                "main_columns": 37,
                "padded_all_column_cells": 4_718_592,
                "padded_rows": 65_536,
                "preprocessed_columns": 3,
            },
            {
                "active_rows": 347_648,
                "all_committed_columns": 35,
                "component": "word-provider",
                "interaction_columns": 16,
                "lane_count": 8,
                "main_columns": 16,
                "padded_all_column_cells": 18_350_080,
                "padded_rows": 524_288,
                "preprocessed_columns": 3,
            },
        ]
        return protocol.seal({
            "claim_boundary": subject._claim_boundary(),
            "comparison_scope": {
                "candidate_padding_included": True,
                "candidate_preprocessed_columns_included": True,
                "current_padding_included": False,
                "current_preprocessed_columns_included": False,
                "scope": (
                    "retained-swap-software-active-main-plus-interaction-vs-"
                    "candidate-padded-all-columns"
                ),
            },
            "inputs": {
                "candidate_sources": {"source": copy.deepcopy(identity)},
                "nm_symbol_map": copy.deepcopy(identity),
                "pc_observation": copy.deepcopy(identity),
                "production_sources": {"source": copy.deepcopy(identity)},
                "swap_workload": copy.deepcopy(identity),
                "swap_workload_content_sha256": "2" * 64,
            },
            "production": False,
            "projection": {
                "candidate_components": components,
                "candidate_padded_all_column_cells": 23_068_672,
                "current_active_main_plus_interaction_cells": 507_261_888,
                "current_families": current,
                "reduction_m31_cells": 484_193_216,
                "reduction_percent_floor_6dp": 95_452_315,
            },
            "sample": {"complete_execution": True, "no_extrapolation": True},
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
        })

    def test_resealed_authority_scope_and_arithmetic_mutations_reject(self) -> None:
        original = self.fixture()
        mutations = (
            lambda value: value.__setitem__("production", 0),
            lambda value: value["claim_boundary"].__setitem__(
                "candidate_proof", {},
            ),
            lambda value: value["comparison_scope"].__setitem__(
                "current_padding_included", True,
            ),
            lambda value: value["projection"].__setitem__(
                "reduction_m31_cells", 484_193_215,
            ),
            lambda value: value["projection"]["current_families"][0].__setitem__(
                "active_rows", True,
            ),
            lambda value: value["projection"]["candidate_components"][0].__setitem__(
                "padded_rows", 65_535,
            ),
            lambda value: value["inputs"].__setitem__(
                "swap_workload_content_sha256", "3" * 64,
            ),
        )
        with (
            mock.patch.object(
                subject, "_validate_identity", side_effect=lambda value, _: value,
            ),
            mock.patch.object(
                subject, "_validate_identity_map", side_effect=lambda value, _: value,
            ),
            mock.patch.object(subject, "build", return_value=original),
        ):
            self.assertIs(subject.validate(original), original)
            for mutate in mutations:
                changed = copy.deepcopy(original)
                mutate(changed)
                changed["content_sha256"] = protocol.content_sha256(changed)
                with self.assertRaises(subject.EvmSwapCellProjectionError):
                    subject.validate(changed)

    def test_unsealed_mutation_rejects(self) -> None:
        value = self.fixture()
        value["projection"]["reduction_m31_cells"] -= 1
        with self.assertRaises(subject.EvmSwapCellProjectionError):
            subject.validate(value)


if __name__ == "__main__":
    unittest.main()
