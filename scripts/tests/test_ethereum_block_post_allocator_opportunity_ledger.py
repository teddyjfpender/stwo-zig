from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_post_allocator_opportunity_ledger as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import riscv_segmented_execution as segmented  # noqa: E402


def digest(value: bytes | str) -> str:
    if isinstance(value, str):
        value = value.encode("ascii")
    return hashlib.sha256(value).hexdigest()


def family_rows(values: dict[str, int]) -> list[dict]:
    return [{"family": family, "rows": values.get(family, 0)}
            for family in segmented.FAMILIES]


def external_rows(values: dict[str, int]) -> list[dict]:
    return [{"family": family, "calls": values.get(family, 0),
             "execution_rows": values.get(family, 0)}
            for family in segmented.EXTERNAL_FAMILIES[segmented.PROFILE_ETHEREUM]]


class PostAllocatorOpportunityLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def identity(self, name: str, raw: bytes | None = None) -> dict:
        path = self.root / name
        path.write_bytes(raw if raw is not None else name.encode("ascii"))
        return {"path": str(path), **store.file_identity(path, name)}

    def test_inventory_alias_and_poseidon_geometry_are_exact(self) -> None:
        segments = [{
            "opcode_family_rows": family_rows({
                "base_alu_imm": 65_537, "branch_eq": 3, "branch_lt": 17,
                "lt_reg": 1, "mul": 16, "mulh": 17, "load_store": 31,
            }),
            "external_family_rows": external_rows({
                "stwo.keccakf-1600.permute-in-place@1": 2,
            }),
        }, {
            "opcode_family_rows": family_rows({
                "base_alu_imm": 1, "branch_eq": 0, "branch_lt": 16,
                "lt_reg": 17, "mul": 1, "mulh": 16, "load_store": 32,
            }),
            "external_family_rows": external_rows({
                "stwo.keccakf-1600.permute-in-place@1": 17,
            }),
        }]
        corpus = {"segment_count": 2,
                  "family_inventory": subject._family_inventory(segments)}
        inventory = subject._inventory_map(corpus)
        self.assertEqual(inventory["base_alu_imm"]["active_rows"], 65_538)
        self.assertEqual(inventory["base_alu_imm"]["diagnostic_padded_rows"], 65_568)
        aliases = subject._alias_opportunities(corpus)
        self.assertEqual(
            aliases[0]["families"][0]["saved_main_cells"], 65_568 * 4,
        )
        self.assertEqual(
            aliases[2]["families"][0]["saved_main_cells"], (32 + 32) * 2,
        )
        profiles = subject._poseidon_opportunity(corpus)["profiles"]
        rows = 2 * (1 << 24)
        self.assertEqual(profiles[1]["main_columns"], 239)
        self.assertEqual(profiles[2]["composition_columns_at_trace_log"], 32)
        self.assertEqual(
            profiles[2]["saved_all_committed_cells_vs_legacy"], rows * 260,
        )

    def test_memcpy_marginals_never_become_joined_geometry(self) -> None:
        value = {
            "content_sha256": digest("memcpy"),
            "source_observation": {
                "call_count": 10,
                "total_requested_bytes": 400,
                "length_histogram": [
                    {"call_count": 2, "length": 8, "total_bytes": 16},
                    {"call_count": 5, "length": 32, "total_bytes": 160},
                    {"call_count": 3, "length": 64, "total_bytes": 192},
                ],
                "alignment_histogram": [
                    {"call_count": 6, "destination_mod_16": 0,
                     "source_mod_16": 4, "total_bytes": 200},
                    {"call_count": 4, "destination_mod_16": 1,
                     "source_mod_16": 2, "total_bytes": 200},
                ],
            },
        }
        model = subject._memcpy_model(value)
        self.assertEqual(model["minimum_length_eligible_calls"], 8)
        self.assertEqual(model["same-mod4-alignment-eligible-calls"], 6)
        self.assertEqual(model["pre-overlap_joint_call_lower_bound"], 4)
        self.assertEqual(model["pre-overlap_joint_call_upper_bound"], 6)
        self.assertIsNone(model["exact_candidate_word_rows"])
        self.assertIsNone(model["exact_candidate_committed_cells"])
        self.assertIsNone(model["full_72_segment_extrapolation"])

    def keccak_fixture(self) -> tuple[Path, Path, dict]:
        executable = self.root / "projection-tool"
        executable.write_bytes(b"projection executable")
        corpus = {
            "identity": {"path": str(self.root / "journal"), "bytes": 1,
                         "sha256": digest("journal")},
            "header": {"elf_sha256": digest("elf")},
            "segment_count": 2,
            "total_core_trace_rows": 100,
            "family_inventory": [{
                "family": "stwo.keccakf-1600.permute-in-place@1",
                "active_rows": 3,
            }],
        }
        modes = [
            {"leaves": 2 if index == 0 else 0,
             "calls": 3 if index == 0 else 0,
             "adaptive_cells": 8 if index == 0 else 0,
             "compact_baseline_cells": 10 if index == 0 else 0}
            for index in range(4)
        ]
        logs = [
            {"leaves": 2 if index == 0 else 0,
             "calls": 3 if index == 0 else 0,
             "adaptive_cells": 8 if index == 0 else 0,
             "compact_baseline_cells": 10 if index == 0 else 0}
            for index in range(17)
        ]
        value = {
            "schema": subject.KECCAK_SCHEMA,
            "schema_version": 1,
            "production_active": False,
            "measurement_kind": "exact-committed-m31-cell-projection",
            "proof_or_fresh_verification": False,
            "journal_sha256": digest("journal"),
            "executable_sha256": digest(executable.read_bytes()),
            "executable_bytes": len(executable.read_bytes()),
            "elf_sha256": digest("elf"),
            "leaf_count": 2,
            "total_core_rows": 100,
            "total_keccak_calls": 3,
            "modes": modes,
            "log_sizes": logs,
            "adaptive_cells": 8,
            "compact_baseline_cells": 10,
            "saved_cells": 2,
            "selected_profile_plan_sha256": digest("plan"),
            "projection_wall_ns": 100,
            "max_rss_bytes": 10,
            "projection_identity": digest("projection"),
        }
        receipt = self.root / "keccak.json"
        receipt.write_bytes((json.dumps(
            value, ensure_ascii=True, separators=(",", ":"),
        ) + "\n").encode("ascii"))
        return receipt, executable, corpus

    def test_keccak_bool_as_int_and_closure_mutations_reject(self) -> None:
        receipt, executable, corpus = self.keccak_fixture()
        parsed = subject._keccak_projection(receipt, executable, corpus)
        self.assertEqual(parsed["receipt"]["saved_cells"], 2)

        value = json.loads(receipt.read_bytes())
        value["production_active"] = 0
        receipt.write_bytes((json.dumps(value, separators=(",", ":")) + "\n").encode())
        with self.assertRaises(subject.PostAllocatorOpportunityLedgerError):
            subject._keccak_projection(receipt, executable, corpus)

        receipt, executable, corpus = self.keccak_fixture()
        value = json.loads(receipt.read_bytes())
        value["modes"][0]["calls"] = 2
        receipt.write_bytes((json.dumps(value, separators=(",", ":")) + "\n").encode())
        with self.assertRaises(subject.PostAllocatorOpportunityLedgerError):
            subject._keccak_projection(receipt, executable, corpus)

    def test_ledger_replay_rejects_resealed_claim_mutation(self) -> None:
        identities = {name: self.identity(name) for name in (
            "allocator", "journal", "memcpy", "keccak", "executable",
        )}
        sources = [{
            "role": role,
            "identity": self.identity(f"source-{index}"),
        } for index, (role, _) in enumerate(subject.SOURCE_PATHS)]
        value = protocol.seal({
            "schema": subject.SCHEMA,
            "status": subject.STATUS,
            "inputs": {
                "allocator_execution_evidence": identities["allocator"],
                "candidate_v3_journal": identities["journal"],
                "memcpy_hotspot_evidence": identities["memcpy"],
                "keccak_projection_receipt": identities["keccak"],
                "keccak_projection_executable": identities["executable"],
            },
            "source_authorities": sources, "corpus": {}, "alias_opportunities": [],
            "poseidon_opportunity": {}, "keccak_opportunity": {},
            "memcpy_opportunity": {},
            "claims": {"production_promotion_eligible": False},
        })
        with (
            mock.patch.object(subject.allocator_evidence, "load", return_value={}),
            mock.patch.object(subject.memcpy_evidence, "load", return_value={}),
            mock.patch.object(subject, "_build_loaded", return_value=value),
        ):
            self.assertIs(subject.validate(value), value)
            mutated = copy.deepcopy(value)
            mutated["claims"]["production_promotion_eligible"] = 0
            mutated["content_sha256"] = protocol.content_sha256(mutated)
            with self.assertRaises(subject.PostAllocatorOpportunityLedgerError):
                subject.validate(mutated)


if __name__ == "__main__":
    unittest.main()
