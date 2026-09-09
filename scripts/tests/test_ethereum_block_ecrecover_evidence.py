from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_ecrecover_bulk_memcpy_evidence as bulk  # noqa: E402
import ethereum_block_ecrecover_execution_evidence as execution  # noqa: E402
import ethereum_block_ecrecover_pc_census_evidence as pc  # noqa: E402
import ethereum_block_keccak_words_execution_evidence as baseline_module  # noqa: E402


def file_identity(path: Path) -> dict:
    return execution._identity(path, "fixture")


def external(keccak: int, recovery: int) -> list[dict]:
    return [
        {"family": execution.KECCAK_FAMILY, "calls": keccak,
         "execution_rows": keccak},
        {"family": execution.RECOVERY_FAMILY, "calls": recovery,
         "execution_rows": recovery},
    ]


class EcrecoverEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.elf = self.root / "candidate.elf"
        self.trace = self.root / "trace"
        self.source = self.root / "source.rs"
        for path, raw in (
            (self.elf, b"candidate ELF"), (self.trace, b"trace"),
            (self.source, b"source"),
        ):
            path.write_bytes(raw)
        self.input_identity = {
            "path": "/private/tmp/input", "bytes": 1, "sha256": "1" * 64,
        }
        self.baseline_elf = {
            "path": "/private/tmp/baseline.elf", "bytes": 1,
            "sha256": "2" * 64,
        }
        self.baseline_journal = {
            "path": "/private/tmp/baseline.ndjson", "bytes": 1,
            "sha256": "3" * 64,
        }
        self.candidate_journal = {
            "path": "/private/tmp/candidate.ndjson", "bytes": 1,
            "sha256": "4" * 64,
        }
        self.comparator = {
            "journal": self.baseline_journal,
            "input_sha256": self.input_identity["sha256"],
            "elf_sha256": self.baseline_elf["sha256"],
            "output_bytes": 43,
            "output_sha256": "5" * 64,
            "final_cpu_sha256": "6" * 64,
            "final_rw_memory_sha256": "7" * 64,
            "segment_count": 4,
            "total_cycles": 100,
            "total_core_trace_rows": 80,
            "total_external_trace_rows": 20,
            "external_family_rows": external(10, 10),
        }
        self.candidate = {
            "journal": self.candidate_journal,
            "input_sha256": self.input_identity["sha256"],
            "elf_sha256": file_identity(self.elf)["sha256"],
            "output_bytes": 43,
            "output_sha256": "5" * 64,
            "final_cpu_sha256": "8" * 64,
            "final_rw_memory_sha256": "9" * 64,
            "segment_count": 2,
            "total_cycles": 72,
            "total_core_trace_rows": 40,
            "total_external_trace_rows": 32,
            "external_family_rows": external(10, 22),
        }
        self.baseline = {
            "schema": baseline_module.SCHEMA,
            "inputs": {
                "common_input": self.input_identity,
                "candidate_elf": self.baseline_elf,
                "candidate_journal": self.baseline_journal,
            },
            "executions": {"keccak_words_candidate": self.comparator},
            "measurements": {
                "keccak_words_candidate_process": {
                    "retained_process_log": True, "wall_ns": 200,
                },
            },
            "claim_boundary": {
                "production_active": False,
                "candidate_air_complete": None,
                "proof_correctness": None,
                "fresh_proof_verification": None,
                "measured_proving_end_to_end_wall_ns": None,
                "production_promotion_eligible": False,
            },
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_execution(self) -> dict:
        timing = {"retained_process_log": True, "wall_ns": 100}
        with (
            mock.patch.object(
                execution.journal_evidence, "_journal",
                side_effect=[self.comparator, self.candidate],
            ),
            mock.patch.object(
                execution.allocator_evidence, "_timing",
                side_effect=[({"path": "timing"}, timing),
                             ({"path": "build"}, timing)],
            ),
        ):
            return execution._build_loaded(
                self.baseline, {"path": "baseline"},
                Path("candidate.ndjson"), self.elf, Path("candidate.time"),
                Path("build.time"), self.trace, self.source,
            )

    def test_success_path_delta_is_exact_and_general_semantics_stay_false(self) -> None:
        value = self.build_execution()
        self.assertEqual(value["observed_equivalence"][
            "added_successful_recovery_calls"
        ], 12)
        self.assertFalse(value["semantics"][
            "general_invalid_input_semantics_satisfied"
        ])
        self.assertIsNone(value["claim_boundary"]["proof_correctness"])
        self.assertIsNone(value["claim_boundary"][
            "measured_proving_end_to_end_wall_ns"
        ])

    def test_wrong_recovery_delta_and_bool_as_int_reject(self) -> None:
        self.candidate["external_family_rows"] = external(10, 21)
        self.candidate["total_external_trace_rows"] = 31
        self.candidate["total_cycles"] = 71
        with self.assertRaises(execution.EcrecoverExecutionEvidenceError):
            self.build_execution()

        self.candidate["external_family_rows"] = external(10, 22)
        self.candidate["total_external_trace_rows"] = 32
        self.candidate["total_cycles"] = 72
        self.baseline["claim_boundary"]["production_active"] = 0
        with self.assertRaises(execution.EcrecoverExecutionEvidenceError):
            self.build_execution()

    def test_bulk_projection_keeps_synthetic_journal_null(self) -> None:
        value = self.build_execution()
        candidate = value["executions"]["ecrecover_success_candidate"]
        candidate["segment_count"] = 2
        observation = {
            "elf_sha256": value["inputs"]["candidate_elf"]["sha256"],
            "input_sha256": value["inputs"]["common_input"]["sha256"],
            "journal_sha256": candidate["journal"]["sha256"],
            "segment_count": 2,
            "sampled_cycles": candidate["total_cycles"],
            "retired_instructions": candidate["total_core_trace_rows"],
            "removable_core_rows": 10,
            "admitted": {
                "calls": 2, "requested_bytes": 64,
                "software_rows": 12, "word_rows": 16,
            },
        }
        timing = {"retained_process_log": True, "wall_ns": 100}
        with (
            mock.patch.object(
                bulk.bulk_support, "_load_observation",
                return_value=(observation, {"path": "observation"}),
            ),
            mock.patch.object(
                bulk.allocator_evidence, "_timing",
                return_value=({"path": "timing"}, timing),
            ),
            mock.patch.object(bulk, "_identity", return_value={"path": "file"}),
        ):
            result = bulk._build_loaded(
                value, {"path": "execution"}, Path("observation"),
                Path("observer"), Path("source"), Path("timing"),
            )
        self.assertIsNone(result["execution_projection"][
            "synthesized_post_bulk_journal"
        ])
        self.assertFalse(result["claim_boundary"][
            "general_invalid_ecrecover_semantics_satisfied"
        ])
        self.assertIsNone(result["claim_boundary"]["proof_correctness"])

    def test_symbol_projection_assigns_all_rows_and_named_totals(self) -> None:
        names = (
            "__wrap_memcpy",
            "sha2::sha256::compress256",
            "<revm_handler::mainnet_handler::MainnetHandler<x> as "
            "revm_handler::handler::Handler>::execution",
            "<zeth_mpt::mpt::node::Node<x> as "
            "alloy_rlp::decode::Decodable>::decode",
            "revm_bytecode::legacy::analysis::analyze_legacy",
            "<zeth_mpt::mpt::node::Node<x>>::resolve_digests::"
            "<alloy_primitives::bytes_::Bytes>",
            "native_keccak256",
        )
        symbol_map = self.root / "nm.stdout"
        symbol_map.write_text("".join(
            f"{0x400 + index * 4:08x} T {name}\n"
            for index, name in enumerate(names)
        ), encoding="utf-8")
        observation = {
            "retired_instructions": sum(range(1, len(names) + 1)),
            "per_pc": [
                {"pc": 0x400 + index * 4, "count": index + 1}
                for index in range(len(names))
            ],
        }
        projection = pc._symbol_projection(observation, symbol_map)
        self.assertEqual(projection["unmapped_rows"], 0)
        self.assertEqual(projection["mapped_rows"],
                         observation["retired_instructions"])
        self.assertEqual(
            [row["role"] for row in projection["named_symbol_totals"]],
            [role for role, _ in pc.NAMED_SELECTORS],
        )


if __name__ == "__main__":
    unittest.main()
