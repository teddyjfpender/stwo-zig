from __future__ import annotations

import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_benchmark_matrix_contract as contract
from scripts import riscv_benchmark_matrix_model as model
from scripts import riscv_benchmark_matrix_runner as controller
from scripts.riscv_release_oracle_lib.public_values import (
    parse_proof_artifact_public_data,
    parse_public_values_diagnostic,
)


DIGEST = "d" * 64
CANDIDATE = "a" * 40
ELF_DIGEST = "e" * 64
INPUT = b"\x07"
INPUT_DIGEST = hashlib.sha256(INPUT).hexdigest()


def public_data() -> dict:
    return {
        "initial_pc": 0x10000,
        "final_pc": 0x10004,
        "clock": 1,
        "initial_regs": [0] * 32,
        "final_regs": [0] * 32,
        "reg_last_clock": [0] * 32,
        "program_root": 1,
        "initial_rw_root": 2,
        "final_rw_root": 3,
        "completion": {
            "kind": "unretired_self_loop",
            "address": 0x10004,
            "value": 0x6F,
            "clock": 0,
        },
        "io_entries": {
            "input_start": 0,
            "input_len": 1,
            "input_words": [7],
            "output_len": 0,
            "output_len_addr": 0,
            "output_data_addr": 0,
            "output_words": [],
        },
    }


def public_diagnostic(*, dirty: bool) -> str:
    return json.dumps({
        "schema": "riscv-public-values-diagnostic-v1",
        "derivation": "execution_and_committed_tree_builders_without_proof_admission",
        "provenance": {
            "implementation_commit": CANDIDATE,
            "implementation_dirty": dirty,
            "oracle_commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "witness_layout_sha256": DIGEST,
        },
        "source": {"elf_sha256": ELF_DIGEST, "input_sha256": INPUT_DIGEST},
        "public_data": public_data(),
    })


def proof_artifact(*, dirty: bool) -> str:
    public = public_data()
    io = public["io_entries"]
    flat = {key: public[key] for key in public if key != "io_entries"}
    flat.update(io)
    return json.dumps({
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "release_status": "not_release_gated",
        "generator": "zig",
        "air": "sail_rv32im_zkvm_v1",
        "backend": "cpu",
        "protocol": "functional",
        "source": {"elf_sha256": ELF_DIGEST, "input_sha256": INPUT_DIGEST},
        "provenance": {
            "oracle_repository": "https://github.com/riscv/sail-riscv",
            "oracle_commit": "8c7f2da58de0ba5e4457e4de07e0046f0439f35f",
            "implementation_repository": "https://github.com/teddyjfpender/stwo-zig",
            "implementation_commit": CANDIDATE,
            "implementation_dirty": dirty,
            "witness_layout_sha256": DIGEST,
        },
        "pcs_config": {},
        "statement": {
            "segment_ordinal": 0,
            "segment_count": 1,
            "initial_pc": public["initial_pc"],
            "final_pc": public["final_pc"],
            "total_steps": public["clock"],
            "components": [],
            "infrastructure": [],
            "public_data": flat,
        },
        "interaction_claim": {},
        "proof_bytes_hex": "00",
    })


class InventoryTests(unittest.TestCase):
    def test_full_inventory_is_exactly_the_reviewed_33_rows(self) -> None:
        workloads, identities = model.load_workloads()
        counts = {
            row_class: sum(item.row_class == row_class for item in workloads)
            for row_class in model.FULL_COUNTS
        }
        self.assertEqual(33, len(workloads))
        self.assertEqual(
            {"proof": 23, "execution": 10},
            counts,
        )
        self.assertEqual(33, len({item.row_id for item in workloads}))
        contract.require_sha256(identities["row_set_sha256"], "row set")

    def test_fixture_digest_mismatch_fails_before_row_construction(self) -> None:
        with mock.patch.object(model, "sha256_file", return_value="0" * 64):
            with self.assertRaisesRegex(model.MatrixModelError, "ELF digest mismatch"):
                model.load_workloads()

    def test_filter_is_explicitly_incomplete(self) -> None:
        workloads, _ = model.load_workloads()
        selection = controller._selection(workloads, workloads[:1])
        self.assertFalse(selection["complete"])
        self.assertEqual("filtered", selection["mode"])
        self.assertEqual(33, selection["expected_full_row_count"])


class DirtyBindingTests(unittest.TestCase):
    def kwargs(self) -> dict:
        return {
            "candidate": CANDIDATE,
            "witness_layout_sha256": DIGEST,
            "elf_sha256": ELF_DIGEST,
            "input_sha256": INPUT_DIGEST,
        }

    def test_release_callers_still_default_to_clean_diagnostics(self) -> None:
        with self.assertRaisesRegex(ValueError, "implementation_dirty differs"):
            parse_public_values_diagnostic(public_diagnostic(dirty=True), **self.kwargs())
        parsed = parse_public_values_diagnostic(
            public_diagnostic(dirty=True), candidate_dirty=True, **self.kwargs(),
        )
        self.assertEqual(public_data(), parsed)

    def test_release_callers_still_default_to_clean_artifacts(self) -> None:
        kwargs = {**self.kwargs(), "release_status": "not_release_gated"}
        with self.assertRaisesRegex(ValueError, "implementation_dirty differs"):
            parse_proof_artifact_public_data(proof_artifact(dirty=True), **kwargs)
        parsed = parse_proof_artifact_public_data(
            proof_artifact(dirty=True), candidate_dirty=True, **kwargs,
        )
        self.assertEqual(public_data(), parsed)


class TraceDumperProvenanceTests(unittest.TestCase):
    """Every ``riscv-trace-dump`` sample is bound to the candidate that built it.

    This is why this harness does not also call the CSP harness's
    ``read_trace_provenance``: the binding below runs on *every* sample and holds
    the dumper to the candidate commit, the worktree's dirty flag, the pinned
    oracle commit, the witness layout digest, and the digests of the exact fixture
    the row measures -- a strict superset of that gate's commit-and-dirty check.
    A second, weaker copy of a check that already runs is the hazard, not the fix
    (issue #152 item 6b).
    """

    @staticmethod
    def capture(raw: str) -> mock.Mock:
        return mock.Mock(stdout=raw.encode("utf-8"))

    @staticmethod
    def workload() -> mock.Mock:
        return mock.Mock(
            row_id="crypto:sha2_input:128B",
            elf_sha256=ELF_DIGEST,
            input_sha256=INPUT_DIGEST,
        )

    def parse(self, raw: str, *, dirty: bool = False) -> dict:
        return controller._candidate_diagnostic_public(
            self.capture(raw), self.workload(), {"commit": CANDIDATE, "dirty": dirty},
        )

    def test_a_dump_from_another_commit_is_refused(self) -> None:
        foreign = public_diagnostic(dirty=False).replace(CANDIDATE, "b" * 40)
        with self.assertRaisesRegex(ValueError, "implementation_commit differs"):
            self.parse(foreign)

    def test_a_dump_that_misreports_the_worktree_is_refused(self) -> None:
        # `--allow-dirty` is served by binding the flag, not by dropping the
        # check: a clean-claiming binary in a dirty tree is still refused, and so
        # is the reverse.
        with self.assertRaisesRegex(ValueError, "implementation_dirty differs"):
            self.parse(public_diagnostic(dirty=True), dirty=False)
        with self.assertRaisesRegex(ValueError, "implementation_dirty differs"):
            self.parse(public_diagnostic(dirty=False), dirty=True)

    def test_a_dump_with_no_provenance_block_is_refused(self) -> None:
        payload = json.loads(public_diagnostic(dirty=False))
        del payload["provenance"]
        with self.assertRaisesRegex(
            controller.MatrixRunError, "diagnostic provenance is missing",
        ):
            self.parse(json.dumps(payload))

    def test_the_execution_sample_path_routes_through_the_binding(self) -> None:
        # Behavioural coverage of the parser cannot show that the trace-dumper
        # lane reaches it; only the call site can.
        source = inspect.getsource(controller._run_candidate_execution_sample)
        self.assertIn("--public-values", source)
        self.assertIn("_candidate_diagnostic_public(capture, workload, candidate)", source)


class CorrectnessBoundaryTests(unittest.TestCase):
    def test_candidate_benchmark_requires_resources_only_on_darwin(self) -> None:
        payload = {
            "profiled": False,
            "total_steps": 1,
            "median_seconds": 0.1,
            "mean_execution_seconds": 0.1,
            "mean_witness_seconds": 0.1,
            "mean_proving_seconds": 0.1,
            "mean_verification_seconds": 0.1,
        }
        workload = mock.Mock(row_id="proof:test")
        candidate = {
            "commit": CANDIDATE,
            "dirty": False,
            "executables": {"riscv_cpu": {"sha256": DIGEST}},
        }
        admission = controller.riscv_cli_admission.Admission(
            "candidate", "not_release_gated", True,
        )
        with mock.patch.object(
            controller.staged_contracts, "validate_benchmark_report",
        ) as validate, mock.patch.object(
            controller.platform, "system", return_value="Linux",
        ):
            controller._validate_candidate_benchmark(
                payload, workload, candidate, None, admission,
            )
        self.assertFalse(validate.call_args.kwargs["require_resource_availability"])

    def test_semantic_parity_compares_the_complete_public_statement(self) -> None:
        oracle = public_data()
        candidate = json.loads(json.dumps(oracle))
        receipt = controller.semantic_parity(oracle, candidate)
        self.assertEqual(list(controller.PUBLIC_DATA_FIELDS), receipt["fields"])
        candidate["final_regs"][31] = 9
        with self.assertRaisesRegex(controller.MatrixRunError, "final_regs"):
            controller.semantic_parity(oracle, candidate)

    def test_stark_v_timing_cycle_evidence_is_mandatory(self) -> None:
        with self.assertRaisesRegex(controller.MatrixRunError, "cycle count"):
            controller._cycles_from_log(b"Guest completed")
        self.assertEqual(
            144,
            controller._cycles_from_log(b"Guest program completed with 144 cycles"),
        )

    def test_signed_multiply_corpus_rows_are_proof_admitted(self) -> None:
        workloads = model.load_workloads()[0]
        selected = {
            item.row_id: item.row_class
            for item in workloads
            if item.row_id in {"corpus:mul_div", "corpus:mulhu_only"}
        }
        self.assertEqual(
            {"corpus:mul_div": "proof", "corpus:mulhu_only": "proof"},
            selected,
        )


class ContractTests(unittest.TestCase):
    @staticmethod
    def valid_execution_row() -> dict:
        empty = hashlib.sha256(b"").hexdigest()
        sidecar = {"path": "log", "sha256": empty, "size_bytes": 0}
        sample = {
            "iteration": 0,
            "warmup": False,
            "order_position": 0,
            "argv": ["tool"],
            "duration_ns": 100_000_000,
            "cpu_time_ns": 100_000_000,
            "cpu_wall_ratio": 1.0,
            "cycles": 1,
            "phases_seconds": {"execution": 0.1},
            "stdout": sidecar,
            "stderr": sidecar,
            "evidence": None,
        }
        other = {**sample, "order_position": 1, "argv": ["oracle"]}
        timing = {
            "mode": "execution",
            "clock": "time.monotonic_ns",
            "warmups": 0,
            "samples": 1,
            "pair_orders": [["candidate", "stark_v"]],
            "candidate": [sample],
            "stark_v": [other],
            "summary": {
                "candidate_median_seconds": 0.1,
                "stark_v_median_seconds": 0.1,
                "candidate_over_stark_v": 1.0,
                "stark_v_median_cpu_wall_ratio": 1.0,
            },
        }
        semantics = {
            "total_steps": 1,
            "final_pc": 0,
            "final_regs_sha256": DIGEST,
            "public_data_sha256": DIGEST,
            "source": {"path": "source", "sha256": DIGEST, "size_bytes": 1},
            "duration_ns": 1,
        }
        return {
            "id": "crypto:test:fixed",
            "suite": "crypto",
            "class": "execution",
            "status": "ok",
            "fixture": {"elf_sha256": DIGEST, "input_sha256": DIGEST},
            "metal": contract.METAL_GATE,
            "oracle_semantics": semantics,
            "candidate_semantics": semantics,
            "semantic_parity": {
                "status": "pass",
                "fields": list(contract.SEMANTIC_FIELDS),
                "mismatches": [],
                "public_data_sha256": DIGEST,
            },
            "timing": timing,
            "proof": None,
            "rejection": None,
            "error": None,
        }

    def test_complete_execution_row_contract_passes(self) -> None:
        contract.validate_row(self.valid_execution_row())

    def test_promotion_eligibility_can_never_be_true(self) -> None:
        payload = {field: None for field in contract.ROOT_FIELDS}
        payload.update({
            "schema": contract.SCHEMA,
            "evidence_class": contract.EVIDENCE_CLASS,
            "promotion_eligible": True,
            "duration_ns": 1,
        })
        with self.assertRaisesRegex(contract.MatrixContractError, "non-promotable"):
            contract.validate_report(payload)

    def test_raw_timing_sample_requires_cycles(self) -> None:
        empty = hashlib.sha256(b"").hexdigest()
        sample = {
            "iteration": 0,
            "warmup": False,
            "order_position": 0,
            "argv": ["tool"],
            "duration_ns": 1,
            "cpu_time_ns": 1,
            "cpu_wall_ratio": 1.0,
            "cycles": None,
            "phases_seconds": {"execution": 0.1},
            "stdout": {"path": "out", "sha256": empty, "size_bytes": 0},
            "stderr": {"path": "err", "sha256": empty, "size_bytes": 0},
            "evidence": None,
        }
        with self.assertRaisesRegex(contract.MatrixContractError, "cycles"):
            contract._validate_command_sample(sample, "sample", measured=True)

    def test_ok_row_cannot_omit_semantic_oracle_parity(self) -> None:
        row = self.valid_execution_row()
        row["semantic_parity"] = None
        with self.assertRaisesRegex(contract.MatrixContractError, "semantic_parity"):
            contract.validate_row(row)

    def test_artifact_tree_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "proof.json"
            evidence.write_bytes(b"proof")
            report = {
                "artifact_root": str(root),
                "proof": {
                    "path": "proof.json",
                    "sha256": hashlib.sha256(b"proof").hexdigest(),
                    "size_bytes": 5,
                },
            }
            contract.validate_artifact_tree(report)
            evidence.write_bytes(b"tampered")
            with self.assertRaisesRegex(contract.MatrixContractError, "digest/size"):
                contract.validate_artifact_tree(report)


if __name__ == "__main__":
    unittest.main()
