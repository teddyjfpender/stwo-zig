from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import ethereum_block_proof_protocol as proof_protocol


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = ROOT / "autoresearch/benchmarks"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

import ethereum_block_benchmark_matrix as matrix_protocol
import ethereum_block_benchmark_replay_admission as matrix_cli
import ethereum_block_compact_replay_admission as admission
import ethereum_block_compact_replay_evidence as subject


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "bytes": len(raw), "path": str(path.absolute()),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def zig_bytes(value: dict) -> bytes:
    unsigned = json.dumps(
        value, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8") + b"\n"
    sealed = {"content_sha256": hashlib.sha256(unsigned).hexdigest(), **value}
    return json.dumps(
        sealed, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
    ).encode("utf-8") + b"\n"


def write_zig(path: Path, value: dict) -> dict:
    path.write_bytes(zig_bytes(value))
    return json.loads(path.read_text())


def ordered(keys: tuple[str, ...], values: dict) -> dict:
    return {key: values[key] for key in keys if key != "content_sha256"}


def boundary_digest(domain: bytes, words: list[tuple[int, int, int]], side: int) -> str:
    value = hashlib.sha256(domain + struct.pack("<I", len(words)))
    for word in words:
        value.update(struct.pack("<II", word[0], word[side]))
    return value.hexdigest()


def cpu_bytes(pc: int, seed: int) -> bytes:
    registers = [0] + [seed + index for index in range(1, 32)]
    return struct.pack("<" + "I" * 33, pc, *registers)


def compact_artifact(
    *, segment_index: int, global_first_cycle: int,
    program: str, input_sha: str, session: str,
    entry_memory: str, exit_memory: str,
    entry_cpu: bytes, exit_cpu: bytes, external: bool, terminal: bool,
) -> tuple[bytes, dict]:
    words = [(0x2000, segment_index + 1, segment_index + 2)]
    entry_boundary = boundary_digest(subject.BOUNDARY_ENTRY_DOMAIN, words, 1)
    exit_boundary = boundary_digest(subject.BOUNDARY_EXIT_DOMAIN, words, 2)
    core_count = 1
    keccak_count = 1 if external else 0
    recovery_count = 1 if external else 0
    cycle_count = core_count + keccak_count + recovery_count
    payload = bytearray()
    for value in (program, input_sha, session, entry_memory, exit_memory,
                  entry_boundary, exit_boundary):
        payload.extend(bytes.fromhex(value))
    payload.extend(struct.pack(
        "<IQII", segment_index, global_first_cycle, cycle_count, core_count,
    ))
    payload.extend(entry_cpu)
    payload.extend(exit_cpu)
    completion = None
    if terminal:
        completion = {
            "kind": 1, "address": 0, "value": 0, "clock": 1, "exit_code": 0,
        }
        payload.extend(struct.pack("<BBIII", 1, 1, 0, 0, 1))
        payload.extend(struct.pack("<BI", 1, 0))
    else:
        payload.extend(b"\x00")
    payload.extend(struct.pack("<I", 0))
    payload.extend(struct.pack("<I", keccak_count))
    if external:
        payload.extend(struct.pack("<III", 2, 0x1000, 0x3000))
        payload.extend(b"\x05")
        payload.extend(struct.pack("<I", 1))
        payload.extend(struct.pack("<" + "I" * 150, *range(150)))
    payload.extend(struct.pack("<I", recovery_count))
    if external:
        payload.extend(struct.pack("<III", 3, 0x1004, 0x4000))
        payload.extend(b"\x06")
        payload.extend(struct.pack("<I", 1))
        payload.extend(bytes(range(32)) * 3)
        payload.extend(struct.pack("<I", 1))
        payload.extend(bytes(range(64)))
        payload.extend(struct.pack("<I", 1))
        payload.extend(struct.pack("<" + "I" * 59, *range(59)))
    leaf_seal = hashlib.sha256(
        subject.LEAF_DOMAIN + struct.pack("<HHH", 1, 1, 3) + payload,
    ).digest()
    body = bytearray(subject.ARTIFACT_MAGIC)
    body.extend(struct.pack("<HHI", 1, 1, 0))
    body.extend(payload)
    body.extend(leaf_seal)
    body.extend(struct.pack("<I", len(words)))
    for word in words:
        body.extend(struct.pack("<III", *word))
    checksum = hashlib.sha256(subject.ARTIFACT_CHECKSUM_DOMAIN + body).digest()
    record = {
        "completion": completion,
        "core_cycle_count": core_count,
        "cycle_count": cycle_count,
        "entry_boundary_sha256": entry_boundary,
        "entry_cpu_sha256": hashlib.sha256(subject.CPU_DOMAIN + entry_cpu).hexdigest(),
        "entry_memory_sha256": entry_memory,
        "exit_boundary_sha256": exit_boundary,
        "exit_cpu_sha256": hashlib.sha256(subject.CPU_DOMAIN + exit_cpu).hexdigest(),
        "exit_memory_sha256": exit_memory,
        "global_first_cycle": global_first_cycle,
        "keccak_calls": keccak_count,
        "leaf_seal_sha256": leaf_seal.hex(),
        "recovery_calls": recovery_count,
        "segment_index": segment_index,
    }
    return bytes(body) + checksum, record


class Fixture:
    def __init__(self, root: Path, *, invalid_profile: bool = False,
                 invalid_witness: bool = False) -> None:
        self.root = root
        paths = {
            name: root / name for name in (
                "elf", "execution-journal", "input", "output", "source-request",
                "materialization-result", "replay-executable",
            )
        }
        for name, path in paths.items():
            path.write_bytes((name + "\n").encode("ascii"))
        ids = {name: identity(path) for name, path in paths.items()}
        program = digest("program")
        session = digest("session")
        memory = [digest(f"memory-{index}") for index in range(3)]
        cpus = [cpu_bytes(0x1000 + index * 4, 10 * index)
                for index in range(3)]
        artifact_inputs = []
        global_cycle = 1
        for index in range(2):
            raw, values = compact_artifact(
                segment_index=index, global_first_cycle=global_cycle,
                program=program, input_sha=ids["input"]["sha256"], session=session,
                entry_memory=memory[index], exit_memory=memory[index + 1],
                entry_cpu=cpus[index], exit_cpu=cpus[index + 1],
                external=index == 0, terminal=index == 1,
            )
            path = root / f"segment-{index}.stwemt01"
            path.write_bytes(raw)
            values["artifact"] = identity(path)
            values["capture_wall_ns"] = 10 + index
            values["encode_wall_ns"] = 12 + index
            values["publish_wall_ns"] = 14 + index
            artifact_inputs.append(ordered(subject.MANIFEST_ARTIFACT_KEYS, values))
            global_cycle += values["cycle_count"]

        profile_values = {
            "attributed_core_rows": 2,
            "attributed_external_calls": 2,
            "core_rows": 2,
            "elf": ids["elf"],
            "execution_journal": ids["execution-journal"],
            "external_calls": 2,
            "external_execution_rows": 2,
            "external_family_counts": [
                {"calls": 1, "execution_rows": 1, "family": "keccakf"},
                {"calls": 1, "execution_rows": 1, "family": "secp256k1_recover"},
            ],
            "function_count": 1,
            "function_top_coverage_core_rows": 2,
            "function_top_coverage_external_calls": 2,
            "functions_truncated": False,
            "materialization_result": ids["materialization-result"],
            "nonzero_pc_count": 1,
            "out_of_text_core_rows": 0,
            "out_of_text_external_calls": 0,
            "pc_stride": 4,
            "pc_top_coverage_core_rows": 2,
            "pc_top_coverage_external_calls": 2,
            "pcs_truncated": False,
            "schema": subject.PROFILE_SCHEMA,
            "source_request": ids["source-request"],
            "status": subject.PROFILE_STATUS,
            "text_end": 0x2000,
            "text_start": 0x1000,
            "top_functions": [{
                "address": 0x1000, "core_rows": 2, "external_calls": 2,
                "name": "main", "size": 16, "total_retirements": 4,
            }],
            "top_pcs": [{
                "core_rows": 2, "external_calls": 2, "function": "main",
                "function_offset": 0, "pc": 0x1000, "total_retirements": 4,
            }],
            "unattributed_core_rows": 0,
            "unattributed_external_calls": 0,
        }
        if invalid_profile:
            profile_values["function_top_coverage_core_rows"] = 1
        profile_path = root / "execution-profile.json"
        self.profile = write_zig(
            profile_path, ordered(subject.PROFILE_KEYS, profile_values),
        )
        ids["execution-profile"] = identity(profile_path)

        chain = hashlib.sha256(
            subject.ARTIFACT_CHAIN_DOMAIN + struct.pack("<I", len(artifact_inputs)),
        )
        for record in artifact_inputs:
            chain.update(struct.pack(
                "<IQ", record["segment_index"], record["artifact"]["bytes"],
            ))
            chain.update(bytes.fromhex(record["artifact"]["sha256"]))
            chain.update(bytes.fromhex(record["leaf_seal_sha256"]))
        timings = {
            "capture_wall_ns": 21, "encode_wall_ns": 25,
            "observer_wall_ns": 100, "pc_attribution_wall_ns": 1,
            "post_execution_authority_wall_ns": 10, "publish_wall_ns": 29,
            "stream_observed_wall_ns": 120,
            "pre_manifest_materialization_wall_ns": 200,
        }
        manifest_values = {
            "artifact_chain_sha256": chain.hexdigest(),
            "artifact_format_version": 1,
            "artifact_magic": "STWEMT01",
            "artifacts": artifact_inputs,
            "clock_frame": "leaf_local",
            "elf": ids["elf"],
            "execution_journal": ids["execution-journal"],
            "execution_profile": subject.EXECUTION_PROFILE,
            "execution_profile_abi_version": 1,
            "execution_profile_receipt": ids["execution-profile"],
            "execution_profile_semantic_sha256": digest("profile-semantic"),
            "expected_output": ids["output"],
            "input": ids["input"],
            "materialization_result": ids["materialization-result"],
            "materializer_executable_sha256": ids["replay-executable"]["sha256"],
            "program_sha256": program,
            "segment_count": 2,
            "segment_step_budget": subject.MAX_LEAF_CYCLES,
            "session_sha256": session,
            "source_request": ids["source-request"],
            "stage_timings": ordered(subject.STAGE_TIMING_KEYS, timings),
            "status": subject.MANIFEST_STATUS,
            "total_artifact_bytes": sum(item["artifact"]["bytes"]
                                        for item in artifact_inputs),
            "total_core_cycles": 2,
            "total_cycles": 4,
            "total_keccak_calls": 1,
            "total_recovery_calls": 1,
            "schema": subject.MANIFEST_SCHEMA,
        }
        manifest_path = root / "compact-manifest.json"
        self.manifest = write_zig(
            manifest_path, ordered(subject.MANIFEST_KEYS, manifest_values),
        )
        ids["manifest"] = identity(manifest_path)

        leaves = []
        for index, artifact in enumerate(artifact_inputs):
            leaf = {
                "core_trace_rows": artifact["core_cycle_count"],
                "core_trace_sha256": digest(f"core-{index}"),
                "entry_cpu_sha256": artifact["entry_cpu_sha256"],
                "exit_cpu_sha256": artifact["exit_cpu_sha256"],
                "keccak_call_count": artifact["keccak_calls"],
                "keccak_calls_sha256": digest(f"keccak-calls-{index}"),
                "keccak_execution_rows": artifact["keccak_calls"],
                "keccak_rows_sha256": digest(f"keccak-rows-{index}"),
                "recovery_call_count": artifact["recovery_calls"],
                "recovery_calls_sha256": digest(f"recovery-calls-{index}"),
                "recovery_execution_rows": artifact["recovery_calls"],
                "recovery_rows_sha256": digest(f"recovery-rows-{index}"),
                "segment_index": index,
                "state_chain_access_count": 1,
                "state_chain_memory_clock_updates": 1,
                "state_chain_register_clock_updates": 1,
                "state_chain_sha256": digest(f"state-{index}"),
                "touched_memory_sha256": digest(f"memory-{index}"),
                "touched_memory_words": 1,
            }
            leaf["witness_sha256"] = subject._leaf_witness(leaf)
            if invalid_witness and index == 0:
                leaf["witness_sha256"] = digest("invalid-witness")
            leaves.append(ordered(subject.LEAF_AUTHORITY_KEYS, leaf))
        replay_chain = hashlib.sha256(
            subject.REPLAY_CHAIN_DOMAIN + struct.pack("<I", len(leaves)),
        )
        for leaf in leaves:
            replay_chain.update(struct.pack("<I", leaf["segment_index"]))
            replay_chain.update(bytes.fromhex(leaf["witness_sha256"]))
        replay_values = {
            "artifact_chain_sha256": self.manifest["artifact_chain_sha256"],
            "artifacts_manifest": ids["manifest"],
            "clock_frame": "leaf_local",
            "elf": ids["elf"],
            "execution_journal": ids["execution-journal"],
            "execution_profile": subject.EXECUTION_PROFILE,
            "execution_profile_abi_version": 1,
            "execution_profile_receipt": ids["execution-profile"],
            "execution_profile_semantic_sha256": digest("profile-semantic"),
            "expected_output": ids["output"],
            "input": ids["input"],
            "leaf_authorities": leaves,
            "manifest_content_sha256": self.manifest["content_sha256"],
            "materialization_result": ids["materialization-result"],
            "process_scope": "single-cli-process",
            "program_sha256": program,
            "replay_chain_sha256": replay_chain.hexdigest(),
            "replay_executable": ids["replay-executable"],
            "replay_receipt": ordered(subject.REPLAY_RECEIPT_KEYS, {
                "admitted_workers": 2, "core_cycles": 2, "keccak_calls": 1,
                "leaf_count": 2, "recovery_calls": 1, "total_cycles": 4,
            }),
            "replay_timing": ordered(subject.REPLAY_TIMING_KEYS, {
                "wall_ns": 10, "user_ns": 8, "system_ns": 2,
            }),
            "requested_workers": 4,
            "schema": subject.REPLAY_SCHEMA,
            "segment_count": 2,
            "segment_step_budget": subject.MAX_LEAF_CYCLES,
            "session_sha256": session,
            "source_request": ids["source-request"],
            "status": subject.REPLAY_STATUS,
            "timing_scope": "parallel-replay-call-self-rusage",
        }
        self.receipt_path = root / "replay-receipt.json"
        self.replay = write_zig(
            self.receipt_path, ordered(subject.REPLAY_KEYS, replay_values),
        )
        self.materialized = {
            "source_request_identity": {
                "schema": "stwo.ethereum.block-proof-leaf-stream-source.v1",
                **ids["source-request"],
            },
            "source_request": {
                "elf": ids["elf"], "execution_profile": subject.EXECUTION_PROFILE,
                "profile_abi_version": 1,
                "profile_semantic_digest": digest("profile-semantic"),
                "segment_count": 2, "segment_step_budget": subject.MAX_LEAF_CYCLES,
            },
            "manifest": {
                "execution_journal": ids["execution-journal"],
                "expected_output": ids["output"], "input": ids["input"],
                "total_cycles": 4,
            },
        }


class CompactReplayEvidenceTests(unittest.TestCase):
    def validate(self, fixture: Fixture) -> dict:
        with mock.patch.object(
            subject.materialization, "validate", return_value=fixture.materialized,
        ):
            return subject.validate(fixture.receipt_path.absolute())

    def test_wire_faithful_capture_profile_and_replay_validate(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            evidence = self.validate(fixture)
        self.assertEqual(subject.EVIDENCE_KIND, evidence["kind"])
        projection = evidence["projection"]
        self.assertEqual(4, projection["total_cycles"])
        self.assertEqual(1, projection["total_keccak_calls"])
        self.assertEqual(1, projection["total_recovery_calls"])
        self.assertFalse(projection["matrix_timing_admissible"])
        self.assertFalse(projection["proof_complete"])

    def test_symlink_mutation_profile_and_source_mismatch_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = Fixture(root, invalid_profile=True)
            with self.assertRaisesRegex(proof_protocol.ProofProtocolError, "coverage"):
                self.validate(fixture)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = Fixture(root, invalid_witness=True)
            with self.assertRaisesRegex(proof_protocol.ProofProtocolError, "leaf authority"):
                self.validate(fixture)
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            fixture = Fixture(root)
            link = root / "receipt-link.json"
            link.symlink_to(fixture.receipt_path)
            with mock.patch.object(subject.materialization, "validate",
                                   return_value=fixture.materialized), self.assertRaisesRegex(
                proof_protocol.ProofProtocolError, "non-symlink regular file",
            ):
                subject.validate(link.absolute())
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            materialized = copy.deepcopy(fixture.materialized)
            materialized["manifest"]["total_cycles"] = 5
            with mock.patch.object(subject.materialization, "validate",
                                   return_value=materialized), self.assertRaisesRegex(
                proof_protocol.ProofProtocolError, "execution authority",
            ):
                subject.validate(fixture.receipt_path.absolute())

    def test_compact_artifact_and_receipt_content_mutations_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            artifact = Path(fixture.manifest["artifacts"][0]["artifact"]["path"])
            value = bytearray(artifact.read_bytes())
            value[32] ^= 1
            artifact.write_bytes(value)
            with self.assertRaisesRegex(proof_protocol.ProofProtocolError, "identity"):
                self.validate(fixture)
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw))
            value = bytearray(fixture.receipt_path.read_bytes())
            value[-3] ^= 1
            fixture.receipt_path.write_bytes(value)
            with self.assertRaises(proof_protocol.ProofProtocolError):
                self.validate(fixture)

    def test_direct_script_entry_point_is_packaged(self) -> None:
        result = subprocess.run(
            [sys.executable, str(BENCHMARK_DIR /
                                 "ethereum_block_benchmark_replay_admission.py"), "--help"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("validate-replay", result.stdout)
        self.assertIn("admit", result.stdout)


class CompactReplayMatrixAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = matrix_protocol.build_matrix(
            matrix_protocol.corpus_authority.DEFAULT_CORPUS,
            matrix_protocol.comparison.DEFAULT_MANIFEST,
        )
        self.source = matrix_protocol._validate_source_authorities(self.matrix)[0][
            "fixtures"
        ][0]

    def fake_evidence(self) -> dict:
        guest = self.source["semantic_io"]["guest_transports"]
        return {
            "kind": subject.EVIDENCE_KIND,
            "receipt": {"bytes": 1, "path": "/retained/replay.json", "sha256": digest("r")},
            "materialization_manifest": {
                "bytes": 1, "path": "/retained/manifest.json", "sha256": digest("m"),
            },
            "execution_profile_receipt": {
                "bytes": 1, "path": "/retained/profile.json", "sha256": digest("p"),
            },
            "replay_executable": {
                "bytes": 1, "path": "/retained/replay", "sha256": digest("e"),
            },
            "projection": {
                "artifact_chain_sha256": digest("chain"),
                "execution_profile": subject.EXECUTION_PROFILE,
                "execution_profile_abi_version": 1,
                "execution_profile_semantic_sha256": digest("semantic"),
                "input": {key: guest["stwo_input"][key] for key in ("bytes", "sha256")},
                "expected_output": {
                    key: guest["stwo_output"][key] for key in ("bytes", "sha256")
                },
                "segment_count": admission.REFERENCE_SEGMENT_COUNT,
                "segment_step_budget": admission.REFERENCE_SEGMENT_STEP_BUDGET,
                "total_cycles": admission.REFERENCE_TOTAL_CYCLES,
                "total_core_cycles": admission.REFERENCE_CORE_CYCLES,
                "total_keccak_calls": admission.REFERENCE_EXTERNAL_CALLS - 33,
                "total_recovery_calls": 33,
                "requested_workers": 16,
                "admitted_workers": 16,
                "replay_chain_sha256": digest("replay-chain"),
                "capture_stage_timings": {
                    field: 1 for field in subject.STAGE_TIMING_KEYS
                },
                "capture_timing_scope": "pre-manifest-materialization-diagnostic",
                "replay_timing": {"wall_ns": 3, "user_ns": 4, "system_ns": 5},
                "timing_scope": "parallel-replay-call-self-rusage",
                "matrix_timing_admissible": False,
                "proof_complete": False,
            },
        }

    def test_real_geometry_admits_only_diagnostic_execution_scope(self) -> None:
        evidence = self.fake_evidence()
        with mock.patch.object(subject, "validate", return_value=evidence):
            admitted = matrix_cli.admit(
                self.matrix, self.source["fixture_id"], Path("/retained/replay.json"),
            )
            matrix_protocol.validate_matrix(admitted)
            report = matrix_protocol.render_report(admitted)
        stages = admitted["fixtures"][0]["systems"]["stwo_zig"]["stages"]
        self.assertEqual("retained_nonpromotable", stages["execution"]["status"])
        self.assertIsNone(stages["execution"]["timing"])
        self.assertFalse(stages["execution"]["evidence"]["projection"]
                         ["matrix_timing_admissible"])
        for scope in ("base_proofs", "aggregation", "fresh_verification", "end_to_end"):
            self.assertEqual("unavailable", stages[scope]["status"])
            self.assertIsNone(stages[scope]["timing"])
        self.assertEqual(0, admitted["aggregate"]["eligible_fixture_count"])
        self.assertFalse(admitted["comparison_ready"])
        self.assertIn("Retained compact replay diagnostics", report)
        self.assertIn("16/16", report)
        self.assertIn("Neither is a comparable execution-stage or proof timing", report)

    def test_transport_geometry_and_fixture_mismatches_reject(self) -> None:
        mutations = (
            lambda value: value["projection"]["input"].update({"sha256": digest("wrong")}),
            lambda value: value["projection"].update({"segment_count": 209}),
            lambda value: value["projection"].update({"total_recovery_calls": 0}),
        )
        for mutation in mutations:
            evidence = self.fake_evidence()
            mutation(evidence)
            with self.subTest(mutation=mutation), mock.patch.object(
                subject, "validate", return_value=evidence,
            ), self.assertRaises(admission.ReplayAdmissionError):
                admission.validate_stage(evidence, self.source)
        evidence = self.fake_evidence()
        with mock.patch.object(subject, "validate", return_value=evidence), self.assertRaisesRegex(
            admission.ReplayAdmissionError, "non-reference",
        ):
            admission.validate_stage(evidence, self.matrix["fixtures"][1])


if __name__ == "__main__":
    unittest.main()
