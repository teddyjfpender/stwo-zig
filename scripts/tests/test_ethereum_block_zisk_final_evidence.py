from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ethereum_block_proof_protocol as protocol


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "autoresearch/benchmarks"


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, BENCHMARK / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


subject = load("zisk_final_evidence_tested", "ethereum_block_zisk_final_evidence.py")
admission = load("zisk_final_admission_tested", "ethereum_block_zisk_final_admission.py")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class ZiskFinalEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.work = self.root / "work"
        self.work.mkdir()
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.tool = self._file("cargo-zisk", b"tool")
        self.elf = self._file("guest.elf", b"elf")
        self.input = self._file("input.bin", b"input")
        self.proof = self._file("proof.bin", b"vadcop-final-proof")
        self.keys = self.root / "proving-key"
        self.keys.mkdir()
        for name, relative in subject.KEY_FILES:
            path = self.keys / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"key:{name}".encode("ascii"))
        block = {
            "chain_id": 1,
            "number": 24_628_607,
            "hash": "0x" + "ab" * 32,
            "transaction_count": 66,
            "gas_used": 7_372_614,
        }
        global_info = self.keys / subject.KEY_FILES[0][1]
        self.manifest_value = {
            "schema": "test.reference.v1",
            "benchmark_protocol": {
                "statement_sha256": digest(b"statement"),
                "statement": {
                    "block": copy.deepcopy(block),
                    "matched_guest_statement_reproduced": False,
                },
            },
            "block": copy.deepcopy(block),
            "zisk": {
                "source": {
                    "repository": "https://example.test/zisk",
                    "commit": "a" * 40,
                    "tree": "b" * 40,
                },
                "ethereum_client": {
                    "repository": "https://example.test/client",
                    "commit": "c" * 40,
                    "tree": "d" * 40,
                },
                "tools": {"version": "1.2.0-alpha"},
                "fixture": self._small_identity(self.input),
                "guest_elf": self._small_identity(self.elf),
                "execution": {
                    "steps": 123,
                    "output": {
                        "bytes": 256,
                        "sha256": digest(b"output"),
                        "framing": "test-output",
                    },
                },
                "plan": {"global_info": self._small_identity(global_info)},
            },
        }
        self.manifest = self.root / "manifest.json"
        self.manifest.write_bytes(protocol.canonical_bytes(self.manifest_value))
        successes = "\n".join(["Block validation succeeded!"] * 16)
        self.prove_stdout = self._file("prove.stdout", (
            "ZisK zkVM 1.2.0-alpha\n"
            f"{successes}\n"
            f"Block Hash: {block['hash']}\n"
            "Transaction Count: 66\nGas Consumed: 7372614\n"
            ">>> GENERATE_VADCOP_FINAL_PROOF\n"
            "<<< GENERATING_INNER_PROOFS (200ms)\n"
            "<<< GENERATE_VADCOP_FINAL_PROOF (30ms)\n"
            "Proof verified successfully.\n"
            "Proof generated in 1.250s, steps: 123\n"
            f"Proof saved to {self.proof}\n"
        ).encode("utf-8"))
        self.verify_stdout = self._file(
            "verify.stdout",
            "Command ZiskVerify\n✓ STARK proof was verified\ntime: 28 milliseconds\n".encode(),
        )
        self.prove_time = self._file("prove.time", self._time("2.00", "3.00", "0.50"))
        self.verify_time = self._file("verify.time", self._time("0.07", "0.05", "0.02"))
        self.receipt = self.root / "receipt.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _file(self, name: str, raw: bytes) -> Path:
        path = self.root / name
        path.write_bytes(raw)
        return path

    @staticmethod
    def _small_identity(path: Path) -> dict:
        raw = path.read_bytes()
        return {"bytes": len(raw), "sha256": digest(raw)}

    @staticmethod
    def _time(real: str, user: str, system: str) -> bytes:
        return (
            f"real {real}\nuser {user}\nsys {system}\n"
            "  100  maximum resident set size\n"
            "  2  page faults\n"
            "  3  involuntary context switches\n"
            "  120  peak memory footprint\n"
        ).encode("ascii")

    def _build(self) -> dict:
        return subject.build(
            reference_manifest=self.manifest,
            tool=self.tool,
            elf=self.elf,
            input_path=self.input,
            proving_key_root=self.keys,
            proof=self.proof,
            prove_stdout=self.prove_stdout,
            prove_stderr_time=self.prove_time,
            verify_stdout=self.verify_stdout,
            verify_stderr_time=self.verify_time,
            work_directory=self.work,
            timing_disqualifiers=["concurrent-unrelated-workload"],
        )

    def _publish(self) -> dict:
        value = self._build()
        self.receipt.write_bytes(protocol.canonical_bytes(value))
        return value

    def test_create_replay_binds_final_proof_fresh_verify_and_null_claims(self) -> None:
        value = self._publish()
        self.assertEqual(value, subject.validate(self.receipt))
        evidence = subject.evidence(self.receipt)
        projection = evidence["projection"]
        self.assertEqual("zisk-vadcop-final", projection["proof_kind"])
        self.assertEqual(digest(b"vadcop-final-proof"), projection["proof"]["sha256"])
        self.assertTrue(projection["fresh_process_verification"])
        self.assertIsNone(projection["security_target_bits"])
        self.assertFalse(projection["matrix_timing_admissible"])
        self.assertEqual(2_000_000_000, value["processes"]["prove"]["timing"]["wall_ns"])
        self.assertEqual(70_000_000,
                         value["processes"]["fresh_verify"]["timing"]["wall_ns"])

    def test_matrix_stages_are_correctness_only_with_all_timing_null(self) -> None:
        self._publish()
        evidence = subject.evidence(self.receipt)
        reference = value_reference = self._build()["reference"]
        fixture = {
            "fixture_id": subject.REFERENCE_FIXTURE_ID,
            "block": copy.deepcopy(reference["block"]),
        }
        manifest = {
            **reference["identity"],
            "statement_sha256": reference["statement_sha256"],
        }
        stages = {
            scope: admission.validate_stage(evidence, fixture, manifest, scope)
            for scope in admission.SUPPORTED_SCOPES
        }
        self.assertEqual("complete_nonpromotable", stages["aggregation"]["status"])
        self.assertEqual("complete_nonpromotable",
                         stages["fresh_verification"]["status"])
        self.assertEqual("retained_nonpromotable", stages["end_to_end"]["status"])
        self.assertTrue(stages["fresh_verification"]["fresh_verification"])
        self.assertTrue(all(stage["timing"] is None for stage in stages.values()))
        self.assertTrue(all(stage["security_target_bits"] is None
                            for stage in stages.values()))

    def test_resealed_identity_semantic_and_promotion_mutations_reject(self) -> None:
        original = self._publish()
        mutations = (
            lambda value: value["files"]["proof"].__setitem__("sha256", digest(b"other")),
            lambda value: value["reference"].__setitem__("statement_sha256", digest(b"other")),
            lambda value: value["claim_boundary"].__setitem__(
                "matrix_timing_admissible", True,
            ),
            lambda value: value["claim_boundary"].__setitem__("comparison_ready", True),
            lambda value: value["processes"]["fresh_verify"].__setitem__("exit_code", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                mutation(value)
                value["content_sha256"] = protocol.content_sha256(value)
                self.receipt.write_bytes(protocol.canonical_bytes(value))
                with self.assertRaises((
                    subject.ZiskFinalEvidenceError, protocol.ProofProtocolError,
                )):
                    subject.validate(self.receipt)
        self.receipt.write_bytes(protocol.canonical_bytes(original))

    def test_mutated_or_symlinked_artifact_rejects(self) -> None:
        original = self._publish()
        self.proof.write_bytes(b"changed-proof")
        with self.assertRaises(protocol.ProofProtocolError):
            subject.validate(self.receipt)
        self.proof.write_bytes(b"vadcop-final-proof")
        self.proof.unlink()
        self.proof.symlink_to(self.tool)
        with self.assertRaises(protocol.ProofProtocolError):
            subject.validate(self.receipt)
        self.proof.unlink()
        self.proof.write_bytes(b"vadcop-final-proof")
        self.assertEqual(original, subject.validate(self.receipt))

    def test_direct_script_create_and_replay(self) -> None:
        command = [
            "python3", str(BENCHMARK / "ethereum_block_zisk_final_evidence.py"),
            "create", "--reference-manifest", str(self.manifest),
            "--tool", str(self.tool), "--elf", str(self.elf),
            "--input", str(self.input), "--proving-key-root", str(self.keys),
            "--proof", str(self.proof), "--prove-stdout", str(self.prove_stdout),
            "--prove-stderr-time", str(self.prove_time),
            "--verify-stdout", str(self.verify_stdout),
            "--verify-stderr-time", str(self.verify_time),
            "--work-directory", str(self.work),
            "--timing-disqualifier", "concurrent-unrelated-workload",
            "--output", str(self.receipt), "--staging-directory", str(self.staging),
        ]
        completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                   timeout=30, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)
        replay = subprocess.run([
            "python3", str(BENCHMARK / "ethereum_block_zisk_final_evidence.py"),
            "replay", "--receipt", str(self.receipt),
        ], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(0, replay.returncode, replay.stderr)


if __name__ == "__main__":
    unittest.main()
