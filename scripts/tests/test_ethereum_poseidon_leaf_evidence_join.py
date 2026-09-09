from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_poseidon_leaf_evidence_join as evidence


def digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def identity(path: Path) -> dict[str, object]:
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest()}


def write_sealed(path: Path, unsigned: dict[str, object]) -> dict[str, object]:
    value = protocol.seal(unsigned)
    path.write_bytes(protocol.canonical_bytes(value))
    return value


def mutate_sealed(path: Path, mutate: object) -> None:
    value = json.loads(path.read_text())
    value.pop("content_sha256")
    mutate(value)
    write_sealed(path, value)


class Fixture:
    def __init__(self, root: Path, *, timing: bool = True):
        self.root = root
        self.root.mkdir()
        self.staging = root / "staging"
        self.staging.mkdir()
        self.request = root / "request.json"
        self.proof = root / "proof.stw"
        self.producer_result = root / "producer-result.json"
        self.verifier_result = root / "verifier-result.json"
        self.verifier_timing = root / "verifier-timing.json"
        self.producer_executable = root / "producer"
        self.verifier_executable = root / "verifier"
        self.source_request = root / "source-v2.json"
        self.source_segment = root / "segment-000000.stwesg31"
        self.wrong_segment = root / "segment-000001.stwesg31"
        self.wrong_request = root / "wrong-request.json"
        self.stdout = root / "wrong.stdout"
        self.stderr = root / "wrong.stderr"
        self.forbidden_result = root / "forbidden-result.json"
        self.forbidden_timing = root / "forbidden-timing.json"
        self.receipt = root / "join.json"
        self.producer_executable.write_bytes(b"producer-executable")
        self.verifier_executable.write_bytes(b"verifier-executable")
        self.proof.write_bytes(b"STWGPOSEIDON-V4-PROOF")
        self.source_request.write_bytes(
            b'{"schema":"stwo.ethereum.block-proof-leaf-stream-source.v2"}\n'
        )
        self.source_segment.write_bytes(b"STWESG31-segment-zero")
        self.wrong_segment.write_bytes(b"STWESG31-segment-one")
        self.stdout.write_bytes(b"")
        self.stderr.write_bytes(evidence.WRONG_SOURCE_STDERR)

        source_request = {
            "schema": evidence.SOURCE_SCHEMA, **identity(self.source_request),
        }
        request = write_sealed(self.request, {
            "expected_recursive_statement_sha256": digest("recursive-statement"),
            "expected_source_public_statement_sha256": digest("source-statement"),
            "producer_sha256": identity(self.producer_executable)["sha256"],
            "schema": evidence.REQUEST_SCHEMA,
            "segment_index": 0,
            "session_id": digest("session"),
            "source_request": source_request,
            "source_segment": identity(self.source_segment),
            "verifier_sha256": identity(self.verifier_executable)["sha256"],
        })
        self.request_value = request
        shared = {
            "recursive_statement_sha256": request[
                "expected_recursive_statement_sha256"
            ],
            "request_sha256": request["content_sha256"],
            "root_sha256": digest("root"),
            "security_identity_sha256": evidence.RECURSIVE_SECURITY_IDENTITY,
            "segment_index": 0,
            "source_public_statement_sha256": request[
                "expected_source_public_statement_sha256"
            ],
            "transcript_state_sha256": digest("transcript"),
            "verified_capture_sha256": digest("capture"),
            "verified_link_id_m31_le": "00" * 32,
        }
        self.shared = shared
        write_sealed(self.producer_result, {
            "descriptor_status": evidence.DESCRIPTOR_UNAVAILABLE,
            "producer_sha256": identity(self.producer_executable)["sha256"],
            "proof": identity(self.proof),
            "prove_timing": {"system_ns": 3, "user_ns": 5, "wall_ns": 11},
            "recursive_admissible": False,
            **shared,
            "schema": evidence.PRODUCER_RESULT_SCHEMA,
            "status": "proved",
        })
        write_sealed(self.verifier_result, {
            "descriptor_status": evidence.DESCRIPTOR_UNAVAILABLE,
            "fresh_verification": True,
            "proof_bytes": identity(self.proof)["bytes"],
            "proof_sha256": identity(self.proof)["sha256"],
            "recursive_admissible": False,
            **shared,
            "schema": evidence.VERIFIER_RESULT_SCHEMA,
            "status": "verified",
            "verifier_sha256": identity(self.verifier_executable)["sha256"],
        })
        if timing:
            write_sealed(self.verifier_timing, {
                "fresh_verification": True,
                "proof": identity(self.proof),
                "request": identity(self.request),
                "request_content_sha256": request["content_sha256"],
                "schema": evidence.VERIFIER_TIMING_SCHEMA,
                "segment_index": 0,
                "status": "verified",
                "timing_scope": evidence.VERIFY_TIMING_SCOPE,
                "verifier_result": identity(self.verifier_result),
                "verifier_sha256": identity(self.verifier_executable)["sha256"],
                "verify_timing": {"system_ns": 7, "user_ns": 13, "wall_ns": 17},
            })
        write_sealed(self.wrong_request, {
            "expected_recursive_statement_sha256": digest("wrong-recursive"),
            "expected_source_public_statement_sha256": digest("wrong-source"),
            "producer_sha256": request["producer_sha256"],
            "schema": evidence.REQUEST_SCHEMA,
            "segment_index": 1,
            "session_id": request["session_id"],
            "source_request": source_request,
            "source_segment": identity(self.wrong_segment),
            "verifier_sha256": request["verifier_sha256"],
        })
        self.timing = timing

    def inputs(self) -> dict[str, object]:
        return {
            "request_path": self.request,
            "proof_path": self.proof,
            "producer_result_path": self.producer_result,
            "verifier_result_path": self.verifier_result,
            "producer_executable_path": self.producer_executable,
            "verifier_executable_path": self.verifier_executable,
            "verifier_timing_receipt_path": (
                self.verifier_timing if self.timing else None
            ),
            "wrong_source": evidence.WrongSourceObservation(
                request_path=self.wrong_request,
                exit_code=1,
                stdout_path=self.stdout,
                stderr_path=self.stderr,
                forbidden_result_path=self.forbidden_result,
                forbidden_timing_receipt_path=self.forbidden_timing,
            ),
        }

    def publish(self) -> dict[str, object]:
        return evidence.publish_receipt(
            self.receipt, self.staging, **self.inputs(),
        )


class PoseidonLeafEvidenceJoinTest(unittest.TestCase):
    def test_advertised_direct_script_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "case")
            repository = Path(__file__).resolve().parents[2]
            command = [
                "python3", "scripts/ethereum_poseidon_leaf_evidence_join.py",
                "join", "--request", str(fixture.request),
                "--proof", str(fixture.proof),
                "--producer-result", str(fixture.producer_result),
                "--verifier-result", str(fixture.verifier_result),
                "--producer-executable", str(fixture.producer_executable),
                "--verifier-executable", str(fixture.verifier_executable),
                "--verifier-timing-receipt", str(fixture.verifier_timing),
                "--wrong-source-request", str(fixture.wrong_request),
                "--wrong-source-exit-code", "1",
                "--wrong-source-stdout", str(fixture.stdout),
                "--wrong-source-stderr", str(fixture.stderr),
                "--forbidden-result", str(fixture.forbidden_result),
                "--forbidden-timing-receipt", str(fixture.forbidden_timing),
                "--receipt", str(fixture.receipt),
                "--staging-directory", str(fixture.staging),
            ]
            completed = subprocess.run(
                command, cwd=repository, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual("", completed.stdout)
            self.assertEqual("", completed.stderr)
            replayed = subprocess.run(
                [
                    "python3",
                    "scripts/ethereum_poseidon_leaf_evidence_join.py",
                    "replay", "--receipt", str(fixture.receipt),
                ],
                cwd=repository, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(0, replayed.returncode, replayed.stderr)
            self.assertEqual("", replayed.stdout)
            self.assertEqual("", replayed.stderr)

    def test_complete_join_replays_every_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "case")
            receipt = fixture.publish()
            self.assertTrue(receipt["evidence_complete"])
            self.assertTrue(receipt["performance_claim_eligible"])
            self.assertFalse(receipt["promotion_ready"])
            self.assertFalse(receipt["recursive_admissible"])
            self.assertEqual(
                "joined_evidence_complete_descriptor_unavailable",
                receipt["status"],
            )
            self.assertEqual(
                {"system_ns": 7, "user_ns": 13, "wall_ns": 17},
                receipt["timing"]["verify"],
            )
            self.assertEqual(receipt, evidence.validate_receipt(fixture.receipt))

    def test_missing_timing_is_explicitly_nonpromotable(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "case", timing=False)
            receipt = fixture.publish()
            self.assertFalse(receipt["evidence_complete"])
            self.assertFalse(receipt["performance_claim_eligible"])
            self.assertIsNone(receipt["timing"]["verify"])
            self.assertIsNone(receipt["files"]["verifier_timing_receipt"])
            self.assertIsNone(
                receipt["bindings"]["verifier_timing_content_sha256"]
            )
            self.assertEqual(
                "joined_nonpromotable_missing_verifier_timing", receipt["status"]
            )

    def test_shared_authority_mutations_reject(self) -> None:
        mutations = {
            "root": ("producer_result", lambda value: value.__setitem__(
                "root_sha256", digest("mutated-root"))),
            "transcript": ("verifier_result", lambda value: value.__setitem__(
                "transcript_state_sha256", digest("mutated-transcript"))),
            "capture": ("producer_result", lambda value: value.__setitem__(
                "verified_capture_sha256", digest("mutated-capture"))),
            "link": ("verifier_result", lambda value: value.__setitem__(
                "verified_link_id_m31_le", "01" + "00" * 31)),
            "security": ("producer_result", lambda value: value.__setitem__(
                "security_identity_sha256", digest("wrong-security"))),
            "recursive statement": ("verifier_result", lambda value: value.__setitem__(
                "recursive_statement_sha256", digest("wrong-recursive"))),
            "source statement": ("producer_result", lambda value: value.__setitem__(
                "source_public_statement_sha256", digest("wrong-source"))),
            "segment": ("verifier_result", lambda value: value.__setitem__(
                "segment_index", 1)),
            "request": ("producer_result", lambda value: value.__setitem__(
                "request_sha256", digest("wrong-request"))),
            "proof": ("verifier_result", lambda value: value.__setitem__(
                "proof_sha256", digest("wrong-proof"))),
        }
        for name, (attribute, mutation) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw) / "case")
                mutate_sealed(getattr(fixture, attribute), mutation)
                with self.assertRaises(protocol.ProofProtocolError):
                    evidence.build_receipt(**fixture.inputs())

    def test_timing_sidecar_mutations_reject(self) -> None:
        mutations = {
            "scope": lambda value: value.__setitem__("timing_scope", "wrong"),
            "request": lambda value: value["request"].__setitem__(
                "sha256", digest("wrong-request")),
            "proof": lambda value: value["proof"].__setitem__(
                "bytes", value["proof"]["bytes"] + 1),
            "result": lambda value: value["verifier_result"].__setitem__(
                "sha256", digest("wrong-result")),
            "verifier": lambda value: value.__setitem__(
                "verifier_sha256", digest("wrong-verifier")),
            "zero wall": lambda value: value["verify_timing"].__setitem__(
                "wall_ns", 0),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw) / "case")
                mutate_sealed(fixture.verifier_timing, mutation)
                with self.assertRaises(protocol.ProofProtocolError):
                    evidence.build_receipt(**fixture.inputs())

    def test_wrong_source_contract_is_exact(self) -> None:
        cases = ("exit", "stdout", "stderr", "result", "timing", "same-source")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw) / "case")
                inputs = fixture.inputs()
                observation = inputs["wrong_source"]
                if case == "exit":
                    observation = evidence.WrongSourceObservation(
                        **{**observation.__dict__, "exit_code": 2}
                    )
                elif case == "stdout":
                    fixture.stdout.write_bytes(b"forbidden\n")
                elif case == "stderr":
                    fixture.stderr.write_bytes(b"error: InvalidProof\n")
                elif case == "result":
                    fixture.forbidden_result.write_bytes(b"{}\n")
                elif case == "timing":
                    fixture.forbidden_timing.write_bytes(b"{}\n")
                else:
                    wrong = copy.deepcopy(fixture.request_value)
                    wrong.pop("content_sha256")
                    write_sealed(fixture.wrong_request, wrong)
                inputs["wrong_source"] = observation
                with self.assertRaises(protocol.ProofProtocolError):
                    evidence.build_receipt(**inputs)

    def test_file_mutation_and_symlink_reject(self) -> None:
        for attribute in (
            "proof", "producer_executable", "verifier_executable",
            "source_request", "source_segment",
        ):
            with self.subTest(mutation=attribute), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw) / "mutation")
                path = getattr(fixture, attribute)
                path.write_bytes(path.read_bytes() + b"changed")
                with self.assertRaises(protocol.ProofProtocolError):
                    evidence.build_receipt(**fixture.inputs())
        for attribute in ("request", "proof", "producer_result", "verifier_executable"):
            with self.subTest(attribute=attribute), tempfile.TemporaryDirectory() as raw:
                fixture = Fixture(Path(raw) / "symlink")
                path = getattr(fixture, attribute)
                retained = path.with_suffix(path.suffix + ".retained")
                path.rename(retained)
                path.symlink_to(retained)
                with self.assertRaises(protocol.ProofProtocolError):
                    evidence.build_receipt(**fixture.inputs())

    def test_replay_rejects_mutated_retained_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "case")
            fixture.publish()
            fixture.stderr.write_bytes(b"error: InvalidProof\n")
            with self.assertRaises(protocol.ProofProtocolError):
                evidence.validate_receipt(fixture.receipt)

    def test_resealed_join_mutation_and_create_only_collision_reject(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "mutation")
            fixture.publish()
            mutate_sealed(
                fixture.receipt,
                lambda value: value.__setitem__("promotion_ready", True),
            )
            with self.assertRaises(protocol.ProofProtocolError):
                evidence.validate_receipt(fixture.receipt)
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "collision")
            fixture.receipt.write_bytes(b"different\n")
            with self.assertRaises(protocol.ProofProtocolError):
                fixture.publish()

    def test_unknown_or_noncanonical_result_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "unknown")
            mutate_sealed(
                fixture.verifier_result,
                lambda value: value.__setitem__("unknown", 1),
            )
            with self.assertRaises(protocol.ProofProtocolError):
                evidence.build_receipt(**fixture.inputs())
        with tempfile.TemporaryDirectory() as raw:
            fixture = Fixture(Path(raw) / "noncanonical")
            value = json.loads(fixture.producer_result.read_text())
            fixture.producer_result.write_text(json.dumps(value) + "\n")
            with self.assertRaises(protocol.ProofProtocolError):
                evidence.build_receipt(**fixture.inputs())


if __name__ == "__main__":
    unittest.main()
