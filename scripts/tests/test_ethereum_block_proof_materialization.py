from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts import ethereum_block_proof_materialization as subject
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store
from scripts import ethereum_block_proof_stream_request as stream_request


def identity(path: Path) -> dict:
    return {"path": path.name, **store.file_identity(path, path.name)}


def native(value: int) -> str:
    return (value.to_bytes(4, "little") * 8).hex()


def publish(path: Path, value: dict) -> None:
    path.write_bytes(protocol.canonical_bytes(protocol.seal(value)))


def fixture(root: Path) -> tuple[Path, dict]:
    for name in ("guest.elf", "input.bin", "output.bin", "execution.ndjson"):
        (root / name).write_bytes(f"fixture:{name}".encode("ascii"))
    source = {
        "clock_frame": "leaf_local",
        "elf": identity(root / "guest.elf"),
        "execution_journal": identity(root / "execution.ndjson"),
        "execution_profile": stream_request.PROFILE_NAME,
        "expected_output": identity(root / "output.bin"),
        "input": identity(root / "input.bin"),
        "pcs": stream_request.NATIVE_BLAKE_PCS,
        "profile_abi_version": 1,
        "profile_semantic_digest": stream_request.PROFILE_DIGEST,
        "profile_wire_id": 3,
        "schema": stream_request.SOURCE_SCHEMA_V1,
        "segment_authority_magic": "STWESG31",
        "segment_authority_version": 1,
        "segment_count": 2,
        "segment_step_budget": 4_194_304,
        "strict_completion": True,
    }
    source_path = root / "source-request.json"
    source_path.write_bytes(protocol.canonical_bytes(source))
    leaves = []
    for index in range(2):
        authority = root / f"segment-{index:06d}.bin"
        authority.write_bytes(f"segment:{index}".encode("ascii"))
        leaves.append({
            "authority": identity(authority),
            "metadata_id_m31_le": native(index + 1),
            "segment_index": index,
            "statement_id_m31_le": native(index + 3),
            "statement_sha256": hashlib.sha256(
                f"statement:{index}".encode("ascii")
            ).hexdigest(),
        })
    manifest = {
        "execution_journal": source["execution_journal"],
        "execution_profile": source["execution_profile"],
        "expected_output": source["expected_output"],
        "input": source["input"],
        "job": {
            "final_state_sha256": hashlib.sha256(b"final").hexdigest(),
            "initial_state_sha256": hashlib.sha256(b"initial").hexdigest(),
            "job_sha256": hashlib.sha256(b"job").hexdigest(),
            "program_m31_le": native(7),
            "public_input_m31_le": native(8),
            "public_output_m31_le": native(9),
        },
        "leaf_sources": leaves,
        "pcs": source["pcs"],
        "schema": subject.MATERIALIZATION_SCHEMA,
        "segment_authority_magic": "STWESG31",
        "segment_authority_version": 1,
        "segment_count": 2,
        "source_request": {
            "schema": stream_request.SOURCE_SCHEMA_V1,
            **identity(source_path),
        },
        "status": "materialized",
        "total_cycles": 8_000_000,
    }
    path = root / "materialization.json"
    publish(path, manifest)
    return path, protocol.seal(manifest)


class MaterializationAdmissionTests(unittest.TestCase):
    def test_reopens_every_materialized_authority_and_preserves_id_domains(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path, expected = fixture(Path(raw))
            admitted = subject.validate(path)
            self.assertEqual(admitted["manifest"], expected)
            self.assertEqual(len(admitted["segment_authority_paths"]), 2)
            self.assertNotEqual(
                expected["leaf_sources"][0]["statement_id_m31_le"],
                expected["leaf_sources"][0]["statement_sha256"],
            )

    def test_noncanonical_m31_and_authority_mutations_fail_closed(self) -> None:
        mutations = (
            lambda value: value["leaf_sources"][0].update({
                "metadata_id_m31_le": native(subject.M31_MODULUS),
            }),
            lambda value: value["leaf_sources"].reverse(),
            lambda value: value["leaf_sources"][0]["authority"].update({
                "sha256": "00" * 32,
            }),
            lambda value: value["source_request"].update({"sha256": "11" * 32}),
            lambda value: value["pcs"].update({"n_queries": 69}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                path, value = fixture(root)
                value = copy.deepcopy(value)
                mutate(value)
                publish(path, {key: item for key, item in value.items()
                               if key != "content_sha256"})
                with self.assertRaises(protocol.ProofProtocolError):
                    subject.validate(path)


if __name__ == "__main__":
    unittest.main()
