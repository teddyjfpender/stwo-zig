"""Pinned transport/header normalization; never a guest or proof acceptance receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from autoresearch.benchmarks import ethereum_block_benchmark_statement as statement
from autoresearch.benchmarks import ethereum_block_comparison as comparison
from scripts import ethereum_block_proof_materialization as materialization
from scripts import ethereum_block_proof_store as store

SCHEMA = "stwo.ethereum.pinned-statement-normalization.v1"
BLOCK_FIELDS = ("chain_id", "number", "hash", "parent_hash", "state_root",
                "transactions_root", "receipts_root", "withdrawals_root",
                "requests_hash", "transaction_count", "gas_used", "gas_limit", "timestamp")


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def identity(path: Path) -> dict:
    return {"path": str(path.resolve()), **store.file_identity(path, str(path))}


def validate_decoded_projection(decoded: dict, manifest: dict, host_output: bytes) -> dict:
    """Join fresh upstream-codec output to independent benchmark expectations."""
    require(set(decoded) == {"projection", "new_payload_request_root"}, "projection fields differ")
    projection = decoded["projection"]
    require(set(projection) == {"schema", "block", "parent_state_root", "schema_id", "guest_execution_reproduced"},
            "decoded projection fields differ")
    require(projection["schema"] == "stwo.ethereum.fixture-normalization-projection.v1"
            and projection["guest_execution_reproduced"] is False, "projection claim differs")
    expected_block = {field: manifest["block"][field] for field in BLOCK_FIELDS}
    require(projection["block"] == expected_block, "decoded Ethereum header differs from benchmark")
    require(comparison.HEX_32.fullmatch(projection["parent_state_root"]) is not None,
            "parent state root is not canonical")
    fork = manifest["stwo"]["semantic_projection"]["fork"]
    require(projection["schema_id"] == fork["schema_id"], "selected fork differs")
    require(len(host_output) == 43 and host_output[32] == 1, "stateless result is not successful")
    require(int.from_bytes(host_output[33:41], "little") == expected_block["chain_id"]
            and int.from_bytes(host_output[41:43], "little") == projection["schema_id"],
            "stateless result namespace differs")
    require(decoded["new_payload_request_root"] == "0x" + host_output[:32].hex(),
            "recomputed payload request root differs from result")
    # This reconstructs the independently pinned expected ZisK framing. It is
    # not a new ZisK execution or a claim that both output byte strings equal.
    zisk_output = bytes([32]) + bytes.fromhex(expected_block["hash"][2:]) + bytes(223)
    pinned = manifest["zisk"]["execution"]["output"]
    require(pinned["framing"] == "u8-length-prefixed-block-hash-zero-padded"
            and len(zisk_output) == pinned["bytes"]
            and hashlib.sha256(zisk_output).hexdigest() == pinned["sha256"],
            "decoded block hash differs from pinned ZisK output statement")
    return {"block": expected_block, "parent_state_root": projection["parent_state_root"],
            "new_payload_request_root": decoded["new_payload_request_root"],
            "successful_validation": True, "chain_id": expected_block["chain_id"],
            "schema_id": projection["schema_id"],
            "zisk_expected_output_sha256": pinned["sha256"]}


def validate_materialization_join(admitted: dict, *, expected_elf: dict,
                                  runner: dict, output: dict) -> dict:
    source, value = admitted["source_request"], admitted["manifest"]
    for field, expected in (("elf", expected_elf), ("input", runner), ("expected_output", output)):
        require(all(source[field][key] == expected[key] for key in ("bytes", "sha256")),
                f"materialization {field} differs from normalized statement")
    require(source["strict_completion"] is True, "materialization is not terminal execution")
    return {"job": value["job"], "segment_count": value["segment_count"],
            "total_cycles": value["total_cycles"],
            "source_request": admitted["source_request_identity"]}


def normalize(*, manifest_path: Path, zisk_input: Path, canonical_input: Path,
              runner_input: Path, host_output: Path, materialization_path: Path,
              materialization_sha256: str, elf_path: Path, elf_sha256: str,
              projection_executable: Path, projection_executable_sha256: str) -> dict:
    manifest = comparison.load_manifest(manifest_path)
    store.validate_file_identity(materialization_path,
                                 {"bytes": materialization_path.stat().st_size, "sha256": materialization_sha256},
                                 "independently pinned materialization")
    exe = identity(projection_executable)
    require(exe["sha256"] == projection_executable_sha256, "projection executable identity differs")
    elf = identity(elf_path)
    require(elf["sha256"] == elf_sha256, "independent guest ELF identity differs")
    comparison._file_identity(zisk_input, manifest["zisk"]["fixture"], "ZisK fixture")
    comparison.validate_zisk_stdin(zisk_input, manifest["zisk"]["fixture"]["transport"])
    projection = comparison.validate_stwo_projection(canonical_input, runner_input, host_output, manifest)
    with tempfile.TemporaryDirectory(prefix="stwo-ethereum-normalization-") as temp:
        recomputed = Path(temp) / "projection"
        subprocess.run([str(projection_executable.resolve()), str(zisk_input.resolve()), str(recomputed)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        require((recomputed / "canonical-input.ssz").read_bytes() == canonical_input.read_bytes(),
                "fresh ZisK projection differs from retained canonical input")
        require((recomputed / "stwo-runner-input.bin").read_bytes() == runner_input.read_bytes(),
                "fresh ZisK projection differs from retained runner input")
        decoded = json.loads((recomputed / "normalization-v1.json").read_text())
    normalized = validate_decoded_projection(decoded, manifest, host_output.read_bytes())
    admitted = materialization.validate_recursive(materialization_path)
    job = validate_materialization_join(admitted, expected_elf=elf,
                                        runner=identity(runner_input), output=identity(host_output))
    result = {"schema": SCHEMA, "normalized_statement": normalized,
              "normalization_sha256": statement.sealed_sha256(normalized),
              "benchmark_statement_sha256": manifest["benchmark_protocol"]["statement_sha256"],
              "benchmark_manifest": identity(manifest_path),
              "materialization": identity(materialization_path), "job_binding": job,
              "elf": elf, "zisk_input": identity(zisk_input),
              "canonical_input": identity(canonical_input), "runner_input": identity(runner_input),
              "expected_output": identity(host_output), "projection_executable": exe,
              "projection": projection,
              "normalizer_source": identity(Path(__file__)),
              "matched_guest_statement_reproduced": False,
              "zisk_execution_reproduced": False, "whole_block_proof_verified": False,
              "claim": "Pinned decoded-header/input/output normalization and materialization job binding only"}
    result["content_sha256"] = statement.sealed_sha256(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=comparison.DEFAULT_MANIFEST)
    for name in ("zisk-input", "canonical-input", "runner-input", "host-output", "materialization",
                 "elf", "projection-executable", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("materialization-sha256", "elf-sha256", "projection-executable-sha256"):
        parser.add_argument("--" + name, required=True)
    args = vars(parser.parse_args())
    output = args.pop("output")
    args["manifest_path"] = args.pop("manifest")
    args["materialization_path"] = args.pop("materialization")
    args["elf_path"] = args.pop("elf")
    result = normalize(**args)
    with output.open("x") as file:
        json.dump(result, file, indent=2)
        file.write("\n")
    print(json.dumps({"status": "normalized-not-proof-verified", "receipt": str(output),
                      "content_sha256": result["content_sha256"]}))


if __name__ == "__main__":
    main()
