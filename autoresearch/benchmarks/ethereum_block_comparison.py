#!/usr/bin/env python3
"""Replay the pinned real-Ethereum-block comparison authority.

This gate deliberately separates execution, AIR planning, and proof claims.  A
fast emulator run is not a proof, and the existing Stwo mini-transition is not
a stateless Ethereum block validator.  The emitted report keeps those facts
machine-readable while the Stwo segmented recursive product is brought up.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any


SCHEMA = "stwo.autoresearch.ethereum-block-comparison.v3"
REPORT_SCHEMA = "stwo.autoresearch.ethereum-block-validation.v1"
DEFAULT_MANIFEST = Path(__file__).with_name("ethereum_block_mainnet_24628607.json")
REPO_ROOT = Path(__file__).resolve().parents[2]
HEX_32 = re.compile(r"^0x[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")


class ContractError(ValueError):
    """A pinned identity or semantic boundary failed closed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def _exact_keys(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{where} must be an object")
    actual = set(value)
    _require(actual == keys, f"{where} keys differ: {sorted(actual ^ keys)}")
    return value


def _positive_int(value: Any, where: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
             f"{where} must be a positive integer")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path: Path, where: str) -> None:
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode), f"{where} must be a regular file")
    _require(not path.is_symlink(), f"{where} must not be a symlink")


def _file_identity(path: Path, expected: dict[str, Any], where: str) -> None:
    _regular_file(path, where)
    _require(path.stat().st_size == expected["bytes"], f"{where} byte length differs")
    _require(_sha256_file(path) == expected["sha256"], f"{where} sha256 differs")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _source_identity(root: Path, expected: dict[str, Any], where: str) -> None:
    _require(_git(root, "rev-parse", "HEAD") == expected["commit"],
             f"{where} commit differs")
    _require(_git(root, "rev-parse", "HEAD^{tree}") == expected["tree"],
             f"{where} tree differs")


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    _regular_file(path, "manifest")
    value = json.loads(path.read_text(encoding="utf-8"))
    validate_manifest(value)
    return value


def validate_manifest(value: Any) -> None:
    root = _exact_keys(value, {"schema", "block", "zisk", "stwo", "claim_boundary"}, "manifest")
    _require(root["schema"] == SCHEMA, "manifest schema differs")

    block = _exact_keys(root["block"], {
        "chain", "chain_id", "number", "rpc_tag", "hash", "parent_hash", "state_root",
        "transactions_root", "receipts_root", "withdrawals_root", "requests_hash",
        "transaction_count", "gas_used", "gas_limit", "timestamp",
    }, "block")
    _require(block["chain"] == "mainnet" and block["chain_id"] == 1, "block chain differs")
    for name in ("number", "transaction_count", "gas_used", "gas_limit", "timestamp"):
        _positive_int(block[name], f"block.{name}")
    _require(block["rpc_tag"] == hex(block["number"]), "block RPC tag is not canonical")
    for name in ("hash", "parent_hash", "state_root", "transactions_root", "receipts_root",
                 "withdrawals_root", "requests_hash"):
        _require(isinstance(block[name], str) and HEX_32.fullmatch(block[name]) is not None,
                 f"block.{name} is not a lowercase 32-byte hex value")

    zisk = _exact_keys(root["zisk"], {
        "source", "ethereum_client", "fixture", "guest_elf", "tools", "execution", "plan",
    }, "zisk")
    for name in ("source", "ethereum_client"):
        source = _exact_keys(zisk[name], {"repository", "commit", "tree"}, f"zisk.{name}")
        _require(source["repository"].startswith("https://github.com/"),
                 f"zisk.{name}.repository differs")
        _require(GIT_OID.fullmatch(source["commit"]) is not None, f"zisk.{name}.commit differs")
        _require(GIT_OID.fullmatch(source["tree"]) is not None, f"zisk.{name}.tree differs")
    fixture = _exact_keys(zisk["fixture"], {
        "path", "bytes", "sha256", "git_blob", "transport",
    }, "zisk.fixture")
    for name in ("bytes",):
        _positive_int(fixture[name], f"zisk.fixture.{name}")
    _require(SHA256.fullmatch(fixture["sha256"]) is not None,
             "zisk.fixture.sha256 differs")
    _require(GIT_OID.fullmatch(fixture["git_blob"]) is not None,
             "zisk.fixture.git_blob differs")
    transport = _exact_keys(fixture["transport"], {"schema", "framing", "frames"},
                            "zisk.fixture.transport")
    _require(transport["schema"] == "zisk-stdin-frame-authority.v1",
             "ZisK stdin authority schema differs")
    _require(transport["framing"] == "u64le-length-prefixed-eight-byte-aligned",
             "ZisK stdin framing differs")
    _require(isinstance(transport["frames"], list) and len(transport["frames"]) == 2,
             "ZisK stdin must contain exactly two frames")
    expected_offset = 0
    for index, raw_frame in enumerate(transport["frames"]):
        frame = _exact_keys(raw_frame, {
            "index", "header_offset", "payload_offset", "payload_bytes", "padding_bytes",
            "sha256", "codec", "semantic_type",
        }, f"zisk.fixture.transport.frames[{index}]")
        _require(frame["index"] == index, "ZisK stdin frame index differs")
        _require(frame["header_offset"] == expected_offset,
                 "ZisK stdin frame header offset differs")
        _require(frame["payload_offset"] == expected_offset + 8,
                 "ZisK stdin frame payload offset differs")
        _positive_int(frame["payload_bytes"], "ZisK stdin frame payload bytes")
        _require(isinstance(frame["padding_bytes"], int)
                 and 0 <= frame["padding_bytes"] <= 7,
                 "ZisK stdin frame padding differs")
        _require(SHA256.fullmatch(frame["sha256"]) is not None,
                 "ZisK stdin frame sha256 differs")
        _require(frame["codec"] == "bincode-v2-serde-standard",
                 "ZisK stdin frame codec differs")
        expected_type = ("guest_reth::RethInputPublic" if index == 0
                         else "guest_reth::RethInputWitness")
        _require(frame["semantic_type"] == expected_type,
                 "ZisK stdin frame semantic type differs")
        end = frame["payload_offset"] + frame["payload_bytes"]
        expected_padding = (-end) % 8
        _require(frame["padding_bytes"] == expected_padding,
                 "ZisK stdin frame padding is not canonical")
        expected_offset = end + expected_padding
    _require(expected_offset == fixture["bytes"],
             "ZisK stdin frame inventory does not cover the fixture")

    item = _exact_keys(zisk["guest_elf"], {"path", "bytes", "sha256", "git_blob"},
                       "zisk.guest_elf")
    _positive_int(item["bytes"], "zisk.guest_elf.bytes")
    _require(SHA256.fullmatch(item["sha256"]) is not None,
             "zisk.guest_elf.sha256 differs")
    _require(GIT_OID.fullmatch(item["git_blob"]) is not None,
             "zisk.guest_elf.git_blob differs")

    tools = _exact_keys(zisk["tools"], {"version", "ziskemu", "cargo_zisk_dev"}, "zisk.tools")
    _require(tools["version"] == "1.2.0-alpha", "ZisK tool version differs")
    for name in ("ziskemu", "cargo_zisk_dev"):
        tool = _exact_keys(tools[name], {"bytes", "sha256"}, f"zisk.tools.{name}")
        _positive_int(tool["bytes"], f"zisk.tools.{name}.bytes")
        _require(SHA256.fullmatch(tool["sha256"]) is not None,
                 f"zisk.tools.{name}.sha256 differs")

    execution = _exact_keys(zisk["execution"], {
        "steps", "sdk_display_cost", "stats_cost_including_initialization",
        "initialization_cost", "cost", "output",
    }, "zisk.execution")
    for name in ("steps", "sdk_display_cost", "stats_cost_including_initialization",
                 "initialization_cost"):
        _positive_int(execution[name], f"zisk.execution.{name}")
    _require(execution["stats_cost_including_initialization"] - execution["sdk_display_cost"]
             == execution["initialization_cost"], "ZisK initialization-cost projection differs")
    cost = _exact_keys(execution["cost"], {
        "base", "main", "opcodes", "precompiles", "memory_including_initialization", "frops",
    }, "zisk.execution.cost")
    for name, amount in cost.items():
        _positive_int(amount, f"zisk.execution.cost.{name}")
    output = _exact_keys(execution["output"], {"bytes", "sha256", "framing"},
                         "zisk.execution.output")
    _positive_int(output["bytes"], "zisk.execution.output.bytes")
    _require(SHA256.fullmatch(output["sha256"]) is not None,
             "zisk.execution.output.sha256 differs")
    _require(output["framing"] == "u8-length-prefixed-block-hash-zero-padded",
             "ZisK output framing differs")

    plan = _exact_keys(zisk["plan"], {
        "instances", "air_types", "total_instances", "padded_rows", "committed_stage_cells",
        "constant_cells", "all_cells", "geometry_sha256", "global_info",
    }, "zisk.plan")
    instances = plan["instances"]
    _require(isinstance(instances, dict) and instances == dict(sorted(instances.items())),
             "ZisK plan instances must be a sorted object")
    for name, count in instances.items():
        _require(isinstance(name, str) and name, "ZisK AIR name is empty")
        _positive_int(count, f"zisk.plan.instances.{name}")
    _require(plan["air_types"] == len(instances), "ZisK AIR type count differs")
    _require(plan["total_instances"] == sum(instances.values()), "ZisK instance total differs")
    for name in ("padded_rows", "committed_stage_cells", "constant_cells", "all_cells"):
        _positive_int(plan[name], f"zisk.plan.{name}")
    _require(plan["all_cells"] == plan["committed_stage_cells"] + plan["constant_cells"],
             "ZisK total cell projection differs")
    _require(SHA256.fullmatch(plan["geometry_sha256"]) is not None,
             "ZisK geometry digest differs")
    global_info = _exact_keys(plan["global_info"], {"bytes", "sha256"},
                              "zisk.plan.global_info")
    _positive_int(global_info["bytes"], "zisk.plan.global_info.bytes")
    _require(SHA256.fullmatch(global_info["sha256"]) is not None,
             "zisk.plan.global_info.sha256 differs")

    stwo = _exact_keys(root["stwo"], {
        "one_shot_max_steps", "whole_frontend_verified", "proof_system_soundness",
        "independent_proof_verifier_implemented", "full_block_guest_ported",
        "semantic_projection", "matched_semantic_input_projected",
        "full_block_execution_reproduced", "full_block_segment_proofs_verified",
        "full_block_recursive_root_verified",
    }, "stwo")
    _positive_int(stwo["one_shot_max_steps"], "stwo.one_shot_max_steps")
    projection = _exact_keys(stwo["semantic_projection"], {
        "schema", "validator_source", "fork", "witness", "canonical_input",
        "stwo_runner_input", "host_validation",
    }, "stwo.semantic_projection")
    _require(projection["schema"] == "stwo.ethereum.stateless-input-projection.v1",
             "Stwo semantic projection schema differs")
    source = _exact_keys(projection["validator_source"], {"repository", "commit", "tree"},
                         "stwo.semantic_projection.validator_source")
    _require(source["repository"] == "https://github.com/paradigmxyz/stateless.git",
             "Stwo stateless validator repository differs")
    _require(GIT_OID.fullmatch(source["commit"]) is not None,
             "Stwo stateless validator commit differs")
    _require(GIT_OID.fullmatch(source["tree"]) is not None,
             "Stwo stateless validator tree differs")
    fork = _exact_keys(projection["fork"], {
        "canonical", "schema_id", "block_timestamp", "legacy_activation_field",
        "legacy_activation_timestamp", "canonical_mainnet_bpo2_timestamp",
    }, "stwo.semantic_projection.fork")
    _require(fork == {
        "canonical": "BPO2",
        "schema_id": 0x1401,
        "block_timestamp": block["timestamp"],
        "legacy_activation_field": "bpo1_time",
        "legacy_activation_timestamp": 1_767_747_671,
        "canonical_mainnet_bpo2_timestamp": 1_767_747_671,
    }, "Stwo semantic projection fork authority differs")
    witness = _exact_keys(projection["witness"], {
        "state_nodes", "codes", "legacy_keys", "headers", "embedded_public_keys",
        "recovered_transaction_public_keys",
    }, "stwo.semantic_projection.witness")
    expected_witness = {
        "state_nodes": 3854,
        "codes": 120,
        "legacy_keys": 835,
        "headers": 1,
        "embedded_public_keys": 0,
        "recovered_transaction_public_keys": block["transaction_count"],
    }
    _require(witness == expected_witness, "Stwo semantic projection witness inventory differs")
    canonical = _exact_keys(projection["canonical_input"], {"bytes", "sha256", "framing"},
                            "stwo.semantic_projection.canonical_input")
    runner_input = _exact_keys(projection["stwo_runner_input"],
                               {"bytes", "sha256", "framing"},
                               "stwo.semantic_projection.stwo_runner_input")
    host = _exact_keys(projection["host_validation"], {
        "successful_validation", "output_bytes", "output_sha256",
        "new_payload_request_root", "chain_id", "schema_id",
    }, "stwo.semantic_projection.host_validation")
    for where, identity in (("canonical input", canonical), ("Stwo runner input", runner_input)):
        _positive_int(identity["bytes"], where + " bytes")
        _require(SHA256.fullmatch(identity["sha256"]) is not None, where + " sha256 differs")
    _require(canonical["framing"] == "u16be-schema-id-plus-ssz",
             "canonical input framing differs")
    _require(runner_input["framing"] == "u32le-payload-length-plus-canonical-input",
             "Stwo runner input framing differs")
    _require(runner_input["bytes"] == canonical["bytes"] + 4,
             "Stwo runner input length projection differs")
    _require(host["successful_validation"] is True, "Stwo host validation did not succeed")
    _require(host["output_bytes"] == 43, "Stwo host output length differs")
    _require(SHA256.fullmatch(host["output_sha256"]) is not None,
             "Stwo host output sha256 differs")
    _require(SHA256.fullmatch(host["new_payload_request_root"]) is not None,
             "Stwo payload-request root differs")
    _require(host["chain_id"] == block["chain_id"] and host["schema_id"] == fork["schema_id"],
             "Stwo host validation authority differs")
    expected_status = {
        "whole_frontend_verified": False,
        "proof_system_soundness": False,
        "independent_proof_verifier_implemented": False,
        "full_block_guest_ported": False,
        "matched_semantic_input_projected": True,
        "full_block_execution_reproduced": False,
        "full_block_segment_proofs_verified": False,
        "full_block_recursive_root_verified": False,
    }
    for name, status in expected_status.items():
        _require(stwo[name] is status, f"stwo.{name} differs from retained evidence")

    claim = _exact_keys(root["claim_boundary"], {
        "zisk_stateless_block_execution_reproduced", "zisk_air_plan_reproduced",
        "zisk_full_block_proof_reproduced", "stwo_mini_transition_is_full_ethereum_block",
        "matched_guest_statement_reproduced", "stwo_full_block_comparison_ready",
        "performance_comparison_status",
    }, "claim_boundary")
    _require(claim["zisk_stateless_block_execution_reproduced"] is True,
             "ZisK execution claim differs")
    _require(claim["zisk_air_plan_reproduced"] is True, "ZisK plan claim differs")
    for name in ("zisk_full_block_proof_reproduced", "stwo_mini_transition_is_full_ethereum_block",
                 "matched_guest_statement_reproduced", "stwo_full_block_comparison_ready"):
        _require(claim[name] is False, f"claim_boundary.{name} is not evidence-backed")
    _require(claim["performance_comparison_status"]
             == "blocked-on-complete-rv32-execution-and-recursive-full-block-proof",
             "performance comparison status differs")


def validate_stwo_source(root: Path, manifest: dict[str, Any]) -> None:
    status = (root / "soundness/RISCV_FRONTEND_VERIFICATION_STATUS.md").read_text()
    _require("whole_frontend_verified = false" in status,
             "frontend verification status is not the pinned false claim")
    _require("proof_system_soundness = false" in status,
             "proof-system soundness status is not the pinned false claim")
    independent = (root / "soundness/INDEPENDENT_PROOF_SYSTEM_VALIDATION.md").read_text()
    _require("**Status:** engineering design; implementation not started." in independent,
             "independent verifier status changed; refresh the comparison authority")
    geometry = (root / "src/frontends/riscv/prover/statement_validation.zig").read_text()
    statement = (root / "src/frontends/riscv/air/statement.zig").read_text()
    _require("const MAX_OPCODE_SHARD_LOG_SIZE: u32 = 16;" in geometry,
             "opcode shard bound changed")
    match = re.search(r"pub const MAX_COMPONENTS: usize = ([0-9]+);", statement)
    _require(match is not None, "MAX_COMPONENTS source authority missing")
    cap = int(match.group(1)) * (1 << 16)
    _require(cap == manifest["stwo"]["one_shot_max_steps"],
             "Stwo one-shot execution cap differs")


def validate_zisk_stdin(path: Path, expected: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate ZiskStdin framing and return its content-addressed frame inventory."""
    _regular_file(path, "ZisK stdin")
    data = path.read_bytes()
    frames: list[dict[str, Any]] = []
    offset = 0
    while offset < len(data):
        _require(offset + 8 <= len(data), "ZisK stdin has a truncated frame header")
        header_offset = offset
        payload_bytes = int.from_bytes(data[offset:offset + 8], "little")
        _positive_int(payload_bytes, "ZisK stdin frame length")
        payload_offset = offset + 8
        payload_end = payload_offset + payload_bytes
        _require(payload_end <= len(data), "ZisK stdin has a truncated frame payload")
        padding_bytes = (-payload_end) % 8
        frame_end = payload_end + padding_bytes
        _require(frame_end <= len(data), "ZisK stdin has truncated alignment padding")
        _require(not any(data[payload_end:frame_end]),
                 "ZisK stdin alignment padding must be zero")
        frames.append({
            "index": len(frames),
            "header_offset": header_offset,
            "payload_offset": payload_offset,
            "payload_bytes": payload_bytes,
            "padding_bytes": padding_bytes,
            "sha256": _sha256_bytes(data[payload_offset:payload_end]),
            "codec": expected["frames"][len(frames)]["codec"]
            if len(frames) < len(expected["frames"]) else None,
            "semantic_type": expected["frames"][len(frames)]["semantic_type"]
            if len(frames) < len(expected["frames"]) else None,
        })
        offset = frame_end
    _require(offset == len(data), "ZisK stdin has trailing bytes")
    _require(frames == expected["frames"], "ZisK stdin frame inventory differs")
    return frames


def validate_stwo_projection(
    canonical_path: Path,
    runner_input_path: Path,
    host_output_path: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Replay the retained canonical-SSZ, runner-transport, and host-result join."""
    projection = manifest["stwo"]["semantic_projection"]
    canonical_identity = projection["canonical_input"]
    runner_identity = projection["stwo_runner_input"]
    host_identity = projection["host_validation"]
    _file_identity(canonical_path, canonical_identity, "canonical Stwo input")
    _file_identity(runner_input_path, runner_identity, "Stwo runner input")
    _file_identity(host_output_path, {
        "bytes": host_identity["output_bytes"],
        "sha256": host_identity["output_sha256"],
    }, "Stwo host output")

    canonical = canonical_path.read_bytes()
    runner_input = runner_input_path.read_bytes()
    host_output = host_output_path.read_bytes()
    schema_id = projection["fork"]["schema_id"]
    _require(canonical[:2] == schema_id.to_bytes(2, "big"),
             "canonical Stwo input schema prefix differs")
    _require(runner_input[:4] == len(canonical).to_bytes(4, "little"),
             "Stwo runner input length prefix differs")
    _require(runner_input[4:] == canonical,
             "Stwo runner input payload differs from canonical SSZ")
    _require(host_output[:32].hex() == host_identity["new_payload_request_root"],
             "Stwo host payload-request root differs")
    _require(host_output[32] == 1, "Stwo host validation success byte differs")
    _require(int.from_bytes(host_output[33:41], "little") == host_identity["chain_id"],
             "Stwo host output chain id differs")
    _require(int.from_bytes(host_output[41:43], "little") == schema_id,
             "Stwo host output schema id differs")
    return {
        "schema": projection["schema"],
        "status": "host-semantic-projection-valid",
        "canonical_input_sha256": canonical_identity["sha256"],
        "stwo_runner_input_sha256": runner_identity["sha256"],
        "host_output_sha256": host_identity["output_sha256"],
        "new_payload_request_root": host_identity["new_payload_request_root"],
    }


def validate_client_fixture(client_root: Path, manifest: dict[str, Any]) -> tuple[Path, Path]:
    zisk = manifest["zisk"]
    _source_identity(client_root, zisk["ethereum_client"], "ZisK Ethereum client")
    fixture = client_root / zisk["fixture"]["path"]
    elf = client_root / zisk["guest_elf"]["path"]
    for name, path in (("fixture", fixture), ("guest ELF", elf)):
        expected = zisk["fixture"] if name == "fixture" else zisk["guest_elf"]
        _file_identity(path, expected, f"ZisK {name}")
        blob = _git(client_root, "hash-object", str(path.relative_to(client_root)))
        _require(blob == expected["git_blob"], f"ZisK {name} git blob differs")
    validate_zisk_stdin(fixture, zisk["fixture"]["transport"])
    return fixture, elf


def parse_execution(stdout_path: Path, stats_path: Path, output_path: Path,
                    manifest: dict[str, Any]) -> dict[str, Any]:
    for name, path in (("execution stdout", stdout_path), ("execution stats", stats_path),
                       ("execution output", output_path)):
        _regular_file(path, name)
    text = stdout_path.read_text(encoding="utf-8")
    block = manifest["block"]
    execution = manifest["zisk"]["execution"]

    def number(pattern: str, where: str) -> int:
        match = re.search(pattern, text, re.DOTALL)
        _require(match is not None, f"{where} missing from ZisK execution output")
        return int(match.group(1).replace(",", ""))

    _require(f"Block Hash: {block['hash']}" in text, "ZisK block hash differs")
    _require(number(r"Transaction Count:\s+([0-9,]+)", "transaction count")
             == block["transaction_count"], "ZisK transaction count differs")
    _require(number(r"Gas Consumed:\s+([0-9,]+)", "gas consumed") == block["gas_used"],
             "ZisK gas consumed differs")
    steps = number(r"║\s+STEPS\s+([0-9,]+)\s+║", "execution steps")
    _require(steps == execution["steps"], "ZisK execution steps differ")
    display_cost = number(
        r"◆ COST DISTRIBUTION SUMMARY.*?║\s+Total\s+([0-9,]+)\s+100\.0%",
        "SDK display cost",
    )
    _require(display_cost == execution["sdk_display_cost"], "ZisK SDK display cost differs")

    rows = list(csv.reader(stats_path.read_text(encoding="utf-8").splitlines()))
    stats: dict[str, int] = {}
    for row in rows:
        if (len(row) >= 3 and row[0] == "COST" and row[1] != "COST DISTRIBUTION"):
            stats[row[1]] = int(row[2])
        elif len(row) >= 2 and row[0] == "STEPS":
            _require(int(row[1]) == steps, "ZisK stats step count differs")
    expected_stats = {
        "MAIN": execution["cost"]["main"],
        "OPCODES": execution["cost"]["opcodes"],
        "PRECOMPILES": execution["cost"]["precompiles"],
        "MEMORY": execution["cost"]["memory_including_initialization"],
        "BASE": execution["cost"]["base"],
        "TOTAL": execution["stats_cost_including_initialization"],
        "FROPS": execution["cost"]["frops"],
    }
    _require(stats == expected_stats | {"VARIABLE": stats.get("VARIABLE")},
             "ZisK aggregate stats differ")
    _positive_int(stats["VARIABLE"], "ZisK variable cost")

    output = output_path.read_bytes()
    expected_output = execution["output"]
    _require(len(output) == expected_output["bytes"], "ZisK output length differs")
    _require(_sha256_bytes(output) == expected_output["sha256"], "ZisK output sha256 differs")
    _require(output[0] == 32, "ZisK output block-hash length differs")
    _require(output[1:33] == bytes.fromhex(block["hash"][2:]), "ZisK committed block hash differs")
    _require(not any(output[33:]), "ZisK output padding is nonzero")
    return {
        "steps": steps,
        "sdk_display_cost": display_cost,
        "stats_cost_including_initialization": stats["TOTAL"],
        "output_sha256": expected_output["sha256"],
    }


def parse_plan_counts(plan_stdout: Path, manifest: dict[str, Any]) -> dict[str, int]:
    _regular_file(plan_stdout, "ZisK plan stdout")
    text = plan_stdout.read_text(encoding="utf-8")
    matches = re.findall(r"Zisk \| (.*?) \| Total instances: ([0-9,]+)", text)
    _require(len(matches) == 1, "ZisK plan must contain exactly one summary")
    body, total_text = matches[0]
    counts: dict[str, int] = {}
    for item in body.split(" | "):
        name, count_text = item.rsplit(": ", 1)
        _require(name not in counts, f"duplicate ZisK AIR in plan: {name}")
        counts[name] = int(count_text.replace(",", ""))
    expected = manifest["zisk"]["plan"]
    _require(counts == expected["instances"], "ZisK AIR instance plan differs")
    _require(int(total_text.replace(",", "")) == expected["total_instances"],
             "ZisK plan total differs")
    match = re.search(r"Execution completed in [0-9,]+ms, steps: ([0-9,]+)", text)
    _require(match is not None, "ZisK plan execution step count missing")
    _require(int(match.group(1).replace(",", "")) == manifest["zisk"]["execution"]["steps"],
             "ZisK plan execution steps differ")
    return counts


def geometry_projection(proving_key: Path, counts: dict[str, int],
                        manifest: dict[str, Any]) -> dict[str, Any]:
    global_path = proving_key / "pilout.globalInfo.json"
    _file_identity(global_path, manifest["zisk"]["plan"]["global_info"],
                   "ZisK global proving-key info")
    global_info = json.loads(global_path.read_text(encoding="utf-8"))
    _require(isinstance(global_info.get("airs"), list) and len(global_info["airs"]) == 1,
             "ZisK global AIR inventory differs")
    row_authority = {item["name"]: item["num_rows"] for item in global_info["airs"][0]}

    projection: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    padded_rows = committed_cells = constant_cells = 0
    for name in sorted(counts):
        _require(name in row_authority, f"ZisK AIR is absent from global info: {name}")
        path = proving_key / f"zisk/Zisk/airs/{name}/air/{name}.starkinfo.json"
        _regular_file(path, f"ZisK {name} stark info")
        info = json.loads(path.read_text(encoding="utf-8"))
        _require(info.get("name") == name, f"ZisK {name} stark-info name differs")
        sections = info.get("mapSectionsN")
        _require(isinstance(sections, dict), f"ZisK {name} map sections missing")
        selected = {key: sections[key] for key in ("const", "cm1", "cm2", "cm3")}
        for key, value in selected.items():
            _positive_int(value, f"ZisK {name}.{key}")
        rows = _positive_int(row_authority[name], f"ZisK {name} rows")
        instances = counts[name]
        active_rows = rows * instances
        committed_columns = selected["cm1"] + selected["cm2"] + selected["cm3"]
        active_committed = active_rows * committed_columns
        active_constants = active_rows * selected["const"]
        padded_rows += active_rows
        committed_cells += active_committed
        constant_cells += active_constants
        projection.append({
            "instances": instances,
            "map_sections_n": selected,
            "name": name,
            "rows_per_instance": rows,
            "security": info["starkStruct"],
        })
        summary.append({
            "name": name,
            "instances": instances,
            "rows_per_instance": rows,
            "committed_columns": committed_columns,
            "committed_cells": active_committed,
        })

    digest = _sha256_bytes(_canonical_bytes(projection))
    expected = manifest["zisk"]["plan"]
    _require(digest == expected["geometry_sha256"], "ZisK active geometry digest differs")
    _require(padded_rows == expected["padded_rows"], "ZisK padded-row total differs")
    _require(committed_cells == expected["committed_stage_cells"],
             "ZisK committed-cell total differs")
    _require(constant_cells == expected["constant_cells"], "ZisK constant-cell total differs")
    return {
        "air_types": len(counts),
        "total_instances": sum(counts.values()),
        "padded_rows": padded_rows,
        "committed_stage_cells": committed_cells,
        "constant_cells": constant_cells,
        "all_cells": committed_cells + constant_cells,
        "geometry_sha256": digest,
        "airs": summary,
    }


def validate_rpc_result(result: Any, manifest: dict[str, Any]) -> None:
    _require(isinstance(result, dict), "Ethereum RPC block result is absent")
    block = manifest["block"]
    expected = {
        "number": block["rpc_tag"],
        "hash": block["hash"],
        "parentHash": block["parent_hash"],
        "stateRoot": block["state_root"],
        "transactionsRoot": block["transactions_root"],
        "receiptsRoot": block["receipts_root"],
        "withdrawalsRoot": block["withdrawals_root"],
        "requestsHash": block["requests_hash"],
        "gasUsed": hex(block["gas_used"]),
        "gasLimit": hex(block["gas_limit"]),
        "timestamp": hex(block["timestamp"]),
    }
    for name, value in expected.items():
        _require(result.get(name) == value, f"Ethereum RPC {name} differs")
    transactions = result.get("transactions")
    _require(isinstance(transactions, list) and len(transactions) == block["transaction_count"],
             "Ethereum RPC transaction count differs")


def query_rpc(endpoint: str, manifest: dict[str, Any]) -> dict[str, Any]:
    payload = _canonical_bytes({
        "jsonrpc": "2.0",
        "method": "eth_getBlockByNumber",
        "params": [manifest["block"]["rpc_tag"], False],
        "id": 1,
    }).rstrip(b"\n")
    request = urllib.request.Request(
        endpoint,
        data=payload,
        headers={
            "content-type": "application/json",
            "user-agent": "stwo-zig-ethereum-block-authority/1",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    _require(value.get("error") is None, "Ethereum RPC returned an error")
    validate_rpc_result(value.get("result"), manifest)
    return value["result"]


def validate_local(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_manifest(args.manifest)
    validate_stwo_source(args.stwo_root, manifest)
    validate_client_fixture(args.client_root, manifest)
    _source_identity(args.zisk_root, manifest["zisk"]["source"], "ZisK source")
    _file_identity(args.ziskemu, manifest["zisk"]["tools"]["ziskemu"], "ziskemu")
    _file_identity(args.cargo_zisk_dev, manifest["zisk"]["tools"]["cargo_zisk_dev"],
                   "cargo-zisk-dev")
    execution = parse_execution(
        args.execution_stdout, args.execution_stats, args.execution_output, manifest,
    )
    counts = parse_plan_counts(args.plan_stdout, manifest)
    geometry = geometry_projection(args.proving_key, counts, manifest)
    return {
        "schema": REPORT_SCHEMA,
        "manifest_sha256": _sha256_file(args.manifest),
        "block": manifest["block"],
        "zisk_execution": execution,
        "zisk_plan": geometry,
        "stwo": manifest["stwo"],
        "claim_boundary": manifest["claim_boundary"],
    }


def validate_projection_files(args: argparse.Namespace) -> dict[str, Any]:
    manifest = load_manifest(args.manifest)
    return validate_stwo_projection(
        args.canonical_input,
        args.stwo_runner_input,
        args.host_output,
        manifest,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    sub = parser.add_subparsers(dest="command", required=True)
    manifest = sub.add_parser("validate-manifest")
    manifest.set_defaults(action=lambda args: {"schema": SCHEMA, "status": "valid"})

    local = sub.add_parser("validate-local")
    local.add_argument("--stwo-root", type=Path, default=REPO_ROOT)
    local.add_argument("--client-root", type=Path, required=True)
    local.add_argument("--zisk-root", type=Path, required=True)
    local.add_argument("--ziskemu", type=Path, required=True)
    local.add_argument("--cargo-zisk-dev", type=Path, required=True)
    local.add_argument("--proving-key", type=Path, required=True)
    local.add_argument("--execution-stdout", type=Path, required=True)
    local.add_argument("--execution-stats", type=Path, required=True)
    local.add_argument("--execution-output", type=Path, required=True)
    local.add_argument("--plan-stdout", type=Path, required=True)
    local.set_defaults(action=validate_local)

    projection = sub.add_parser("validate-projection")
    projection.add_argument("--canonical-input", type=Path, required=True)
    projection.add_argument("--stwo-runner-input", type=Path, required=True)
    projection.add_argument("--host-output", type=Path, required=True)
    projection.set_defaults(action=validate_projection_files)

    rpc = sub.add_parser("validate-rpc")
    rpc.add_argument("--endpoint", required=True)
    rpc.set_defaults(action=lambda args: {
        "schema": REPORT_SCHEMA,
        "status": "rpc-valid",
        "block": query_rpc(args.endpoint, load_manifest(args.manifest)),
    })
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        if args.command == "validate-manifest":
            validate_stwo_source(REPO_ROOT, manifest)
        report = args.action(args)
    except (ContractError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(_canonical_bytes(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
