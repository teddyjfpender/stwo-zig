"""Strict product authority for the experimental Stwo Ethereum guest."""

from __future__ import annotations

import hashlib
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


PROVIDER_SCHEMA = "stwo.ethereum.alloy-signer-provider.v1"
OVERLAY_SCHEMA = "stwo.ethereum.guest-source-overlay.v1"
PRODUCTS_SCHEMA = "stwo.ethereum.guest-products.v1"
SMOKE_EXECUTION_SCHEMA = "stwo.ethereum.abi-smoke-execution-receipt.v1"
KECCAK_DIAGNOSTIC_SCHEMA = "stwo.ethereum.keccak-only-full-block-execution.v1"
ABI_SCHEMA = "stwo.ethereum.secp256k1-recover-abi.v1"
PROFILE_NAME = "rv32im-zkvm-ethereum-v1"
PROFILE_DIGEST = "fbe8833de35b29ab155afed58f593d44d2a7257ad4491d953742d394da66cfc2"
RECOVERY_WORD = 0x0602_800B
KECCAK_WORD = 0x0402_800B
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")
SMOKE_EXPECTED_ADDRESS = "7e5f4552091a69125d5dfcb7b8c2659029395bdf"


class ProductContractError(ValueError):
    """A source, ABI, or guest-product identity failed closed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProductContractError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(isinstance(value, dict), f"{where} must be an object")
    actual = set(value)
    _require(actual == keys, f"{where} keys differ: {sorted(actual ^ keys)}")
    return value


def _positive(value: Any, where: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
             f"{where} must be a positive integer")
    return value


def _canonical(value: Any) -> bytes:
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


def _identity(value: Any, where: str, *, empty: bool = False) -> dict[str, Any]:
    value = _exact(value, {"bytes", "sha256"}, where)
    valid_bytes = (isinstance(value["bytes"], int) and not isinstance(value["bytes"], bool)
                   and value["bytes"] >= int(not empty))
    _require(valid_bytes, f"{where} byte length differs")
    _require(SHA256.fullmatch(value["sha256"]) is not None, f"{where} sha256 differs")
    return value


def _relative_path(value: Any, where: str) -> str:
    _require(isinstance(value, str) and value, f"{where} path is empty")
    path = Path(value)
    _require(not path.is_absolute() and ".." not in path.parts,
             f"{where} path is not a safe relative path")
    return value


def validate_manifest(provider: Any, products: Any) -> None:
    """Validate the provider, ABI, source-overlay, and product declarations."""
    provider = _exact(provider, {"schema", "source", "scope", "abi", "profile"},
                      "stwo.provider")
    _require(provider["schema"] == PROVIDER_SCHEMA, "Stwo provider schema differs")

    source = _exact(provider["source"], {"repository", "commit", "tree", "overlay"},
                    "stwo.provider.source")
    _require(source["repository"] == "https://github.com/paradigmxyz/stateless.git",
             "Stwo provider repository differs")
    _require(GIT_OID.fullmatch(source["commit"]) is not None,
             "Stwo provider commit differs")
    _require(GIT_OID.fullmatch(source["tree"]) is not None,
             "Stwo provider tree differs")
    overlay = _exact(source["overlay"], {"schema", "files", "sha256"},
                     "stwo.provider.source.overlay")
    _require(overlay["schema"] == OVERLAY_SCHEMA, "Stwo source overlay schema differs")
    _require(isinstance(overlay["files"], list) and overlay["files"],
             "Stwo source overlay is empty")
    paths: list[str] = []
    for index, raw in enumerate(overlay["files"]):
        item = _exact(raw, {"path", "bytes", "sha256"}, f"source overlay file {index}")
        paths.append(_relative_path(item["path"], f"source overlay file {index}"))
        _positive(item["bytes"], f"source overlay file {index} bytes")
        _require(SHA256.fullmatch(item["sha256"]) is not None,
                 f"source overlay file {index} sha256 differs")
    _require(paths == sorted(set(paths)), "Stwo source overlay paths are not unique and sorted")
    _require(SHA256.fullmatch(overlay["sha256"]) is not None,
             "Stwo source overlay digest differs")
    _require(_sha256_bytes(_canonical(overlay["files"])) == overlay["sha256"],
             "Stwo source overlay inventory digest differs")

    expected_scope = {
        "alloy_transaction_signer_recovery": "native-success-only",
        "alloy_address_derivation": "native-keccak256-over-recovered-pubkey",
        "alloy_verify_given_pubkey": "software-k256",
        "revm_ecrecover": "software-default-crypto",
        "native_rejection": "fatal-no-fallback",
        "invalid_result_air_implemented": False,
    }
    _require(provider["scope"] == expected_scope, "Stwo provider scope differs")

    abi = _exact(provider["abi"], {
        "schema", "instruction", "instruction_word_x5", "alignment", "record_bytes", "fields",
    }, "stwo.provider.abi")
    _require(abi == {
        "schema": ABI_SCHEMA,
        "instruction": "CUSTOM-0/funct7=3/rs1=record-ptr/rs2=0/funct3=0/rd=0",
        "instruction_word_x5": f"0x{RECOVERY_WORD:08x}",
        "alignment": 4,
        "record_bytes": 168,
        "fields": [
            {"name": "digest", "offset": 0, "bytes": 32, "encoding": "big-endian-bytes"},
            {"name": "r", "offset": 32, "bytes": 32, "encoding": "big-endian-bytes"},
            {"name": "s", "offset": 64, "bytes": 32, "encoding": "big-endian-bytes"},
            {"name": "recovery_id", "offset": 96, "bytes": 4,
             "encoding": "u32-little-endian-0-or-1"},
            {"name": "public_key_xy", "offset": 100, "bytes": 64,
             "encoding": "big-endian-bytes"},
            {"name": "status", "offset": 164, "bytes": 4,
             "encoding": "u32-little-endian-exactly-1"},
        ],
    }, "Stwo signer-recovery ABI differs")

    _require(provider["profile"] == {
        "name": PROFILE_NAME,
        "wire_id": 3,
        "descriptor_schema": 1,
        "capability_bits": 6,
        "abi_version": 1,
        "semantic_digest": PROFILE_DIGEST,
    }, "Stwo combined execution profile differs")

    products = _exact(products, {"schema", "real_guest", "abi_smoke", "real_block"},
                      "stwo.guest_products")
    _require(products["schema"] == PRODUCTS_SCHEMA, "Stwo product schema differs")
    product_keys = {
        "path", "bytes", "sha256", "recovery_instruction_sites",
        "keccak_instruction_sites", "execution_reproduced", "execution_receipt",
    }
    expected_sites = {"real_guest": (1, 17), "abi_smoke": (1, 1)}
    for name in ("real_guest", "abi_smoke"):
        keys = product_keys | ({"expected_address"} if name == "abi_smoke" else set())
        product = _exact(products[name], keys, f"stwo.guest_products.{name}")
        _relative_path(product["path"], f"Stwo {name}")
        _positive(product["bytes"], f"Stwo {name} bytes")
        _require(SHA256.fullmatch(product["sha256"]) is not None,
                 f"Stwo {name} sha256 differs")
        sites = (product["recovery_instruction_sites"], product["keccak_instruction_sites"])
        _require(sites == expected_sites[name], f"Stwo {name} instruction inventory differs")
        if name == "real_guest":
            _require(product["execution_reproduced"] is False
                     and product["execution_receipt"] is None,
                     "Stwo real-guest execution is not yet retained")
        else:
            _require(product["execution_reproduced"] is True,
                     "Stwo ABI-smoke execution was not reproduced")
    _require(products["abi_smoke"]["expected_address"] == SMOKE_EXPECTED_ADDRESS,
             "Stwo ABI-smoke expected address differs")
    smoke_receipt = _exact(products["abi_smoke"]["execution_receipt"], {
        "schema", "claim_boundary", "source", "controller", "runner", "bundle",
        "execution", "proof_generated", "independent_proof_verification",
    }, "Stwo ABI-smoke execution receipt")
    _require(smoke_receipt["schema"] == SMOKE_EXECUTION_SCHEMA,
             "Stwo ABI-smoke execution schema differs")
    _require(smoke_receipt["claim_boundary"] == "execution-only-not-a-proof",
             "Stwo ABI-smoke claim boundary differs")
    source_receipt = _exact(smoke_receipt["source"], {
        "head", "tree", "status_sha256", "clean",
    }, "Stwo ABI-smoke source")
    for field in ("head", "tree"):
        _require(GIT_OID.fullmatch(source_receipt[field]) is not None,
                 f"Stwo ABI-smoke source {field} differs")
    _require(SHA256.fullmatch(source_receipt["status_sha256"]) is not None
             and source_receipt["clean"] is False,
             "Stwo ABI-smoke source dirty identity differs")
    _identity(smoke_receipt["controller"], "Stwo ABI-smoke controller")
    _identity(smoke_receipt["runner"], "Stwo ABI-smoke runner")
    bundle = _exact(smoke_receipt["bundle"], {
        "plan", "journal", "receipt", "stderr",
    }, "Stwo ABI-smoke bundle")
    for name in ("plan", "journal", "receipt"):
        _identity(bundle[name], f"Stwo ABI-smoke bundle {name}")
    _identity(bundle["stderr"], "Stwo ABI-smoke bundle stderr", empty=True)
    _require(bundle["stderr"] == {"bytes": 0, "sha256": _sha256_bytes(b"")},
             "Stwo ABI-smoke stderr is not empty")
    execution_receipt = _exact(smoke_receipt["execution"], {
        "schema", "status", "claim_boundary", "plan_sha256", "journal_bytes",
        "journal_sha256", "segment_count", "total_cycles", "total_core_trace_rows",
        "total_external_trace_rows", "clock_frame", "max_segment_cycle_count",
        "leaf_local_clock_ranges_within_v3_limit", "segment_statement_v2_admissible",
        "final_cpu_sha256", "final_rw_memory_sha256", "output_sha256",
    }, "Stwo ABI-smoke segmented receipt")
    _require(execution_receipt["schema"]
             == "stwo.riscv.segmented-execution-capture-receipt.v3"
             and execution_receipt["status"] == "complete"
             and execution_receipt["claim_boundary"] == "execution-only-not-a-proof",
             "Stwo ABI-smoke segmented receipt status differs")
    _require(execution_receipt["segment_count"] == 1
             and execution_receipt["total_cycles"] == 1256
             and execution_receipt["total_core_trace_rows"] == 1254
             and execution_receipt["total_external_trace_rows"] == 2
             and execution_receipt["max_segment_cycle_count"] == 1256,
             "Stwo ABI-smoke execution geometry differs")
    _require(execution_receipt["total_cycles"]
             == execution_receipt["total_core_trace_rows"]
             + execution_receipt["total_external_trace_rows"],
             "Stwo ABI-smoke row partition differs")
    _require(execution_receipt["clock_frame"] == "leaf_local"
             and execution_receipt["leaf_local_clock_ranges_within_v3_limit"] is True
             and execution_receipt["segment_statement_v2_admissible"] is True,
             "Stwo ABI-smoke segment admission differs")
    for field in ("plan_sha256", "journal_sha256", "final_cpu_sha256",
                  "final_rw_memory_sha256", "output_sha256"):
        _require(SHA256.fullmatch(execution_receipt[field]) is not None,
                 f"Stwo ABI-smoke {field} differs")
    _require(execution_receipt["journal_bytes"] == bundle["journal"]["bytes"]
             and execution_receipt["journal_sha256"] == bundle["journal"]["sha256"],
             "Stwo ABI-smoke journal custody differs")
    _require(execution_receipt["output_sha256"]
             == _sha256_bytes(bytes.fromhex(SMOKE_EXPECTED_ADDRESS)),
             "Stwo ABI-smoke output differs")
    _require(smoke_receipt["proof_generated"] is False
             and smoke_receipt["independent_proof_verification"] is False,
             "Stwo ABI-smoke proof boundary differs")

    real_block = _exact(products["real_block"], {
        "runner_input_path", "runner_input_bytes", "runner_input_sha256",
        "expected_output_path", "expected_output_bytes", "expected_output_sha256",
        "transaction_count", "execution_reproduced", "execution_receipt",
    }, "stwo.guest_products.real_block")
    _relative_path(real_block["runner_input_path"], "Stwo real-block runner input")
    _relative_path(real_block["expected_output_path"], "Stwo real-block expected output")
    for field in ("runner_input_bytes", "expected_output_bytes", "transaction_count"):
        _positive(real_block[field], f"Stwo real-block {field}")
    for field in ("runner_input_sha256", "expected_output_sha256"):
        _require(SHA256.fullmatch(real_block[field]) is not None,
                 f"Stwo real-block {field} differs")
    _require(real_block["execution_reproduced"] is False
             and real_block["execution_receipt"] is None,
             "Stwo real-block execution is not yet retained")


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return result.stdout.strip()


def _validate_elf(path: Path, expected: dict[str, Any], profile: dict[str, Any], where: str) -> None:
    _file_identity(path, expected, where)
    blob = path.read_bytes()
    _require(blob[:4] == b"\x7fELF" and blob[4:6] == b"\x01\x01",
             f"{where} is not a little-endian ELF32 image")
    _require(int.from_bytes(blob[18:20], "little") == 243,
             f"{where} is not a RISC-V ELF")
    magic = b"STWZKVM\x00"
    _require(blob.count(magic) == 1, f"{where} profile descriptor count differs")
    start = blob.index(magic)
    descriptor = blob[start:start + 56]
    _require(len(descriptor) == 56, f"{where} profile descriptor is truncated")
    _require(int.from_bytes(descriptor[8:10], "little") == profile["descriptor_schema"],
             f"{where} descriptor schema differs")
    _require(int.from_bytes(descriptor[10:12], "little") == profile["wire_id"],
             f"{where} profile id differs")
    _require(int.from_bytes(descriptor[12:20], "little") == profile["capability_bits"],
             f"{where} capability bits differ")
    _require(int.from_bytes(descriptor[20:22], "little") == profile["abi_version"],
             f"{where} ABI version differs")
    _require(descriptor[22:24] == b"\x00\x00", f"{where} descriptor reserved bits differ")
    _require(descriptor[24:56].hex() == profile["semantic_digest"],
             f"{where} semantic digest differs")
    program_offset = int.from_bytes(blob[28:32], "little")
    program_entry_bytes = int.from_bytes(blob[42:44], "little")
    program_count = int.from_bytes(blob[44:46], "little")
    _require(program_entry_bytes >= 32 and program_count > 0,
             f"{where} program-header table differs")
    executable = bytearray()
    for index in range(program_count):
        offset = program_offset + index * program_entry_bytes
        _require(offset + program_entry_bytes <= len(blob),
                 f"{where} program-header table is truncated")
        header = blob[offset:offset + program_entry_bytes]
        if int.from_bytes(header[:4], "little") != 1:
            continue
        if int.from_bytes(header[24:28], "little") & 1 == 0:
            continue
        file_offset = int.from_bytes(header[4:8], "little")
        file_bytes = int.from_bytes(header[16:20], "little")
        _require(file_offset + file_bytes <= len(blob),
                 f"{where} executable segment is truncated")
        executable.extend(blob[file_offset:file_offset + file_bytes])
    _require(executable, f"{where} has no executable load segment")
    _require(executable.count(RECOVERY_WORD.to_bytes(4, "little"))
             == expected["recovery_instruction_sites"],
             f"{where} recovery instruction inventory differs")
    _require(executable.count(KECCAK_WORD.to_bytes(4, "little"))
             == expected["keccak_instruction_sites"],
             f"{where} Keccak instruction inventory differs")


def validate_products(source_root: Path, provider: dict[str, Any],
                      products: dict[str, Any]) -> dict[str, Any]:
    """Replay source-overlay and built-product custody under `source_root`."""
    validate_manifest(provider, products)
    source = provider["source"]
    _require(_git(source_root, "rev-parse", "HEAD") == source["commit"],
             "Stwo guest base commit differs")
    _require(_git(source_root, "rev-parse", "HEAD^{tree}") == source["tree"],
             "Stwo guest base tree differs")
    for item in source["overlay"]["files"]:
        _file_identity(source_root / item["path"], item, f"Stwo source {item['path']}")

    profile = provider["profile"]
    for name in ("real_guest", "abi_smoke"):
        product = products[name]
        _validate_elf(source_root / product["path"], product, profile, f"Stwo {name}")
    real_block = products["real_block"]
    _file_identity(source_root / real_block["runner_input_path"], {
        "bytes": real_block["runner_input_bytes"],
        "sha256": real_block["runner_input_sha256"],
    }, "Stwo real-block runner input")
    _file_identity(source_root / real_block["expected_output_path"], {
        "bytes": real_block["expected_output_bytes"],
        "sha256": real_block["expected_output_sha256"],
    }, "Stwo real-block expected output")
    return {
        "schema": PRODUCTS_SCHEMA,
        "status": "source-and-products-valid",
        "source_overlay_sha256": source["overlay"]["sha256"],
        "real_guest_sha256": products["real_guest"]["sha256"],
        "abi_smoke_sha256": products["abi_smoke"]["sha256"],
        "real_block_runner_input_sha256": real_block["runner_input_sha256"],
    }


def validate_smoke_execution(bundle_root: Path, controller: Path, runner: Path,
                             product: dict[str, Any]) -> dict[str, Any]:
    """Replay the exact execution-only ABI-smoke bundle and retained tools."""
    declaration = product["execution_receipt"]
    _file_identity(controller, declaration["controller"], "retained smoke controller")
    _file_identity(runner, declaration["runner"], "retained smoke runner")
    names = {
        "plan": "plan.json",
        "journal": "execution.ndjson",
        "receipt": "receipt.json",
        "stderr": "invocation-000000.stderr",
    }
    for key, name in names.items():
        _file_identity(bundle_root / name, declaration["bundle"][key], f"smoke {key}")
    plan = json.loads((bundle_root / "plan.json").read_text(encoding="utf-8"))
    receipt = json.loads((bundle_root / "receipt.json").read_text(encoding="utf-8"))
    _require(plan["source"] == declaration["source"], "smoke source identity differs")
    _require({key: plan["controller"][key] for key in ("bytes", "sha256")}
             == declaration["controller"], "smoke controller plan identity differs")
    _require({key: plan["tool"][key] for key in ("bytes", "sha256")}
             == declaration["runner"], "smoke runner plan identity differs")
    _require({key: plan["elf"][key] for key in ("bytes", "sha256")}
             == {key: product[key] for key in ("bytes", "sha256")},
             "smoke ELF plan identity differs")
    _require(plan["input"] == {"path": None, "bytes": 0, "sha256": _sha256_bytes(b"")},
             "smoke input identity differs")
    _require(plan["execution_profile"] == PROFILE_NAME
             and plan["segment_step_budget"] == 65536
             and plan["strict_completion"] is True
             and plan["clock_frame"] == "leaf_local",
             "smoke execution plan differs")
    _require(receipt == declaration["execution"], "smoke receipt projection differs")
    replay = subprocess.run(
        [sys.executable, str(controller), "validate", str(bundle_root)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _require(replay.returncode == 0 and replay.stderr == b"",
             "smoke controller replay failed")
    _require(replay.stdout == (bundle_root / "receipt.json").read_bytes(),
             "smoke controller replay bytes differ from the retained receipt")
    return {
        "schema": SMOKE_EXECUTION_SCHEMA,
        "status": "execution-replayed",
        "claim_boundary": "execution-only-not-a-proof",
        "elf_sha256": product["sha256"],
        "journal_sha256": declaration["bundle"]["journal"]["sha256"],
        "output_sha256": declaration["execution"]["output_sha256"],
    }


def validate_keccak_diagnostic(value: Any) -> None:
    """Validate the historical Keccak-only full-block execution boundary."""
    value = _exact(value, {
        "schema", "profile", "combined_ethereum_profile", "transaction_signer_recovery",
        "claim_boundary", "source", "controller", "runner", "guest_elf", "input",
        "bundle", "execution", "timing", "proof_generated", "segment_proofs_verified",
        "recursive_root_verified",
    }, "Stwo Keccak-only diagnostic")
    _require(value["schema"] == KECCAK_DIAGNOSTIC_SCHEMA
             and value["profile"] == "rv32im-zkvm-keccakf-v1"
             and value["combined_ethereum_profile"] is False
             and value["transaction_signer_recovery"]
             == "host-supplied-key-plus-software-recovery-and-match"
             and value["claim_boundary"] == "execution-only-not-a-proof",
             "Stwo Keccak-only diagnostic boundary differs")
    source = _exact(value["source"], {
        "head", "tree", "status_sha256", "clean", "variant",
    }, "Stwo Keccak-only source")
    for field in ("head", "tree"):
        _require(GIT_OID.fullmatch(source[field]) is not None,
                 f"Stwo Keccak-only source {field} differs")
    _require(SHA256.fullmatch(source["status_sha256"]) is not None
             and source["clean"] is False
             and source["variant"] == "byte-equivalent-host-memory-snapshot-optimization",
             "Stwo Keccak-only source variant differs")
    for name in ("controller", "runner", "guest_elf", "input"):
        _identity(value[name], f"Stwo Keccak-only {name}")
    bundle = _exact(value["bundle"], {"plan", "journal", "receipt", "stderr"},
                    "Stwo Keccak-only bundle")
    for name in ("plan", "journal", "receipt"):
        _identity(bundle[name], f"Stwo Keccak-only bundle {name}")
    _identity(bundle["stderr"], "Stwo Keccak-only stderr", empty=True)
    _require(bundle["stderr"] == {"bytes": 0, "sha256": _sha256_bytes(b"")},
             "Stwo Keccak-only stderr is not empty")
    execution = _exact(value["execution"], {
        "schema", "status", "claim_boundary", "plan_sha256", "journal_bytes",
        "journal_sha256", "segment_count", "total_cycles", "total_core_trace_rows",
        "total_external_trace_rows", "clock_frame", "max_segment_cycle_count",
        "leaf_local_clock_ranges_within_v3_limit", "segment_statement_v2_admissible",
        "final_cpu_sha256", "final_rw_memory_sha256", "output_sha256",
    }, "Stwo Keccak-only segmented receipt")
    _require(execution["schema"] == "stwo.riscv.segmented-execution-capture-receipt.v3"
             and execution["status"] == "complete"
             and execution["claim_boundary"] == "execution-only-not-a-proof",
             "Stwo Keccak-only segmented receipt status differs")
    _require((execution["segment_count"], execution["total_cycles"],
              execution["total_core_trace_rows"], execution["total_external_trace_rows"])
             == (389, 1_630_632_307, 1_630_599_472, 32_835),
             "Stwo Keccak-only execution geometry differs")
    _require(execution["total_cycles"]
             == execution["total_core_trace_rows"] + execution["total_external_trace_rows"],
             "Stwo Keccak-only row partition differs")
    _require(execution["clock_frame"] == "leaf_local"
             and execution["max_segment_cycle_count"] == 4_194_304
             and execution["leaf_local_clock_ranges_within_v3_limit"] is True
             and execution["segment_statement_v2_admissible"] is False,
             "Stwo Keccak-only segment boundary differs")
    for field in ("plan_sha256", "journal_sha256", "final_cpu_sha256",
                  "final_rw_memory_sha256", "output_sha256"):
        _require(SHA256.fullmatch(execution[field]) is not None,
                 f"Stwo Keccak-only {field} differs")
    _require(execution["journal_bytes"] == bundle["journal"]["bytes"]
             and execution["journal_sha256"] == bundle["journal"]["sha256"],
             "Stwo Keccak-only journal custody differs")
    timing = _exact(value["timing"], {
        "authority", "normative", "wall_seconds", "user_seconds", "system_seconds",
    }, "Stwo Keccak-only timing")
    _require(timing["authority"] == "operator-observed-not-v3-receipt-bound"
             and timing["normative"] is False,
             "Stwo Keccak-only timing authority differs")
    for field in ("wall_seconds", "user_seconds", "system_seconds"):
        amount = timing[field]
        _require(isinstance(amount, (int, float)) and not isinstance(amount, bool) and amount > 0,
                 f"Stwo Keccak-only {field} differs")
    _require(value["proof_generated"] is False
             and value["segment_proofs_verified"] is False
             and value["recursive_root_verified"] is False,
             "Stwo Keccak-only proof boundary differs")


def validate_keccak_execution(bundle_root: Path, controller: Path, runner: Path,
                              guest_elf: Path, diagnostic: dict[str, Any]) -> dict[str, Any]:
    """Replay the retained Keccak-only full-block execution diagnostic."""
    validate_keccak_diagnostic(diagnostic)
    _file_identity(controller, diagnostic["controller"], "retained Keccak controller")
    _file_identity(runner, diagnostic["runner"], "retained Keccak runner")
    _file_identity(guest_elf, diagnostic["guest_elf"], "retained Keccak guest ELF")
    names = {
        "plan": "plan.json",
        "journal": "execution.ndjson",
        "receipt": "receipt.json",
        "stderr": "invocation-000000.stderr",
    }
    for key, name in names.items():
        _file_identity(bundle_root / name, diagnostic["bundle"][key], f"Keccak {key}")
    plan = json.loads((bundle_root / "plan.json").read_text(encoding="utf-8"))
    receipt = json.loads((bundle_root / "receipt.json").read_text(encoding="utf-8"))
    plan_source = {key: plan["source"][key] for key in ("head", "tree", "status_sha256", "clean")}
    _require(plan_source == {key: diagnostic["source"][key] for key in plan_source},
             "Keccak source identity differs")
    for plan_key, declaration_key in (("controller", "controller"), ("tool", "runner"),
                                      ("elf", "guest_elf"), ("input", "input")):
        _require({key: plan[plan_key][key] for key in ("bytes", "sha256")}
                 == diagnostic[declaration_key], f"Keccak {plan_key} identity differs")
    _require(plan["execution_profile"] == diagnostic["profile"]
             and plan["segment_step_budget"] == 4_194_304
             and plan["strict_completion"] is True
             and plan["clock_frame"] == "leaf_local",
             "Keccak execution plan differs")
    _require(receipt == diagnostic["execution"], "Keccak receipt projection differs")
    replay = subprocess.run(
        [sys.executable, str(controller), "validate", str(bundle_root)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    _require(replay.returncode == 0 and replay.stderr == b"",
             "Keccak controller replay failed")
    _require(replay.stdout == (bundle_root / "receipt.json").read_bytes(),
             "Keccak replay bytes differ from the retained receipt")
    return {
        "schema": KECCAK_DIAGNOSTIC_SCHEMA,
        "status": "execution-replayed",
        "claim_boundary": "execution-only-not-a-proof",
        "journal_sha256": diagnostic["bundle"]["journal"]["sha256"],
        "output_sha256": diagnostic["execution"]["output_sha256"],
        "segment_count": diagnostic["execution"]["segment_count"],
        "total_cycles": diagnostic["execution"]["total_cycles"],
    }
