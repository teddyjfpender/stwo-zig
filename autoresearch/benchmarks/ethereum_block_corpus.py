"""Fail-closed custody for the small Ethereum block benchmark corpus."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


CORPUS_SCHEMA = "stwo.ethereum.block-benchmark-corpus.v1"
FIXTURE_SCHEMA = "stwo.ethereum.block-benchmark-fixture.v1"
SOURCE_SCHEMA = "stwo.ethereum.public-rpc-projection-source.v1"
INPUT_SCHEMA = "ethereum-mainnet-block-execution-input-projection.v1"
OUTPUT_SCHEMA = "ethereum-mainnet-block-execution-output-projection.v1"
PROJECTION_FRAMING = "canonical-json-sort-keys-no-lf"
DEFAULT_CORPUS = Path(__file__).with_name("ethereum_block_corpus_mainnet_v1.json")
CATEGORIES = (
    "representative-medium-block",
    "empty-or-light-transfer",
    "keccak-heavy",
    "ecrecover-heavy",
    "contract-or-storage-heavy",
)
HEX_32 = re.compile(r"^0x[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
INPUT_ENVIRONMENT_FIELDS = (
    "number", "parentHash", "sha3Uncles", "miner", "difficulty", "mixHash", "gasLimit",
    "timestamp", "extraData", "baseFeePerGas", "withdrawalsRoot", "parentBeaconBlockRoot",
    "blobGasUsed", "excessBlobGas", "requestsHash",
)


class CorpusError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CorpusError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _positive(value: Any, where: str) -> int:
    _require(type(value) is int and value > 0, f"{where} must be a positive integer")
    return value


def _nonnegative(value: Any, where: str) -> int:
    _require(type(value) is int and value >= 0, f"{where} must be a nonnegative integer")
    return value


def _identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"bytes", "sha256", "framing"}, where)
    _positive(value["bytes"], f"{where}.bytes")
    _require(type(value["sha256"]) is str and SHA256.fullmatch(value["sha256"]),
             f"{where}.sha256 differs")
    _require(type(value["framing"]) is str and value["framing"],
             f"{where}.framing differs")
    return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def corpus_sha256(value: dict[str, Any]) -> str:
    return _canonical_sha256({
        "selection_principles": value["selection_principles"],
        "source_provenance": value["source_provenance"],
        "fixtures": value["fixtures"],
    })


def projection_identity(value: Any) -> dict[str, Any]:
    """Return the exact identity used by the checked-in RPC projections."""
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return {
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "framing": PROJECTION_FRAMING,
    }


def rpc_projections(block: dict[str, Any], parent: dict[str, Any]) -> tuple[dict, dict]:
    """Normalize public-RPC block data into the corpus input/output authorities."""
    input_projection = {
        "schema": INPUT_SCHEMA,
        "chain_id": "0x1",
        "parent_state_root": parent["stateRoot"],
        "environment": {field: block.get(field) for field in INPUT_ENVIRONMENT_FIELDS},
        "transactions": block["transactions"],
        "withdrawals": block.get("withdrawals"),
    }
    output_projection = {
        "schema": OUTPUT_SCHEMA,
        "number": block["number"],
        "hash": block["hash"],
        "stateRoot": block["stateRoot"],
        "receiptsRoot": block["receiptsRoot"],
        "logsBloom": block["logsBloom"],
        "gasUsed": block["gasUsed"],
    }
    return input_projection, output_projection


def validate_rpc_fixture(
    fixture: dict[str, Any], block: dict[str, Any], parent: dict[str, Any],
    receipts: list[dict[str, Any]],
) -> None:
    """Replay one fixture identity from full-transaction public-RPC responses."""
    authority = fixture["block"]
    expected = {
        "number": int(block["number"], 16),
        "hash": block["hash"],
        "parent_hash": block["parentHash"],
        "parent_state_root": parent["stateRoot"],
        "state_root": block["stateRoot"],
        "transactions_root": block["transactionsRoot"],
        "receipts_root": block["receiptsRoot"],
        "withdrawals_root": block["withdrawalsRoot"],
        "requests_hash": block["requestsHash"],
        "transaction_count": len(block["transactions"]),
        "gas_used": int(block["gasUsed"], 16),
        "gas_limit": int(block["gasLimit"], 16),
        "timestamp": int(block["timestamp"], 16),
    }
    for field, value in expected.items():
        _require(authority[field] == value, f"RPC fixture block.{field} differs")
    _require(parent["hash"] == block["parentHash"], "RPC fixture parent hash differs")
    input_projection, output_projection = rpc_projections(block, parent)
    _require(fixture["semantic_io"]["input"] == projection_identity(input_projection),
             "RPC fixture input projection differs")
    _require(fixture["semantic_io"]["output"] == projection_identity(output_projection),
             "RPC fixture output projection differs")
    _require(len(receipts) == len(block["transactions"]),
             "RPC fixture receipt count differs")
    metrics = fixture["classification"]["metrics"]
    _require(metrics["receipt_log_count"] == sum(len(receipt["logs"]) for receipt in receipts),
             "RPC fixture receipt-log count differs")
    _require(metrics["contract_creation_count"]
             == sum(receipt.get("contractAddress") is not None for receipt in receipts),
             "RPC fixture contract-creation count differs")


def load(path: Path = DEFAULT_CORPUS) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    validate(value)
    return value


def validate(value: Any) -> None:
    value = _exact(value, {
        "schema", "selection_principles", "source_provenance", "fixtures",
        "corpus_sha256", "promotion_ready",
    }, "corpus")
    _require(value["schema"] == CORPUS_SCHEMA, "corpus schema differs")
    principles = _exact(value["selection_principles"], {
        "axes", "ordered_current_fixture_first", "unique_blocks",
        "dynamic_workload_claims_require_instrumented_counts",
        "semantic_io_does_not_imply_guest_transport_equivalence", "proofs_not_run",
    }, "corpus.selection_principles")
    _require(principles == {
        "axes": list(CATEGORIES),
        "ordered_current_fixture_first": True,
        "unique_blocks": True,
        "dynamic_workload_claims_require_instrumented_counts": True,
        "semantic_io_does_not_imply_guest_transport_equivalence": True,
        "proofs_not_run": True,
    }, "corpus selection principles differ")
    source = _exact(value["source_provenance"], {
        "schema", "network", "chain_id", "provider", "endpoint", "retrieved_on",
        "rpc_methods", "input_projection", "output_projection", "canonicalization",
        "payload_custody",
    }, "corpus.source_provenance")
    _require(source == {
        "schema": SOURCE_SCHEMA,
        "network": "ethereum-mainnet",
        "chain_id": 1,
        "provider": "PublicNode",
        "endpoint": "https://ethereum-rpc.publicnode.com",
        "retrieved_on": "2026-08-30",
        "rpc_methods": [
            "eth_getBlockByNumber(full_transactions=true)",
            "eth_getBlockByHash(parent,full_transactions=false)",
            "eth_getBlockReceipts",
        ],
        "input_projection": INPUT_SCHEMA,
        "output_projection": OUTPUT_SCHEMA,
        "canonicalization": PROJECTION_FRAMING,
        "payload_custody": "identity-only-refetch-and-rehash-required",
    }, "corpus source provenance differs")

    fixtures = value["fixtures"]
    _require(type(fixtures) is list and len(fixtures) == len(CATEGORIES),
             "corpus fixture count differs")
    _require([fixture.get("category") for fixture in fixtures] == list(CATEGORIES),
             "corpus category order differs")
    seen_ids: set[str] = set()
    seen_blocks: set[tuple[int, int]] = set()
    for index, fixture in enumerate(fixtures):
        _validate_fixture(fixture, index, seen_ids, seen_blocks)
    _require(fixtures[0]["block"]["chain_id"] == 1
             and fixtures[0]["block"]["number"] == 24_628_607,
             "current reference block is not the first fixture")
    _require(value["corpus_sha256"] == corpus_sha256(value),
             "corpus digest differs")
    _require(value["promotion_ready"] is False,
             "corpus cannot promote before dynamic counts and guest transports land")


def validate_reference_manifest(value: dict[str, Any], manifest: dict[str, Any]) -> None:
    """Bind the corpus's first fixture to the existing cross-system authority."""
    validate(value)
    fixture = value["fixtures"][0]
    block = manifest["block"]
    fields = (
        "chain_id", "number", "hash", "parent_hash", "state_root", "transactions_root",
        "receipts_root", "withdrawals_root", "requests_hash", "transaction_count",
        "gas_used", "gas_limit", "timestamp",
    )
    _require(fixture["block"] == {
        **{field: block[field] for field in fields},
        "chain": block["chain"],
        "parent_state_root": fixture["block"]["parent_state_root"],
    }, "corpus reference block differs from benchmark manifest")
    protocol = manifest["benchmark_protocol"]["statement"]
    guest = fixture["semantic_io"]["guest_transports"]
    _require(guest == {
        "zisk_input": protocol["inputs"]["zisk_transport"],
        "zisk_output": protocol["outputs"]["zisk_transport"],
        "stwo_input": protocol["inputs"]["stwo_transport"],
        "stwo_output": protocol["outputs"]["stwo_transport"],
    }, "corpus reference guest transports differ")


def _validate_fixture(
    fixture: Any, index: int, seen_ids: set[str], seen_blocks: set[tuple[int, int]],
) -> None:
    where = f"corpus.fixtures[{index}]"
    fixture = _exact(fixture, {
        "schema", "fixture_id", "category", "admission_status", "block", "semantic_io",
        "classification", "source", "proof_status",
    }, where)
    _require(fixture["schema"] == FIXTURE_SCHEMA, f"{where}.schema differs")
    fixture_id = fixture["fixture_id"]
    _require(type(fixture_id) is str and fixture_id and fixture_id not in seen_ids,
             f"{where}.fixture_id differs")
    seen_ids.add(fixture_id)
    _require(fixture["category"] == CATEGORIES[index], f"{where}.category differs")

    block = _exact(fixture["block"], {
        "chain", "chain_id", "number", "hash", "parent_hash", "parent_state_root",
        "state_root", "transactions_root", "receipts_root", "withdrawals_root",
        "requests_hash", "transaction_count", "gas_used", "gas_limit", "timestamp",
    }, f"{where}.block")
    _require(block["chain"] == "mainnet" and block["chain_id"] == 1,
             f"{where}.block chain differs")
    for field in ("number", "gas_limit", "timestamp"):
        _positive(block[field], f"{where}.block.{field}")
    for field in ("transaction_count", "gas_used"):
        _nonnegative(block[field], f"{where}.block.{field}")
    for field in (
        "hash", "parent_hash", "parent_state_root", "state_root", "transactions_root",
        "receipts_root", "withdrawals_root", "requests_hash",
    ):
        _require(type(block[field]) is str and HEX_32.fullmatch(block[field]),
                 f"{where}.block.{field} differs")
    block_key = (block["chain_id"], block["number"])
    _require(block_key not in seen_blocks, f"{where}.block is duplicated")
    seen_blocks.add(block_key)

    semantic_io = _exact(fixture["semantic_io"], {
        "input_projection_schema", "input", "output_projection_schema", "output",
        "guest_transports",
    }, f"{where}.semantic_io")
    _require(semantic_io["input_projection_schema"] == INPUT_SCHEMA,
             f"{where} input schema differs")
    _require(semantic_io["output_projection_schema"] == OUTPUT_SCHEMA,
             f"{where} output schema differs")
    _identity(semantic_io["input"], f"{where}.semantic_io.input")
    _identity(semantic_io["output"], f"{where}.semantic_io.output")
    guest = _exact(semantic_io["guest_transports"], {
        "zisk_input", "zisk_output", "stwo_input", "stwo_output",
    }, f"{where}.semantic_io.guest_transports")
    for name, identity in guest.items():
        if identity is not None:
            _identity(identity, f"{where}.semantic_io.guest_transports.{name}")
    admission = fixture["admission_status"]
    if admission == "guest-transports-pinned":
        _require(all(identity is not None for identity in guest.values()),
                 f"{where} guest transport custody is partial")
    else:
        _require(admission == "semantic-io-pinned-guest-transports-pending"
                 and all(identity is None for identity in guest.values()),
                 f"{where}.admission_status differs")

    classification = _exact(fixture["classification"], {
        "status", "selection_basis", "metrics",
    }, f"{where}.classification")
    _require(type(classification["selection_basis"]) is str
             and classification["selection_basis"],
             f"{where}.classification.selection_basis differs")
    metrics = _exact(classification["metrics"], {
        "transaction_count", "gas_used", "receipt_log_count", "contract_creation_count",
        "canonical_signer_recoveries", "dynamic_keccak_calls", "dynamic_storage_writes",
    }, f"{where}.classification.metrics")
    for field in ("transaction_count", "gas_used", "receipt_log_count",
                  "contract_creation_count", "canonical_signer_recoveries"):
        _nonnegative(metrics[field], f"{where}.classification.metrics.{field}")
    for field in ("dynamic_keccak_calls", "dynamic_storage_writes"):
        _require(metrics[field] is None
                 or (type(metrics[field]) is int and metrics[field] >= 0),
                 f"{where}.classification.metrics.{field} differs")
    _require(metrics["transaction_count"] == block["transaction_count"]
             and metrics["gas_used"] == block["gas_used"],
             f"{where} classification does not bind block geometry")
    _require(metrics["canonical_signer_recoveries"] == block["transaction_count"],
             f"{where} canonical signer-recovery count differs")
    _validate_category(fixture["category"], classification, where)

    source = _exact(fixture["source"], {
        "block_parameter", "block_hash_verified", "parent_state_root_verified",
        "receipts_retrieved",
    }, f"{where}.source")
    _require(source == {
        "block_parameter": hex(block["number"]),
        "block_hash_verified": True,
        "parent_state_root_verified": True,
        "receipts_retrieved": True,
    }, f"{where}.source differs")
    proof = _exact(fixture["proof_status"], {
        "execution_reproduced", "leaf_proofs_freshly_verified",
        "recursive_final_root_freshly_verified", "status",
    }, f"{where}.proof_status")
    _require(proof == {
        "execution_reproduced": False,
        "leaf_proofs_freshly_verified": False,
        "recursive_final_root_freshly_verified": False,
        "status": "not-run",
    }, f"{where}.proof_status is overstated")


def _validate_category(category: str, classification: dict[str, Any], where: str) -> None:
    metrics = classification["metrics"]
    if category == "empty-or-light-transfer":
        _require(classification["status"] == "selection-evidenced"
                 and metrics["transaction_count"] == 0 and metrics["gas_used"] == 0,
                 f"{where} empty-block classification differs")
    elif category == "ecrecover-heavy":
        _require(classification["status"] == "selection-evidenced"
                 and metrics["canonical_signer_recoveries"] >= 1000,
                 f"{where} ecrecover classification differs")
    elif category in ("keccak-heavy", "contract-or-storage-heavy"):
        _require(classification["status"] == "pinned-candidate-dynamic-count-pending",
                 f"{where} dynamic classification is overstated")
        field = ("dynamic_keccak_calls" if category == "keccak-heavy"
                 else "dynamic_storage_writes")
        _require(metrics[field] is None, f"{where} dynamic count lacks execution custody")
    else:
        _require(classification["status"] == "selection-evidenced",
                 f"{where} representative classification differs")
