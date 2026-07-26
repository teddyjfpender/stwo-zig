"""Strict public-value wires for the RISC-V CP-11 oracle boundary."""

from __future__ import annotations

import json


PINNED_ORACLE = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
ORACLE_REPOSITORY = "https://github.com/riscv/sail-riscv"
IMPLEMENTATION_REPOSITORY = "https://github.com/teddyjfpender/stwo-zig"

PUBLIC_VALUES_SCHEMA = "riscv-public-values-diagnostic-v1"
PUBLIC_VALUES_DERIVATION = (
    "execution_and_committed_tree_builders_without_proof_admission"
)
PUBLIC_DATA_FIELDS = (
    "initial_pc",
    "final_pc",
    "clock",
    "initial_regs",
    "final_regs",
    "reg_last_clock",
    "program_root",
    "initial_rw_root",
    "final_rw_root",
    "completion",
    "io_entries",
)
COMPLETION_FIELDS = ("kind", "address", "value", "clock")
PUBLIC_IO_FIELDS = (
    "input_start",
    "input_len",
    "input_words",
    "output_len",
    "output_len_addr",
    "output_data_addr",
    "output_words",
)
ARTIFACT_PUBLIC_FIELDS = PUBLIC_DATA_FIELDS[:-1] + PUBLIC_IO_FIELDS
ARTIFACT_FIELDS = (
    "artifact_kind",
    "schema_version",
    "exchange_mode",
    "release_status",
    "generator",
    "air",
    "backend",
    "protocol",
    "source",
    "provenance",
    "pcs_config",
    "statement",
    "interaction_claim",
    "proof_bytes_hex",
)
ARTIFACT_STATEMENT_FIELDS = (
    "segment_ordinal",
    "segment_count",
    "initial_pc",
    "final_pc",
    "total_steps",
    "components",
    "infrastructure",
    "public_data",
)
ARTIFACT_PROVENANCE_FIELDS = (
    "oracle_repository",
    "oracle_commit",
    "implementation_repository",
    "implementation_commit",
    "implementation_dirty",
    "witness_layout_sha256",
)


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def exact_fields(value: object, expected: tuple[str, ...], label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise ValueError(
            f"{label} fields differ: missing={sorted(wanted - actual)} "
            f"unknown={sorted(actual - wanted)}"
        )
    return value


def require_u32(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be a u32")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest") from error
    if raw.hex() != value:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def validate_public_data_shape(value: object, label: str) -> dict:
    public = exact_fields(value, PUBLIC_DATA_FIELDS, label)
    for field in ("initial_pc", "final_pc", "clock"):
        require_u32(public[field], f"{label}.{field}")
    for field in ("initial_regs", "final_regs", "reg_last_clock"):
        words = public[field]
        if not isinstance(words, list) or len(words) != 32:
            raise ValueError(f"{label}.{field} must contain exactly 32 words")
        for index, word in enumerate(words):
            require_u32(word, f"{label}.{field}[{index}]")
    for field in ("program_root", "initial_rw_root", "final_rw_root"):
        if public[field] is not None:
            require_u32(public[field], f"{label}.{field}")
    completion = exact_fields(
        public["completion"], COMPLETION_FIELDS, f"{label}.completion"
    )
    if completion["kind"] not in ("halt_flag", "unretired_self_loop"):
        raise ValueError(f"{label}.completion.kind is unsupported")
    for field in ("address", "value", "clock"):
        require_u32(completion[field], f"{label}.completion.{field}")

    io = exact_fields(public["io_entries"], PUBLIC_IO_FIELDS, f"{label}.io_entries")
    for field in (
        "input_start",
        "input_len",
        "output_len",
        "output_len_addr",
        "output_data_addr",
    ):
        require_u32(io[field], f"{label}.io_entries.{field}")
    for field in ("input_words", "output_words"):
        if not isinstance(io[field], list):
            raise ValueError(f"{label}.io_entries.{field} must be an array")
    for index, word in enumerate(io["input_words"]):
        require_u32(word, f"{label}.io_entries.input_words[{index}]")
    for index, raw_word in enumerate(io["output_words"]):
        word = exact_fields(
            raw_word,
            ("addr", "value", "clock"),
            f"{label}.io_entries.output_words[{index}]",
        )
        for field in ("addr", "value", "clock"):
            require_u32(word[field], f"{label}.io_entries.output_words[{index}].{field}")
    return public


def _validate_binding(
    source: object,
    provenance: object,
    *,
    candidate: str,
    candidate_dirty: bool,
    witness_layout_sha256: str,
    elf_sha256: str,
    input_sha256: str,
    artifact: bool,
) -> None:
    source = exact_fields(source, ("elf_sha256", "input_sha256"), "source")
    expected_source = {"elf_sha256": elf_sha256, "input_sha256": input_sha256}
    for field, expected in expected_source.items():
        require_sha256(source[field], f"source.{field}")
        if source[field] != expected:
            raise ValueError(f"source.{field} differs")

    fields = ARTIFACT_PROVENANCE_FIELDS if artifact else (
        "implementation_commit",
        "implementation_dirty",
        "oracle_commit",
        "witness_layout_sha256",
    )
    provenance = exact_fields(provenance, fields, "provenance")
    expected_provenance = {
        "implementation_commit": candidate,
        "implementation_dirty": candidate_dirty,
        "oracle_commit": PINNED_ORACLE,
        "witness_layout_sha256": witness_layout_sha256,
    }
    if artifact:
        expected_provenance.update({
            "oracle_repository": ORACLE_REPOSITORY,
            "implementation_repository": IMPLEMENTATION_REPOSITORY,
        })
    for field, expected in expected_provenance.items():
        if provenance[field] != expected or type(provenance[field]) is not type(expected):
            raise ValueError(f"provenance.{field} differs")
    require_sha256(provenance["witness_layout_sha256"], "provenance.witness_layout_sha256")


def parse_public_values_diagnostic(
    raw: str,
    *,
    candidate: str,
    candidate_dirty: bool = False,
    witness_layout_sha256: str,
    elf_sha256: str,
    input_sha256: str,
) -> dict:
    """Parse the proof-independent diagnostic as a candidate-bound wire."""
    payload = json.loads(raw, object_pairs_hook=strict_object)
    root = exact_fields(
        payload,
        ("schema", "derivation", "provenance", "source", "public_data"),
        "public-values diagnostic",
    )
    if root["schema"] != PUBLIC_VALUES_SCHEMA:
        raise ValueError("public-values diagnostic schema differs")
    if root["derivation"] != PUBLIC_VALUES_DERIVATION:
        raise ValueError("public-values diagnostic derivation differs")
    _validate_binding(
        root["source"],
        root["provenance"],
        candidate=candidate,
        candidate_dirty=candidate_dirty,
        witness_layout_sha256=witness_layout_sha256,
        elf_sha256=elf_sha256,
        input_sha256=input_sha256,
        artifact=False,
    )
    public = validate_public_data_shape(root["public_data"], "Zig public_data")
    io = public["io_entries"]
    if not io["input_words"] and not io["output_words"]:
        raise ValueError("public-values diagnostic carries no public I/O words")
    return public


def parse_proof_artifact_public_data(
    raw: str,
    *,
    candidate: str,
    candidate_dirty: bool = False,
    release_status: str,
    witness_layout_sha256: str,
    elf_sha256: str,
    input_sha256: str,
) -> dict:
    """Return the public statement bound by a strict production proof artifact."""
    payload = json.loads(raw, object_pairs_hook=strict_object)
    artifact = exact_fields(payload, ARTIFACT_FIELDS, "proof artifact")
    expected_identity = {
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "release_status": release_status,
        "generator": "zig",
        "air": "sail_rv32im_zkvm_v1",
        "backend": "cpu",
        "protocol": "functional",
    }
    for field, expected in expected_identity.items():
        if artifact[field] != expected or type(artifact[field]) is not type(expected):
            raise ValueError(f"proof artifact {field} differs")
    _validate_binding(
        artifact["source"],
        artifact["provenance"],
        candidate=candidate,
        candidate_dirty=candidate_dirty,
        witness_layout_sha256=witness_layout_sha256,
        elf_sha256=elf_sha256,
        input_sha256=input_sha256,
        artifact=True,
    )
    statement = exact_fields(
        artifact["statement"],
        ARTIFACT_STATEMENT_FIELDS,
        "proof artifact statement",
    )
    flat = exact_fields(
        statement["public_data"],
        ARTIFACT_PUBLIC_FIELDS,
        "proof artifact public_data",
    )
    public = {field: flat[field] for field in PUBLIC_DATA_FIELDS[:-1]}
    public["io_entries"] = {field: flat[field] for field in PUBLIC_IO_FIELDS}
    validate_public_data_shape(public, "proof artifact public_data")
    if (
        statement["initial_pc"] != public["initial_pc"]
        or statement["final_pc"] != public["final_pc"]
        or statement["total_steps"] != public["clock"]
    ):
        raise ValueError("proof artifact statement/public_data fields differ")
    proof_hex = artifact["proof_bytes_hex"]
    if (
        not isinstance(proof_hex, str)
        or not proof_hex
        or len(proof_hex) % 2
        or any(byte not in "0123456789abcdef" for byte in proof_hex)
    ):
        raise ValueError("proof artifact has no canonical proof bytes")
    return public
