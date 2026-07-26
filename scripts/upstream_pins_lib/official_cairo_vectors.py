"""Validate official Stwo-Cairo input, proof, and semantic-summary vectors."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path


def check(
    root: Path,
    *,
    cairo_repository: str,
    cairo_revision: str,
    stwo_repository: str,
    stwo_revision: str,
) -> list[str]:
    authority = {
        "repository": cairo_repository,
        "revision": cairo_revision,
        "stwo_repository": stwo_repository,
        "stwo_revision": stwo_revision,
    }
    errors = _check_record(
        root,
        "vectors/cairo/official/all_opcodes_blake2s.provenance.json",
        "stwo_cairo_official_oracle_vector_v1",
        authority,
        requires_proof=True,
    )
    errors.extend(
        _check_record(
            root,
            "vectors/cairo/official/all_builtins.provenance.json",
            "stwo_cairo_official_input_vector_v1",
            authority,
            requires_proof=False,
        )
    )
    errors.extend(_check_witness_bundle(root, authority))
    return errors


def _check_witness_bundle(
    root: Path,
    authority: dict[str, str],
) -> list[str]:
    relative_path = "vectors/cairo/official/witness_programs_v1.provenance.json"
    try:
        record = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid provenance: {error}"]
    if (
        not isinstance(record, dict)
        or record.get("schema") != "stwo_cairo_official_witness_program_bundle_v1"
    ):
        return [f"{relative_path}: invalid schema"]

    errors: list[str] = []
    source = record.get("source")
    artifact = record.get("artifact")
    compiler = record.get("compiler")
    parity = record.get("parity")
    if not all(isinstance(value, dict) for value in (source, artifact, compiler, parity)):
        return [f"{relative_path}: source, compiler, artifact, and parity are required"]
    for key, expected in authority.items():
        if key == "repository":
            actual = source.get("repository")
        elif key == "revision":
            actual = source.get("revision")
        else:
            actual = source.get(key)
        if actual != expected:
            errors.append(
                f"{relative_path}: source {key!r} is {actual!r}, expected {expected!r}"
            )
    if record.get("release_eligible") is not False:
        errors.append(f"{relative_path}: incomplete bundle must not be release eligible")
    blockers = record.get("release_blockers")
    if not isinstance(blockers, list) or len(blockers) < 3:
        errors.append(f"{relative_path}: explicit release blockers are required")
    if compiler.get("classification") != "repository_owned_source_compiler":
        errors.append(f"{relative_path}: compiler classification drifted")

    path = artifact.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return errors + [f"{relative_path}: witness bundle path is invalid"]
    try:
        encoded = (root / path).read_bytes()
    except OSError as error:
        return errors + [f"{relative_path}: unable to read witness bundle: {error}"]
    if artifact.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: witness bundle byte count drifted")
    if artifact.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: witness bundle digest drifted")
    if artifact.get("format") != "STWZWIT/1":
        errors.append(f"{relative_path}: witness bundle format drifted")

    parsed, parse_errors = _parse_witness_bundle(encoded, relative_path)
    errors.extend(parse_errors)
    if parsed is None:
        return errors
    labels, instruction_count = parsed
    if artifact.get("component_count") != len(labels):
        errors.append(f"{relative_path}: witness component count drifted")
    if artifact.get("instruction_count") != instruction_count:
        errors.append(f"{relative_path}: witness instruction count drifted")
    if artifact.get("components") != labels:
        errors.append(f"{relative_path}: witness component order drifted")
    errors.extend(
        _check_witness_compiler(
            root,
            relative_path,
            compiler,
            source,
            artifact,
            labels,
            instruction_count,
            encoded,
        )
    )

    expected_parity = {
        "all_opcodes": (
            "7f94bd5dcf32e7dd69a8a47f42d41830b4fdd3b75846ef9f7694f3164117fcd6",
            "e0cfb2e402dd53fa25d2d42fbc582b14abe8d81a49c98cbce8f9e8b6a89c42a7",
            42,
            21,
            21,
        ),
        "all_builtins": (
            "d7e902c3b8584a79b466ef0c384208ad95ea75340f0b0590ea0ba765c54acac1",
            "ef50c874b8160ed3d3a41cdbb2c03bed813e2bdf6195c7bbb18e1b8fd38bdd44",
            45,
            18,
            27,
        ),
    }
    for case, expected in expected_parity.items():
        value = parity.get(case)
        if not isinstance(value, dict):
            errors.append(f"{relative_path}: parity case {case!r} is missing")
            continue
        actual = (
            value.get("input_sha256"),
            value.get("checkpoint_sha256"),
            value.get("active_recordings"),
            value.get("executed_recordings"),
            value.get("deferred_input_edges"),
        )
        if actual != expected or value.get("column_mismatches") != 0:
            errors.append(f"{relative_path}: parity case {case!r} drifted")
    return errors


def _check_witness_compiler(
    root: Path,
    relative_path: str,
    compiler: dict[str, object],
    source: dict[str, object],
    artifact: dict[str, object],
    labels: list[str],
    instruction_count: int,
    encoded: bytes,
) -> list[str]:
    errors: list[str] = []
    receipt_metadata = compiler.get("receipt")
    if not isinstance(receipt_metadata, dict):
        return [f"{relative_path}: compiler receipt metadata is required"]
    receipt_path = receipt_metadata.get("path")
    if not isinstance(receipt_path, str) or Path(receipt_path).is_absolute():
        return [f"{relative_path}: compiler receipt path is invalid"]
    try:
        receipt_bytes = (root / receipt_path).read_bytes()
        receipt = json.loads(receipt_bytes)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid compiler receipt: {error}"]
    if not isinstance(receipt, dict):
        return [f"{relative_path}: compiler receipt must be an object"]
    if receipt_metadata.get("bytes") != len(receipt_bytes):
        errors.append(f"{relative_path}: compiler receipt byte count drifted")
    if receipt_metadata.get("sha256") != hashlib.sha256(receipt_bytes).hexdigest():
        errors.append(f"{relative_path}: compiler receipt digest drifted")
    if receipt.get("schema") != "stwo_zig_cairo_witness_compiler_receipt_v1":
        errors.append(f"{relative_path}: compiler receipt schema drifted")

    official_source = receipt.get("official_source")
    if not isinstance(official_source, dict):
        errors.append(f"{relative_path}: compiler receipt source is missing")
    elif (
        official_source.get("revision") != source.get("revision")
        or official_source.get("tree") != source.get("tree")
        or not isinstance(official_source.get("commit_timestamp"), int)
    ):
        errors.append(f"{relative_path}: compiler receipt source drifted")

    receipt_artifact = (
        receipt.get("artifact_bytes"),
        receipt.get("artifact_sha256"),
        receipt.get("program_count"),
        receipt.get("instruction_count"),
    )
    expected_artifact = (
        artifact.get("bytes"),
        artifact.get("sha256"),
        len(labels),
        instruction_count,
    )
    if receipt_artifact != expected_artifact:
        errors.append(f"{relative_path}: compiler receipt artifact identity drifted")
    emitted = receipt.get("emitted_components")
    if not isinstance(emitted, list) or sorted(emitted) != sorted(labels):
        errors.append(f"{relative_path}: compiler receipt component set drifted")

    if (
        compiler.get("repository") != "https://github.com/teddyjfpender/stwo-zig"
        or compiler.get("path") != "tools/cairo-witness-compiler"
    ):
        errors.append(f"{relative_path}: compiler repository identity drifted")
    compiler_root = root / "tools/cairo-witness-compiler"
    try:
        closure_contract = {
            "orchestrator_sha256": _files_sha256(
                compiler_root,
                (
                    compiler_root / "generate.py",
                    compiler_root / "orchestrator.py",
                ),
            ),
            "rewriter_closure_sha256": _closure_sha256(compiler_root / "rewriter"),
            "support_closure_sha256": _closure_sha256(compiler_root / "support"),
        }
    except OSError as error:
        return errors + [f"{relative_path}: unable to hash witness compiler: {error}"]
    for key, expected in closure_contract.items():
        if receipt.get(key) != expected or compiler.get(key) != expected:
            errors.append(f"{relative_path}: compiler {key} drifted")

    migration = compiler.get("migration_equivalence")
    if not isinstance(migration, dict):
        errors.append(f"{relative_path}: migration equivalence is not explicit")
    else:
        added = migration.get("added_components")
        preserved_count = migration.get("preserved_component_count")
        if (
            migration.get("baseline_artifact_byte_identical") is not False
            or migration.get("preserved_programs_byte_identical") is not True
            or not isinstance(preserved_count, int)
            or preserved_count <= 0
            or migration.get("preserved_entry_stream_sha256")
            != _witness_entry_stream_sha256(encoded, set(added or []))
            or not isinstance(added, list)
            or any(not isinstance(label, str) for label in added)
            or preserved_count + len(added) != len(labels)
            or sorted(added)
            != sorted(
                [
                    "add_mod_builtin",
                    "blake_compress_opcode",
                    "blake_round_sigma",
                    "bitwise_builtin",
                    "ec_op_builtin",
                    "generic_opcode",
                    "mul_mod_builtin",
                    "partial_ec_mul_window_bits_9",
                    "pedersen_aggregator_window_bits_9",
                    "pedersen_builtin",
                    "pedersen_builtin_narrow_windows",
                    "pedersen_points_table_window_bits_18",
                    "pedersen_points_table_window_bits_9",
                    "poseidon_3_partial_rounds_chain",
                    "poseidon_aggregator",
                    "poseidon_builtin",
                    "poseidon_full_round_chain",
                    "poseidon_round_keys",
                    "range_check96_builtin",
                    "range_check_11",
                    "range_check_12",
                    "range_check_18",
                    "range_check_20",
                    "range_check_3_3_3_3_3",
                    "range_check_3_6_6_3",
                    "range_check_4_3",
                    "range_check_4_4",
                    "range_check_4_4_4_4",
                    "range_check_6",
                    "range_check_7_2_5",
                    "range_check_8",
                    "range_check_9_9",
                    "range_check_builtin",
                    "verify_bitwise_xor_4",
                    "verify_bitwise_xor_7",
                    "verify_bitwise_xor_8",
                    "verify_bitwise_xor_9",
                ]
            )
            or not set(added).issubset(labels)
        ):
            errors.append(f"{relative_path}: migration extension evidence drifted")
    return errors


def _witness_entry_stream_sha256(
    encoded: bytes,
    excluded_labels: set[str],
) -> str:
    """Hash canonical serialized entries while excluding an explicit extension."""
    digest = hashlib.sha256()
    offset = 16
    count = struct.unpack_from("<I", encoded, 12)[0]
    for _ in range(count):
        start = offset
        label_len = struct.unpack_from("<H", encoded, offset)[0]
        counts = struct.unpack_from("<7I", encoded, offset + 4)
        label_start = offset + 40
        label = encoded[label_start : label_start + label_len].decode("ascii")
        offset = label_start + label_len + counts[-1] * 16
        if label not in excluded_labels:
            digest.update(encoded[start:offset])
    return digest.hexdigest()


def _closure_sha256(root: Path) -> str:
    files = sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not {"target", "__pycache__", ".git"}.intersection(
            path.relative_to(root).parts
        )
        and path.suffix != ".pyc"
    )
    return _files_sha256(root, files)


def _files_sha256(root: Path, paths: tuple[Path, ...] | list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "little"))
        digest.update(data)
    return digest.hexdigest()


def _parse_witness_bundle(
    encoded: bytes,
    relative_path: str,
) -> tuple[tuple[list[str], int] | None, list[str]]:
    errors: list[str] = []
    if len(encoded) < 16 or encoded[:8] != b"STWZWIT\0":
        return None, [f"{relative_path}: invalid witness bundle magic"]
    version, count = struct.unpack_from("<II", encoded, 8)
    if version != 1 or count == 0 or count > 256:
        return None, [f"{relative_path}: invalid witness bundle header"]

    labels: list[str] = []
    instruction_count = 0
    offset = 16
    try:
        for _ in range(count):
            label_len, reserved = struct.unpack_from("<HH", encoded, offset)
            offset += 4
            counts = struct.unpack_from("<7I", encoded, offset)
            offset += 28
            semantic_hash = struct.unpack_from("<Q", encoded, offset)[0]
            offset += 8
            if reserved != 0 or label_len == 0 or label_len > 256:
                raise ValueError("invalid entry header")
            n_regs, _n_inputs, n_cols, _n_mult, _n_lookup, _n_sub, n_insts = counts
            if n_regs == 0 or n_cols == 0 or n_insts == 0 or n_insts > 1_000_000:
                raise ValueError("invalid entry geometry")
            label = encoded[offset : offset + label_len].decode("ascii")
            offset += label_len
            instruction_bytes = encoded[offset : offset + n_insts * 16]
            if len(instruction_bytes) != n_insts * 16:
                raise ValueError("truncated instruction stream")
            offset += len(instruction_bytes)
            if label in labels:
                raise ValueError("duplicate component label")
            if any(instruction_bytes[index + 1] != 0 for index in range(0, len(instruction_bytes), 16)):
                raise ValueError("nonzero instruction padding")
            if any(instruction_bytes[index] > 27 for index in range(0, len(instruction_bytes), 16)):
                raise ValueError("unknown witness opcode")
            if _witness_semantic_hash(instruction_bytes, counts[:6]) != semantic_hash:
                raise ValueError(f"semantic hash mismatch for {label}")
            labels.append(label)
            instruction_count += n_insts
    except (UnicodeDecodeError, ValueError, struct.error) as error:
        errors.append(f"{relative_path}: invalid witness bundle: {error}")
        return None, errors
    if offset != len(encoded):
        errors.append(f"{relative_path}: witness bundle has trailing data")
        return None, errors
    return (labels, instruction_count), errors


def _witness_semantic_hash(instructions: bytes, counts: tuple[int, ...]) -> int:
    value = 0xCBF29CE484222325
    for byte in instructions + b"".join(count.to_bytes(4, "little") for count in counts):
        value ^= byte
        value = (value * 0x100000001B3) & ((1 << 64) - 1)
    return value


def _check_record(
    root: Path,
    relative_path: str,
    schema: str,
    authority: dict[str, str],
    *,
    requires_proof: bool,
) -> list[str]:
    try:
        record = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid provenance: {error}"]
    if not isinstance(record, dict) or record.get("schema") != schema:
        return [f"{relative_path}: invalid schema"]

    source = record.get("source")
    prover_input = record.get("prover_input")
    if not isinstance(source, dict) or not isinstance(prover_input, dict):
        return [f"{relative_path}: source and prover_input objects are required"]
    errors = [
        f"{relative_path}: source {key!r} is {source.get(key)!r}, expected {expected!r}"
        for key, expected in authority.items()
        if source.get(key) != expected
    ]
    if requires_proof:
        proof = record.get("proof")
        claim_summary = record.get("claim_summary")
        if not isinstance(proof, dict):
            errors.append(f"{relative_path}: proof object is required")
        else:
            errors.extend(_check_proof(root, relative_path, proof))
        if not isinstance(claim_summary, dict):
            errors.append(f"{relative_path}: claim_summary object is required")
        else:
            errors.extend(_check_claim_summary(root, relative_path, claim_summary))
    checkpoint = record.get("base_trace_checkpoint")
    if not isinstance(checkpoint, dict):
        errors.append(f"{relative_path}: base_trace_checkpoint object is required")
    else:
        errors.extend(
            _check_base_trace_checkpoint(
                root,
                relative_path,
                checkpoint,
                authority,
                source.get("prover_input_sha256"),
            )
        )
    errors.extend(_check_input(root, relative_path, source, prover_input))
    return errors


def _check_proof(
    root: Path,
    relative_path: str,
    proof: dict[str, object],
) -> list[str]:
    path = proof.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: proof path is invalid"]
    try:
        vector = (root / path).read_bytes()
    except OSError as error:
        return [f"{relative_path}: unable to read proof vector: {error}"]
    errors: list[str] = []
    if proof.get("bytes") != len(vector):
        errors.append(f"{relative_path}: proof byte count drifted")
    if proof.get("sha256") != hashlib.sha256(vector).hexdigest():
        errors.append(f"{relative_path}: proof digest drifted")
    if proof.get("channel") != "blake2s" or proof.get("format") != "binary":
        errors.append(f"{relative_path}: proof transport identity drifted")
    return errors


def _check_claim_summary(
    root: Path,
    relative_path: str,
    summary: dict[str, object],
) -> list[str]:
    path = summary.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: claim summary path is invalid"]
    try:
        encoded = (root / path).read_bytes()
        document = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid claim summary: {error}"]

    errors: list[str] = []
    schema = "stwo_cairo_official_claim_summary_v1"
    if summary.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: claim summary byte count drifted")
    if summary.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: claim summary digest drifted")
    if (
        summary.get("schema") != schema
        or not isinstance(document, dict)
        or document.get("schema") != schema
    ):
        return errors + [f"{relative_path}: claim summary schema drifted"]

    flat = document.get("flat_claim")
    interaction = document.get("interaction")
    if not isinstance(flat, dict) or not isinstance(interaction, dict):
        return errors + [f"{relative_path}: claim summary sections are required"]
    enable_bits = flat.get("component_enable_bits")
    log_sizes = flat.get("component_log_sizes")
    claimed_sums = interaction.get("claimed_sums_m31")
    if not isinstance(enable_bits, list) or len(enable_bits) != 83:
        errors.append(f"{relative_path}: claim enable-slot cardinality drifted")
    active = (
        sum(value is True for value in enable_bits)
        if isinstance(enable_bits, list)
        else -1
    )
    if not isinstance(log_sizes, list) or len(log_sizes) != active:
        errors.append(f"{relative_path}: active claim log cardinality drifted")
    if not isinstance(claimed_sums, list) or len(claimed_sums) != active:
        errors.append(f"{relative_path}: interaction claim cardinality drifted")
    if document.get("preprocessed_trace_variant") not in {
        "canonical",
        "canonical_without_pedersen",
        "canonical_small",
    }:
        errors.append(f"{relative_path}: preprocessed trace variant drifted")
    return errors


def _check_base_trace_checkpoint(
    root: Path,
    relative_path: str,
    checkpoint: dict[str, object],
    authority: dict[str, str],
    input_digest: object,
) -> list[str]:
    path = checkpoint.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: base checkpoint path is invalid"]
    try:
        encoded = (root / path).read_bytes()
        document = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid base checkpoint: {error}"]

    errors: list[str] = []
    schema = "stwo-cairo-base-trace-checkpoint-v1"
    if checkpoint.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: base checkpoint byte count drifted")
    if checkpoint.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: base checkpoint digest drifted")
    if (
        checkpoint.get("schema") != schema
        or not isinstance(document, dict)
        or document.get("schema") != schema
    ):
        return errors + [f"{relative_path}: base checkpoint schema drifted"]
    if document.get("input_sha256") != input_digest:
        errors.append(f"{relative_path}: base checkpoint input authority drifted")

    expected_authority = {
        "stwo_cairo_revision": authority["revision"],
        "stwo_revision": authority["stwo_revision"],
    }
    if document.get("authority") != expected_authority:
        errors.append(f"{relative_path}: base checkpoint source authority drifted")

    components = document.get("components")
    if not isinstance(components, list) or not components:
        return errors + [f"{relative_path}: base checkpoint has no components"]
    if checkpoint.get("component_count") != len(components):
        errors.append(f"{relative_path}: base checkpoint component count drifted")

    column_count = 0
    for component_ordinal, component in enumerate(components):
        if not isinstance(component, dict):
            errors.append(f"{relative_path}: invalid base checkpoint component")
            continue
        if component.get("ordinal") != component_ordinal:
            errors.append(f"{relative_path}: base component ordinal drifted")
        columns = component.get("columns")
        if not isinstance(columns, list) or not columns:
            errors.append(f"{relative_path}: base component has no columns")
            continue
        column_count += len(columns)
        for column_ordinal, column in enumerate(columns):
            if not isinstance(column, dict) or column.get("ordinal") != column_ordinal:
                errors.append(f"{relative_path}: base column ordinal drifted")
                continue
            rows = column.get("row_count")
            if not isinstance(rows, int) or rows <= 0 or rows & (rows - 1):
                errors.append(f"{relative_path}: base column domain is not a power of two")
        if not isinstance(component.get("accumulator_sha256"), str):
            errors.append(f"{relative_path}: base component accumulator is missing")

    if checkpoint.get("column_count") != column_count:
        errors.append(f"{relative_path}: base checkpoint column count drifted")
    final_accumulator = document.get("final_accumulator_sha256")
    if (
        checkpoint.get("final_accumulator_sha256") != final_accumulator
        or components[-1].get("accumulator_sha256") != final_accumulator
    ):
        errors.append(f"{relative_path}: base checkpoint final accumulator drifted")
    return errors


def _check_input(
    root: Path,
    relative_path: str,
    source: dict[str, object],
    prover_input: dict[str, object],
) -> list[str]:
    path = prover_input.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: prover input path is invalid"]
    try:
        encoded = (root / path).read_bytes()
    except OSError as error:
        return [f"{relative_path}: unable to read prover input: {error}"]

    errors: list[str] = []
    digest = hashlib.sha256(encoded).hexdigest()
    if prover_input.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: prover input byte count drifted")
    if prover_input.get("sha256") != digest:
        errors.append(f"{relative_path}: prover input digest drifted")
    if source.get("prover_input_sha256") != digest:
        errors.append(f"{relative_path}: source prover input digest drifted")
    if prover_input.get("format") != "official_json":
        errors.append(f"{relative_path}: prover input transport identity drifted")
    summary = prover_input.get("summary")
    if not isinstance(summary, dict):
        return errors + [f"{relative_path}: prover input summary is required"]
    errors.extend(_check_summary(root, relative_path, summary, digest))
    return errors


def _check_summary(
    root: Path,
    relative_path: str,
    summary: dict[str, object],
    input_digest: str,
) -> list[str]:
    path = summary.get("path")
    if not isinstance(path, str) or Path(path).is_absolute():
        return [f"{relative_path}: prover input summary path is invalid"]
    try:
        encoded = (root / path).read_bytes()
        document = json.loads(encoded)
    except (OSError, json.JSONDecodeError) as error:
        return [f"{relative_path}: invalid prover input summary: {error}"]

    errors: list[str] = []
    if summary.get("bytes") != len(encoded):
        errors.append(f"{relative_path}: prover input summary byte count drifted")
    if summary.get("sha256") != hashlib.sha256(encoded).hexdigest():
        errors.append(f"{relative_path}: prover input summary digest drifted")
    schema = "stwo_cairo_official_input_summary_v2"
    if (
        summary.get("schema") != schema
        or not isinstance(document, dict)
        or document.get("schema") != schema
    ):
        errors.append(f"{relative_path}: prover input summary schema drifted")
    if document.get("input_sha256") != input_digest:
        errors.append(f"{relative_path}: prover input summary authority drifted")
    return errors
