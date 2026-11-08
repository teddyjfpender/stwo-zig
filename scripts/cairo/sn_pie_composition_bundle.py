#!/usr/bin/env python3
"""Retarget a validated Cairo composition bundle to another proof's trace logs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
from typing import NamedTuple


BUNDLE_MAGIC = b"STWZEVA\0"
BUNDLE_VERSION = 1
PROJECTED_BUNDLE_VERSION = 2
PROJECTION_MANIFEST_FORMAT = "stwo-zig-cairo-composition-projection"
PROJECTION_MANIFEST_VERSION = 2
PROGRAM_MAGIC = 0x31505453
PROGRAM_HEADER_BYTES = 96
PROGRAM_SECTION_BYTES = 24
PROGRAM_DOMAIN_LOG_OFFSET = 60
PROGRAM_SEMANTIC_HASH_OFFSET = 16
PROGRAM_BASE_INSTRUCTIONS = 3
PROGRAM_BASE_CONSTANT_OPCODE = 3
M31_PRIME = 0x7FFFFFFF
MEMORY_ADDRESS_TO_ID = "memory_address_to_id"
MEMORY_ADDRESS_TO_ID_SPLIT = 16


class ComponentRecord(NamedTuple):
    label: str
    start: int
    end: int
    trace_log: int
    n_constraints: int
    span_offset: int
    spans: tuple[tuple[int, int, int], ...]
    preprocessed_offset: int
    preprocessed_count: int
    program_ranges: tuple[tuple[int, int], ...]


def u16(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def active_components_and_trace_logs(
    proof_path: Path,
) -> tuple[list[str], dict[str, int]]:
    claim = json.loads(proof_path.read_text())["claim"]
    active: list[str] = []
    result: dict[str, int] = {}
    for label, value in claim.items():
        if label == "public_data" or value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(f"{label} has unsupported claim shape")
        active.append(label)
        if "log_size" in value:
            result[label] = int(value["log_size"])
        elif label == "memory_id_to_big":
            logs = value.get("big_log_sizes", [])
            if len(logs) != 1:
                raise ValueError(f"{label} has unsupported instances: {logs}")
            result[label] = int(logs[0])
        elif value:
            raise ValueError(f"{label} has unsupported fixed claim shape")
    return active, result


def trace_logs(proof_path: Path) -> dict[str, int]:
    return active_components_and_trace_logs(proof_path)[1]


def proof_tree_columns(proof: dict[str, object]) -> tuple[int, int, int, int]:
    stark_proof = proof.get("stark_proof")
    if stark_proof is None:
        extended = proof.get("extended_stark_proof")
        if not isinstance(extended, dict):
            raise ValueError("proof has no canonical STARK proof payload")
        stark_proof = extended.get("proof")
    if not isinstance(stark_proof, dict):
        raise ValueError("proof has no canonical STARK proof payload")
    queried = stark_proof.get("queried_values")
    sampled = stark_proof.get("sampled_values")
    if not isinstance(queried, list) or not isinstance(sampled, list):
        raise ValueError("proof has no canonical sampled/queried tree geometry")
    if len(queried) != 4 or len(sampled) != 4:
        raise ValueError("proof does not have four commitment trees")
    queried_counts = tuple(len(tree) for tree in queried)
    sampled_counts = tuple(len(tree) for tree in sampled)
    if queried_counts != sampled_counts:
        raise ValueError("sampled and queried tree geometry disagree")
    return queried_counts


def validate_interaction_claim(proof: dict[str, object], active: list[str]) -> None:
    interaction_claim = proof.get("interaction_claim")
    if not isinstance(interaction_claim, dict):
        raise ValueError("projection requires the canonical interaction claim")
    interaction_active = [label for label, value in interaction_claim.items() if value is not None]
    if interaction_active != active:
        raise ValueError("claim and interaction claim component order disagree")


def proof_variant(proof: dict[str, object]) -> str:
    variant = proof.get("preprocessed_trace_variant")
    if not isinstance(variant, str):
        raise ValueError("projection requires a preprocessed trace variant")
    return variant


def public_segment_starts(proof_path: Path) -> dict[str, int]:
    claim = json.loads(proof_path.read_text())["claim"]
    segments = claim.get("public_data", {}).get("public_memory", {}).get("public_segments", {})
    return {
        label: int(segment["start_ptr"]["value"])
        for label, segment in segments.items()
        if int(segment["start_ptr"]["value"]) != 0
    }


def statement_constant_substitutions(template_proof: Path, target_proof: Path) -> dict[int, int]:
    template = public_segment_starts(template_proof)
    target = public_segment_starts(target_proof)
    substitutions: dict[int, int] = {}
    for label in template.keys() & target.keys():
        old, new = template[label], target[label]
        if old == new:
            continue
        previous = substitutions.setdefault(old, new)
        if previous != new:
            raise ValueError(f"ambiguous statement constant {old}: {previous} or {new}")
    return substitutions


def fnv64(chunks: list[bytes]) -> int:
    result = 0xCBF29CE484222325
    for chunk in chunks:
        for byte in chunk:
            result ^= byte
            result = (result * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return result


def retarget_program_constants(
    data: bytearray,
    program_offset: int,
    program_len: int,
    substitutions: dict[int, int],
) -> tuple[int, int, list[tuple[int, int]]]:
    if not substitutions:
        semantic_hash = struct.unpack_from("<Q", data, program_offset + PROGRAM_SEMANTIC_HASH_OFFSET)[0]
        return semantic_hash, semantic_hash, []
    n_sections = u32(data, program_offset + 8)
    payload_start = program_offset + PROGRAM_HEADER_BYTES + n_sections * PROGRAM_SECTION_BYTES
    program_end = program_offset + program_len
    sections: dict[int, tuple[int, int, int]] = {}
    for index in range(n_sections):
        descriptor = program_offset + PROGRAM_HEADER_BYTES + index * PROGRAM_SECTION_BYTES
        kind, elem_size, relative_offset, count = struct.unpack_from("<IIQQ", data, descriptor)
        start = payload_start + relative_offset
        end = start + elem_size * count
        if end > program_end:
            raise ValueError("program section exceeds its encoded extent")
        sections[kind] = (start, elem_size, count)

    base = sections.get(PROGRAM_BASE_INSTRUCTIONS)
    if base is None or base[1] != 16:
        raise ValueError("evaluation program has no canonical base instruction section")
    replacements: list[tuple[int, int]] = []
    start, _, count = base
    for index in range(count):
        instruction = start + index * 16
        if data[instruction] != PROGRAM_BASE_CONSTANT_OPCODE:
            continue
        old = u32(data, instruction + 4)
        new = substitutions.get(old)
        if new is None:
            continue
        struct.pack_into("<I", data, instruction + 4, new)
        replacements.append((old, new))

    old_hash = struct.unpack_from("<Q", data, program_offset + PROGRAM_SEMANTIC_HASH_OFFSET)[0]
    if not replacements:
        return old_hash, old_hash, []
    canonical_sections: list[bytes] = []
    for kind in range(1, 6):
        section = sections.get(kind)
        if section is None:
            raise ValueError("evaluation program is missing a semantic section")
        section_start, elem_size, section_count = section
        canonical_sections.append(bytes(data[section_start : section_start + elem_size * section_count]))
    new_hash = fnv64(canonical_sections)
    struct.pack_into("<Q", data, program_offset + PROGRAM_SEMANTIC_HASH_OFFSET, new_hash)
    return old_hash, new_hash, replacements


def memory_address_stride_substitutions(
    label: str, source_log: int, target_log: int
) -> dict[int, int]:
    if label != MEMORY_ADDRESS_TO_ID or source_log == target_log:
        return {}
    source_stride = 1 << source_log
    target_stride = 1 << target_log
    maximum_address_offset = (MEMORY_ADDRESS_TO_ID_SPLIT - 1) * target_stride
    if maximum_address_offset >= M31_PRIME:
        raise ValueError(f"unsupported {label} target log {target_log}")
    return {
        chunk * source_stride: chunk * target_stride
        for chunk in range(1, MEMORY_ADDRESS_TO_ID_SPLIT)
    }


def preprocessed_identities(path: Path) -> list[str]:
    with path.open("rb") as stream:
        if stream.read(8) != b"STWZPPC\0":
            raise ValueError("unsupported preprocessed coefficient fixture")
        version, count = struct.unpack("<II", stream.read(8))
        if version != 1:
            raise ValueError("unsupported preprocessed coefficient fixture")
        result: list[str] = []
        for _ in range(count):
            identity_len, reserved = struct.unpack("<HH", stream.read(4))
            log_size = struct.unpack("<I", stream.read(4))[0]
            value_count = struct.unpack("<Q", stream.read(8))[0]
            if reserved != 0 or value_count != 1 << log_size:
                raise ValueError("invalid preprocessed coefficient fixture")
            result.append(stream.read(identity_len).decode())
            stream.seek(value_count * 4, 1)
        if stream.read(1):
            raise ValueError("trailing preprocessed coefficient fixture data")
        return result


def target_preprocessed_identities(
    source: list[str], source_variant: str, target_variant: str
) -> list[str]:
    if len(source) != len(set(source)):
        raise ValueError("preprocessed coefficient fixture contains duplicate identities")
    if source_variant == target_variant:
        return list(source)
    if source_variant != "canonical" or target_variant != "canonical_without_pedersen":
        raise ValueError(
            f"unsupported preprocessed projection {source_variant} -> {target_variant}"
        )
    pedersen = [f"pedersen_points_{index}" for index in range(56)]
    present = [identity for identity in source if identity.startswith("pedersen_points_")]
    if present != pedersen:
        raise ValueError("canonical preprocessed identities have unexpected Pedersen columns")
    result = [identity for identity in source if not identity.startswith("pedersen_points_")]
    if len(source) != 161 or len(result) != 105:
        raise ValueError("canonical preprocessed identity counts are invalid")
    return result


def semantic_program_payload(data: bytes | bytearray, offset: int, length: int) -> bytes:
    if u32(data, offset) != PROGRAM_MAGIC or length < PROGRAM_HEADER_BYTES:
        raise ValueError("invalid evaluation program")
    section_count = u32(data, offset + 8)
    payload_start = offset + PROGRAM_HEADER_BYTES + section_count * PROGRAM_SECTION_BYTES
    end = offset + length
    sections: dict[int, bytes] = {}
    for index in range(section_count):
        descriptor = offset + PROGRAM_HEADER_BYTES + index * PROGRAM_SECTION_BYTES
        kind, elem_size, relative_offset, count = struct.unpack_from("<IIQQ", data, descriptor)
        start = payload_start + relative_offset
        section_end = start + elem_size * count
        if section_end > end:
            raise ValueError("program section exceeds its encoded extent")
        sections[kind] = bytes(data[start:section_end])
    try:
        return b"".join(sections[kind] for kind in range(1, 6))
    except KeyError as missing:
        raise ValueError("evaluation program is missing a semantic section") from missing


def validate_span_partition(
    records: list[ComponentRecord], tree_columns: tuple[int, int, int, int]
) -> None:
    cursors = {1: 0, 2: 0}
    for record in records:
        trees = [tree for tree, _, _ in record.spans]
        if trees != [0, 1, 2]:
            raise ValueError(f"{record.label} has non-canonical trace span order")
        for tree, start, end in record.spans:
            if tree == 0:
                if start != 0 or end != 0:
                    raise ValueError(f"{record.label} has an unsupported tree-0 trace span")
                continue
            if start != cursors[tree] or end < start:
                raise ValueError(f"composition trace spans are not contiguous at {record.label}")
            cursors[tree] = end
    if cursors[1] != tree_columns[1] or cursors[2] != tree_columns[2]:
        raise ValueError("template composition spans do not match its proof geometry")


def projection_plan_hash(data: bytes | bytearray) -> int:
    canonical = bytearray(data)
    canonical[32:40] = bytes(8)
    result = fnv64([bytes(canonical)])
    if result == 0:
        raise ValueError("projected composition plan hash is zero")
    return result


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def project_components(
    source_data: bytes,
    retargeted_data: bytearray,
    records: list[ComponentRecord],
    active: list[str],
    source_proof_path: Path,
    target_proof_path: Path,
    source_identities: list[str],
    changed_programs: set[tuple[str, int]],
) -> tuple[bytearray, dict[str, object]]:
    source_proof_bytes = source_proof_path.read_bytes()
    target_proof_bytes = target_proof_path.read_bytes()
    source_proof = json.loads(source_proof_bytes)
    target_proof = json.loads(target_proof_bytes)
    source_active, source_logs = active_components_and_trace_logs(source_proof_path)
    if source_active != [record.label for record in records]:
        raise ValueError("template proof component order does not match the composition bundle")
    for record in records:
        if record.label in source_logs and source_logs[record.label] != record.trace_log:
            raise ValueError(f"template proof trace log does not match {record.label}")
    validate_interaction_claim(source_proof, source_active)
    validate_interaction_claim(target_proof, active)

    active_set = set(active)
    retained = [record for record in records if record.label in active_set]
    if [record.label for record in retained] != active:
        raise ValueError("target claim order is not a projection of the template claim")
    if not retained:
        raise ValueError("target claim has no active components")

    source_columns = proof_tree_columns(source_proof)
    target_columns = proof_tree_columns(target_proof)
    source_variant = proof_variant(source_proof)
    target_variant = proof_variant(target_proof)
    target_identities = target_preprocessed_identities(
        source_identities, source_variant, target_variant
    )
    if source_columns[0] != len(source_identities) or target_columns[0] != len(target_identities):
        raise ValueError("preprocessed identities do not match proof tree-0 geometry")
    if source_columns[3] != 8 or target_columns[3] != 8:
        raise ValueError("composition tree geometry is not the canonical eight columns")
    validate_span_partition(records, source_columns)

    target_identity_indices = {
        identity: index for index, identity in enumerate(target_identities)
    }
    projected_records: list[bytes] = []
    tree_cursors = {1: 0, 2: 0}
    random_offset = 0
    component_manifest: list[dict[str, object]] = []
    for record in retained:
        component = bytearray(retargeted_data[record.start : record.end])
        struct.pack_into("<I", component, 20, random_offset)
        mapped_spans: list[dict[str, int]] = []
        for index, (tree, old_start, old_end) in enumerate(record.spans):
            length = old_end - old_start
            new_start = 0 if tree == 0 else tree_cursors[tree]
            new_end = new_start + length
            if tree != 0:
                tree_cursors[tree] = new_end
            relative = record.span_offset - record.start + index * 12
            struct.pack_into("<III", component, relative, tree, new_start, new_end)
            mapped_spans.append(
                {
                    "tree": tree,
                    "source_start": old_start,
                    "source_end": old_end,
                    "target_start": new_start,
                    "target_end": new_end,
                }
            )

        preprocessed_mapping: list[dict[str, object]] = []
        for index in range(record.preprocessed_count):
            absolute = record.preprocessed_offset + index * 4
            source_index = u32(retargeted_data, absolute)
            if source_index >= len(source_identities):
                raise ValueError(f"invalid preprocessed index for {record.label}")
            identity = source_identities[source_index]
            target_index = target_identity_indices.get(identity)
            if target_index is None:
                raise ValueError(
                    f"{record.label} references unavailable preprocessed column {identity}"
                )
            relative = absolute - record.start
            struct.pack_into("<I", component, relative, target_index)
            preprocessed_mapping.append(
                {
                    "slot": index,
                    "identity": identity,
                    "source_index": source_index,
                    "target_index": target_index,
                }
            )

        source_program_hashes: list[str] = []
        target_program_hashes: list[str] = []
        for part_index, (program_offset, program_len) in enumerate(record.program_ranges):
            source_payload = semantic_program_payload(source_data, program_offset, program_len)
            target_payload = semantic_program_payload(retargeted_data, program_offset, program_len)
            expected_change = (record.label, part_index) in changed_programs
            if (source_payload != target_payload) != expected_change:
                raise ValueError(
                    f"projection evaluator rewrite authentication failed for "
                    f"{record.label} part {part_index}"
                )
            source_program_hashes.append(sha256_bytes(source_payload))
            target_program_hashes.append(sha256_bytes(target_payload))
        component_manifest.append(
            {
                "label": record.label,
                "random_coefficient_offset": random_offset,
                "constraints": record.n_constraints,
                "spans": mapped_spans,
                "preprocessed": preprocessed_mapping,
                "source_semantic_program_sha256": source_program_hashes,
                "semantic_program_sha256": target_program_hashes,
            }
        )
        projected_records.append(bytes(component))
        random_offset += record.n_constraints

    if tree_cursors[1] != target_columns[1] or tree_cursors[2] != target_columns[2]:
        raise ValueError("projected composition spans do not match target proof geometry")
    maximum_log = max(u32(record_data, 12) for record_data in projected_records)
    output = bytearray(retargeted_data[:40])
    struct.pack_into("<I", output, 8, PROJECTED_BUNDLE_VERSION)
    struct.pack_into("<Q", output, 16, random_offset)
    struct.pack_into("<II", output, 24, maximum_log, len(projected_records))
    struct.pack_into("<Q", output, 32, 0)
    for record_data in projected_records:
        output.extend(record_data)
    plan_hash = projection_plan_hash(output)
    struct.pack_into("<Q", output, 32, plan_hash)
    manifest = {
        "format": PROJECTION_MANIFEST_FORMAT,
        "version": PROJECTION_MANIFEST_VERSION,
        "bundle_version": PROJECTED_BUNDLE_VERSION,
        "source": {
            "bundle_sha256": sha256_bytes(source_data),
            "proof_sha256": sha256_bytes(source_proof_bytes),
            "preprocessed_identities_sha256": sha256_bytes(
                json.dumps(source_identities, separators=(",", ":")).encode()
            ),
            "preprocessed_variant": source_variant,
            "tree_columns": list(source_columns),
        },
        "target": {
            "proof_sha256": sha256_bytes(target_proof_bytes),
            "preprocessed_variant": target_variant,
            "tree_columns": list(target_columns),
            "bundle_sha256": sha256_bytes(output),
            "plan_hash": f"{plan_hash:016x}",
            "components": len(projected_records),
            "constraints": random_offset,
            "max_evaluation_log_size": maximum_log,
        },
        "components": component_manifest,
    }
    return output, manifest


def retarget(
    template_path: Path,
    proof_path: Path,
    output_path: Path,
    preprocessed_path: Path | None = None,
    template_proof_path: Path | None = None,
    project: bool = False,
    projection_manifest_path: Path | None = None,
) -> dict[str, object]:
    source_data = template_path.read_bytes()
    data = bytearray(source_data)
    if data[:8] != BUNDLE_MAGIC or u32(data, 8) != BUNDLE_VERSION:
        raise ValueError("unsupported composition bundle")
    active_components, logs = active_components_and_trace_logs(proof_path)
    component_count = u32(data, 28)
    offset = 40
    template_components: list[str] = []
    component_records: list[ComponentRecord] = []
    changed: dict[str, tuple[int, int]] = {}
    preprocessed_changes: dict[str, list[dict[str, object]]] = {}
    max_evaluation_log = 0
    identities = preprocessed_identities(preprocessed_path) if preprocessed_path else None
    identity_indices = {identity: index for index, identity in enumerate(identities or [])}
    substitutions = (
        statement_constant_substitutions(template_proof_path, proof_path)
        if template_proof_path is not None
        else {}
    )
    statement_changes: dict[str, list[dict[str, object]]] = {}
    domain_constant_changes: dict[str, list[dict[str, object]]] = {}
    changed_programs: set[tuple[str, int]] = set()

    for _ in range(component_count):
        component_offset = offset
        label_len = u16(data, offset)
        if u16(data, offset + 2) != 0:
            raise ValueError("invalid component header")
        trace_log = u32(data, offset + 8)
        evaluation_log = u32(data, offset + 12)
        span_count = u32(data, offset + 24)
        preprocessed_count = u32(data, offset + 28)
        denominator_count = u32(data, offset + 32)
        ext_source_count = u32(data, offset + 36)
        part_count = u32(data, offset + 40)
        offset += 44
        label = data[offset : offset + label_len].decode()
        template_components.append(label)
        offset += label_len

        target_log = logs.get(label, trace_log)
        target_evaluation_log = target_log + (evaluation_log - trace_log)
        if target_evaluation_log < target_log:
            raise ValueError(f"invalid evaluation log for {label}")
        if denominator_count != 1 << (target_evaluation_log - target_log):
            raise ValueError(f"denominator geometry changed for {label}")
        struct.pack_into("<II", data, component_offset + 8, target_log, target_evaluation_log)
        if target_log != trace_log:
            changed[label] = (trace_log, target_log)
        max_evaluation_log = max(max_evaluation_log, target_evaluation_log)

        span_offset = offset
        spans = tuple(
            struct.unpack_from("<III", data, span_offset + index * 12)
            for index in range(span_count)
        )
        offset += span_count * 12
        preprocessed_offset = offset
        if identities is not None and target_log != trace_log:
            old_sequence = f"seq_{trace_log}"
            target_sequence = f"seq_{target_log}"
            for index in range(preprocessed_count):
                index_offset = offset + index * 4
                old_index = u32(data, index_offset)
                if old_index >= len(identities):
                    raise ValueError(f"invalid preprocessed index for {label}")
                if identities[old_index] != old_sequence:
                    continue
                target_index = identity_indices.get(target_sequence)
                if target_index is None:
                    raise ValueError(f"missing {target_sequence} preprocessed column")
                struct.pack_into("<I", data, index_offset, target_index)
                preprocessed_changes.setdefault(label, []).append(
                    {
                        "slot": index,
                        "from": old_sequence,
                        "to": target_sequence,
                        "from_index": old_index,
                        "to_index": target_index,
                    }
                )
        offset += preprocessed_count * 4
        offset += denominator_count * 4
        offset += ext_source_count * 32
        program_ranges: list[tuple[int, int]] = []
        for part_index in range(part_count):
            part_offset = offset
            program_len = u32(data, offset + 4)
            program_offset = offset + 16
            if u32(data, program_offset) != PROGRAM_MAGIC:
                raise ValueError(f"invalid evaluation program for {label}")
            program_ranges.append((program_offset, program_len))
            struct.pack_into("<I", data, program_offset + PROGRAM_DOMAIN_LOG_OFFSET, target_log)
            domain_substitutions = memory_address_stride_substitutions(
                label, trace_log, target_log
            )
            program_substitutions = dict(substitutions)
            for old, new in domain_substitutions.items():
                previous = program_substitutions.setdefault(old, new)
                if previous != new:
                    raise ValueError(
                        f"conflicting constant retarget for {label}: "
                        f"{old} -> {previous} or {new}"
                    )
            old_hash, new_hash, replacements = retarget_program_constants(
                data, program_offset, program_len, program_substitutions
            )
            domain_replacements = [
                replacement for replacement in replacements if replacement[0] in domain_substitutions
            ]
            if sorted(domain_replacements) != sorted(domain_substitutions.items()):
                raise ValueError(
                    f"unexpected {label} stride constants in evaluator part {part_index}"
                )
            if replacements:
                struct.pack_into("<Q", data, part_offset + 8, new_hash)
                changed_programs.add((label, part_index))
            statement_replacements = [
                replacement
                for replacement in replacements
                if replacement[0] in substitutions
                and replacement[0] not in domain_substitutions
            ]
            if statement_replacements:
                statement_changes.setdefault(label, []).append(
                    {
                        "part": part_index,
                        "from_semantic_hash": f"{old_hash:016x}",
                        "to_semantic_hash": f"{new_hash:016x}",
                        "constants": [
                            {"from": old, "to": new}
                            for old, new in sorted(set(statement_replacements))
                        ],
                    }
                )
            if domain_replacements:
                domain_constant_changes.setdefault(label, []).append(
                    {
                        "part": part_index,
                        "source_log_size": trace_log,
                        "target_log_size": target_log,
                        "from_semantic_hash": f"{old_hash:016x}",
                        "to_semantic_hash": f"{new_hash:016x}",
                        "constants": [
                            {"from": old, "to": new}
                            for old, new in sorted(domain_replacements)
                        ],
                    }
                )
            offset = program_offset + program_len
        component_records.append(
            ComponentRecord(
                label=label,
                start=component_offset,
                end=offset,
                trace_log=trace_log,
                n_constraints=u32(data, component_offset + 16),
                span_offset=span_offset,
                spans=spans,
                preprocessed_offset=preprocessed_offset,
                preprocessed_count=preprocessed_count,
                program_ranges=tuple(program_ranges),
            )
        )

    if offset != len(data):
        raise ValueError("trailing composition bundle data")
    template_set = set(template_components)
    if len(template_set) != len(template_components):
        raise ValueError("composition bundle contains duplicate component labels")
    active_set = set(active_components)
    projection_manifest: dict[str, object] | None = None
    if active_set != template_set:
        inactive = sorted(template_set - active_set)
        missing = sorted(active_set - template_set)
        if not project:
            raise ValueError(
                "target proof changes the active component set; component projection "
                f"is required (inactive_template={inactive}, missing_template={missing})"
            )
        if missing:
            raise ValueError(f"target proof has components absent from the template: {missing}")
        if template_proof_path is None or preprocessed_path is None:
            raise ValueError(
                "projection requires the template proof and preprocessed coefficient identities"
            )
        if projection_manifest_path is None:
            raise ValueError("projection requires an explicit manifest output")
        data, projection_manifest = project_components(
            source_data,
            data,
            component_records,
            active_components,
            template_proof_path,
            proof_path,
            identities or [],
            changed_programs,
        )
        changed = {label: value for label, value in changed.items() if label in active_set}
        preprocessed_changes = {
            label: value for label, value in preprocessed_changes.items() if label in active_set
        }
        statement_changes = {
            label: value for label, value in statement_changes.items() if label in active_set
        }
        domain_constant_changes = {
            label: value
            for label, value in domain_constant_changes.items()
            if label in active_set
        }
        max_evaluation_log = u32(data, 24)
        component_count = u32(data, 28)
    elif project:
        raise ValueError("component projection was requested but the component set is unchanged")
    else:
        struct.pack_into("<I", data, 24, max_evaluation_log)

    if projection_manifest is not None:
        projection_manifest_path.write_text(
            json.dumps(projection_manifest, indent=2, sort_keys=True) + "\n"
        )
    output_path.write_bytes(data)
    result: dict[str, object] = {
        "components": component_count,
        "changed_components": len(changed),
        "changed_preprocessed_components": len(preprocessed_changes),
        "changed_statement_components": len(statement_changes),
        "changed_domain_constant_components": len(domain_constant_changes),
        "max_evaluation_log_size": max_evaluation_log,
        "changes": {label: {"from": old, "to": new} for label, (old, new) in changed.items()},
        "preprocessed_changes": preprocessed_changes,
        "statement_changes": statement_changes,
        "domain_constant_changes": domain_constant_changes,
    }
    if projection_manifest is not None:
        result["projection"] = projection_manifest["target"]
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--preprocessed-coefficients", type=Path)
    parser.add_argument("--template-proof", type=Path)
    parser.add_argument("--project-components", action="store_true")
    parser.add_argument("--projection-manifest", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            retarget(
                args.template,
                args.proof,
                args.output,
                args.preprocessed_coefficients,
                args.template_proof,
                args.project_components,
                args.projection_manifest,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
