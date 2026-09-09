"""Measurement-envelope validation for Ethereum block comparisons."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")


class MeasurementError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MeasurementError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _positive(value: Any, where: str) -> int:
    _require(type(value) is int and value > 0, f"{where} must be positive")
    return value


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values()),
             f"{where} differs")
    return value


def validate_timing_buckets(
    value: Any, names: tuple[str, ...], where: str,
) -> bool:
    """Validate mutually exclusive timing buckets and exact total wall."""
    value = _exact(value, set(names) | {"total_wall_ns"}, where)
    present = []
    wall_total = 0
    for name in names:
        bucket = value[name]
        if bucket is None:
            present.append(False)
            continue
        bucket = _timing(bucket, f"{where}.{name}")
        wall_total += bucket["wall_ns"]
        present.append(True)
    total = value["total_wall_ns"]
    _require(total is None or (type(total) is int and total >= 0),
             f"{where}.total_wall_ns must be a nonnegative integer or null")
    if all(present):
        _require(total == wall_total, f"{where} total wall does not reconcile")
    else:
        _require(total is None, f"{where} partial timing cannot claim total wall")
    return all(present)


def _trace_stage(
    value: Any, where: str, strategy: str, *, efficiency: bool,
    extra_keys: set[str] | None = None,
) -> tuple[int, int, int]:
    keys = {"cycles", "wall_ns", "rate", "worker_count", "strategy", "authority"}
    if efficiency:
        keys.add("efficiency")
    keys.update(extra_keys or set())
    value = _exact(value, keys, where)
    cycles = _positive(value["cycles"], f"{where}.cycles")
    wall = _positive(value["wall_ns"], f"{where}.wall_ns")
    _require(value["rate"] == {"cycles": cycles, "nanoseconds": wall},
             f"{where} rate differs")
    workers = _positive(value["worker_count"], f"{where}.worker_count")
    _require(value["strategy"] == strategy, f"{where} strategy differs")
    _require(value["authority"] in ("measured", "modeled"),
             f"{where} authority differs")
    return cycles, wall, workers


def validate_trace_generation(
    value: Any, where: str, expected_schema: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact(value, {
        "schema", "mode", "whole_program", "capture", "parallel_replay",
        "total_trace_generation_wall_ns", "total_authority",
    }, where)
    _require(value["schema"] == expected_schema, f"{where} schema differs")
    total = _positive(value["total_trace_generation_wall_ns"], f"{where}.total wall")
    if value["mode"] == "whole-program-repetitions":
        _require(value["capture"] is None and value["parallel_replay"] is None,
                 f"{where} whole-program mode contains capture/replay stages")
        whole = _exact(value["whole_program"], {
            "cycles", "wall_ns", "rate", "worker_count", "multiplicity", "strategy",
            "authority",
        }, f"{where}.whole_program")
        _, wall, _ = _trace_stage(
            whole, f"{where}.whole_program", "parallel-whole-program-repetitions",
            efficiency=False, extra_keys={"multiplicity"},
        )
        _positive(whole["multiplicity"], f"{where}.whole_program.multiplicity")
        _require(total == wall and value["total_authority"] == whole["authority"],
                 f"{where} total authority does not reconcile")
        return value
    _require(value["mode"] == "sequential-capture-plus-parallel-replay"
             and value["whole_program"] is None, f"{where} mode differs")
    capture_cycles, capture_wall, capture_workers = _trace_stage(
        value["capture"], f"{where}.capture", "sequential-authoritative-capture",
        efficiency=False,
    )
    replay_cycles, replay_wall, replay_workers = _trace_stage(
        value["parallel_replay"], f"{where}.parallel_replay",
        "parallel-memoryless-replay", efficiency=True,
    )
    _require(capture_workers == 1, f"{where} capture is not sequential")
    _require(value["parallel_replay"]["efficiency"] == {
        "numerator": replay_cycles * capture_wall,
        "denominator": replay_wall * capture_cycles * replay_workers,
    }, f"{where} replay efficiency differs")
    _require(total == capture_wall + replay_wall, f"{where} total wall does not reconcile")
    authority = ("measured" if value["capture"]["authority"] == "measured"
                 and value["parallel_replay"]["authority"] == "measured" else "modeled")
    _require(value["total_authority"] == authority, f"{where} total authority differs")
    return value


def validate_execution_work(
    value: Any, where: str, expected_schema: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact(value, {
        "schema", "multiplicity", "strategy", "per_execution_isa_steps",
        "total_execution_isa_steps", "user_ns", "system_ns", "total_cpu_ns", "authority",
    }, where)
    _require(value["schema"] == expected_schema, f"{where} schema differs")
    multiplicity = _positive(value["multiplicity"], f"{where}.multiplicity")
    _require(type(value["strategy"]) is str and value["strategy"],
             f"{where}.strategy differs")
    per_execution = _positive(
        value["per_execution_isa_steps"], f"{where}.per_execution_isa_steps",
    )
    _require(value["total_execution_isa_steps"] == per_execution * multiplicity,
             f"{where} ISA-step total does not reconcile")
    _require(type(value["user_ns"]) is int and value["user_ns"] >= 0
             and type(value["system_ns"]) is int and value["system_ns"] >= 0
             and value["total_cpu_ns"] == value["user_ns"] + value["system_ns"],
             f"{where} CPU total does not reconcile")
    _require(value["authority"] in ("measured", "modeled"),
             f"{where}.authority differs")
    return value


def validate_security(
    value: Any, where: str, fields: tuple[str, ...], *, complete: bool,
) -> bool:
    value = _exact(value, set(fields), where)
    nested = {
        "schema", "proof_profile", "native_blake_leaf", "recursive_ethereum_leaf",
        "recursive_node",
        "conservative_end_to_end_target_bits", "proof_bytes", "fresh_verification",
        "independent_verifier",
    }
    if set(fields) == nested:
        if all(item is None for item in value.values()):
            _require(not complete, f"{where} is absent")
            return False
        _validate_stwo_security(value, where)
        return True
    for field, item in value.items():
        if item is None:
            _require(not complete, f"{where}.{field} is absent")
            continue
        if field in ("field", "commitment_hash", "transcript_hash"):
            _require(type(item) is str and item, f"{where}.{field} differs")
        elif field in ("fresh_verification", "independent_verifier"):
            _require(type(item) is bool, f"{where}.{field} differs")
        else:
            _positive(item, f"{where}.{field}")
    return all(item is not None for item in value.values())


def _pcs(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    value = _exact(value, keys, where)
    for field in ("field", "commitment_hash", "transcript_hash"):
        _require(type(value[field]) is str and value[field],
                 f"{where}.{field} differs")
    for field in ("n_queries", "fold_step"):
        _positive(value[field], f"{where}.{field}")
    for field in ("pow_bits", "log_blowup_factor", "log_last_layer_degree_bound"):
        _require(type(value[field]) is int and value[field] >= 0,
                 f"{where}.{field} differs")
    _require(value["lifting_log_size"] is None
             or (type(value["lifting_log_size"]) is int
                 and value["lifting_log_size"] >= 0),
             f"{where}.lifting_log_size differs")
    return value


def _configured_bits(value: dict[str, Any]) -> int:
    return value["pow_bits"] + value["n_queries"] * value["log_blowup_factor"]


def _validate_stwo_security(value: dict[str, Any], where: str) -> None:
    pcs_fields = {
        "field", "commitment_hash", "transcript_hash", "pow_bits", "n_queries",
        "log_blowup_factor", "fold_step", "log_last_layer_degree_bound",
        "lifting_log_size",
    }
    _require(value["native_blake_leaf"] is None,
             f"{where}.native_blake_leaf is selected")
    leaf = _exact(value["recursive_ethereum_leaf"], {"pcs", "proof_profile"},
                  f"{where}.recursive_ethereum_leaf")
    _pcs(leaf["pcs"], pcs_fields, f"{where}.recursive_ethereum_leaf.pcs")
    profile = _exact(leaf["proof_profile"], {
        "air_program_id_m31_le", "configured_pcs_bits",
        "conjectured_security_bits", "extension_component_count", "hash_suite",
        "interaction_pow_bits",
        "child_air_manifest_sha256", "leaf_verification_key_id_m31_le",
        "profile_id_m31_le", "profile_name", "proof_kind", "recursive_ingress",
        "security_identity_sha256",
    }, f"{where}.recursive_ethereum_leaf.proof_profile")
    for field in ("child_air_manifest_sha256", "security_identity_sha256"):
        _require(type(profile[field]) is str and SHA256.fullmatch(profile[field]),
                 f"{where}.recursive_ethereum_leaf.{field} differs")
    _require(profile["extension_component_count"] == 14
             and profile["configured_pcs_bits"] == 209
             and profile["conjectured_security_bits"] == 120
             and profile["hash_suite"] == "Poseidon2-M31"
             and profile["interaction_pow_bits"] == 10
             and profile["proof_kind"] == "ethereum_segment_v3_poseidon2"
             and profile["recursive_ingress"] == "ethereum_segment_v3_full",
             f"{where}.recursive_ethereum_leaf profile differs")
    recursive_fields = pcs_fields | {
        "interaction_pow_bits", "configured_pcs_bits", "conjectured_security_bits",
        "security_identity_sha256",
    }
    node = _pcs(value["recursive_node"], recursive_fields,
                f"{where}.recursive_node")
    expected_node = {
        "field": "M31", "commitment_hash": "Poseidon2-M31",
        "transcript_hash": "Poseidon2-M31", "pow_bits": 16,
        "n_queries": 193, "log_blowup_factor": 1, "fold_step": 4,
        "log_last_layer_degree_bound": 0, "lifting_log_size": None,
        "interaction_pow_bits": 10, "configured_pcs_bits": 209,
        "conjectured_security_bits": 120,
    }
    _require(all(node[field] == item for field, item in expected_node.items())
             and node["security_identity_sha256"]
             == "675ff4fd58923d26ae7f4573b19a53a268bcf27bf9ad96cb18a04bd845169e63",
             f"{where}.recursive_node differs")
    _require(value["schema"] == "stwo.ethereum.block-proof-artifact-security.v2"
             and value["proof_profile"]
             in ("recursive_ethereum_leaf", "recursive_node")
             and value["conservative_end_to_end_target_bits"] == 120,
             f"{where} authority differs")
    _positive(value["proof_bytes"], f"{where}.proof_bytes")
    _require(value["fresh_verification"] is True
             and value["independent_verifier"] is True,
             f"{where} verification authority differs")


def validate_hardware(value: Any, where: str, fields: tuple[str, ...]) -> bool:
    value = _exact(value, set(fields), where)
    strings = {
        "machine_model", "cpu_model", "gpu_model", "operating_system", "power_source",
        "thermal_state", "execution_strategy",
    }
    positives = {
        "cpu_logical_cores", "memory_bytes", "process_count", "thread_count",
        "process_workers", "execution_multiplicity",
    }
    for field, item in value.items():
        if item is None:
            continue
        if field in strings:
            _require(type(item) is str and item, f"{where}.{field} differs")
        elif field in positives:
            _positive(item, f"{where}.{field}")
        else:
            _require(type(item) is int and item >= 0, f"{where}.{field} differs")
    return all(item is not None for item in value.values())


def validate_leaf_producer_observation(
    value: Any, executable: dict[str, Any], node_index: int, where: str,
) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "role", "executable", "argv", "stream_session_sha256",
        "segment_index", "progress_record_sha256", "prove_timing",
    }, where)
    _require(value["schema"]
             == "stwo.ethereum.block-proof-leaf-stream-observation.v1"
             and value["role"] == "leaf_stream_producer"
             and value["executable"] == executable
             and value["segment_index"] == node_index,
             f"{where} authority differs")
    _require(type(value["argv"]) is list and len(value["argv"]) >= 2
             and all(type(item) is str and item for item in value["argv"]),
             f"{where}.argv differs")
    for field in ("stream_session_sha256", "progress_record_sha256"):
        _require(type(value[field]) is str and SHA256.fullmatch(value[field]),
                 f"{where}.{field} differs")
    _timing(value["prove_timing"], f"{where}.prove_timing")
    return value


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("ascii")


def _content_sha256(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    return hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()


def _file_identity(value: Any, where: str, *, path: bool = False) -> dict[str, Any]:
    keys = {"bytes", "sha256"} | ({"path"} if path else set())
    value = _exact(value, keys, where)
    _require(type(value["bytes"]) is int and value["bytes"] > 0
             and type(value["sha256"]) is str and SHA256.fullmatch(value["sha256"]),
             f"{where} differs")
    if path:
        _require(type(value["path"]) is str and value["path"], f"{where}.path differs")
    return value


def validate_leaf_stream_sessions(
    publications: Any, artifacts: list[dict[str, Any]], expected_segments: int,
    where: str,
) -> bool:
    _require(type(publications) is list, f"{where} differs")
    session_ids = []
    session_receipts: dict[str, dict[str, Any]] = {}
    published: list[int] = []
    session_by_segment: dict[int, str] = {}
    all_complete = True
    for index, publication in enumerate(publications):
        publication = _exact(
            publication, {"receipt", "file"}, f"{where}[{index}]",
        )
        receipt = _exact(publication["receipt"], {
            "schema", "classification", "session_index", "stream_session_sha256",
            "executable", "argv", "request", "first_segment_index",
            "published_segment_indices", "exit_code", "stdout_bytes", "stderr_bytes",
            "timing", "stream_result", "content_sha256",
        }, f"{where}[{index}].receipt")
        _require(receipt["schema"]
                 == "stwo.ethereum.block-proof-leaf-session-receipt.v1"
                 and receipt["session_index"] == index
                 and receipt["content_sha256"] == _content_sha256(receipt),
                 f"{where}[{index}] receipt authority differs")
        session_id = receipt["stream_session_sha256"]
        _require(type(session_id) is str and SHA256.fullmatch(session_id),
                 f"{where}[{index}] session identity differs")
        _require(session_id not in session_receipts,
                 f"{where}[{index}] duplicates a session identity")
        _file_identity(receipt["executable"], f"{where}[{index}].executable")
        _file_identity(receipt["request"], f"{where}[{index}].request", path=True)
        _require(type(receipt["argv"]) is list and len(receipt["argv"]) >= 2,
                 f"{where}[{index}].argv differs")
        indices = receipt["published_segment_indices"]
        _require(type(indices) is list and indices == sorted(set(indices))
                 and all(type(item) is int and 0 <= item < expected_segments
                         for item in indices),
                 f"{where}[{index}] publications differ")
        classification = receipt["classification"]
        _require(classification in {
            "complete", "failed", "indeterminate_after_controller_loss",
            "terminated_by_controller", "timed_out",
        }, f"{where}[{index}] classification differs")
        if classification == "complete":
            _require(receipt["exit_code"] == 0 and receipt["stdout_bytes"] == 0
                     and receipt["stderr_bytes"] == 0 and type(receipt["timing"]) is dict
                     and receipt["stream_result"] is not None,
                     f"{where}[{index}] completion differs")
        elif classification == "indeterminate_after_controller_loss":
            _require(receipt["exit_code"] is None and receipt["timing"] is None,
                     f"{where}[{index}] indeterminate custody differs")
            all_complete = False
        else:
            _require(type(receipt["exit_code"]) is int
                     and type(receipt["timing"]) is dict,
                     f"{where}[{index}] terminal custody differs")
            all_complete = False
        _require(type(receipt["stdout_bytes"]) is int and receipt["stdout_bytes"] >= 0
                 and type(receipt["stderr_bytes"]) is int
                 and receipt["stderr_bytes"] >= 0,
                 f"{where}[{index}] transport custody differs")
        if receipt["timing"] is not None:
            timing = _exact(
                receipt["timing"], {"wall_ns", "user_ns", "system_ns"},
                f"{where}[{index}].timing",
            )
            _require(type(timing["wall_ns"]) is int and timing["wall_ns"] >= 0
                     and timing["user_ns"] is None and timing["system_ns"] is None,
                     f"{where}[{index}] timing differs")
        if receipt["stream_result"] is not None:
            _file_identity(
                receipt["stream_result"], f"{where}[{index}].stream_result", path=True,
            )
        file_identity = _file_identity(
            publication["file"], f"{where}[{index}].file", path=True,
        )
        encoded = _canonical_bytes(receipt)
        _require(file_identity["bytes"] == len(encoded)
                 and file_identity["sha256"] == hashlib.sha256(encoded).hexdigest(),
                 f"{where}[{index}] file custody differs")
        session_ids.append(session_id)
        session_receipts[session_id] = receipt
        published.extend(indices)
        for segment_index in indices:
            _require(segment_index not in session_by_segment,
                     f"{where} publishes a segment more than once")
            session_by_segment[segment_index] = session_id
    leaf_sessions = {
        artifact["processes"]["producer"]["stream_session_sha256"]
        for artifact in artifacts if artifact["scope"] == "leaf"
    }
    _require(leaf_sessions <= set(session_ids), f"{where} omits a leaf producer session")
    for artifact in artifacts:
        if artifact["scope"] == "leaf":
            producer = artifact["processes"]["producer"]
            _require(
                session_by_segment.get(artifact["node_index"])
                == producer["stream_session_sha256"],
                f"{where} leaf-to-session binding differs",
            )
            session = session_receipts[producer["stream_session_sha256"]]
            _require(session["executable"] == artifact["prover"]
                     and session["argv"] == producer["argv"],
                     f"{where} leaf producer process custody differs")
    expected_published = sorted(
        artifact["node_index"] for artifact in artifacts if artifact["scope"] == "leaf"
    )
    _require(sorted(published) == expected_published
             and len(published) == len(set(published)),
             f"{where} publication coverage differs")
    return all_complete and len(publications) == 1
