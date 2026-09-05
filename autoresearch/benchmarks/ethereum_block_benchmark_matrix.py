#!/usr/bin/env python3
"""Create-only 5x2 Ethereum benchmark matrix and evidence admissions.

The matrix is deliberately non-promotable.  It distinguishes retained
execution or leaf capability evidence from a matched, freshly verified final
proof, and never turns a log timestamp or a modeled value into a measurement.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


BENCHMARK_DIR = Path(__file__).resolve().parent
REPOSITORY = Path(__file__).resolve().parents[2]
for search_path in (str(REPOSITORY), str(BENCHMARK_DIR)):
    if search_path not in sys.path:
        sys.path.insert(0, search_path)

import ethereum_block_benchmark_protocol as benchmark_protocol  # noqa: E402
import ethereum_block_benchmark_matrix_contract as matrix_contract  # noqa: E402
import ethereum_block_compact_replay_admission as compact_replay  # noqa: E402
import ethereum_block_comparison as comparison  # noqa: E402
import ethereum_block_corpus as corpus_authority  # noqa: E402
import ethereum_block_zisk_final_admission as zisk_final  # noqa: E402
import ethereum_block_zisk_final_evidence as zisk_final_evidence  # noqa: E402
from scripts import ethereum_block_proof_protocol as proof_protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
from scripts import ethereum_poseidon_leaf_evidence_join as leaf_join  # noqa: E402
from scripts import riscv_segmented_execution as segmented_execution  # noqa: E402


MATRIX_SCHEMA = "stwo.ethereum.block-benchmark-matrix.v1"
CAPABILITY_SCHEMA = "stwo.ethereum.block-benchmark-capability-evidence.v1"
ZISK_EXECUTION_KIND = "zisk-pinned-execution-projection-v1"
STWO_EXECUTION_KIND = "stwo-segmented-execution-receipt-v3"
BENCHMARK_RESULT_KIND = "ethereum-apples-to-apples-result-v3"
LEAF_CAPABILITY_KIND = "stwo-poseidon-v4-leaf-capability-v1"
TARGET_AVERAGE_WALL_NS = matrix_contract.TARGET_AVERAGE_WALL_NS
SCOPES = matrix_contract.SCOPES
SYSTEMS = matrix_contract.SYSTEMS
CONTRACT = matrix_contract.CONTRACT
UNAVAILABLE_REASONS = matrix_contract.UNAVAILABLE_REASONS
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class MatrixError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MatrixError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value), f"{where} differs")
    return value


def _read_json(path: Path, where: str, *, canonical: bool) -> tuple[bytes, dict[str, Any]]:
    raw = store.read_regular(path, where, maximum=store.MAX_JSON_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    if canonical:
        _require(raw == proof_protocol.canonical_bytes(value),
                 f"{where} is not canonical JSON")
    return raw, value


def _file_identity(path: Path, where: str) -> dict[str, Any]:
    path = path.absolute()
    identity = store.file_identity(path, where)
    return {"path": str(path), **identity}


def _validate_identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"path", "bytes", "sha256"}, where)
    _require(type(value["path"]) is str and Path(value["path"]).is_absolute(),
             f"{where}.path differs")
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where}.bytes differs")
    _sha(value["sha256"], f"{where}.sha256")
    store.validate_file_identity(Path(value["path"]), {
        "bytes": value["bytes"], "sha256": value["sha256"],
    }, where)
    return value


def _transport(value: Any, where: str) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact(value, {"bytes", "sha256", "framing"}, where)
    _require(type(value["bytes"]) is int and value["bytes"] > 0,
             f"{where}.bytes differs")
    _sha(value["sha256"], f"{where}.sha256")
    _require(type(value["framing"]) is str and value["framing"],
             f"{where}.framing differs")
    return value


def _unavailable(scope: str, reason: str) -> dict[str, Any]:
    return {
        "scope": scope,
        "status": "unavailable",
        "reason": reason,
        "evidence": None,
        "timing": None,
        "timing_authority": None,
        "security_target_bits": None,
        "fresh_verification": None,
    }


def _retained_stage(
    scope: str, reason: str, evidence: dict[str, Any],
    *, timing: dict[str, int] | None = None,
    timing_authority: str | None = None,
    security_target_bits: int | None = None,
    fresh_verification: bool | None = None,
    status: str = "retained_nonpromotable",
) -> dict[str, Any]:
    return {
        "scope": scope,
        "status": status,
        "reason": reason,
        "evidence": evidence,
        "timing": timing,
        "timing_authority": timing_authority,
        "security_target_bits": security_target_bits,
        "fresh_verification": fresh_verification,
    }


def _zisk_execution_evidence(
    manifest_identity: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    execution = manifest["zisk"]["execution"]
    return {
        "kind": ZISK_EXECUTION_KIND,
        "identity": manifest_identity,
        "projection": {
            "steps": execution["steps"],
            "sdk_display_cost": execution["sdk_display_cost"],
            "output": execution["output"],
            "final_proof_retained": False,
        },
    }


def _base_system(
    fixture: dict[str, Any], system: str, manifest_identity: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    guest = fixture["semantic_io"]["guest_transports"]
    prefix = "zisk" if system == "zisk" else "stwo"
    stages = {
        scope: _unavailable(scope, UNAVAILABLE_REASONS[system].get(
            scope, "no-retained-evidence",
        ))
        for scope in SCOPES
    }
    if system == "zisk" and fixture["block"]["number"] == 24_628_607:
        evidence = _zisk_execution_evidence(manifest_identity, manifest)
        stages["execution"] = _retained_stage(
            "execution",
            "pinned-output-and-work-projection-without-bound-stage-timing",
            evidence,
        )
    return {
        "input_transport": copy.deepcopy(guest[f"{prefix}_input"]),
        "output_transport": copy.deepcopy(guest[f"{prefix}_output"]),
        "stages": stages,
    }


def _base_fixture(
    fixture: dict[str, Any], manifest_identity: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    block = fixture["block"]
    return {
        "fixture_id": fixture["fixture_id"],
        "category": fixture["category"],
        "block": {
            "chain_id": block["chain_id"],
            "number": block["number"],
            "hash": block["hash"],
            "parent_state_root": block["parent_state_root"],
        },
        "semantic_io": {
            "input": copy.deepcopy(fixture["semantic_io"]["input"]),
            "output": copy.deepcopy(fixture["semantic_io"]["output"]),
        },
        "systems": {
            system: _base_system(fixture, system, manifest_identity, manifest)
            for system in SYSTEMS
        },
        "equivalence": {
            "guest_semantics_matched": False,
            "semantic_input_matched": False,
            "semantic_output_matched": False,
            "hardware_power_thermal_matched": False,
            "security_matched": False,
        },
        "comparison_ready": False,
    }


def build_matrix(corpus_path: Path, manifest_path: Path) -> dict[str, Any]:
    _, corpus = _read_json(corpus_path, "benchmark corpus", canonical=False)
    _, manifest = _read_json(manifest_path, "reference manifest", canonical=False)
    try:
        corpus_authority.validate(corpus)
        comparison.validate_manifest(manifest)
        corpus_authority.validate_reference_manifest(corpus, manifest)
    except (corpus_authority.CorpusError, comparison.ContractError) as error:
        raise MatrixError(str(error)) from error
    corpus_identity = _file_identity(corpus_path, "benchmark corpus")
    corpus_identity["corpus_sha256"] = corpus["corpus_sha256"]
    manifest_identity = _file_identity(manifest_path, "reference manifest")
    manifest_identity.update({
        "schema": manifest["schema"],
        "statement_sha256": manifest["benchmark_protocol"]["statement_sha256"],
    })
    fixtures = [
        _base_fixture(fixture, manifest_identity, manifest)
        for fixture in corpus["fixtures"]
    ]
    return proof_protocol.seal({
        "schema": MATRIX_SCHEMA,
        "contract": copy.deepcopy(CONTRACT),
        "corpus": corpus_identity,
        "reference_manifest": manifest_identity,
        "fixtures": fixtures,
        "capability_evidence": [],
        "aggregate": _derived_aggregate(fixtures),
        "comparison_ready": False,
    })


def _validate_source_authorities(
    matrix: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    corpus_identity = _exact(matrix["corpus"], {
        "path", "bytes", "sha256", "corpus_sha256",
    }, "matrix.corpus")
    _sha(corpus_identity["corpus_sha256"], "matrix.corpus.corpus_sha256")
    _validate_identity({key: corpus_identity[key] for key in ("path", "bytes", "sha256")},
                       "matrix corpus")
    _, corpus = _read_json(Path(corpus_identity["path"]), "matrix corpus", canonical=False)
    try:
        corpus_authority.validate(corpus)
    except corpus_authority.CorpusError as error:
        raise MatrixError(str(error)) from error
    _require(corpus_identity["corpus_sha256"] == corpus["corpus_sha256"],
             "matrix corpus content authority differs")

    manifest_identity = _exact(matrix["reference_manifest"], {
        "path", "bytes", "sha256", "schema", "statement_sha256",
    }, "matrix.reference_manifest")
    _validate_identity({key: manifest_identity[key] for key in ("path", "bytes", "sha256")},
                       "matrix reference manifest")
    _, manifest = _read_json(
        Path(manifest_identity["path"]), "matrix reference manifest", canonical=False,
    )
    try:
        comparison.validate_manifest(manifest)
        corpus_authority.validate_reference_manifest(corpus, manifest)
    except (comparison.ContractError, corpus_authority.CorpusError) as error:
        raise MatrixError(str(error)) from error
    _require(manifest_identity["schema"] == manifest["schema"]
             and manifest_identity["statement_sha256"]
             == manifest["benchmark_protocol"]["statement_sha256"],
             "matrix reference manifest authority differs")
    return corpus, manifest


def _timing(value: Any, where: str) -> dict[str, int] | None:
    if value is None:
        return None
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    _require(all(type(item) is int and item >= 0 for item in value.values()),
             f"{where} differs")
    return value


def _validate_zisk_execution(
    evidence: Any, manifest_identity: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    expected = _zisk_execution_evidence(manifest_identity, manifest)
    _require(evidence == expected, "ZisK execution evidence differs")
    return _retained_stage(
        "execution",
        "pinned-output-and-work-projection-without-bound-stage-timing",
        expected,
    )


def _execution_projection(bundle: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        receipt = segmented_execution.validate_bundle(bundle)
    except (segmented_execution.ContractError, OSError) as error:
        raise MatrixError(str(error)) from error
    # validate_bundle has already replayed this controller's insertion-order
    # canonical codec.  It intentionally predates the sorted proof codec.
    _, plan = _read_json(bundle / "plan.json", "segmented execution plan", canonical=False)
    evidence = {
        "kind": STWO_EXECUTION_KIND,
        "bundle_path": str(bundle.absolute()),
        "plan": _file_identity(bundle / "plan.json", "segmented execution plan"),
        "journal": _file_identity(bundle / "execution.ndjson", "segmented execution journal"),
        "receipt": _file_identity(bundle / "receipt.json", "segmented execution receipt"),
        "projection": {
            "execution_profile": plan["execution_profile"],
            "source_clean": plan["source"]["clean"],
            "elf": {key: plan["elf"][key] for key in ("bytes", "sha256")},
            "input": {key: plan["input"][key] for key in ("bytes", "sha256")},
            "segment_count": receipt["segment_count"],
            "total_cycles": receipt["total_cycles"],
            "total_core_trace_rows": receipt["total_core_trace_rows"],
            "total_external_trace_rows": receipt["total_external_trace_rows"],
            "max_segment_cycle_count": receipt["max_segment_cycle_count"],
            "clock_frame": receipt["clock_frame"],
            "segment_statement_v2_admissible": receipt[
                "segment_statement_v2_admissible"
            ],
            "output_sha256": receipt["output_sha256"],
        },
    }
    return evidence, plan


def _validate_stwo_execution(
    evidence: Any, fixture: dict[str, Any],
) -> dict[str, Any]:
    evidence = _exact(evidence, {
        "kind", "bundle_path", "plan", "journal", "receipt", "projection",
    }, "Stwo execution evidence")
    _require(evidence["kind"] == STWO_EXECUTION_KIND,
             "Stwo execution evidence kind differs")
    bundle = Path(evidence["bundle_path"])
    _require(bundle.is_absolute(), "Stwo execution bundle path differs")
    expected, _ = _execution_projection(bundle)
    _require(evidence == expected, "Stwo execution evidence replay differs")
    guest_input = fixture["semantic_io"]["guest_transports"]["stwo_input"]
    guest_output = fixture["semantic_io"]["guest_transports"]["stwo_output"]
    _require(guest_input is not None and guest_output is not None,
             "Stwo execution fixture transport is unavailable")
    projection = evidence["projection"]
    _require(projection["execution_profile"] == "rv32im-zkvm-ethereum-v1",
             "Stwo execution profile differs")
    _require(projection["input"] == {
        "bytes": guest_input["bytes"], "sha256": guest_input["sha256"],
    }, "Stwo execution input differs from corpus")
    _require(projection["output_sha256"] == guest_output["sha256"],
             "Stwo execution output differs from corpus")
    return _retained_stage(
        "execution",
        "execution-only-receipt-without-bound-stage-timing-or-proof",
        evidence,
    )


def _benchmark_result_evidence(
    path: Path, system: str, manifest: dict[str, Any],
) -> dict[str, Any]:
    _, result = _read_json(path, "benchmark result", canonical=True)
    try:
        benchmark_protocol.validate_result(result, manifest["benchmark_protocol"])
    except benchmark_protocol.BenchmarkProtocolError as error:
        raise MatrixError(str(error)) from error
    result_name = "stwo" if system == "stwo_zig" else "zisk"
    system_result = result["systems"][result_name]
    custody = system_result["proof_custody"]
    security = system_result["security"]
    return {
        "kind": BENCHMARK_RESULT_KIND,
        "identity": _file_identity(path, "benchmark result"),
        "projection": {
            "statement_sha256": result["statement_sha256"],
            "result_comparison_ready": result["comparison_ready"],
            "system": system,
            "system_status": system_result["status"],
            "timings": system_result["timings"],
            "proof_scope": None if custody is None else custody["scope"],
            "proof_artifact_count": 0 if custody is None else len(custody["artifacts"]),
            "security_target_bits": security["conservative_end_to_end_target_bits"],
            "fresh_verification": security["fresh_verification"],
        },
    }


def _result_stage(evidence: dict[str, Any], scope: str) -> dict[str, Any] | None:
    projection = evidence["projection"]
    timings = projection["timings"]
    proof_scope = projection["proof_scope"]
    security = projection["security_target_bits"]
    fresh = projection["fresh_verification"]
    if scope == "execution" and timings["execution"] is not None:
        return _retained_stage(
            scope, "validated-result-execution-under-unpromoted-statement-contract",
            evidence, timing=timings["execution"], timing_authority="typed-result-measured",
        )
    if scope == "base_proofs" and proof_scope is not None:
        return _retained_stage(
            scope, "verified-proof-custody-is-not-a-complete-promoted-comparison",
            evidence, security_target_bits=security, fresh_verification=fresh,
            status="partial_verified_nonpromotable",
        )
    if scope == "aggregation" and proof_scope in ("parent", "final_root"):
        return _retained_stage(
            scope, "recursive-custody-under-unpromoted-statement-contract",
            evidence, security_target_bits=security, fresh_verification=fresh,
            status=("complete_nonpromotable" if proof_scope == "final_root"
                    else "partial_verified_nonpromotable"),
        )
    if scope == "fresh_verification" and proof_scope is not None:
        return _retained_stage(
            scope, "proof-verification-is-not-a-promoted-five-block-final-comparison",
            evidence, timing=timings["verification"],
            timing_authority=(None if timings["verification"] is None
                              else "typed-result-measured"),
            security_target_bits=security, fresh_verification=fresh,
            status=("complete_nonpromotable" if proof_scope == "final_root" and fresh is True
                    else "partial_verified_nonpromotable"),
        )
    if scope == "end_to_end" and projection["system_status"] == "complete":
        buckets = [timings[name] for name in (
            "execution", "witness_generation", "proving", "verification",
        )]
        _require(all(bucket is not None for bucket in buckets),
                 "complete benchmark result timing buckets differ")
        timing = {
            "wall_ns": timings["total_wall_ns"],
            "user_ns": sum(bucket["user_ns"] for bucket in buckets),
            "system_ns": sum(bucket["system_ns"] for bucket in buckets),
        }
        return _retained_stage(
            scope, "complete-system-result-under-unpromoted-five-block-contract",
            evidence, timing=timing,
            timing_authority="derived-exact-from-measured-exclusive-buckets",
            security_target_bits=security, fresh_verification=fresh,
            status="complete_nonpromotable",
        )
    return None


def _validate_result_evidence(
    evidence: Any, system: str, scope: str, manifest: dict[str, Any],
) -> dict[str, Any]:
    evidence = _exact(evidence, {"kind", "identity", "projection"},
                      "benchmark result evidence")
    _require(evidence["kind"] == BENCHMARK_RESULT_KIND,
             "benchmark result evidence kind differs")
    identity = _validate_identity(evidence["identity"], "benchmark result evidence")
    expected_evidence = _benchmark_result_evidence(Path(identity["path"]), system, manifest)
    _require(evidence == expected_evidence, "benchmark result evidence replay differs")
    expected = _result_stage(expected_evidence, scope)
    _require(expected is not None, "benchmark result does not evidence this scope")
    return expected


def _validate_stage(
    value: Any, fixture: dict[str, Any], system: str, scope: str,
    manifest_identity: dict[str, Any], manifest: dict[str, Any],
) -> None:
    value = _exact(value, {
        "scope", "status", "reason", "evidence", "timing", "timing_authority",
        "security_target_bits", "fresh_verification",
    }, f"{fixture['fixture_id']} {system} {scope}")
    _require(value["scope"] == scope, f"{fixture['fixture_id']} {system} scope differs")
    _timing(value["timing"], f"{fixture['fixture_id']} {system} {scope} timing")
    if value["status"] == "unavailable":
        expected = _unavailable(
            scope, UNAVAILABLE_REASONS[system].get(scope, "no-retained-evidence"),
        )
        _require(value == expected, f"{fixture['fixture_id']} {system} unavailable stage differs")
        return
    _require(value["evidence"] is not None, f"{fixture['fixture_id']} {system} evidence absent")
    kind = value["evidence"].get("kind") if type(value["evidence"]) is dict else None
    if kind == ZISK_EXECUTION_KIND:
        _require(system == "zisk" and scope == "execution"
                 and fixture["block"]["number"] == 24_628_607,
                 "ZisK execution evidence is attached to the wrong cell")
        expected = _validate_zisk_execution(value["evidence"], manifest_identity, manifest)
    elif kind == STWO_EXECUTION_KIND:
        _require(system == "stwo_zig" and scope == "execution",
                 "Stwo execution evidence is attached to the wrong cell")
        expected = _validate_stwo_execution(value["evidence"], fixture)
    elif kind == compact_replay.EVIDENCE_KIND:
        _require(system == "stwo_zig" and scope == "execution",
                 "compact replay evidence is attached to the wrong cell")
        expected = compact_replay.validate_stage(value["evidence"], fixture)
    elif kind == BENCHMARK_RESULT_KIND:
        _require(fixture["block"]["number"] == 24_628_607,
                 "benchmark result is attached to an unmaterialized fixture protocol")
        expected = _validate_result_evidence(value["evidence"], system, scope, manifest)
    elif kind == zisk_final.EVIDENCE_KIND:
        _require(system == "zisk", "ZisK final proof is attached to another system")
        expected = zisk_final.validate_stage(
            value["evidence"], fixture, manifest_identity, scope,
        )
    else:
        raise MatrixError(f"unsupported matrix evidence kind: {kind}")
    _require(value == expected, f"{fixture['fixture_id']} {system} stage projection differs")


def _leaf_capability(path: Path, fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        receipt = leaf_join.validate_receipt(path)
    except proof_protocol.ProofProtocolError as error:
        raise MatrixError(str(error)) from error
    source_request_path = Path(receipt["files"]["source_request"]["path"])
    _, source = _read_json(source_request_path, "leaf capability source request", canonical=True)
    source_input = {key: source["input"][key] for key in ("bytes", "sha256")}
    source_output = {key: source["expected_output"][key] for key in ("bytes", "sha256")}
    matches = []
    for fixture in fixtures:
        guest = fixture["semantic_io"]["guest_transports"]
        input_identity = guest["stwo_input"]
        output_identity = guest["stwo_output"]
        if input_identity is not None and output_identity is not None and source_input == {
            "bytes": input_identity["bytes"], "sha256": input_identity["sha256"],
        } and source_output == {
            "bytes": output_identity["bytes"], "sha256": output_identity["sha256"],
        }:
            matches.append(fixture["fixture_id"])
    _require(len(matches) <= 1, "leaf capability matches multiple corpus fixtures")
    fixture_id = matches[0] if matches else None
    return {
        "schema": CAPABILITY_SCHEMA,
        "kind": LEAF_CAPABILITY_KIND,
        "identity": _file_identity(path, "Poseidon leaf evidence join"),
        "corpus_fixture_id": fixture_id,
        "claim_boundary": (
            "one-corpus-leaf-proof-not-a-complete-block-proof" if fixture_id is not None
            else "non-corpus-leaf-proof-capability-only"
        ),
        "status": receipt["status"],
        "segment_index": receipt["bindings"]["segment_index"],
        "proof_sha256": receipt["bindings"]["proof_sha256"],
        "source_public_statement_sha256": receipt["bindings"][
            "source_public_statement_sha256"
        ],
        "recursive_statement_sha256": receipt["bindings"][
            "recursive_statement_sha256"
        ],
        "security_identity_sha256": receipt["bindings"]["security_identity_sha256"],
        "prove_timing": receipt["timing"]["prove"],
        "fresh_verify_timing": receipt["timing"]["verify"],
        "evidence_complete": receipt["evidence_complete"],
        "performance_claim_eligible": receipt["performance_claim_eligible"],
        "recursive_admissible": receipt["recursive_admissible"],
        "corpus_comparison_eligible": False,
    }


def _validate_capability(value: Any, fixtures: list[dict[str, Any]]) -> None:
    value = _exact(value, {
        "schema", "kind", "identity", "corpus_fixture_id", "claim_boundary", "status",
        "segment_index", "proof_sha256", "source_public_statement_sha256",
        "recursive_statement_sha256", "security_identity_sha256", "prove_timing",
        "fresh_verify_timing", "evidence_complete", "performance_claim_eligible",
        "recursive_admissible", "corpus_comparison_eligible",
    }, "matrix capability evidence")
    _require(value["schema"] == CAPABILITY_SCHEMA and value["kind"] == LEAF_CAPABILITY_KIND,
             "matrix capability schema differs")
    identity = _validate_identity(value["identity"], "matrix leaf capability")
    expected = _leaf_capability(Path(identity["path"]), fixtures)
    _require(value == expected, "matrix leaf capability replay differs")
    _require(value["corpus_comparison_eligible"] is False,
             "one leaf cannot become a corpus comparison")


def _derived_aggregate(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = [fixture for fixture in fixtures if fixture["comparison_ready"]]
    return {
        "fixture_count": len(fixtures),
        "eligible_fixture_count": len(eligible),
        "observed_end_to_end_average_wall_ns": None,
        "target_average_wall_ns": TARGET_AVERAGE_WALL_NS,
        "target_met": None,
        "comparison_ready": False,
        "promotion_checklist": matrix_contract.promotion_checklist(fixtures),
    }


def validate_matrix(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "contract", "corpus", "reference_manifest", "fixtures",
        "capability_evidence", "aggregate", "comparison_ready", "content_sha256",
    }, "benchmark matrix")
    _require(value["schema"] == MATRIX_SCHEMA, "benchmark matrix schema differs")
    _require(value["content_sha256"] == proof_protocol.content_sha256(value),
             "benchmark matrix content seal differs")
    _require(value["contract"] == CONTRACT, "benchmark matrix contract differs")
    corpus, manifest = _validate_source_authorities(value)
    fixtures = value["fixtures"]
    _require(type(fixtures) is list and len(fixtures) == len(corpus["fixtures"]),
             "benchmark matrix fixture count differs")
    manifest_identity = value["reference_manifest"]
    for index, (fixture, source_fixture) in enumerate(zip(fixtures, corpus["fixtures"])):
        fixture = _exact(fixture, {
            "fixture_id", "category", "block", "semantic_io", "systems",
            "equivalence", "comparison_ready",
        }, f"matrix.fixtures[{index}]")
        expected_base = _base_fixture(source_fixture, manifest_identity, manifest)
        for field in ("fixture_id", "category", "block", "semantic_io", "equivalence",
                      "comparison_ready"):
            _require(fixture[field] == expected_base[field],
                     f"matrix fixture {source_fixture['fixture_id']} {field} differs")
        systems = _exact(fixture["systems"], set(SYSTEMS),
                         f"matrix fixture {fixture['fixture_id']} systems")
        for system in SYSTEMS:
            system_value = _exact(systems[system], {
                "input_transport", "output_transport", "stages",
            }, f"matrix fixture {fixture['fixture_id']} {system}")
            expected_system = expected_base["systems"][system]
            _require(system_value["input_transport"] == expected_system["input_transport"]
                     and system_value["output_transport"] == expected_system["output_transport"],
                     f"matrix fixture {fixture['fixture_id']} {system} transport differs")
            _transport(system_value["input_transport"], "matrix system input transport")
            _transport(system_value["output_transport"], "matrix system output transport")
            stages = _exact(system_value["stages"], set(SCOPES),
                            f"matrix fixture {fixture['fixture_id']} {system} stages")
            for scope in SCOPES:
                _validate_stage(
                    stages[scope], source_fixture, system, scope,
                    manifest_identity, manifest,
                )
    capabilities = value["capability_evidence"]
    _require(type(capabilities) is list, "matrix capability evidence differs")
    identities = []
    for capability in capabilities:
        _validate_capability(capability, corpus["fixtures"])
        identities.append(capability["identity"]["sha256"])
    _require(identities == sorted(set(identities)),
             "matrix capability evidence order or identity differs")
    _require(value["aggregate"] == _derived_aggregate(fixtures),
             "benchmark matrix aggregate differs")
    _require(value["comparison_ready"] is False,
             "matrix v1 cannot promote before statement and final-proof closure")
    return value


def load_matrix(path: Path) -> dict[str, Any]:
    _, value = _read_json(path, "benchmark matrix", canonical=True)
    return validate_matrix(value)


def publish_matrix(path: Path, staging: Path, value: dict[str, Any]) -> None:
    validate_matrix(value)
    store.require_directory(path.parent, "matrix output parent")
    store.require_directory(staging, "matrix staging directory", create=True)
    store.publish_new_or_identical(
        path, proof_protocol.canonical_bytes(value), staging_directory=staging,
    )


def admit_leaf_capability(matrix: dict[str, Any], path: Path) -> dict[str, Any]:
    validate_matrix(matrix)
    result = copy.deepcopy(matrix)
    result.pop("content_sha256")
    capability = _leaf_capability(path, [
        source for source in _validate_source_authorities(matrix)[0]["fixtures"]
    ])
    by_sha = {
        item["identity"]["sha256"]: item for item in result["capability_evidence"]
    }
    existing = by_sha.get(capability["identity"]["sha256"])
    _require(existing is None or existing == capability,
             "matrix leaf capability identity collides")
    by_sha[capability["identity"]["sha256"]] = capability
    result["capability_evidence"] = [by_sha[key] for key in sorted(by_sha)]
    return proof_protocol.seal(result)


def admit_stwo_execution(
    matrix: dict[str, Any], fixture_id: str, bundle: Path,
) -> dict[str, Any]:
    validate_matrix(matrix)
    result = copy.deepcopy(matrix)
    result.pop("content_sha256")
    fixture = next((item for item in result["fixtures"]
                    if item["fixture_id"] == fixture_id), None)
    _require(fixture is not None, "matrix execution fixture is unknown")
    source_fixtures = _validate_source_authorities(matrix)[0]["fixtures"]
    source = next(item for item in source_fixtures if item["fixture_id"] == fixture_id)
    evidence, _ = _execution_projection(bundle.absolute())
    fixture["systems"]["stwo_zig"]["stages"]["execution"] = (
        _validate_stwo_execution(evidence, source)
    )
    result["aggregate"] = _derived_aggregate(result["fixtures"])
    return proof_protocol.seal(result)


def admit_benchmark_result(
    matrix: dict[str, Any], fixture_id: str, path: Path,
) -> dict[str, Any]:
    validate_matrix(matrix)
    result = copy.deepcopy(matrix)
    result.pop("content_sha256")
    fixture = next((item for item in result["fixtures"]
                    if item["fixture_id"] == fixture_id), None)
    _require(fixture is not None and fixture["block"]["number"] == 24_628_607,
             "benchmark result fixture protocol is unavailable")
    manifest = _validate_source_authorities(matrix)[1]
    changed = False
    for system in SYSTEMS:
        evidence = _benchmark_result_evidence(path, system, manifest)
        for scope in SCOPES:
            stage = _result_stage(evidence, scope)
            if stage is not None:
                fixture["systems"][system]["stages"][scope] = stage
                changed = True
    _require(changed, "benchmark result contains no retained stage evidence")
    result["aggregate"] = _derived_aggregate(result["fixtures"])
    return proof_protocol.seal(result)


def render_report(matrix: dict[str, Any]) -> str:
    validate_matrix(matrix)
    return matrix_contract.render_report(matrix)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    validate_corpus = subcommands.add_parser("validate-corpus")
    validate_corpus.add_argument("--corpus", type=Path, default=corpus_authority.DEFAULT_CORPUS)
    validate_corpus.add_argument("--reference-manifest", type=Path,
                                 default=comparison.DEFAULT_MANIFEST)
    materialize = subcommands.add_parser("materialize")
    materialize.add_argument("--corpus", type=Path, default=corpus_authority.DEFAULT_CORPUS)
    materialize.add_argument("--reference-manifest", type=Path,
                             default=comparison.DEFAULT_MANIFEST)
    for command in (materialize,):
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--staging-directory", type=Path, required=True)
    validate = subcommands.add_parser("validate")
    validate.add_argument("--matrix", type=Path, required=True)
    leaf = subcommands.add_parser("admit-leaf-capability")
    leaf.add_argument("--matrix", type=Path, required=True)
    leaf.add_argument("--leaf-join", type=Path, required=True)
    execution = subcommands.add_parser("admit-stwo-execution")
    execution.add_argument("--matrix", type=Path, required=True)
    execution.add_argument("--fixture-id", required=True)
    execution.add_argument("--bundle", type=Path, required=True)
    result = subcommands.add_parser("admit-benchmark-result")
    result.add_argument("--matrix", type=Path, required=True)
    result.add_argument("--fixture-id", required=True)
    result.add_argument("--result", type=Path, required=True)
    for command in (leaf, execution, result):
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--staging-directory", type=Path, required=True)
    report = subcommands.add_parser("render-report")
    report.add_argument("--matrix", type=Path, required=True)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--staging-directory", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-corpus":
            matrix = build_matrix(arguments.corpus, arguments.reference_manifest)
            validate_matrix(matrix)
            print(proof_protocol.canonical_bytes({
                "schema": MATRIX_SCHEMA,
                "status": "valid",
                "fixture_count": len(matrix["fixtures"]),
                "corpus_sha256": matrix["corpus"]["corpus_sha256"],
                "comparison_ready": False,
            }).decode("ascii"), end="")
            return 0
        if arguments.command == "materialize":
            value = build_matrix(arguments.corpus, arguments.reference_manifest)
            publish_matrix(arguments.output.absolute(), arguments.staging_directory.absolute(), value)
            return 0
        matrix = load_matrix(arguments.matrix.absolute())
        if arguments.command == "validate":
            return 0
        if arguments.command == "admit-leaf-capability":
            value = admit_leaf_capability(matrix, arguments.leaf_join.absolute())
            publish_matrix(arguments.output.absolute(), arguments.staging_directory.absolute(), value)
            return 0
        if arguments.command == "admit-stwo-execution":
            value = admit_stwo_execution(
                matrix, arguments.fixture_id, arguments.bundle.absolute(),
            )
            publish_matrix(arguments.output.absolute(), arguments.staging_directory.absolute(), value)
            return 0
        if arguments.command == "admit-benchmark-result":
            value = admit_benchmark_result(
                matrix, arguments.fixture_id, arguments.result.absolute(),
            )
            publish_matrix(arguments.output.absolute(), arguments.staging_directory.absolute(), value)
            return 0
        report = render_report(matrix).encode("utf-8")
        store.require_directory(arguments.output.absolute().parent, "report output parent")
        store.require_directory(arguments.staging_directory.absolute(),
                                "report staging directory", create=True)
        store.publish_new_or_identical(
            arguments.output.absolute(), report,
            staging_directory=arguments.staging_directory.absolute(),
        )
        return 0
    except (MatrixError, proof_protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
