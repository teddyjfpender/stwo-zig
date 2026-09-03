"""Closed validation for a sealed Ethereum block proof plan."""

from __future__ import annotations

from typing import Any

from scripts import ethereum_block_proof_plan_authority as authority
from scripts import ethereum_block_proof_profile_plan as profile_plan


def validate(value: Any) -> dict[str, Any]:
    # Lazy import keeps the protocol's stable `validate_plan` facade cycle-free.
    from scripts import ethereum_block_proof_protocol as protocol

    value = protocol.exact(value, {
        "schema", "session_id", "benchmark_statement_sha256",
        "proved_root_statement_sha256", "statement_binding", "arity", "levels",
        "node_counts", "real_segment_count", "slot_capacity", "padded_leaf_count",
        "empty_leaf_count", "topology_sha256", "job_sha256",
        "profile_policy_template",
        "segments", "expected_statements", "prover",
        "verifier", "leaf_stream_request", "security_parameters", "parent_execution",
        "result_template", "content_sha256",
    }, "proof plan")
    protocol.require(value["schema"] == protocol.PLAN_SCHEMA,
                     "proof plan schema differs")
    for field in ("session_id", "benchmark_statement_sha256",
                  "proved_root_statement_sha256"):
        protocol._sha(value[field], f"proof plan {field}")
    try:
        binding = protocol.benchmark.validate_statement_binding(
            value["statement_binding"], value["benchmark_statement_sha256"],
            "proof plan statement binding",
        )
    except protocol.benchmark.BenchmarkProtocolError as error:
        raise protocol.ProofProtocolError(str(error)) from error
    protocol.require(binding["proved_root_statement_sha256"]
                     == value["proved_root_statement_sha256"],
                     "proof plan proved-root statement binding differs")
    arity = protocol._positive(value["arity"], "proof plan arity")
    protocol.require(arity == 2, "proof plan arity must be binary")
    segments = value["segments"]
    protocol.require(type(segments) is list and len(segments) >= 2
                     and value["real_segment_count"] == len(segments),
                     "proof plan real segment count differs")
    protocol.require(len(segments) % 2 == 0,
                     "proof plan would require an unsupported mixed h1 profile")
    for index, segment in enumerate(segments):
        segment = protocol.exact(segment, {
            "segment_index", "source", "source_public_statement_sha256",
            "recursive_statement_sha256",
        }, f"proof plan segment {index}")
        protocol.require(segment["segment_index"] == index,
                         "proof plan segment order differs")
        protocol._identity(segment["source"], f"proof plan segment {index} source",
                           path=True)
        for field in ("source_public_statement_sha256", "recursive_statement_sha256"):
            protocol._sha(segment[field], f"proof plan segment {index}.{field}")
    try:
        counts = authority.node_counts(len(segments), arity)
    except authority.PlanAuthorityError as error:
        raise protocol.ProofProtocolError(str(error)) from error
    protocol.require(value["node_counts"] == counts
                     and value["slot_capacity"] == counts[0]
                     and value["padded_leaf_count"] == counts[0]
                     and value["empty_leaf_count"] == counts[0] - len(segments),
                     "proof plan node counts differ")
    protocol.require(value["topology_sha256"] == protocol.benchmark.topology_sha256(
        arity, len(counts) - 1, counts, len(segments),
    ), "proof plan topology digest differs")
    protocol._sha(value["job_sha256"], "proof plan job_sha256")
    profile_plan.validate_binding(value["profile_policy_template"])
    protocol.require(value["levels"] == len(counts) - 1,
                     "proof plan level count differs")
    statements = value["expected_statements"]
    protocol.require(type(statements) is list, "proof plan statements differ")
    expected_keys = [(level, index) for level, count in enumerate(counts)
                     for index in range(count)]
    actual_keys = []
    for position, statement in enumerate(statements):
        statement = protocol.exact(statement, {
            "level", "node_index", "recursive_statement_sha256",
        }, f"proof plan statement {position}")
        actual_keys.append((statement["level"], statement["node_index"]))
        protocol._sha(statement["recursive_statement_sha256"],
                      f"proof plan statement {position} digest")
    protocol.require(actual_keys == expected_keys,
                     "proof plan statement topology differs")
    for index, segment in enumerate(segments):
        protocol.require(segment["recursive_statement_sha256"]
                         == statements[index]["recursive_statement_sha256"],
                         "proof plan leaf recursive statement differs")
    protocol.require(statements[-1]["recursive_statement_sha256"]
                     == value["proved_root_statement_sha256"],
                     "proof plan final statement differs from proved-root statement")
    protocol._identity(value["prover"], "proof plan prover")
    protocol._identity(value["verifier"], "proof plan verifier")
    protocol._typed_source_identity(value["leaf_stream_request"],
                                    "proof plan leaf stream request")
    protocol.require(value["leaf_stream_request"]["schema"]
                     == protocol.LEAF_STREAM_SOURCE_SCHEMA,
                     "proof plan leaf stream source schema differs")
    protocol.require(binding["source_request_sha256"]
                     == value["leaf_stream_request"]["sha256"],
                     "proof plan source request binding differs")
    try:
        authority.require_production_security(
            value["security_parameters"], "proof plan security",
        )
        authority.validate_parent_execution(value["parent_execution"],
                                            "proof plan parent execution")
    except authority.PlanAuthorityError as error:
        raise protocol.ProofProtocolError(str(error)) from error
    template = value["result_template"]
    protocol.require(type(template) is dict, "proof plan result template differs")
    try:
        protocol.benchmark.validate_result(template, {
            "statement_sha256": value["benchmark_statement_sha256"],
            "matched_guest_statement_reproduced": binding[
                "matched_guest_statement_reproduced"
            ],
            "promotion_ready": False,
        })
    except protocol.benchmark.BenchmarkProtocolError as error:
        raise protocol.ProofProtocolError(str(error)) from error
    protocol.require(all(system["status"] == "incomplete"
                         and system["proof_custody"] is None
                         for system in template["systems"].values()),
                     "proof plan result template contains preexisting proof claims")
    protocol.require(value["content_sha256"] == protocol.content_sha256(value),
                     "proof plan digest differs")
    return value
