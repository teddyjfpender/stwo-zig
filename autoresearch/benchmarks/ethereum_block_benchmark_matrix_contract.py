"""Static contract and human rendering for the Ethereum 5x2 matrix."""

from __future__ import annotations

from typing import Any


CONTRACT_SCHEMA = "stwo.ethereum.apples-to-apples-matrix-contract.v1"
TARGET_AVERAGE_WALL_NS = 5_000_000_000
SCOPES = (
    "one_time_setup",
    "execution",
    "base_proofs",
    "aggregation",
    "fresh_verification",
    "end_to_end",
)
SYSTEMS = ("zisk", "stwo_zig")

CONTRACT = {
    "schema": CONTRACT_SCHEMA,
    "systems": list(SYSTEMS),
    "scopes": [
        {
            "name": "one_time_setup",
            "boundary": "tool-and-key-setup-excluded-from-end-to-end-but-disclosed",
        },
        {
            "name": "execution",
            "boundary": "admitted-guest-input-to-canonical-semantic-output",
        },
        {
            "name": "base_proofs",
            "boundary": "witness-ready-to-all-base-or-real-leaf-proofs-serialized",
        },
        {
            "name": "aggregation",
            "boundary": "verified-base-proofs-to-one-serialized-final-proof",
        },
        {
            "name": "fresh_verification",
            "boundary": "retained-final-proof-to-fresh-independent-verdict",
        },
        {
            "name": "end_to_end",
            "boundary": "admitted-guest-input-to-fresh-final-proof-verdict",
        },
    ],
    "semantic_equivalence": {
        "chain_and_block": "exact-chain-id-number-hash-and-parent-state",
        "guest_semantics": "same-versioned-ethereum-state-transition",
        "semantic_input": "independent-codec-decode-to-one-canonical-input-projection",
        "semantic_output": "independent-normalization-to-one-canonical-output-projection",
        "codec_policy": "codec-specific-bytes-are-not-semantic-equivalence",
    },
    "measurement_policy": {
        "authority": "typed-retained-receipts-only",
        "timing_unit": "nanoseconds",
        "timing_fields": ["wall_ns", "user_ns", "system_ns"],
        "synthetic_or_log_inferred_timing": "forbidden",
        "one_time_setup_in_end_to_end": False,
        "exclusive_stage_reconciliation": True,
    },
    "diagnostic_models": [
        {
            "schema": "stwo.ethereum.block-benchmark-diagnostic-model.v1",
            "status": "diagnostic_nonpromotable",
            "workload": "ordinary-rv32-minimal-trace-replay",
            "worker_count": 16,
            "median_ordinary_cycles_per_second": 318_960_000,
            "projection": {
                "reference_execution_cycles": 880_760_229,
                "rounded_replay_only_seconds": "2.76",
                "measured_end_to_end": False,
            },
            "gate_run_ids": [
                "1788158796726792000-14319",
                "1788158819621198000-14377",
                "1788158831860465000-14432",
            ],
            "metric_custody": "rounded-terminal-summary-not-typed-result",
            "missing_from_projection": [
                "sequential-capture",
                "ethereum-external-precompile-mix",
                "witness-generation",
                "proof-generation",
                "aggregation",
                "fresh-verification",
            ],
            "matrix_timing_admissible": False,
            "headline_eligible": False,
        },
    ],
    "proof_policy": {
        "base_proof_only_is_end_to_end": False,
        "inner_verification_is_fresh_final_verification": False,
        "required_final_scope": "one-final-proof-covering-the-entire-block",
        "required_verification": "fresh-independent-final-proof-verifier",
        "security_comparison": "same-or-higher-conservative-end-to-end-target",
    },
    "hardware_policy": {
        "machine_model": "MacBookPro Mac17,7",
        "cpu": "Apple M5 Max 18-core (12P+6E)",
        "gpu": "Apple M5 Max 40-core Metal 4",
        "memory_bytes": 68_719_476_736,
        "operating_system": "macOS 26.6.2",
        "zig": "0.15.2",
        "same_power_source": True,
        "same_thermal_state": True,
        "headline_power_requirement": "AC Power and not discharging",
        "thermal_performance_warnings_allowed": False,
        "current_battery_diagnostics_promotable": False,
    },
    "aggregation_policy": {
        "fixture_count": 5,
        "statistic": "arithmetic-mean-of-five-complete-end-to-end-wall-times",
        "partial_corpus_average": "forbidden",
        "target_average_wall_ns": TARGET_AVERAGE_WALL_NS,
        "target_is_goal_not_measurement": True,
    },
    "promotion_requires": {
        "all_five_fixtures": True,
        "both_systems": True,
        "matched_guest_statement": True,
        "same_hardware_power_thermal_envelope": True,
        "matched_security": True,
        "all_scopes_complete": True,
        "fresh_final_verification": True,
    },
}

UNAVAILABLE_REASONS = {
    "zisk": {
        "one_time_setup": "no-canonical-one-time-setup-receipt",
        "base_proofs": "retained-inner-proof-log-is-not-a-canonical-base-proof-receipt",
        "aggregation": "no-retained-final-aggregation-proof",
        "fresh_verification": "inner-proof-checks-are-not-fresh-final-proof-verification",
        "end_to_end": "no-retained-final-proof",
    },
    "stwo_zig": {
        "one_time_setup": "no-canonical-one-time-setup-receipt",
        "execution": "no-admitted-corpus-execution-receipt",
        "base_proofs": "no-complete-corpus-real-leaf-proof-set",
        "aggregation": "verifier-minted-recursive-descriptor-plan-unavailable",
        "fresh_verification": "no-freshly-verified-corpus-final-root",
        "end_to_end": "no-retained-corpus-final-proof",
    },
}


def promotion_checklist(fixtures: list[dict[str, Any]]) -> dict[str, bool]:
    systems = [
        fixture["systems"][system]
        for fixture in fixtures
        for system in SYSTEMS
    ]

    def scope_complete(scope: str) -> bool:
        return bool(systems) and all(
            system["stages"][scope]["status"] == "complete"
            for system in systems
        )

    equivalence = [fixture["equivalence"] for fixture in fixtures]
    return {
        "all_five_fixtures_present": len(fixtures) == 5,
        "both_systems_present": bool(fixtures) and all(
            set(fixture["systems"]) == set(SYSTEMS) for fixture in fixtures
        ),
        "guest_semantics_matched": bool(equivalence) and all(
            item["guest_semantics_matched"] for item in equivalence
        ),
        "semantic_input_matched": bool(equivalence) and all(
            item["semantic_input_matched"] for item in equivalence
        ),
        "semantic_output_matched": bool(equivalence) and all(
            item["semantic_output_matched"] for item in equivalence
        ),
        "security_matched": bool(equivalence) and all(
            item["security_matched"] for item in equivalence
        ),
        "hardware_power_thermal_matched": bool(equivalence) and all(
            item["hardware_power_thermal_matched"] for item in equivalence
        ),
        "execution_scope_complete": scope_complete("execution"),
        "base_proof_scope_complete": scope_complete("base_proofs"),
        "aggregation_scope_complete": scope_complete("aggregation"),
        "fresh_final_verification_complete": (
            scope_complete("fresh_verification") and all(
                system["stages"]["fresh_verification"]["fresh_verification"]
                is True
                for system in systems
            )
        ),
        "end_to_end_scope_complete": scope_complete("end_to_end"),
    }


def render_report(matrix: dict[str, Any]) -> str:
    rows = []
    replay_rows = []
    zisk_final_rows = []
    for fixture in matrix["fixtures"]:
        for system in SYSTEMS:
            for scope in SCOPES:
                stage = fixture["systems"][system]["stages"][scope]
                wall = "null" if stage["timing"] is None else str(stage["timing"]["wall_ns"])
                rows.append(
                    f"| {fixture['fixture_id']} | {system} | {scope} | "
                    f"{stage['status']} | {wall} | {stage['reason']} |"
                )
            execution = fixture["systems"][system]["stages"]["execution"]
            evidence = execution["evidence"]
            if (type(evidence) is dict and evidence.get("kind") ==
                    "stwo-compact-ethereum-capture-replay-diagnostic-v1"):
                projection = evidence["projection"]
                replay = projection["replay_timing"]
                capture = projection["capture_stage_timings"]
                replay_rows.append(
                    f"| {fixture['fixture_id']} | "
                    f"{projection['requested_workers']}/"
                    f"{projection['admitted_workers']} | "
                    f"{capture['pre_manifest_materialization_wall_ns']} | "
                    f"{replay['wall_ns']} | {replay['user_ns']} | "
                    f"{replay['system_ns']} | {projection['total_cycles']} | "
                    f"{projection['total_keccak_calls']}/"
                    f"{projection['total_recovery_calls']} |"
                )
        final = fixture["systems"]["zisk"]["stages"]["aggregation"]
        evidence = final["evidence"]
        if (type(evidence) is dict and evidence.get("kind") ==
                "zisk-vadcop-final-proof-evidence-v1"):
            projection = evidence["projection"]
            zisk_final_rows.append(
                f"| {fixture['fixture_id']} | {projection['proof']['bytes']} | "
                f"`{projection['proof']['sha256']}` | "
                f"`{str(projection['fresh_process_verification']).lower()}` | "
                f"{projection['timing_classification']} |"
            )
    return "\n".join([
        "# Ethereum block 5x2 benchmark matrix",
        "",
        f"- Matrix schema: `{matrix['schema']}`",
        f"- Corpus SHA-256: `{matrix['corpus']['corpus_sha256']}`",
        f"- Target five-block mean E2E wall: `{TARGET_AVERAGE_WALL_NS}` ns (goal only)",
        "- Comparison ready: `false`",
        "- Timing promotion requires an admitted AC/no-interference host envelope.",
        "- Missing values are rendered as `null`; no timing is inferred from logs.",
        "",
        "| Fixture | System | Scope | Status | Wall ns | Blocker / boundary |",
        "|---|---|---|---|---:|---|",
        *rows,
        "",
        "## Retained compact replay diagnostics",
        "",
        "Capture is the receipt's pre-manifest materialization scope; replay is "
        "the single-process parallel-replay call's SELF rusage scope. Neither is "
        "a comparable execution-stage or proof timing.",
        "",
        "| Fixture | Requested/admitted workers | Capture wall ns | Replay wall ns | "
        "Replay user ns | Replay system ns | Cycles | Keccak/recovery calls |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
        *(replay_rows or ["| None | - | - | - | - | - | - | - |"]),
        "",
        "## Retained ZisK final-proof correctness evidence",
        "",
        "Operational rusage remains in the sealed receipt, but no matrix timing "
        "is populated when exclusive stage buckets or an interference-free host "
        "observation are absent.",
        "",
        "| Fixture | Proof bytes | Proof SHA-256 | Fresh verify | Timing class |",
        "|---|---:|---|---|---|",
        *(zisk_final_rows or ["| None | - | - | - | - |"]),
        "",
        "## Capability evidence",
        "",
        *(
            [
                f"- `{item['identity']['sha256']}`: {item['claim_boundary']} "
                f"(corpus fixture: `{item['corpus_fixture_id']}`)"
                for item in matrix["capability_evidence"]
            ] or ["- None admitted."]
        ),
        "",
        "## Diagnostic model (not a benchmark result)",
        "",
        "- Worker-arena ordinary replay median at 16 workers: "
        "`318960000` cycles/s.",
        "- Applying that rounded rate to `880760229` ordinary cycles gives a "
        "replay-only projection of about `2.76` s.",
        "- This excludes sequential capture, the Ethereum external-precompile mix, "
        "witness/proof generation, aggregation, and fresh verification. It cannot "
        "populate any matrix timing cell.",
        "",
        "## Apples-to-apples promotion checklist",
        "",
        "| Requirement | Satisfied |",
        "|---|---|",
        *[
            f"| {name} | `{str(satisfied).lower()}` |"
            for name, satisfied in matrix["aggregate"]["promotion_checklist"].items()
        ],
        "",
        "## Promotion boundary",
        "",
        "A headline comparison requires matched guest semantics and semantic I/O, "
        "the same admitted hardware/power/thermal and security envelope, every scope "
        "complete for both systems on all five fixtures, and fresh verification of "
        "one final proof per fixture. Inner proofs and isolated leaves are not E2E.",
        "",
    ])
