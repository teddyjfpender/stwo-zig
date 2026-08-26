"""Raw-cohort replay and report assembly for native CSP A/B evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from scripts.riscv_csp_ab_benchmark_lib import contract

from .host_gate import _now


def _partial_relative(entry: Mapping[str, Any]) -> Path:
    return Path("partials") / (
        f"{entry['ordinal']:03d}-r{entry['round'] + 1:02d}-"
        f"c{entry['case_ordinal']:02d}-{entry['target']}-"
        f"{entry['input_size']}-{entry['arm']}.json"
    )


def _receipt_relative(entry: Mapping[str, Any]) -> Path:
    return Path("receipts") / f"launch-{entry['ordinal']:03d}.json"


def _pair_gate_relative(entry: Mapping[str, Any]) -> Path:
    return Path("gates") / (
        f"r{entry['round'] + 1:02d}-c{entry['case_ordinal']:02d}-"
        f"{entry['target']}-{entry['input_size']}.json"
    )


def _gate_evidence(
    artifact: Path,
    relative: Path,
    *,
    require_admissible: bool,
) -> dict[str, Any]:
    if relative.is_absolute() or ".." in relative.parts:
        raise contract.ABError("quiet gate path escapes the evidence directory")
    gate, raw = contract.load_json(artifact / relative)
    contract.validate_seal(gate, f"quiet gate {relative}")
    if gate.get("schema") != "stwo_native_ab_bounded_quiet_gate_v1":
        raise contract.ABError(f"quiet gate schema drifted: {relative}")
    if not isinstance(gate.get("admissible"), bool):
        raise contract.ABError(f"quiet gate verdict is missing: {relative}")
    if require_admissible and gate["admissible"] is not True:
        raise contract.ABError(
            f"quiet gate did not recover: {relative}: "
            + "; ".join(gate.get("reasons") or ["unknown interference"])
        )
    return {
        "path": str(relative),
        "sha256": contract.sha256_bytes(raw),
        "bytes": len(raw),
        "seal_sha256": gate["seal_sha256"],
        "label": gate.get("label"),
        "admissible": gate["admissible"],
        "reasons": gate.get("reasons"),
        "attempt_count": len(gate.get("attempts") or []),
        "elapsed_seconds": gate.get("elapsed_seconds"),
        "enforce_load_threshold": gate.get("enforce_load_threshold"),
    }


def _case_for(entry: Mapping[str, Any], workload: Mapping[str, Any]) -> Mapping[str, Any]:
    cases = workload["cases"]
    case = cases[entry["case_ordinal"]]
    if case["target"] != entry["target"] or case["input_size"] != entry["input_size"]:
        raise contract.ABError("schedule entry does not identify its canonical workload")
    return case

def assemble_report(
    plan: Mapping[str, Any],
    artifact: Path,
    *,
    plan_evidence: Mapping[str, Any],
    snapshot_bundle: Mapping[str, Any],
    execution_preflight: Mapping[str, Any],
    post_build_gate: Mapping[str, Any],
    pair_gates: Sequence[Mapping[str, Any]],
    allow_nonnormative_power: bool = False,
) -> dict[str, Any]:
    contract.validate_plan(plan)
    if (
        plan.get("status") != "ready_ephemeral_current"
        and not (
            allow_nonnormative_power
            and plan.get("status") == "diagnostic_smoke_only_host_interference"
        )
    ):
        raise contract.ABError("full A/B assembly requires a publishable plan")
    if (
        execution_preflight.get("schema")
        != "stwo_native_ab_quiet_host_preflight_v1"
        or (
            execution_preflight.get("admissible") is not True
            and not allow_nonnormative_power
        )
    ):
        raise contract.ABError("execution quiet-host preflight was not admissible")
    post_path = Path(str(post_build_gate.get("path", "")))
    actual_post_gate = _gate_evidence(
        artifact, post_path, require_admissible=not allow_nonnormative_power
    )
    if actual_post_gate != post_build_gate:
        raise contract.ABError("post-build quiet-gate evidence drifted")
    expected_pair_count = plan["settings"]["rounds"] * plan["workload"]["case_count"]
    if len(pair_gates) != expected_pair_count:
        raise contract.ABError("paired quiet-gate cohort is incomplete")
    pair_gate_by_path: dict[str, Mapping[str, Any]] = {}
    for supplied in pair_gates:
        path_text = supplied.get("path")
        if not isinstance(path_text, str) or path_text in pair_gate_by_path:
            raise contract.ABError("paired quiet-gate path is invalid or duplicated")
        actual = _gate_evidence(
            artifact,
            Path(path_text),
            require_admissible=not allow_nonnormative_power,
        )
        if actual != supplied:
            raise contract.ABError(f"paired quiet-gate evidence drifted: {path_text}")
        pair_gate_by_path[path_text] = supplied
    records: dict[tuple[int, str], list[dict[str, Any]]] = {}
    captures: list[dict[str, Any]] = []
    executable_hashes: dict[str, set[tuple[str, str]]] = {
        name: set() for name in contract.ARM_NAMES
    }
    for entry in plan["schedule"]:
        relative = _partial_relative(entry)
        path = artifact / relative
        report, raw = contract.load_json(path)
        case = _case_for(entry, plan["workload"])
        normalized = contract.validate_partial_report(
            report,
            arm=plan["arms"][entry["arm"]],
            case=case,
            settings=plan["settings"],
            expected_host=plan["host"],
            require_publishable_power=not allow_nonnormative_power,
        )
        receipt_relative = _receipt_relative(entry)
        receipt, receipt_raw = contract.load_json(artifact / receipt_relative)
        contract.validate_seal(receipt, f"launch receipt {entry['ordinal']}")
        gate_evidence = receipt.get("quiet_gate")
        expected_gate = pair_gate_by_path.get(str(_pair_gate_relative(entry)))
        if (
            receipt.get("schema")
            != "stwo_riscv_csp_native_ab_launch_receipt_v1"
            or receipt.get("entry") != entry
            or receipt.get("report_path") != str(relative)
            or receipt.get("report_sha256") != contract.sha256_bytes(raw)
            or receipt.get("report_bytes") != len(raw)
            or not isinstance(gate_evidence, dict)
            or (
                gate_evidence.get("admissible") is not True
                and not allow_nonnormative_power
            )
            or gate_evidence != expected_gate
        ):
            raise contract.ABError(f"launch receipt {entry['ordinal']} drifted")
        records.setdefault((entry["case_ordinal"], entry["arm"]), []).append(normalized)
        executable_hashes[entry["arm"]].add(
            (
                normalized["prover_executable_sha256"],
                normalized["trace_executable_sha256"],
            )
        )
        captures.append(
            {
                **entry,
                "report_path": str(relative),
                "report_sha256": contract.sha256_bytes(raw),
                "report_bytes": len(raw),
                "launch_receipt": {
                    "path": str(receipt_relative),
                    "sha256": contract.sha256_bytes(receipt_raw),
                    "bytes": len(receipt_raw),
                    "seal_sha256": receipt["seal_sha256"],
                },
                "quiet_gate": gate_evidence,
            }
        )

    cases: list[dict[str, Any]] = []
    rounds = plan["settings"]["rounds"]
    for case in plan["workload"]["cases"]:
        grouped = {
            arm: records.get((case["ordinal"], arm), [])
            for arm in contract.ARM_NAMES
        }
        if any(len(grouped[arm]) != rounds for arm in contract.ARM_NAMES):
            raise contract.ABError("A/B capture cohort is incomplete")
        cases.append({"workload": case, **contract.summarize_case(grouped)})
    for arm, identities in executable_hashes.items():
        if len(identities) != 1:
            raise contract.ABError(f"{arm} cohort used multiple executable identities")

    return contract.attach_seal(
        {
            "schema": contract.REPORT_SCHEMA,
            "schema_version": contract.REPORT_VERSION,
            "generated_at": _now(),
            "status": (
                "paired_native_full_cohort_complete_nonnormative_power"
                if allow_nonnormative_power
                else "paired_native_full_cohort_complete"
            ),
            "plan": dict(plan_evidence),
            "source_snapshot_bundle": dict(snapshot_bundle),
            "arms": plan["arms"],
            "settings": plan["settings"],
            "host": plan["host"],
            "environment": plan["environment"],
            "publishable_preflight": {
                "planning": plan["publishable_preflight"],
                "execution": dict(execution_preflight),
            },
            "post_build_quiet_gate": dict(post_build_gate),
            "paired_case_quiet_gates": [dict(value) for value in pair_gates],
            "workload": plan["workload"],
            "schedule": plan["schedule"],
            "captures": captures,
            "cases": cases,
            "executable_identities": {
                arm: {
                    "prover_sha256": next(iter(values))[0],
                    "trace_sha256": next(iter(values))[1],
                }
                for arm, values in executable_hashes.items()
            },
            "historical_context": plan["historical_context"],
            "interpretation": {
                "aggregate_speedup_claim": False,
                "delta_sign": "positive percent delta means current is larger/slower",
                "scope": "same-host native leaf proving only; recursion forced off",
                "tails": "nearest-rank over retained verified end-to-end samples",
                "limitations": [
                    "No cross-workload aggregate is reported because no workload weighting is justified.",
                    "Peak RSS includes mandatory self-verification and is conservative for prove-only memory.",
                    "This diagnostic is not an EthProofs upload and is not rankable across different hosts.",
                    *(
                        [
                            "Operator accepted nonnormative power/quiet conditions; results are descriptive only."
                        ]
                        if allow_nonnormative_power
                        else []
                    ),
                ],
            },
            "power_claim_boundary": {
                "publishable_performance_claim": not allow_nonnormative_power,
                "operator_accepted_nonnormative_power": allow_nonnormative_power,
            },
        }
    )
