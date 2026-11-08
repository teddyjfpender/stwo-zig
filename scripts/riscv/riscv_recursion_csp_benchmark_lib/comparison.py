"""Diagnostic native/recursive CSP comparison construction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import EvidenceError, seal_document
from .contract import (
    AGGREGATES,
    COMPARISON_CLASSIFICATION,
    COMPARISON_SCHEMA,
    PHASES,
    SCHEMA_VERSION,
    not_applicable_metric,
    validate_recursive_report,
)


def _empty_recursive_lane(native_sample: dict[str, Any]) -> dict[str, Any]:
    reason = (
        "no complete recursive producer report was supplied, and the audited lanes "
        "do not establish an end-to-end recursive proof path"
    )
    phases = {
        phase: {
            "duration_ns": not_applicable_metric("ns", "recursive source boundary", reason),
            "poseidon2_permutations": not_applicable_metric(
                "permutations", "recursive source boundary", reason
            ),
        }
        for phase in PHASES
    }
    aggregates: dict[str, Any] = {}
    for name in AGGREGATES:
        if name.endswith("_ns"):
            unit = "ns"
        elif name.endswith("_bytes"):
            unit = "bytes"
        else:
            unit = "permutations"
        aggregates[name] = not_applicable_metric(unit, "recursive source boundary", reason)
    return {
        "workload_id": native_sample["workload_id"],
        "workload": native_sample["workload"],
        "status": "not_measured_missing_end_to_end_producer",
        "artifact": None,
        "attempts": [],
        "phases": phases,
        "aggregates": aggregates,
    }


def _comparison_metric(native: dict[str, Any], recursive: dict[str, Any]) -> dict[str, Any]:
    if native["unit"] != recursive["unit"]:
        raise EvidenceError("comparison metric unit mismatch")
    result = {
        "status": "unavailable",
        "unit": native["unit"],
        "native_value": native["value"] if native["status"] == "available" else None,
        "recursive_value": recursive["value"] if recursive["status"] == "available" else None,
        "recursive_minus_native": None,
        "recursive_over_native_ppm": None,
        "lower_is_better": True,
        "interpretation": "engineering_diagnostic_only",
        "reason": None,
    }
    if native["status"] == "available" and recursive["status"] == "available":
        native_value = native["value"]
        recursive_value = recursive["value"]
        if native_value == 0:
            result["reason"] = "native denominator is zero"
            return result
        result.update(
            {
                "status": "available",
                "recursive_minus_native": recursive_value - native_value,
                "recursive_over_native_ppm": (
                    recursive_value * 1_000_000 + native_value // 2
                )
                // native_value,
                "reason": None,
            }
        )
        return result
    reasons = []
    if native["status"] != "available":
        reasons.append(f"native metric is {native['status']}: {native['reason']}")
    if recursive["status"] != "available":
        reasons.append(f"recursive metric is {recursive['status']}: {recursive['reason']}")
    result["reason"] = "; ".join(reasons)
    return result


def build_comparison(
    plan: dict[str, Any],
    *,
    recursive_report: dict[str, Any] | None,
    repo_root: Path,
    active_outer_probe: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from .pipeline import validate_plan

    validate_plan(plan, repo_root=repo_root)
    if active_outer_probe is not None:
        from .active_probe import validate_active_outer_probe

        validate_active_outer_probe(active_outer_probe, plan=plan)
    recursive_by_id: dict[str, dict[str, Any]] = {}
    if recursive_report is not None:
        validate_recursive_report(recursive_report, plan=plan)
        recursive_by_id = {
            sample["workload_id"]: sample for sample in recursive_report["samples"]
        }
    rows = []
    for native in plan["native_samples"]:
        recursive = recursive_by_id.get(native["workload_id"])
        if recursive is None:
            recursive = _empty_recursive_lane(native)
        phase_comparisons = {}
        for phase in PHASES:
            phase_comparisons[phase] = {
                "duration_ns": _comparison_metric(
                    native["phases"][phase]["duration_ns"],
                    recursive["phases"][phase]["duration_ns"],
                ),
                "poseidon2_permutations": _comparison_metric(
                    native["phases"][phase]["poseidon2_permutations"],
                    recursive["phases"][phase]["poseidon2_permutations"],
                ),
            }
        aggregate_comparisons = {
            name: _comparison_metric(native["aggregates"][name], recursive["aggregates"][name])
            for name in AGGREGATES
        }
        rows.append(
            {
                "workload_id": native["workload_id"],
                "workload": native["workload"],
                "legacy_native": native,
                "typed_recursive": recursive,
                "phase_comparisons": phase_comparisons,
                "aggregate_comparisons": aggregate_comparisons,
            }
        )
    has_recursive = recursive_report is not None
    comparable_peak_rss = has_recursive and all(
        sample["aggregates"]["peak_rss_bytes"]["status"] == "available"
        for sample in plan["native_samples"]
    )
    same_compiler_version = has_recursive and (
        recursive_report["producer"]["compiler_version"]
        == plan["native_source"]["reproducibility"]["compiler_version"]
    )
    unsigned = {
        "schema": COMPARISON_SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "classification": COMPARISON_CLASSIFICATION,
        "plan_digest": plan["canonical_digest"],
        "cohort_id": plan["cohort_id"],
        "native_source": plan["native_source"],
        "recursive_report_digest": (
            recursive_report["canonical_digest"] if recursive_report is not None else None
        ),
        "recursive_evidence_present": has_recursive,
        "active_outer_probe": (
            {
                "canonical_digest": active_outer_probe["canonical_digest"],
                "status": active_outer_probe["status"],
                "comparison_eligible": False,
                "summary": active_outer_probe["summary"],
                "limitations": active_outer_probe["limitations"],
            }
            if active_outer_probe is not None
            else None
        ),
        "comparability": {
            "exact_workload_set": has_recursive,
            "same_host_identity": has_recursive,
            "same_security_profile": has_recursive,
            "same_backend": has_recursive,
            "same_sampling_schedule": has_recursive,
            "same_compiler_version": same_compiler_version,
            "comparable_proof_payload_scope": has_recursive,
            "comparable_peak_rss_scope": comparable_peak_rss,
            "complete_recursive_proof_pipeline": has_recursive,
            "active_outer_probe_is_csp_evidence": False,
            "publication_comparison_authority": False,
        },
        "rows": rows,
        "limitations": [
            "Ratios are raw same-cohort engineering diagnostics, never publication speedup claims.",
            "Publication authority is false even when a recursive report is complete.",
            "Native Poseidon2 counts remain unavailable; no count comparison is inferred.",
            (
                "Native raw end-to-end samples are retained, but its historical report "
                "does not expose raw per-phase samples; phase comparisons therefore use "
                "producer means on both lanes."
            ),
            (
                "Proof-size comparisons cover canonical proof payload bytes only and "
                "exclude JSON or other transport envelopes."
            ),
            (
                "Peak-RSS comparisons are emitted only for self-process lifetime peaks "
                "covering warmups, measured samples, and mandatory verification."
            ),
            (
                "An attached active-outer probe is a fixed-guest readiness observation; "
                "its timers, in-memory size estimate, and unavailable full peak RSS are "
                "never substituted for CSP workload evidence."
                if active_outer_probe is not None
                else "No active-outer readiness probe was attached."
            ),
            (
                "No complete recursive report was supplied; the audited source lanes "
                "do not establish an end-to-end recursive proof path."
                if not has_recursive
                else (
                    "The recursive producer self-reports internal timers and counters; "
                    "independent artifact replay remains an integration responsibility."
                )
            ),
        ],
    }
    return seal_document(unsigned)
