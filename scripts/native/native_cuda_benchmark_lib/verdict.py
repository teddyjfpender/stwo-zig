"""Coverage and promotion verdicts for Native CUDA measurements."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .activation import ActivationError, load_state
from .model import BenchmarkError, COVERAGE_MATRIX, Settings


def coverage() -> dict[str, Any]:
    classes: dict[str, dict[str, Any]] = {}
    for workload in COVERAGE_MATRIX:
        entry = classes.setdefault(
            workload.structural_class,
            {
                "enabled_workloads": [],
                "headline_excluded_workloads": [],
                "blockers": [],
            },
        )
        if workload.enabled:
            entry["enabled_workloads"].append(workload.workload_id)
            if not workload.headline_scored:
                entry["headline_excluded_workloads"].append(
                    workload.workload_id
                )
        else:
            entry["blockers"].append(
                {
                    "workload_id": workload.workload_id,
                    "reason": workload.unavailable_reason,
                }
            )
    missing = [
        class_name
        for class_name, entry in classes.items()
        if not entry["enabled_workloads"]
    ]
    try:
        activation, _ = load_state(Path(__file__).resolve().parents[2])
    except ActivationError as error:
        raise BenchmarkError(
            f"CUDA activation authority is invalid: {error}"
        ) from error
    structural_ready = not missing
    return {
        "classes": classes,
        "required_class_count": len(classes),
        "covered_class_count": len(classes) - len(missing),
        "missing_classes": missing,
        "structural_coverage_ready": structural_ready,
        "native_air_activation": activation,
        "activation_ready": (
            structural_ready and activation["activation_ready"]
        ),
    }


def headline_eligible(
    settings: Settings,
    coverage_result: dict[str, Any],
    portfolio: dict[str, Any],
    workloads: list[dict[str, Any]],
) -> bool:
    return (
        settings.profile_name == "judge"
        and all(workload.get("headline_scored", True) for workload in workloads)
        and portfolio["available"]
        and portfolio["passes_1_3x_target"]
        and coverage_result["activation_ready"]
        and all(workload["rust_oracle"]["accepted"] for workload in workloads)
        and all(
            workload["comparison"]["passes_regression_ceiling"]
            for workload in workloads
        )
        and all(
            workload["cold_comparison"] is not None
            and workload["cold_comparison"]["passes_regression_ceiling"]
            for workload in workloads
        )
    )
