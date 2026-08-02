"""Shared host-evidence contract for optional RISC-V timing reports.

The retired pre-Sail benchmark matrix used to own this small contract.  The
Stark-V corpus and crypto comparison tools still publish the same block, so the
contract stays without retaining the 2,600-line matrix controller.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from scripts.riscv_csp_benchmark_lib.host import power_conditions_admissible


HOST_ENVIRONMENT_SCHEMA = "riscv_benchmark_host_environment_v2"
HOST_ENVIRONMENT_FIELDS = {
    "schema",
    "platform",
    "hardware",
    "toolchain",
    "stark_v_commit",
    "power_conditions",
}
POWER_CONDITION_FIELDS = {
    "power_source",
    "low_power_mode",
    "admissible",
    "reasons",
}
STARK_V_COMMIT = "d478f783055aa0d73a93768a433a3c6c31c91d1c"


class HostContractError(ValueError):
    pass


def _exact_fields(
    value: object,
    fields: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HostContractError(f"{label}: must be an object")
    actual = set(value)
    if actual != fields:
        raise HostContractError(
            f"{label}: fields drifted; missing={sorted(fields - actual)} "
            f"unknown={sorted(actual - fields)}"
        )
    return value


def validate_host_environment(
    host_environment: object,
    label: str,
) -> Mapping[str, Any]:
    """Validate evidence and re-derive its power-admissibility verdict."""
    host = _exact_fields(host_environment, HOST_ENVIRONMENT_FIELDS, label)
    if host["schema"] != HOST_ENVIRONMENT_SCHEMA:
        raise HostContractError(f"{label} schema drifted")
    if host["stark_v_commit"] != STARK_V_COMMIT:
        raise HostContractError(f"{label} Stark-V identity drifted")
    power = _exact_fields(
        host["power_conditions"],
        POWER_CONDITION_FIELDS,
        f"{label}.power_conditions",
    )
    if not isinstance(power["admissible"], bool):
        raise HostContractError(
            f"{label}.power_conditions.admissible: must be a boolean"
        )
    reasons = power["reasons"]
    if not isinstance(reasons, list) or not all(
        isinstance(reason, str) and reason for reason in reasons
    ):
        raise HostContractError(
            f"{label}.power_conditions.reasons: must be nonempty strings"
        )
    expected_admissible, expected_reasons = power_conditions_admissible(power)
    if power["admissible"] is not expected_admissible or reasons != expected_reasons:
        raise HostContractError(
            f"{label}.power_conditions: recorded verdict does not follow from "
            "the recorded power evidence"
        )
    return host
