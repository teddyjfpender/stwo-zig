"""Compatibility policy for Native benchmark Rust-oracle transitions."""

from __future__ import annotations

from typing import Any

from .common import DeltaError, IncompatibleReports


ORACLE_BINARY_TRANSITIONS = {
    (
        "4d223c37e85b96f61dccc684f2897c82d2d55f6c50b59616a69cc5cc70d2ccf8",
        "395c5549f383052e4e37ac29ae77923a5422f51cb310cfc7f9ef1281cd03819a",
    ): ("v4_to_v5", "fail_closed_outer_embedded_pcs_config_check_outside_timed_lanes"),
    (
        "4d223c37e85b96f61dccc684f2897c82d2d55f6c50b59616a69cc5cc70d2ccf8",
        "b8b8d824fa54db7091d77918f2f72c470b5fa372d65e9d5a9c91638536b57697",
    ): ("v4_to_v5", "fail_closed_pcs_schema_and_verifier_safety_checks_outside_timed_lanes"),
    (
        "b8b8d824fa54db7091d77918f2f72c470b5fa372d65e9d5a9c91638536b57697",
        "bca74321517d41e6c2128ab20567756ab498ef18cee3fba422a51eea74b92b2b",
    ): ("v5_to_v6", "enable_parallel_feature_in_pinned_rust_oracle_outside_timed_lanes"),
}


def oracle_binary_pair(
    baseline: dict[str, Any], current: dict[str, Any], index: int
) -> tuple[str, str]:
    for field in ("toolchain", "upstream_commit"):
        if baseline.get(field) != current.get(field):
            raise IncompatibleReports(
                f"native Rust oracle contract differs at row {index}: {field}"
            )
    result: list[str] = []
    for value, context in (
        (baseline.get("binary_sha256"), "baseline"),
        (current.get("binary_sha256"), "current"),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise DeltaError(
                f"{context}.rows[{index}].rust_oracle.binary_sha256 is invalid"
            )
        result.append(value)
    return result[0], result[1]


def classify_transition(
    pairs: set[tuple[str, str]],
    protocols: tuple[object, object],
    v4_protocol: str,
    v5_protocol: str,
    v6_protocol: str,
) -> dict[str, Any] | None:
    if len(pairs) != 1:
        raise IncompatibleReports("native Rust oracle binaries differ between rows")
    pair = next(iter(pairs))
    if pair[0] == pair[1]:
        return None
    transition = ORACLE_BINARY_TRANSITIONS.get(pair)
    if transition is None:
        raise IncompatibleReports("native Rust oracle contract differs: binary_sha256")
    boundary, reason = transition
    expected_protocols = {
        "v4_to_v5": (v4_protocol, v5_protocol),
        "v5_to_v6": (v5_protocol, v6_protocol),
    }[boundary]
    if protocols != expected_protocols:
        raise IncompatibleReports("native Rust oracle contract differs: binary_sha256")
    return {
        "baseline_sha256": pair[0],
        "current_sha256": pair[1],
        "reason": reason,
        "timed_lane_impact": "none",
        "proof_identity_required": True,
    }
