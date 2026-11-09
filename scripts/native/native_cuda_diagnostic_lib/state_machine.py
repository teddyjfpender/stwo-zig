"""State-machine artifact validation for Native CUDA evidence."""

from __future__ import annotations

from typing import Any

from .model import DiagnosticError, StateMachineShape


def validate_artifact_statement(
    value: Any,
    shape: StateMachineShape,
) -> None:
    if not isinstance(value, dict):
        raise DiagnosticError(
            "CUDA state-machine artifact statement must be an object"
        )
    expected_keys = {"public_input", "stmt0", "stmt1"}
    if set(value) != expected_keys:
        raise DiagnosticError(
            "CUDA state-machine artifact statement has wrong fields"
        )

    expected = shape.artifact_statement()
    if value["public_input"] != expected["public_input"]:
        raise DiagnosticError(
            "CUDA state-machine public input does not match request"
        )
    if value["stmt0"] != expected["stmt0"]:
        raise DiagnosticError(
            "CUDA state-machine row geometry does not match request"
        )

    claims = value["stmt1"]
    expected_claims = {"x_axis_claimed_sum", "y_axis_claimed_sum"}
    if not isinstance(claims, dict) or set(claims) != expected_claims:
        raise DiagnosticError(
            "CUDA state-machine interaction claims have wrong fields"
        )
    for axis in sorted(expected_claims):
        coordinates = claims[axis]
        if (
            not isinstance(coordinates, list)
            or len(coordinates) != 4
            or any(
                isinstance(coordinate, bool)
                or not isinstance(coordinate, int)
                or not 0 <= coordinate < (1 << 31) - 1
                for coordinate in coordinates
            )
        ):
            raise DiagnosticError(
                f"CUDA state-machine {axis} is not one canonical QM31"
            )
