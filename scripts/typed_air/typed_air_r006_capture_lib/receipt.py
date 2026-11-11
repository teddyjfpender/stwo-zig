"""Workload-conditioned R-006 independent-verifier receipt admission."""

from __future__ import annotations

from typing import Any

from .guest_verifier_receipt import validate_guest_verifier_receipt
from .verifier_receipt import validate_verifier_receipt
from .workload_profile import is_guest_workload, workload_for_attempt


def validate_receipt(
    raw: bytes,
    *,
    plan: dict[str, Any],
    attempt: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    workload = workload_for_attempt(plan, attempt)
    if is_guest_workload(workload):
        return validate_guest_verifier_receipt(raw, plan=plan, identity=identity)
    return validate_verifier_receipt(raw, plan=plan, identity=identity)
