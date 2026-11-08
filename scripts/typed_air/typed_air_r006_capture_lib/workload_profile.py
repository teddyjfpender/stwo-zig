"""Fail-closed execution-profile routing for frozen R-006 workloads."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import (
    GENERATED_WORKLOADS,
    GENERATED_WORKLOAD_PARAMETERS,
    CaptureError,
)


BASE_TASK_PROFILE_EXAMPLE = "sail_rv32im_zkvm_v1"
GUEST_TASK_PROFILE_EXAMPLE = "rv32im-zkvm-poseidon2-v1"
GUEST_PROFILE_VERSION = 1
GUEST_PROFILE_MANIFEST_SHA256 = (
    "265df524ca93ba5f240aec9e5ce2f9f616c302850410ee812c220aa3e59fb891"
)
GUEST_ARTIFACT_KIND = "stwo_riscv_guest_poseidon2_proof"
GUEST_ARTIFACT_MAGIC = b"STWGPF01"
GUEST_ARTIFACT_FORMAT_VERSION = 1
GUEST_ARTIFACT_HEADER_BYTES = 80
GUEST_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
GUEST_EXTENSION_BYTES = 278
GUEST_IDENTITY_BYTES = 152


def workload_for_attempt(
    plan: dict[str, Any], attempt: dict[str, Any]
) -> dict[str, Any]:
    workload_id = attempt.get("workload_id")
    for workload in plan.get("workloads", ()):
        if workload.get("id") == workload_id:
            return workload
    raise CaptureError(f"attempt names an unplanned workload: {workload_id}")


def is_guest_workload(workload: dict[str, Any]) -> bool:
    workload_id = workload.get("id")
    expected = GENERATED_WORKLOADS.get(workload_id)
    generator = workload.get("generator")
    if expected is None:
        if generator is not None:
            raise CaptureError("fixed workload unexpectedly selects an execution profile")
        return False
    if generator != expected:
        raise CaptureError("generated workload execution profile changed")
    parameters = workload.get("parameters")
    if parameters != GENERATED_WORKLOAD_PARAMETERS[workload_id]:
        raise CaptureError("generated workload parameters changed")
    if type(workload.get("input")) is not dict:
        raise CaptureError("generated workload lacks its frozen input identity")
    return True


def task_profile_example(workload: dict[str, Any]) -> str:
    return GUEST_TASK_PROFILE_EXAMPLE if is_guest_workload(workload) else BASE_TASK_PROFILE_EXAMPLE


def validate_guest_artifact_header(path: Path, artifact_bytes: int) -> None:
    """Authenticate the fixed STWGPF01 frame before trusting its receipt."""

    try:
        with path.open("rb") as source:
            header = source.read(GUEST_ARTIFACT_HEADER_BYTES)
    except OSError as error:
        raise CaptureError("cannot read retained guest proof artifact") from error
    if not GUEST_ARTIFACT_HEADER_BYTES < artifact_bytes <= GUEST_MAX_ARTIFACT_BYTES:
        raise CaptureError("guest proof artifact length is outside its fixed bound")
    if len(header) != GUEST_ARTIFACT_HEADER_BYTES:
        raise CaptureError("guest proof artifact header is truncated")
    if header[:8] != GUEST_ARTIFACT_MAGIC:
        raise CaptureError("guest proof artifact magic changed")
    if int.from_bytes(header[8:10], "little") != GUEST_ARTIFACT_FORMAT_VERSION:
        raise CaptureError("guest proof artifact format version changed")
    if int.from_bytes(header[10:12], "little") != GUEST_ARTIFACT_HEADER_BYTES:
        raise CaptureError("guest proof artifact header length changed")
    if int.from_bytes(header[12:16], "little") != 0:
        raise CaptureError("guest proof artifact flags are unsupported")
    if int.from_bytes(header[16:24], "little") != artifact_bytes:
        raise CaptureError("guest proof artifact declared length disagrees")
    if int.from_bytes(header[24:26], "little") != 1:
        raise CaptureError("guest proof artifact encoding changed")
    if int.from_bytes(header[26:28], "little") != 1:
        raise CaptureError("guest proof artifact hasher changed")
    section_lengths = tuple(
        int.from_bytes(header[offset : offset + 4], "little")
        for offset in range(60, 80, 4)
    )
    statement, extension, identity, claim, proof = section_lengths
    if (
        statement == 0
        or extension != GUEST_EXTENSION_BYTES
        or identity != GUEST_IDENTITY_BYTES
        or claim == 0
        or proof == 0
        or GUEST_ARTIFACT_HEADER_BYTES + sum(section_lengths) != artifact_bytes
    ):
        raise CaptureError("guest proof artifact section framing changed")
