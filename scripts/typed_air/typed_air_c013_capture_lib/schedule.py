"""Independent replay of the allocation-free Zig C-013 launch schedule."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Literal

from .model import CaptureError, SCHEDULE_SHA256


CALL_COUNTS = (0, 1, 8, 64, 512, 4096)
SHAPES = (
    "core_only",
    "balanced_core_and_poseidon2",
    "poseidon2_dominant",
)
WARMUPS_PER_ARM = 10
MEASURED_ROUNDS = 3
PAIRS_PER_ROUND = 10
ATTEMPTS_PER_CELL = 80
CALIBRATION_ATTEMPTS = 80
M6_ATTEMPTS = 1_440
GLOBAL_ATTEMPTS = 1_520
COOLDOWN_NS = 1_000_000_000

Phase = Literal["calibration", "warmup", "measured"]


@dataclass(frozen=True)
class Attempt:
    global_ordinal: int
    kind: Literal["calibration", "m6"]
    sample_index: int
    phase: Phase
    arm: str
    round: int | None
    pair_index: int
    position: int
    cell_index: int | None = None
    shape: str | None = None
    calls: int | None = None


def _arm(first_b: int, position: int, a: str, b: str) -> str:
    return a if (first_b ^ position) == 0 else b


def calibration_attempt_at(ordinal: int) -> Attempt:
    if not 0 <= ordinal < CALIBRATION_ATTEMPTS:
        raise CaptureError("calibration attempt ordinal is out of range")
    warmup_attempts = 2 * WARMUPS_PER_ARM
    if ordinal < warmup_attempts:
        pair = ordinal // 2
        position = ordinal % 2
        round_index = None
        first_b = pair & 1
    else:
        measured = ordinal - warmup_attempts
        attempts_per_round = 2 * PAIRS_PER_ROUND
        round_index = measured // attempts_per_round
        within_round = measured % attempts_per_round
        pair = within_round // 2
        position = within_round % 2
        first_b = round_index & 1
    return Attempt(
        global_ordinal=ordinal,
        kind="calibration",
        sample_index=ordinal,
        phase="calibration",
        arm=_arm(first_b, position, "a", "a_control"),
        round=round_index,
        pair_index=pair,
        position=position,
    )


def m6_attempt_at(ordinal: int) -> Attempt:
    if not 0 <= ordinal < M6_ATTEMPTS:
        raise CaptureError("M6 attempt ordinal is out of range")
    cell = ordinal // ATTEMPTS_PER_CELL
    local = ordinal % ATTEMPTS_PER_CELL
    shape = SHAPES[cell // len(CALL_COUNTS)]
    calls = CALL_COUNTS[cell % len(CALL_COUNTS)]
    warmup_attempts = 2 * WARMUPS_PER_ARM
    if local < warmup_attempts:
        pair = local // 2
        position = local % 2
        phase: Phase = "warmup"
        round_index = None
        first_b = pair & 1
    else:
        measured = local - warmup_attempts
        attempts_per_round = 2 * PAIRS_PER_ROUND
        round_index = measured // attempts_per_round
        within_round = measured % attempts_per_round
        pair = within_round // 2
        position = within_round % 2
        phase = "measured"
        first_b = round_index & 1
    return Attempt(
        global_ordinal=CALIBRATION_ATTEMPTS + ordinal,
        kind="m6",
        sample_index=ordinal,
        phase=phase,
        arm=_arm(first_b, position, "software", "precompile"),
        round=round_index,
        pair_index=pair,
        position=position,
        cell_index=cell,
        shape=shape,
        calls=calls,
    )


def all_attempts() -> tuple[Attempt, ...]:
    attempts = tuple(
        calibration_attempt_at(index) for index in range(CALIBRATION_ATTEMPTS)
    ) + tuple(m6_attempt_at(index) for index in range(M6_ATTEMPTS))
    if len(attempts) != GLOBAL_ATTEMPTS:
        raise AssertionError("C-013 schedule cardinality drifted")
    return attempts


def _integer(value: int) -> bytes:
    return struct.pack("<Q", value)


def _optional_integer(value: int | None) -> bytes:
    return bytes((0 if value is None else 1,)) + _integer(value or 0)


def schedule_digest() -> str:
    """Replay `capture_schedule.zig:digest` byte for byte."""

    digest = hashlib.sha256()
    digest.update(b"STWC013S\x00v1")
    phase_tags = {"calibration": 1, "warmup": 2, "measured": 3}
    calibration_tags = {"a": 0, "a_control": 1}
    arm_tags = {"software": 0, "precompile": 1}
    shape_tags = {shape: index for index, shape in enumerate(SHAPES)}
    for ordinal in range(CALIBRATION_ATTEMPTS):
        attempt = calibration_attempt_at(ordinal)
        digest.update(_integer(ordinal))
        digest.update(
            bytes(
                (
                    phase_tags[attempt.phase],
                    calibration_tags[attempt.arm],
                    attempt.position,
                )
            )
        )
        digest.update(_optional_integer(attempt.round))
        digest.update(_integer(attempt.pair_index))
    for ordinal in range(M6_ATTEMPTS):
        attempt = m6_attempt_at(ordinal)
        assert attempt.cell_index is not None
        assert attempt.shape is not None
        assert attempt.calls is not None
        digest.update(_integer(ordinal))
        digest.update(_integer(attempt.cell_index))
        digest.update(
            bytes(
                (
                    shape_tags[attempt.shape],
                    phase_tags[attempt.phase],
                    arm_tags[attempt.arm],
                    attempt.position,
                )
            )
        )
        digest.update(_integer(attempt.calls))
        digest.update(_optional_integer(attempt.round))
        digest.update(_integer(attempt.pair_index))
    digest.update(_integer(COOLDOWN_NS))
    return digest.hexdigest()


def validate_authority() -> None:
    actual = schedule_digest()
    if actual != SCHEDULE_SHA256:
        raise CaptureError(
            f"Python/Zig C-013 schedule identity drift: {actual} != "
            f"{SCHEDULE_SHA256}"
        )
