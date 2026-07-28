"""Constructive uniqueness audit for the six preprocessed lookup tables."""

from __future__ import annotations

import hashlib
import struct
from typing import Callable, Sequence

from .models import AuditError, TableAudit

try:
    from air_satisfaction_lib import infrastructure
    from air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO
except ModuleNotFoundError:  # Imported through scripts.* in tests.
    from scripts.air_satisfaction_lib import infrastructure
    from scripts.air_satisfaction_lib.field import P, QM31, QM31_ONE, QM31_ZERO


TABLE_ORDER = (
    "bitwise",
    "range_check_20",
    "range_check_8_11",
    "range_check_8_8_4",
    "range_check_8_8",
    "range_check_m31",
)

# SHA-256 over, for every natural row, little-endian
# (natural_row, committed_row, tuple[0], tuple[1], tuple[2], tuple[3]).
# Missing tuple limbs are zero. This pins both the tuple function and the
# circle-domain placement without storing roughly three million rows.
TABLE_SEMANTIC_DIGESTS = {
    "bitwise": "0e19d78e512562e5dd59ecb49acfd08eeec1b920568bdc48d44aa80bbccd7d54",
    "range_check_20": "ec6ae9336fc3923a3ef7607f248fac5c62e19019cfef04ac003cca36a3140235",
    "range_check_8_11": "113a078514116f8ccdb7c83df36740072517dab6ab1e1d98694774449c8aa62d",
    "range_check_8_8_4": "1ccfc1980bd3add53d310c584793fd8760f3706bb6540730c2ff447c4c8e8d68",
    "range_check_8_8": "2a0721cb88559eb416241bbc330dbf22fb9d57d7283b33b8de4b65ab7e77decf",
    "range_check_m31": "b4ab54610d360a6a28db6829844901646d9c66fac5566444d00aafaaaa80aaef",
}


def table_formula(kind: str, row: int) -> tuple[int, ...]:
    size = 1 << infrastructure.TABLE_LOG_SIZES[kind]
    if not 0 <= row < size:
        raise ValueError(f"{kind} row {row} outside domain")
    low8 = row & 0xFF
    if kind == "bitwise":
        high8 = (row >> 8) & 0xFF
        operation = (row >> 16) & 0x3
        output = (
            low8 & high8,
            low8 | high8,
            low8 ^ high8,
            0,
        )[operation]
        return low8, high8, output, operation
    if kind == "range_check_20":
        return (row,)
    if kind == "range_check_8_11":
        return low8, row >> 8
    if kind == "range_check_8_8_4":
        return low8, (row >> 8) & 0xFF, row >> 16
    if kind == "range_check_8_8":
        return low8, row >> 8
    if kind == "range_check_m31":
        return (0, 0) if row == size - 1 else (low8, row >> 8)
    raise ValueError(f"unknown table {kind}")


def table_index(kind: str, values: Sequence[int]) -> int:
    expected_arity = infrastructure.TABLE_ARITIES[kind]
    if len(values) != expected_arity:
        raise ValueError("invalid tuple arity")
    if kind == "bitwise":
        lhs, rhs, output, operation = values
        if lhs >= 256 or rhs >= 256 or output >= 256 or operation >= 4:
            raise ValueError("bitwise tuple outside boxes")
        expected = (lhs & rhs, lhs | rhs, lhs ^ rhs, 0)[operation]
        if output != expected:
            raise ValueError("invalid bitwise result")
        return lhs | (rhs << 8) | (operation << 16)
    widths = {
        "range_check_20": (20,),
        "range_check_8_11": (8, 11),
        "range_check_8_8_4": (8, 8, 4),
        "range_check_8_8": (8, 8),
        "range_check_m31": (8, 7),
    }[kind]
    if any(value < 0 or value >= 1 << width for value, width in zip(values, widths)):
        raise ValueError("range tuple outside boxes")
    if kind == "range_check_m31" and tuple(values) == (255, 127):
        raise ValueError("forbidden range-M31 tuple")
    row = values[0]
    for value, shift in zip(values[1:], (8, 16)):
        row |= value << shift
    return row


def _bit_reverse(index: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (index & 1)
        index >>= 1
    return result


def committed_index(row: int, log_size: int) -> int:
    circle = row // 2 if row % 2 == 0 else ((2 << log_size) - row) // 2
    return _bit_reverse(circle, log_size)


def _dummy_powers() -> tuple[tuple[int, int, int, int], ...]:
    alpha = QM31(4, 3, 2, 1)
    powers = [QM31_ONE]
    for _ in range(infrastructure.TABLE_ARITIES["bitwise"] - 1):
        powers.append(powers[-1] * alpha)
    return tuple(power.as_tuple() for power in powers)


def _dummy_denominator_coordinates(
    values: Sequence[int],
    powers: Sequence[tuple[int, int, int, int]],
) -> tuple[int, int, int, int]:
    coordinates = [-1, -2, -3, -4]
    for value, power in zip(values, powers):
        for coordinate in range(4):
            coordinates[coordinate] += value * power[coordinate]
    return tuple(value % P for value in coordinates)  # type: ignore[return-value]


def dummy_denominator(values: Sequence[int]) -> QM31:
    return QM31(*_dummy_denominator_coordinates(values, _dummy_powers()))


def transition_residual(
    *,
    signed_multiplicity: int,
    current: QM31,
    previous: QM31,
    is_first: int,
    claim: QM31,
    denominator: QM31,
) -> QM31:
    numerator = -QM31.from_base(signed_multiplicity)
    delta = current - previous + claim.mul_base(is_first)
    return delta * denominator - numerator


def _nonzero_transcript_control(kind: str) -> bool:
    """Construct a full-domain trace with one nonzero multiplicity at row 17."""
    row = 17
    denominator = dummy_denominator(table_formula(kind, row))
    if denominator.is_zero():
        return False
    increment = denominator.inv()  # signed multiplicity -1 => table numerator +1.
    zero = QM31_ZERO

    # These are all distinct row shapes in the piecewise full-domain trace:
    # row 0 wraps from the final claim, rows before 17 stay at zero, row 17
    # adds the one term, and every later row stays at the claim.
    checks = (
        transition_residual(
            signed_multiplicity=0,
            current=zero,
            previous=increment,
            is_first=1,
            claim=increment,
            denominator=dummy_denominator(table_formula(kind, 0)),
        ),
        transition_residual(
            signed_multiplicity=0,
            current=zero,
            previous=zero,
            is_first=0,
            claim=increment,
            denominator=dummy_denominator(table_formula(kind, row - 1)),
        ),
        transition_residual(
            signed_multiplicity=P - 1,
            current=increment,
            previous=zero,
            is_first=0,
            claim=increment,
            denominator=denominator,
        ),
        transition_residual(
            signed_multiplicity=0,
            current=increment,
            previous=increment,
            is_first=0,
            claim=increment,
            denominator=dummy_denominator(table_formula(kind, row + 1)),
        ),
        transition_residual(
            signed_multiplicity=0,
            current=increment,
            previous=increment,
            is_first=0,
            claim=increment,
            denominator=dummy_denominator(
                table_formula(kind, (1 << infrastructure.TABLE_LOG_SIZES[kind]) - 1)
            ),
        ),
    )
    if any(not value.is_zero() for value in checks):
        return False

    # The row equation reacts to either copy changing its purported output.
    mutated = transition_residual(
        signed_multiplicity=P - 1,
        current=increment + QM31_ONE,
        previous=zero,
        is_first=0,
        claim=increment,
        denominator=denominator,
    )
    return mutated == denominator and not mutated.is_zero()


def zero_denominator_counterexample() -> bool:
    common = dict(
        signed_multiplicity=0,
        previous=QM31_ZERO,
        is_first=0,
        claim=QM31_ZERO,
        denominator=QM31_ZERO,
    )
    first = transition_residual(current=QM31_ZERO, **common)
    second = transition_residual(current=QM31_ONE, **common)
    return first.is_zero() and second.is_zero()


def audit_tables(
    tuple_function: Callable[[str, int], tuple[int, ...]] = infrastructure.table_tuple,
) -> tuple[TableAudit, ...]:
    if tuple(infrastructure.TABLE_LOG_SIZES) != TABLE_ORDER:
        raise AuditError("lookup table order drifted from the transcript order")
    if set(infrastructure.TABLE_ARITIES) != set(TABLE_ORDER):
        raise AuditError("lookup table arity set drifted")

    powers = _dummy_powers()
    results: list[TableAudit] = []
    for kind in TABLE_ORDER:
        log_size = infrastructure.TABLE_LOG_SIZES[kind]
        arity = infrastructure.TABLE_ARITIES[kind]
        size = 1 << log_size
        digest = hashlib.sha256()
        zero_denominators = 0
        for row in range(size):
            actual = tuple_function(kind, row)
            expected = table_formula(kind, row)
            if actual != expected:
                raise AuditError(
                    f"{kind} row {row} is {actual}, expected deterministic {expected}"
                )
            if len(actual) != arity or any(not 0 <= value < P for value in actual):
                raise AuditError(f"{kind} row {row} is not a canonical arity-{arity} tuple")
            inverse = table_index(kind, actual)
            if kind == "range_check_m31" and row == size - 1:
                if inverse != 0 or actual != (0, 0):
                    raise AuditError("range-M31 duplicate-row contract drifted")
            elif inverse != row:
                raise AuditError(f"{kind} row {row} does not roundtrip through its tuple")
            padded = actual + (0,) * (4 - len(actual))
            digest.update(
                struct.pack(
                    "<II4I",
                    row,
                    committed_index(row, log_size),
                    *padded,
                )
            )
            if _dummy_denominator_coordinates(actual, powers) == (0, 0, 0, 0):
                zero_denominators += 1

        semantic_digest = digest.hexdigest()
        if semantic_digest != TABLE_SEMANTIC_DIGESTS[kind]:
            raise AuditError(
                f"{kind} semantic digest changed: expected "
                f"{TABLE_SEMANTIC_DIGESTS[kind]}, got {semantic_digest}"
            )
        control = _nonzero_transcript_control(kind)
        if not control:
            raise AuditError(f"{kind} nonzero transcript non-vacuity control failed")
        if zero_denominators:
            raise AuditError(
                f"{kind} dummy relation has {zero_denominators} zero denominators"
            )
        results.append(
            TableAudit(
                kind=kind,
                log_size=log_size,
                arity=arity,
                rows=size,
                semantic_digest=semantic_digest,
                dummy_zero_denominators=zero_denominators,
                nonzero_transcript_control=control,
                is_first_deterministic=True,
                row_to_tuple_deterministic=True,
                tuple_to_row_injective=kind != "range_check_m31",
            )
        )

    try:
        table_index("range_check_m31", (255, 127))
    except ValueError:
        pass
    else:
        raise AuditError("forbidden range-M31 tuple became addressable")
    return tuple(results)
