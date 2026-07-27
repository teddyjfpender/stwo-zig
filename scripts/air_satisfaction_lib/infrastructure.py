"""Independent row constraints and relation requests for Tree-1 infrastructure.

This module is intentionally literal.  It does not import Zig-generated IR:
the five witness-bearing component layouts and six deterministic table schemas
are transcribed here, then checked against the exact committed buffers exported
at the Tree-1 boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import poseidon2
from .dump import Component
from .field import P
from .rows import Counts, Violation

INV2 = 1_073_741_824
MAX_CLOCK_DIFF = (1 << 20) - 1

TABLE_LOG_SIZES = {
    "bitwise": 18,
    "range_check_20": 20,
    "range_check_8_11": 19,
    "range_check_8_8_4": 20,
    "range_check_8_8": 16,
    "range_check_m31": 15,
}

TABLE_ARITIES = {
    "bitwise": 4,
    "range_check_20": 1,
    "range_check_8_11": 2,
    "range_check_8_8_4": 3,
    "range_check_8_8": 2,
    "range_check_m31": 2,
}

MAIN_COLUMNS = {
    "program": 10,
    "memory": 8,
    "merkle": 10,
    "poseidon2": poseidon2.N_MAIN_COLUMNS,
    "clock_update": 10,
    **{kind: 1 for kind in TABLE_LOG_SIZES},
}

BUS_DOMAINS = {
    "memory_access",
    "program_access",
    "merkle",
    "poseidon2",
    "poseidon2_io",
}


@dataclass(frozen=True)
class Request:
    domain: str
    numerator: int
    values: tuple[int, ...]


def table_tuple(kind: str, row: int) -> tuple[int, ...]:
    """The deterministic natural-row tuple of one preprocessed table."""
    size = 1 << TABLE_LOG_SIZES[kind]
    if not 0 <= row < size:
        raise ValueError(f"{kind} row {row} is outside its domain")
    if kind == "bitwise":
        lhs = row & 0xFF
        rhs = (row >> 8) & 0xFF
        operation = (row >> 16) & 0x3
        value = (lhs & rhs, lhs | rhs, lhs ^ rhs, 0)[operation]
        return lhs, rhs, value, operation
    if kind == "range_check_20":
        return (row,)
    if kind == "range_check_8_11":
        return row & 0xFF, row >> 8
    if kind == "range_check_8_8_4":
        return row & 0xFF, (row >> 8) & 0xFF, row >> 16
    if kind == "range_check_8_8":
        return row & 0xFF, row >> 8
    if kind == "range_check_m31":
        # The final preprocessed row deliberately duplicates (0, 0); the
        # otherwise corresponding (255, 127) tuple is excluded.
        if row == size - 1:
            return 0, 0
        return row & 0xFF, row >> 8
    raise ValueError(f"unknown lookup table {kind!r}")


def _lookup_violation(domain: str, values: tuple[int, ...]) -> str | None:
    if len(values) != TABLE_ARITIES[domain]:
        return f"arity {len(values)}, expected {TABLE_ARITIES[domain]}"
    if domain == "bitwise":
        lhs, rhs, value, operation = values
        if lhs >= 256 or rhs >= 256 or value >= 256 or operation >= 4:
            return f"tuple {values} exceeds the bitwise table boxes"
        expected = (lhs & rhs, lhs | rhs, lhs ^ rhs, 0)[operation]
        if value != expected:
            return f"{lhs}, {rhs}, op {operation} gives {expected}, not {value}"
        return None
    widths = {
        "range_check_20": (20,),
        "range_check_8_11": (8, 11),
        "range_check_8_8_4": (8, 8, 4),
        "range_check_8_8": (8, 8),
        "range_check_m31": (8, 7),
    }[domain]
    for position, (value, width) in enumerate(zip(values, widths)):
        if value >= 1 << width:
            return f"component {position} = {value} exceeds its {width}-bit box"
    if domain == "range_check_m31" and values == (255, 127):
        return "tuple (255, 127) is deliberately absent from range_check_m31"
    return None


def _geometry(component: Component) -> None:
    if component.class_ != "infra":
        raise ValueError(f"{component.family}[{component.index}] is not infrastructure")
    expected_columns = MAIN_COLUMNS.get(component.family)
    if expected_columns is None:
        raise ValueError(f"unknown infrastructure kind {component.family!r}")
    if component.n_columns != expected_columns:
        raise ValueError(
            f"{component.family}[{component.index}] has {component.n_columns} columns, "
            f"expected {expected_columns}"
        )
    if component.family in TABLE_LOG_SIZES:
        expected_log = TABLE_LOG_SIZES[component.family]
        if (
            component.log_size != expected_log
            or component.n_rows != 1 << expected_log
            or not component.is_sparse()
        ):
            raise ValueError(
                f"{component.family}[{component.index}] has invalid fixed-table geometry"
            )
    elif component.is_sparse():
        raise ValueError(f"{component.family}[{component.index}] must be dense")


def _constraint(
    component: Component,
    row_index: int,
    name: str,
    value: int,
    counts: Counts,
    violations: list[Violation],
) -> None:
    counts.constraints += 1
    residue = value % P
    if residue:
        violations.append(
            Violation(
                component.family,
                component.index,
                row_index,
                "constraint",
                f"{name} evaluates to {residue}, not 0",
            )
        )


def _request(
    component: Component,
    row_index: int,
    domain: str,
    numerator: int,
    values: tuple[int, ...],
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    numerator %= P
    if numerator == 0:
        counts.inactive_requests += 1
        return
    request = Request(domain, numerator, tuple(value % P for value in values))
    requests.append(request)
    if domain in TABLE_LOG_SIZES:
        if domain == "bitwise":
            counts.bitwise_requests += 1
        else:
            counts.box_requests += 1
        detail = _lookup_violation(domain, request.values)
        if detail is not None:
            violations.append(
                Violation(
                    component.family,
                    component.index,
                    row_index,
                    "lookup",
                    f"request on {domain}: {detail}",
                )
            )
    elif domain in BUS_DOMAINS:
        counts.bus_requests += 1
    else:
        raise ValueError(f"unknown relation domain {domain!r}")


def _program(
    component: Component,
    row_index: int,
    row: tuple[int, ...],
    is_active: int,
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    enabler, addr = row[0], row[1]
    values = row[2:6]
    multiplicity, root, low20, high = row[6:10]
    _constraint(component, row_index, "enabler == is_active", enabler - is_active, counts, violations)
    _constraint(
        component,
        row_index,
        "padding multiplicity",
        multiplicity * (1 - is_active),
        counts,
        violations,
    )
    word_address = (low20 + (1 << 20) * high) % P
    _constraint(
        component,
        row_index,
        "byte address recomposition",
        enabler * (addr - 4 * word_address),
        counts,
        violations,
    )
    _request(component, row_index, "program_access", multiplicity, (addr, *values), counts, violations, requests)
    for limb, value in enumerate(values):
        _request(
            component,
            row_index,
            "merkle",
            -enabler,
            ((addr + limb) % P, 30, value, root),
            counts,
            violations,
            requests,
        )
    _request(component, row_index, "range_check_20", -enabler, (low20,), counts, violations, requests)
    _request(component, row_index, "range_check_8_8", -enabler, (high, 0), counts, violations, requests)


def _memory(
    component: Component,
    row_index: int,
    row: tuple[int, ...],
    is_active: int,
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    addr, clock = row[0], row[1]
    values = row[2:6]
    multiplicity, root = row[6], row[7]
    squared = multiplicity * multiplicity % P
    _constraint(
        component,
        row_index,
        "signed multiplicity is -1, 0, or 1",
        multiplicity * (squared - 1),
        counts,
        violations,
    )
    _constraint(
        component,
        row_index,
        "multiplicity square == is_active",
        squared - is_active,
        counts,
        violations,
    )
    _request(component, row_index, "range_check_8_8", -is_active, values[0:2], counts, violations, requests)
    _request(component, row_index, "range_check_8_8", -is_active, values[2:4], counts, violations, requests)
    _request(
        component,
        row_index,
        "memory_access",
        multiplicity,
        (1, addr, clock, *values),
        counts,
        violations,
        requests,
    )
    for limb, value in enumerate(values):
        _request(
            component,
            row_index,
            "merkle",
            -is_active,
            ((addr + limb) % P, 30, value, root),
            counts,
            violations,
            requests,
        )


def _merkle(
    component: Component,
    row_index: int,
    row: tuple[int, ...],
    is_active: int,
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    enabler, index, depth, lhs, rhs, current = row[:6]
    lhs_mult, rhs_mult, current_mult, root = row[6:10]
    _constraint(component, row_index, "enabler == is_active", enabler - is_active, counts, violations)
    for name, multiplicity in (
        ("lhs multiplicity", lhs_mult),
        ("rhs multiplicity", rhs_mult),
        ("current multiplicity", current_mult),
    ):
        _constraint(
            component,
            row_index,
            f"{name} in {{0,1,2}}",
            multiplicity * (multiplicity - 1) * (multiplicity - 2),
            counts,
            violations,
        )
        _constraint(
            component,
            row_index,
            f"{name} is zero on padding",
            multiplicity * (1 - is_active),
            counts,
            violations,
        )
    _request(component, row_index, "merkle", lhs_mult, (index, depth, lhs, root), counts, violations, requests)
    _request(
        component,
        row_index,
        "merkle",
        rhs_mult,
        ((index + 1) % P, depth, rhs, root),
        counts,
        violations,
        requests,
    )
    _request(
        component,
        row_index,
        "merkle",
        -current_mult,
        (index * INV2 % P, (depth - 1) % P, current, root),
        counts,
        violations,
        requests,
    )
    poseidon_input = (lhs, rhs, *([0] * 14))
    poseidon_output = (current, *([0] * 15))
    _request(component, row_index, "poseidon2", enabler, poseidon_input, counts, violations, requests)
    _request(component, row_index, "poseidon2", -enabler, poseidon_output, counts, violations, requests)


def _poseidon(
    component: Component,
    row_index: int,
    row: tuple[int, ...],
    is_active: int,
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    for index, value in enumerate(poseidon2.residuals(row, is_active)):
        _constraint(
            component,
            row_index,
            f"Poseidon2 residual {index}",
            value,
            counts,
            violations,
        )
    enabler = row[0]
    wide = row[poseidon2.WIDE_COLUMN]
    io = row[poseidon2.IO_COLUMN]
    inputs = row[poseidon2.INPUT_START : poseidon2.INPUT_START + poseidon2.WIDTH]
    output = row[poseidon2.OUTPUT_START : poseidon2.OUTPUT_START + poseidon2.WIDTH]
    narrow = (output[0], *([0] * 15))
    wide_output = (*output[:8], *([0] * 8))
    _request(
        component,
        row_index,
        "poseidon2",
        -enabler * (1 - io),
        inputs,
        counts,
        violations,
        requests,
    )
    _request(
        component,
        row_index,
        "poseidon2",
        enabler * (1 - wide - io),
        narrow,
        counts,
        violations,
        requests,
    )
    _request(
        component,
        row_index,
        "poseidon2",
        enabler * wide,
        wide_output,
        counts,
        violations,
        requests,
    )
    _request(
        component,
        row_index,
        "poseidon2_io",
        enabler * io,
        (*inputs, *output),
        counts,
        violations,
        requests,
    )


def _clock(
    component: Component,
    row_index: int,
    row: tuple[int, ...],
    is_active: int,
    counts: Counts,
    violations: list[Violation],
    requests: list[Request],
) -> None:
    enabler, addr_space, addr, previous = row[:4]
    values = row[4:8]
    low20, high4 = row[8:10]
    _constraint(
        component,
        row_index,
        "enabler is boolean",
        enabler * (1 - enabler),
        counts,
        violations,
    )
    _constraint(component, row_index, "enabler == is_active", enabler - is_active, counts, violations)
    _constraint(
        component,
        row_index,
        "clock predecessor recomposition",
        enabler * (previous - low20 - (1 << 20) * high4),
        counts,
        violations,
    )
    _request(
        component,
        row_index,
        "memory_access",
        -enabler,
        (addr_space, addr, previous, *values),
        counts,
        violations,
        requests,
    )
    _request(
        component,
        row_index,
        "memory_access",
        enabler,
        (addr_space, addr, (previous + MAX_CLOCK_DIFF) % P, *values),
        counts,
        violations,
        requests,
    )
    _request(component, row_index, "range_check_20", -enabler, (low20,), counts, violations, requests)
    _request(component, row_index, "range_check_8_8_4", -enabler, (0, 0, high4), counts, violations, requests)


def check_component(component: Component) -> tuple[list[Violation], Counts, tuple[Request, ...]]:
    _geometry(component)
    violations: list[Violation] = []
    counts = Counts()
    requests: list[Request] = []

    if component.family in TABLE_LOG_SIZES:
        for row_index, values in component.sparse_rows:
            counts.rows += 1
            signed_multiplicity = values[0]
            _request(
                component,
                row_index,
                component.family,
                -signed_multiplicity,
                table_tuple(component.family, row_index),
                counts,
                violations,
                requests,
            )
        return violations, counts, tuple(requests)

    handlers = {
        "program": _program,
        "memory": _memory,
        "merkle": _merkle,
        "poseidon2": _poseidon,
        "clock_update": _clock,
    }
    handler = handlers[component.family]
    if len(component.rows) != component.domain_size():
        raise ValueError(
            f"{component.family}[{component.index}] carries {len(component.rows)} "
            f"rows for domain {component.domain_size()}"
        )
    for row_index, row in enumerate(component.rows):
        counts.rows += 1
        handler(
            component,
            row_index,
            row,
            int(row_index < component.n_rows),
            counts,
            violations,
            requests,
        )
    return violations, counts, tuple(requests)
