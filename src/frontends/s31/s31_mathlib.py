"""Field math built from the existing constrained S31 relation operations.

These functions add no AIR primitives. Every operation lowers through Builder,
so the ordinary circuit compiler and generated native verifier prove the same
nodes a handwritten relation would use.
"""

from __future__ import annotations

from s31_stdlib import Builder, P, StaticGroup, TypeErrorS31, Value


BUILTINS = {
    "std::math::neg", "std::math::sub", "std::math::square", "std::math::pow",
    "std::math::inv", "std::math::div",
    "std::math::sum", "std::math::dot", "std::math::poly_eval", "std::math::matvec", "std::math::matmul",
    "std::math::sum_lanes", "std::math::dot_lanes",
    "std::math::add_u256", "std::math::add_u256_checked", "std::math::le_u256",
    "std::math::sub_u256", "std::math::sub_u256_checked",
    "std::math::lt_u256", "std::math::gt_u256", "std::math::ge_u256",
    "std::math::eq_u256", "std::math::ne_u256", "std::math::min_u256", "std::math::max_u256",
}
MAX_STATIC_TERMS = 64


def _m31(value: Value) -> None:
    if value.typ.kind != "m31":
        raise TypeErrorS31("std::math requires [m31; N] values")


def add_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
             span: dict[str, int] | None = None) -> Value:
    """Wrapping 256-bit addition, with a Boolean carry at every limb."""
    return builder.u256_binary("u256_add", lhs, rhs, wanted=wanted, span=span)


def add_u256_checked(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
                     span: dict[str, int] | None = None) -> Value:
    """256-bit addition constrained to reject a final carry."""
    return builder.u256_binary("u256_add_checked", lhs, rhs, wanted=wanted, span=span)


def le_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    """Return one field bit for unsigned lhs <= rhs."""
    return builder.u256_binary("u256_le", lhs, rhs, wanted=wanted, span=span)


def sub_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
             span: dict[str, int] | None = None) -> Value:
    """Wrapping 256-bit subtraction, with a Boolean borrow at every limb."""
    return builder.u256_binary("u256_sub", lhs, rhs, wanted=wanted, span=span)


def sub_u256_checked(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
                     span: dict[str, int] | None = None) -> Value:
    """256-bit subtraction constrained to reject a final borrow."""
    return builder.u256_binary("u256_sub_checked", lhs, rhs, wanted=wanted, span=span)


def lt_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    """One 256-bit comparison followed by a constrained Boolean negation."""
    le_reverse = builder.u256_binary("u256_le", rhs, lhs, span=span)
    return builder.boolean("bool_not", le_reverse, wanted=wanted, span=span)


def gt_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    return lt_u256(builder, rhs, lhs, wanted=wanted, span=span)


def ge_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    return builder.u256_binary("u256_le", rhs, lhs, wanted=wanted, span=span)


def eq_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    le = builder.u256_binary("u256_le", lhs, rhs, span=span)
    ge = builder.u256_binary("u256_le", rhs, lhs, span=span)
    return builder.boolean("bool_and", le, ge, wanted=wanted, span=span)


def ne_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
            span: dict[str, int] | None = None) -> Value:
    equal = eq_u256(builder, lhs, rhs, span=span)
    return builder.boolean("bool_not", equal, wanted=wanted, span=span)


def min_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
             span: dict[str, int] | None = None) -> Value:
    le = builder.u256_binary("u256_le", lhs, rhs, span=span)
    return builder.select(le, rhs, lhs, wanted=wanted, span=span)


def max_u256(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
             span: dict[str, int] | None = None) -> Value:
    le = builder.u256_binary("u256_le", lhs, rhs, span=span)
    return builder.select(le, lhs, rhs, wanted=wanted, span=span)


def neg(builder: Builder, value: Value, *, wanted: str | None = None,
        span: dict[str, int] | None = None) -> Value:
    _m31(value)
    if value.constant is not None:
        return builder.splat(-value.constant % P, value.typ.length)
    return builder.binary("mul", value, builder.splat(P - 1, value.typ.length),
                          wanted=wanted, span=span)


def sub(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
        span: dict[str, int] | None = None) -> Value:
    _m31(lhs)
    if lhs.typ != rhs.typ:
        raise TypeErrorS31("std::math::sub requires equally shaped [m31; N] values")
    opposite = neg(builder, rhs, span=span)
    return builder.binary("add", lhs, opposite, wanted=wanted, span=span)


def square(builder: Builder, value: Value, *, wanted: str | None = None,
           span: dict[str, int] | None = None) -> Value:
    _m31(value)
    return builder.binary("mul", value, value, wanted=wanted, span=span)


def inv(builder: Builder, value: Value, *, wanted: str | None = None,
        span: dict[str, int] | None = None) -> Value:
    """Field inverse; a zero in any active lane makes the circuit unsatisfied."""
    return builder.inverse(value, wanted=wanted, span=span)


def div(builder: Builder, lhs: Value, rhs: Value, *, wanted: str | None = None,
        span: dict[str, int] | None = None) -> Value:
    """Field quotient with an explicit nonzero denominator constraint."""
    return builder.divide(lhs, rhs, wanted=wanted, span=span)


def pow_static(builder: Builder, value: Value, exponent: int, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
    _m31(value)
    if not 0 <= exponent < P:
        raise TypeErrorS31("std::math::pow exponent must be a static integer in 0..p-1")
    if exponent == 0:
        return builder.splat(1, value.typ.length)
    if value.constant is not None:
        return builder.splat(pow(value.constant, exponent, P), value.typ.length)
    result = value
    bits = bin(exponent)[3:]  # The leading one is the initial value.
    for index, bit in enumerate(bits):
        last = index == len(bits) - 1
        result = builder.binary("mul", result, result,
                                wanted=wanted if last and bit == "0" else None,
                                span=span)
        if bit == "1":
            result = builder.binary("mul", result, value,
                                    wanted=wanted if last else None, span=span)
    return result


def _group(value: StaticGroup, operation: str) -> tuple[Value, ...]:
    if not isinstance(value, StaticGroup):
        raise TypeErrorS31(f"std::math::{operation} requires a static array of [m31; N] values")
    terms = value.elements
    if not 1 <= len(terms) <= MAX_STATIC_TERMS:
        raise TypeErrorS31(f"std::math::{operation} requires 1..{MAX_STATIC_TERMS} terms")
    if not all(isinstance(term, Value) for term in terms):
        raise TypeErrorS31(f"std::math::{operation} requires a static array of [m31; N] values")
    shape = terms[0].typ
    _m31(terms[0])
    if any(term.typ != shape for term in terms[1:]):
        raise TypeErrorS31(f"std::math::{operation} requires equally shaped [m31; N] terms")
    return terms


def matvec(builder: Builder, matrix: StaticGroup, vector: StaticGroup, *,
           span: dict[str, int] | None = None) -> StaticGroup:
    """A small fixed matrix times a vector of lane-parallel M31 values.

    The result remains a static group of circuit values. Each row uses the
    ordinary constrained dot product; matrix shape does not enter the AIR.
    """
    if not isinstance(matrix, StaticGroup) or not 1 <= len(matrix.elements) <= 16:
        raise TypeErrorS31("std::math::matvec requires 1..16 static matrix rows")
    columns = _group(vector, "matvec")
    if len(columns) > 16:
        raise TypeErrorS31("std::math::matvec requires at most 16 columns")
    rows = matrix.elements
    for row in rows:
        if not isinstance(row, StaticGroup) or len(row.elements) != len(columns):
            raise TypeErrorS31("std::math::matvec requires rectangular rows matching the vector")
        _group(row, "matvec")
        if any(term.typ != columns[0].typ for term in row.elements):
            raise TypeErrorS31("std::math::matvec requires equally shaped [m31; N] terms")
    return StaticGroup(tuple(dot_static(builder, row, vector, span=span) for row in rows))


def _matrix(value: StaticGroup, operation: str) -> tuple[tuple[StaticGroup, ...], int]:
    if not isinstance(value, StaticGroup) or not 1 <= len(value.elements) <= 16:
        raise TypeErrorS31(f"std::math::{operation} requires 1..16 static matrix rows")
    rows = value.elements
    if not isinstance(rows[0], StaticGroup) or not 1 <= len(rows[0].elements) <= 16:
        raise TypeErrorS31(f"std::math::{operation} requires 1..16 static matrix columns")
    width = len(rows[0].elements)
    shape = _group(rows[0], operation)[0].typ
    for row in rows[1:]:
        if not isinstance(row, StaticGroup) or len(row.elements) != width:
            raise TypeErrorS31(f"std::math::{operation} requires rectangular static rows")
        if _group(row, operation)[0].typ != shape:
            raise TypeErrorS31(f"std::math::{operation} requires equally shaped [m31; N] terms")
    return rows, width


def matmul(builder: Builder, lhs: StaticGroup, rhs: StaticGroup, *,
           span: dict[str, int] | None = None) -> StaticGroup:
    """Multiply fixed matrices of lane-parallel M31 values in row-major order.

    Every output is an ordinary static dot product; the returned matrix is a
    nested group of references, not a new relation or witness operation.
    """
    left_rows, inner = _matrix(lhs, "matmul")
    right_rows, columns = _matrix(rhs, "matmul")
    if inner != len(right_rows):
        raise TypeErrorS31("std::math::matmul inner matrix dimensions must agree")
    if left_rows[0].elements[0].typ != right_rows[0].elements[0].typ:
        raise TypeErrorS31("std::math::matmul requires equally shaped [m31; N] terms")
    right_columns = tuple(StaticGroup(tuple(row.elements[j] for row in right_rows))
                          for j in range(columns))
    return StaticGroup(tuple(StaticGroup(tuple(dot_static(builder, row, column, span=span)
                                              for column in right_columns))
                             for row in left_rows))


def sum_static(builder: Builder, group: StaticGroup, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
    """Balanced static reduction; each output lane sums the same source lane."""
    layer = list(_group(group, "sum"))
    while len(layer) > 1:
        next_layer: list[Value] = []
        for index in range(0, len(layer), 2):
            if index + 1 == len(layer):
                next_layer.append(layer[index])
            else:
                next_layer.append(builder.binary(
                    "add", layer[index], layer[index + 1],
                    wanted=wanted if len(layer) == 2 else None, span=span))
        layer = next_layer
    return layer[0]


def dot_static(builder: Builder, lhs: StaticGroup, rhs: StaticGroup,
               *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
    """Pointwise products followed by a balanced sum across static terms."""
    left = _group(lhs, "dot")
    right = _group(rhs, "dot")
    if len(left) != len(right):
        raise TypeErrorS31("std::math::dot requires equal static array lengths")
    if left[0].typ != right[0].typ:
        raise TypeErrorS31("std::math::dot requires equally shaped [m31; N] terms")
    products = tuple(builder.binary(
        "mul", a, b, wanted=wanted if len(left) == 1 else None, span=span)
        for a, b in zip(left, right))
    return sum_static(builder, StaticGroup(products),
                      wanted=wanted if len(left) > 1 else None, span=span)


def sum_lanes(builder: Builder, value: Value, *, wanted: str | None = None,
              span: dict[str, int] | None = None) -> Value:
    """Sum all lanes of one fixed M31 array to a single M31 word."""
    _m31(value)
    return builder.sum_lanes(value, wanted=wanted, span=span)


def dot_lanes(builder: Builder, lhs: Value, rhs: Value,
              *, wanted: str | None = None,
              span: dict[str, int] | None = None) -> Value:
    """One pointwise product followed by the constrained lane reduction."""
    _m31(lhs)
    if lhs.typ != rhs.typ:
        raise TypeErrorS31("std::math::dot_lanes requires equally shaped [m31; N] values")
    products = builder.binary("mul", lhs, rhs,
                              wanted=wanted if lhs.typ.length == 1 else None, span=span)
    return builder.sum_lanes(products,
                             wanted=wanted if lhs.typ.length > 1 else None, span=span)


def poly_eval(builder: Builder, x: Value, coefficients: StaticGroup,
              *, wanted: str | None = None,
              span: dict[str, int] | None = None) -> Value:
    """Horner evaluation of c0 + c1*x + ... with low-to-high coefficients."""
    _m31(x)
    terms = _group(coefficients, "poly_eval")
    if terms[0].typ != x.typ:
        raise TypeErrorS31("std::math::poly_eval coefficients must match x's [m31; N] shape")
    result = terms[-1]
    for index in range(len(terms) - 2, -1, -1):
        result = builder.binary("mul", result, x, span=span)
        result = builder.binary("add", result, terms[index],
                                wanted=wanted if index == 0 else None, span=span)
    return result
