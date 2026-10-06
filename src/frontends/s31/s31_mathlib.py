"""Field math built from the existing constrained S31 relation operations.

These functions add no AIR primitives. Every operation lowers through Builder,
so the ordinary circuit compiler and generated native verifier prove the same
nodes a handwritten relation would use.
"""

from __future__ import annotations

from s31_stdlib import Builder, P, TypeErrorS31, Value


BUILTINS = {"std::math::neg", "std::math::sub", "std::math::square", "std::math::pow"}


def _m31(value: Value) -> None:
    if value.typ.kind != "m31":
        raise TypeErrorS31("std::math requires [m31; N] values")


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
