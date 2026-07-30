"""Independent scalar oracle for exact Blake paired-LogUp interaction output."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


P = (1 << 31) - 1


@dataclass(frozen=True)
class CM31:
    a: int
    b: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "a", self.a % P)
        object.__setattr__(self, "b", self.b % P)

    def __add__(self, other: CM31) -> CM31:
        return CM31(self.a + other.a, self.b + other.b)

    def __sub__(self, other: CM31) -> CM31:
        return CM31(self.a - other.a, self.b - other.b)

    def __neg__(self) -> CM31:
        return CM31(-self.a, -self.b)

    def __mul__(self, other: CM31) -> CM31:
        return CM31(
            self.a * other.a - self.b * other.b,
            self.a * other.b + self.b * other.a,
        )

    def inverse(self) -> CM31:
        norm = (self.a * self.a + self.b * self.b) % P
        if norm == 0:
            raise ZeroDivisionError("zero CM31 denominator")
        inverse_norm = pow(norm, P - 2, P)
        return CM31(self.a * inverse_norm, -self.b * inverse_norm)


@dataclass(frozen=True)
class QM31:
    c0: CM31
    c1: CM31

    @staticmethod
    def zero() -> QM31:
        return QM31(CM31(0, 0), CM31(0, 0))

    @staticmethod
    def one() -> QM31:
        return QM31(CM31(1, 0), CM31(0, 0))

    @staticmethod
    def coordinates(values: Sequence[int]) -> QM31:
        if len(values) != 4:
            raise ValueError("QM31 requires four coordinates")
        return QM31(CM31(values[0], values[1]), CM31(values[2], values[3]))

    def to_coordinates(self) -> tuple[int, int, int, int]:
        return self.c0.a, self.c0.b, self.c1.a, self.c1.b

    def __add__(self, other: QM31) -> QM31:
        return QM31(self.c0 + other.c0, self.c1 + other.c1)

    def __sub__(self, other: QM31) -> QM31:
        return QM31(self.c0 - other.c0, self.c1 - other.c1)

    def __neg__(self) -> QM31:
        return QM31(-self.c0, -self.c1)

    def __mul__(self, other: QM31) -> QM31:
        ac = self.c0 * other.c0
        bd = self.c1 * other.c1
        # u^2 = 2 + i.
        rbd = CM31(2 * bd.a - bd.b, bd.a + 2 * bd.b)
        return QM31(ac + rbd, self.c0 * other.c1 + self.c1 * other.c0)

    def inverse(self) -> QM31:
        if self == QM31.zero():
            raise ZeroDivisionError("zero QM31 denominator")
        b2 = self.c1 * self.c1
        rb2 = CM31(2 * b2.a - b2.b, b2.a + 2 * b2.b)
        denominator = (self.c0 * self.c0 - rb2).inverse()
        return QM31(self.c0 * denominator, -self.c1 * denominator)

    def divide_base(self, value: int) -> QM31:
        if value % P == 0:
            raise ZeroDivisionError("zero M31 denominator")
        inverse = pow(value, P - 2, P)
        return QM31(
            CM31(self.c0.a * inverse, self.c0.b * inverse),
            CM31(self.c1.a * inverse, self.c1.b * inverse),
        )


@dataclass(frozen=True)
class Fraction:
    numerator: QM31
    denominator: QM31


def batch_inverse(values: Sequence[QM31]) -> list[QM31]:
    if not values:
        return []
    prefix: list[QM31] = []
    product = QM31.one()
    for value in values:
        if value == QM31.zero():
            raise ZeroDivisionError("zero batch denominator")
        prefix.append(product)
        product = product * value
    inverse = product.inverse()
    output = [QM31.zero()] * len(values)
    for index in range(len(values) - 1, -1, -1):
        output[index] = inverse * prefix[index]
        inverse = inverse * values[index]
    return output


def paired_fraction(p0: QM31, p1: QM31) -> Fraction:
    return Fraction(p0 + p1, p0 * p1)


def weighted_negative_fraction(
    p0: QM31,
    p1: QM31,
    m0: int,
    m1: int,
) -> Fraction:
    numerator = p1 * base(m0) + p0 * base(m1)
    return Fraction(-numerator, p0 * p1)


def base(value: int) -> QM31:
    return QM31.coordinates((value, 0, 0, 0))


def bit_reverse(values: Sequence[int]) -> list[int]:
    size = len(values)
    if size == 0 or size & (size - 1):
        raise ValueError("bit reverse requires a nonempty power of two")
    bits = size.bit_length() - 1
    output = list(values)
    for index in range(size):
        reverse = int(f"{index:0{bits}b}"[::-1], 2) if bits else index
        if reverse > index:
            output[index], output[reverse] = output[reverse], output[index]
    return output


def inclusive_circle_prefix(values: Sequence[int]) -> list[int]:
    circle = bit_reverse(values)
    coset: list[int] = []
    for index in range(len(circle) // 2):
        coset.extend((circle[index], circle[-1 - index]))
    total = 0
    for index, value in enumerate(coset):
        total = (total + value) % P
        coset[index] = total
    circle = [0] * len(coset)
    for index in range(len(circle) // 2):
        circle[index] = coset[2 * index]
        circle[-1 - index] = coset[2 * index + 1]
    return bit_reverse(circle)


def build(
    rows: Sequence[Sequence[Fraction]],
    prefix: Callable[[Sequence[int]], list[int]] = inclusive_circle_prefix,
    *,
    shift_tail: bool = True,
) -> tuple[list[list[int]], QM31]:
    if not rows or not rows[0]:
        raise ValueError("interaction geometry cannot be empty")
    secure_columns = len(rows[0])
    if any(len(row) != secure_columns for row in rows):
        raise ValueError("ragged interaction fractions")
    flat = [fraction for row in rows for fraction in row]
    inverses = batch_inverse([fraction.denominator for fraction in flat])
    evaluated = [
        fraction.numerator * inverse
        for fraction, inverse in zip(flat, inverses, strict=True)
    ]

    output = [[0] * len(rows) for _ in range(secure_columns * 4)]
    claimed_sum = QM31.zero()
    for row_index in range(len(rows)):
        cumulative = QM31.zero()
        for column in range(secure_columns):
            cumulative = cumulative + evaluated[
                row_index * secure_columns + column
            ]
            for coordinate, value in enumerate(cumulative.to_coordinates()):
                output[4 * column + coordinate][row_index] = value
        claimed_sum = claimed_sum + cumulative

    shift = (
        claimed_sum.divide_base(len(rows)).to_coordinates()
        if shift_tail
        else (0, 0, 0, 0)
    )
    last = 4 * (secure_columns - 1)
    for coordinate in range(4):
        shifted = [
            (value - shift[coordinate]) % P
            for value in output[last + coordinate]
        ]
        output[last + coordinate] = prefix(shifted)
    return output, claimed_sum


def synthetic_rows(row_count: int, secure_columns: int, seed: int) -> list[list[Fraction]]:
    rows: list[list[Fraction]] = []
    for row in range(row_count):
        fractions: list[Fraction] = []
        for column in range(secure_columns):
            tag = seed + row * (secure_columns + 3) + column * 7
            numerator = QM31.coordinates(
                (tag + 1, tag * 3 + 2, tag * 5 + 3, tag * 11 + 4)
            )
            denominator = QM31.coordinates(
                (tag * 13 + 5, tag * 17 + 6, tag * 19 + 7, tag * 23 + 8)
            )
            fractions.append(Fraction(numerator, denominator))
        rows.append(fractions)
    return rows


def columns_sha256(columns: Iterable[Sequence[int]]) -> str:
    digest = hashlib.sha256()
    for column in columns:
        for value in column:
            digest.update(struct.pack("<I", value))
    return digest.hexdigest()
