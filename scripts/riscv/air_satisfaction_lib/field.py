"""M31, CM31 and QM31 arithmetic, and the committed-row placement permutation.

Written from the algebraic definitions in `src/core/fields/{m31,cm31,qm31}.zig`
and `src/core/utils.zig`, not ported from them: the point of this package is to
recompute what Zig computed without sharing the code that computes it, so a
transcription would defeat it.  The definitions are short enough that a reviewer
can check them against the Zig by reading both:

    M31   integers mod p = 2^31 - 1
    CM31  M31[i] / (i^2 + 1)
    QM31  CM31[u] / (u^2 - (2 + i))

`scripts/tests/test_air_satisfaction.py` cross-checks QM31 against a public
LogUp boundary vector pinned in `air/public_logup.zig` from the Rust oracle, so
the arithmetic here is anchored to something outside this repository's Zig.
"""

from __future__ import annotations

from dataclasses import dataclass

P = (1 << 31) - 1


class FieldError(ArithmeticError):
    """Inversion of zero, or a value that is not a canonical residue."""


def m31(value: int) -> int:
    return value % P


# --- CM31 as a 2-tuple ------------------------------------------------------


def _cm_mul(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
    return ((x[0] * y[0] - x[1] * y[1]) % P, (x[0] * y[1] + x[1] * y[0]) % P)


def _cm_add(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
    return ((x[0] + y[0]) % P, (x[1] + y[1]) % P)


def _cm_sub(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
    return ((x[0] - y[0]) % P, (x[1] - y[1]) % P)


def _cm_inv(x: tuple[int, int]) -> tuple[int, int]:
    norm = (x[0] * x[0] + x[1] * x[1]) % P
    if norm == 0:
        raise FieldError("CM31 inverse of zero")
    inverse = pow(norm, P - 2, P)
    return ((x[0] * inverse) % P, (-x[1] * inverse) % P)


# `u^2 = R`.  Multiplying a CM31 by R is the only place the extension's
# irreducible polynomial appears, so it is spelled out once.
def _cm_mul_r(x: tuple[int, int]) -> tuple[int, int]:
    return ((2 * x[0] - x[1]) % P, (2 * x[1] + x[0]) % P)


@dataclass(frozen=True)
class QM31:
    """`(a + b i) + (c + d i) u`, stored in the coefficient order the Zig
    `toM31Array` emits and the dump therefore carries."""

    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0

    @staticmethod
    def from_list(values: list[int]) -> "QM31":
        if len(values) != 4:
            raise FieldError(f"a secure-field value needs 4 coordinates, got {len(values)}")
        for value in values:
            if not 0 <= value < P:
                raise FieldError(f"coordinate {value} is not a canonical M31 residue")
        return QM31(*values)

    @staticmethod
    def from_base(value: int) -> "QM31":
        return QM31(value % P, 0, 0, 0)

    def is_zero(self) -> bool:
        return (self.a, self.b, self.c, self.d) == (0, 0, 0, 0)

    def as_tuple(self) -> tuple[int, int, int, int]:
        return (self.a, self.b, self.c, self.d)

    def _halves(self) -> tuple[tuple[int, int], tuple[int, int]]:
        return ((self.a, self.b), (self.c, self.d))

    def __add__(self, other: "QM31") -> "QM31":
        x0, x1 = self._halves()
        y0, y1 = other._halves()
        return QM31(*_cm_add(x0, y0), *_cm_add(x1, y1))

    def __sub__(self, other: "QM31") -> "QM31":
        x0, x1 = self._halves()
        y0, y1 = other._halves()
        return QM31(*_cm_sub(x0, y0), *_cm_sub(x1, y1))

    def __neg__(self) -> "QM31":
        return QM31.from_base(0) - self

    def __mul__(self, other: "QM31") -> "QM31":
        # (a + b u)(c + d u) = (ac + R bd) + (ad + bc) u.
        x0, x1 = self._halves()
        y0, y1 = other._halves()
        ac = _cm_mul(x0, y0)
        bd = _cm_mul(x1, y1)
        cross = _cm_sub(_cm_sub(_cm_mul(_cm_add(x0, x1), _cm_add(y0, y1)), ac), bd)
        return QM31(*_cm_add(ac, _cm_mul_r(bd)), *cross)

    def mul_base(self, value: int) -> "QM31":
        scalar = value % P
        return QM31(
            (self.a * scalar) % P,
            (self.b * scalar) % P,
            (self.c * scalar) % P,
            (self.d * scalar) % P,
        )

    def inv(self) -> "QM31":
        # (a + b u)^-1 = (a - b u) / (a^2 - R b^2).
        x0, x1 = self._halves()
        denominator = _cm_sub(_cm_mul(x0, x0), _cm_mul_r(_cm_mul(x1, x1)))
        if denominator == (0, 0):
            raise FieldError("QM31 inverse of zero")
        inverse = _cm_inv(denominator)
        return QM31(
            *_cm_mul(x0, inverse),
            *_cm_mul(((-x1[0]) % P, (-x1[1]) % P), inverse),
        )


QM31_ZERO = QM31()
QM31_ONE = QM31(1, 0, 0, 0)


# --- committed-row placement ------------------------------------------------


def _bit_reverse_index(index: int, log_size: int) -> int:
    if log_size == 0:
        return index
    return int(f"{index:0{log_size}b}"[::-1], 2)


def _coset_index_to_circle_domain_index(index: int, log_size: int) -> int:
    if index % 2 == 0:
        return index // 2
    return ((2 << log_size) - index) // 2


def committed_placement(log_size: int) -> list[int]:
    """`placement[logical] = physical`, matching
    `infra_trace/permutation.BitReversalTable`.

    Two permutations composed, not one: coset order to circle-domain order, then
    the bit reversal.  Undoing only the bit reversal reads the wrong row for
    every odd logical index, which is exactly the placement mistake this checker
    exists to be unable to share with the prover.
    """
    return [
        _bit_reverse_index(_coset_index_to_circle_domain_index(row, log_size), log_size)
        for row in range(1 << log_size)
    ]


def logical_index_from_committed(index: int, log_size: int) -> int:
    """Invert `committed_placement` without materialising a 2^k inverse table.

    This particular circle-domain/bit-reversal composition is an involution.
    Keeping the scalar inverse matters for sparse lookup-table exports whose
    domains reach 2^20 but whose committed multiplicity columns have only a
    handful of nonzero cells.
    """
    size = 1 << log_size
    if not 0 <= index < size:
        raise ValueError(f"committed row {index} is outside a log-{log_size} domain")
    return _bit_reverse_index(
        _coset_index_to_circle_domain_index(index, log_size),
        log_size,
    )
