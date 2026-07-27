"""Independent LogUp accounting for one exported proving run.

Two computations, and the difference between them matters:

  * `opcode_claim` RECOMPUTES a component's claimed sum from the committed
    trace, the extracted lookup requests and the exported challenges.  Nothing
    from the prover's interaction layer enters it, so a disagreement with the
    exported claim is a real discrepancy between the trace and the claim the
    verifier will be handed.
  * `public_boundary` RECOMPUTES the verifier's public compensation from the
    public statement alone.  This is a second implementation of
    `air/public_logup.zig`, anchored by the pinned Rust-oracle vector in
    `scripts/tests/test_air_satisfaction.py`.

Infrastructure claims (program, memory, Merkle, Poseidon2, the six lookup
tables, clock update) are taken from the export as given: recomputing them needs
the infrastructure witnesses, which this export does not carry.  `closure`
therefore checks that the whole ledger cancels, with the opcode half verified
against the trace and the infrastructure half trusted.
"""

from __future__ import annotations

from dataclasses import dataclass

from .dump import Dump, PublicData, Relation
from .field import P, QM31
from .rows import Prepared


class UnsupportedStatement(ValueError):
    """A public statement this reimplementation deliberately refuses."""


def _inverse_of(relation: Relation, values: list[int]) -> QM31:
    denominator = relation.combine([QM31.from_base(value) for value in values])
    if denominator.is_zero():
        raise UnsupportedStatement("a LogUp denominator vanished under these challenges")
    return denominator.inv()


def opcode_claim(prepared: Prepared, relations: dict[str, Relation]) -> QM31:
    """Sum of `numerator / combine(tuple)` over every row and every request.

    Batching is invisible here on purpose.  The prover accumulates pairs
    `n1/d1 + n2/d2` as `(n1 d2 + n2 d1)/(d1 d2)`; the total over a component is
    the same field element either way, so recomputing term by term checks the
    claim without reproducing the pairing.  A disagreement is therefore about the
    values, not about how they were grouped.
    """
    total = QM31()
    # Every row of the domain, padding included: a padding row whose numerators
    # are all zero contributes nothing, and asserting that rather than assuming
    # it is the difference between recomputing the claim and guessing it.
    for row in prepared.component.rows:
        values = prepared.evaluate(row)
        for lookup in prepared.system.lookups:
            numerator = values[lookup.numerator]
            if numerator == 0:
                continue
            inverse = _inverse_of(
                relations[lookup.domain], [values[node] for node in lookup.tuple_]
            )
            total = total + inverse.mul_base(numerator)
    return total


# --- public boundary --------------------------------------------------------
#
# A second implementation of `air/public_logup.zig`. Emissions add the inverse
# denominator, consumptions subtract it, exactly as `addInverse` does.


def _memory_tuple(addr_space: int, addr: int, clock: int, word: int) -> list[int]:
    return [
        addr_space % P,
        addr % P,
        clock % P,
        word & 0xFF,
        (word >> 8) & 0xFF,
        (word >> 16) & 0xFF,
        (word >> 24) & 0xFF,
    ]


def registers_state_sum(public: PublicData, relations: dict[str, Relation]) -> QM31:
    relation = relations["registers_state"]
    # Instruction clocks start at one, so the final public consume is at
    # `clock + 1`; a wrapped clock is a statement this checker will not model.
    final_clock = public.clock + 1
    if final_clock >= (1 << 32):
        raise UnsupportedStatement("final clock overflows u32")
    return _inverse_of(relation, [public.initial_pc, 1]) - _inverse_of(
        relation, [public.final_pc, final_clock]
    )


def merkle_sum(public: PublicData, relations: dict[str, Relation]) -> QM31:
    relation = relations["merkle"]
    total = QM31()
    # Presence is semantic: an absent root contributes no tuple, a present zero
    # root emits a zero-valued one.
    for root in (public.program_root, public.initial_rw_root, public.final_rw_root):
        if root is None:
            continue
        total = total + _inverse_of(relation, [0, 0, root, root])
    return total


def memory_access_sum(public: PublicData, relations: dict[str, Relation]) -> QM31:
    relation = relations["memory_access"]
    total = QM31()
    for index in range(32):
        total = total + _inverse_of(relation, _memory_tuple(0, index, 0, public.initial_regs[index]))
        total = total - _inverse_of(
            relation,
            _memory_tuple(0, index, public.reg_last_clock[index], public.final_regs[index]),
        )
    for position, word in enumerate(public.io.input_words):
        address = public.io.input_start + position * 4
        if address >= (1 << 32):
            raise UnsupportedStatement("public input address overflows u32")
        total = total + _inverse_of(relation, _memory_tuple(1, address, 0, word))
    for word in public.io.output_words:
        total = total - _inverse_of(relation, _memory_tuple(1, word.addr, word.clock, word.value))
    if public.completion_kind == "halt_flag":
        total = total - _inverse_of(
            relation,
            _memory_tuple(
                1, public.completion_address, public.completion_clock, public.completion_value
            ),
        )
    return total


def program_access_sum(public: PublicData, relations: dict[str, Relation]) -> QM31:
    """Only the unretired-self-loop completion contributes here, and this
    reimplementation refuses that case rather than guessing.

    The sentinel's contribution is the DECODED program tuple of the word at
    `final_pc`, so computing it needs a second RV32IM decoder.  Writing one to
    close a term that is zero for every halt-flag statement would add a large
    unchecked surface to a checker whose value is that it is small enough to
    review.  A guest that ends on the sentinel is out of scope, loudly.
    """
    if public.completion_kind == "halt_flag":
        return QM31()
    raise UnsupportedStatement(
        f"completion kind {public.completion_kind!r} needs a decoded program tuple; "
        "this checker covers halt-flag completions only"
    )


def public_boundary(public: PublicData, relations: dict[str, Relation]) -> QM31:
    if public.program_root is None:
        raise UnsupportedStatement("the statement declares no program root")
    return (
        registers_state_sum(public, relations)
        + merkle_sum(public, relations)
        + memory_access_sum(public, relations)
        + program_access_sum(public, relations)
    )


@dataclass
class Closure:
    """The whole ledger, with each half labelled by how much it is trusted."""

    recomputed_opcode: tuple[tuple[str, int, QM31, QM31], ...]
    infra_total: QM31
    boundary: QM31
    total: QM31

    def disagreeing_claims(self) -> list[str]:
        return [
            f"{family}[{index}]: claim {claimed.as_tuple()} but the committed "
            f"trace gives {recomputed.as_tuple()}"
            for family, index, claimed, recomputed in self.recomputed_opcode
            if claimed.as_tuple() != recomputed.as_tuple()
        ]

    def is_closed(self) -> bool:
        return self.total.is_zero() and not self.disagreeing_claims()


def closure(dump: Dump, prepared: dict[int, Prepared]) -> Closure:
    recomputed: list[tuple[str, int, QM31, QM31]] = []
    running = QM31()
    for component in dump.components:
        value = opcode_claim(prepared[component.index], dump.relations)
        recomputed.append(
            (component.family, component.index, dump.claim_for(component.index), value)
        )
        running = running + value
    infra_total = QM31()
    for claim in dump.infra_claims:
        infra_total = infra_total + claim.total
    boundary = public_boundary(dump.public, dump.relations)
    return Closure(
        recomputed_opcode=tuple(recomputed),
        infra_total=infra_total,
        boundary=boundary,
        total=running + infra_total + boundary,
    )
