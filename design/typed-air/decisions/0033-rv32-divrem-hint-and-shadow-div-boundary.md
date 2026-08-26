# ADR-0033 — RV32 DIV/REM hint and shadow DIV boundary

**Status:** accepted
**Date:** 2026-08-10

**Classification:** deterministic hint contract and direct-AIR shadow pilot;
native lookup effects and production authority remain open

## Context

RV32 `DIV`, `DIVU`, `REM`, and `REMU` share one quotient/remainder witness but
have two architectural exceptional classes. Division by zero and signed
`INT_MIN / -1` cannot be left to host-language arithmetic because their
results are fixed by the ISA and the latter may trap or overflow in a naive
implementation. Regular signed division must truncate toward zero, with a
remainder carrying the dividend's sign.

The production DIV family has 67 main columns, 79 direct roots, and 25 ordered
lookups. Its product carries and signed high-limb checks are derived field
expressions whose integer bounds are proved by the same fixed-table lookups
that consume them. The current typed effect validator accepts only bounds
known from expression types. Treating those expressions as `uint11`, `uint7`,
or `uint20` through an unchecked cast would turn the lookup premise into an
author assertion; adding columns would break compatibility.

## Decision

### One closed recipe computes both architectural outputs

Add `rv32_divrem@1` to the closed hint registry with input types
`(word32, word32, bit)` and output types
`(word32, word32, bit, bit)`. The input bit selects signed semantics. The two
output bits identify zero-divisor and signed-overflow classes; they are
mutually exclusive by construction.

The algorithm is exact:

| Class | Quotient | Remainder |
| --- | --- | --- |
| divisor is zero | `0xffff_ffff` | dividend |
| signed `0x8000_0000 / 0xffff_ffff` | `0x8000_0000` | `0` |
| other unsigned | `lhs / rhs` | `lhs % rhs` |
| other signed | truncation toward zero | signed remainder |

The hint is deterministic witness generation only. AIR constraints and lookup
effects remain the proof authority for every output and exceptional flag.

### Direct DIV authorship may land before native effect refinement

The E-011 pilot independently authors the exact 67-column direct program and
all 79 roots at maximum degree three. It retains the 25 production lookups in
one fixed-width, allocation-free compatibility record that binds exact kind,
schema, role, numerator, field order, arity, access ordinal, and batch order.
The direct semantic digest is
`788c3718b4ec661d7ec03516ad97364da5e75139d44bb40bcc523f094b367482`;
the separate lookup-record identity is
`b0d170c39e609b4f11d8f9a51f2ca2be812dc087094e6c606179d805143f80bd`.

This record is explicitly not `Arena.effects`, is not eligible for canonical
native lowering, and does not satisfy a fully typed DIV migration. It is an
exact shadow oracle used to validate the direct algebra and expose the missing
refinement boundary without weakening it.

### The missing capability must be proof-carrying

Native DIV effects require a closed constraint-proven range refinement for at
least:

- each product carry as `uint11`;
- `q[3] - 128 * q_sign` as `uint7`; and
- `lt_diff - 1` as `uint20`.

Any accepted refinement must bind the exact expression, proving constraint or
fixed-table premise, liveness, and target type; reject circular or
self-justifying evidence; advance canonical identity; and add no physical
column. Until that capability exists, unsafe casts and native-effect claims
are forbidden.

## Validation evidence

The deterministic corpus contains 73 operand pairs across every opcode for
exactly 292 rows. It covers zero divisors, signed overflow, all signed operand
quadrants, quotient/remainder boundaries, destination zero and aliases,
inverses, absolute-value and comparison witnesses, carry ranges, and selector
behavior. Every direct root and every lookup numerator/field replays equal to
the production program. A forged quotient demonstrates the important split:
direct equations can remain satisfied while the fixed carry-range premise
rejects.

Construction rollback is allocation-failure tested, and prepared row replay
allocates nothing. The focused suite passes in Debug, ReleaseSafe, and
ReleaseFast. Production witness selection, commitments, transcript, and proof
authority are unchanged.

## Performance invariants

- The recipe performs fixed-width integer operations and allocates nothing.
- The shadow program preserves 67 columns, 79 roots, 25 lookups, batch size
  one, and maximum degree three.
- No additional range witness or compatibility column is permitted merely to
  satisfy the typed API.
- Lookup replay and identity construction are setup/test work, not a
  production row-loop path.

## Consequences

E-010 has a complete ISA-exact hint contract, and E-011 has a reviewable exact
direct pilot plus a precise soundness blocker. The distinction prevents a
large parity test suite from being mistaken for a fully typed effect program.
The next DIV authoring task is the proof-carrying refinement and replacement
of the inline record with native effects, followed by a direct-to-column
witness and production activation gates.

## Rejected alternatives

- Host `/` and `%` without explicit exceptional dispatch: behavior is not the
  RV32 contract for all inputs.
- Separate DIV and REM recipes: they duplicate the same witness authority and
  can disagree on exceptional classes.
- Unchecked field-to-bounded casts: they assume exactly what range lookups must
  prove.
- Extra committed carry/range columns: they break the compatibility geometry
  and increase prover work.
- Calling the inline record native typed effects: canonical lowering and
  validator ownership would be false.

## Revisit when

Revisit after the proof-carrying refinement has native serialization,
adversarial validation, exact lowering parity, and no-column/no-degree
regressions, or if a different closed refinement calculus proves the same
facts more simply.
