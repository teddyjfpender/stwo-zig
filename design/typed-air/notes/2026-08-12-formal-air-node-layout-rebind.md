# Formal AIR programs: reviewed node-layout rebind

Status: implemented and mechanically gated on 2026-08-12.

## Question

Moving all RV32IM families to the typed authority changes the first-use order
in which the symbolic recorder interns shared expressions. The resulting AIR
programs can therefore assign different integer IDs to identical expression
trees. How can the existing Lean certificates keep their reviewed node layout
without treating a serializer detail as a semantic change?

## Decision

The formal generator admits an unsigned production program only after
normalizing it to a reviewed topological node layout. The normalizer is
fail-closed and deliberately stricter than polynomial equivalence:

1. recursively hash every supported expression tree (`col`, `const`, `neg`,
   `add`, `sub`, and `mul`);
2. require exactly the reviewed structural-expression set, with no duplicate,
   malformed, unknown, or non-topological node;
3. remap the node table and every expression reference into the reviewed
   layout; and
4. require the complete normalized unsigned AIR object to have the reviewed
   canonical SHA-256.

The final byte comparison authenticates more than the expressions. Column
metadata, fixed tables, selector identity, active-row expression, constraint
and lookup order, lookup roles and tuples, projection events, and `next_pc`
must all remain exact. A candidate with the same node set but different event
semantics is rejected.

The 46-program receipt is
`formal/riscv-refinement/air-program-node-layout-v1.json`. It records the
reviewed revision, ordered structural node hashes, event geometry, and the
canonical unsigned digest for every RV32IM selector. Source identity and the
signed content digest are attached only after normalization, so the generated
formal inputs continue to bind the current typed implementation rather than
the historical source closure.

## Gates

```text
python3 scripts/riscv_air_program_layout.py check \
  --candidate-dir zig-out/refinement-air-ir-v2

python3 -m unittest scripts.tests.test_riscv_air_program_layout

python3 scripts/riscv_refinement.py check-generated \
  --no-export-air \
  --air-ir-dir zig-out/uniqueness-ir \
  --air-program-ir-dir zig-out/refinement-air-ir-v2 \
  --reuse-committed-sail-evidence
```

The adversarial tests cover event-root substitution, structural-expression
drift, malformed and unknown nodes, receipt tampering, and attempted rewriting
of an already signed candidate.

## Claim boundary

This mechanism establishes exact compatibility between current production
exports and the reviewed formal serialization after a semantics-preserving
node permutation. It does not claim that arbitrary polynomially equivalent AIR
programs are interchangeable, and it does not replace witness, cross-row,
lookup-closure, Sail, or proof-system checks. Those remain separate gates.
