# ADR-0003 — One-proof precompiles before separate proof recursion

**Status:** accepted
**Date:** 2026-08-04

## Context

The prover already supports heterogeneous components and shared LogUp
relations. Core and precompile components inside one transcript can share
relation challenges and close one global sum.

Separately proving components introduces a new obligation: both leaf proofs
must expose relation summaries that are demonstrably about the same challenges,
schema, calls, and statement. Two locally valid proofs do not create that
binding automatically.

## Decision

Implement the first guest precompile as another component inside one proof and
one transcript. Parallelize trace, interaction, and quotient work within that
statement.

Design cross-proof summaries and two-to-one recursive aggregation only after
the one-proof component ABI, multiplicity rules, and statement identity are
stable.

## Consequences

- The first performance experiment reuses current prover and verifier
  machinery.
- Relation soundness is easier to review.
- The design still gains component specialization and substantial parallelism.
- It does not initially give independently distributable proofs or a
  constant-sized recursively aggregated final proof.

## Rejected alternatives

- **Start with recursive leaves:** rejected because it couples the DSL,
  precompile ABI, relation summary, recursive verifier, and aggregation
  protocol in one unreviewable step.
- **Unrelated leaf LogUp sums:** rejected as unsound composition.

## Revisit when

The guest Poseidon component proves and verifies under one transcript, mutation
tests cover call closure, and a reviewed relation-summary ADR exists.
