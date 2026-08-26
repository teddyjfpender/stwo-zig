# 2026-08-05 — M2 complete degree audit

## Question

Does the typed shadow program reproduce the complete algebraic degree and
quotient geometry of the current RISC-V AIR, including lookup interactions, or
only the visible degree of direct symbolic roots?

## Context and exact revisions

- Branch: `feat/typed-air-precompiles`.
- Production shadow boundary: commit `3c5fad5a`.
- Expression importer and independent logical-degree oracle: commit
  `18adac75`.
- Production authorities inspected:
  `air/logup.zig`, `air/lookups/opcode_component.zig`,
  `air/semantic_eval.zig`, and the vendored stwo constraint-framework degree
  evaluator.
- Scope: the 17 values of `runner/trace.zig::OpcodeFamily`.

## Commands or experiment

The implementation constructs the exact complete
`constraint_program.Builder(symbolic.Scalar)` output once per family, imports
it through `shadow_program.buildProduction`, runs `protocol_degree.analyze`, and
then renders `protocol_report.collect` in stable enum/schema order.

Primary verification command:

```sh
zig build test --build-file src/frontends/riscv/build.zig \
  -Doptimize=ReleaseFast -j2
```

The test compares the minimum inferred direct bound to
`semantic_eval.constraintLogDegreeBound` and the inferred interaction bound to
a real `OpcodeLookupComponent.maxConstraintLogDegreeBound` for every family.
Focused vectors separately exercise paired nonlinear denominators, nonlinear
singletons, numerator-dominating products, quotient-expansion thresholds, log
overflow, malformed report summaries, and writer allocation failures.

## Observations

The production recurrence is:

```text
(S - S_prev + is_first * claimed) * d1 * d2
    - n1 * d2 - n2 * d1
```

`S`, `S_prev`, and `is_first` are degree-one columns. Row shifting does not
raise degree. The claimed sum and relation challenges are transcript constants
of degree zero. Each relation denominator has the maximum degree of its tuple
fields. A single-entry batch substitutes degree-zero `n2 = 0, d2 = 1`.

After division by a trace-domain vanishing polynomial, final algebraic degree
`d` requires `ceil(log2(max(1, d - 1)))` additional log-degree bits. Thus a
degree-two constraint needs no expansion and a degree-three constraint needs
one bit.

Across independently compiled families, the pinned report records:

| Measure | Result |
| --- | ---: |
| Families | 17 |
| Main columns, summed independently | 644 |
| Production symbolic nodes | 3,051 |
| Canonical typed nodes | 3,049 |
| Direct roots | 545 |
| Ordered lookup entries | 242 |
| Interaction batches | 155 |
| M31 coordinates of QM31 interaction columns | 620 |
| Maximum direct degree | 3 |
| Maximum lookup numerator degree | 2 |
| Maximum relation denominator degree | 2 |
| Maximum interaction degree | 3 |

Ten families have maximum direct degree three. LUI, AUIPC, JALR, JAL, MUL,
MULH, and FENCE have maximum direct degree two. Every current interaction is
degree three. The semantic backend's uniform `trace_log_size + 1` declaration
is therefore safe but conservative for those seven direct families; the lookup
backend's identical declaration is exact for all families.

The pairing policy exposes a normal AIR tradeoff. For two linear-denominator
fractions, a single cumulative column has a degree-three transition, whereas
separate singleton columns would each have degree two. Pairing reduces width
while increasing quotient-domain capacity. “Degree three” describes a local
polynomial identity; it is not `O(N^3)` proving complexity. Per-row evaluation
remains constant work, and large-trace proving remains driven by
quasi-linear transforms and commitments with degree-dependent constants.

## Interpretation

The shadow abstraction introduces no algebraic-degree inflation. It reconstructs
the current protocol geometry and makes the existing width/degree decisions
visible before compatibility lowering. The seven quadratic direct families are
a possible future tuning opportunity, but the shared lookup layer still needs
degree-three capacity and no production bound should change without end-to-end
proof and performance measurements.

The report is useful as a structural baseline: a later source edit that changes
root count, lookup order, batching, relation dependencies, or any degree maximum
now creates a byte-visible artifact diff.

## What this does not establish

- It does not prove RISC-V architectural semantics; Sail and existing soundness
  ledgers remain authoritative.
- It does not establish a physical layout identity or a generated lowering.
- It does not activate the typed IR in production proving or verification.
- It does not show that tightening a family-specific direct bound improves total
  proving time.
- It does not benchmark a different lookup batching policy.

## Decisions/tasks affected

- Accept ADR-0011.
- Complete A-004 and A-005, closing M2.
- Activate A-006 as the first M3 compatibility-layout task.
- Preserve degree/batching optimization as an explicit later protocol and
  performance decision.
