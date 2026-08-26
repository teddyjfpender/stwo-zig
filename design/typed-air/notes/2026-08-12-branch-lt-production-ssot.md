# 2026-08-12 — BRANCH_LT production SSOT

## Status

BLT/BLTU/BGE/BGEU are live production typed authorities. One authenticated,
pointer-free capability owns architectural retirement, physical witness
projection, direct roots, ordered relation events, and formal extraction. The
generated-retirement registry owns all four decoded opcodes, the legacy
executor fails closed without mutation, and the handwritten semantic evaluator
is retained only as an explicitly named differential test oracle.

## Fixed authority

`typed_branch_lt_authority.zig` authenticates the complete typed graph and
physical witness recipe to this fixed geometry:

```text
main columns:       37
direct roots:       33 (32 family roots plus placement)
ordered relations: 11
lookup batch size:  2
protocol opcodes:   BLT=29, BLTU=31, BGE=30, BGEU=32
authority digest:   77e729cdac93b45bfd71ecfb8f7afa9411a1db09f9caf567c9fd87d460412a95
```

The authority owns signed and unsigned comparison, strict-less versus
greater-or-equal selection, equality, selected sequential/taken targets, the
30-bit program-address domain, four-byte selected-target alignment, x0 and
same-source aliases, two ordered read-only register accesses, and the exact
range evidence for shifted sign bytes and the first positive difference.

Production direct and lookup facades use statically selected BRANCH_LT seams
after family admission. PC and selected-target scalar views are exposed only
after the exact 37-column row shape has been checked. This removes generic
constructor dispatch from the hot path without introducing a second semantic
implementation.

## Failure-atomic retirement

The 80-byte plan authenticates the complete B-type word: all immediate bits,
both register fields, all four funct3 variants, and the decoder's trace-visible
diagnostic `rd`. It stages source values, alias-aware raw and effective
predecessor clocks, closed-form gap counts, PC, target, and physical branch
marker before any logical publication. The single-use prepared token remains
within its 16-byte cap.

Source one publishes before source two. For aliased sources, source two's
authenticated predecessor is source one's newly emitted event. Every fallible
sink is reserved and all live state is revalidated before the transaction
publishes its two accesses, PC, and trace row. Allocation failures and stale
CPU, trace, plan, or tracker snapshots expose no prefix; the warm fused path
allocates nothing.

The encoding gate covers all four opcodes, all 4,096 representable even B
immediates, all 32 × 32 source-register encodings, and every funct3 variant.
Separate cases cover signed and unsigned extrema, equality, selected and
unselected 2-mod-4 targets, x0, aliases, target bounds, malformed words,
clock-gap boundaries, stale plans, and induced allocation failure.

## Production evidence

The canonical AIR root passes 693/693 tests in Debug and ReleaseSafe. The
runner root passes 355/355 in Debug, ReleaseSafe, and ReleaseFast. Formal
production extraction agrees for all 17 families across 32 deterministic
trials. The exhaustive BRANCH_LT rigidity lane performs 6,918 admissibility
evaluations within its 8,000-evaluation budget.

Stabilized focused ReleaseFast medians, with complete outputs consumed to
prevent dead-code elimination, are:

| Route | Typed/production | Retired legacy | Legacy / typed |
| --- | ---: | ---: | ---: |
| production direct AIR | 16,614,250–17,379,166 ns | 18,420,833–19,247,833 ns | 1.1073–1.1132x |
| production lookup construction | 5,807,792–6,186,583 ns | 14,182,416–14,988,208 ns | 2.3772–2.4420x |
| runner retirement | 221,417–226,833 ns | 337,500–359,125 ns | 1.5243–1.5832x |

The independent witness-scaling gate measures 1.0739x, 1.0642x, and 1.0620x
legacy throughput at 1,024, 16,384, and 262,144 rows. Every production route
retains the strict 0.97x throughput floor without a waiver.

The complete ReleaseFast AIR root reached and passed every BRANCH_LT gate,
sampling 1.1090x direct, 3.5812x lookup, and 1.0355x--1.0536x witness
throughput in that noisier aggregate run. The root finished 691/693: only the
already-noisy BRANCH_EQ lookup and JAL direct microbenchmarks sampled below
their thresholds. Neither failure is attributed to or waived by this
promotion.

Generated and retained-legacy arms produced identical statements,
interaction claims, terminal transcript state, and serialized proof bytes;
both proofs independently verified. The pinned Sail oracle was required to
answer on the same guest:

```text
proof bytes: 56132
proof sha256: e9baeb3697eec792fbf7a30aff4ae16b279dae4d7d41e67d7df0f1c39bc55f44
transcript:   f21881aeb03399e0cbb3b70800eec988b391ca765678c5f97f472aabc660d3c5
draws:        1
Sail:         required and answered; exact retirement stream agreed
```

## Closed promotion checklist

- Generated retirement owns BLT/BLTU/BGE/BGEU, and the legacy executor rejects
  all four without mutation.
- Retirement, witness projection, direct roots, relations, and formal
  extraction route through the same pinned typed authority.
- The handwritten semantic evaluator is absent from production and explicitly
  named as a retained test oracle.
- Canonical roots and inventory include authority and retirement gates; the
  private root has been removed.
- Exact polynomial and ordered-relation parity, exhaustive encoded-word
  coverage, allocation and stale-state negatives, formal extraction,
  exhaustive witness rigidity, proof A/B, independent verification,
  required-live Sail, and strict performance gates are closed.

The compatibility/refinement golden source closure still names the retired
semantic path. It is intentionally not regenerated while other family
identities are concurrently migrating; that repository-level artifact update
remains one coordinated final admission task and is not a production escape
hatch for BRANCH_LT.
