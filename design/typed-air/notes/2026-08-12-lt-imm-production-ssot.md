# 2026-08-12 — LT_IMM production SSOT

## Status

SLTI/SLTIU are live production typed authorities. One authenticated,
pointer-free capability owns architectural retirement, physical witness
projection, direct roots, ordered relation events, and formal extraction. The
generated-retirement registry owns both decoded opcodes, the legacy executor
fails closed without mutation, and the handwritten semantic evaluator is
retained only as an explicitly named differential test oracle.

## Fixed authority

`typed_lt_imm_authority.zig` authenticates the complete typed graph and
physical witness recipe to this fixed geometry:

```text
main columns:       37
direct roots:       33 (32 family roots plus placement)
ordered relations: 11
lookup batch size:  2
protocol opcodes:   SLTI=5, SLTIU=6
authority digest:   bfe5a4896da341e2efd83feaf82c2ac289937712a3d2971162f3d783a25b491f
```

The authority owns signed and unsigned 32-bit comparison against the exact
sign-extended I immediate, equality, first-differing-byte selection, positive
difference evidence, x0 result discard, source/destination aliases, the
ordered read-then-write register chain, and the exact immediate/range lookup
tuples. Production direct and lookup facades use statically selected LT_IMM
seams after family admission, avoiding a second dynamic constructor dispatch
without introducing another semantic implementation.

## Failure-atomic retirement

The 64-byte compact transaction and 80-byte plan authenticate the complete
I-type word: opcode/funct3, all twelve immediate bits, `rd`, `rs1`, and the
decoder's trace-visible immediate-low diagnostic `rs2`. The plan stages the
source and prior destination values, alias-aware raw/effective predecessor
clocks, closed-form gap counts, result visibility, PC, and trace geometry
before any publication. The single-use prepared token is 16 bytes.

Source publication precedes destination publication. When `rd == rs1`, the
destination predecessor is the newly emitted source access. Every fallible
sink is reserved and all live state is revalidated before the transaction
publishes its two accesses, register result, PC, and trace row. Allocation
failure and stale CPU, trace, plan, or tracker state expose no prefix; the warm
fused path allocates nothing.

Exact word admission exhausts both opcodes, all 4,096 signed immediates, and
all 32 × 32 destination/source encodings: 8,388,608 accepted words. Separate
cases cover signed/unsigned extrema, equality, x0, aliases, malformed words,
clock-gap boundaries, stale plans, and induced allocation failure.

## Production evidence

The canonical AIR root passes 702/702 tests in Debug and ReleaseSafe. The
runner root passes 365/365 in Debug, ReleaseSafe, and ReleaseFast. Focused
ReleaseFast AIR and runner roots pass 27/27 and 13/13. Formal production
extraction agrees for all 17 families across 32 deterministic trials. The
exhaustive LT_IMM rigidity lane performs 6,918 admissibility evaluations within
its 8,000-evaluation budget.

Focused ReleaseFast medians consume complete outputs to prevent dead-code
elimination:

| Route | Typed/production | Retired legacy | Legacy / typed |
| --- | ---: | ---: | ---: |
| production direct AIR | 18,862,208–19,198,833 ns | 21,333,292–21,718,208 ns | 1.1262–1.1312x |
| production lookup construction | 5,674,833–6,556,208 ns | 27,519,125–30,457,167 ns | 4.6455–4.9150x |
| runner retirement | 232,333 ns | 287,708 ns | 1.2383x |

The independent witness-scaling gate measures 1.0372x, 1.0265x, and 1.0504x
legacy throughput at 1,024, 16,384, and 262,144 rows. Every production route
retains the strict 0.97x throughput floor without a waiver.

The complete ReleaseFast AIR root reached and passed every LT_IMM gate,
sampling 1.1360x direct, 4.7437x lookup, and 1.0095x--1.0155x witness
throughput in that noisier aggregate run. The root finished 699/702 only on
unrelated pre-existing microbenchmark samples. No such failure is attributed
to or waived by this promotion.

Generated and retained-legacy arms produced identical statements,
interaction claims, terminal transcript state, and serialized proof bytes;
both proofs independently verified. The pinned Sail oracle was required to
answer on the same guest:

```text
proof bytes: 55680
proof sha256: adc29b4eb673320042dbbc08a7ab87945ea19636ddb6ce65d624b5db7d043726
transcript:   9ed39ee4acb48175243824e4212318a51d821ac30eed565494c26b0339e69b05
draws:        1
Sail:         required and answered; exact retirement stream agreed
```

## Closed promotion checklist

- Generated retirement owns SLTI/SLTIU, and the legacy executor rejects both
  without mutation.
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
hatch for LT_IMM.
