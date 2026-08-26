# 2026-08-12 — JALR production SSOT

## Status

JALR is a live production typed authority. One fixed capability now owns
architectural retirement, witness construction, direct constraints, ordered
relations, and formal extraction. The legacy executor fails closed, and the
retired handwritten evaluator survives only as an explicitly named independent
test oracle. Exact proof A/B, independent verification, and required-live Sail
all passed on the same indirect-control retirement stream.

## Fixed authority

`typed_jalr_authority.zig` binds the authenticated typed graph to a pointer-free
executable capability:

```text
main columns:       41
direct roots:       23 (22 family roots plus placement)
ordered relations: 18
lookup batch size:  2
protocol opcode:    34
authority digest:   1570bb5a80ad2929a39c3962577bae9f9caea9ccf722158e351224d3b299de98
```

The authority pins signed 12-bit I-immediate reconstruction, wrapping
`rs1 + immediate`, architectural bit-zero clearing, four-byte zkVM target
alignment, the 30-bit program-commitment address domain, the `pc + 4` link,
x0 discard, and source-before-destination ordering for `rd == rs1`.

The aggregate production gate found one subtle pre-admission defect that the
private value differential could not expose: the destination access clock was
written as `source_clock + 1`, while the authored access schedule derives phase
two directly from the instruction clock. They are field-equal, but have
different symbolic DAG identities. The fixed evaluator now uses the authored
phase-two form, so typed construction and production lowering agree exactly at
the expression graph as well as at every evaluated value.

## Failure-atomic retirement

The 88-byte retirement plan authenticates the complete I-type word, trace
position, pre-retirement PC, source and destination values, the decoder's
trace-visible diagnostic `rs2` snapshot, raw and effective predecessor clocks,
target, link, and branch marker. Source publication precedes destination
publication, including aliases, so an indirect target always observes the
pre-write source value.

All capacity work precedes logical mutation. Any allocator return is followed
by complete CPU, trace, and state-chain revalidation; the warm fused path
allocates nothing. Compile-time ceilings keep the plan at or below 96 bytes and
the single-use prepared token at or below 16 bytes.

## Production evidence

The canonical AIR root passes 678/678 tests in Debug and ReleaseSafe. The
runner root passes 336/336 in Debug, ReleaseSafe, and ReleaseFast. Formal
production extraction agrees for all 17 families across 32 deterministic
trials. The exhaustive JALR rigidity lane performs 6,918 admissibility
evaluations within its 8,000-evaluation budget.

The complete ReleaseFast AIR root reached and passed every JALR test, then
reported 677/678 because the unrelated BASE_ALU_REG witness benchmark sampled
below its retained-throughput threshold. No threshold was weakened and the
failure is not attributed to JALR.

Final paired ReleaseFast medians were:

| Route | Typed/production | Retired legacy | Legacy / typed |
| --- | ---: | ---: | ---: |
| production direct AIR | 11,350,334 ns | 11,849,000 ns | 1.0439x |
| production lookup construction | 10,146,959 ns | 32,095,459 ns | 3.1631x |
| runner retirement | 229,375 ns | 353,000 ns | 1.5390x |

The separate witness writer scaling gate remained at parity across 1,024,
16,384, and 262,144 rows (0.9990x, 0.9997x, and 0.9995x in the final run). All
production hot-path gates enforce at least 0.97x retained throughput and consume
their complete outputs to prevent dead-code-elimination benchmarks.

Generated and retained-legacy arms produced identical statements, interaction
claims, terminal transcript state, and serialized proof bytes, and each proof
was independently verified. With the pinned Sail oracle required to answer on
that exact guest, the receipt was:

```text
proof bytes: 59502
proof sha256: bdc91a1290cac3ac66500581fa4f414621f90f5fef67af1aa3c0a2a4c0354f81
transcript:   d0fc1b48bfdcabecf41cd0b3953825a85d19aa08eba4306b8b94b129c584c0dd
draws:        1
Sail:         required and answered; exact retirement stream agreed
```

## Closed promotion checklist

- Generated retirement owns JALR; the legacy executor rejects it atomically.
- Witness generation, direct roots, relations, and formal extraction route
  through the pinned typed authority.
- The handwritten semantic module is absent from production and explicitly
  named as a test oracle.
- Every signed I-immediate, encoded register field, x0 case, alias class,
  target bound, stale state, and allocation boundary is covered.
- Canonical roots and inventory include the authority and retirement gates;
  the private root has been removed.
- Proof A/B, independent verification, exact transcript/bytes, required-live
  Sail, exhaustive corpus, and performance gates are closed.

The compatibility manifest was audited but intentionally not regenerated while
other families are migrating. Its sole mismatch is the already-known concurrent
BASE_ALU_REG formal-export digest; JALR introduces no artifact mismatch.
