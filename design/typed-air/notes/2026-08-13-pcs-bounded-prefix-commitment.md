# 2026-08-13 — bounded-prefix Poseidon PCS commitment

## Result

The recursion leaf's Poseidon PCS commitment now keeps the largest complete
streaming-state prefix that fits a hard 96 MiB budget and expands only the
remaining high-domain tail into the final leaf layer. This restores the native
prover's fast single-pass absorption behavior without retaining the former
unbounded state or replaying the complete lower-domain column set.

On the real frozen-V1 RISC-V leaf, native proving measured 12.021 seconds. The
prior stable path measured about 12.464 seconds, while an attempted generic
batched-leaf fallback measured 127.273 seconds on the same proof shape. The
accepted implementation therefore removes the 10.2x regression and is 3.6%
faster than the earlier stable sample. These are single-run engineering
measurements, not a normative performance receipt.

## Algorithm

Poseidon leaf construction is stateful: short columns affect every later leaf.
Rebuilding those contributions independently at the final domain makes memory
small but repeats a large amount of absorption work. Retaining state through
the maximum column height is fast but makes the live state allocation scale
with the complete maximum domain.

The accepted path chooses the largest complete height group whose streaming
state fits the fixed byte budget. It:

1. absorbs every column through that prefix exactly once;
2. maps the retained prefix state into the final leaf domain;
3. absorbs only columns above the prefix directly into the mapped leaves; and
4. frees prefix state before Merkle layer construction.

The cut is made only between complete height groups. Column order and Poseidon
state transitions are unchanged, and the tail never reabsorbs prefix columns.
An exact allocation/replay ledger records the selected logs, prefix and tail
column counts, live bytes, and repeated tail absorptions.

## Production-shape evidence

The real leaf emitted these exact ReleaseFast histograms:

| Tree | Column-height groups | Prefix | Tail | Prefix state | Leaf layer | Leaf-phase peak |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Main, 625 columns | `5:164, 9:455, 16:1, 17:1, 19:1, 20:1, 21:2` | log 20, 623 columns | 2 | 72 MiB | 64 MiB | 136 MiB |
| Interaction, 200 columns | `5:156, 9:20, 16:4, 17:4, 19:4, 20:4, 21:8` | log 20, 192 columns | 8 | 72 MiB | 64 MiB | 136 MiB |

Both trees report zero repeated tail absorptions. The previous full-state leaf
phase retained 144 MiB of state beside the same 64 MiB leaf layer, for a
208 MiB peak. The accepted path saves exactly 72 MiB, or 34.6%, at this phase.

The complete inactive leaf still proves, serializes, passes allocation-free
ingress, independently verifies, adapts transactionally to the 2,111,588-byte
fixed wire, and rejects the 21-case adapter mutation fleet. Its measured
native timings were:

| Phase | Time |
| --- | ---: |
| Prove | 12.021 s |
| Serialize | 1.773 ms |
| Ingress preflight | 0.863 ms |
| Decode | 5.040 ms |
| Independent verify | 6.405 s |
| End to end | 18.445 s |

## Root parity and performance gate

The focused native PCS root passes in Debug, ReleaseSafe, and ReleaseFast for
generic batched leaves, the former full-streaming construction, and the new
bounded-prefix construction under a forced cap. The complete native PCS suite
passes 27 tests in Debug and ReleaseFast.

An opt-in ReleaseFast benchmark uses the representative 625-column mixed-height
shape with domain and cap scaled together from log 21/96 MiB to log 16/3 MiB.
After one warm-up, the median of three runs measured:

| Construction | Median | Relative to old full state |
| --- | ---: | ---: |
| Old full streaming state | 100.455 ms | 1.000x |
| Rejected generic batched leaves | 2,965.355 ms | 29.52x |
| Bounded prefix | 65.675 ms | 0.654x |

The new path is 34.6% faster than the former path and 45.15x faster than the
rejected fallback on this replay-sensitive shape. The opt-in gate rejects a
regression greater than 10% against the old full-state implementation.

## Reproduction

```text
STWO_ZIG_RUN_POSEIDON_PREFIX_BENCH=1 \
python3 scripts/zig_protocol_test.py \
  src/tests/native/prover/pcs/mod.zig -OReleaseFast

STWO_ZIG_PCS_COLUMN_HISTOGRAM=1 \
zig build test-riscv-recursion-poseidon-leaf -Doptimize=ReleaseFast
```

Histogram and benchmark output are opt-in so production proving and ordinary
test gates do not acquire formatting, synchronization, or timing overhead.

## Boundary

This is a prover implementation optimization. It does not alter the AIR,
statement, transcript, commitment root, proof bytes, FRI profile, or security
parameters. The 12.021-second result is a development observation from the
mutable branch; a clean, fresh-process benchmark cohort remains required for a
promotion claim.
