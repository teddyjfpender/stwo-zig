# Tensor frontend: CPU prover performance (stream `perf`)

Branch `codex/tensor-perf`, based on the tensor branch head `cc5ac62c9`.
Host: M4 Max (12 P + 4 E cores), AC power, shared with other agents (numbers
are medians of 3 alternating runs; single-run noise is ~5-10%).

**The protocol is unchanged.** Every change here is prover-side: it produces
the same proof bytes as before (or, for the split-eq prover with a false
claim, a different but still rejected proof; see §Soundness). The golden
proof digests in `src/tensor/proof_digest.zig` were recorded on the
unmodified prover and still match. They cover an MLP and a product
statement, with 1 and 5 threads.

## Results

Default bench mode: one proof per process, system allocator. This is what
`tensor-bench` printed before.

| bench | before prove | after prove | speedup |
|---|---|---|---|
| product 20, 1 thread | 0.337 s (321 ns/entry) | 0.136 s (130 ns/entry) | 2.5x |
| product 20, 12 threads | 0.067 s | 0.032 s | 2.1x |
| mlp 8 10 11, 12 threads | 0.176 s | 0.118 s | 1.5x |
| mlp 9 11 12, 12 threads | 0.583 s (23.2 ns/weight) | 0.372 s (14.8 ns/weight) | 1.57x |

Steady state means the prover runs repeatedly in one process with the
recycling allocator (`TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3`, best of 3):

| bench | before (single shot) | after (steady state) |
|---|---|---|
| mlp 8 10 11 | 0.176 s | 0.077 s |
| mlp 9 11 12 | 0.583 s | 0.212 s (8.4 ns/weight, 2.75x) |

Proof sizes and verify times are unchanged: product 20 is 323,352 B and
1.6 ms; mlp 9 11 12 is 3,859,600 B and 14 ms.

Per-stage breakdown in seconds, single shot (the before/after pairs are
separated by `→`):

| stage | product 20 / 1 thr | product 20 / 12 thr | mlp 9 11 12 / 12 thr | mlp 9 11 12 steady |
|---|---|---|---|---|
| accumulators (recompute) | – | – | ≈0.07 → 0 (reused) | 0 |
| witness commit | 0.168 → 0.062 | 0.026 → 0.014 | 0.110 → 0.067 | 0.027 |
| GKR (input+build+sumcheck) | – | – | 0.204 → 0.202 | 0.108 |
| op sumchecks | 0.053 → 0.017 | 0.012 → 0.006 | 0.024 → 0.011 | 0.009 |
| batch sumcheck | 0.102 → 0.044 | 0.024 → 0.008 | 0.124 → 0.045 | 0.025 |
| witness open (PoW) | 0.014 → 0.013 | 0.003 → 0.005 | 0.008 → 0.007 | 0.007 |
| weight fold + open | – | – | 0.017 → 0.017 | 0.013 |

GKR breakdown for mlp 9 11 12, steady state, 12 threads: input 2 ms, layer
build 15 ms, layer sumchecks 87 ms. On 1 thread these are 23, 142 and 630 ms.

## What changed (in commit order)

1. **Proof digest pinning** (`proof_digest.zig`). A canonical Blake2s over
   every transmitted value, with golden values from `cc5ac62c9` and a 1-vs-5
   thread equality check.
2. **SIMD Merkle hashing** (`pcs.buildTree`). Leaves hash four contiguous
   columns per call with stwo's `Blake2sHasher.hashEqual4WithMode` (4-lane
   NEON). Internal levels use `hashFixedSingleBlock4`, because the children
   of four consecutive parents are four contiguous 64-byte blocks. The
   digests are identical Blake2s. Witness commit on 1 thread went from 0.164
   to 0.062 s.
3. **Packed sumcheck kernels** (`sumcheck.roundChunkT`/`foldChunkT`). Each
   step processes `PACK_WIDTH = 4` indices with `PackedQM31`. This now
   includes the region whose high partner is an implicit zero beyond
   `active`: there the fold becomes `(1-r) f`. That region was most of
   round 0 for a table that is 60% full.
4. **Witness batch sumcheck** (`batch.zig`):
   - Round 0 runs with the witness in the base field (packed M31×QM31). It
     folds straight into E's upper half, which is free after round 0 (each
     index reads before it writes), so there is no full-table QM31 copy and
     no extra buffer.
   - `fillRegion` builds each tensor's E block in one write pass:
     `sum_c gamma_c eq(z_c, .)` from per-claim prefix (8 bits) × suffix
     tables. Claims at identical points are merged. There is no full-size eq
     table per claim and no memset followed by read-modify-write.
   - On 12 threads the stage went from 0.124 to 0.045 s.
5. **Split-eq op sumchecks** (`eqsum.zig`) for `eq·A·B` (hadamard) and
   `eq·(A·B − C)` (product):
   - The eq table is never materialised or folded:
     `s_k(t) = C_k e_k(t) q_k(t)`.
   - The suffix eq tables come from summing halves (additions only).
   - `q_k(1)` is derived from the running claim, so only q(0) and q(2) are
     summed.
   - Round 0 works directly on the i32 witness.
   - Product op sumcheck, 1 thread: 0.040 → 0.015 s.
6. **Forward-pass reuse and LogUp preparation**:
   - `protocol.proveWithAccumulators` accepts the forward pass's
     accumulators. `model.buildMlp` keeps them in `Built.accs`, and the
     bench uses them by default. `TENSOR_RECOMPUTE_ACC=1` restores the
     recomputation, which took 0.065–0.10 s for mlp 9 11 12.
   - `prep.zig` builds multiplicities from per-task histograms.
   - Denominators are specialised per key kind: remainder is one M31
     subtraction, range8/lookup is a 256-entry LUT. Before, every element
     went through a switch and an i64 `@mod`.
7. **Recycling allocator** (`recycle.zig`, opt-in). `/usr/bin/time -l` on
   mlp 9 11 12 showed 1.9 s of system time against 3.0 s of user time,
   caused by zero-fill page faults on fresh `mmap`s. The fast GKR prover also
   stopped scaling at about 4 threads. The `Recycler` keeps freed blocks of
   1 MiB or more in exact-size free lists, so repeated proofs of the same
   shape touch fresh pages only once. Single-shot proofs still pay the
   faults, which is why the GKR single-shot time barely moved.
8. **GKR scheduling**. `Config.gkr_min_parallel` defaults to 2^10 instead of
   stwo's 2^13. The many small late-round loops of every layer ran serially.
   The GKR sumcheck went from 0.109–0.115 to 0.087–0.091 s; 512 and 256 were
   slower again because of dispatch overhead.
9. **Dyadic-extension FFT encoding** (`Twiddles.encodeBatch`). This uses
   stwo's `evaluateDyadicExtensionBuffersWithTwiddlesWithPool` over the
   16-row commit blocks: it skips the degenerate top layers, needs no zero
   fill and is bit-identical. The verifier's `encodeSecure` batches its four
   coordinates.

Timings: `Timings` gains `accumulators_ns`, `multiplicities_ns`,
`gkr_input_ns`, `gkr_build_ns` and `gkr_sumcheck_ns`. `tensor-bench mlp`
prints `prep_s`, `gkr_parts_s`, `prove_first_s` and `prove_reps`. The
environment knobs are `TENSOR_RECYCLE`, `TENSOR_PROVE_REPS`,
`TENSOR_RECOMPUTE_ACC` and `TENSOR_GKR_MINPAR`.

## Soundness

The verifier is untouched, and no prover change weakens a check. The prover
still refuses invalid witnesses: out-of-range remainders, out-of-range values
and lookup mismatches are detected while counting multiplicities, before any
denominator is built.

The individual changes are safe for these reasons:

- **Hashing.** It is the same hash function (Blake2s-256) over the same bytes.
  Only the evaluation order changed, four messages per SIMD call.
- **Packed and reordered arithmetic.** M31/QM31 arithmetic is exact, so lane
  and chunk order cannot change any value. The implicit-zero identities used
  are field identities:
  - `f + r(0 − f) = (1 − r) f`;
  - `(2·0 − e)(2·0 − f) = e f`;
  - `eq(ρ,(t,x')) = e(ρ₀,t)·eq(ρ_rest,x')`;
  - `T_{k+1}(x'') = T_k(0,x'') + T_k(1,x'')`, because `e(0) + e(1) = 1`.
- **Split-eq q(1) derivation.** For a true claim, s(0)+s(1)=claim holds, so
  `q(1) = (claim − C(1−ρ)q(0)) / (Cρ)` is the true value and every
  transmitted round value equals the generic prover's. When `Cρ = 0` the
  prover sums q(1) directly. For a false claim, the transmitted values differ
  from the generic prover's. That only affects a cheating prover's output;
  standard sumcheck soundness still applies, and a test checks such proofs
  are rejected.
- **Accumulator reuse.** Accumulators supplied by the caller are untrusted.
  A wrong one yields a remainder the prover refuses, or a proof the verifier
  rejects. Shape mismatches are refused (`error.AccumulatorShape`).
- **Allocator.** It is a policy change only; buffers are fully initialised
  before use, as before. The E blocks are fully written by `fillRegion`, or
  zeroed when a tensor has no claims. Entries at or beyond `active` are never
  read.

These tests guard the changes:

- golden proof digests (mlp, product), plus 1-thread vs 5-thread equality;
- `batch`: proveBaseTimesExt vs the generic prover for n ∈ {0,1,3,9,14},
  several active lengths and signed F (rounds, points, finals, next
  challenge); fillRegion vs summed eq tables with merged duplicate points;
- `eqsum`: vs the generic prover for n ∈ {1,2,3,7,13}, both kinds, the ρ₀ = 0
  fallback, and false-claim rejection;
- `sumcheck`: an active-length prover with garbage beyond `active` equals the
  zero-padded full-length prover;
- `prep`: parallel histograms equal the serial ones, and the error is
  reported;
- `model`: `proveWithAccumulators` produces the same digest as `prove`, and
  a wrong accumulator shape is refused;
- `recycle`: reuse, pass-through and cross-class realloc;
- all pre-existing tamper tests.

## Remaining hot spots and recommendations

1. **The GKR is now about 50% of MLP prover time** (mlp 9 11 12 steady state:
   0.108 of 0.212 s). Its layer sumchecks scale only about 6x on 12 threads.
   The time goes to the per-round, per-instance dispatch of small loops and
   to first-touch faults on its upfront layer allocations. There are two
   options:
   - Prover-side, inside `gkr_prover_fast`: run the small instances' rounds
     concurrently, one task per instance instead of one barrier per instance
     per round. Also allocate each layer lazily, since today every layer of
     every instance is allocated before round 0.
   - Protocol-side, needing coordination with the protocol owners:
     - drop the `y_range` key of a matmul/hadamard output that is also a
       lookup input. The lookup key `(in, T(in))` already forces
       `in ∈ [−128,128)`. In the SwiGLU MLP this removes one of ~10 T·F-sized
       instances (gate output); the op sumcheck would take y(ρ) from the
       lookup's `lookup_in_values` instead of the y_range denominator.
     - fold the remainder and y_range keys of one op into a single key over a
       2-column table (e.g. key = r + 2^s·(y+128) with a 2^(s+8) range
       table). This halves those instances, but a larger table is needed.
2. **Page faults dominate single-shot runs.** A long-lived prover should pass
   `recycle.Recycler.allocator()` as `prove`'s allocator. Steady-state
   mlp 9 11 12 is 0.21 s against 0.37 s single shot. The coordinator can
   reproduce this with
   `TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3 tensor-bench mlp …`.
3. **The remaining batch sumcheck cost** in mlp 9 11 12 is split into an E
   build of about 15 ms, which is now one pass, fold 0 at about 9 ms
   (first-touch faults) and generic rounds 1.. at about 14 ms. A further step
   would fuse fold(k) with round(k+1)'s sums as the GKR prover does, halving
   memory passes.
4. **Weight passes are small.** At mlp 4 11 12 (25M weights), weight fold +
   open take 3.4 + 4.2 ms on 12 threads (≈0.3 ns/weight) and 32 + 27 ms on 1
   thread. An i32-accumulating 16-bit-limb or `sdot` kernel would help the
   single-thread number. It is under 1% of the 1024-token MLP, so it was not
   done.
5. **Hashing.** The 4-lane Blake2s already has ILP 4 (`g4Interleaved`), so an
   8-lane variant is unlikely to pay. Hashed bytes are 4 × the witness table
   at blowup 4.

## Reproduce

```
cd src/tensor
zig build test -Doptimize=ReleaseSafe                       # all tests incl. golden digests
zig build -Doptimize=ReleaseFast --prefix <dir>
<dir>/bin/tensor-bench product 20 1 ; <dir>/bin/tensor-bench product 20 12
<dir>/bin/tensor-bench mlp 8 10 11 ; <dir>/bin/tensor-bench mlp 9 11 12
TENSOR_RECYCLE=1 TENSOR_PROVE_REPS=3 <dir>/bin/tensor-bench mlp 9 11 12   # steady state
```
