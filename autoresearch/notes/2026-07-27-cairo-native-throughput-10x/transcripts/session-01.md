# Session 01: Cairo 10x system-throughput search

## Request

Use the repository's high-performance-computing autoresearch skills to pursue
a `10x` improvement for both Zig CPU and Zig Metal Cairo proving, measured
across the broad program portfolio rather than a selected benchmark.

## Research discipline

This session applies:

- `zig-profiling` for CPU counters, samples, code generation, and paired
  comparisons;
- `metal-profiling` for device time and complete-command attribution;
- `metal-performance-design` for resource, submission, residency, and AOT
  architecture; and
- the transcript contract from `submission-transcripts`.

The current generic Native autoresearch board does not score Cairo. This work
uses the same evidence and promotion discipline on a dedicated branch and
must not be represented as a Native-board promotion.

## Initial interpretation

The observed M-cells/s gap is real, but the native and Cairo proof protocols
are not directly comparable. Official Cairo uses PoW 26 and 70 queries; the
native fixtures commonly use PoW 10 and three queries. The Arithmetic 2m stage
profile spends approximately 590 ms in PoW alone. That cost must be accelerated
or retained explicitly; lowering it by changing security parameters is
forbidden.

The prior round already removed a Metal quotient scheduling pathology. The
remaining largest costs are host base-trace construction, host composition/AIR
evaluation, static preprocessing, interaction construction, and PoW. Metal
waits were not dominant. This rules out another isolated small shader fusion
as the first experiment.

## Hypothesis 1: batch independent PoW nonces

The channel currently precomputes the invariant first BLAKE2s digest, then each
worker hashes one independent 40-byte `prefix_digest || nonce` message at a
time. The crypto backend already implements four- and eight-stream BLAKE2s
compression for equal-length independent messages.

Map each worker's next four residue-class nonces into one parallel SIMD
compression. Check all four outputs in ascending nonce order and atomically
lower the global bound. Preserve the existing strided partition, failed-spawn
completion, deterministic lowest-valid-nonce result, scalar fallback, and
verification function.

Prediction:

- nonce hashes per second improve materially on AArch64;
- official Cairo PoW falls from roughly 590 ms toward 150-250 ms;
- complete CPU and Metal proofs both improve;
- proof bytes remain exact because the lowest valid nonce is unchanged; and
- non-PoW stages remain unchanged.

Falsifiers are a different nonce, any verification failure, no counter-level
improvement, or a complete-proof regression.

### Result: accepted as a focused checkpoint

The four-stream fixed-single-block primitive matched scalar BLAKE2s across
lengths 0, 1, 40, 63, and 64. Existing lowest-nonce, zero-bit, and failed-spawn
tests passed.

The live paired `stwo-prof` comparison reported candidate/baseline:

```text
wall improvement  4.5447x, 95% CI [4.420783, 5.038067]
instructions      4.1523x fewer
cycles            4.8856x fewer
```

The 18-bit counter medians moved from 5.917 ms, 474.6M instructions, 267.6M
cycles, and IPC 1.775 to 1.350 ms, 114.0M instructions, 53.9M cycles, and IPC
2.116.

Arithmetic 2m exact-proof profiles then measured:

- CPU PoW 587.482 -> 137.662 ms, complete proof 4,664.871 ms;
- Metal PoW 594.663 -> 151.838 ms, complete proof 3,872.615 ms;
- canonical proof hash unchanged at `25e571...deea6`; and
- Metal 74 dispatches, zero fallbacks.

The complete-proof movement is much smaller than the kernel result because
base trace construction, composition evaluation, commitments, and interaction
construction remain. The candidate is retained and the search proceeds to
those architectural stages.

## Hypothesis 2: heterogeneous-core worker reduction

The local M5 Max reports 6 `Super` and 12 `Performance` cores. Test whether the
global pool's assumption that all 18 workers are interchangeable creates
memory-bandwidth contention or slow-tail effects. Hold PoW at 18 workers and
screen complete Arithmetic 2m proofs with 6, 12, and 18 prover workers.

### Result: rejected

Complete proof time was 6,567.685, 5,198.112, and 4,680.900 ms respectively.
Base-trace construction was 1,756.180, 1,636.156, and 1,597.465 ms;
composition was 792.475, 597.468, and 424.224 ms. Proof digests were exact and
peak RSS was effectively unchanged. The complete prover benefits from both
core tiers, so reducing the shared pool cannot supply the desired system gain.

## Hypothesis 3: one Pedersen table per proof transaction

The symbolized complete-process sample showed Pedersen-table generation both
inside preprocessed materialization and again between main commitment and
interaction construction. The latter work was outside every named stage.
Retain one authenticated table under transaction ownership, supply it to both
consumers, and use the already bounded eight-worker generation plan.

### Result: accepted as a structural checkpoint

The duplicate table construction is removed and the complete Arithmetic 2m
proof remains byte-exact. One diagnostic under unrelated concurrent host load
measured 5,108.769 ms and 5.244 GiB peak RSS. The gap between the sum of named
stages and the complete proof fell from roughly 294 ms to 62 ms. Because
surrounding stage times were visibly perturbed by concurrent RISC-V gates, no
portfolio speedup is claimed from this run; a later controlled matrix will
judge its net effect.

## Hypothesis 4: extend eight-stream BLAKE2s through Merkle leaves

The complete CPU sample names BLAKE2s compression as the largest aggregate
active stack. Parent layers already batch eight independent hashes, but leaf
continuation batches four. Extend the same logical-vector implementation
through M31 column updates and terminal blocks, retaining four/scalar tails
and exact scalar differential tests.

### Result: rejected

All differential tests and proof hashes passed. Isolated Arithmetic 2m
A-B-B-A against the Pedersen-only predecessor measured 4,655.697 ms for the
four-stream path and 4,717.112 ms for eight streams, a `1.013191` regression.
The M5 executes the 256-bit logical vector as native halves; extra live state
and code pressure outweighed scheduling overlap for fragmented leaf messages.
All implementation source was removed.

## Hypothesis 5: use eight streams only for independent PoW messages

The Merkle rejection was shape-specific: fragmented leaf continuation grows
live state and code pressure. PoW hashes independent fixed 40-byte messages
and can reuse the existing tested eight-stream terminal compressor without
carrying continuation state.

Widen each worker's ordered nonce batch from four to eight. Preserve nonce
order, the atomic minimum, failed-spawn recovery, scalar behavior, and every
proof parameter. The candidate is falsified by any digest mismatch, invalid
lowest nonce, a paired PoW regression, or a complete proof mismatch.

### Result: accepted as a focused checkpoint

Core differential tests passed across message lengths 0, 1, 40, 63, and 64.
The immutable four-stream/live eight-stream paired comparison measured:

```text
wall B/A  0.7307, 95% CI [0.693294, 0.758206]
cycles    0.7247
instr     1.2366
```

The candidate trades additional issued instructions for more compression
overlap and reduces wall time by 1.369x. Exact Arithmetic 2m diagnostics
retained proof hash `25e571...deea6`. CPU PoW was 109.298 ms. Metal PoW was
101.537 ms and the complete Metal proof was 3,564.711 ms with 74 dispatches
and zero fallbacks. An unrelated RISC-V test occupied one core throughout the
complete screens, so no causal whole-proof ratio is claimed from them.

## Hypothesis 6: use the host for canonical preprocessing

The full canonical profile exposed a qualitatively different scale from the
seven-program canonical-small matrix: 161 columns and 543,100,528 immutable
preprocessed cells. A stage profile attributed about 30 seconds of a 35-second
proof to preprocessed materialization and commitment, while the commitment's
interpolation, extension, and Merkle children accounted for only about five
seconds. Source inspection found two independent host-side restrictions:

- the standard Pedersen table has 58 independent block plans but a fixed
  eight-worker ceiling; and
- column materialization reparses textual identities per cell and fills all
  columns serially.

Compile every non-Pedersen column identity into a typed evaluation plan once,
split disjoint row ranges through the global work pool, and make zero-worker
Pedersen configuration mean bounded host auto-detection. Preserve explicit
worker overrides, deterministic table geometry, and byte-exact proofs.

### Result: accepted

Focused plan and small-table tests, the complete Cairo frontend suite, and the
CPU product gate passed. The exact predecessor/candidate canonical comparison
was:

```text
                                      b0439ccf      candidate      speedup
complete prove                       35103.393 ms   23983.830 ms    1.464x
preprocessed materialize + commit    30967.369 ms   19745.659 ms    1.568x
peak RSS                             23.086 GB      23.086 GB       neutral
proof bytes                          564602         564602          exact
proof SHA-256                        bd663c9...dc9f bd663c9...dc9f  exact
```

The candidate retired essentially the same total instruction count while
compressing the parallel wall interval. It does not dispatch on program or
input identity. The remaining approximately 20-second stage proves that
regenerating an immutable canonical product is now the stronger system
boundary; authenticated coefficient/evaluation/Merkle reuse is the next
hypothesis.

## Hypothesis 7: expose uniform Pedersen scheduling units

The 58 logical standard-table blocks are not homogeneous. Twenty-six contain
262,144 rows and dominate work; the remaining 32 contain only 16,384 rows.
Even with host-auto worker selection, static round-robin placement leaves the
large blocks in two waves on 18 cores.

Split only blocks larger than 64K rows, derive each subplan's exact projective
starting point, reduce scratch workspaces to the maximum subplan size, and use
an atomic task cursor. Falsifiers are a boundary-point mismatch, changed proof
bytes, higher preprocessing time, or a memory increase.

### Result: accepted

The exact first chunk boundary agrees with the canonical Pedersen deduction,
the complete small table remains exact, and the canonical proof is
byte-identical. The incremental result was:

```text
                                      262K plans     64K plans      speedup
complete prove                       23983.830 ms   21859.696 ms    1.097x
preprocessed materialize + commit    19745.659 ms   17497.209 ms    1.128x
worker scratch rows                  262144         65536           4x fewer
```

Against the immutable `b0439ccf` control, the cumulative result is `1.606x`
end-to-end and `1.770x` for canonical preprocessing. Further table arithmetic
tuning has diminishing system leverage; immutable product reuse remains the
architectural target.

## Hypothesis 8: transfer generated base storage into commitment

The witness interpreter's `u32` outputs are ABI-identical to canonical `M31`
words. Transfer those component allocations into base-trace ownership and
pass backing buffers through the PCS contract. Keep CPU on detached columns
because its streaming commitment does not adopt shared backing.

### Result: rejected

Metal no-copy admission requires one backing arena that is covered
contiguously by every column. The live witness graph produces one allocation
per component plus separate implicit-table allocations. Consequently, the
backend still packed the fragments and the ownership change removed no
complete representation pass.

```text
Arithmetic 2m Metal             predecessor     candidate      ratio
prove                           3388.989 ms     3410.897 ms    1.0065
instructions                    207.040 B       208.308 B      1.0061
dispatches / fallbacks          74 / 0          74 / 0         exact
proof SHA-256                   caf3c89b...ae9f caf3c89b...ae9f exact
```

The candidate was removed completely. The architectural lesson is stricter:
one final arena must be planned before witness execution so writers target
their committed offsets directly. Ownership metadata cannot repair fragmented
construction after the fact.
