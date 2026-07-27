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
