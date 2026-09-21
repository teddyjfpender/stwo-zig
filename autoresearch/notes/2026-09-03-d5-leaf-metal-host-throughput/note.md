# D5 provider leaf on Metal: host-side throughput round (2026-09-03)

Branch `autoresearch/metal-ecdsa-subsecond-20260829`, on top of checkpoint
`6084a979`. Host: Apple M5 Max, 18 logical CPUs, 64 GiB, macOS 25.6, Zig 0.15.2.

## Unit of work and oracle

The retained Stage101 D5 provider sweep (`stage101-degree5-provider-sweep-v1`,
segment 1 of the V4 hoisted-release campaign): 6,671,301 Poseidon2 calls proved
as 26 log18 shards (18 concurrent owners, 2 waves) on the authenticated-AOT
Metal recursion engine, then freshly decoded and verified by the CPU engine.
Proofs are deterministic: every accepted run below produced
`ordered_proof_identity_sha256 = 89ee5ce2ec0ed975...`,
`ordered_fresh_identity_sha256 = 64ed3a589c76248a...`, 19,856,500 canonical
proof bytes. That identity is the equivalence oracle for every change here.

Concurrent owner count is an input to `ProviderShardPlanV1.create`, so it is
statement-relevant: 9 owners produced a different (valid) shard plan and proof
identity. The retained arm stays at 18 owners, 1 engine worker.

## State at the start

The checkpointed tree did not run: its pinned AOT bundle was ABI21 while the
committed runtime was ABI22 (`CoreShaderAbiMismatch`). A fresh bundle was
minted (`zig build metal-core-aot-acceptance -Doptimize=ReleaseFast -p <dir>`,
9 min, 165 exports) and the sweep/leaf pins were updated (manifest
`6bd5d5bf...`, metallib `e2083bfc...`, source `0c57e848...`, air `0a2d0a1a...`,
export count 165). With that bundle the committed source proved and verified
all 26 shards; the earlier `InvalidBasePolynomialProgram` stop was already
fixed in the checkpoint.

Baseline (ReleaseFast, uninstrumented unless noted):

| phase | wall |
| --- | --- |
| source preparation (open, replay, witness, plan) | 70.9 s |
| Stage A (trace + three commitments, 26 shards) | 6.65 s |
| Metal prove (composition, quotients, FRI, encode) | 12.51 s |
| CPU fresh verify | 5.17 s |

GPU kernel time in the profiled baseline was about 3.1 s total, so the
19.2 s of Stage A plus prove was host-bound.

## Attribution

`sample` during Stage A: the 239-column D5 main trace was written by a per-row
interpreter over the candidate arena (`fillRow`, ~40 s CPU across shards) with
bit-reversed column scatter, a 250 MB memset per shard, and a full
materializer-plan re-validation (`Plan.validate`/`computeDegrees`) on every
shard, export, and trace.

`sample` during prove: all owners serialized on one composition-domain
scratch owner (`_os_unfair_lock_lock_slow` under `evaluateInternal`), and the
window held a fresh 1 GB Metal allocation, a single-threaded 1 GB
copy/zero-fill, the expansion transform, and the five kernels. The order
component's CPU composition and claim pass (`evaluateSelectedGeneric`,
`callValue` via 17 full QM31 products per row/call) were the next CPU items.

## Changes

1. `composition_domain_scratch`: resident scratch buffers are pooled by exact
   byte length and reused across proofs (no per-proof 1 GB allocation and
   page-fault sweep); the coefficient copy and zero fill run on the shared
   work pool; owner windows are a two-permit semaphore (`OWNER_WINDOWS = 2`)
   with the reservation authority scaled to match
   (`D5_COMPOSITION_DOMAIN_SCRATCH_CONCURRENT_OWNERS = 2`, receipts and tests
   repinned). The backend releases the pool before runtime shutdown.
2. `typed_poseidon2_degree5_row_program`: the candidate arena is compiled once
   into a reachability-pruned instruction list and evaluated eight rows at a
   time as two four-lane M31 vectors; blocks are addressed by committed row so
   every column store streams. Padding rows are written by the same pass, so
   the memset is gone. Equivalence test against `Candidate.fillRow` with
   padding at log 6.
3. `Candidate.validateRetained`: per-shard hot paths (component init, backend
   exports, trace generation, canonical program checks) rebind identity,
   digests, geometry and selection without re-deriving the materializer plan.
   Construction and cold entry points keep the full `validate`.
4. Order component: `runPrepared` uses hoisted `row_power` powers and
   M31-by-QM31 products (`evaluateSelectedRowPrepared`); interaction
   generation derives the claim in the same pass with `CallValuePowersV1`.
   Both have field-identity parity tests against the generic evaluators.
5. Sweep: `-Derror-tracing` build option for diagnostic binaries; owner/wave
   pins relaxed to environment-supplied host knobs (geometry pins kept).

## Results (build 4, ReleaseFast, uninstrumented, 18 owners x 1 worker)

| phase | baseline | now (3 runs) |
| --- | --- | --- |
| Stage A | 6.65 s | 1.02 / 1.08 / 1.49 s |
| Metal prove | 12.51 s | 3.02 / 3.12 / 4.25 s |
| Stage A + prove | 19.2 s | 4.0-5.7 s |
| CPU fresh verify | 5.17 s | 2.8-3.8 s |
| source preparation | 70.9 s | ~50 s |

Proof identity unchanged on every accepted run. Run-to-run variance is about
30 percent on this shared host (other workloads were resident); a paired
ABBA cohort is still owed before promotion.

Two scratch windows did not separate from one window within that variance;
the retained-arm receipts now record two windows and the scaled reservation.

## Round 3: shader-side and per-shard host chain

Uncontended attribution (one owner, 26 waves, profiled) gave the true GPU
floor with the round-2 binary: 3.45 s. Main-tree LDE plus Merkle 1.0 s
(Poseidon2 leaves absorb at rate 8, so 239 columns cost 30 permutations per
leaf, ~20 ms per tree), the other 209 trees 0.78 s, composition-domain
expansion transforms 0.75 s (about 10 GB of traffic per shard, near
bandwidth), D5 composition kernels 0.61 s plus lookup 0.07 s, sampled values
0.14 s. Merkle parent chains ran about 14x slower per permutation than leaves.

Changes:

1. Merkle parent chain policy (host `.m`, no remint): the fused
   bottom-eight-level tail kernel is used only when the first parent level is
   below 2^13 nodes; larger chains take per-level plain dispatches.
   `STWO_ZIG_METAL_MERKLE_BOTTOM_FUSION=0|1` forces either policy. Other-tree
   commits 0.78 -> 0.32 s.
2. Generated composition kernels: 32-bit exact M31 add/mul helpers instead of
   a 64-bit double-fold reduce, and constraint roots folded into the QM31
   accumulator at definition instead of a 57-value live tail. Applied in
   `base_polynomial_codegen`/`lookup_polynomial_codegen` and to the checked-in
   `riscv_polynomials.metal` (the `update-riscv-polynomial-aot` step in this
   checkpoint fails with a duplicate `stwo_metal_backend` module root, so the
   checked-in source was transformed with the same two rewrites; kernel names
   are program-content hashes and did not change). D5 composition kernels
   0.61 -> 0.24 s, lookup 0.07 -> 0.02 s. Bundle v24 minted and repinned.
3. `air/extract/symbolic.zig`: the installed arena is now `threadlocal`. With
   two scratch windows, two owners exported kernel programs concurrently and
   panicked on the shared global.
4. `poseidon2_air.narrowRowPairsFromCall`: canonical narrow calls build their
   two LogUp pairs from four base-field relation combinations instead of a
   445-column main row promoted to QM31 with entry-list copies (this was the
   prove-phase memmove and the `generateInteractionSerial` cost). Parity test
   against the generic builder.

Uncontended GPU after 1-3: 2.47 s. Single-owner prove wall 18.9 s over 26
shards is 0.73 s per shard with CPU equal to wall, so the 18-owner prove phase
(two waves, ~3.2 s) is bounded by the per-shard host chain, not GPU
throughput. With change 4 (build 7) the 18-owner prove phase measured 2.46 and
2.87 s wall with 19-21 s CPU (from 26 s).

5. Poseidon2 channel proof of work on the GPU
   (`stwo_zig_poseidon2_channel_pow_search`, bundle v25, 166 exports): the
   channel exposes its nonce-independent sponge prefix state, the kernel
   replays `mixU64` + `drawU32s` per candidate (three permutations) and takes
   the atomic minimum over 2^20-nonce batches, so it returns exactly the
   sequential lowest nonce; the generic prover re-verifies it on the host
   channel. The single-threaded 16-bit grind had been ~0.15 s of every shard
   chain. `Channel.powCandidateWordFromPrefix` is the host restatement with a
   replay test against `verifyPowNonce` and `grind`.

## Results after round 4 (build 8, bundle v25, 18 owners x 1 worker)

| phase | baseline | round 2 | round 4 (3 runs) |
| --- | --- | --- | --- |
| Stage A | 6.65 s | 1.0-1.5 s | 1.06 / 1.14 / 1.39 s |
| Metal prove | 12.51 s | 3.0-4.2 s | 2.15 / 2.23 / 2.45 s |
| prove CPU | 53 s | 26 s | 12.6-15.3 s |
| Stage A + prove | 19.2 s | 4.0-5.7 s | 3.2-3.8 s |
| CPU fresh verify | 5.17 s | 2.8-3.8 s | 3.5-3.7 s |

Proof identity 89ee5ce2ec0ed975... on every accepted run. Single-owner
(26 waves) prove wall fell 18.9 -> 16.7 -> 11.2 s across rounds 3-4, i.e. the
per-shard host chain is now 0.43 s; uncontended GPU total is 2.47 s (Stage A
main-tree LDE+leaves ~1.0 s of it).

## Where the time is now

Stage A (~1.1 s) is GPU-bound on the main-tree commit: Poseidon2 leaves at
rate 8 (30 permutations per 239-column leaf, ~20 ms/tree, ~0.5 s total) plus
LDE (~0.27 s). Prove (~2.2 s) is two waves of an 18-owner batch whose
per-shard chain is 0.43 s host CPU plus GPU waits; uncontended prove GPU is
~1.4 s, dominated by the log+2 composition-domain expansion transforms (26 ms
per shard, ~10 GB of traffic, at bandwidth for a ~6-pass FFT).

Remaining per-shard host chain (single-owner sample, build 8): order
component prepared composition 0.08 s plus its CPU LDE of 23 columns 0.045 s
and owner buffers, GPU waits 0.055 s, memmove 0.05 s, Blake2s call-commitment
hashing 0.037 s, interaction pairs 0.036 s, LogUp per-row QM31 inversions
0.03 s (batchable), FRI packing.

Next steps in priority order:

- order component: let the host worker borrow the GPU-expanded scratch
  columns (add its 4 interaction columns to the expansion, hold the window
  until host workers join) or move it to a resident kernel; ~0.13 s/shard.
- LogUp cumulative columns: batch-invert the 2^18 denominators per sum.
- Poseidon2 leaves: two rows per thread for ILP (new kernel + dispatch),
  target 0.5 -> ~0.3 s of Stage A.
- expansion FFT: fuse more layers per pass (6 -> 3 passes) to cut the
  10 GB/shard transform traffic; highest effort and risk.
- wave quantization: 26 shards over 18 owners costs two full waves; owner
  count is statement-relevant (changes the shard plan and proof identity), so
  any change here is a protocol decision, not a host knob.

Sub-second Stage A plus prove is not reachable by kernel tuning alone with
26 log18 shards, 239-column rate-8 Poseidon2 leaves and a log+2 expansion;
it needs protocol-level work reduction.

Host-side items outside the timed proving window: ~50 s of source
preparation (cold campaign open, sparse Merkle rebuild, Blake2s call
commitments) that the prepared-program cache targets, and the CPU verify.

## Reproduction

```
cd src/integrations/riscv_metal
zig build -p <prefix> install-stage101-degree5-provider-sweep-v1 -Doptimize=ReleaseFast
STWO_RISCV_METAL_AOT_BUNDLE=<bundle>/share/stwo-zig/metal/core \
STWO_ZIG_D5_PROVIDER_SHARD_LOG=18 STWO_ZIG_D5_PROVIDER_CONCURRENT_OWNERS=18 \
STWO_ZIG_D5_PROVIDER_ENGINE_WORKERS=1 STWO_ZIG_D5_PROVIDER_HOST_BYTE_BUDGET=51539607552 \
STWO_ZIG_D5_PROVIDER_HOST_BYTE_LIMIT=64424509440 \
STWO_ZIG_D5_PROVIDER_CONTROLLER_RESERVE_BYTES=8589934592 \
STWO_ZIG_D5_PROVIDER_NON_COLUMN_RESERVE_BYTES=536870912 \
<prefix>/bin/stage101-degree5-provider-sweep-v1 \
  --retained-materialization-result <campaign>/authority/materialization-v2.json \
  --publication-root <campaign>/run/publication-parent/ethereum-incremental-capture-v4 \
  --segment-index 1 --output receipt.json
```

Add `STWO_ZIG_METAL_PROFILE_OUT=<file> STWO_ZIG_METAL_PROFILE_ENCODER_COUNTERS=1`
for GPU attribution (adds overhead; not for verdicts).


## Full-leaf baseline against bundle v25 (2026-09-04)

The full Stage101 leaf (`stage101-metal-autoresearch-v1`) was built against the
v25 bundle and run on segment 1. Two harness guards had to be corrected first;
neither touches the proof protocol:

1. `validateStage101HostPlacements` pinned the three tiny log<3 circle
   operations as exactly one interpolation, one evaluation and one LDE. Since
   the batched circle-LDE commit route (0f7a0177) all three are classified as
   small LDEs, so the run failed closed with
   `Stage101SmallCirclePlacementMismatch` after proving. The pin is now on the
   admitted total (3) with the per-kind split free; `cpuFallbackTotal` must
   still equal it, so no unexpected host fallback can hide.
2. The pinned 5-second steady-state budget is aspirational for this route and
   fails closed before the artifact is written. `ThroughputBudgetV1` now reads
   an optional explicit budget from `STWO_ZIG_STAGE101_BUDGET_MS`
   (`admission_and_replay,witness_and_profile,proof_core,encode_and_custody`
   in milliseconds). The budget stays exact and fail-closed; only its value
   becomes an explicit, receipt-recorded input. Absent the variable the pinned
   five seconds is unchanged.

Separately, the campaign's guest input and expected output had been deleted by
the macOS periodic /private/tmp cleanup (files older than three days). Both were
recovered by sha256 from the campaign content-addressed store at
`/private/tmp/stwo-campaign-import-release.KBtjED/cas/objects/sha256/` and
restored to the paths `materialization-v2.json` names; the D5 sweep and the leaf
both verify again from them.

Measured leaf (18 workers, ReleaseFast, three runs; run 4 completed and wrote
its artifact):

| phase | run 1 | run 3 | run 4 |
| --- | ---: | ---: | ---: |
| input admission | 4.32 s | 4.87 s | 4.76 s |
| compact replay | 0.38 s | 0.51 s | 0.51 s |
| prepared transaction (witness + profile) | 11.06 s | 11.91 s | 12.20 s |
| prove | 175.90 s | 189.53 s | 216.35 s |
| encode | 0.16 s | 0.17 s | 0.30 s |
| **leaf transaction** | **191.84 s** | **207.03 s** | **234.17 s** |
| cold CPU verify | 21.35 s | 22.68 s | 24.29 s |
| wall | 253.18 s | 271.73 s | 302.13 s |

Run 4 exited zero and wrote `segment-000001.stwief04` whose sha256 is
`20baa3ae632cf116b94a5e7af36ce084e82c5dc1eeaaafd568684afb61c3effa`, identical to
the pinned reference artifact, so the leaf is byte-exact against the retained
oracle on the v25 bundle.

Inside `prove` (run 1 profile): FRI quotient build and commit 48.45 s, base-trace
Merkle commit 43.73 s, interaction Merkle commit 35.16 s, composition evaluation
8.87 s, trace generation 3.54 s, interaction traces 8.11 s, everything else under
one second, and about 26 s unattributed. A CPU-sample attribution of a second run
put 111.5 s (47%) of the wall in `waitUntilCompleted` on the three Metal commits
and the quotient build, with the rest CPU-bound at roughly one core
(`producer_parallelism_milli` 465-523).

The leaf still proves the Poseidon memory provider as the native 445-column
component inside Tree 1/Tree 2, so this baseline is the pre-route-flip number.
The D5 sweep proves the same 6,671,301 calls in ~3.4 s. The implementation plan
for routing the leaf through the D5 shard batch is
`autoresearch/notes/2026-09-03-leaf-route-flip-plan/note.md`.
