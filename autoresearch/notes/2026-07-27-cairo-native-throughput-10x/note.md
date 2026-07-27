# Cairo Native-Throughput Research

## Objective

Raise verified end-to-end proving throughput for the official Zig Stwo-Cairo
CPU and Metal products toward a `10x` system target across the fixed
seven-program portfolio:

- all-opcodes;
- Poseidon aggregator;
- Pedersen aggregator;
- Fibonacci 100k;
- Factorial 100k;
- Arithmetic 2m; and
- Memory 7m.

The optimization unit is the portfolio geometric mean. Every row is also a
regression guard. No candidate may dispatch on program name, input path,
benchmark identity, input digest, or a hard-coded program shape.

## Correctness and evidence contract

- Preserve official Cairo security parameters, statement semantics, trace
  geometry, transcript order, proof format, and verifier behavior.
- Require deterministic Zig CPU/Metal proof-byte equality and acceptance by
  the pinned official Rust verifier.
- Require Metal dispatch evidence and zero CPU fallbacks.
- Profile complete-proof stage placement before kernel or field tuning.
- Use an exact predecessor/candidate paired schedule for causal claims.
- Retain execution, prove, committed-cell throughput, VM-step MHz, peak
  footprint, and backend evidence.
- Record rejected candidates and cross-run drift rather than selecting only
  favorable samples.

## Baseline

Candidate parent: `0338f75b`.

| Lane | Seven-row current prove status |
| --- | --- |
| Rust SIMD | contemporary geometric-mean control |
| Zig CPU | `2.760x` slower than Rust |
| Zig Metal | `2.519x` slower than Rust |
| Zig Metal / Zig CPU | `1.096x` faster |

The latest medians and complete throughput table are in the preceding
`2026-07-27-cairo-system-throughput` note.

## Comparability warning

The current native benchmark protocol is not the official Cairo protocol.
Native benchmark fixtures commonly use `pow_bits=10` and `n_queries=3`;
official Cairo uses `pow_bits=26` and `n_queries=70`. Arithmetic 2m currently
spends roughly `590 ms` in proof of work alone. Native M-cells/s therefore
cannot be used as a direct end-to-end Cairo target without preserving and
accounting for this additional security work.

The `10x` target remains useful as an architectural forcing function. It does
not authorize weaker security parameters or a different committed-cell
numerator.

## Initial stage model

The latest pre-quotient-fix Arithmetic 2m profile attributes:

| Shared or CPU stage | CPU | Metal |
| --- | ---: | ---: |
| base trace build | 1,507 ms | 1,550 ms |
| preprocessed materialize/commit | 400 ms | 344 ms |
| main trace commit | 459 ms | 165 ms |
| interaction trace build | 342 ms | 336 ms |
| interaction trace commit | 320 ms | 136 ms |
| composition evaluation | 397 ms | 414 ms |
| proof of work | 587 ms | 595 ms |

The accepted fragmented-input Metal quotient change subsequently reduced its
FRI quotient/commit stage from 1,350 ms to about 212 ms. Host witness, AIR,
interaction, static preprocessing, and PoW are now the architectural targets.

## First hypotheses

1. **Parallel fixed-block PoW hashing.** Current workers evaluate one 40-byte
   BLAKE2s nonce at a time despite an existing four/eight-stream SIMD
   compression implementation. Batch independent nonces per worker while
   retaining lowest-valid-nonce semantics.
2. **Immutable preprocessed commitment product.** Canonical fixed columns and
   their commitment are rebuilt every process despite being profile-invariant.
   Bind an authenticated reusable artifact without changing the transcript.
3. **Resident or compiled Cairo execution plans.** The official products still
   interpret witness and AIR programs on the host. Reuse the repository's
   authenticated code-generation and resident-arena machinery through a
   general program-identity admission boundary.
4. **Persistent proof-session ownership.** Remove allocation/materialization
   boundaries that force base, interaction, and composition columns through
   repeated host representations.

The first experiment isolates PoW because it is shared by CPU and Metal,
security-preserving, easy to falsify, and an absolute floor on every official
Cairo proof.

## Result 1: four-stream PoW search

The existing four-stream BLAKE2s compressor now exposes a general equal-length
single-block hash. Each PoW worker hashes four ordered residue-class nonces per
compression and checks the resulting digests in nonce order. The global atomic
minimum and failed-spawn completion logic are unchanged.

Live `stwo-prof` comparison on deterministic 18-bit grinds measured:

| Metric | Scalar-per-nonce | Four-stream | Improvement |
| --- | ---: | ---: | ---: |
| paired wall time | 3.292 ms | 0.731 ms | `4.545x` |
| instructions | ratio basis | `0.2408x` | `4.152x` fewer |
| cycles | ratio basis | `0.2047x` | `4.886x` fewer |
| wall 95% CI | | | `[4.421x, 5.038x]` |

An independent counter run measured IPC rising from `1.775` to `2.116`.

Arithmetic 2m complete-proof profiles retained exact proof hash
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`:

| Lane | Prior PoW | Candidate PoW | Candidate prove |
| --- | ---: | ---: | ---: |
| Zig CPU | 587.482 ms | 137.662 ms | 4,664.871 ms |
| Zig Metal | 594.663 ms | 151.838 ms | 3,872.615 ms |

Metal reported 74 dispatches and zero fallbacks. The stage win is broad and
security-preserving, but it moves complete proofs only about `1.13-1.16x`
against the latest current medians. It is retained as one system checkpoint,
not represented as the `10x` objective.

## Rejected: homogeneous worker reduction

The M5 Max exposes 6 `Super` and 12 `Performance` cores. The prover currently
treats all 18 as one pool, so a complete Arithmetic 2m screen held PoW at 18
workers and varied the shared prover pool:

| Prover workers | Prove | Base trace | Composition |
| ---: | ---: | ---: | ---: |
| 6 | 6,567.685 ms | 1,756.180 ms | 792.475 ms |
| 12 | 5,198.112 ms | 1,636.156 ms | 597.468 ms |
| 18 | 4,680.900 ms | 1,597.465 ms | 424.224 ms |

All proofs had the exact canonical digest. Peak footprint stayed within
approximately 1% across the screen. Reducing the worker count is therefore
rejected: every core tier contributes useful throughput, and the current
bottleneck is not simple oversubscription.

## Result 2: retain the Pedersen table across proof phases

Complete-process sampling found that the same immutable Pedersen point table
was generated once inside preprocessed materialization and then generated
again before interaction construction. The second generation occurred outside
the recorded interaction stage, so the stage profile hid the duplicate.

The proof transaction now owns one table and passes the authenticated window
variant to both consumers. The table generator uses its existing eight-worker
bound instead of the historical four-worker default. The selection depends
only on the canonical preprocessed variant.

An exact Arithmetic 2m diagnostic retained proof digest
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
Under a concurrently loaded host, prove time was 5,108.769 ms and peak RSS was
5.244 GiB. The uninstrumented remainder outside named stages fell from about
294 ms in the preceding 18-worker screen to 62 ms. Cross-run stage times were
noisy because unrelated RISC-V gates were active, so this is retained on the
strength of deleted duplicate work and exact end-to-end parity, not presented
as a causal portfolio speedup.
