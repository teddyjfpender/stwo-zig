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

## Rejected: eight-stream Merkle leaf continuation

The CPU sample identified BLAKE2s as the largest aggregate active stack.
Merkle parent layers already use the proven eight-stream compressor, while
fragmented leaf continuation used four streams. An exact implementation
extended eight-stream state gathering, column updates, tail finalization, and
scalar/four-stream tails through the generic leaf path.

Against the Pedersen-only commit, Arithmetic 2m A-B-B-A means were:

| Candidate | Mean prove | Ratio |
| --- | ---: | ---: |
| four-stream predecessor | 4,655.697 ms | `1.000000` |
| eight-stream leaves | 4,717.112 ms | `1.013191` |

Proof bytes were identical. The wider logical vectors did not turn the
existing active stack into a win; register and generated-code pressure
slightly outweighed additional instruction-level parallelism. The
implementation was removed completely.

## Result 3: eight-stream PoW search

The rejected Merkle experiment did not falsify eight-stream hashing for
independent fixed messages. Merkle leaves carry fragmented state, variable
tails, and enough live values to make the wider logical vector regress. PoW
hashes independent fixed 40-byte messages with no continuation state.

The fixed-message helper now reuses the already tested eight-stream terminal
compressor. Each worker checks eight ordered residue-class nonces per batch.
The strided partition, atomic global minimum, failed-spawn recovery, proof
parameters, transcript order, and scalar fallback remain unchanged.

An immutable four-stream predecessor and live eight-stream candidate measured:

| Metric | Candidate / predecessor | Interpretation |
| --- | ---: | --- |
| paired wall time | `0.7307` | `1.369x` faster |
| wall 95% CI | `[0.693294, 0.758206]` | stable win |
| cycles | `0.7247` | `1.380x` fewer |
| instructions | `1.2366` | more issued work |

Complete Arithmetic 2m diagnostics retained canonical proof hash
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
CPU and Metal PoW stages measured 109.298 and 101.537 ms. The Metal proof
completed in 3,564.711 ms with 74 dispatches and zero fallbacks. The CPU proof
completed in 4,701.342 ms. These complete timings were collected while an
unrelated RISC-V test occupied one core, so they are correctness and stage
diagnostics rather than a controlled end-to-end promotion claim.

## Result 4: parallel canonical preprocessing

The canonical profile commits 543,100,528 immutable preprocessed cells. Its
standard Pedersen table consists of 58 independent elliptic-curve block plans,
but table generation admitted only eight workers on the 18-core M5 Max.
Preprocessed column materialization also parsed a textual column identity for
every cell and filled columns serially.

The candidate now compiles each column identity into a typed plan once,
partitions disjoint column ranges through the repository work pool, and lets
Pedersen table generation select the bounded host CPU count. Explicit worker
overrides remain available, auto-selection is capped at 32 workers, and every
worker owns its elliptic-curve scratch space and output ranges.

An immutable `b0439ccf` predecessor and the live candidate proved the same
Arithmetic 2m input under `official-live-cairo-canonical`:

| Metric | Predecessor | Candidate | Improvement |
| --- | ---: | ---: | ---: |
| complete prove | 35,103.393 ms | 23,983.830 ms | `1.464x` |
| preprocessed materialize + commit | 30,967.369 ms | 19,745.659 ms | `1.568x` |
| peak RSS | 23.086 GB | 23.086 GB | neutral |

Both produced the exact 564,602-byte binary proof with SHA-256
`bd663c9ba5e89fe3c8d9a70a3eb57d12da5e0cf1ef3715d254ce75e29900dc9f`.
The complete Cairo frontend and CPU product gates pass.

This is a broad profile-level improvement, not a program dispatch: every
canonical proof receives it. It is still only a partial remedy. Roughly 20
seconds remain in preprocessing because every cold process regenerates and
commits immutable profile data. The next system candidate is a
protocol-identity-bound preprocessed product containing the coefficient,
evaluation, and Merkle state needed by both CPU and Metal. Loading such a
product must preserve the exact transcript commitment and cannot trust a path
or unauthenticated cache entry.

## Result 5: balance Pedersen block geometry

The standard table's 26 dominant blocks each contained 262,144 rows. With 18
workers, static plan assignment still executed two uneven waves and allocated
a full-size elliptic-curve scratch workspace per worker. Splitting each large
block into 64K plans exposes 104 uniform large tasks. Each plan carries its
exact projective starting point, and workers claim tasks dynamically while
writing disjoint output ranges.

Against Result 4, the same canonical Arithmetic 2m proof measured:

| Metric | 262K static plans | 64K dynamic plans | Improvement |
| --- | ---: | ---: | ---: |
| complete prove | 23,983.830 ms | 21,859.696 ms | `1.097x` |
| preprocessed materialize + commit | 19,745.659 ms | 17,497.209 ms | `1.128x` |
| worker scratch rows | 262,144 | 65,536 | `4x` fewer |

The binary proof remained byte-identical with SHA-256
`bd663c9ba5e89fe3c8d9a70a3eb57d12da5e0cf1ef3715d254ce75e29900dc9f`.
The cumulative canonical improvement from the immutable `b0439ccf` control is
`1.606x` end to end and `1.770x` in preprocessing. This improves cold
canonical construction but does not change the conclusion that an
authenticated immutable preprocessed product is the dominant next boundary.

## Rejected: retrofit base-trace backing ownership

Generated witness components first write `u32` storage, then the base collector
copies those values into `M31` commitment columns. A candidate transferred the
original ABI-identical storage through the PCS backing contract. The CPU lane
had to retain its existing detached-column path because the streaming
commitment policy otherwise regressed materially.

The Metal backend accepts a true no-copy host source only when all columns
cover one contiguous arena. Cairo component execution produces multiple
independent allocations, so Metal still had to pack them. An exact
predecessor/candidate Arithmetic 2m comparison measured 3,388.989 ms versus
3,410.897 ms, with candidate instructions also 0.6% higher. Proofs were exact,
both used 74 Metal dispatches and zero fallbacks, and peak footprint was
neutral.

The implementation was removed. A valid successor must allocate one
backend-shaped base arena before component execution and write every generated
and implicit column directly into its final offset. Retrofitting ownership
after fragmented allocation does not remove the representation transform.

## Final clean portfolio screen

Commit `43e9f3b5` was rebuilt cleanly and screened once across the fixed
seven-workload canonical-small portfolio. This is a diagnostic portfolio
screen, not a multi-round judged promotion. The comparison column uses the
clean `03644459` matrix recorded before this research branch.

| Workload | CPU ms | CPU M cells/s | CPU gain | Metal ms | Metal M cells/s | Metal gain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 1,556.857 | 62.575 | `1.505x` | 1,442.562 | 67.533 | `1.609x` |
| Poseidon aggregator | 1,173.401 | 41.162 | `1.685x` | 970.110 | 49.787 | `1.951x` |
| Pedersen aggregator | 4,066.334 | 11.813 | `1.072x` | 3,758.979 | 12.779 | `1.129x` |
| Fibonacci 100k | 2,060.214 | 54.829 | `1.198x` | 1,586.225 | 71.213 | `1.347x` |
| Factorial 100k | 2,709.832 | 45.458 | `1.570x` | 2,245.060 | 54.869 | `1.729x` |
| Arithmetic 2m | 4,350.179 | 49.800 | `1.211x` | 3,368.295 | 64.317 | `1.336x` |
| Memory 7m | 11,492.443 | 52.570 | `1.062x` | 9,277.984 | 65.118 | `1.115x` |

The geometric-mean throughput gains are `1.309x` CPU and `1.431x` Metal.
Against the unchanged pinned Rust medians, current Zig remains `2.109x`
slower on CPU and `1.760x` slower on Metal. Therefore neither the Rust-parity
threshold nor the `10x` forcing target is reached.

All seven CPU/Metal binary proof pairs were byte-identical and verified. Metal
reported 73-79 dispatches per row and zero CPU fallbacks. The invalid
historical memory corpus was not reused: the memory row used the valid
7.37M-step replacement established by the preceding soundness-aware study.
Peak RSS ranged from 1.39 to 13.98 GB on CPU and 0.53 to 9.76 GB on Metal.

The results reject the premise that native and Cairo committed-cell rates
differ only because of low-level PCS kernels. The remaining gap is dominated
by Cairo-specific witness execution, interaction construction, static
preprocessing, and host AIR evaluation. Reaching another order of magnitude
requires the already identified system architecture:

- profile-authenticated immutable preprocessing products;
- one final base arena planned before witness execution;
- generated CPU witness writers rather than a row-wise bytecode switch;
- general Metal AOT witness admission beyond the captured SN2 schedule; and
- resident interaction and AIR evaluation fused into commitment epochs.

## Result 6: reuse authenticated Pedersen points in deductions

Component-level profiling showed that the Pedersen aggregator spent 2.65
seconds inside its generated witness program. The program invokes the
window-nine partial-EC deduction 56 times per row. Each invocation rebuilt the
same fixed Pedersen window point even though the proof transaction had already
constructed the exact authenticated preprocessed point table.

The transaction now constructs that table before base witness execution and
passes a typed borrowed view through the deduction context. Window-nine,
window-eighteen, and points-table deductions read the exact existing points.
No program label or benchmark input participates in dispatch.

| Backend | Before | After | Improvement |
| --- | ---: | ---: | ---: |
| CPU | 3,915.226 ms | 1,509.376 ms | `2.594x` |
| Metal | 3,760.697 ms | 1,369.378 ms | `2.746x` |

CPU and Metal produced the same 769,097-byte proof with SHA-256
`2f22237a78c26b5abaae644979c0caaf3fc7c8bf4587c8b2d050ff42acb71325`.
Metal used 75 dispatches and zero CPU fallbacks.

## Frontend placement profile

Nested stage instrumentation was extended through base witness components,
interaction components, source materialization, output initialization,
program execution, base lowering, and feed retention. The profile established
that the current Metal product is intentionally hybrid: witness generation,
interaction construction, and Cairo AIR evaluation are host work; Metal owns
PCS, quotient, and FRI stages.

Before the direct-feed change, representative CPU attribution was:

| Workload | Base witness | Interaction build | AIR composition |
| --- | ---: | ---: | ---: |
| Arithmetic 2m | 1,499 ms | 352 ms | 378 ms |
| Memory 7m | 4,518 ms | 853 ms | 1,181 ms |

Metal reported the same host shape: Memory 7m spent 4,606 ms in the base
witness, 884 ms in interaction construction, and 1,221 ms in AIR composition.
It then used 79 Metal dispatches with zero fallbacks.

A symbolized `/usr/bin/sample` capture agreed with the stage data. The
recorded witness graph and BLAKE2s commitments were the dominant active CPU
stacks. A device trace could not be collected: `xctrace` requires full Xcode,
while this host has `/Library/Developer/CommandLineTools`. No Metal
complete-command or occupancy claim is made without that evidence.

## Result 7: emit canonical lookup feeds directly

The finer profile found the dominant frontend defect. On Memory 7m,
`add_opcode_small` spent only 176-189 ms executing its witness bytecode but
more than 2.1 seconds retaining its 116-word lookup feed. The writer emitted
row-major words and `live_graph` allocated and transposed the complete feed
into the column-major layout consumed by LogUp.

The witness ABI now emits lookup words in canonical column-major layout, which
already matches the Metal generated-witness ABI. `live_graph` and the
conformance executor transfer ownership of lookup and subcomponent feeds
instead of duplicating them. A static coverage check also avoids clearing
trace and feed destinations that a straight-line recorded program proves it
will overwrite; incomplete compatibility programs retain zero initialization.

The Memory 7m witness graph fell from 4,518 ms to 0.92 seconds in the final
portfolio screen. A direct before/after screen measured complete CPU proving
at 10,115.634 versus 7,140.352 ms before the coverage refinement. The final
screen measured 6,888.709 ms CPU and 5,069.174 ms Metal.

## Current seven-workload screen

This is a single controlled diagnostic screen at `9c46d8fc`, not a judged
multi-round promotion. Gains compare with the post-PoW, pre-Pedersen profile
captured before Results 6 and 7.

| Workload | CPU ms | CPU gain | Metal ms | Metal gain |
| --- | ---: | ---: | ---: | ---: |
| all-opcodes | 1,430.705 | `0.978x` | 1,384.647 | `1.061x` |
| Poseidon aggregator | 1,069.266 | `0.983x` | 925.778 | `1.040x` |
| Pedersen aggregator | 1,528.133 | `2.562x` | 1,355.564 | `2.774x` |
| Fibonacci 100k | 1,648.315 | `1.142x` | 1,254.109 | `1.254x` |
| Factorial 100k | 2,156.506 | `1.157x` | 1,775.236 | `1.254x` |
| Arithmetic 2m | 2,810.166 | `1.416x` | 2,044.014 | `1.625x` |
| Memory 7m | 6,888.709 | `1.541x` | 5,069.174 | `1.790x` |

The geometric-mean complete-proof improvements are `1.323x` CPU and `1.458x`
Metal. Every CPU/Metal pair is byte-identical and verifies. Metal reports
73-79 dispatches and zero fallbacks in every row. The two small CPU ratios are
neutral diagnostic noise, not claimed regressions or wins.

The next high-leverage boundary is now narrower and better supported by data:

1. Generate authenticated CPU witness writers from semantic program identity,
   replacing the row-wise opcode switch.
2. Generalize the existing Metal witness AOT path from the SN2 resident
   schedule to live Cairo geometry.
3. Emit base columns and retained feeds into one backend-shaped arena so
   witness output, interaction input, and commitment share storage.
4. Move interaction materialization and Cairo AIR evaluation behind explicit
   CPU-SIMD and Metal backend interfaces.

## Result 8: generated CPU witness writers

The official witness bundle now generates one native writer per full
`Program.semanticIdentity()`. Admission uses the complete 256-bit structural
identity rather than labels or the legacy 64-bit diagnostic hash. The same
writers serve the CPU product and the current host-witness portion of the
Metal product.

On Memory 7m, the CPU witness graph fell from 813.373 to 632.933 ms (`1.285x`)
and witness execution fell from 630.323 to 492.046 ms (`1.281x`). The Metal
product's host witness graph fell from 805.644 to 691.123 ms (`1.166x`) and
execution fell from 627.719 to 557.105 ms (`1.127x`). Complete proofs moved
only from 6,888.709 to 6,832.396 ms CPU and from 5,069.174 to 4,973.406 ms
Metal. The result is accepted architecture and a material witness-stage gain,
not a broad system-performance promotion.

## Result 9: generalized Metal AOT and LogUp bridge

Metal witness generation now covers every official deduction selector from 0
through 18. Focused Apple runtime-compiler probes passed add-mod, mul-mod,
Blake, window-nine Pedersen, Poseidon, and the 3.17 MB generic EC-op kernel.
The complete official source has 128 kernels, 12,120,041 bytes, and 276,276
lines. Runtime source JIT is therefore rejected as a production architecture.
The required build is sharded offline compilation followed by one
authenticated metallib link and one runtime library load.

A backend-neutral interaction executor boundary and a fail-closed Metal
implementation exercise the existing authenticated relation kernels over all
official source layouts. CPU remains the default. The host-bridged Metal path
is available only with `STWO_CAIRO_METAL_HOST_BRIDGED_LOGUP=1` while resident
witness storage is incomplete.

Exact proof parity held on all-opcodes, Arithmetic 2m, and Memory 7m. Metal
reported zero fallbacks. The bridge is not promoted:

| Workload | Default Metal ms | Host-bridged LogUp ms | Result |
| --- | ---: | ---: | --- |
| Arithmetic 2m | 2,044.014 | 2,162.338 | reject |
| Memory 7m | 4,973.406 | 4,892.090 | inconclusive single-sample noise |

The device arithmetic is already fast. On Arithmetic 2m, the 2,097,152-row
main relation used 16.5-16.8 ms of GPU time, while copying its host source
columns into a transient arena cost 96.9-123.7 ms. The controlled Memory 7m
run spent 849.440 ms in the bridged fraction stage and peaked at 9.76 GB RSS
with a 17.65 GB physical-footprint counter.

This rejects post-witness host bridging. The critical path is one shared
resident allocation whose ownership crosses generated witness execution,
lookup-word retention, LogUp, and commitment. The staged executor remains an
exact differential harness for that architecture and is not enabled in the
production capability surface.
