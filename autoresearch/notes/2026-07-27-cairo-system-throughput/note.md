# Cairo system-throughput autoresearch

## Status

Final Cairo throughput research round based on the merged soundness head
`053db61ad5c2f7561028424ed5c137feaf8729fc`. This is not a Native-board
promotion: the current autoresearch manifest does not yet score the Cairo
frontend.

## Objective

Reduce the geometric mean of complete proof-transaction time across the fixed
seven-workload Cairo portfolio on Zig SIMD and Zig Metal. Preserve every
workload, statement, protocol parameter, proof byte, Rust-oracle result,
backend capability declaration, and resource-admission rule.

An optimization is useful only when its admission follows semantic or
structural properties shared by production workloads. Workload names, benchmark
selectors, fixture hashes, and target sizes must never select a fast path.

## Portfolio

| Workload | VM steps | Committed cells |
| --- | ---: | ---: |
| all-opcodes | 1,499 | 97,420,320 |
| Poseidon aggregator | 6,892 | 48,299,328 |
| Pedersen aggregator | 5,872 | 48,037,024 |
| Fibonacci 100k | 700,022 | 112,959,872 |
| Factorial 100k | 600,015 | 123,184,848 |
| Arithmetic 2m | 2,200,019 | 216,639,776 |
| Memory 7m | 7,367,979 | 604,162,096 |

## Baseline

Three samples per lane, rotated Rust/Zig CPU/Zig Metal order, no discarded
measured samples. Rust uses release-native Stwo-Cairo with `parallel` and
`prover`; Zig uses `ReleaseFast`; Metal uses authenticated AOT. Every Zig
CPU/Metal proof matches exactly and the official Rust verifier accepts the
representative proofs.

| Workload | Rust prove ms | Zig CPU prove ms | Zig Metal prove ms |
| --- | ---: | ---: | ---: |
| all-opcodes | 1,320.000 | 4,660.253 | 8,528.904 |
| Poseidon aggregator | 1,130.000 | 3,326.286 | 6,098.325 |
| Pedersen aggregator | 1,050.000 | 6,196.363 | 7,654.078 |
| Fibonacci 100k | 1,740.000 | 3,933.672 | 4,224.887 |
| Factorial 100k | 2,610.000 | 6,187.767 | 6,880.955 |
| Arithmetic 2m | 3,090.000 | 9,729.436 | 10,215.586 |
| Memory 7m | 6,060.000 | 22,438.403 | 22,927.321 |

## Current candidate

Parallelizing structurally independent 32K-row interaction inversion batches
through the existing bounded prover pool improves all seven CPU workloads.
Exact proof bytes are unchanged.

| Workload | Baseline mean ms | Candidate mean ms | Speedup |
| --- | ---: | ---: | ---: |
| all-opcodes | 3,965.944 | 3,051.751 | 1.300x |
| Poseidon aggregator | 2,646.140 | 2,208.967 | 1.198x |
| Pedersen aggregator | 5,035.496 | 4,592.651 | 1.096x |
| Fibonacci 100k | 3,483.555 | 2,597.287 | 1.341x |
| Factorial 100k | 5,317.483 | 4,326.557 | 1.229x |
| Arithmetic 2m | 9,322.759 | 7,033.067 | 1.326x |
| Memory 7m | 21,297.286 | 15,355.970 | 1.387x |

The geometric-mean ratio is `0.790753`, a `1.265x` portfolio speedup. Metal
validation and post-change profiling remain in progress.

## Metal design brief

Workload and target devices:
: Complete Cairo proofs on the Apple M5 Max family, initially the local
  Mac17,7 host. The production route uses authenticated AOT only.

Unit of work and equivalence oracle:
: One complete proof transaction for an unchanged Cairo statement. Exact Zig
  CPU/Metal bytes plus independent pinned Rust verification are required.

Measurement boundary, build mode, and run conditions:
: Backend-reported proof transaction and cold CLI wall time, `ReleaseFast`,
  interleaved baseline/candidate orders, controlled sequential large runs.

Measured bottleneck and evidence:
: Host witness execution and host SIMD AIR constraint evaluation dominate the
  large Metal profile. Metal driver waits are a small sampled fraction. The
  released capability contract confirms that only commitment, LDE, quotient,
  and FRI are currently on Metal.

Required features and fallbacks:
: Existing authenticated AOT core library and current device capability gates.
  Device-labelled evidence must report zero CPU fallbacks.

Resource lifetime/storage table:
: To be completed from the live witness, AIR, prepared-column, tree, quotient,
  and FRI ownership graph before changing residency.

Peak working set and in-flight multiplier:
: The memory-7m case reaches roughly 14 GiB process peak when run sequentially.
  Any resident design must retain bounded ownership and avoid duplicating the
  trace.

CPU-GPU and pass dependency graph:
: Cairo VM sidecar -> host witness -> host AIR evaluation -> Metal
  commitment/LDE/quotient/FRI -> host serialization/verification.

Command-buffer and in-flight ownership plan:
: Reuse existing proof-session ownership. Enlarge epochs only after tracing
  synchronization boundaries; do not add a parallel lifetime registry.

Binding and pipeline-compilation plan:
: Reuse authenticated AOT pipelines and existing prepared plans. No source JIT
  or per-request pipeline construction may enter the product path.

Shader/threadgroup plan:
: Derive only after stage attribution. Structural AIR/witness programs, not
  benchmark identities, may select generated kernels.

Work/byte/dispatch budget:
: First remove host materialization and redundant full-trace passes. Kernel
  tuning is secondary until device work is a material share of request time.

Expected trace changes:
: Lower host witness/AIR samples, fewer host-to-device bytes and ownership
  transitions, higher GPU busy share, unchanged proof bytes and fallbacks.

Correctness, ABI, and synchronization proof:
: Per-component cumulative parity with the CPU implementation, checked buffer
  layouts, explicit owner lifetime through last GPU use, independent final
  verification, and mutation tests.

Before/after validation:
: Focused per-component A/B, then the complete seven-workload portfolio on CPU
  and Metal, then normal repository product and oracle gates.

## Paused-state findings

Three implementation increments are accepted on the research branch:

1. parallel interaction-trace inversion batches;
2. packed QM31 batch inversion; and
3. generic dominant-domain AIR scheduling.

The fully measured seven-workload CPU portfolio is `1.29x` faster than the
original branch baseline. The later domain scheduler has not yet received a
new full seven-workload judgement, but its exact A-B-B-A large-workload screen
added `1.16x`, `1.36x`, and `1.28x` on all-opcodes, arithmetic-2m, and
memory-7m respectively.

Authenticated CPU AIR AOT specialization was rejected. It produced exact
proofs but only `1.017x` geometric-mean speedup across the same three large
sentinels, while growing the executable from 1.8 MiB to 5.9 MiB and requiring
a 57.73-second, 3.20-GiB build. That source is not retained.

The official products now expose opt-in machine-readable Cairo stage profiles.
On arithmetic-2m, the accepted CPU head proved in 4.812 seconds and Metal in
5.351 seconds. Proof bytes were exact across both backends; Metal used 74
dispatches and zero CPU fallbacks.

The profile changes the next-round priority:

- host base-trace construction costs 1.51-1.55 seconds on both backends;
- Metal FRI quotient build/commit costs 1.350 seconds versus 0.262 seconds on
  CPU, a `5.15x` stage inversion;
- PoW costs about 0.59 seconds on both; and
- host composition plus interaction construction remains roughly 0.75 seconds
  in the Metal transaction.

The immediate next candidate is not another interpreter micro-optimization.
It is a Metal System Trace of the FRI quotient stage followed by a live-code
base-trace pass/allocation profile. Diagnostic artifacts are stored under
`/private/tmp/cairo-stage-profile-20260727`.

## Final Metal quotient round

The 5.15x FRI inversion came from an unbounded scheduling branch, not weak FRI
arithmetic. Arithmetic-2m supplies 1.821 GB of raw quotient columns in 361
physical source runs. Although the runtime documents a 64-run ceiling, its
historical `raw_bytes >= 64 MiB` predicate launched one full-domain numerator
pass per run. Device timing measured 1,291 ms for those passes.

The accepted candidate applies the run ceiling at every byte size. Large,
high-fragmentation inputs are gathered once with a Metal blit encoder into a
private flat arena and evaluated by the existing fused raw quotient kernel.
Low-run resident inputs retain zero-copy segmented evaluation; small
fragmented inputs retain the previously proven CPU flat pack. Selection uses
only byte volume and physical source fragmentation.

Arithmetic-2m FRI quotient/commit falls from 1,350 ms to 212 ms, a 6.37x stage
improvement. Its complete proof falls from 5.351 s to 4.107 s in the adjacent
profile, a 1.30x system improvement. Exact proof bytes and zero-fallback
classification are unchanged.

The exact-predecessor A-B-B-A portfolio result is:

| Workload | Predecessor mean ms | Candidate mean ms | Speedup |
| --- | ---: | ---: | ---: |
| all-opcodes | 7,355.605 | 3,130.339 | 2.350x |
| Poseidon aggregator | 5,758.749 | 2,688.987 | 2.141x |
| Pedersen aggregator | 7,627.300 | 5,622.601 | 1.357x |
| Fibonacci 100k | 3,533.128 | 2,785.952 | 1.268x |
| Factorial 100k | 5,621.864 | 5,297.604 | 1.061x |
| Arithmetic 2m | 5,600.671 | 4,340.107 | 1.290x |
| Memory 7m | 13,774.909 | 10,841.578 | 1.271x |

Geometric-mean prove ratio is `0.678774`, or `1.473x` throughput. All 28
measured proofs verified, each row was byte-identical across predecessor and
candidate, and Metal reported zero CPU fallbacks throughout. Cold wall ratio
is `0.683646`.

The optimization trades latency for a larger temporary source arena.
Geometric-mean peak-footprint ratio is `1.100906`; memory-7m rises from 13.722
to 16.433 GiB. That measured cost is accepted for this research candidate but
must remain visible in any later promotion or service-capacity decision.

The original memory corpus artifact was invalid under the sound global LogUp
statement path because it encoded a reversed output segment. The final row
uses the intended `stwo_memory_200x300.json` execution, preserves the
historical proof hash, and does not weaken statement validation.

Final validation passed:

- `zig build metal-check test-cairo-metal-product -Doptimize=ReleaseFast
  -Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle
  -j2`;
- `zig build test-native-metal test-cairo-metal-oracle
  -Doptimize=ReleaseFast
  -Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle
  -j2`;
- exact proof verification and zero-fallback assertions in every measured
  candidate process; and
- `git diff --check`.

## Latest three-lane Cairo matrix

A clean identity-bound build of commit `03644459` was compared on the Apple M5
Max against the unchanged pinned Rust `stwo-cairo` Release/native binary with
its default parallel feature. Each lane ran three cold processes in rotated
order. No sample was discarded. Prove time is the backend-reported proof
transaction and excludes execution and verification.

| Workload | Steps | Committed cells | Rust exec / prove ms | Zig CPU exec / prove ms | Zig Metal exec / prove ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 1,499 | 97,420,320 | 3.189 / 1,010.000 | 18.407 / 2,343.844 | 20.098 / 2,321.179 |
| Poseidon aggregator | 6,892 | 48,299,328 | 2.917 / 815.000 | 17.684 / 1,976.634 | 14.891 / 1,893.150 |
| Pedersen aggregator | 5,872 | 48,037,024 | 6.841 / 794.000 | 21.781 / 4,358.832 | 22.670 / 4,244.287 |
| Fibonacci 100k | 700,022 | 112,959,872 | 77.248 / 1,250.000 | 112.550 / 2,467.677 | 114.533 / 2,136.681 |
| Factorial 100k | 600,015 | 123,184,848 | 65.619 / 1,250.000 | 104.890 / 4,253.705 | 99.452 / 3,881.166 |
| Arithmetic 2m | 2,200,019 | 216,639,776 | 208.288 / 2,190.000 | 298.090 / 5,269.462 | 291.823 / 4,501.328 |
| Memory 7m | 7,367,979 | 604,162,096 | 713.659 / 5,000.000 | 951.691 / 12,206.887 | 953.136 / 10,341.602 |

| Workload | Rust step MHz / Mcells/s | Zig CPU step MHz / Mcells/s | Zig Metal step MHz / Mcells/s |
| --- | ---: | ---: | ---: |
| all-opcodes | 0.001484 / 96.456 | 0.000640 / 41.564 | 0.000646 / 41.970 |
| Poseidon aggregator | 0.008456 / 59.263 | 0.003487 / 24.435 | 0.003640 / 25.513 |
| Pedersen aggregator | 0.007395 / 60.500 | 0.001347 / 11.021 | 0.001384 / 11.318 |
| Fibonacci 100k | 0.560018 / 90.368 | 0.283677 / 45.776 | 0.327621 / 52.867 |
| Factorial 100k | 0.480012 / 98.548 | 0.141057 / 28.959 | 0.154597 / 31.739 |
| Arithmetic 2m | 1.004575 / 98.922 | 0.417503 / 41.112 | 0.488749 / 48.128 |
| Memory 7m | 1.473596 / 120.832 | 0.603592 / 49.494 | 0.712460 / 58.421 |

Against the first same-host Cairo matrix, raw geometric-mean prove throughput
improved `1.678x` for Zig CPU and `2.333x` for Zig Metal. The unchanged Rust
control also improved `1.425x` between those sessions, exposing meaningful
cross-run host drift. Normalizing by that control gives directional net gains
of about `1.18x` for Zig CPU and `1.64x` for Zig Metal. The exact
predecessor/candidate A-B-B-A Metal result above, `1.473x`, remains the stronger
causal claim.

Zig Metal is now `1.096x` faster than Zig CPU by geometric mean across this
portfolio, but Zig CPU and Zig Metal remain respectively `2.760x` and `2.519x`
slower than the contemporary Rust baseline. The frontend has materially
benefited, especially on Metal, but it has not reached Rust parity.

All 63 measured processes self-verified. The pinned official Rust verifier
accepted one proof from every lane and workload. Each lane was deterministic;
Zig CPU and Zig Metal proof bytes matched exactly on all seven rows, and Metal
reported zero CPU fallbacks. The pinned Rust prover uses a different
transcript/claim realization, so its accepted proofs are not byte-identical to
the Zig proofs.
