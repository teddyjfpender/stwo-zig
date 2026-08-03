# RISC-V CSP PoW variance and Fibonacci-500k diagnostic

**Captured:** 2026-08-03

**Implementation:** `ded31a82c5d83a1c71f491f3350de88c6a6e2a47`

**Host:** Apple M5 Max, 18 logical CPUs, 40 GPU cores, 64 GiB, macOS 26.6

**Power:** AC power, Low Power Mode disabled

**Mode:** clean `ReleaseFast` CPU and authenticated-AOT Metal products

This note records two findings from the complete post-optimization RISC-V
benchmark pass:

1. Small non-monotonic CSP timings are dominated by fixed proof geometry and
   transcript-specific proof-of-work rather than guest-hash scaling.
2. The exact current Stark-V Fibonacci-500k guest exceeds 1.7 MHz through the
   CPU product and 2.1 MHz through Metal at the run-plus-prove boundary.

This is local diagnostic evidence. It does not replace a locked-host judged
receipt or make a cross-device supremacy claim.

## Measurement protocol

The CSP matrix used one verified warmup and three verified samples per row at
the production security profile:

- Blake2s channel
- `pow_bits = 26`
- 70 FRI queries
- blowup log 1
- fold step 1

Stage diagnostics used one verified warmup and one profiled sample. The
reported non-PoW time is the measured proving stage minus its profiled
`proof_of_work` child. It is diagnostic rather than a protocol timing boundary.

## SHA-256 scaling

The headline matrix reported 512 bytes slightly faster than 128 and 256 bytes.
The underlying proof work is monotonic:

| Input | Retired cycles | Padded proof cells | Proving excluding PoW | PoW |
| ---: | ---: | ---: | ---: | ---: |
| 128 B | 14,056 | 18,754,688 | 0.608 s | 0.116 s |
| 256 B | 22,832 | 19,293,824 | 0.615 s | 0.116 s |
| 512 B | 40,384 | 20,568,704 | 0.618 s | 0.089 s |

All three statements use 427 opcode columns, 489 infrastructure columns, and
444 interaction columns. Fixed infrastructure contributes 18,006,176 padded
cells, so a 2.87x increase in retired cycles from 128 to 512 bytes increases
the calculated padded proof geometry by only 9.7%. The 512-byte transcript's
shorter PoW search and small witness/runtime variation reverse that small
structural increase in the total timing.

The correct interpretation is therefore not that SHA-256 scales negatively.
At these sizes the proof is fixed-overhead dominated, and its non-PoW proving
time grows from 0.608 to 0.618 seconds.

## Keccak-512 regression

The secure headline timing at 512 bytes is a real latency outlier for this
exact deterministic statement, but the underlying Keccak/AIR path scales
normally:

| Input | Padded proof cells | Proving excluding PoW | PoW | Matrix proof duration |
| ---: | ---: | ---: | ---: | ---: |
| 256 B | 19,916,112 | 0.616 s | 0.154 s | 0.871 s |
| 512 B | 21,854,960 | 0.628 s | **0.954 s** | **1.739 s** |
| 1,024 B | 25,730,032 | 0.652 s | 0.091 s | 0.883 s |

The current pooled grinder searches for the lowest valid nonce. That nonce is
fully determined by the Fiat-Shamir transcript and is independent of worker
scheduling. Repeating an identical ELF and input therefore repeats essentially
the same amount of PoW work; three timing samples do not average over three PoW
draws.

Changing trace layout, commitments, or proof implementation changes the
transcript and effectively draws a new first-valid-nonce distance. That makes
a single fixed statement's secure total unsuitable as the only engineering
regression metric across implementation commits.

The CPU and Metal totals show the same outlier because both products currently
use the shared host PoW grinder after FRI. Metal residency cannot accelerate or
hide this CPU-side stage.

An AC-power rerun of baseline commit `5d540e94174e4a678088a5ad793306280aa70c40`
confirmed that the outlier is not the earlier battery-power problem. At the
same time, the optimized frontend materially reduced the 512-byte execution
and witness path:

| Backend | Baseline execution + witness | Current execution + witness |
| --- | ---: | ---: |
| CPU | 0.448 s | 0.106 s |
| Metal | 0.434 s | 0.087 s |

The optimization should not be reverted on the basis of the aggregate
Keccak-512 number. The secure latency remains honest, while its attribution
must identify PoW separately.

## Benchmark follow-up

Issue #36 should retain the following requirements when stage-level RISC-V
descriptors are added:

- Publish secure total prove time including PoW.
- Publish `pow_seconds` and proving time excluding PoW alongside the total.
- Use the non-PoW structural time for implementation regression attribution.
- Measure PoW throughput with fixed work, or use independent authenticated
  messages when estimating expected end-to-end PoW latency. Repeating one
  deterministic statement is not an independent sample.
- Record enough public PoW telemetry to distinguish candidate count from hash
  throughput without weakening transcript binding.
- Treat a native Metal PoW grinder as a backend optimization opportunity, not
  as a change to the 26-bit production security policy.

## Exact Stark-V Fibonacci-500k guest

The comparison guest was built unchanged from
`ClementWalter/stark-v@d478f783055aa0d73a93768a433a3c6c31c91d1c` using its
pinned `nightly-2026-01-29` toolchain. Its input is the little-endian `u32`
value 500,000.

| Artifact | SHA-256 |
| --- | --- |
| `fib_input` ELF | `dc8176f484d287ba07aa1057feaf5a7ce1d9c7035f50d03be66abc241f055ee7` |
| input bytes | `46cb8fe47782edc9066a7a0c3f03a2e32cf3e6d4151a6f7148d1e51935056cf9` |

The frontend retired 2,500,157 instructions and produced the same statement
and transcript on both backends:

- statement: `0354c0a93d27b88aedac158fd748d9e49b82d31820bc846f9257c9e0c21d23c7`
- transcript: `48642a80d60419bba6e766ebf44830a69d7b9948b5630e813af810088827b517`

One verified warmup and three verified samples produced:

| Backend | Run + prove | Run + prove MHz | Verified E2E | Verified MHz | Peak footprint |
| --- | ---: | ---: | ---: | ---: | ---: |
| CPU/SIMD | 1.460 s | **1.712 MHz** | 1.610 s | **1.553 MHz** | 3.60 GiB |
| Metal | 1.185 s | **2.110 MHz** | 1.292 s | **1.934 MHz** | 3.58 GiB |

`MHz` means retired RISC-V instructions per second, not Fibonacci iterations
per second. The CPU profile attributed approximately 0.102 seconds to PoW for
this transcript.

Stark-V's README reports 0.747-0.921 MHz on an M2 Max for 8-12 simultaneous
proofs at 24-bit PoW. Its Divan counter is aggregate cycles across those
parallel proofs. The table above is single-proof intra-proof parallelism at the
stricter 26-bit production profile on an M5 Max. The result is useful context,
but hardware, concurrency mode, and security differ, so it is not a controlled
supremacy comparison.

## Local report digests

The reports used to prepare this note had these SHA-256 digests:

| Report | SHA-256 |
| --- | --- |
| complete CSP CPU | `b4d0c6b8200fa312e887b0d2c63d487a9108911bb3849c41b772b4cd3cda2275` |
| complete CSP Metal | `059dc2ca76c634677a742f24688939c85a042a2cb25b9cfd401724e44d0dad4e` |
| Fibonacci-500k CPU | `ada7d7c018a91abc1c286f089a2624ac733179f114ed1de43844d7d810174350` |
| Fibonacci-500k Metal | `cba35e1b761fe5cdffb30fcb45415943b4579cba0daeb79ebc5037397f6c36ec` |

All measured proofs verified. Both product identities were clean,
`ReleaseFast`, and bound to the implementation commit named above.
