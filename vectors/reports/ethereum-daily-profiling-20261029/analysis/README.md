# Representative CPU execution profile — 2026-10-29

These are synthetic Ethereum-profile programs, not Ethereum block proofs. All successful cases use canonical q70/PoW26, ReleaseSafe with profiling symbols, four native windows, and a single complete original STARK. Each proof is decoded and independently verified after producer destruction. Recursion and checkpoint I/O are not exercised.

Three clean samples per case are selected in `analysis/selection.json`: original repeats2/3 plus one replacement. A concurrent capture overlapped all three runs in the first repeat; those original measurements remain intact and are excluded explicitly.

| Workload | Cycles | Keccak / recovery calls | First-touch words | Request median | Prove median | Verify median | RSS median | Proof size |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| keccak_heavy × 8 | 38 | 8 / 0 | 0 | 2.355s | 1.967s | 0.190s | 258.3MB | 12.34MB |
| memory_heavy × 4096 | 32,782 | 0 / 0 | 4,096 | 2.145s | 1.833s | 0.070s | 348.6MB | 1.26MB |
| mixed_ethereum × 8 | 32,815 | 8 / 1 | 4,096 | 5.464s | 4.678s | 0.328s | 473.4MB | 20.56MB |

The mixed workload executes512 native RAM/ALU rounds per Keccak call. It therefore has nearly the same32.8k native cycles and4096 first-touch words as the memory case, plus eight Keccak calls and one recovery call. This provides a controlled small workload comparison; it does not establish full-block scaling.

## Measured priorities

- Keccak8: DEEP quotient/FRI commitment is1.295s median, about55% of request time. Composition itself is0.137s. Repeated sampled-column and opening work deserves priority over optimizing the already small instruction-execution phase.
- Memory4096: composition is0.808s, native interaction preparation0.387s and proof-of-work0.411s. Its bottleneck differs materially from the Keccak case.
- Dense mixed8: DEEP/FRI is2.128s, composition0.887s, proof-of-work0.833s and native interaction preparation0.353s. Independent verification adds0.328s. No gain is inferred by summing overlapping parent and child timings: these figures use exclusive stage costs.
- Proof envelopes are12.34MB for Keccak8 and20.56MB for mixed8. The complete pipeline must account for serialization, transfer and verification; the current request timer includes local serialization and verification only.

The stage rankings are based on measured exclusive durations in `analysis/stage-priorities.csv`. A stage median need not add exactly to the median request duration. Detailed inclusive and exclusive rows, immutable reports, hashes, software/machine metadata and original failures are retained alongside the CSVs.

## Ratio-matched421 attempt

The larger `mixed_ethereum:421` attempt failed closed with `V7MemoryResourceLimit` after6.944s command wall time. Its retained failure is in `ratio-matched-421/`. It produces215,552 first-touch words: the corresponding native stores and loads alone require431,104 RAM events, exceeding the unchanged default65,536-event memory admission cap. The guard runs before sorted witness matrix construction; this is not evidence of observed physical memory exhaustion.

There is no successful proof, stage report, RSS measurement or whole-block timing to infer from that failed attempt. No cap was raised automatically. A subsequent explicitly reported benchmark policy, if approved, must remain a separate run and keep this failure evidence.

## Explicit-policy421 retry

The separately retained `ratio-matched-421-policy/` retry used an explicit benchmark admission policy of1,048,576 events and at most eight RAM cohorts, keeping the8GiB memory-stage,24GiB request and8GiB retained-PCS limits unchanged. It completed original proof generation, then the fresh receiver rejected `UnclosedV7NativeRelations`: a native ordinary-memory or auxiliary-clock relation did not close. The process ended after112.090s; this is a failed-attempt duration, not an input-to-verified-proof measurement.

The producer logged a9,062,228,863-byte cumulative tracked allocation peak. This is not process RSS. No successful report or complete stage distribution was emitted, so those fields remain unavailable. The original event-cap failure and this algebraic rejection are both preserved. Diagnosis must resolve the exact relation without weakening verification before the larger workload can be counted as successful.

A source-only diagnostic reusing the exact native interaction generator subsequently found all four ordinary-memory residuals to be zero. All four auxiliary memory-clock sums were nonzero, with21,152 /21,152 /21,153 /21,158 clock-update rows. The1,726,115-cycle program therefore exposed honest gap-row accounting that the smaller corpus did not exercise. This diagnostic is explicitly unauthenticated (`verified=false`); it identifies the failing guard and does not replace a complete proof or justify bypassing the guard.

## Completed larger case after explicit layout correction

The separately retained `ratio-matched-421-actual-ram/` run now proves and freshly verifies all1,726,115 cycles,421 Keccak calls, one recovery call and452,200 RAM events in113.412s input-to-verified-proof time (105.112s producer,0.804s verification). Peak RSS was8.719GB and tracked cumulative peak9.048GB. The complete envelope is21,906,041 bytes; the stdout raw STARK payload is21,742,610 bytes.

This one clean sample identifies three dominant exclusive costs: DEEP/FRI42.974s, composition37.522s and native interaction preparation17.054s, together about86% of request time. The new layout removes only the no-consumer synthetic RAM-clock projection under a distinct identity; complete receiver guards remain strict. Earlier failures are retained. The run is synthetic and contains no recursive reduction or checkpoint I/O; it supports no full-block latency claim.
