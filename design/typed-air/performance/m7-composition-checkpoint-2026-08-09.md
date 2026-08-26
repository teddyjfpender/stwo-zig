# M7 composition development checkpoint — 2026-08-09

> **Classification:** non-promotional development evidence. This note is not
> an M7 receipt, does not close R-001, and cannot support formal promotion.

This checkpoint records a controlled CPU comparison for the prepared RISC-V
composition scheduler and a separate proof-identity check. It exists to retain
useful engineering evidence while the complete frozen M7 protocol remains
open.

## Timing comparison

The measured candidate was commit
`72527052cf838b7cc41b02975cdfb6a1f47db0a0` with tree
`7ccc338fc059382afa674187f3987559ea9f4666`. Its benchmark binary SHA-256 was
`68ae7160dbafd61778167bfacd6b241e2e51e1ad00493c22354f38aa9d551614`.
The prior implementation was commit
`4232cc5521d7296c2a0c6da12e51ccd49f0a389e`; its benchmark binary SHA-256 was
`b6cd658dcab89807ae31a5eef654555968099ea2af5d78aa0c82c495a9f544b8`.

The comparison used the development profile `pow_bits=0`, `n_queries=3`, 12
excluded warmups, and 60 measured samples, with five interleaved samples per
candidate/baseline cell. All 94 proof-bearing runs in the complete validation
session verified. The proof-identity reporting mode described below was not
enabled for timing.

| Workload | Workers | Prove result | Composition result | Other observation |
| --- | ---: | --- | --- | --- |
| `multi_shard_addi` | 1 | paired median -0.14% (flat) | — | expected low-parallelism control |
| `multi_shard_addi` | 2 | 1818.4 ms vs 2064.6 ms; paired median -11.92% | 305 ms vs 546 ms; -44.14% | total time -10.26% |
| `multi_shard_addi` | 4 | paired median -5.18% | — | positive but below the two-worker gain |
| Poseidon field16 | 1 | near flat | — | expected low-parallelism control |
| Poseidon field16 | 2 | paired median -13.22% | 631 ms vs 1171 ms; -46.11% | gain isolated to composition |
| Poseidon field16 | 4 | paired median -4.97% | — | positive but below the two-worker gain |

Times in each `A vs B` cell are candidate versus prior. Main trace,
interaction trace, and FRI stages were flat; the observed gain was isolated to
composition. Median peak RSS was flat within 0.01%. One Poseidon four-worker
candidate sample reached 1928.8 MiB, but three additional paired repetitions
did not reproduce it: candidate RSS remained between 1897.6 and 1897.8 MiB.
The candidate benchmark binary was 0.72% larger than the prior binary.

These results support continued development of prepared composition lanes.
They are not a general scaling result: the two-worker cells improved more than
the four-worker cells, the security parameters were deliberately reduced, and
this capture is not a digest-bound M7 attempt bundle or receipt.

## Separate proof-identity check

Proof identity was checked later at final development head
`b84bd6c0c24a5fb3f7fc076cd1ce2a55ede9150d`, tree
`ff80551e84c0e235bbbf3362ccc8d6240ec9b287`. The ReleaseFast benchmark binary
SHA-256 was
`30802dc4f9623fed2971924563a7e99654b5c96891a713f440349a9fc46e1a9a`.
At `pow_bits=0`, `n_queries=3`, worker counts 1, 2, and 4 all produced the same
canonical proof identity for each checked workload:

| Workload | Canonical bytes | SHA-256 at workers 1, 2, and 4 |
| --- | ---: | --- |
| `multi_shard_addi` | 161274 | `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293` |
| Poseidon field16 | 285105 | `19389b1a3a42eeebb6712244d3490f89791831ba653c1c9bd8db3d5cf529a90c` |

For the one-worker predecessor check, the proof reporter from
`035db833449fae2e2177adcdec7e262623a78388` was applied only as
instrumentation to `4232cc5521d7296c2a0c6da12e51ccd49f0a389e`. That instrumented ReleaseFast
binary had SHA-256
`7bac33622ea3a207fd167621e02333172083dafb2c4a76cb6d8d281901d90b80`.
Both one-worker predecessor proof identities exactly matched the corresponding
final-head identities above.

`--proof-identity` canonicalizes and hashes a successfully verified proof. It
is a correctness-only diagnostic and was deliberately excluded from all
timing runs, so encoding and hashing costs do not contaminate the performance
comparison.

## Flat task-profile checkpoint — non-promotional

The later commit sequence below adds graph-local observability without changing
the proof request or proof protocol:

- `dc8617f3` defines the independently versioned flat task-profile schema and
  exact-capacity recorder reservation;
- `0d5c4a26` renders its raw integer authority in the RISC-V benchmark console;
- `5f4dc56c` distinguishes exact outer-task activity from physical-worker
  activity that cannot be observed inside pool-exclusive child waves;
- `e73c5e8b` captures bounded task graphs into canonical post-join events with
  checked accounting and cancellation causality; and
- `a1fc6786` publishes generic and RISC-V CPU composition through the existing
  opt-in proof recorder.

This is a flat-task-profile development checkpoint, not a new timing baseline
and not an M7 or R-006 receipt.

### Exact proof identity and observed graph

For `multi_shard_addi` under the development profile, the verified canonical
proof identity remained byte-for-byte identical at every exercised worker
count:

| Workers | Canonical bytes | SHA-256 |
| ---: | ---: | --- |
| 1 | 161274 | `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293` |
| 2 | 161274 | `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293` |
| 4 | 161274 | `f367ca04d554a9d00d32c9279795b8e26032f4211a453074daa91211a9084293` |

The real profiled four-worker proof verified and published one graph with the
following raw structure. `null` is an intentional statement that physical
worker activity inside pool-exclusive child waves is not observable; it must
not be read as zero activity.

| Graph field | Exact value |
| --- | ---: |
| Events | 15 |
| Component aggregates | 12 |
| Requested / admitted / pool-capacity workers | 4 / 4 / 4 |
| Peak active outer tasks | 4 |
| Peak active physical workers | `null` |
| Physical-worker busy nanoseconds | `null` |
| Planned / submitted / completed tasks | 15 / 15 / 15 |
| Failed / submitted-cancelled / unsubmitted-cancelled tasks | 0 / 0 / 0 |
| Started / finished tasks | 15 / 15 |
| Duplicate starts / duplicate finishes | 0 / 0 |
| Scheduler / steal count | `central_queue_no_steal` / 0 |
| Completed rows | 5964368 |
| Completed tiles | 33 |

The 15 events are in canonical `TaskKey` order. The 12 component records are
aggregates, not a second event count: in particular, the fused lane remains one
component aggregate while its constituent task events remain independently
visible.

The full RISC-V CPU product test body reached 1,205 passed out of 1,212
collected tests, with seven expected Sail skips. The enclosing product gate's
sole remaining failure was the already-recorded stale canonical production-AIR
source binding. This checkpoint did not regenerate or accept that binding.

### Five-pair predecessor/candidate diagnostic

This diagnostic used five A/B pairs. In the table, A is predecessor
`5f4dc56c`, B is candidate `a1fc6786`, all times are milliseconds, and the
relative delta is `(B - A) / A`. These are descriptive central results from the
five-pair check, not confidence intervals.

| Workers | Metric | A: predecessor | B: candidate | B - A | Relative delta |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Prove | 1932.9 | 1932.3 | -0.6 | -0.03% |
| 1 | Total | 2304.7 | 2306.0 | +1.3 | +0.06% |
| 4 | Prove | 896.6 | 899.7 | +3.1 | +0.35% |
| 4 | Total | 1058.7 | 1061.4 | +2.7 | +0.26% |

The candidate is effectively flat in this small diagnostic: its one-worker
prove time is 0.03% lower, while the other reported deltas range from +0.06%
to +0.35%. This does not establish either a regression or an improvement.

### Five-pair disabled/profiled diagnostic

This second five-pair A/B check used candidate `a1fc6786` on both sides. A had
flat task profiling disabled and B had it enabled; times and deltas use the
same conventions as the predecessor/candidate table.

| Workers | Metric | A: disabled | B: profiled | B - A | Relative delta |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Prove | 1940.8 | 1942.7 | +1.9 | +0.10% |
| 1 | Total | 2317.8 | 2319.7 | +1.9 | +0.08% |
| 4 | Prove | 903.3 | 914.5 | +11.2 | +1.24% |
| 4 | Total | 1065.8 | 1086.0 | +20.2 | +1.90% |

The observed profiled-minus-disabled deltas are +0.10% prove and +0.08% total
at one worker, and +1.24% prove and +1.90% total at four workers. They are a
diagnostic estimate of the current opt-in path only; the capture is too small
and incomplete to serve as an overhead bound.

### Limits of this checkpoint

- This was not a frozen-protocol capture, authenticated raw attempt bundle, or
  validator-recomputed receipt. It cannot promote M7, R-001, R-005, or R-006.
- It used the reduced-security development profile, not the required
  full-security corpus and parameter matrix.
- Five pairs provide no confidence interval, A/A noise study, or controlled
  distributional result. No instruction count or RSS comparison was captured
  for these two diagnostics.
- Task timestamps and `graph_elapsed_ns` are graph-local. They are not proof
  duration, end-to-end request duration, or a cross-graph critical path.
- Recorder-owned profile memory is allocated outside composition admission and
  is excluded from the graph's resource-byte authority. This checkpoint did
  not separately measure that memory.
- Pool-exclusive tasks can execute nested child waves. Consequently,
  `peak_active_workers` and `worker_busy_ns` are nullable and were `null` in the
  real four-worker graph even though outer-task concurrency was measured
  exactly.
- The fused lane is represented by a component aggregate; aggregate count must
  not be substituted for event count or physical-worker count.
- Secure-recurrence kernels, device execution, and legacy backend hooks remain
  outside this flat composition profile. Their absence is unprofiled scope,
  not zero work.

## Later request-binding and Tree-1 planning checkpoint

Commits `4f8dbfb3`, `3b7606bb`, and `f0504be0` harden the measurement boundary
and prepare the next parallel epoch without revising the timing results above.
Main-trace profile scopes now close after helper join on every tested exit.
Each opt-in verified benchmark sample then binds its sample index and owned
flat task profile to checked monotonic raw integers for guest execution,
proving including witness, and native verification. The three integers sum
exactly; proof serialization and all later snapshot, telemetry, artifact, and
report work are excluded.

This is a distinct `riscv_profiled_proof_v1` development schema, not an
extension of the unprofiled `riscv_proof_v2` contract. Its timing authority
sets `protocol_partition_complete=false`: witness and proving are not yet
separated, so these samples cannot satisfy R-005 or become R-006 evidence. The
accepted exact implementation contract will time five non-overlapping witness
materialization regions and derive proving as the checked complement of the
proof boundary. In particular, it will not sum the nested opcode and
infrastructure diagnostic scopes, whose wall-clock intervals overlap.

The pure Tree-1 plan at `3b7606bb` independently fixes column ownership,
65,536-row opcode and 4,096-row Poseidon partitions, stable task keys,
deterministic worker admission, finite named host-resource classes, private
lookup-counter chunk reduction, and 1,024-task wave limits. It is pointer-free,
allocation-free, capped at 4,096 bytes, and has no execution or commitment
authority. Backend commitment scratch, allocator metadata, and executor/profile
storage remain outside its first resource envelope and must be named before a
whole-proof memory claim.

Focused planner tests pass 9/9 and adapter tests pass 30/30 in Debug,
ReleaseSafe, and ReleaseFast. These are structural/correctness gates only; no
new performance sample, proof identity, or promotional receipt was captured.

## Promotion boundary

This checkpoint does **not** close M7, R-001, the formal performance-promotion
gate, or the full-security benchmark obligation. A promotable result still
requires the complete frozen corpus and security profiles, authenticated raw
attempt bundle, required host/backend lanes, exact and statistical gates, and
a validator-recomputed receipt under
[`m5-m9-protocol-v1.json`](m5-m9-protocol-v1.json).
