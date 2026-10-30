# Ethereum optimization benchmark delivery

The daily profiler uses complete canonical RISC-V execution proofs and records
preparation, proving, public serialization and independent verification. It
compiles once and reuses the exact source-bound binary. Reference proofs and
hostile replays are outside benchmark mode. The source, binary, toolchain,
statement/output and proof identities are evidence, not inferred from Git HEAD.

The entrypoint is `python3 scripts/benchmark_riscv_ethereum.py`; the full runbook
is [ethereum-daily-profiling.md](ethereum-daily-profiling.md). Retained CSVs,
JSONs, logs and source manifests are under
[`ethereum-daily-profiling-20261029`](../../../vectors/reports/ethereum-daily-profiling-20261029/).

## Bounded complete-execution basket

| Workload | Actual native cycles | Keccak | Recovery | Request median | Core proving median |
|---|---:|---:|---:|---:|---:|
| Keccak-heavy 8 | 38 | 8 | 0 | 2.355 s | 1.967 s |
| Memory-heavy 4096 | 32,782 | 0 | 0 | 2.145 s | 1.833 s |
| Mixed Ethereum 8 | 32,815 | 8 | 1 | 5.464 s | 4.678 s |

These are three uncontaminated samples each, CPU ReleaseSafe, q70/PoW26, four
execution windows, original complete-STARK output contract. The mixed program
performs 512 native RAM/ALU rounds per Keccak call, including first-touch writes
and dependent loads. This approximates the retained instruction/Keccak ratio;
its recovery frequency remains deliberately higher in the small case. It is a
synthetic stress basket, not a model of arbitrary Ethereum transactions.

The exact original and replacement sample selection, with known capture overlap
excluded, is retained in `analysis/selection.json`. No contaminated samples
were deleted. Process command time includes startup/teardown; request time ends
after bounded proof decoding and verification. Checkpoint I/O is zero for this
in-memory route. Recursive reduction is explicitly unmeasured/null.

The 421-Keccak/one-recovery larger case matches the retained call ratio and
reaches roughly 1.7 million native instructions. Its initial attempt rejected
the legacy fixture's 65,536-event limit. An explicit benchmark policy now admits
at most 1,048,576 events and sizes power-of-two cohorts toward eight instances;
the 8 GiB memory-stage, 8 GiB retained-PCS and 24 GiB request budgets remain.
The subsequent proof exposed a native RAM clock-ghost closure issue. The v7
layout now explicitly omits the obsolete auxiliary RAM-clock projection while
retaining actual RAM accesses, register-clock projections and strict global
closure. Both earlier failures remain in the dataset. The final complete proof
passed bounded decoding and independent verification after producer destruction:

| Larger complete case | Preparation | Proving | Verification | Request | Tracked peak | RSS peak |
|---|---:|---:|---:|---:|---:|---:|
| Mixed421: 1,726,115 instructions, 421 Keccak, one recovery, four windows | 7.437 s | 105.112 s | 0.804 s | 113.412 s | 9.048 GB | 8.719 GB |

This is one idle-host observation, not a latency distribution. DEEP/FRI costs
42.974 s, composition 37.522 s and native interaction preparation 17.054 s:
about 86% of request time. It is the primary larger profiling target because
these costs dominate startup and PoW. Evidence is retained in
`ratio-matched-421-actual-ram/` under the daily profiling dataset.

## Actual retained Ethereum windows

The source ELF and augmented input were recovered and hash-matched exactly to
the original mainnet 24,628,607 execution. Three saved windows execute 32,768 real
instructions each. Both complete incoming and outgoing machine states are
explicit benchmark inputs with externally selected identities. The skipped
prefix is not authenticated by these proofs.

| Window | Keccak | Recovery | Proving | Prepared input to verified | Tracked peak |
|---|---:|---:|---:|---:|---:|
| Native, offset 1 | 0 | 0 | 28.571 s | 46.104 s | 9.577 GB |
| Recovery region | 32 | 6 | 20.272 s | 33.111 s | 3.825 GB |
| Keccak region | 228 | 0 | 32.539 s | 55.025 s | 10.009 GB |

These use the existing canonical partial-leaf architecture, not the new terminal
v7 union. They are shared-host diagnostic observations, not controlled medians.
Each saved proof passed an independent fresh-process reload after the original
runner, witness and producer key were destroyed. Instrumented repeats preserved
exact proof bytes. Full loading, prefix capture, witness/provider/commitment,
composition, OODS/DEEP/FRI, serialization and verification observations remain
in the raw records; preparation is not silently removed from end-to-end time.

See [`block-v7-real-window-corpus-20261029`](../../../vectors/reports/block-v7-real-window-corpus-20261029/)
and `scripts/v7_real_window_corpus.py`. This is a reference for actual work, not
a claim that whole-block or skipped-prefix verification is qualified.

## Evidence-driven priorities

1. In the small complete basket, DEEP/FRI quotient construction leads the
   crypto-heavy workloads (about 1.295 s for Keccak and 2.128 s for mixed).
   Share arithmetic inventories across windows before optimizing kernel details.
2. Memory-heavy composition evaluation costs about 0.808 s; native interaction
   preparation about 0.387 s. Native direct-field evaluation and byte/word
   witness architecture should be profiled at the larger case as well.
3. Real native/Keccak windows spend 9.825/12.855 s in composition and
   4.824/7.422 s in memory-hash witness construction. Their older whole-memory
   commitment architecture is an explicit target for replacement by the new
   current-event WORD argument and independently admitted boundary state.
4. The real recovery window spends about 11.102 s in lazy DEEP/FRI. Its cost
   cannot be predicted from instruction count or from Keccak call counts alone.
5. Canonical PoW is a separately visible stage. Changing security parameters is
   not an optimization result under this benchmark contract.

The shared-Keccak source protocol and combined original-STARK union have exact
physical-claim parity against eight independently produced originals. Their
fully recommitted ownership attack passes the arithmetic proof but fails
independent global RAM closure. Bounded public-proof framing is qualified.
Matched daily measurements must still use the same generated ELF, cuts,
statement, security and complete output contract on both layouts.

The completed same-binary matched comparison satisfies those conditions.
At eight Keccak calls, three samples per architecture in ABBAAB order give
2.568 s baseline versus 1.340 s shared request medians (1.92x). DEEP/FRI falls
from 1.285 s to 0.042 s, while composition increases from 0.141 s to 0.263 s.
At 32 calls, one paired observation gives 4.095 s versus 2.281 s. PoW remains
included and separately reported; its nonce-dependent difference must not be
attributed to the layout. See `keccak-matched-actual-ram/`. The shared route is
currently Keccak-only; the mixed recovery case uses the per-window caller route.

## Recommended profiling loop

Use the default three-case basket for quick iteration, Mixed421 for substantial
native/crypto work, and the real-window corpus to check whether an architectural
change addresses costs present in actual Ethereum execution. A small Keccak-only
pair isolates shared-call inventory changes; it is not a substitute for Mixed421.

```sh
python3 scripts/benchmark_riscv_ethereum.py --build-only --out zig-out/ethereum-profile-build
python3 scripts/benchmark_riscv_ethereum.py --binary zig-out/ethereum-profile-build/prover \
  --basket default --repeats 3 --out zig-out/ethereum-profile-small
python3 scripts/benchmark_riscv_ethereum.py --binary zig-out/ethereum-profile-build/prover \
  --case mixed_ethereum:421 --repeats 3 --timeout 600 --out zig-out/ethereum-profile-mixed421
```

These are compile-once commands; use fresh output directories for another
campaign. Reports separate source execution, preparation, proving,
serialization, verification, command wall time and memory. Stage CSVs retain
inclusive and exclusive time. Recursive reduction remains explicitly null:
none of these measurements qualifies a complete Ethereum-block-to-recursive-root
benchmark. Real windows declare incoming state and do not prove their skipped
prefix. Their older partial-leaf timings must not be pooled with v7 synthetic
complete proofs as a same-contract speedup.

No greater-than-tenfold whole-block speedup has been measured. This benchmark
setup supplies the necessary real and synthetic profiles to evaluate the large
architectural changes without attributing kernel, security or output-contract
changes to a block-level speedup.
