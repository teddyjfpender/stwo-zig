# Session 02 - Cairo Metal quotient/FRI inversion

## Resumed objective

Resume the paused Cairo system-throughput round at the largest measured
backend-specific inversion:

- arithmetic-2m CPU `fri_quotient_build_and_commit`: 262.340 ms;
- arithmetic-2m Metal `fri_quotient_build_and_commit`: 1,350.223 ms;
- Metal/CPU stage ratio: 5.15;
- complete Metal proof: 5.351 s, 74 logical dispatches, zero fallbacks; and
- exact CPU/Metal canonical proof bytes.

The acceptance boundary remains system-wide. A candidate must be selected from
structural trace/storage properties, preserve exact proof bytes and zero
fallbacks, improve the arithmetic sentinel materially, and then survive the
fixed seven-workload Cairo judgement. No workload name, benchmark size, input
digest, or statement-specific dispatch is admissible.

## Correctness reconciliation

The research branch was merged with `feature/cairo-frontend-completion` at
`a0404916`, bringing in the global LogUp soundness fix before further
performance work. Performance evidence must therefore be generated from the
sound verifier/prover surface rather than retained against the superseded
claim boundary.

## First architectural finding

The resident quotient transaction has two raw-input schedules:

1. flat-pack all raw columns once, then run one fused quotient kernel; or
2. bind each physically contiguous/resident source run and launch one
   full-domain numerator kernel per run, followed by one finalize kernel.

The source explicitly caps the segmented schedule at 64 source runs because
each run read-modify-writes every quotient accumulator over the complete
domain. The actual predicate, however, admits every input at or above 64 MiB
to the segmented schedule regardless of source-run count:

```text
raw_bytes >= 64 MiB
    OR (resident candidate AND source_runs <= 64)
```

The earlier fragmented-quotient repair intentionally retained this historical
large-input rule because its measured native workloads were below that
boundary. Cairo supplies a much larger and more fragmented raw-column set, so
it is a direct test of the unbounded branch rather than a contradiction of the
earlier result.

## Current hypothesis

Arithmetic-2m exceeds 64 MiB and contains enough independent Cairo component
allocations to select segmented evaluation with substantially more than 64
physical source runs. That would multiply full-domain numerator traffic and
explain why quotient/FRI is slow while main, interaction, composition, and
Merkle commitments accelerate normally.

The next measurement records raw bytes, column/view counts, source-run count,
selected schedule, quotient GPU time, and wall time. The hypothesis is
falsified if arithmetic-2m has at most 64 runs, selects the flat path, or the
quotient kernels do not dominate the 1.350 second interval.

## Candidate order

1. Enforce the existing source-run ceiling for all raw byte sizes and screen
   the arithmetic sentinel. This is the smallest correction to the documented
   cost model.
2. If CPU flat packing becomes material, replace it with one GPU gather/blit
   transaction into a contiguous arena followed by one quotient dispatch.
3. Only after quotient scheduling is bounded, profile Merkle and FRI folding
   inside the resident transaction.

Every rejected candidate and its proof/timing evidence remains recorded here.

## Measurement 1: source topology

An authenticated-AOT arithmetic-2m proof on the merged branch measured:

```text
raw bytes       1,821,233,152
active columns  646
quotient views  878
source runs     361
batches         14
domain rows     4,194,304
selected path   segmented
quotient GPU    1,291.391 ms
quotient wall   1,300.041 ms
FRI stage       1,341.806 ms
complete prove  5,433.507 ms
```

The proof is the canonical 1,853,428-byte
`25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`
artifact, with 74 logical Metal dispatches and zero fallbacks. This confirms
the hypothesis: the unbounded large-input branch performs 361 full-domain
numerator passes, and those passes account for essentially the complete stage
inversion.

## Candidate 1: enforce the run ceiling

The first candidate applies the existing 64-run ceiling to every segmented
candidate, including inputs at or above 64 MiB. Arithmetic-2m therefore packs
its raw columns once and evaluates one fused raw quotient kernel:

```text
selected path   flat
quotient GPU    127.042 ms
quotient wall   250.854 ms
FRI stage       286.238 ms
complete prove  4,371.186 ms
```

The FRI stage is 4.70x faster and the complete proof is 1.24x faster than the
adjacent instrumented baseline. Proof bytes are byte-for-byte identical and
Metal remains at zero fallbacks. The remaining 124 ms host/GPU gap is mainly
the serial 1.821 GB CPU pack, so the next candidate moves that exact gather
into the resident command rather than accepting the avoidable host pass.

## Candidate 2: GPU flat gather

For large inputs above the existing 64 MiB structural threshold, high source
fragmentation now selects one private GPU flat arena. The proof command blits
each raw column from its existing resident or page-aliased source into that
arena, then launches the unchanged fused raw quotient kernel. The input owners
remain live until the synchronous resident quotient/FRI transaction completes.
Small fragmented workloads retain the proven CPU pack, and inputs at 64 source
runs or fewer retain segmented zero-copy evaluation.

Arithmetic-2m measured:

```text
quotient GPU    127.070 ms
quotient wall   173.412 ms
FRI stage       212.095 ms
complete prove  4,107.014 ms
```

That is a 6.34x FRI-stage improvement and a 1.30x complete-proof improvement
against the resumed 5.351-second profile. The GPU gather removes a further
74 ms from the FRI stage versus serial CPU packing. The canonical proof remains
byte-identical and independently verifies with zero fallbacks.

## Six-row A-B-B-A screen

The exact merged predecessor and candidate were built as separate ReleaseFast
products against the same authenticated AOT bundle. Each workload ran in cold
process order A-B-B-A. No sample was discarded.

| Workload | Predecessor mean ms | Candidate mean ms | Ratio | Speedup | Peak ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| all-opcodes | 7,355.605 | 3,130.339 | 0.425572 | 2.350x | 1.1339 |
| Poseidon aggregator | 5,758.749 | 2,688.987 | 0.466940 | 2.141x | 0.9504 |
| Pedersen aggregator | 7,627.300 | 5,622.601 | 0.737168 | 1.356x | 0.9573 |
| Fibonacci 100k | 3,533.128 | 2,785.952 | 0.788523 | 1.268x | 1.1674 |
| Factorial 100k | 5,621.864 | 5,297.604 | 0.942322 | 1.061x | 1.1817 |
| Arithmetic 2m | 5,600.671 | 4,340.107 | 0.774926 | 1.290x | 1.1500 |

The six-row geometric-mean prove ratio is `0.662235`, a `1.510x` throughput
improvement. Cold wall ratio is `0.666520`; peak-footprint ratio is `1.085561`.
All 24 proofs verified, all four proof hashes per row were identical, and
every run reported zero Metal CPU fallbacks.

The peak increase is the explicit cost of replacing a repeated numerator arena
with a packed source arena. It is largest where raw source bytes exceed the
old batch-by-domain accumulator. The result remains below this host's resource
ceiling, but the tradeoff must be retained in the final judgement rather than
reported as a latency-only win.

The old memory-7m corpus cannot supply the seventh row after the global LogUp
soundness fix: its synthetic public output pointers encode `stop < start`, and
the sound statement path correctly returns `InvalidOutputSegment` before
proving. The verifier will not be weakened to preserve an invalid benchmark.
A semantically equivalent valid memory-heavy input must replace that artifact
before this round can claim a complete seven-workload judgement.

## Seven-row judgement

The intended memory workload was recovered from the
`stwo_memory_200x300.json` execution already used by the original benchmark
driver. Its prover input has SHA-256
`18b4187b182bc415651a5552bddcdf9834b698e66cdeaeea3d5e76ba609f3fcc`,
retains the 7.37M-step memory-heavy geometry, and produces the historical
canonical proof hash
`e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`.

Its A-B-B-A result was:

| Workload | Predecessor mean ms | Candidate mean ms | Ratio | Speedup | Peak ratio |
| --- | ---: | ---: | ---: | ---: | ---: |
| Memory 7m | 13,774.909 | 10,841.578 | 0.787053 | 1.271x | 1.1976 |

The complete fixed-geometry result is therefore:

| Metric | Result |
| --- | ---: |
| seven-row geometric-mean prove ratio | `0.678774` |
| seven-row geometric-mean throughput gain | `1.473x` |
| seven-row geometric-mean cold-wall ratio | `0.683646` |
| seven-row geometric-mean peak-footprint ratio | `1.100906` |
| verified proofs | `28 / 28` |
| cross-arm exact rows | `7 / 7` |
| Metal CPU fallbacks | `0` |

The memory row's candidate peak is 16.433 GiB versus 13.722 GiB for the
predecessor. This is the largest observed resource increase and remains well
inside the 64 GiB host envelope. It comes from the structurally explicit flat
source arena, not a leak: every proof is a fresh process, the runtime reports
one initialization and one shutdown, and the process exits cleanly after
verification. The accepted claim is latency plus its measured memory cost; it
is not a memory-neutral promotion.

## Final validation

The implementation passed:

```text
zig build metal-check test-cairo-metal-product \
  -Doptimize=ReleaseFast \
  -Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle \
  -j2

zig build test-native-metal test-cairo-metal-oracle \
  -Doptimize=ReleaseFast \
  -Dmetal-core-aot-bundle=/private/tmp/cairo-quotient-baseline-v2/aot-bundle \
  -j2

git diff --check
```

The second command exercised the pinned Rust verifier/oracle, executable and
legacy Cairo program inputs, native Metal lifecycle and boundary tests, and
the complete 376-source Cairo Metal product closure. All commands passed.
