# Daily RISC-V execution profiling

Run `scripts/benchmark_riscv_ethereum.py` from any directory. It compiles the
focused production-backed workload entrypoint once, then invokes that binary
directly for each case and repeat. Benchmark mode disables the original-proof
oracle and hostile test replays. Every accepted report must describe canonical
q70/PoW26 proving and independent verification after producer destruction.

These deterministic programs exercise the Ethereum RISC-V profile. They are
**synthetic workloads, not Ethereum block proofs**. The mixed case includes a
recovery call plus Keccak and RAM work. Recursion is not run; its timing stays
null. Checkpoint I/O is explicitly reported and is currently zero.

## Daily commands

```sh
# Three workload types, one repeat, small correctness/profile check.
python3 scripts/benchmark_riscv_ethereum.py --basket quick --repeats 1

# Daily repeated basket: Keccak8, memory4096, mixed8; three repeats each.
python3 scripts/benchmark_riscv_ethereum.py --basket default --repeats 3

# Nine sizes/mixes; inspect smaller cases before spending time on this basket.
python3 scripts/benchmark_riscv_ethereum.py --basket scaling --repeats 3

# Build without running proofs. Profiling symbols are retained by default.
python3 scripts/benchmark_riscv_ethereum.py --build-only --out zig-out/ethereum-build

# Reuse that exact binary; its adjacent .build.json supplies source provenance.
python3 scripts/benchmark_riscv_ethereum.py \
  --binary zig-out/ethereum-build/prover --case memory_heavy:4096 --repeats 3
```

`--dry-run` prints the exact build, case and environment plan without executing
it. `--case WORKLOAD:ITERATIONS` overrides the basket and can be repeated.
`--windows` defaults to four; the harness derives a cycle cut from the actual
workload. `--cut` selects an explicit cut instead. The fixture has a bounded
maximum of sixteen windows. `--timeout` bounds each run, while `--build-timeout`
bounds the separate build command. `--fail-fast` stops after recording the first
failed case; otherwise later cases continue and the campaign still exits nonzero.

`--workers N` selects the total CPU worker count, including the coordinator,
within the prover's bound of 1 through 32. Four remains the default. New reports
attest this count; a historical binary without the field can only attest the
old fixed four-worker mode. Stage rankings keep worker counts separate. Compare
1, 4, 8 and 12 workers using the same binary and inputs to expose the parallel
work and its memory-bandwidth limits rather than assuming linear scaling.
`--deep-census` logs admitted groups, direct contributions and grouping memory
under the explicit DEEP cap. Use that diagnostic separately from timing samples.

## Evidence and timing boundaries

The default output directory is a new `zig-out/benchmarks/<UTC-id>` directory.
Existing nonempty directories are rejected so evidence cannot be overwritten.
Each campaign retains:

- `manifest.json`, `source-manifest.json`, `build.log` and the build sidecar:
  exact source-file hashes, Git HEAD/dirty state, binary hash, command, toolchain
  and machine information, including compiler executable and runner hashes. A source mutation during compilation rejects the
  ambiguous build. External binaries lacking a sidecar are explicitly marked
  `external_unattested`; the current checkout is not claimed as their source.
- `runs.csv`: every attempted run, including failures, complete reported scalar
  metadata, process command time, proof/preparation/verification times, memory,
  proof and ELF hashes, and source/binary identity.
- `stages.csv`: one row per recorded stage, with a unique path, parent, depth,
  leaf marker, inclusive duration and exclusive self-time. Repeated native or
  caller stages remain separate rows. `stage-leaves.csv` is the leaf-only view;
  internal-node self-time remains available in `stages.csv`.
- `stage-rankings.csv`: repeated-run median/mean/p95 exclusive stage costs,
  ranked both across cases for each stage and within each case. This is measured
  diagnostic prioritization, not promotion or a leaderboard score.
- One directory per run containing the raw log, untouched report JSON and the
  command/environment/status receipt. Missing reports, schema failures, timeouts
  and nonzero exits are recorded; none become successful timing samples.

Compilation wall time is recorded separately and includes waiting for the
shared build lock. It is never added to proof timing. Process command time
includes all process startup and teardown; reported request time is the
harness's input-to-independently-verified-proof boundary. Their difference is
visible rather than hidden. RSS is the process lifetime peak; tracked allocator
peaks and cumulative producer high-water marks are separate fields.

Inclusive parent durations contain their children. Use a parent **or** sum
its exclusive descendants, never both. The CLI rejects substantive child-time
overlap and tolerates only bounded microsecond rounding. It also validates
workload/cut, security, verification, source kind, proof hashes and required
production stages. Root-only or incomplete profiles cannot silently pass.

The independent campaign lock serializes this CLI's builds and runs across
worktrees. Compilation additionally uses the existing Zig build lock; optional
`--build-lock` chooses the coordinated integration lane. These locks do not
stop arbitrary external programs. Keep unrelated compiles and proofs idle for
performance comparisons, and use repeated measurements rather than one noisy
sample. Inherited `STWO_*` diagnostic flags are cleared before each invocation;
the retained run receipt lists the exact benchmark flags applied.

## Validation

```sh
python3 -m unittest discover -s scripts/tests -p test_benchmark_riscv_ethereum.py -v
```

The tests cover canonical report admission, omitted verification/security data,
nonfinite/negative timing, parent-child containment, repeated stage IDs,
exclusive-time aggregation, inherited-flag isolation, and a failed run followed
by a successful run with durable CSV/status evidence. They do not invoke a
prover. Real workload qualification and repeat measurements remain necessary.

Use `--shared-keccak --case keccak_heavy:8` to select the distinct shared-Keccak complete original proof. This option sets an explicit environment switch, rejects other workload kinds, requires the shared architecture/proof contract in the report, and validates the corresponding `keccak_union_prove`/`keccak_union_core_proof` stage boundary. Use the same source-bound binary, workload, cut, security and memory policy for the baseline comparison; compare statement/output hashes, cycles, RAM events and program fetches before comparing costs. Changed protocol identities do not imply byte-identical proofs across architectures.

## Reproduce the completed comparison

Build once from the current source, then keep that binary fixed for both modes:

```sh
python3 scripts/benchmark_riscv_ethereum.py --build-only --out zig-out/ethereum-comparison-build
python3 scripts/benchmark_riscv_ethereum.py --binary zig-out/ethereum-comparison-build/prover \
  --case keccak_heavy:8 --repeats 3 --out zig-out/ethereum-baseline8
python3 scripts/benchmark_riscv_ethereum.py --binary zig-out/ethereum-comparison-build/prover \
  --shared-keccak --case keccak_heavy:8 --repeats 3 --out zig-out/ethereum-shared8
python3 scripts/benchmark_riscv_ethereum.py --binary zig-out/ethereum-comparison-build/prover \
  --case mixed_ethereum:421 --repeats 1 --timeout 600 --out zig-out/ethereum-mixed421
```

The saved matched campaign used single-repeat ABBAAB invocation order rather than two grouped runs; repeat that order when controlling drift matters. Use new output directories on reruns. Compare `statement_sha256`, `output_sha256`, ELF, cycles, window cut, RAM events, program fetches, query/PoW settings and memory policy before interpreting a speedup. Report PoW separately as a secondary attribution view; primary request time includes it.

Benchmark-only memory admission is explicitly1,048,576 events, with a power-of-two RAM cohort size of at least4096 chosen to keep at most eight cohorts. The memory-stage8GiB, request24GiB and retained-PCS8GiB budgets are unchanged. Resource rejection remains a recorded failure; the runner does not raise limits. Existing production/qualification defaults are not silently replaced by this benchmark policy.

The completed evidence and requirement matrix are in `vectors/reports/ethereum-daily-profiling-20261029/dataset-index/`. The full canonical mixed421 proof qualifies honest high-clock completeness under the new actual-event RAM layout. The earlier event-cap and auxiliary-clock failures remain recorded. Actual Ethereum-derived partial-window reproduction is documented separately in `v7-real-window-corpus-20261029.md`; those endpoint-admitted proofs have a different contract and their timings must not be pooled with complete synthetic executions.
