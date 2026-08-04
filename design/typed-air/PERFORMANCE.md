# Performance engineering contract

**Status:** measurement and optimization policy
**Last updated:** 2026-08-04

## Goal

Optimize verified end-to-end proving while preserving protocol meaning and
making every shifted cost visible.

The project distinguishes:

- engineering efficiency;
- main-trace size;
- interaction-trace size;
- algebraic degree and blowup;
- witness-generation work;
- commitment/LDE work;
- quotient/composition work;
- FRI/decommitment work;
- critical-path wall time;
- total CPU/GPU resource work;
- peak resident memory;
- proof size; and
- verification time.

No single metric stands in for the rest.

## Derived geometry

For a component with column groups `g`:

```text
main cells        = sum(main_columns_g * 2^log_size_g)
interaction cells = sum(interaction_columns_g * 2^log_size_g)
committed cells   = main cells + interaction cells + preprocessed contribution
```

Reports also include:

- active rows versus padded rows;
- constraints by final degree;
- maximum constraint log-degree bound;
- expression node count and evaluated multiplication count;
- materialized columns and reuse counts;
- relation entries and batches;
- committed bytes and device-resident bytes.

## Performance hypotheses

### SSoT migration

Expected benefit: reduced development/review time and fewer correlated
transcription defects. Runtime should be neutral in compatibility mode.

### Automatic materialization

Possible benefit: lower degree and fewer repeated multiplications.

Possible cost: more committed columns, LDEs, memory traffic, and interaction
inputs. It is accepted only on measured total cost under a versioned layout.

### Specialized precompiles

Expected benefit: replace many generic RISC-V rows with a smaller,
operation-specific table and batch all calls.

Possible cost: guest ABI rows, call buffering, another component commitment,
relation columns, padding, and aggregation.

### Parallel components

Expected benefit: reduce critical path toward the maximum component time rather
than the sum.

Possible cost: higher peak memory, contention, synchronization, and total
resource consumption.

### Recursion

Expected benefit: bounded leaf memory, distributed proving, compact final proof.

Possible cost: leaf proof generation, verifier AIR, hash-heavy aggregation, and
additional latency levels. Small workloads may never cross over.

## Benchmark corpus

Retain the existing structural workloads:

- `branch_fib` — control flow and multi-family composition;
- `memcpy_loop` — memory and commitment components;
- `multi_shard_addi` — shard/state structure;
- `sha2_input_128B` — cryptographic instruction workload.

Add project-specific diagnostics:

- pure Poseidon component at several call counts;
- guest Poseidon software implementation;
- guest Poseidon precompile at identical inputs;
- mixed core plus Poseidon workload;
- zero-call precompile overhead;
- dominant-precompile and balanced-component cases;
- one-, two-, four-, and maximum-worker scheduling;
- CPU/SIMD and authenticated Metal where supported.

The canonical CSP benchmark remains the publication-grade external workload.

## Measurement procedure

1. Start from a clean tree and record commit, branch, compiler, host, power, and
   backend identity.
2. Build baseline and candidate with identical optimization and protocol.
3. Verify every measured proof.
4. Warm up according to the benchmark's declared protocol.
5. Run enough samples to distinguish noise; retain raw samples.
6. Report median, spread, and outliers rather than only the best sample.
7. Record stage timings, peak memory, worker utilization, and geometry.
8. Compare on the same host and power state.
9. Treat build, crash, proof, or verification failures as failures, never zero
   or omitted timings.
10. Store reports separately by backend so results cannot overwrite.

Compatibility changes pass when differences are inside the benchmark's
measured noise interval and no structural cost unexpectedly changes. A fixed
percentage budget should be set only after the baseline distribution is
recorded.

## Compiler cost report

Every layout proposal reports a vector rather than one magic score:

```text
main columns and cells
interaction columns and cells
maximum degree
constraints by degree
expression additions/multiplications
materializations and reuse
estimated commitment/LDE bytes
estimated CPU evaluation operations
estimated Metal reads/writes and occupancy pressure
```

A weighted score may rank experiments, but the weights are backend/version
specific and never part of soundness. The accepted manifest records the policy,
not the transient machine profile that suggested it.

## Parallel critical path

For components `i`, disclose:

```text
serial work estimate = sum(component_time_i)
ideal parallel floor = max(component_time_i)
observed wall time   = scheduling + contention + critical path
parallel efficiency = useful component work / available worker time
```

Also report total CPU time or GPU command time. A wall-clock win from additional
hardware is still valuable, but is not called a reduction in proving work.

## Memory discipline

- Preplan final column storage.
- Generate directly into committed/resident buffers when possible.
- Avoid a full temporary copy of wide components.
- Bound concurrent component allocation by admission policy.
- Reuse scratch only when lifetimes cannot overlap.
- Report high-water resident and host allocation.
- Include padding cost in admission decisions.
- Cancel and clean up all sibling tasks after the first fatal error.

## Promotion requirements

An optimization becomes production only when:

1. correctness and formal gates are green;
2. the layout/protocol decision is explicit;
3. verified representative workloads improve the stated metric;
4. no hidden regression appears in total cells, memory, proof size, verifier
   time, or another supported backend without explicit acceptance;
5. the implementation has a simple rollback path; and
6. evidence is stored under the repository's current performance-authority
   protocol.

Source-code elegance is necessary for maintenance but insufficient for
performance promotion.
