# Performance engineering contract

**Status:** measurement and optimization policy
**Last updated:** 2026-08-06

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

An explicitly scoped microbenchmark may measure a pre-proof implementation
boundary for diagnosis, but it must say that no proof was executed and cannot
support production promotion. H-010 is such a boundary: independent expected
outputs, complete direct-root evaluation, and mutation coverage admit its
samples, while any later production decision still requires verified
proof-path evidence under the full procedure above.

## Normative M5--M9 promotion contract

The machine-readable
[`performance/m5-m9-protocol-v1.json`](performance/m5-m9-protocol-v1.json)
is the numerical and procedural authority for M5 through M9 performance
promotion. The [protocol README](performance/README.md) describes its evidence
boundary. A milestone does not close its performance scope on an informal
benchmark, a best sample, or correctness evidence alone.

`python3 scripts/typed_air_performance_protocol.py` validates the frozen
contract and its digest-bound local authorities before a capture begins. Its
mutation suite is
`python3 -m unittest scripts.tests.test_typed_air_performance_protocol`.

Before candidate execution, the capture plan freezes the predecessor commit
and tree, corpus manifest, build and security parameters, authority hosts and
backends, and exactly one primary target. Post-selection is forbidden. M5 and
M8 predeclare non-inferiority targets; the optimization milestones M6, M7, and
M9 predeclare a real improvement. A threshold change after results are visible
requires a new reviewed protocol version and a new capture.

### Evidence classes

Exact gates have no noise allowance. They cover semantic outputs and ordered
multiplicities; component descriptors, padding, cells, degrees, relation
summaries, statements and transcripts; protocol-preserving proof bytes;
allocation-free prepared row loops; and bounded task accounting. Cell totals
are computed as columns times their individual domains, never inferred from
column counts alone.

Statistical gates cover verified request, proving and verification time,
process/GPU work, material stages, and peak RSS. A stage is material only when
its baseline median is at least 10 ms and at least five percent of verified
request time. Smaller stages and uncalibrated hardware counters are retained
as observations but cannot decide promotion.

### Sampling and decisions

Every attempt is a fresh serial child and every timed proof is natively and
independently verified. Each arm receives ten excluded verified warmups and
three paired alternating AB/BA rounds of ten measured proofs per arm. There is
a one-second cooldown, no early stopping, no retries, no outlier deletion, and
no omitted failures. Raw attempts remain in launch order.

Round-median ratios use the digest-pinned epoch-3 Hodges--Lehmann estimator and
deterministic 4,000-iteration 95% percentile bootstrap. Speed is normalized as
baseline duration divided by candidate duration; resources are candidate
divided by baseline. An A/A run of the complete protocol is required for each
host/backend session. Its interval must contain 1.0 and be no wider than 0.06,
or the session has no verdict.

Every required workload and backend passes independently. The universal hard
budgets are:

| Measure | Required result |
| --- | ---: |
| Verified-request speed | lower CI `>= 0.97` |
| Proving speed | lower CI `>= 0.97` |
| Native verification candidate/baseline | upper CI `<= 1.03` |
| Peak RSS candidate/baseline | upper CI `<= 1.05`, maxima ratio `<= 1.10` |
| CPU, supported instruction, and Metal command work | upper CI `<= 1.05` |
| Protocol-preserving proof bytes | exact equality |
| Protocol-changing proof size | candidate/baseline `<= 1.10` |

The protocol names narrow M7 and M9 resource overrides where parallelism or
aggregation deliberately exchanges bounded total work for critical-path time.
No aggregate or geometric mean can hide a failing workload.

### Milestone benefit gates

| Milestone | Required corpus and distinguishing hard gate |
| --- | --- |
| M5 | LUI, ADDI, signed load, JALR, and DIV at logs 10/14/18 plus five full proofs; exact compatibility, zero hot-loop allocation, at-most-linear-plus-10% row scaling, and witness lower CI `>= 0.97`. |
| M6 | Identical software/precompile Poseidon inputs at 0/1/8/64/512/4096 calls in core, balanced, and dominant shapes; crossover by 512, committed-cell ratios `<= 0.85` at 512 and `<= 0.75` at 4096, and dominant 4096-call speed lower CI `>= 1.10` CPU and `>= 1.05` Metal. |
| M7 | One/two/four/max-worker sweeps over shard, memory, balanced-hash, and dominant-hash proofs; exact proof identity and bounded task accounting, at least two qualifying parallel workloads, and largest-worker speed lower CI at least `max(1.05, 70% of Amdahl ideal)` with total-work/RSS scaling caps of 1.15/1.25. |
| M8 | Isolated logs 10/14/18 for all 17 opcode families plus nine full-proof workloads; exact compatibility and M5 allocation/scaling gates for every family, with no portfolio averaging. |
| M9 | Logs 14/16/18, 2/4/8/16/32 leaves and 1/4/8 workers; deterministic two-to-one summaries, eight-leaf/four-worker speed lower CI `>= 1.25`, crossover by eight leaves, root proof-size 32/2 `<= 1.05`, verifier 32/2 `<= 1.10`, and bounded total-work/RSS scaling. |

### Receipts and outcomes

A promotion receipt binds the protocol and capture-plan identities, clean
baseline and candidate sources, executables, corpus inputs, host/power state,
all attempts, raw bundle, geometry, proofs and both verifier results, stage and
task profiles, summaries, gates, artifacts, and open claims by byte count and
SHA-256. The validator recomputes every ratio, interval, and outcome and rejects
unknown or duplicate fields, identity or threshold drift, reordered or
deleted attempts, omitted failures, fallback, and digest mismatches.

Candidate correctness, exact-invariant, or budget failure is `FAIL`.
Unstable A/A calibration, environmental identity drift, unavailable mandatory
counters, or incomplete evidence is `NO_VERDICT`. Neither outcome permits
promotion.

### C-013 CPU capture boundary

The repository-owned C-013 CPU controller is
`scripts/typed_air_c013_capture.py`. Before planning, install the current
ReleaseFast `riscv-poseidon2-proof-child`, `riscv-c013-aa-proof-child`, and
`riscv-c013-corpus-manifest` artifacts; plan admission checks their embedded
protocol versions so a stale `zig-out/bin` executable cannot consume a cohort.
The `plan`, `capture`, and `validate-bundle` commands respectively freeze the
1,520-attempt authority, retain the append-only raw bundle, and independently
recompute the 18 CPU rows plus per-shape crossover.

The retained `cpu-reduction.json` reports uncertainty, exact cells and proof
bytes, fresh-child wall time, CPU/counter work, RSS, and its environment
binding. It is a CPU-lane reduction only. It leaves the M6 outcome null until
the required Metal cohort and complete promotion receipt validate. The exact
runbook and current measurement gap are recorded in the
[C-013 CPU capture readiness note](notes/2026-08-12-c013-cpu-capture-readiness.md).

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

H-009's first reviewed report uses checked integer coordinates and five row
scenarios rather than backend weights. The complete one-pass Poseidon
neighbourhood is a plateau: 126 retained non-seed cuts exactly match the
compatibility seed. Its `canonical_streaming_peak_live_nodes = 39` describes a
theoretical ordered schedule derived from interned-node births and explicit
root-fold events after each lowering phase. The 3,460-node coordinate is the
modeled proposal DAG, not observed production-backend scratch. Production
Poseidon still uses a separate static evaluator, and Poseidon composition has
no candidate Metal capability. H-010 now provides one common retained CPU
evaluator for the compatibility seed and three authenticated H-009
representatives. It must not relabel either H-009 structural coordinate as an
observed saving, and its measurements cannot be pooled with the differently
shaped production static evaluator.

## H-010 isolated layout experiment

H-010 is a pre-promotion CPU microbenchmark, not a prover benchmark. Its
correctness admission comes from checked deterministic vectors, independently
recorded static-reference outputs, all 430 direct roots evaluating to zero on
every admitted row, and the complete materialization/fixed-role mutation
matrix. Candidate trace digests are useful drift alarms but are classified as
regression pins rather than independent correctness evidence.

Every ranked arm uses the same ReleaseFast executable, retained scalar-M31
interpreter, prepared capabilities, and allocation-free row loops. The default
logs are 10 and 14, read from checked `STWAIRB\0` vectors with a regenerated
readable index. Log 18 is deterministically generated only when explicitly
requested and is labelled
`generated_opt_in_uncommitted_non_receiptable`; it cannot enter or replace a
default cohort.

Each arm/sample pair runs in a fresh serial child. For each default log, three
full warmup rounds precede eleven measured rounds, with the starting arm rotated
each round. No sample is discarded or retried. Reports retain every raw value
and integer median, median absolute deviation, minimum, and maximum for:

- `setup_ns` — authenticated arm construction, lowering, allocation, and
  prepared-capability validation;
- `witness_ns` — base/fixed-role writes and the selected 426 materializations;
- `direct_ns` — all 3,460 direct nodes and all 430 ordered root folds; and
- `peak_rss_bytes` — normalized operating-system high-water resident memory,
  alongside its native value and unit.

Vector read and authentication, reference comparisons, completed-trace
digesting, mutation tests, report serialization, process launch, and teardown
are outside the phase timers. Missing RSS, identity drift, output/root failure,
child failure, schema drift, or a missing sample invalidates the whole host/log
cohort. The report path is create-only and timing artifacts remain uncommitted
unless a later reviewed receipt freezes exact bytes.

The boundary excludes the hash-component shell, LogUp and interactions,
commitments/LDEs, quotient construction, PCS/FRI, proof encoding, verification,
parallel component scheduling, and Metal candidate execution. Consequently an
H-010 result says only how these authenticated layouts behave in this common
CPU evaluator. It cannot establish proving speed, proof size, verifier cost,
backend parity, or production authority, and does not satisfy the promotion
requirements below without later full proof-path evidence.

### Completed H-010 result

The experiment closed on clean implementation commit
`82bf6b9cd5eb1ab48edd6fb7c0c88a3be687e8c6`, tree
`8cbb9300fa9b820baa079eeb94addf71db97f130`. Both independently
collected default reports are valid and complete, contain 112 fresh sample
children, and record zero failures, retries, or drops. They were collected at
declared power state `AC/100%/powermode0` from the same executable SHA-256
`65cc075bea26b731ce50093cc1fffa06ef7fd2ddb9979370b40f2e9398ab96bf`
and the same 301-source closure SHA-256
`b23fea8136f4791b60196a2c21b15afad5274e45bd29f672657a992dfc48d983`.
The exact locally retained ignored report identities are:

| Report | Bytes | SHA-256 |
| --- | ---: | --- |
| `v2` | 337,144 | `98abdf472818e21e43ff0e3cc3d509598558a6df6c1c215ea789a997fb5bc25d` |
| `v3-confirm` | 337,146 | `eabeba5d67b26574dbe4246f8924411fe7c1df252452d078688ae6a0bcb5682a` |

Candidate-arm median deltas against the compatibility seed were:

| Report | Log | Witness range | Direct range | RSS range |
| --- | ---: | ---: | ---: | ---: |
| `v2` | 10 | +0.123% to +1.009% | -0.415% to +0.384% | 0.000% to +0.209% |
| `v2` | 14 | -2.557% to +2.242% | -0.124% to +0.214% | -0.128% to -0.043% |
| `v3-confirm` | 10 | -1.121% to +0.924% | -0.872% to +0.940% | -0.416% to -0.208% |
| `v3-confirm` | 14 | -1.589% to +0.271% | +0.004% to +0.796% | +0.043% for every candidate arm |

These ranges do not establish a meaningful or repeatable layout regression.
In particular, q0 and q100 log-14 witness directions flip between the two
runs, and the observed movement remains within MAD/noise. H-010 therefore
selects no layout and makes no proof, Metal-candidate, production, or promotion
claim. Any future optimized layout needs a new decision and full verified
proof-path evidence rather than reinterpretation of this microbenchmark.

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
