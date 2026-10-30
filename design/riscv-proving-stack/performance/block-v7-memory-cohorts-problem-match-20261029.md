# Bounded original memory cohorts

The block census in `next-generation-riscv-20261028.md` is 356,303,914 events,
including 298,427,187 register events. This leaves 57,876,727 RAM events, plus
13 terminal reads. The adjacent JSON records a **calculated allocation model,
not measured RSS**. At row logs 20–23 the current joint stage pads to 29,360,128
rows. Its 24 fixed + 88 main + 116 interaction columns occupy 24.9375 GiB raw,
24.9375 GiB coefficients and 49.875 GiB doubled LDEs: **99.75 GiB** before other
owners. Log-22 quotient evaluation adds **14.25 GiB**. One STARK does not imply
bounded memory.

Evidence: `block_v7_memory_witness_v1.zig:25` copies and sorts all events; lines
55–62 temporarily retain old 78-column and new 112-column matrices, retaining
all finished matrices. `block_v7_memory_joint_proof_v1.zig:102` retains
coefficients; lines 104–112 keep all first-round trees; lines 136–164 keep all
interaction matrices through proving. `block_v5_word_quotient_adapter_v1.zig:126`
evaluates all component columns on a four-times-larger domain. Streaming column
commitment bounds transient batches, not retained complete trees.

The default joint limits reject much earlier: 8 GiB stage, 65,536 events,
128 MiB matrix, row log 16. The current streamed execution driver raises event
capacity to 1,048,576, still below this block. Compact polynomial storage exists
in PCS but is not enabled by the joint Stage. Compact alone leaves 49.875 GiB
payload plus 14.25 GiB quotient scratch at log 22, already 64.125 GiB before
Merkle/FRI/twiddles and other stages. Raising caps is not a solution.

## Problem matching and chosen boundary

This is external-memory staged processing and globally coupled permutation
closure. The existing separate v7 `.ram`, `.interval`, `.range16`, `.terminal`
epoch already expresses bounded original proofs under one challenge draw; use
it instead of inventing an unauthenticated per-chunk reset. One row-log-22 RAM
component per proof yields seven RAM proofs plus three small provider proofs.
Original equations, source identities and challenge grammar remain unchanged.

The producer must commit/spill each complete prechallenge cohort once, retain
only metadata and census, then restore/prove one cohort after the complete epoch
is known. A sorted reader boundary avoids loading the complete event stream;
the execution driver now supplies an external transition sorter. Original checkpoint
bytes are untrusted proving material. Exact independent fixed roots and fresh
original proof verification remain authoritative.

All event ordinals, predecessor/endpoints and the complete geometry sequence
must remain global. Initialization, range16, link, integer counts and terminal
transition contributions close once across every authenticated cohort. First
halt remains constrained per active RAM event. No per-cohort global zero-sum
shortcut is valid; no RAW/FOLD source proof is required.

Implemented modules: `block_v7_memory_cohort_checkpoint_v1.zig` reuses the existing
bounded CPU PCS tree codec; `block_v7_memory_cohorts_v1.zig` owns bounded
collect/spill/reload/prove. The independent existing
`block_v7_memory_source_v1.For(Cpu).verify` receives the resulting ordinary
Bundle. The qualified joint route remains unchanged. First qualification is a
genuine multi-cohort exact-proof differential and fresh verification with
missing/reordered/corrupt checkpoint negatives; block-scale runtime and recursive
cohort adapters are separate subsequent gates.

## Implemented original-proof seam

`block_v7_memory_cohorts_v1.Owner.collectSorted` now consumes a bounded reader,
constructs/commits/spills one original RAM component at a time, and retains only
its geometry/checkpoint pins plus interval/range census. The reader must include
the terminal events in its sorted stream. It is not proof authority: the unchanged
original source verifier closes the terminal transition relation against the
independent public output policy. The three providers are constructed and
checkpointed separately. `entries` supplies the original Epoch roster;
`prove` restores one raw matrix and its two original PCS trees at a time.

The checkpoint stores exact prechallenge LDE/Merkle state with no FFT or Merkle
recommit on load. Coefficients are not stored: the existing quotient adapter
recovers the polynomial into its already bounded quotient buffer, checking the
high tail. Each cache file binds policy/family/index/geometry-derived identity,
roots and exact bounded shape. Canonical cache corruption remains untrusted
witness data and can never bypass the ordinary fresh verifier.

Focused genuine differential gate (2026-10-29): **PASS**, five RAM cohorts and
three providers, 16 guest events plus 13 terminal reads. Every RAM root and proof
byte matches the old in-memory separate Stage. After the producer is destroyed,
the unchanged `block_v7_memory_source_v1.For(Cpu).verify` succeeds. Missing files,
wrong-cohort files, noncanonical cells, undersized load limits, reordered global
geometry and altered physical claims are rejected. Charged peak is **74,358,776
bytes**, under a 96 MiB stage cap. This is a tiny correctness gate, not a full
block memory measurement or a timing benchmark.

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_memory_cohorts_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'bounded spill'
```

## External sorting and execution integration

The opt-in execution driver now writes native and caller transitions directly to
`block_v7_transition_spool_v1`, appends the thirteen independently derived
terminal reads, and performs a bounded 32-way external merge. The 21-byte record
preserves both before and after values. Ordering is strict on address/clock;
duplicate keys are rejected even when their values differ. The existing
17-byte event spool delegates to the same generic sort implementation, retaining
its original radix sorter and API. Sort-buffer capacity, event count, run count,
merge fan-in, matrix memory and checkpoint storage all have explicit limits.

`block_v7_streaming_memory_v1` owns the joint/cohort choice and removes every
checkpoint before the execution consumer returns. Cohort proofs are ordinary
original proofs under the existing complete Epoch; no synthetic source receipt
or additional RAW/FOLD proof is introduced. The default joint route is unchanged.

Qualification: all four pre-existing sorter tests and the new transition test
passed, including 129 records across 33 initial runs, two merge rounds, exact
before/after values, and duplicates crossing the fan-in boundary. The genuine
execution gate then passed with 20 guest cycles, 103 guest memory events and
13 original proofs. The configured four-record sort buffer reported 96 bytes;
the cohort stage charged peak was 104,192,824 bytes. Its original fresh receiver
closed the execution, ROM, lookup, callers, memory and terminal obligations, and
the temporary directory was empty afterward. A repeated gate retained only
`Metadata.Owned`, destroyed the producer and all original proofs, then
reconstructed the exact separate-family public roster from owned independent
profiles successfully. Missing cohorts, a missing memory mode, and reordered
cohorts are rejected by the detached reconstruction. These are tiny diagnostic
correctness measurements, not a block-scale performance claim.

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_cohort_execution_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 execution externally'
```

The recursive integration has four finite original verifier families: RAM,
interval, range16 and terminal. Each RAM profile retains its independent
geometry, ordinal, predecessor and endpoints; the complete receiver must admit
the entire ordered geometry sequence and close the original shared relations
once. Each provider profile independently derives its fixed roots and original
physical claims. The root public union distinguishes these families from joint
memory and requires exactly one of the two modes. Metadata owns the initialized
ELF policy and every profile after producer destruction. Partial windows remain
open; they never authorize missing cohorts or per-cohort zero-sum shortcuts.

Remaining qualification: canonical-security and block-scale capped
execution. No large-block feasibility or recursive performance claim follows
from the small original-proof gates.


For capacity planning, one full log-22 cohort has 1.75 GiB raw fixed/main
columns, 3.5 GiB prechallenge LDEs and at most 1 GiB of their Merkle nodes.
Its interaction matrix adds 1.8125 GiB, interaction LDEs 3.625 GiB and at most
0.5 GiB Merkle nodes; the current quotient-domain array adds 14.25 GiB.
These simultaneously plausible payloads total about **26.44 GiB**, excluding
composition/FRI, FFT scratch, twiddles and other owners. This is a planning
calculation, not a peak-memory bound or a successful large run. Diagnostic
2 GiB cohort and 24 GiB fixture budgets deliberately cannot admit this shape.
Checkpoint disk, matrix caps and the encompassing host budget must be selected
explicitly before a block-scale run; they cannot be inferred from the tiny gate.

## Complete recursive execution gate

The genuine streaming execution fixture also reached one detached complete
root with the cohort option enabled: **PASS11** on 2026-10-29, diagnostic
q8/PoW0. The 20-cycle workload produced two native proofs, one caller proof,
four RAM cohorts, interval/range16/terminal providers, ROM and lookup: twelve
original proofs reduced to a 159,188-byte root. Verification followed destruction
of all original proof owners and checkpoint files. Missing cohorts and
compensated RAM-initialization/interval claim changes were rejected.

The observed run took 68.33 seconds and charged peak was 7,999,930,428 bytes.
This is an unranked tiny diagnostic measurement, not canonical security,
block-scale memory qualification, or a controlled performance comparison. The
binary preceded the later receiver-matrix-cap hardening, which has its own
focused qualification gate.

```sh
STWO_V7_SCALE_MEMORY_COHORTS=1 python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v7_streaming_complete_root_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'v7 variable execution'
```

## Allocation accounting across recursive windows

`block_v7_bounded_complete_cpu_producer_v1.WindowStats.charged_peak_bytes`
measures allocations routed through that window's `SharedHostBudget`. It is
**not whole-proof memory or RSS**. Its backing allocator also retains the source
metadata and staging owners. In the bounded streaming fixture the window cap is
24 GiB and its outer source cap is 48 GiB. The shared WorkPool is created before
windows, backed by that outer budget; ordinary pool submissions and thread-pool
metadata therefore bypass the window counter. OS thread stacks, allocator
metadata, code and file-cache residency also make process RSS different from
requested heap bytes. Pool lifetime must remain outside every window: rebinding
its allocator to a short-lived child would create invalid retained owners.

Source inspection found no persistent FFT workspace allocated through the
WorkPool: FFT buffers and finite CPU composition scratch use the explicit request
allocator. A real bypass existed in sampled-value evaluation instead:
`src/prover/pcs/sampled_values.zig` used `page_allocator` for per-tree worker plans
and shared barycentric waves, and `sampled_coefficient_split.zig` used it for
split bases. A barycentric workspace contains two QM31 arrays, or **32 × 2^L
bytes** (512 MiB at L=24; 1 GiB at L=25), in addition to an already charged
8 × 2^L-byte domain context. Concurrent tree workers may hold more than one
workspace. Split bases use 16 × (1024 + 2^(L−10)) bytes for L≥12: 272 KiB at
L=24. These allocations previously bypassed both window and outer counters.

The sampled-value path now forwards request allocation through a scoped
`ThreadSafeAllocator`, keeping non-thread-safe caller allocators safe while
workers allocate concurrently. All workers join before the wrapper dies. Shared
waves use the same request allocator; split bases take it explicitly and
propagate allocation failure. Neither pool lifetime nor proof equations change.
The focused log-12/log-18 gate (PASS2) passes both execution paths, rejecting insufficient
budgets, checking exact evaluation values and zero live temporary bytes after
cleanup. A separate PASS2 checks split-basis independent polynomial parity across
ragged worker batches and exact-cap/OOM accounting. Existing earlier receipts remain evidence of the **old counters**;
they must not be reinterpreted as measurements after this accounting fix.

For context, the saved diagnostic three-window run records window peaks
5,707,266,668 / 1,491,448,676 / 1,151,626,371 bytes, reduction peak 2,787,624,396
bytes, and process maximum RSS **5,809,078,272 bytes**. These are different scopes,
not quantities to subtract to infer hidden simultaneous allocations. Its cold
resource model is a planning estimate, not an RSS theorem. Canonical qualification
started before the sampled-value fix and requires a new run before making claims
about the updated accounting; no new block-scale memory result is implied here.

Bounded-window statistics now additionally report optional parent-budget live
bytes before/after the window, its cumulative lifetime peak and its cap. These
are observations of the identifiable backing budget, not a window-attributed
RSS estimate. `STWO_HOST_MEMORY_PROFILE` also emits process and child/parent
markers at the same boundaries. The producer semantics compile after this
instrumentation; it has not generated a new proof timing receipt.
