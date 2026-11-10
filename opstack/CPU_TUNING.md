# Bounded CPU recursion experiments

The historical bounded M7 group has three cold trials at 21.981 s median and
a later 18.840 s qualification. New source-only grouped constructions have
separate qualification results below; these are different protocols and timing
scopes, so this note does not rank them using unmatched runs. Native production
is additional to recursion-only times in this note. The heavy target is still
open; no new heavy proof has been rerun.

## Current execution and root observations

The experimental R7 terminal route now has a real one-process small-block
measurement, including guest execution and native production. It is separate
from the historical M6/M7 experiments below.

| Qualified scope | Time | Requested peak | Evidence |
| --- | ---: | ---: | --- |
| Actual OP120794432, guest through complete R7 root, latest integrated cache/ownership | 24.927 s | 8.667 GB | [Producer and fresh receiver](../vectors/reports/rv64-opstack-performance-20261110/selected-latest-cache-from-guest-v1.json) |
| Additional source-only receiver, including nine controls | 6.040 s | 4.511 GB | Same receipt; native proof bytes absent |
| Actual heavy guest's first 4M instructions, conditional B4 CPU proof | 21.170 s, originally 74.732 s | 10.093 GB unchanged | [Exact proof parity and stages](../vectors/reports/rv64-opstack-cpu-20261109/p2-native-intermediate-tiles-physical-v1.json) |

These are single qualification observations, not repeated quiet medians.
The last row leaves RAM/Wire obligations outstanding and proves no complete
block or recursive root. The first row closes the actual small execution, but
does not prove anchored derivation or admit experimental terminal Blake into
production or settlement. The heavy tenfold target remains open.

Use the [narrow terminal development gate](../src/integrations/riscv_cpu/poseidon2_outer/native_group/terminal_blake/DEV_LOOP.md)
for isolated root work, then the broader regression gates for integration.

The [matched small-block receipt](../vectors/reports/rv64-opstack-cpu-20261108/cpu-recursion-admission.json)
compares the existing M6 three-child tree on the same already produced D2 bundle:

| Experiment | Control median | Candidate median | Candidate RSS |
| --- | ---: | ---: | ---: |
| One 16-worker proof at a time → two CPU lanes | 35.375 s | 34.464 s | 28.13 GiB |
| Two lanes, 64 MiB → 1 GiB freed-block cache | 34.813 s | 34.000 s | 28.82 GiB |

There are two cold trials per variant, in balanced order. These are small observed
changes, not a large-block multiplier or a new small-block record. All eight
complete roots, every physical recursive proof and the tree bytes match exactly.
Every separate strict receiver accepts. Defaults remain serial with a 64 MiB
CPU wrap cache. The fanout experiment below is now rejected.

The first P2 repair changes only commitment dispatch/reuse. Selected stages of
the same conditional 4M fragment are:

| Stage | Before | After |
| --- | ---: | ---: |
| MAIN Merkle | 39.245 s | 5.792 s |
| INTER Merkle | 20.095 s | 3.828 s |
| Local GKR | 3.864 s | 3.515 s |
| Composition evaluation | 1.924 s | 1.803 s |
| FRI quotient and commit | 2.503 s | 2.316 s |

The non-hashing stages have no algorithmic change in this comparison; their
small timing differences are not additional claimed optimizations. Both proof
files and all statement/claim identities are identical.

The subsequent bounded native-four intermediate cache reduces the same fragment
from 24.426 to **21.170 seconds** (1.154×). MAIN and INTER Merkle become
3.810 and 2.739 seconds. GKR and composition timings remain essentially unchanged;
PCS/GKR bytes, source statements, claims and the exact 10.093 GB requested peak
remain identical. Overall native improvement against the original fragment is
3.53×, not a whole-block result. The explicit caller workspace is about 82 KB
per worker; this is not a complete compiler/thread-stack peak measurement.
See the [real cache qualification](../vectors/reports/rv64-opstack-cpu-20261109/p2-native-intermediate-tiles-physical-v1.json).

## Explicit B2 conditional control

The same actual-heavy 4M CPU fragment takes **12.612 s** under the existing
B2/q144 profile, versus **21.170 s** with B4/q72. Requested peak falls from
10.093 to **7.351 GB**, while the native proof grows from 1,333,204 to
2,411,820 bytes (**80.9% larger**). This is a different-protocol control,
not byte parity or a mixed-profile block acceptance result. Source layout,
base cells and execution agree; independently rebuilt profile keys verify
their genuine proofs and reject both cross-profile replays. No whole-block
or recursive performance follows from this conditional fragment.
See the [control receipt](../vectors/reports/rv64-opstack-cpu-20261109/heavy-conditional-b2-cpu-control-v1.json).

## CPU interaction ownership

The detached CPU worker now transfers completed interaction matrices to PCS
through a failure-atomic ownership handoff. Component handles keep immutable
points, challenges and claims; they read the committed trace during proving.
Failed irreversible commits mark the worker consumed before transcript mixing.

The same actual 4M fragment removes a source-derived 690,888,704-byte payload
copy and measures approximately 690 MB less RSS during composition/decommit.
The earlier MAIN/GKR high watermark remains 10.093 GB. Native time is
24.426 seconds versus 23.931 seconds in single observations: **no latency gain
is established**. Tiny complete two-CPU closure and both large fragment proof
files remain byte-identical; OOM, alias and early-PCS-error cleanup tests pass.
See the [ownership receipt](../vectors/reports/rv64-opstack-cpu-20261109/sponge-cpu-owned-interaction-v1.json).

## Retained-source GKR subphase profile

An isolated replay of the authentic 4M fragment's local GKR child matches its
entire 113,288-byte proof, receipt and eta. It reads the pinned retained MAIN
commitment and rebuilds source authority; it produces no new MAIN/INTER
commitment or native STARK and makes no new block/root acceptance claim.

| Local GKR phase | Wall |
| --- | ---: |
| Fused source projection and initial checkpoint tree | 0.659 s |
| Complete sumcheck traversal, including regeneration and transcript | 2.751 s |
| Total child production | 3.413 s |

Artifact assembly, closure/receipt and wire encoding are negligible here.
Traversal is 80.6% of this child measurement, but this does not isolate pure
field arithmetic from checkpoint regeneration. Requested peak for the isolated
source/key/replay process is 4.869 GB; measured RSS is 5.370 GB. The legacy
52-byte-per-fact diagnostic is a conservative admission planning reserve,
not a measured lower bound; all caps and admission charges remain unchanged.
See the [profile](../vectors/reports/rv64-opstack-cpu-20261109/heavy-retained-gkr-subphases-v1.json)
and [reserve reconciliation](../vectors/reports/rv64-opstack-cpu-20261109/gkr-checkpoint-reserve-reconciliation-v1.json).

## GKR memory and denominator controls

Retaining all upper fraction-tree layers reduces this isolated authentic child
from 3.413 to **2.636 s**, but raises requested peak from 4.869 to **11.252 GB**.
Proof bytes, channel state, receipt and eta match. Checkpointed storage remains
the default: a 0.777 s saving does not justify another 6.383 GB per concurrent
worker. This measures only the child, not a complete native proof or root.

Denominator lookup tables passed byte parity and allocation-failure tests but
took **3.544 s**, versus the checkpointed 3.413 s observation. This single
comparison establishes no benefit; the code remains isolated and only the
[negative receipt](../vectors/reports/rv64-opstack-cpu-20261109/heavy-gkr-denominator-tables-negative-v1.json)
was integrated. Neither control is counted as a production speedup.

## Current-source small-group repeat

The final [balanced repeat](../vectors/reports/rv64-opstack-cpu-20261108/final-small-group-repeat.json)
produces and freshly verifies nine complete roots, all matching their prior
same-variant proof bytes. Classic GROUP1 takes **21.466 s median** and
structural GROUP2 **21.881 s median** in three balanced trials per variant;
fresh reception takes **2.859 / 2.878 s**. The earlier 18.840 s GROUP2 sample
remains a single qualification, not a repeated median. Both variants still
pad arithmetic to 2^24 rows despite fewer GROUP2 active rows. GROUP1 remains
the default; GROUP2 is an explicitly qualified arithmetic experiment, with
smaller root bytes and no demonstrated wall speedup. None of these grouped
results admits more than four native members.

## Full-block result: CPU fanout rejected

The complete selected heavy block reproduces every physical recursive proof
under both schedules. Serial recursion takes **1,781.674 s**, at **31.117 GiB**
RSS. Two proof lanes take **1,790.027 s**, at **39.119 GiB**. Both strict fresh
receivers accept all 115 native proofs and 173 recursive nodes. The small
fixture's apparent 2.6% gain does not carry over; measured peak RSS increases
by about 26% on the heavy block.

The CPU fanout route is removed from production. Its [recoverable patch](../vectors/reports/rv64-opstack-cpu-20261108/rejected-cpu-recursion-lanes.patch)
and measurements remain available for research on other hardware. The patch
contains bounded pool ownership, dependency-safe dispatch, full-pool folds,
stack accounting and refusal tests; apply with `git apply --unidiff-zero`.
Supplying the retired `STWO_RV64_RECURSION_CPU_LANES` selector now refuses,
so an old script cannot silently benchmark serial execution as parallel.
The established GPU DAG route is unchanged.

This result concerns **outer recursive proofs**. The native execution/service
scheduler is separate: its existing two lanes of eight workers improved the
heavy native qualification from 1,723 to 1,428 s before guest improvements.
Do not infer one layer's scaling from the other.

## Freed-block cache

`STWO_RV64_CPU_WRAP_RECYCLE_BYTES` independently selects a finite CPU producer
cache from zero through 4 GiB; unset preserves 64 MiB. Freed cached blocks are
outside requested-live allocation accounting. Add that cap to the live budget
when sizing a host; neither quantity is an RSS guarantee. The producer receipt
records its cap, reuse/mapping counts and remaining cached bytes. Larger caches
trade RSS for fewer map/unmap faults; the small receipt does not establish a
large heavy-block gain.

For example, for an already produced **D2** complete native bundle and an
operator-sized host:

```sh
STWO_RV64_OUTER_PROFILE=m6_outer_diet_k3_r1_b2_q108_p20_fold4_v1 \
STWO_RV64_FOLD_ARITY=3 \
STWO_RV64_CPU_WRAP_RECYCLE_BYTES=1073741824 \
STWO_ZIG_RV64_RECEIVER_IDENTITY_ONLY_CPU=1 \
STWO_ZIG_RV64_RECEIVER_SETUP_THREADS=2 \
zig-out/bin/rv64-word16-ethereum-gkr-recursion \
  --security-profile d2_native_b4_q54_p20_fold4 \
  recurse-candidate execution-config.json complete-proof-directory \
  8589934592 55834574848
```

Use the native profile that actually produced the bundle. These settings do not
convert a B2 bundle to D2. The 8 GiB fixed-key admission is a subset of the
52 GiB requested-live limit; the freed-block cache is additional. Regenerate
request ABI symbols from the selected ELF. A fresh receiver independently
rebuilds source authority; neither producer setup files nor timing metadata
supply trusted keys.

The security label remains **128-bit security target under documented
assumptions**, with `security_qualified=false`. This is an execution-only root,
not authenticated L1 derivation, a portable root-only checkpoint, checkpoint
accumulation or a complete Solidity settlement proof.

Fast bounded-cache admission checks:

```sh
zig build test-riscv64-recursion -Doptimize=ReleaseSafe -j1
```

## Experimental pure-P2 source retention

The explicit `rv64-op-native` route accepts these optional resource-file fields:

```json
{
  "park_cpu_metadata": true,
  "retire_source_auxiliaries": true
}
```

Both default to false. They change producer custody, not the native profile,
source statement, manifest or receiver policy. They do not configure the older
Ethereum/D2 driver illustrated above.

On the detached route, metadata parking now writes each completed capture
shard immediately into the existing quota-charged, unlinked store and restores
only the active shard. The classic pure-P2 route retains its post-capture
parking behavior. Auxiliary retirement frees
post-seal LS32/LS-D64 raw fixed masks and SHIFT histograms after validating the
saved packed MAIN multiplicities. The later binding reads that already-retained
MAIN; it does not reconstruct a table or discard an authenticated obligation.
Immutable key FIXED data and its leases remain independently owned.

The actual small OP block was re-proved with both options: all 5,317,432 bundle
bytes match the unmodified schema-2 control, a fresh receiver closes the global
relations and terminal statement, and final heap/external reservations are zero.
The heavy source model identifies 2,224,128,000 bytes of removable auxiliary
payload plus inactive CPU metadata. This is not a measured RSS improvement or a
complete heavy proof. Do not add these payload reductions as though all objects
had overlapping lifetimes.

See the [metadata custody review](../vectors/reports/rv64-opstack-performance-20261109/native/cpu-metadata-parking.md)
and [auxiliary consumer review](../vectors/reports/rv64-opstack-performance-20261109/native/source-auxiliary-retirement.md)
for refusal rules, consumer citations and qualification scope. The user-requested
heavy rerun remains off the measurement schedule.

## Larger segments and smaller recursive statements

Larger **native execution segments** and larger **outer recursive traces** are
different changes. At the selected guest's retained 238,226,172 instructions,
ceil-dividing by nominal capacities of 2^22, 2^23 and 2^24 gives 57, 29 and 15
CPU leaves. These are planning counts, not admitted requests or measured speedups:
`rv64_ethereum_request.validateBudgetForOp` currently refuses batches at or
above 2^22. Service leaf counts do not fall automatically with the CPU count.
Clock/range authority, authenticated GKR geometry, independent source setup,
memory admission and endpoint/continuity tests must qualify a changed protocol
before the loader can admit a larger segment. Do not remove the guard alone.

The grouped experiment above is a useful counterexample: fewer active
arithmetic rows did not improve repeated wall time because both variants still
padded that component to 2^24. Instance sizing should follow actual per-component
work and memory, rather than forcing CPU, arithmetic and services to that height.

The current structural work is:

| Change | Concrete evidence | Remaining production gate |
| --- | --- | --- |
| Native DEEP dot accumulator | Seven-role physical R7 proof and degree3/2n AIR; live DEEP lowering with joint source usage and legacy-key refusal; source-count model reduces relevant heavy outer cells by 23.5% | Actual CPU-leaf and complete-root qualification, with class-specific padding/cost admission |
| Serialized sponge | Five independently sized roles, full RAM/IO/OWNER closure and fresh physical PCS/GKR reception | A narrow authenticated CPU frontier and complete inventory/root integration; no admission from an isolated zero local claim |
| Immutable outer Miller setup | Bounded producer/verifier caches reproduce the exact complete fixture root, including forced fallback, with separate request bindings and class lifetime barriers | Repeated-class whole-execution timing; the one-Miller fixture has no amortized proving hit |
| Guest Miller packet retention | Independent tiny RV64 probe and host packet-equivalence tests | Explicit opt-in candidate and representative qualification; modeled copy savings are not proof-time savings |

See [delivery gates](COMPLETION.md) and the
[native-dot receipt](../vectors/reports/rv64-opstack-cpu-20261109/native-dot/standalone-physical.json).
The next architecture should reduce verification work and leaf count together;
neither a larger padding threshold nor additional CPU lanes establishes that.

The actual suite3 small-block root's five serial node profiles locate the next
CPU bottleneck: MAIN commitment33.749 seconds, INTER commitment31.382 seconds,
composition commitment20.086 seconds, but composition evaluation only4.323
seconds. Nested streaming Merkle work accounts for55.876 seconds; streaming
preparation is9.255 seconds (including7.372 seconds extended-domain evaluation).
Those nested numbers are included in their parent commitments, not additional
wall time. Full recursion takes140.855 seconds including source construction and
collector overhead. This qualification was not a quiet performance A/B. It
motivates improving P2 hashing and lowering committed volume before pursuing
another composition-only optimization; proof identities must remain unchanged
for an operational hash-kernel improvement.

## Current grouped-source qualification

The detached route explicitly selects its own source suite and never inherits
producer-provided keys. The group root accepts independently pinned request
configuration, reconstructs native geometry and full statements, authenticates
all members directly and closes RAM/KIO/Wire plus the terminal 43-byte output.
Canonical groups of 1, 2 or 4 preserve the original ordered fold-tree digest.

The same selected 796,406-instruction execution has complete R6/B2 and R7/B2
one-group roots in 46.589 /37.757 s of node work, respectively; full cold root
producer times are 62.630 /51.743 s. Two groups plus one fold lower requested
peak to 10.071 /7.413 GB but increase totals to 100.110 /106.125 s. These are
engineering qualification runs, not quiet A/B measurements. In particular, R7
pads the CPU+sponge subgroup worse than R6: select from actual per-group cost
rather than assuming every arithmetic rewrite or smaller group is faster.

The separate terminal-Blake test closes that same source in 19.078 s of proof
work and 37.097 s producer total. Both real Poseidon2 source setup and separate
Blake FIXED construction are included. Fresh source-only verification takes
15.377 s setup plus 9.489 ms root read/verify. The suite has its own key identity,
transcript domain and wire format; valid roots do not substitute across suites.
It remains test-only, without runtime/settlement admission, pending bounded
hash/Fiat-Shamir accounting. It cannot be fed into the existing Poseidon2 parent
verifier as though the formats were interchangeable.

See [current delivery evidence](COMPLETION.md#complete-grouped-small-execution)
for exact receipts, proof sizes, controls and security qualifications. None of
these measurements establishes the complete heavy-block tenfold target.

## Streaming capture custody

The detached native producer's optional `park_cpu_metadata` now applies during
ordered capture, before inactive metadata from every shard accumulates. The
chronological RAM ledger first consumes the compact tape; raw CPU capture rows
are retired; only then may the custody hook move immutable metadata to disk.
Planning uses retained public boundaries and fact censuses. Before either proof
stage consumes metadata, the same descriptor and SHA-256 checks restore it into
the explicitly budgeted heap. Disk quota is shared with retained MAIN.

An actual two-CPU split of selected OP120794432 produces the exact same
6,315,160-byte native bundle, metadata and public cells as the unparked control.
Fresh receivers/callback checks pass; an injected failure immediately after
parking releases every file quota and heap/external owner. This is not a measured
RSS multiplier. The metadata payload model for the selected heavy guest falls
from 13.34 GB retained across capture to at most 234.9 MB for one full shard;
other facts, RAM events, key/witness/PCS scratch and disk retention are additional.
The 256-worker cap is unchanged, and this does not qualify the anchored replay.

[Qualification receipt](../vectors/reports/rv64-opstack-cpu-20261109/streaming-capture-custody-v1.json).
