# Bounded CPU recursion experiments

The fastest measured small-block route remains the explicit bounded M7 group
(three cold trials at 21.981 s median; one later 18.840 s qualification). It
refuses complete rosters larger than four native members. The ordinary recursive
DAG handles larger executions and remains the subject of heavy-block tuning.
Native proof production is additional to every recursion time in this note.

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

Metadata parking writes inactive CPU advice once into the existing quota-charged,
unlinked store and restores only the active shard. Auxiliary retirement frees
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
