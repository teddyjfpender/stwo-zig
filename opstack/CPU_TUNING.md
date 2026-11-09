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
CPU wrap cache.

## CPU lane ownership

`STWO_RV64_RECURSION_CPU_LANES=2` enables the experimental CPU route for an
explicit planned three- or four-child profile. Values 2–4 are admitted if the
caller's existing worker budget supplies at least two workers per lane. The
worker count comes from the request, rather than creating additional active
workers above that budget.

Each lane has a distinct, stably owned pool. Leaves partition the worker budget;
folds wait for active leaves to drain and then use the original complete pool.
A waiting fold blocks new leaves, preventing starvation. The existing DAG
retains dependency, ordered-coverage, publication and root checks. Its authority
slot bound is derived from the carry plan and lane count. Metadata, witnesses,
proofs and helper/coordinator stack reservations share the existing hard host
allocation budget. Allocation or spawn failures join started workers and refuse
root acceptance. Historical binary streaming trees explicitly refuse this
option rather than changing their durable node IDs.

`RECURSION_CPU_NODE_TIMELINE` records CPU pool width per node. GPU factories,
device admission and the established GPU timeline remain separate. The producer
writes `scheduler-cpu.json` with the actual lane/worker policy and budget snapshot.
The strict receiver ignores scheduling hints and reconstructs/checks the original
physical proofs and complete execution closure; it has no proving fallback.

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
STWO_RV64_RECURSION_CPU_LANES=2 \
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

Fast ownership, admission and cleanup checks:

```sh
zig build test-riscv64-recursion -Doptimize=ReleaseSafe -j1
```
