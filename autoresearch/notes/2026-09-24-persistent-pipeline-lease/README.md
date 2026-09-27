# Persistent pipeline ownership — 2026-09-24

The previous goal turn made progress: the shared bounded-limb BLAKE3 default was
qualified, measured on a canonical tree, and exercised across the CPU/Metal CSP
basket. This checkpoint returns to objective 1: persistent plans and bounded
scheduling. It makes no speed claim.

## Finding and implementation

The shared runner documented exclusive worker use but acquired the worker mutex
only inside each proof. Preparation, queue waits, and gaps between jobs did not
hold that reservation. A competing request could consume the admitted worker
budget or rebind its authenticated plan in those gaps; even a rejected competing
pipeline could do expensive preparation before discovering that the worker was
busy.

`Worker.acquire()` now returns a scoped lease. Existing one-shot proving methods
use the same lease internally. The shared runner acquires one lease after policy
admission and before reading worker state or allocating any request data. It
retains the lease until the producer is cancelled/joined, queued owners are
released, and error cleanup completes. All three native, execution, and tree
adapters prove through this lease rather than recursively acquiring the mutex.
The same thread acquires and releases the mutex. Inputs and worker still must
outlive the call; callers must prevent requests during destruction.

The focused tree gate adds decisive regression checks: a busy worker rejects a
pipeline before its deliberately failing allocator is touched, a competing lease
and one-shot proof are rejected, and allocation/preparation failures release the
lease for reuse. The existing two-job real proof path checks overlap, immutable
plan/fixed-column reuse, bounded memory, and verification after worker destruction.

## Qualification

The focused ReleaseSafe tree gate passed. It exercised two preparation workers and
two proving workers, 1.433 s of overlap, and a 3,387,424,087-byte worker peak under
8 GiB. Both outputs independently verified after worker destruction.

The canonical Metal execution pipeline passed **7/7 checks** with the accepted
ABI24 BLAKE3 bundle. Two jobs reused the same plan and fixed columns; both produced
839,853-byte independently verified artifacts with SHA256
`33b85e0a6519962ca53511b4dc06cecc0f2f5d0e06f299f95a8868efd10744dd`.
Eight proving workers plus one preparation worker were admitted. The two-job window
was 9.613 s with 1.912 s of actual preparation/proving overlap; worker allocations
peaked at 10,470,061,141 bytes under 24 GiB. This is a single correctness run, not
a matched speed experiment; that window excludes seed preparation, key/worker
construction, negative checks, and final verification. Both child and parent use
70 queries and 26 PoW bits.

The native-child ReleaseSafe gate passed **3/3 tests**, including two pipeline
proofs, reuse and independently verified output custody. Its first build exposed
four stale test calls to `State.finish(allocator)` after that API became `finish()`;
only those test calls were updated. The failed compiler log is retained separately.
All three adapters are now covered by real proofs.
The diagnostic tree uses q8/PoW0; it cannot qualify canonical speed or security
parameters. The canonical execution fixture uses q70/PoW26 and two identical jobs;
it does not establish heterogeneous-job or full-tree throughput.

No global overlap-default promotion, parameter change, or hash-protocol change is
part of this checkpoint. Canonical multi-job tree throughput, effective PCS/DEEP
fusion, remaining witness materialization, and a separately reviewed parameter
experiment remain open.

## Reproduce

```sh
python3 scripts/zig_serial_build.py test-riscv-blake3-tree-pipeline -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/autoresearch/notes/2026-09-24-blake3-rotate7-limbs/core" -Doptimize=ReleaseFast --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

The worktree is dirty. `control/`, `source/`, and `changes.patch` isolate this change
from earlier work. Raw qualification output is retained. No new CSP numbers are
claimed: the prior qualified CSP executable predates this worker ownership change.

## Matched serial versus overlap measurement

`measure.py` runs the frozen current binary in serial/overlap/overlap/serial order,
with eight proof workers, one preparation worker, the same ABI24 bundle, same
allocator, admission and two identical jobs. Serial mode drains the first job before
starting the second through the same bounded pipeline. The driver checks exact
artifact hashes, canonical parameters, plan reuse, worker budgets and independent
verification for every sample. All **eight artifacts** independently verify.

| Mode | Complete fixture (s) | Two-job window (s) | Overlap (s) |
| --- | ---: | ---: | ---: |
| serial | 22.791 | 11.033 | 0 |
| overlapped | 20.924 | 9.588 | 1.912 |
| overlapped | 21.033 | 9.614 | 1.910 |
| serial | 22.605 | 11.127 | 0 |

Median complete fixture **22.698 → 20.978 s (7.6% lower)**; median two-job window
**11.080 → 9.601 s (13.3% lower)**. Peak physical footprint rises
**26,258,142,864 → 28,178,414,208 bytes (+1.920 GB)**. These are two samples per mode
on this host with two identical canonical single-level jobs. Both modes include the
lease fix and current narrow G precompile; this measures scheduling, not the lease's
performance effect or a direct comparison with the older Poseidon/BLAKE3 binaries.
Full-fixture time includes initial child proving, seed preparation, key/worker
construction, checks and final verification. It is not full-tree throughput.

Unlike the older noisy single-level experiment, both overlap samples are faster
than both serial samples here. That supports this explicitly admitted bounded
schedule for this workload, while memory headroom remains necessary. It does not
justify blanket overlap across dependent tree levels or heterogeneous jobs. Default
preparation-worker count and canonical security parameters remain unchanged.

```sh
python3 autoresearch/notes/2026-09-24-persistent-pipeline-lease/measure.py
```

`binary.json`, raw process logs, `results.json`, `summary.json`, source snapshots and
`SHA256SUMS` preserve the observation. The frozen ABI24 bundle is the adjacent
`2026-09-24-blake3-rotate7-limbs/core` checkpoint.
