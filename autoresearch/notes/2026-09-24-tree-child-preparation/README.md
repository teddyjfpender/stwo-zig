# Bounded tree child preparation — 2026-09-24

## Measured problem

The frozen two-level-frontier profile spends 4.694 seconds preparing the root's two
independent Merkle path witnesses. Live emission accounts for 4.174 seconds. Transcript
planning is only about 7.7 ms per child, so additional transcript caching is not the
first target. See the adjacent frontier-preparation-profile note and raw receipts.

## Implementation

`tree.preparePairWithPool` accepts a caller-owned persistent WorkPool and admits at
most two workers (one helper plus the coordinator). A one-worker pool and the existing
`preparePair` API execute serially. Admission rejects aliases, invalid keys/spans and
nonadjacent nodes before witness allocation. Both preparations finish before any
helper result is read or a lease released. Errors destroy partial owned preparations;
success transfers both owners to the existing namespace/rebase/join implementation.
Borrowed nodes remain valid on every path. The circuit, key derivation and parameters
are unchanged. No ambient global worker count or unbounded thread creation is added.

The caller must supply an allocator safe for concurrent access and the aggregate
preparation budget; pool stacks are a separate caller reservation. Canonical qualification
uses the existing 48 GiB SharedHostBudget for the complete fixture and a two-worker
pool. It forces allocation failure under a separate one-byte budget, checks zero live
bytes and all worker slots returned, then reuses that same pool for success. The root
proof independently verifies after the preparation pool has been destroyed.

This API permits caller reuse across jobs; this fixture qualifies failure-to-success
reuse. It does not establish throughput across multiple successful concurrent trees.
The prior prepare/prove overlap experiment remains separately opt-in.

## Validation and measurements

Canonical qualification passes **7/7**, including the forced budget failure, returned
worker slots and successful reuse. All three independently verified artifacts retain
the exact previous sizes. Root preparation is 4.507 seconds in this profiled run,
versus 6.902 seconds in the preceding frozen profile; these diagnostic observations
are not the matched result. Routed peak remains 29,486,122,073 bytes. Frozen matched
ABBA measurements have completed as recorded below. The driver compares against the frozen native-two-level
frontier executable, checks unchanged artifact sizes 853044/850623/903838 and
q70/PoW26 at every level, and requires the candidate's pool reuse receipt. All runs
use the same archived authenticated core bundle, SMP allocator and eight CPU leaf
workers. Full fixture timings include checks and cleanup, not only proving.


## Root domain floor

`root_floor.py` reads the previous qualified canonical census. Current root G rows:
6,032,768. Remaining repeated upper hashes: at most 1,433,264 G rows saved before
any additional routing overhead. The optimistic residual is 4,599,504, still 405,200
above the 4,194,304-row threshold. Therefore deeper upper-node sharing alone cannot
halve this root G domain with the measured child proof geometry. This is a topology
bound for this fixture, not a global lower bound: changing child geometry, leaf work,
hash representation or separately reviewed parameters can change it. Do not prioritize
another dense frontier solely on an assumed root domain reduction.

The first frozen control completed before the candidate launch failed because the
copied executable lacked its executable mode. The failure launched no proof; its raw
log is retained. File mode was corrected, the driver gained hash-checked resumption,
and the remaining candidate/candidate/control runs resumed without discarding the
completed control or rerunning it.


## Scheduling scope and next integration

The supplied-pool API is explicit. The existing serial API remains available and the
shared prepare/prove pipeline still admits one preparation CPU token. It must not
silently receive a second helper: extending that pipeline needs two preparation tokens
plus its admitted proof workers, a preparation-pool lifetime spanning jobs, separate
stack accounting and evidence that overlap does not regress total time. The present
canonical benchmark qualifies parallel child preparation without concurrent proving.


## Final matched result — retained as explicit scheduling

| Run | Arm | Complete fixture seconds |
|---|---|---:|
| 1 | control | 44.566 |
| 2 | candidate | 43.059 |
| 3 | candidate | 43.416 |
| 4 | control | 46.510 |

Complete fixture median: **45.538 → 43.237 seconds (5.1% reduction)**.
Root preparation median: **7.055 → 4.705 seconds (33.3% reduction)**.
Both candidates are faster than both controls, but there are only two samples per
arm and the controls vary by nearly two seconds. Treat this as a local result, not
a broadly established distribution or an order-of-magnitude gain.

| Phase median | Control seconds | Candidate seconds |
|---|---:|---:|
| Left leaf pair + preparation | 6.205 | 6.115 |
| Left aggregate + checks | 6.063 | 6.068 |
| Right leaf pair + preparation | 6.576 | 6.395 |
| Right aggregate + checks | 6.082 | 6.091 |
| Root preparation | 7.055 | 4.705 |
| Root aggregate + checks | 13.207 | 13.195 |

Maximum physical footprint: 44,450,685,840 → 44,445,491,896 bytes, essentially unchanged.
Routed peak remains 29,486,122,073 bytes. Root retained rows and every artifact size
are unchanged. All twelve timed aggregate artifacts independently verify at q70/PoW26;
every fixture passes all seven checks. No additional broad test suite was run for this
scheduling change. Formatting/whitespace checks pass and source snapshots match.

The goal remains active. Full CSP recovery, further effective PCS/DEEP fusion,
additional direct emission and a separately reviewed parameter experiment remain open.
This does not demonstrate subsecond recursion or superiority to ZisK.

```sh
STWO_RISCV_PARENT_PREPARATION_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-tree-child-preparation/measure.py
python3 autoresearch/notes/2026-09-24-tree-child-preparation/root_floor.py
```

The measurement driver resumes existing hash-checked results; a fresh experiment
needs a new results directory/checkpoint. The archive includes the failed launch,
all completed samples, changed-source snapshots and relative patch. It is a dirty
worktree checkpoint, not a complete source checkout.
