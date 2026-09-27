# Bounded compression-call emission — 2026-09-24

## Finding and change

The preceding goal checkpoint made progress: canonical bounded pipelining was
implemented and qualified, but overlap alone did not establish a stable total-time
benefit. Phase profiling now identifies live Merkle-path witness emission as the
main preparation cost. In the control qualification it accounts for over 93% of
path preparation; path preparation itself accounts for roughly 90% of complete
preparation. Transcript planning, trusted path metadata and teardown are much smaller.

The shared native-main-column hash emitter previously switched among all 112 G
columns for every row. It now stages exactly one compression call (56 G rows and
16 XOR rows) on the stack and writes each destination column across that batch.
This reduces destination-column switching while retaining the same committed row
mapping and compact metadata. There is no full-witness intermediate, new heap
allocation, workload dispatch, alternate protocol or parameter change. The same
emitter serves transcript and Merkle-path main-column generation. Improved memory
locality is the mechanism targeted; no hardware-counter evidence isolates TLB versus
cache effects. This is a recursive witness change, not a measured ordinary CSP win.

`STWO_RISCV_PARENT_PREPARATION_PROFILE=1` enables preparation phase timing and
aggregate path timing (live generation, trusted generation, append, other).
The other bucket includes geometry, handoff bookkeeping and per-opening cleanup.
Disabled profiling has no clock reads. Output includes thread IDs to distinguish
seed preparation from producer preparation. Timings are diagnostic, not protocol data.

## Qualification

- Focused ReleaseSafe: **12/12 tests pass** across hash, frame, transcript plan,
  draw, bounded draw and query batch. Existing tests compare every logical row,
  compact metadata, physical lookup columns and claimed sums, untouched padding,
  invalid shapes and allocation failure behavior. The main-column hash test covers
  empty, multi-block and multi-chunk inputs with a nonzero output offset.
- Canonical Metal pipeline: **7/7 tests pass** with SMP allocation, eight proving
  workers and one preparation worker, q70/PoW26 for both child and parent.
- All eight timed parent outputs verify, including fresh codec copies after worker
  destruction, retain fixed plan identity and fit the admitted allocation limits.
- Every parent artifact remains 857,591 bytes with SHA-256
  `87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b`.

The job pair repeats one tiny canonical execution capture. It is not a full
recursive tree, heterogeneous-job reuse or a production root-latency benchmark.

## Matched measurement

M5 Max, ReleaseFast, SMP allocator, same authenticated Metal AOT bundle and job
limits. Frozen control/candidate/candidate/control process order; compilation is
excluded. Profiling is enabled in both binaries. Two processes per variant, two
parent proofs per process; all observations retained.

| Metric | Control | Batched emission |
|---|---:|---:|
| Complete fixture median | 24.3146 s | 21.3398 s |
| Two-job pipeline window median | 13.7485 s | 11.6790 s |
| Seed live-path emission median | 2.4288 s | 1.5943 s |
| Maximum physical footprint | 32,767,738,656 B | 32,498,221,472 B |

Complete fixture time falls **12.2%**, pipeline window **15.1%**, and seed live-path
emission **34.4%** in this experiment. Both candidate observations are faster than
both controls. This is stronger evidence than the earlier noisy overlap comparison,
but still a small local sample, not a cross-machine throughput guarantee. The small
physical-peak reduction (~269 MB) does not establish a broad memory-footprint claim.
Tracked worker allocation peak remains unchanged at 11,994,253,102 bytes.

The fixture includes child proving, seed preparation, key/worker construction,
negative checks, the two parents, and final verification. The pipeline window
excludes those outer costs. These totals must not be compared directly with CSP
prove-only historical numbers. Both arms use overlap, so this experiment qualifies
the emission improvement; it does not separately establish an overlap-versus-serial
benefit or justify changing production scheduling defaults.

## Reproduce and evidence

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-hash test-blake3-frame-witness test-blake3-transcript-plan test-blake3-draw test-blake3-bounded-draw test-blake3-query-batch -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PARENT_PREPARATION_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-pipeline-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-parent-preparation-profile/measure.py
```

`binary.json` pins the frozen binaries and identifies the preceding checkpoint's
archived authenticated core bundle. `initial-qualified.log` profiles only outer
phases; `control-qualified.log` adds path buckets; `candidate-qualified.log` qualifies
the batched emitter. `focused.log` records the ReleaseSafe checks. Raw matched logs,
results and summaries are retained. `emission.patch` is the control/candidate emitter
delta. `candidate-source` records the three changed production files; `source`
records the initial profiles and control emitter. This is a dirty-worktree checkpoint,
not a claim that repository HEAD plus these three files reproduces every dependency.
The previous pipeline evidence retains the prerequisite source snapshots.

Full canonical recursive trees, heterogeneous persistent reuse, reliable scheduling
policy, deeper PCS/DEEP fusion, full CPU/Metal CSP recovery, and the separately
reviewed parameter experiment remain open. No 10x or subsecond recursion claim.
