# Session 08 — parallel witness counting passes

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Branch `autoresearch/cairo-native-throughput-10x`, base `c8e29225`.
Host: Apple M5 Max, 12 performance + 6 efficiency cores.

Increment 7 left a measured pool-invariant serial floor of ~139 ms inside
`base_trace_build` on memory-7m. This session audits the three routines that
make it up, asks whether each admits an exact parallel merge, and implements
the ones that do.

## 1. Audit

### Method

A temporary probe gated on `STWO_INC8_AUDIT` was added to
`compact_inputs.materializeInternal`, `cpu_memory_multiplicity.collectTopology`
and `multiplicity_tables.Tables.route`, plus a `std.time.Timer` split inside
`fixed_trace.populateLiveTopology`. One cold memory-7m run; the probe was
reverted before any implementation commit. Counts are exact; the two timer
figures carry only the cost of two `Timer.lap()` calls.

memory-7m, `stwo_memory_200x300.json`:

```
INC8 compact: rows=7367978 unique=247 tuple_words=7
INC8 route: routed=8732 dense_words=542848 tables=22
INC8   table range_check_11 words=2048
INC8   table range_check_18 words=524288
INC8   table range_check_4_3 words=128
INC8   table range_check_7_2_5 words=16384
INC8 populateLiveTopology: route_ms=0.180 range_checks_ms=43.000
INC8 collectTopology: address=6099360 big=304 small=842576 increments=30891958
```

Both `populateLiveTopology` calls in the process (base trace and interaction
trace) reported the same split, 43.000 / 42.187 ms.

### The first surprise: `route` is not the cost

`fixed_trace.populateLiveTopology` is two phases. `Tables.route` — the
producer-graph scatter into fixed multiplicity tables — is **0.180 ms**. It
performs only 8,732 routed rows on this workload, because the producers that
feed fixed tables are the small ones. The entire 43-44 ms that increment 7
attributed to "fixed multiplicities" is `addMemoryRangeChecksLive`, which is a
different shape: it walks the memory *value* tables and feeds
`range_check_9_9`.

That retargets the third lever completely. `route`'s per-row cost is genuinely
awful — `std.mem.startsWith` on the target name, a decimal `rangeKey` shape
parse with `splitScalar` + `parseUnsigned`, and a linear `find(label)` string
scan over 22 tables, all per row — but at 8,732 rows it is worth 0.18 ms and
optimizing it would be unmeasurable. Recorded and left alone.

### Order-dependence table

| Routine | Output | Depends on traversal order? | Why |
| --- | --- | --- | --- |
| `compact_inputs.materializeInternal` (`src/frontends/cairo/witness/compact_inputs.zig:103`) | unique tuple set with additive multiplicities, emitted **sorted** by `key_words` | **No** | Counts are `u32` additions. The emitted order is a total sort, and the keys are provably distinct under that sort: two rows sharing a `key_words` prefix but differing in the full tuple are rejected as `ConflictingKey` (`:158`), and two rows with the same full tuple cannot both exist (hash-map keys are unique). So the comparator has no ties and `sortUnstable` has a unique fixed point independent of the pre-sort permutation. |
| `cpu_memory_multiplicity.collectTopology` (`src/frontends/cairo/witness/cpu_memory_multiplicity.zig:99`) | three dense `u32` count arrays (`address`, `big`, `small`) | **No** | Pure scatter-increment histogram. `increment` (`:173`) is a checked `u32` add; addition is commutative, and counts are monotone so a checked add on the merged total fails exactly when the serial running count would have failed. |
| `fixed_trace.addMemoryRangeChecksLive` (`src/frontends/cairo/conformance/fixed_trace.zig:445`) | `range_check_9_9` dense multiplicity columns | **No** for values; **yes** for one allocation side effect | The increments are the same additive histogram. The order-sensitive part is `Tables.increment`'s lazy dense allocation (`multiplicity_tables.zig:59`) and its `self.dense_words` budget: *which* table trips `GeometryTooLarge` first depends on allocation order. The value output does not. |
| `multiplicity_tables.Tables.route` (`:108`) | fixed multiplicity tables | No (same additive argument) | Not parallelized: 0.180 ms measured. |

No pass in the floor assigns first-seen ordinals or builds an insertion-ordered
table. All three are additive histograms, and all three admit an exact merge.
The only order-dependent artefact anywhere in the set is the lazy-allocation
budget, which is handled by reserving the one affected table sequentially
before the parallel phase, in exactly the position the serial path would have
allocated it.

### Shape of each pass, and what that implies for the merge

**`materializeDerived` — 7,367,978 input rows collapsing to 247 unique
tuples.** This is the ideal parallel histogram: the private per-worker table is
247 entries at worst, and the merge is `workers x 247` map operations. There is
no memory penalty and no merge cost worth measuring. The pass is 43 ms of
`getOrPut` on a 28-byte key, about 5.8 ns/row, against a working set that fits
in L1. Expected to parallelize near-linearly until it becomes bandwidth-bound
on the ~206 MB of producer words it must read.

**`collectTopology` — 30,891,958 increments into 6,942,240 `u32` slots
(27.8 MB).** Private full copies are the only exact merge available: every
producer and every feed can hit any address slot, so there is no disjoint
output partition to exploit without re-reading the input once per worker.
Private copies cost `W x 27.8 MB` to allocate, zero and re-read, so the merge
is bandwidth-bound and the optimum worker count is finite. Modelling the pass
as `30/W + c*W` ms with `c ~ 1.4` (zeroing plus merge traffic at this host's
~40 GB/s) puts the optimum near `W = 4-6` and the floor near 13 ms. A byte
budget therefore has to cap the worker count; an 18-way split would spend more
on merge traffic than it saves on scatter.

**`addMemoryRangeChecksLive` — dominated by the small-value loop.** `big` holds
304 values, so `bigComponentCount` x `bigRowCount` is a few thousand rows and
the big loop is noise. `small` is `smallRowCount` = 2^20 rows and
`small_limb_count` = 8, so the loop is 4 pairs x 1,048,576 rows, each row
costing two `execution_tables.limb` extractions plus one increment — 8.4M limb
extractions and 4.2M increments. Critically, for the small loop the relation
index **is** the pair index (`fixed_trace.zig:477`), so different pairs write
to different `range_check_9_9` relation columns. Row-parallelism within a pair
needs only a private copy of the columns that pair touches — `row_count` is
2^18, one column is 1 MB — not a private copy of the whole table.

### Verdict of the audit

Three passes, three exact merges, no negative audit. Two of them
(`materializeDerived`, `addMemoryRangeChecksLive`'s small loop) have cheap
merges; one (`collectTopology`) has a bandwidth-bound merge that has to be
worker-capped. Expected combined saving on memory-7m: roughly 116 ms of
serial work reduced to roughly 22 ms, i.e. about -94 ms on an ~880 ms
`base_trace_build`, or ~1.12x. That is above the 1.10x stage bar but not by
much, and the prove-level effect (~-94 ms on ~6.3 s) is ~1.015x, below the
1.02x prove bar. Measured numbers below.

## 2. What was built

Three parallel counting passes and one shared helper, in four functional
commits plus one correction.

| Commit | Change |
| --- | --- |
| `dd32f365` | audit record |
| `54269062` | compact tuple counting on the pool |
| `ca930644` | small-value range checks on the pool |
| `4c38115d` | shared `pool_split` row-split helpers |
| `b7b1b63b` | memory multiplicity scatter on the pool |
| `0e70389f` | worker 0 owns the live range-check columns |

Each was byte-parity spot-checked before commit.

### Reasoning that shaped the design

**The compact pass was obvious once the shape was known.** 7.37M probes, 247
unique tuples. A private table per worker is 247 entries; the merge is free.
The only question was correctness of the emitted order, and the `ConflictingKey`
check turns out to be exactly the property needed: it guarantees the sort
comparator is tie-free, which makes the sorted output a function of the *set*
of tuples rather than of the order they were inserted.

**The range-check pass needed the relation-index observation.** The obvious
parallelization is row-split with a private copy of the whole `range_check_9_9`
table, which is `multiplicity_columns x 2^18` words. But the small loop's
relation index *is* the limb-pair index, so a worker only ever writes four
relation columns and the private copy shrinks to `4 x 2^18` = 4 MB.

**The memory scatter had no such structure**, and that is what made it the
weakest of the three. Any producer and any feed can hit any address slot. I
tried the two exact options in order:

1. Private tables. 27.8 MB per worker. Phase-timed at 13.3 ms scatter +
   2.6 ms merge with 7 workers, against ~30 ms serial.
2. Relaxed atomic increments, no copies at all. Order-independent, fail-closed
   on overflow via the previous-value return. Measured **57.4 ms** for
   `base_memory_tables` against 38.1 ms for option 1 and 47.5 ms serial.

Option 2 losing to option 1 was the session's biggest surprise. 30.9M scattered
`ldadd`s over a 24 MB table cost more than 166 MB of private-copy traffic. Kept
option 1.

The budget sweep then showed the scatter is flat from three workers to seven:

```
budget  workers  scatter_ms  merge_ms  base_memory_tables_ms
 32MiB        1         --        --                 51.418
 64MiB        2     16.707     3.256                 44.831
 96MiB        3     12.999     2.510                 38.133
128MiB        4     12.784     3.001                 38.753
192MiB        7     13.188     3.084                 38.700
```

That is the same bandwidth wall increment 7 found in the witness executor, seen
from a different pass. Shipped budget 96 MiB.

**The one-worker case bit back.** The first range-check implementation gave a
private histogram to every worker including the only worker, so a null pool or
a too-small row supply paid a 4 MB allocation, zeroing and merge for nothing.
all-opcodes caught it: `base_fixed_multiplicities` 5.646 ms predecessor against
6.520 ms candidate over six paired samples, a clean 0.87 ms regression on a
5 ms pass. Fixed at `0e70389f` by letting worker 0 own the live columns, which
also makes the serial fallback allocation-free rather than merely correct.

## 3. Paired measurement, per-sample

Harness: A-B-B-A cold processes, `--verify` on every run, one untimed warmup
per arm per workload, uninstrumented binaries, predecessor the pristine
`zig-out` tree from `c8e29225` copied whole to `/private/tmp/campaign-inc8-pred`,
cwd the worktree root. `prove` is `timing.prove_ns` from the report; the stage
columns are summed `seconds` from the stage profile.

### memory-7m, six blocks, quiet window (candidate at `b7b1b63b`)

```
# block 1 load 7.84 / block 2 load 14.84 / block 3 load 12.91
pred b1-1  prove=6302.122  btb=951.012   vi=40.369  bfm=47.385  bmt=51.193
cand b1-1  prove=6290.537  btb=863.443   vi=6.955   bfm=8.287   bmt=40.606
cand b1-2  prove=6445.670  btb=871.459   vi=7.387   bfm=8.679   bmt=42.447
pred b1-2  prove=6985.168  btb=958.839   vi=41.143  bfm=45.363  bmt=52.225
pred b2-1  prove=6977.554  btb=1060.554  vi=44.370  bfm=51.119  bmt=53.222
cand b2-1  prove=6639.762  btb=943.571   vi=7.655   bfm=9.031   bmt=45.332
cand b2-2  prove=6616.352  btb=897.714   vi=7.443   bfm=8.593   bmt=44.446
pred b2-2  prove=6308.468  btb=988.383   vi=40.513  bfm=47.825  bmt=55.154
pred b3-1  prove=6246.803  btb=884.873   vi=38.805  bfm=47.767  bmt=52.167
cand b3-1  prove=6714.325  btb=934.357   vi=7.833   bfm=9.133   bmt=43.575
cand b3-2  prove=6667.649  btb=917.806   vi=7.427   bfm=8.888   bmt=43.818
pred b3-2  prove=6814.671  btb=1034.072  vi=45.440  bfm=49.016  bmt=56.029
# block 4 load 11.45 / block 5 load 10.59 / block 6 load 12.95
pred b4-1  prove=6488.473  btb=957.868   vi=40.996  bfm=47.036  bmt=53.569
cand b4-1  prove=6474.636  btb=902.281   vi=7.510   bfm=9.714   bmt=43.289
cand b4-2  prove=6050.007  btb=834.170   vi=5.229   bfm=7.843   bmt=41.473
pred b4-2  prove=6583.578  btb=994.599   vi=43.357  bfm=51.102  bmt=56.005
pred b5-1  prove=6191.123  btb=915.105   vi=40.544  bfm=47.806  bmt=52.833
cand b5-1  prove=6137.998  btb=861.336   vi=5.631   bfm=8.485   bmt=41.733
cand b5-2  prove=6808.313  btb=892.697   vi=7.649   bfm=8.786   bmt=44.036
pred b5-2  prove=6785.718  btb=1035.692  vi=43.666  bfm=51.592  bmt=52.264
pred b6-1  prove=6749.754  btb=999.360   vi=46.989  bfm=58.116  bmt=54.565
cand b6-1  prove=6635.896  btb=903.337   vi=8.080   bfm=9.028   bmt=42.886
cand b6-2  prove=6597.559  btb=902.868   vi=7.249   bfm=8.667   bmt=42.569
pred b6-2  prove=6747.908  btb=984.499   vi=41.953  bfm=48.504  bmt=53.516
```

Every one of the 24 samples produced `e3317e55a5db5a4251e04827b3d4f2ccaeb801feb6a9d2848e71ef23daced994`.

Per-block `base_trace_build` ratios: 1.1008, 1.1128, **1.0361**, 1.1244,
1.1122, 1.0984. Pooled 1.0970, ranges overlapping (pred min 884.873, cand max
943.571). Block 3 is the outlier and it is the block where `pred b3-1` came in
at 884.873 — the fastest predecessor sample of the session — before load rose
through the rest of the block.

Pooled prove 6,598.445 vs 6,506.559 = 1.0141. Per block: 1.0433, 1.0023,
0.9760, 1.0437, 1.0024, 1.0200.

### arithmetic-2m, three blocks, quiet window

```
pred b1-1  prove=2705.887  btb=307.479  vi=10.713  bfm=12.359  bmt=23.511
cand b1-1  prove=2630.640  btb=277.335  vi=2.256   bfm=6.755   bmt=18.161
cand b1-2  prove=2747.305  btb=289.889  vi=2.166   bfm=6.544   bmt=16.823
pred b1-2  prove=2752.677  btb=307.927  vi=14.418  bfm=12.595  bmt=26.370
pred b2-1  prove=2754.244  btb=308.883  vi=14.601  bfm=12.979  bmt=25.923
cand b2-1  prove=2732.414  btb=288.064  vi=2.268   bfm=6.918   bmt=18.290
cand b2-2  prove=2749.708  btb=291.830  vi=2.279   bfm=7.006   bmt=18.011
pred b2-2  prove=2816.311  btb=313.216  vi=11.617  bfm=13.743  bmt=24.636
pred b3-1  prove=2806.978  btb=318.245  vi=11.845  bfm=13.784  bmt=24.204
cand b3-1  prove=2776.372  btb=291.869  vi=2.217   bfm=6.861   bmt=18.297
cand b3-2  prove=2764.941  btb=287.820  vi=2.650   bfm=6.945   bmt=19.444
pred b3-2  prove=2821.167  btb=310.159  vi=11.530  bfm=12.215  bmt=26.008
```

All 12 samples `25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6`.
`base_trace_build` block ratios 1.0849, 1.0728, 1.0840; pooled **1.0806 with
disjoint ranges** (pred min 307.479 > cand max 291.869). Prove pooled 1.0156.

### all-opcodes, three blocks, shipped candidate (`0e70389f`)

```
pred b1-1  prove=1470.171  btb=17.797  vi=0.456  bfm=5.397  bmt=0.048
cand b1-1  prove=1473.239  btb=18.244  vi=0.458  bfm=5.622  bmt=0.056
cand b1-2  prove=1425.923  btb=18.241  vi=0.446  bfm=5.700  bmt=0.048
pred b1-2  prove=1424.701  btb=17.851  vi=0.414  bfm=5.283  bmt=0.051
pred b2-1  prove=1427.051  btb=17.745  vi=0.402  bfm=5.402  bmt=0.044
cand b2-1  prove=1501.266  btb=19.183  vi=0.460  bfm=5.947  bmt=0.051
cand b2-2  prove=1490.688  btb=18.057  vi=0.457  bfm=5.373  bmt=0.050
pred b2-2  prove=1507.943  btb=18.592  vi=0.446  bfm=5.612  bmt=0.048
pred b3-1  prove=1497.903  btb=18.708  vi=0.426  bfm=5.704  bmt=0.051
cand b3-1  prove=1351.665  btb=18.282  vi=0.482  bfm=5.552  bmt=0.053
cand b3-2  prove=1358.848  btb=18.446  vi=0.430  bfm=5.578  bmt=0.050
pred b3-2  prove=1393.736  btb=18.783  vi=0.418  bfm=5.640  bmt=0.048
```

All 12 samples `79ae76e1ac0c48b1e3b06810ddb1fed8aabe5dfb10d028e879105b79716cb310`.
`base_trace_build` 18.246 vs 18.409 (0.991x), `bfm` 5.506 vs 5.629 (0.978x),
prove 1,453.584 vs 1,433.605 (1.014x). Every observable overlaps. The prior
block on the pre-fix candidate had `bfm` at 5.646 vs 6.520 (0.866x) — the
regression the one-worker fix removed.

### Blocks on the shipped candidate under heavy load

Three further blocks per large workload were taken after `0e70389f` at load
average 24-36, with an unrelated process on the host inflating absolute times
about 1.8x. Reported for completeness, not as the measurement of record.

```
memory-7m   btb pred [1614.188,1785.473] mean 1697.648
            btb cand [1370.205,1761.817] mean 1514.749   ratio 1.1207
            block ratios 1.0637 / 1.1131 / 1.1964
            vi   63.681 -> 13.225   bfm 74.405 -> 13.820   bmt 77.381 -> 65.395
arithmetic  btb pred [ 373.421, 402.211] mean  389.749
            btb cand [ 355.703, 375.450] mean  362.248    ratio 1.0759
            block ratios 1.0930 / 1.0610 / 1.0741
            vi   13.457 ->  2.788   bfm 15.483 ->  8.713   bmt 28.920 -> 23.274
```

### The arithmetic that makes the result credible

| Workload | span delta ms | `base_trace_build` delta ms |
| --- | ---: | ---: |
| arithmetic-2m | 50.509 - 27.315 = **23.19** | 310.985 - 287.801 = **23.18** |
| memory-7m | 145.293 - 58.949 = **86.34** | 980.405 - 893.753 = **86.65** |

The stage moves by exactly what the three targeted spans give up. Nothing else
in `base_trace_build` moved, which is what a correct row-split of three
counting passes should look like.

## 4. Verdict reasoning

Bars: `base_trace_build` >= 1.10x with disjoint ranges across >= 3 paired
blocks, **or** prove >= 1.02x with non-overlapping paired CI.

- memory-7m stage: 1.0970 pooled, five of six blocks above 1.10x, ranges
  overlap. **Straddles.**
- arithmetic-2m stage: 1.0806 pooled with disjoint ranges. Below the bar but
  unambiguously real.
- prove: 1.0141 and 1.0156. **Below.**
- mechanism: 5.9x / 5.6x / 1.25x with disjoint ranges on every large workload.
  **Confirmed beyond doubt.**

The ceiling was arithmetic and known in advance: ~145 ms of a ~980 ms stage,
with ~59 ms of it irreducible because the memory scatter is bandwidth-bound.
1.097x is close to this lever's maximum, and the gap to the bar is 3 ms of
stage time against a 60 ms run-to-run spread. Not self-accepted, not
self-rejected: **undecided-borderline**, implementation preserved.

## 5. Verification, final tree `17c3893b`

- Digests, every arm of every paired block: memory-7m `e3317e55…`,
  arithmetic-2m `25e5719f…`, all-opcodes `79ae76e1…`. All equal the campaign
  values. Every run used `--verify` and self-verified.
- `STWO_ZIG_WORKERS=1` on arithmetic-2m: proves and self-verifies at
  `25e5719f…`. Increment 7's serial composition fix still holds. Note that all
  three new serial fallbacks are `worker_count == 1` degenerations of the same
  parallel code, not separate paths, so there is no second implementation to
  drift.
- `zig build test-cairo-cpu-product test-cairo-frontend -Doptimize=ReleaseFast`
  passes. `stwo-cairo-cpu closure: PASS` over 330 transitive Zig sources,
  identity `dirty: false`. Source conformance: 5 explained legacy findings, no
  new violations (also enforced by the pre-commit hook on every commit).
- Official Rust verifier on the candidate arithmetic-2m proof:
  `{"verified":true, "channel":"blake2s",
  "stwo_cairo_revision":"82f21252a68ec006d73e299f5bf1ce6d4db0ee78",
  "proof_sha256":"25e5719f4c578eb7ef10d76d6033e65f0a4a9d981c2414c3f7ac1950966deea6"}`.
- Metal arithmetic-2m, pinned AOT bundle: proof `25e5719f…`,
  `accelerated_without_fallbacks`, 74 dispatches, `cpu_fallbacks: 0`.
  The metal product needs `-Dmetal-core-aot-bundle=...` on the build line or
  `zig build stwo-cairo-metal` reports success without reinstalling the binary;
  the installed one was three commits stale until the flag was passed. Worth
  knowing for later sessions: always check `identity`'s `source.commit` before
  trusting a Metal parity run.
- Pre-existing, unchanged, not chased: `merkle-worker-stress` `blake_deep`
  `InvalidNRounds`; stale untracked
  `vectors/reports/merkle_worker_stress_artifacts/`; corpus `pedersen.json`
  `SegmentPointerOverflow` in the adapter.

### Host load

Every block records `uptime`. The session ran at load average 4.7-15 for the
measurement of record and 24-36 for the later confirmatory blocks. Note that
the prover itself is an 18-thread process, so a load average near 12-15 during
a block is largely self-inflicted and is the normal state for these runs; the
24-36 window was an unrelated process and is flagged as such. A-B-B-A adjacency
is the only defence applied, which is why only ratios are read.
