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
