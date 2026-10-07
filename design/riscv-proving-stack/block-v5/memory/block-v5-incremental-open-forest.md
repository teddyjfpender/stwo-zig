# Incremental exact open forest

`prover/block_v5_open_forest_stage_v1.zig` exposes a producer-owned `Stream`:

```zig
const stream = try OpenStage.Stream.start(a, dir, public_pins, options);
errdefer stream.abort();
// After each native recursive leaf file is durably published:
try stream.submit(index, .{ .policy = independent_leaf_policy, .file = file_pin });
// After the complete exact leaf roster has been submitted:
var staged = try stream.finish();
defer staged.deinit();
```

The common B5SS seal, exact execution count and public endpoints must already
be admitted before starting the stream. The caller retains immutable native
prepared policy through `finish` or `abort`. The stream copies recursive public
schedules and owns normalized child metadata; it retains no execution trace or
native proof capture. `finish` consumes the stream on success. On error it remains
abortable. `abort` always joins lane threads before releasing metadata or pools.
The compatibility `prove(all_leaves)` entrypoint delegates to the same path.

Submission checks native and recursive PCS security, key identity and public
schedule, common job/source/seal, exact ordinal and public PC/clock endpoints,
adjacent published spans, and bounded file length/SHA. It freshly verifies the
recursive leaf equation before the queue publication barrier. The queue waits
for unpublished leaf edges and completed parent edges, rather than treating a
partially published roster as a stalled DAG. Ready pairs/quartets can therefore
finish while later native leaves or independent global providers are still being
proved. All files, parent slots and final exact root order follow the existing
canonical mixed-radix DAG; no padding or changed proof encoding is introduced.

Each dedicated lane owns its scoped work pool and an exclusive OpenV2 setup
cache. `setup_cache_entries_per_lane` defaults to one; both entry count and idle
scratch retention are explicit options. Cache hits require the full Context,
exact profile/config, byte-for-byte public routing schedule, and every AIR's
fixed-row fingerprint and geometry to match. Every hit constructs and rebinds
the new dynamic admission even when the immutable key ID is identical. Owned
child metadata avoids retaining a previous lane stack slice. Misses evict before
constructing replacement setup, and retained fixed commitments/workspace are
reused on hits. Cold misses still derive the key before `Plan.init`; that path
currently commits fixed data twice.

All stage heap work, cache entries, fixed commitments, retained scratch, proof
transport and metadata use the same synchronized aggregate allocator. Passing
the producer's budget allocator as `a` also charges concurrent base/recursive
work to the producer's aggregate limit. `total_host_limit` is a tracked heap
limit, not process RSS: caller-owned immutable native policy, budget control
objects and explicitly bounded thread stacks are outside the stage snapshot.
`setup_cache_stats` reports hits/misses/evictions; `stage_owned_peak_bytes`
includes setup retention and concurrent lanes. These counters provide no speedup
claim without an actual workload measurement.

The result remains a provisional open forest. Complete reception must still
derive native exports from fresh base proofs, independently admit all recursive
keys/schedules, verify exact detached transport, and close every global relation.
Neither queue completion nor an authenticated file hash supplies that authority.

Focused source tests cover unpublished odd tails, nested dependencies, out-of-
order leaf arrival, duplicate/missing publications, abort and metadata caps. An
eight-real-native-leaf q8 fixture is prepared to require an early genuine fold,
same-key setup reuse with changed public inputs, strict file/key rejection and
fresh detached exact verification. This revision is awaiting the exclusive build
lane; these new tests have not yet been run.
