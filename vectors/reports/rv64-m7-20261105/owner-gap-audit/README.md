# Accepted D2 headline callback-gap audit [D]

**Prioritize off-owner CPU assignment retirement and bounded class/workspace reuse.** The accepted trace does not support attributing the callback gap to host Fiat–Shamir alone. Device FS remains a prerequisite for longer GPU pipelines, not a measured 2-second saving here. Whole RC/PCS graphs alone do not cover the largest measured gaps.

This is a read-only derivation from the existing accepted D2/coalesced block24628607 warm capture: driver9cf6589f, imagea25cc3b2, source9531c5c16. No GPU job, new proof, build, limit change or wall A/B was run. `api-census.json` preserves the original ownership/API rows and provenance; `interval-partition.json` partitions actual same-device activity inside outermost owner ranges. The reproducer is `scripts/rv64_m7_owner_gap.py`.

The after-native request window is 5.926329 s with 6.204127 kernel GPU-s over two GPUs and19 nodes. Outermost owner ranges sum to9.843365 host-thread seconds; this is **not request wall time**. The following categories are mutually exclusive interval unions, separately on each physical device and its owner thread:

| Exclusive owner interval | Thread/device seconds [D] |
|---|---:|
| Actual kernels active |6.204127488|
| Copy or memset active without kernels |1.094630166|
| Blocking CUDA API while neither kernels nor copies/sets are active |0.052292675|
| Other traced runtime/driver API while GPU otherwise idle |0.620736505|
| Untraced host interval while GPU otherwise idle |1.871578197|
| Owner total |9.843365031|

Untraced host time includes CPU computation, allocation/free, lock waits, scheduling and untraced APIs. It cannot be called pure CPU computation without further CPU-stack attribution. Copies are actual device activity, not inferred from host memcpy durations. This partition removes overlap before summation; its kernel total exactly recovers the published6.204127488 GPU-s.

| Exclusive source stage | Owner s [D] | Kernels s [D] | Copy/set only s [D] | Other runtime while idle s [D] | Untraced host while idle s [D] |
|---|---:|---:|---:|---:|---:|
| Unmarked owner intervals |1.712762|0|0.372968|0.020091|1.317175|
| MAIN assignment |1.958917|1.215330|0.308890|0.277561|0.151832|
| RC |1.636604|1.221270|0.105433|0.215963|0.085897|
| PCS |2.013061|1.774634|0.061666|0.032698|0.124236|
| TC FIXED |0.286890|0.122178|0.048228|0.006143|0.107268|
| TC MAIN |0.548435|0.411546|0.072234|0.012638|0.048336|
| TC INTER |0.963981|0.767011|0.115260|0.042028|0.035257|
| INTER witness |0.722716|0.692159|0.009953|0.013614|0.001578|

The omitted per-stage blocking-API/no-GPU column totals0.052293 s and is retained in JSON. Rows do not overlap; smaller PCS NVTX subranges remain inclusive in the API census and must not be added to their parent.

## Actual synchronization and source boundaries

Across the19 nodes there are916 `cudaEventSynchronize` and1,078 `cudaStreamSynchronize` calls: **104.95 calls/node [D]**, not a count of transcript draws. Their aggregate host durations4.276821+1.923560=6.200381 thread-seconds largely overlap actual device work. Eliminating calls does not eliminate the work being waited for.

CPCS alone has700 event synchronizations and76 stream synchronizations (40.84/node). Of those,681 event calls belong to final readback/encoding and together take only0.002599 s. Its substantial waits are queued DEEP work at retirement (0.684668 s) and opening work (1.048853 s). The selected `pcs_pipeline.cuh` already runs sampled-value absorption, DEEP alpha, all FRI challenges, PoW and query draws on GPU. Three explicit sync sites are supplemented by joined `retirePlanes` transitions and owner reset/cleanup; counting channel callsites cannot establish selected-runtime synchronization counts.

The unchanged CPU prefix has four OM31 draws: z, lookup alpha, composition alpha and OODS seed. They return host values; the draw itself does not perform a device readback. Existing TC root and claim readbacks create the actual data boundaries. INTER already returns all11 claims plus status in one89-word readback. RC enqueue mode skips per-role joins. The105/node observed API count therefore cannot be charged to four host draws.

## Largest concrete gaps and next targets

The largest unmarked controller interval is **0.657228 s [D] after MAIN-assignment ends and before TC MAIN begins**, with no kernel/copy/runtime API activity. Source `outer_source.zig` performs joined generation, `owner.retireAssignment()`, then TC commit. Assignment retirement destroys CPU plans/decoded tasks and uses host allocation/locking machinery. This is a source-bounded retirement/commit-entry interval; the trace cannot separate allocator time from lock waits or scheduling. A bounded ownership transfer that lets a host worker retire this already-joined CPU assignment while the GPU proceeds is a concrete next architectural target. It must keep all source/template/cache references valid and charge retained host memory; moving the free later on the same owner thread would only relocate the gap.

Other unmarked controller intervals are0.011403 s TC MAIN→INTER witness (channel begin/root mixes and z/alpha included),0.002165 s TC INTER→RC (lookup closure/binding included),0.166924 s RC→PCS (OODS point/masks and export included), and0.211704 s PCS→controller end (CPU OODS checking/assembly included). They are aggregate thread seconds and source envelopes, not individual function timings. Standalone unmarked callbacks add0.624749 s, including0.362784 s actual copies and0.245171 s untraced host intervals; these cover fixed ingress/adoption and cleanup boundaries.

MAIN assignment includes14 graph instantiations taking0.217969 s in this warm request. Its existing graph replay still rebuilds these leaf-class graphs. Source-pinned topology reuse with complete pointer/lease refresh is a measurable target; it requires the existing graph custody gates and a bounded cache. RC's runtime time includes `cuMemSetAccess`0.108181 s and `cuMemUnmap`0.065098 s. A static per-class physical plan with liveness-based mapping reuse can address those costs while preserving the arena cap; merely adding a graph does not remove VMM churn.

**GO:** qualify off-owner CPU retirement, bounded immutable topology reuse, and static RC/TC workspace planning, then measure with the same ownership tool. Continue device-FS parity/real-consumer work as an enabling boundary. **NO-GO:** claim that host FS alone explains3.64 thread-seconds, promise the whole gap from RC/PCS graph capture, treat tiny already-completed event calls as equivalent to long data-dependent waits, or enable two lanes before the exact28GB whole-process gate.
