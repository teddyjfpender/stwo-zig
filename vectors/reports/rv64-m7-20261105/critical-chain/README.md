# R2: accepted D2 headline, nineteen-node critical-chain audit

**Status: measured existing schedule + source audit; no new GPU/proof run.** This is warm trial1 of `daemon-24628607-r2-combined-d2-coalesce-v1`, native D2/coalesced14leaves, nineteen recursive nodes, two lanes **total (one per physical GPU)**. Driver9cf6589f1b479f4c6b1049cc98860c55bfbb2fa680e4716ffd976748f782a2f6, CUDAa25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45. The receipt directly fresh-verifies cold trial0 with isolated ddcb CPU receiver. Read-only hashing establishes **all38 native/stage/bundle/tree/recursive-proof artifacts byte-identical cold↔warm**, closing the profiled warm artifacts to that accepted pair. No new receiver claim is made.

`table.md` contains **all19 rows**; `table.json` retains full timestamps, tree authority/digest hashes, class log prefix, exact controller NVTX intervals and phase partitions. Full class hash, device scope hash, host-worker ID and memory readiness were not logged and remain null. A truncated class prefix is never treated as a full source identity. Original `pipeline.json`, `tree.json`, receipt and cold/warm fingerprints are retained. Existing SQLite is read-only and SHA-bound by the reproducer; it is not copied into git.

## Decision and actual last-known chain

The root's last child is **fold14**, whose last child is **leaf13**. Fold14 prep finishes at6.475488s after lane0 predecessor16 releases at6.461254s, so prep is its last known device gate. Root18's child14 finishes7.340079s, later than child17 at7.225385s. These are direct same-clock comparisons, not sums of thread seconds.

Walking backward through the latest observed **known** predecessor gives:

`root18 finish ← root18 device ← root18 prep ← fold14 finish ← fold14 device ← fold14 prep ← leaf13 finish ← leaf13 device ← leaf12 device ← leaf10 device ← fold4 device ← leaf5 device ← leaf2 device ← leaf1 device`.

Before the first devices, native completion is a mandatory barrier because global admission was inactive. Its exact pipeline timestamp is unavailable (clock issue below). The known-edge walk then reaches leaf1 prep, but this **does not establish prep as the actual initial gating event**; native completion is an omitted external predecessor. The proof DAG alone is insufficient: lane resource edges make nodes2,5,4,10,12 part of this observed serialization chain even when they are not direct ancestors of leaf13.

Warm DAG wall8.290759044s, root node finish8.289065250s, last leaf finish6.573262973s, reported post-leaf tail1.717496071s. An additional17.414366ms `root_publication_ns` follows the DAG: source includes final fresh root verification, serialization/publication and tree/report/scheduler emission, not merely disk write. The concurrent root metadata check is679.228749ms but its absolute start/end are unlogged; the selected source starts it when native completes and joins before final verification. No critical-path charge is inferred from duration alone.

The next high-value target is **on-chain assignment/commit transition and fold14/root18 prep/device work**, measured as actual wall edges. Existing async finishing already overlaps the next device node on both lanes. A second async-finish architecture is not supported by this trace.

## Timing semantics and missing data

`Pipelined.now()` returns `Streaming.timer.read() - origin_ns`. `Streaming.open()` and `nativeDone()` instead store raw `Streaming.timer.read()`. The emitter serializes both without `origin_ns`. Therefore stream ready timestamps **cannot be directly compared** with node stamps: leaf0 reports native-ready1.054783220s but is taken at0.794407697s; native-done2.658293252s is numerically later than first devices2.397939529/2.397948719s. This is a clock-origin omission, not evidence of unauthorized early dispatch.

`device_wait_for_native_ns=2.397950909s` is measured by the coordinator **after it wakes**, not the exact publication instant. It is an upper-bound observation of the barrier. It can follow a device worker's first start by microseconds. Do not substitute it as an exact predecessor timestamp.

The nineteen controller NVTX ranges map uniquely to node device sequences by owner-thread order/count(9/10) and a common containment offset. Both lanes constrain Nsight minus pipeline offset to43.311836750–43.338542519s. This is an **interval**, not an exact cross-clock calibration. Controller partitions below are exact in the Nsight clock and do not require picking a midpoint.

Host scheduler semantics from `execution_wrap.zig` and `ready_dag.zig`:

- A leaf becomes *input available* after native proof publication and receiver-frame derivation; host admission additionally requires streaming-prep share, prep-ahead and authority-slot bounds. Default m5 leaf admission is lowest ordinal: a closed earlier leaf can hold already-open later leaves. Own native-ready time alone is not host-ready time.
- A fold can be taken only once every child is done. Done means CPU finish/verification **and durable publication** succeeded, followed by `completeLocked`; device-end is insufficient.
- Host workers prioritize finishing before prep. Their IDs and occupied intervals are not serialized. `taken` is the actual queue admission observation, not the time all hidden gates became ready.
- A device job needs prep complete, native barrier open, a free lane, and leaf-size-class admission. m5 selects widest ready parent then lowest id. `ready` insertion happens after prep returns and mutex reacquisition; prep-end is a lower bound on queue availability, not its exact insertion instant.
- A lane returns after proveDevice plus HostPrep cleanup; `device_end` is that release. CPU finish runs on the host pool. The records show next same-lane device starts before the previous finish ends. The DAG node completes only after finish/publication.
- Memory admission was false, and no per-node memory-ready timestamp exists. All rows explicitly say **UNKNOWN**, not zero or automatically ready. One lane/physicalGPU removes same-device leaf competition in this run but does not establish globally complete physical admission.

## Slack formula and limits

Three vertices per node represent fixed observed prep/device/finish durations. Known precedence edges are prep→device→finish, child-finish→parent-prep, and preceding same-lane-device→next-device. Deadline is observed root-node finish. Reverse topological pass:

`latest_start(v) = min(latest_start(successor)) - observed_duration(v)`;

`slack_upper(v) = latest_start(v) - observed_start(v)`.

Every edge and all nonnegative slack assertions are checked by the script. This is a **known-edge delay-slack upper bound**, not an attainable reschedule or speedup prediction. Unknown host-worker contention, authority-slot readiness, native clock origin and memory gating could reduce it. Source/machine contention can also change task durations after any optimization. The actual last-known-predecessor walk uses each stage's latest predecessor **observed end**, retaining intervening gaps rather than assigning them to an invented gate.

Device slack upper bounds: node1 8.312ms, node13 8.207ms, fold14 2.611ms, root18 0.020ms. Node15 has168.084ms, fold17 has117.316ms. This justifies concentrating diagnosis on the chain, not optimizing the largest off-chain thread aggregate.

## Exclusive owner spans, not additive waits

Each matched controller range is partitioned by interval unions, in this order: correlated own kernel time; copy/memset excluding kernel overlap; host runtime API excluding GPU overlap; untraced host excluding GPU and API. The four sum **exactly to each controller wall span**, including phase subpartitions. Blocking API wall is separately reported and **must not be added** to GPU time. Untraced host is a coverage class, not an identified allocator function or scheduler wait.

All19 controller spans sum6.081949454 kernel-seconds +0.683618383 copy-only-seconds +0.647019408 API-without-GPU-seconds +1.518759247 untraced-host-seconds. These are controller-only: FIXED precommit/authority and post-proof cleanup outside the range remain a coverage gap. They are not the full-device-stage partition, and totals across parallel nodes are not elapsed request savings.

For chain device nodes1,2,5,4,10,12,13,14,18 only, measured controller phase wall amounts are MAIN-assignment921.303ms, TCMAIN304.283ms, INTERwitness390.655ms, TCINTER532.070ms, RC834.961ms, PCS1084.287ms, unmarked controller556.378ms. These sequential owner intervals belong to the observed chain but remain diagnostic: speeding one can change which competing predecessor is critical. The source-bounded MAIN-assignment-end→TCMAIN-start gaps total370.508ms on these nodes, of which fold14 is49.587ms and root18 is50.175ms. The trace does not isolate allocator destruction from lock/scheduling in those gaps.

## Minimum instrumentation to close R2 uncertainty

A metadata-only future emitter can supply: pipeline origin in stream-clock units; physical device IDs per lane; exact native publication/barrier timestamps in that same clock; ready-queue insertion time; host-worker slot and prep/finish take times; logged gate observations for prep-ahead, authority slots, leaf admission and memory decisions; source-derived full class key plus proof scope identity at controller entry; node ordinal on NVTX precommit/controller/release ranges. Record final metadata-check start/end and final-root publication start/end separately. Missing memory state must remain unknown until the global admission runtime owns it.

No runtime edits, profiling rerun, two-lane/GPU experiment, cleanup/graph/VMM/PP tuning or proof-format change is part of this audit.
