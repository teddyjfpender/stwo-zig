# M7 per-request critical path and GPU seconds [M]

One profiler capture of already-qualified v3 driver197b/image148c, block24628607 cold+warm. No A/B or further tuning. All figures below are observations with profiler overhead; fresh acceptance and full M6 byte parity belong to the previously qualified identical binary/format.

| Exclusive request stage | Cold wall s | Warm wall s | Cold kernel GPU-s | Warm kernel GPU-s |
|---|---:|---:|---:|---:|
| Capture |2.004|2.039|0|0|
| Native setup |11.913|0.137|included below|included below|
| Native proof |5.467|4.653|3.984|3.991|
| After-native recursion/publication |18.871|10.430|10.036|10.049|
| Cleanup/audit |0.037|0.041|0|0|
| Request total |38.292|17.301|14.019|14.040|

GPU-seconds are the interval union of actual CUDA kernels separately per physical GPU, then summed. Native setup's kernels, if any, are included in native GPU-seconds, so that column spans setup+proof. Native/recursion split uses reported native-stage end with a5ms unassigned band; no kernels landed in that band. Warm device0kernel-active7.272s and device1active6.768s;14.040/(2×17.301)=40.6% kernel active over the request. These are not SM occupancy. Copies and host work are not kernels.

Native CPU verification2.496s WARM (2.364s COLD) overlaps recursion and is not added to the exclusive table. Recursion pipeline itself overlaps native production; its12.734s warm DAG wall must not be added to native4.653s.

A service dependency path through node readiness AND per-lane serialization partitions warm pipeline12.734s: device-owner callback wall9.452s, host prep1.287s, native-ready/host-queue gap1.526s, host finish/verify/publish0.377s, other queues0.092s. The final2.710s occur after the last leaf finishes. Across all workers, prep consumes10.967thread-wall-seconds and finish3.102thread-wall-seconds; those overlap and are not request seconds.

Recursion lane0 spends9.452s inside callbacks but only5.691kernel seconds; lane1spends7.557s vs4.358kernel seconds. The remaining6.960summed callback-seconds include transfers, synchronization, host/transcript work and enqueue gaps. They cannot all be called CPU overhead. Inner TC/RC/PCS ownership remains unassigned because this binary emitted no NVTX ranges despite capture being enabled. Next runtime admission endpoints will mark owned stages and expose actual arena snapshots; no additional wall-only A/B is needed.

Raw acknowledgements plus recorded client latency recover request windows; their CUDA launch counts exactly match the harness's original UTC-window census82473/82460. The extractor preserves that check and the5ms phase uncertainty band. Source attestation: external producer binary197b was built from a365plus the two qualified v3 overrides; helper is96a99plus NVTX trace selection. Raw helper `source_commit:null` is retained. Full numerical receipt, script and SQLite hash are in vectors/reports/rv64-m7-20261105/admission/ownership.json.
