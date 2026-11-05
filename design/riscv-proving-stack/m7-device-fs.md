# M7 owner controller and device transcript

The initial checkpoint adds opt-in `STWO_RV64_NVTX=1` owner and PCS phase ranges. It changes no numerical operation or ordering. The matched128 image builds and preserves the qualified fused-Blake object. Full producer artifact parity and profiler attribution are pending; this is observational instrumentation, not a latency improvement or completed stream.

Image: `/workspace/m3/build/m7-device-fs/cuda/native/libstwo-rv64-native.so`, SHA256 `05eedd9d4fc14f108ae14c7d57dcbb88faec3cba101503aebfcf48e9eda0b08a`. Its build manifest records the baseline, all object hashes, source hashes and exact commands. Raw owner ranges include the unconditional post-callback join. Nested PCS ranges cover metadata/allocation, source LDE and trees, sample evaluation, DEEP, retirement, FRI, proof of work, openings, and final readback/encoding.

The existing C PCS path already performs sampled-values, DEEP, FRI, PoW and query transcript feedback on GPU. The remaining outer controller performs MAIN-root challenge generation, INTER claims/root binding, composition challenges, and OODS setup across host-visible stage boundaries. The next controller checkpoint retains the complete proof's graph, authority, preparation, source and buffer owners in one native owner job; it must preserve TLS hints, error custody and all final readbacks before any enqueue-only path can be qualified.

The first whole-owner controller candidate has an additive synchronous C entry. Nested same-owner callbacks and native PCS execute inline only during that explicit job; ordinary submissions continue to reject owner reentrancy. Its host wrapper retains all proof inputs until terminal return and transfers class/leaf/tape/Blake TLS. The current source is based on the older hard `native_done` barrier: **controller plus early native overlap is not qualified**. The follow-up transfers scoped work-pool TLS for the complete owner job. `Factory.requires_native_complete` declares the scheduling restriction; admission-enabled endpoints are refused before acquiring the owner-call lock.

The actual GPU custody fixture passes 12 cases, including fresh readback, stale lease rejection, ordinary reentrancy rejection and failed-controller destruction. The freshly built driver `e93af189...` and image `116a3658...` were frozen for one ON/OFF capture pair. Both daemons failed the same native 32 MiB allocation with 25,652,139,944 retained lease bytes in a 27,279,753,216-byte automatic arena. ON completed only the small cold request; OFF completed small cold, headline cold and small warm. Every completed native, bundle and recursive artifact matches M6. The ON small proof was accepted by the fresh CPU receiver in 35.946 s. These partial captures do not qualify a two-block resident service or a latency improvement.

An inherited hardlinked Zig cache initially returned an older executable despite a successful build command. Its unchanged hash and absent controller environment string caught this before any full proof. The executable was rebuilt from a clean local cache and its feature string/source hashes checked. Receipts preserve the actual frozen assets and negative capacity result. Further identical OOM profiling is stopped.


The isolated follow-up qualifies controller correctness for both development blocks with a fresh resident service per block/configuration: **8/8 requests match every M6 native, bundle, recursive tree and node artifact**. Both controller-ON cold proofs pass the fresh CPU-only receiver (small 35.044 s; headline 49.740 s). The exact assets are driver `76b2a5ca7deea679c3df498c50637c985aeed046ca9135e4f7d0cc86bd1cb2f4` and image `116a3658ed4aecb1dff18d56e4a3be62d651411dc845da018a8362830a7590aa`; ON and OFF use the same frozen assets and full v3 preset. Receipts and companion M6 comparisons are under `vectors/reports/rv64-m7-20261105/device-fs/isolated/`.

| Measured warm request | Controller ON total / recursion | Same-assets OFF total / recursion |
| --- | --- | --- |
| 26235156 | 11.819 s / 6.566 s | 12.673 s / 7.597 s |
| 24628607 | 17.302 s / 9.902 s | 17.781 s / 10.491 s |

These are single loaded observations, not a robust latency improvement. Profiling attribution remains separate from inclusive host waits. The previous mixed-block capacity failure remains open; isolated correctness does not qualify cross-block service capacity, early native overlap, enqueue-only proof completion, or complete device-side Fiat–Shamir.
