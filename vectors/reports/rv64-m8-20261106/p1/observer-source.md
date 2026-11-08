# P1 allocator observer: frozen source, unbuilt and unmeasured

Frozen measured parent: `b68e02081`. This candidate adds diagnostics only. No allocation lifetime, footprint, admission bound, proof/security parameter or transcript policy changes.

Enable `STWO_RV64_ALLOCATION_OBSERVER=1` for the first single-lane diagnostic. Stage boundaries and cache-idle transitions host-join the owner lanes, so request walls are **not latency results**. No build or GPU job was launched by this engineer.

`GPU_NODE_ALLOC_STAGE` contains exact requested reservation and arena-rounded host allocator lifetime peaks, active request peaks, separate large/small maxima, pending-fence bounds and shared/backing snapshots. Whole oversized PCS cache reservations follow the current node on reuse; joined idle transitions classify them as shared cache. Birth attribution survives MAIN root rebind. Provisional FIXED setup remains separate shared setup with an authenticated link to the final node and requested coefficient alias bytes.

Use `rounded_reservation_peak_bytes` as the concurrent rounded total. Do not add independent large/small maxima or requested/pending maxima. `rounded_including_pending_upper_peak_bytes` is a conservative bound that can double count overlapping reused ranges or fences not yet queried. It does not certify GPU-completion residency. `cudaMemGetInfo`, mapped/carve/cache values and stack limits/delta are separate boundary measurements, not an exact per-node physical peak.

`GPU_NODE_ALLOC_MODEL` prints existing stage-additional, retained-after and successor model inputs unchanged. Calibration must retain the shared/cold setup baseline and compare in original large/small planner units. No model discount is implemented.

Reject any `GPU_NODE_ALLOC_COVERAGE_GAP` or `GPU_NODE_ALLOC_CLOSE_FAILED` marker, including gaps outside an active stage or through a capture/non-arena pool path. Exclude fused Blake shadow/check modes because their direct `cudaMallocAsync` shadow buffers bypass the arena ledger. Require all expected 19 final recursion ordinals and each required MAIN/INTER/composition/PCS phase before publishing a complete table. The 11 GB target and exact process physical peak remain unmeasured; no P1 exit or request-time gain is claimed.

Local static checks: Zig formatting PASS; diff whitespace PASS; 47-field C++ printf arity PASS. Pod build, parity, fresh CPU receiver and 19-node diagnostic are pending. `observer-source.json` contains the exact source hashes. Keep raw evidence on the pod and retain only compact summaries and references with SHA256.

Local coverage correction after independent review: observer domains now follow semantic callers even when native and recursion share one physical session. Resident composition uses its outer-workspace flag. A diagnostic-only PCS request field defaults to native-packet; the outer PCS adapter explicitly selects recursion-node. This field does not enter Scope equality, security identities, wire encoding or admission policy. Native diagnostic stages19/20 are named GKR/binding and retain node attribution; only FIXED setup stages16–18 are shared. These local source corrections require a fresh build and complete native-hook review; an older pod02 build cannot qualify them.

Native coverage hooks now enclose the whole multi-submit SOURCE build, native GKR/binding/global work and native truth MAIN. Retained compact MAIN replay uses diagnostic stage21 rather than resetting a live node epoch. Both engineers cross-reviewed the hooks and semantic-domain adapter; formatting and whitespace checks pass. This frozen correction remains unbuilt/unmeasured until the owner runs a fresh source-matched build and diagnostic.
