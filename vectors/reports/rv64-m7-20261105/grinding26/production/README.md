q102/P26 production activation: ACCEPTED, size win; no latency win

Same frozen9531 source plus5ac profile hunks, same final driver570671f8…02e4, CPU receiver310b7a15…6b87, a25 CUDA image; native D2 + coalesced truth families, auto arena, packedfold1, assignment graph/controller ON. Only the outer profile selector differs. Bothdev ×2profiles ×cold/warm =8 completed requests. All4 fresh separate CPU receivers accepted, GPU disabled and caches disabled. Within each arm all native/recursive proof artifacts are byte-identical cold↔warm; native artifacts are byte-identical across outer policies (14 small/17 headline files).

| Block | Profile | Cold request s | Warm request s | Root B |
|---|---|---:|---:|---:|
|26235156|q108-control|23.606700|10.697730|749464|
|26235156|q102-p26|24.461157|10.837298|715568|
|24628607|q108-control|29.789666|12.694166|749688|
|24628607|q102-p26|29.928573|13.204740|717520|

Root bytes decrease4.52% and4.29%; warm request observations increase1.30% and4.02%. Load1m12–27 exceeds quiet8, so no statistically qualified speedup/regression claim. No additional A/B was run. Fold padding did not halve on either block; cheaper query shape alone did not cross the expected Blake padding cliff. Profiles remain explicit optional policies; default unchanged.

Auto-arena whole-device sampled peak is around31.6GB (NVML,200ms sampling); this does not establish exact process peak<=28GB. Allocator pressure/overrun diagnostics were recovered by idle trimming; terminal requests all completed and fresh proofs accepted. Source/a25 immutable assets and accepted proof pairs remain on pod under`/workspace/m3/runs/m7-q102-953/`. Native and recursion timelines overlap; do not add stage fields.

Root-only/full receiver costs remain as measured in raw receipts (31–41s per complete fresh CPU receiver); this experiment does not claim the root-only target. C1 wrapper activation is separate and absent from this result. Whole-protocol128 certification is absent; profiles use the explicitly conjectured FRI arithmetic.
