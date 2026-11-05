# M7 expanded immutable fold caches

Status: **8/8 full artifact comparisons pass** against the accepted D2 plus partial-family-coalescing reference, with **2/2 fresh CPU acceptances** for the expanded-cache cold proofs. The existing flag changes only producer cache representation; native, bundle, every recursive node and tree artifacts match. No numerical source or image rebuild is involved.

The source falsifier established that asynchronous finish already exists: `deviceLane` releases the device stage to a shared host finish queue, and verification/publication completes the DAG node independently. In the final warm M6 timeline, the next same-lane proof overlaps the preceding finish in 12/13 small-block transitions and 18/21 headline transitions. Headline node 0 starts its successor after 14 microseconds while its finish still has 221.596 ms left. An additional finish API would duplicate existing behavior.

The critical remaining fold prep serially unpacks cached PP columns, then cached tasks. `STWO_RV64_PACK_FOLD_CACHE=0` retains expanded immutable fold arrays instead: acquisitions borrow them, so both the unpack and later per-proof clone destruction disappear. Leaf classes always remain compressed. Existing independent 6 GiB PP and task cache caps remain unchanged. The headline five-fold-class roster contains 3.164 GB of logical PP columns and 2.702 GB of task records, fitting those caps; cache metadata and compressed leaves are additional. These existing caches use a separate allocator, so this is not a new global host admission guarantee.

| Measured warm request | Expanded folds (flag 0) | Packed folds (flag 1) |
| --- | ---: | ---: |
| 26235156: request | 9.659 s | 10.684 s |
| 26235156: recursion | 4.438 s | 5.179 s |
| 26235156: tail after last leaf | 1.441 s | 2.039 s |
| 26235156: sampled producer HWM | 21.90 GiB | 19.33 GiB |
| 24628607: request | 12.261 s | 13.222 s |
| 24628607: recursion | 5.081 s | 5.959 s |
| 24628607: tail after last leaf | 1.288 s | 1.844 s |
| 24628607: sampled producer HWM | 23.81 GiB | 19.59 GiB |

Headline warm fold prep calls fall from 209–332 ms to 20–89 ms; host-plan calls fall from 46–157 ms to 5–16 ms. Publication plus retirement falls from 73–188 ms to 17–19 ms. Five PP and five task unpack calls become zero. The comparable small block also eliminates all four PP and four task unpacks. These observed CPU phases support the causal improvement; per-node CPU spans overlap and must not be added to wall time.

This is one loaded pair per block. Native proving time and GPU clocks can vary, so the wall differences are diagnostic, not a robust latency distribution. Both arms omit Nsight; GPU seconds were not remeasured. Actual process RSS/HWM is sampled from `/proc` every 100 ms, excluding helpers and receivers; the final subinterval may be missed. The headline trade is approximately +4.22 GiB sampled HWM for the expanded immutable cache.

The warm-throughput candidate should set `STWO_RV64_PACK_FOLD_CACHE=0`, keeping the existing cache caps and all other final D2/coalescing settings. Covered evidence is the two development blocks in fresh per-block services. This does not qualify arbitrary unseen geometries, multi-block cache residency, two proofs per GPU, 22 GiB device admission, or the full M7 targets.

Frozen assets: driver `9cf6589f1b479f4c6b1049cc98860c55bfbb2fa680e4716ffd976748f782a2f6`; CUDA image `a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45`; fresh receiver `ddcbcf4b24aaf770f8b42d22188ea3c3c9b7f57726db1d0aa9cb09be27069b42`. All case commands, raw pipeline records, identity checks and RSS receipts are in `vectors/reports/rv64-m7-20261105/fold-expanded/`.
