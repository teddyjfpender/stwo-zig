# P1: two-lane completion and a small matched gain; exit remains open

Current frozen candidate passes the full preservation gate and all 12 headline fresh CPU receivers [M]. P1 is **OPEN**: exact per-node peaks remain unmeasured, and the separate profile misses the busy gate.

| 24628607, warm, 2 RTX 5090s | Default | Composed candidate | Delta |
|---|---:|---:|---:|
| Quiet 3+3 request median [M] | 13.464796338 s | 13.131352881 s | -0.333443457 s / -2.48% [D] |
| Capture median [M] | 2.053 s | 2.134 s | +0.081 s [D] |
| Native proving median [M] | 4.785 s | 5.239 s | +0.454 s [D] |
| Recursion median [M] | 6.230 s | 5.379 s | -0.851 s [D] |
| Kernel duration sum, separate warm profile [M] | 10.578838 GPU-s | 10.597261 GPU-s | +0.018424 GPU-s [D] |
| Kernel occupied union, separate warm profile [M] | 10.578838 GPU-s | 10.311834 GPU-s | -0.267003 GPU-s [D] |
| After-native kernel busy, separate profile [D] | 53.54% | 47.01% | -6.53 percentage points [D] |
| Exact per-node peak | unmeasured | unmeasured | P1 gate open |
| Root proof bytes [M] | 749688 | 749688 | unchanged |

Stage medians do not sum directly to the request median. Profile walls are instrumented and do not replace the primary timings. Interval union measures occupied time; the nearly flat kernel-duration sum does not establish less kernel work. The after-native profile boundary is exclusive native end plus a 5 ms uncertainty band. Both captures end normally, contain kernel activity through both requests, have no graph envelopes in measured windows, and all four profiled proofs are freshly CPU-accepted [M]. Raw files remain on pod cps13bvat3xhdo by SHA-256 in `inter-contributions-summary/summary.json`.

The new default-off phase bound counts existing joined DEEP/FRI retirement versus late source rebuild; it removes no physical buffer. Its standalone predecessor completes cold but stalls warm at the 120 s watchdog [M]. All three completed predecessor proofs are freshly accepted; 27 matching partial files and five missing required files remain a failed warm request [M].

The second default-off selection generates INTER contributions directly, performs the same warp-batched inversion in registers, and applies the unchanged cumulative encoding in place through explicitly named exact-alias APIs. Legacy overlap contracts remain unchanged. The largest numerator plane disappears: 3489660928 bytes [D, allocation model], with INTER generation additional allocation 8858370048 to 5368709120 bytes [D]. Neither number is a node peak.

On 26235156, baseline cold/warm are 28.358851591/15.479253111 s and candidate 30.860458379/15.839329958 s [M, correctness-only walls]. Both candidate requests now complete; all four smoke proofs match native/recursive payloads and captured inputs and pass fresh CPU verification [M]. The ABI fixture passes 132 cases across both GPUs and rejects 2112 invalid calls; memcheck and synccheck each report zero errors [M]. The preservation gate passes build, unit tests, both default proofs against 32 frozen payloads, two fresh CPU receivers, and all 19 corpus cases [M; V04 size cap only]. Conjectured-128 and the hash-based format are unchanged.

Default remains D2 + truth coalescing, automatic arena, one lane. No P1 feature is promoted.

The revised user-directed order is binding: measure all 19 nodes by stage/lane on a single lane; calibrate admission against those observations; audit native regressions with the P1 flags composed on one lane and scope outer-only features correctly. No further footprint implementation or two-lane retry until measured peaks are at most 11 GB or a calibrated model shows two nodes fit. Parallel P3/P5 and P2/P4 engineering uses explicit file ownership, default-off changes, and ordered GPU qualification.

Checkpoint receipts total about 52 KB [M] plus this summary and the progress ledger. Raw Nsight, SQLite, payloads, source snapshots and logs stay on the pod or in `/Users/theodorepender/Coding/ge-artifacts/rv64-m8-20261106`; summaries identify them by SHA-256. Earlier raw files will be removed from the current Git tree in a separate follow-up without rewriting history.
