# Current resident source and transfer audit

The performance essay uses the 9.8525-second one-lane warm run as if its stage proportions also describe the latest 7.7085-second two-lane result. They do not. The latest receipt has two lanes, four workers per lane, a faster capture configuration and the coordinate DEEP default. Its capture is 5.2741 seconds, warm setup 0.1868 seconds and same-process native verification 2.2200 seconds. A new nonoverlapping stage account is needed for that schedule.

The claimed wide host uploads are obsolete. All 17 composition records of the archived one-lane warm run report **zero host coefficient cells**, versus 4,816,048,896 device coefficient cells. GKR's `coefficient_cells` counter likewise describes its source warehouse, not H2D traffic: the strict path reads device coefficient leases, copies them D2D and transforms them on the device. Global INTER already projects resident MAIN and computes fractions, inverses and prefixes on the GPU, returning only compact claims and a verdict.

The 104 composition geometry misses are cumulative cold entries. The warm run adds **zero** new misses. Retaining immutable shape metadata has already landed. Truth MAIN replay is also executable: the default `replay_main` path discards wide MAIN after stage-one seal, retains compact input, and regenerates/re-commits MAIN with an explicit expected-root check at stage two.

A real remaining transfer cost is per-column orchestration. The same warm run's composition coefficient-stream event spans total 324.521 ms even though no coefficient came from the host. These spans include idle gaps while the CPU validates and enqueues thousands of individual D2D copies. Adjacent physical columns in one lease can be validated as one full proof-scoped range and copied in one call. `device_copy_run.zig` merges only equal-token, equal-generation ranges with contiguous source and destination addresses. Composition and global INTER use this planner; all merged ranges still pass the native scope/range registry. No byte traffic is claimed removed, and no speedup is measured yet. New counters expose copy-call counts; `STWO_RV64_GLOBAL_PROFILE=1` exposes joined ingress wall time.

Core source formatting also performs a whole-device join before and after each ALU/BINARY/SHIFT/JALR/LS launch. `STWO_RV64_CORE_SINGLE_STREAM=1` is an opt-in experiment that orders uploads and kernels on the same stream, with compact input ownership retained until the stream joins. Its staging payload cap is 64 MiB; reaching the cap joins and retires prior inputs before more are adopted. Oversized individual inputs use an immediate join. Error paths join before releasing caller input. DIV support writes remain ordered before MUL reads, and shared histogram updates preserve ordering. The control path retains its original synchronization. No GPU kernel or cryptographic transcript changes.

Host tests cover zero-copy ownership, capacity/OOM failure atomicity, join-before-release ordering, adjacent-range merging, pointer overflow and rejection of token/generation/gap changes. The CUDA host suite passes 127 tests and the fully instantiated production semantic check passes. GPU parity and timing remain pending. Before adoption, run the exact real segment/full block with unchanged profile, compare all native proof bytes and freshly verify, then measure copy-call reductions, source joins, source staging peak and physical GPU peak. These changes do not establish the essay's projected 3x or subsecond proving claims.


## Thesis checkpoint, 2026-11-04

This is a scope audit, not a completion or speedup claim. The fifteen-block
native receipt and the ten-block recursive receipt are separate qualification
sets. They contain versioned, concurrent-workload observations; they do not
establish quiet basket medians or the thesis's projected subsecond timings.

| Thesis item | Current evidence | Remaining acceptance gate |
|---|---|---|
| Overlap independent proofs | Native two-lane controls exist; the ready recursion DAG and exact recycler-backed shared-budget admission pass host tests | Physical one-lane parity, then admitted multi-device runs; source-tested admission is not measured overlap |
| Keep numerical proving resident | Source audit and all fifteen native blocks exercise device MAIN/INTER, coefficient ingress, composition and PCS; CPU execution supplies compact advice | Continue to distinguish immutable host setup, execution and verification from device proving; eliminate duplicate recursive fixed commitment |
| Bound memory over the whole request | INTER retirement, compact composition coefficients and smaller prefix banks have exact-proof gates; phase-separated PCS has physical tiny parity and ownership tests | Largest actual recursive shape under the unchanged cap, then complete recursive basket; logical caps are not sampled physical peaks |
| Reduce GKR launches | Real-block persistent-tail A/B preserves bytes and reduces launches, but establishes no end-to-end gain; default stays off | Multi-CTA fold/next-sum candidate needs numerical GPU parity and timing; graph capture and cross-proof traversal batching remain open |
| Fuse transforms and commitment hashing | Generated composition kernels and existing resident FRI/commitment stages execute in production | FFT/leaf-hash and FRI-fold/hash fusion are still optimization work, not delivered by phase retirement |
| Retain immutable geometry | Earlier audit shows no added warm geometry misses; admitted shape metadata is bounded | Do not confuse unique per-node recursive authorities with reusable per-program setup |
| Profile the real path | Real Nsight Systems source receipt records copies, launches, joins and GPU activity | Hardware counters remain blocked by host policy; do not infer occupancy or sustained bandwidth from event spans |
| Benchmark the complete basket | Fifteen native blocks independently accepted; ten recursive roots independently accepted | Five recursive cases, controlled repeated timings and physical 2/4-device measurements remain open |

The newest recursive setup sample is block25229951:115 nodes, with summed
finalize11.117s, column generation66.426s and authority construction178.305s.
Those are separately observed CPU setup spans, not savings. Device precommit is
being qualified as an explicit prover-only constructor; independent receivers
must continue to rebuild the original authority. Reusing a producer's claimed
root in the receiver would invalidate this optimization's acceptance argument.

Evidence: `vectors/reports/rv64-cuda-real-segment-20261103/` contains
`resident-native-full15-policy-v2-qualified.json`,
`gkr-mixed-persistent-tail-real-block-ab.json`,
`resident-real-nsys-source-v1.json` and
`pcs-phase-retirement-physical-gate.json`.
`vectors/reports/rv64-om31-recursion-20261103/recursive-basket-ten-accepted-v2.json`
pins the accepted recursive cases and their distinct producer groups.
The security description remains **128-bit security target under documented
assumptions**, without a certified whole-protocol claim.
