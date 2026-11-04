# Current resident source and transfer audit

The performance essay uses the 9.8525-second one-lane warm run as if its stage proportions also describe the latest 7.7085-second two-lane result. They do not. The latest receipt has two lanes, four workers per lane, a faster capture configuration and the coordinate DEEP default. Its capture is 5.2741 seconds, warm setup 0.1868 seconds and same-process native verification 2.2200 seconds. A new nonoverlapping stage account is needed for that schedule.

The claimed wide host uploads are obsolete. All 17 composition records of the archived one-lane warm run report **zero host coefficient cells**, versus 4,816,048,896 device coefficient cells. GKR's `coefficient_cells` counter likewise describes its source warehouse, not H2D traffic: the strict path reads device coefficient leases, copies them D2D and transforms them on the device. Global INTER already projects resident MAIN and computes fractions, inverses and prefixes on the GPU, returning only compact claims and a verdict.

The 104 composition geometry misses are cumulative cold entries. The warm run adds **zero** new misses. Retaining immutable shape metadata has already landed. Truth MAIN replay is also executable: the default `replay_main` path discards wide MAIN after stage-one seal, retains compact input, and regenerates/re-commits MAIN with an explicit expected-root check at stage two.

A real remaining transfer cost is per-column orchestration. The same warm run's composition coefficient-stream event spans total 324.521 ms even though no coefficient came from the host. These spans include idle gaps while the CPU validates and enqueues thousands of individual D2D copies. Adjacent physical columns in one lease can be validated as one full proof-scoped range and copied in one call. `device_copy_run.zig` merges only equal-token, equal-generation ranges with contiguous source and destination addresses. Composition and global INTER use this planner; all merged ranges still pass the native scope/range registry. No byte traffic is claimed removed, and no speedup is measured yet. New counters expose copy-call counts; `STWO_RV64_GLOBAL_PROFILE=1` exposes joined ingress wall time.

Core source formatting also performs a whole-device join before and after each ALU/BINARY/SHIFT/JALR/LS launch. `STWO_RV64_CORE_SINGLE_STREAM=1` is an opt-in experiment that orders uploads and kernels on the same stream, with compact input ownership retained until the stream joins. Its staging payload cap is 64 MiB; reaching the cap joins and retires prior inputs before more are adopted. Oversized individual inputs use an immediate join. Error paths join before releasing caller input. DIV support writes remain ordered before MUL reads, and shared histogram updates preserve ordering. The control path retains its original synchronization. No GPU kernel or cryptographic transcript changes.

Host tests cover zero-copy ownership, capacity/OOM failure atomicity, join-before-release ordering, adjacent-range merging, pointer overflow and rejection of token/generation/gap changes. The CUDA host suite passes 127 tests and the fully instantiated production semantic check passes. GPU parity and timing remain pending. Before adoption, run the exact real segment/full block with unchanged profile, compare all native proof bytes and freshly verify, then measure copy-call reductions, source joins, source staging peak and physical GPU peak. These changes do not establish the essay's projected 3x or subsecond proving claims.


## Thesis checkpoint, 2026-11-04

This is a scope audit, not a completion or speedup claim. The fifteen-block
native receipt and the fifteen-block recursive receipt are separate qualification
sets. They contain versioned, concurrent-workload observations; they do not
establish quiet basket medians or the thesis's projected subsecond timings.

| Thesis item | Current evidence | Remaining acceptance gate |
|---|---|---|
| Overlap independent proofs | Native two-lane controls exist; the ready recursion DAG and exact recycler-backed shared-budget admission pass host tests | Explicit ready-candidate N1 has exact native and recursive proof parity and fresh CPU acceptance. Physical N2/N4 runs and measured overlap remain open |
| Keep numerical proving resident | Source audit and all fifteen native blocks exercise device MAIN/INTER, coefficient ingress, composition and PCS; CPU execution supplies compact advice | Continue to distinguish immutable host setup, execution and verification from device proving; serial device FIXED candidate removes the host commitment with exact real-block parity and fresh CPU acceptance; full-basket adoption remains gated |
| Bound memory over the whole request | INTER retirement, compact composition coefficients and smaller prefix banks have exact-proof gates; phase-separated PCS has physical tiny parity, ownership tests and fresh acceptance of the complete largest block | All fifteen recursive blocks accepted, including the largest. Logical caps are not sampled physical peaks; device FIXED still needs worst-shape capacity qualification |
| Reduce GKR launches | Real-block persistent-tail A/B preserves bytes and reduces launches, but establishes no end-to-end gain; default stays off | Multi-CTA fold/next-sum passed numerical and fresh full-block acceptance, but warm proving regressed 1.78% and launches increased; default remains off. Mixed wake/fold successor, graph capture and cross-proof batching are unqualified |
| Fuse transforms and commitment hashing | Generated composition kernels and existing resident FRI/commitment stages execute in production | FFT/leaf-hash and FRI-fold/hash fusion are still optimization work, not delivered by phase retirement |
| Retain immutable geometry | Earlier audit shows no added warm geometry misses; admitted shape metadata is bounded | Do not confuse unique per-node recursive authorities with reusable per-program setup |
| Profile the real path | Real Nsight Systems source receipt records copies, launches, joins and GPU activity | Hardware counters remain blocked by host policy; do not infer occupancy or sustained bandwidth from event spans |
| Benchmark the complete basket | Fifteen native blocks and fifteen recursive roots independently accepted | Homogeneous final-runtime repeated timings and physical 2/4-device measurements remain open |

The newest recursive setup sample is block25229951:115 nodes, with summed
finalize11.117s, column generation66.426s and authority construction178.305s.
Those are separately observed CPU setup spans, not savings. Device precommit is now qualified on one real block as an explicit prover-only
constructor; independent receivers continue to rebuild the original authority.
On block26235156, one ordered same-binary true/false comparison measured
authority construction1.972s versus34.759s over21 nodes, and full request
126.221s versus164.769s. Every proof, root and ordered tree was identical.
The device candidate has fresh independent CPU acceptance; the later CPU
control has producer parity but no fresh independent receiver run yet. This
is one observation, not a quiet median, worst-shape fit or full-basket gain. Reusing a producer's claimed
root in the receiver would invalidate this optimization's acceptance argument.

Evidence: `vectors/reports/rv64-cuda-real-segment-20261103/` contains
`resident-native-full15-policy-v2-qualified.json`,
`gkr-mixed-persistent-tail-real-block-ab.json`,
`resident-real-nsys-source-v1.json` and
`pcs-phase-retirement-physical-gate.json`.
`vectors/reports/rv64-om31-recursion-20261103/recursive-basket-fifteen-accepted-v7.json`
pins the accepted recursive cases and their distinct producer groups.
The security description remains **128-bit security target under documented
assumptions**, without a certified whole-protocol claim.

The ready scheduler and serial device FIXED routes are separate explicit manifest
candidates. Their combination is rejected, defaults remain serial CPU FIXED,
and strict independent verification cannot be disabled for either candidate.
See `rv64-resident-ready-candidate.md`, `rv64-outer-device-fixed-precommit.md`
and `rv64-gkr-batched-fold-next-sum.md` for route-specific gates.

## Qualified CPU preparation follow-up

Commit `c80592fac` fills independent preprocessed row intervals on the existing
scoped pool. Validation, multiplicity scatter, allocations, permutation lowering
and stable column ordering stay on the caller. No pool, cache or histogram is
created by this path. Workers join before errors release any column; an
unavailable pool falls back to the same serial fill.

A bounded Blake-heavy CPU case (2^21 Blake rows, 2^20 binary rows and all fixed
tables) measured 61.483ms serial versus 21.513ms with four workers, medians of
three runs. The integrated repeat measured 61.350ms versus 21.388ms. These are
column-construction timings, not projected full-block savings. Exact all45
columns/layout, native FIXED root, authority identity, proof bytes and fresh
CPU acceptance pass. Last-shard errors, retry, leased-pool fallback and all
allocation failures are covered. The three GNU entry-point checks also pass.
The fifteen-block cold report predates this change; no new basket timing is
claimed. See `pp-disjoint-column-fill-cpu-candidate-v1.json`.

## Isolated follow-ups awaiting physical qualification

These source branches are preserved separately and do not change the accepted
producer/runtime pins or the current production defaults.

| Slice | Branch and checkpoint | Evidence still needed |
|---|---|---|
| Reuse raw FIXED evaluations through MAIN/INTER | `codex/rv64-device-fixed-ingress-reuse`, `c0632a697` | 158 host checks and three GNU semantic targets pass. Physical exact-proof/fresh-receiver parity, worst-shape peak and complete-basket timing remain open. The raw lease stays separate from retained coefficient custody; cleanup failure is terminal and blocks reuse. |
| Mixed GKR fold/wake grid | `codex/rv64-gkr-mixed-fold-sum`, `7231bbed8` | 18 host checks and production semantic target pass. CUDA compilation, numerical/poison fixtures and a controlled real-block A/B remain open. The qualified earlier fold/next-sum route was slower and stays disabled. |
| Persistent narrow assignment levels | `codex/rv64-outer-assignment-narrow-runs`, `802ce316b` | Six planner checks and GNU recursion semantic target pass. CUDA compilation, task-width census, exact GPU assignments/proofs and real timing remain open. One CTA handles at most256 consecutive levels of at most128 tasks; broad levels keep the original stream barriers. |

No uncompiled kernel or source-only test is counted as a delivered GPU speedup.

## Qualified task-packing follow-up

Commit `2a96793bd` packs zero-CSR assignment plans directly into the existing
Task buffer on the scoped pool. It removes the separate capability scan while
preserving packing-error precedence, hint encodings and the missing-query
capability mask. CSR graphs retain their original append/census path. No extra
task array, pool, cache, GPU kernel or transcript change is introduced.

A compact-source packing microbenchmark over 8,388,608 mixed records measured
28.456ms versus8.106ms with four workers; the integrated repeat measured
29.218ms versus8.090ms. The source fixture is repeated deliberately, so these
are packing timings rather than a complete generated-circuit or block result.
Every record, seed, level and schedule-identity byte matches the original
encoder. All hint variants, capability rejection, packing-error precedence,
CSR handling, joined last-shard failure/retry and pool fallback pass. The
integrated target passed23 tests and the GNU combined-entry check. See
`task-pack-disjoint-cpu-candidate-v1.json`; final GPU/basket timing remains open.

## Qualified stable-ordering follow-up

Commit `35b966f63` parallelizes only stable task ordering after the dependency
walk. Eight fixed logical chunks count their levels and scatter into disjoint
output ranges; changing physical worker availability between waves cannot
change task order. The existing source/ordered arrays are reused. One optional
histogram and the existing serial cursor workspace are limited to16MiB of
requested scratch; allocator rounding is still charged by the caller budget.
No-pool, unavailable/cooperative pool, small/deep-narrow schedules, oversize
scratch and allocation failure keep the original serial path.

The bounded 8,388,608-record/110,003-level CPU case measured22.982ms serial
versus12.940ms with four workers. The integrated repeat measured26.338ms
versus13.781ms. These include histogram allocation and are ordering-only
observations under host workloads, not block speedups. Stable records, level
ends, real-builder seeds and packed GPU identities match the independent DFS
control. Different count/scatter shard counts, last-chunk rejection/retry and
scratch fallback checks pass. The integrated GKR/packing target passed24 tests
and the focused circuit target43; source GNU entry-point checks also passed.
See `stable-order-disjoint-cpu-candidate-v1.json`.
