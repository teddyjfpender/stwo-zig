# outer-fold review fixes (hybrid recursion, STWO_RV64_M8_OUTER_JOBS=1)

Branch `codex/rv64-m8-outer-fold-review` on `codex/rv64-m7-integrate @ a82e42389`. Pod 2x RTX 5090. Labels: [M] measured,
[D] derived. All walls below come from gate runs (diagnostic quiet mode), not canonical interleaved measurements.

## Findings and fixes

| finding (severity) | fix |
|---|---|
| persistent-window reopen has no rollback on a partial unpark (major) | `jobs/outer_window.zig unparkAll`: re-parks every worker that unparked; `Hybrid.open` tears the window down if it cannot be restored. Host test on the fake device model (worker 1 refuses its arena -> both parked, next reopen works) |
| graph cache budget latches, never evicts (major) | LRU eviction by last launch; only a key whose own executable is unknown-cost or larger than the budget is banned; executables, sightings and bans idle for `STWO_RV64_M8_OUTER_GRAPH_IDLE_REQUESTS` (4) requests age out (aged on the worker thread, signalled by `noteRequest` at window open). Host tests: 10 keys into a 3-executable budget keep capturing, hot key survives; aging drops executable + ban |
| FIXED gathered/uploaded/committed twice per node (major) | the precommit FixedJob writes its coefficients into a per-lane worker-persistent handoff region; the node of the same ordinal and FIXED root binds it as Region.fixed (no packFixed, no second H2D, no in-node commit). Region size = the lane's largest FIXED image from earlier windows, reserved out of the window arena (`handoff_words`), released at park. The PCS still rebuilds the FIXED tree and decode checks its root, so a wrong handoff fails closed. `STWO_RV64_M8_OUTER_FIXED_HANDOFF=0` turns it off |
| int32 index guard misses full-LDE / composition buffers (major + minor) | guard in `Heap.alloc` for every allocation of the trace-commit phases (held, FIXED, MAIN, INTER incl. the full-LDE scratch) and in FixedJob's view; holdBuffers also refuses full-LDE images and composition stream chunk/banks up front. Composition (RC) and native PCS allocations are receipted (`max_unguarded_alloc_words`), not refused: a guard-everything build refused 26235156 folds 4/9 in the composition phase (rg1) where the deployed legacy kernels were byte-identical on every gate |
| unattributed job_ns; decode on the worker thread (minor) | PCS proof decode moved to the lane thread (`decodeProof`); new `GPU_M8_OUTER_NODE_HOST` line: prestage/init/job/stage/enqueue/wait/finish/decode/assemble |
| enqueueStreamed untested (minor) | recording-double test: seeded and compact calls, both twiddle modes, run grouping, layer offsets, root copy |
| loose env knobs (minor) | `jobs/outer_env.zig` strict parse, all hybrid knobs parsed at `Hybrid.create` (`InvalidM8OuterEnvironment`); env table in `jobs/README.md` |
| compactEager silently downgrades (minor) | fails `Kernels.load` like legacy (`MissingCompactEagerPcsCapability` / missing symbol) |
| magic phase ordinals; `[6]` arrays (minor) | `K.Phase` enum through `Device.phase`; Report arrays sized `n_phases` |
| composition errors mislabeled (minor) | `OuterJobTreeCustodyMismatch`, `OuterCompositionStreamMismatch` |
| dead `node_fixed_commit`, stale docs, `stop_ns` (minor) | removed; docs rewritten; park log `close_ns` |
| detached Counters doc (minor) | moved back |
| FixedJob body_launches double count (minor) | last enqueue only (node job too) |

## Gates [M] (pod run `runs/m8-outer-fold-p3/rg2`, `gates.json`)

- default `rv64_gate.sh` 26235156: PASS (32/32 + 32/32 byte-identical to the frozen D2 golden, 2 fresh CPU receivers, corpus).
- `--env STWO_RV64_M8_OUTER_JOBS=1` (+ addon / outer-fs / pinned envs) 26235156: PASS (32/32 both requests).
- same on 24628607: PASS (39/39 both requests).
- host tests: pod ReleaseSafe `test-rv64-jobs-outer test-rv64-jobs` 295/300 (5 skipped); local `test-rv64-jobs-outer` 71/71.

## Hybrid gate receipts (2 requests per service: window 1 cold, window 2 warm) [M]

| block | request | FIXED handoff nodes | node stage sum | FIXED precommit stage + wait | init (initWhole + footprint) | finish (worker) | decode (lane) | request wall | recursion |
|---|---|---|---|---|---|---|---|---|---|
| 26235156 | 1 | 0/15 | 2.20 s | 0.82 + 0.27 s | 9.66 s | 0.50 s | 0.34 s | 43.35 s | 27.13 s |
| 26235156 | 2 | 15/15 | 1.24 s | 0.76 + 0.27 s | 5.26 s | 0.05 s | 1.11 s | 17.09 s | 11.16 s |
| 24628607 | 1 | 0/19 | 2.89 s | 1.09 + 0.31 s | 10.87 s | 2.38 s | 0.96 s | 52.31 s | 31.61 s |
| 24628607 | 2 | 17/19 | 1.66 s | 0.94 + 0.34 s | 6.48 s | 1.09 s | 0.22 s | 20.57 s | 13.07 s |

Window 2 reserved `handoff_words=175293184` per device (arena 5.789e9 words vs 6.048e9 cold, 26235156) and released
the persistent regions at park. Largest guarded allocation 1.245e9 words; largest unguarded (composition/PCS) 2.80e9 words.
On 24628607, 2 warm nodes ran with a FIXED image larger than their lane's cap from window 1 and recommitted in the node.
No graph budget evictions or bans were logged.

[D] Warm node stage time dropped 1.94 s -> 1.24 s summed over 15 nodes on 26235156 (outer-fold-p3 r3-p6 request 2 vs this
gate's request 2; different runs, not matched). The new receipts show where the formerly unattributed per-node time
goes: `init` (initWhole + footprint: stream plans and placeholder PCS framing, lane thread) is 5.3-6.5 s summed per warm
request, about 0.35 s per node — the next host-side target. Both GPUs share it, one lane per device, so per-device it is
about half that.
