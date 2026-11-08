# gn-bind: GPU-native driver binding, JOBS=1 gates, first GPU-native request (2026-11-07)

Branch `codex/rv64-m8-gn-bind` (from `codex/rv64-m8-gpu` @ b289b021f; merges gn-shape, gn-s2, gn-truth, gn-node).
Labels: [M] measured, [D] derived, [E] estimate. Compact data: `gates.json`; runtime: `runtime-addon-3.json`; repro: `repro.py`.
Raw logs stay on the pod under `/workspace/m3/runs/m8-gn-bind/` (gate-N/gate.json sha256 in `gates.json`).

## What landed

| piece | file | notes |
|---|---|---|
| gate ships the job-path env | `scripts/rv64_gate.py` (+test) | a runtime JSON may carry `jobs_env` + `jobs_env_sha256` (libraries pinned); applied only when `--env` selects a job path (`STWO_RV64_M8_{JOBS,NATIVE_JOBS,OUTER_JOBS}=1`); explicit `--env` wins. Fixes gate-14 `MissingM8OuterFsLibrary`. Default gate unchanged. |
| jobs + outer-fs addons on the 25d0e62f base | `/workspace/m3/build/m8-gn-bind/addon-{1,2,3}` | rebuilt from source (`rv64_m8_jobs_addon_build.py --base .../m8-opt-combined/img/...25d0e62f`). addon-3 = every NAT/rv64/jobs/*.cu incl. gn-s2 oods/flat seal, gn-truth truth_oods, gn-node outer_seed. |
| service binding | `rv64/jobs/driver_bind.zig` (new) | n-stage1 `Registry` (Stage-1 + local-GKR symbols, workers, devices, CUDA-event timing) and n-stage2 `Factory` (encode/seal/commit/pcs/composition/global + gn-s2 `oods` symbols, chain identity, seal device) bound into `native_device.Native`; gn-shape `Builder.hooks()` as `shape_hooks` (shape + `class_of_block`); `truth_factory` as `RecursionFactory.truth`/`truth_stage2` + truth `class_of`; gn-node `DeviceOps` (seed fill, D2D, peer). Optional hooks resolve to the stream's vtable when landed, else to fail-closed fallbacks (recursion shape = 4-ary tree over `STWO_RV64_M8_GPU_NATIVE_TRUTHS`, default 5; artifact writers for cpu-N.bin / stage-one.bin / truth-N.bin / recursion-om31/*.proof). Per request: `Registry.release`, `Factory.endRequest`, truth `end`, node `end` after finish (success or failure). |
| combined-serve wiring | `rv64/jobs/driver_ge.zig`, `driver_serve.zig`, `driver_request.zig`, `rv64_combined_ethereum_main.zig` (1 line) | builder env from the manifest (`profile`, `gkr_bytes`, `fixed_setup_bytes`); composition host artifacts injected from the combined entry (lint keeps `m8_class_build_composition.zig` out of jobs/ imports); install loop + request plan use `class_of_block`; capture output directory created at install; install-stage diagnostics (`GPU_M8_GN_BIND ...`, `GPU_RESIDENT_SERVICE install_stage=...`). |

## Gates (rv64_gate.sh; correctness only, walls are diagnostic, not matched timings)

| gate | block | env | result |
|---|---|---|---|
| gate-1 | 26235156 | JOBS=1, HEADROOM 4 GiB | FAIL [M]: native-hybrid stage-1 window shrunk to 2.68G words -> `JobWorkExceedsArena` |
| gate-2 | 26235156 | JOBS=1, addon-1, HEADROOM 2 GiB | **PASS** [M]: 2/2 byte-identical to frozen D2 (32 artifacts), 2/2 fresh receivers, corpus; 23/23 jobs accepted per request |
| gate-3 | 24628607 | JOBS=1, addon-2 | **PASS** [M]: 2/2 byte-identical, 2/2 receivers, corpus; 33/33 jobs accepted per request |
| gate-5 | 26235156 | default | **PASS** [M] |
| gate-4 | 26235156 | JOBS=1 GPU_NATIVE=1, addon-2 | FAIL at install: warm capture `FileNotFound` |
| gate-6 | 26235156 | JOBS=1 GPU_NATIVE=1, addon-3 | FAIL at install: warm capture `FileNotFound` (see below) |

Diagnostic request walls [M, one process, no quiet gate]: JOBS=1 26235156 cold 43.58 s / warm 16.45 s; 24628607 cold 64.47 / warm 23.11 s;
default 26235156 cold 24.70 / warm 10.03 s. The JOBS=1 feeder is the legacy orchestration with every proof a job: not a speed arm.

**Arena pressure (gate-15 `CudaEnqueueFailed`) [M]:** not the addon link. The 25d0e62f image's SONAME is the a25 path, so an addon
linked against either dedups to the preloaded library. The failure was the native-hybrid stage-2 window probe: the window shrank to
3.89G words and left 0.3 GB, then a 726 MB long allocation failed. `STWO_RV64_M8_NATIVE_JOBS_HEADROOM` A/B on 26235156 JOBS=1 [M]:
1 GiB (default) -> gate-15 stage-2 `CudaEnqueueFailed`; 4 GiB -> gate-1 stage-1 `JobWorkExceedsArena`; **2 GiB -> gate-2 PASS**
(then gate-3 PASS on 24628607). The runtime JSONs ship 2 GiB.

## First GPU-native request (26235156): failure point [M]

Install resolves: native shape = gn-shape builder (stream), pack = **missing** (gn-pack not pushed), captured = missing, publish =
fallback writer, recursion shape = fallback, truth = gn-truth factory, node ops bound (addon-3). The request is never reached:
`Service.install -> CaptureSource.warm(26235156) -> Direct.Started.startWithAuthority` OK -> `Started.capture` returns
`FileNotFound`, before any class build or device work. Reproduced 3x outside the gate (`repro.py`: the gate's plan.json env, inbox
STOP pre-placed, under gpu.lock). The gn-shape harness runs the same capture call successfully with the donor gate env, so the
difference is in the service process (not found yet: no file open in the direct-capture path matched; ReleaseFast has no
error trace). Next: an error-trace (ReleaseSafe) build of combined-serve for the warm capture.

## What a GPU-native request still needs after the capture (in order)
1. NativeFactory.pack (gn-pack: TraceChunk v2 + Registry.setRequest per segment): without it the capture fails closed
   (`GpuNativeCaptureNoPacker`).
2. Per request: S2 `Factory.beginRequest` (roster, `flat` entries for v1-flat, inputs), `bindSegment(framingKey(class_of_block))`,
   `Exchange.receipts = true` + Stage 1 publishing `Exchange.receipt(s)` (gn-s2 ask), truth `Factory.begin` (gn-truth; its
   `classOf` is per-request, so the truth class must be known at plan time).
3. Recursion classes: authority registration + `NodeClasses` from one warm check-mode request (gn-node); recursion `shape`.
4. Publish hooks for the non-proof files (bundle.json, cells.bin, tree.json, candidate-source-bounds.json).

## Remaining host work (GPU-native path, per request)
Capture (the only intended CPU compute); RequestWords seed/prefix (a few Blake2s); S2 roster/flat script; slicing + file writes after the
single wait. Install-time: class build 11-15 s/block host [M, gn-shape].

## Pod hygiene
No service, tmux session or GPU memory of mine left. Foreign GPU holder seen at ~15:55Z: pid 526130 (m8-gn-node combined-serve, PPID 1,
no gpu.lock held) - reported in M8-INTERFACES, not touched.
