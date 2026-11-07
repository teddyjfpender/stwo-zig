# m8-gpu-n-stage1 round 1: GPU-native native Stage 1 (status: PARTIAL)

Branch `codex/rv64-m8-gpu-n-stage1`. Code: `src/integrations/riscv_cuda/rv64/jobs/native_device_stage1.zig`
(+ `_test.zig`, `_gpu_test.zig`), `src/backends/cuda/native/rv64/jobs/native_witness_stage1.cu`, Stage-1 routing in
`native_device.zig` (`Stage1Hooks`). Interfaces: `/workspace/m3/M8-INTERFACES.md` section `m8-gpu-n-stage1`.

## What is on device
| item | design | status |
|---|---|---|
| FIXED adopted from class region (H6) | WarmJob per (class, GPU) at install commits FIXED once into a worker-persistent region; request job only mixes the device root; not warm -> `GpuNativeFixedNotWarmed` | done, GPU parity [M] |
| MAIN commit into main_resident (H5, H12) | `native_commit.enqueueInto(main_resident view)`; root written into the exchange root slot, mixed, peer-published | done (commit kernels parity [M]); main_resident wiring untested on GPU |
| local GKR + binding, section kept on device (H7) | section into the resident section region, binding + authority into resident regions; claims -> exchange claims slot | code done, NOT GPU-run in this job form |
| device checks | `stwo_rv64_n1_check_v1_on`: witness_status, binding_authority, root_match | kernel parity + negatives [M] |
| witness from TraceChunks (H4) | chunk ingress v1 (run table + MAIN evaluation words), h2d from the pinned ring + scatter kernel, no joins | ingress done [M]; the capture does NOT produce chunks yet, and the evaluations are not computed on device from compact facts |

## Measurements [M] (pod 2x RTX 5090, 2026-11-07)
- `zig build test-rv64-jobs -Doptimize=ReleaseSafe` with STWO_RV64_M8_GPU_BASE (frozen a25cc3b2 image) and the n-stage1 addon
  (`/workspace/m3/build/m8-gpu-n-stage1/addon1`): 337/338 passed, 1 skipped.
- `GPU_M8_N1_PROLOGUE_PARITY fixed_root_equal=1 main_root_equal=1 channel_equal=1 root_match=0x0 witness_status=0x0`
  (warm FIXED commit fresh; request: adopted region, 2-chunk witness with a split column, MAIN root + post-MAIN channel equal the host scheme).
- `GPU_M8_N1_NEGATIVES root_match=0x2080010 witness_status=0x2010001` (corrupted class root; one run past the image, no word written).
- Logs: `/workspace/m3/runs/m8-gpu-n-stage1/{gpu-tests2.log,gpu-direct2.log}`.

## Not measured
Per-segment byte identity vs the frozen golden on 26235156 / 24628607, CUDA-event GPU time of Stage 1 per segment and remaining host
time per request: they need the service wiring (Registry.register per class from setup, setRequest per request, driver
batch_pinned_words) and a capture that emits chunks. The `Span` CUDA-event hooks are in Stage1Job (Registry.gpuMs).
