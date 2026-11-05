# Stream infra receipts (2026-11-04, 2x RTX 5090 pod)

Everything here was measured on the pod. Each row is one observation, not a median.
All runs execute the producer under `/workspace/m3/locks/gpu.lock`. Other streams were
running CPU builds concurrently, so these are not quiet-machine numbers.

| file | block | driver | library | request s | rec. s | byte-identical vs v7 | fresh receiver |
|---|---|---|---|---:|---:|---|---|
| 26235156-2gpu-accepted-assets-harness-check | 26235156 | accepted d5766d83 | accepted 25295868 | 75.1 † | 50.7 | yes | not run |
| 26235156-2gpu-source-driver-accepted-library | 26235156 | source fbb6c6c76 (b66643bf) | accepted | 65.4 | 42.9 | yes | accepted (44.0 s) |
| 24628607-2gpu-source-driver-accepted-library | 24628607 | source + timeline log (d1632593) | accepted | 100.7 | 66.4 | yes | accepted (66.0 s) |
| 24628607-2gpu-nsys-receipt / -nsys-timeline | 24628607 | d1632593 under nsys | accepted | 103.4 | 68.5 | yes | not run |
| **24628607-2gpu-from-source** | 24628607 | d1632593 | **source 3e16cd89** | **100.2** | 64.2 | **yes** | **accepted (61.7 s)** |
| **26235156-2gpu-from-source** | 26235156 | d1632593 | **source 3e16cd89** | **64.6** | 41.5 | **yes** | **accepted (41.4 s)** |

† Measured while a 32-job nvcc build was competing for the 40.8-core CPU quota.

- **Receiver.** `rv64-word16-ethereum-recursion-receiver` (08fe4791) is built from this
  branch for x86_64 Linux. It runs as a separate process in `verify-recursion-candidate`
  mode with `CUDA_VISIBLE_DEVICES=""`, PCS helper `/bin/false` and the setup cache unset.
  It re-verifies the native proofs and every recursive node from the files on disk.
  `producer_strict_checks: pass` means the full15 harness's
  zero-CPU-assignment, device-FIXED and lifecycle checks also passed.
- **Reference.** For comparison, the accepted run took 98.9 s, with 63.6 s of recursion.
- **`build-from-source.json`** covers the driver, receiver and CUDA image built from
  `/workspace/m3/src/infra`:
  - a cold CUDA build took 2,106 s;
  - an incremental CUDA build took 144 s (39 objects compiled, 658 from the store);
  - each zig build took about 320 s;
  - stack admission passed: the worst kernel is 12,544 B.
- **`from-source-v1-image-oom-rejected.json`.** The first from-source image used the
  frozen catalogue with core roles 43/44 unsharded. It OOMed both blocks, and the
  file records why: an unsharded role 44 has a 19,832 B per-thread stack.
- **`24628607-2gpu-nsys-timeline.json`** has the per-node and per-device timeline. Its
  summary is in `design/riscv-proving-stack/rv64-m3-timeline-24628607.md`.
