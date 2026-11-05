# RV64 M6 native-stream: native witness/commit pipeline (proof-neutral)

Status: M6 stream `native-stream` (branch `codex/rv64-m6-native-stream`, from 95d40063d). Proof format:
UNCHANGED. Every change here is scheduling or placement only; the gate is byte identity of every native,
bundle and recursive proof with the M5 default receipts on 26235156 and 24628607.

## 1. What the native stage was bound by (M5, measured)

From the M5 `a5-nsys` service run on 24628607 (`vectors/reports/rv64-m6-20261105/native-stream/`):

- native window 6.6 s; kernel busy in that window 1.80 s (GPU0) and 2.58 s (GPU1);
- 2,790 `cudaStreamSynchronize` calls = 3.7 s of API time; H2D 8.4 GB (about 312 B per instruction);
- every GPU is driven by ONE service owner thread: `stwo_rv64_gpu_session_submit` (pcs_native.cu) runs each
  callback on the device's owner and serialises submitters;
- the owner thread's largest idle class is "after a D2H readback, before the next job" (1.6 s on GPU0, 2.0 s on
  GPU1): the lane thread is doing host work between jobs and nobody else is submitting to that device;
- coordinator: 2 lanes x 4 workers, each lane claims the next ordinal of one shared queue, while the router places
  ordinal i on GPU i % 2. Two lanes can collide on one GPU while the other idles (stage two: ordinals 0 and 2 both
  on GPU0 for 0.7 s), and the long poles (keccak truth 7, 1.2-1.4 s of stage two) start last;
- `STWO_RV64_GPU_CPU_REPLAY=1` parks every CPU segment's MAIN after stage one and regenerates it after the
  manifest barrier from a host copy of the compact capture (second host projection pass, second H2D of the
  56 B/row metadata and the core ingress, second MAIN commit). On the dev blocks this costs about 1 s of stage two.

## 2. Mechanisms

### 2.1 Device-affine lanes, heaviest first (services/schedule.zig, `Policy.device_affinity`, `heaviest_first`)

`device_affinity = N` splits the dispatch into N queues, queue q = { i : i % N == q } (the resident router's
placement), and lane l claims only from queue l % N. With lanes = 4 and N = 2 each GPU always has two workers
in flight, so one worker's host phases overlap the other's device phases on the same owner thread.
`heaviest_first` orders each queue by the coordinator's own per-index estimate (descending, stable by ordinal)
when no explicit order is given, so keccak truth 7 and the CPU segments start before the small truths.

Why bytes cannot change: `services/schedule.zig` already requires (and tests) that every index runs exactly once
with the same inputs whatever lane or time it runs at; the queues are a partition of the same permutation, and
the memory admission (`memory_cap_bytes`) is unchanged code. Tests: `schedule_test.zig` "Device-affine lanes ...".

### 2.2 Replay as overflow only (riscv_cuda/rv64/cpu_replay.zig)

The replay stage keeps its interface (`gkr_local/cpu_replay.zig` `Stage{estimate, prepare -> Owner{park,
restore, release}}`). The CUDA-side owner now retains the first `STWO_RV64_GPU_REPLAY_RETAIN_PER_DEVICE`
(default 4) CPU workers live on each device: their park/restore are no-ops, so MAIN, the deferred binding and the
compact facts stay exactly where stage one left them (the non-replay path, which the M3/M4 runs used before
replay existed), and no compact host copy is made. Workers beyond the bound park and replay as in M5.

Why bytes cannot change: a retained worker's stage two consumes the stage-one MAIN directly; a replayed worker's
regenerated MAIN must reproduce the original root (`expected_main_root`) and projection digest before it is
published. Both paths are independently byte-identical to M5 (measured below). The bound keeps retained device
inventory at the dev-block level (24628607 holds 4 CPU segments on GPU0) whatever the block size, so the large
blocks still replay their overflow instead of exhausting device memory.

### 2.3 Single-stream core ingress is the default (riscv_cuda/rv64/core_witness.zig)

`STWO_RV64_CORE_SINGLE_STREAM` was the M3-M5 headline configuration (`rv64-resident-source-audit-20261103.md`:
same kernels, ordered on one stream, no transcript change). It is now the code default; `=0` restores the
joined two-lane ingress.

### 2.4 Harness default (scripts/rv64_m3_pod.py)

`DEFAULT_NATIVE_SCHEDULE` replaces every plan job's `resources.schedule` (prove, bench and the resident daemon),
`RV64_NATIVE_SCHEDULE` overrides it for experiments; the 1-GPU route drops the affinity.

## 3. Measured results

Receipts: `vectors/reports/rv64-m6-20261105/native-stream/daemon-*.json` (+ `summary-*.json`), ledger
`vectors/reports/progress/native-stream.jsonl`. [M], single observations, resident service with warm store, pod
load 11-29 (not quiet-host quotable; compare within the table). Every request byte-identical to the M5 default.

| run | schedule | replay | 607 native s | 607 request s | 156 native s |
|---|---|---|---|---|---|
| e1-base (M5 binaries + M5 default) | 2 lanes x 4, shared queue | all replayed | 6.05 / 6.51 | 27.24 / 28.28 | 5.02 / 4.29 |
| e3-m5sched (this branch) | M5 | overflow only, 0 replayed | 5.33 | 27.55 | 4.20 |
| e3-replayall (this branch) | M6 default | all (RETAIN=0) | 5.69 | 27.94 | 4.23 |
| **e3-default (this branch)** | **4 x 2, affinity 2, heaviest first** | **overflow only, 0 replayed** | **4.18 / 4.35** | **25.24 / 25.28** | **3.49 / 3.13** |
| e3-cap64 | default + 64 GiB cap | overflow only | 4.35 | 25.84 | 3.32 |

e3-default spans on 24628607: stage one 1.53 / 1.67 s, stage two 2.38 / 2.41 s (M5: 2.22 + 4.03 s). Fresh
receiver accepted e3-default trial 0 on both blocks (42.8 s / 65.7 s). Recursion unchanged (18.0-18.1 s).

## 4. Not done in this stream yet (honest list)

- GPU witness widening from compact records (ZisK gpu-witness): the 56 B/row metadata is built during capture on
  the host (`word16_execution/cpu_source.zig` Scan) and uploaded once per segment; replacing it needs a device
  register-file scan (values + last-access clocks) and is not started.
- streaming stage one during capture (capture C1 hook): needs the coordinator (native-format) and the combined
  request path (sched) to admit per-segment statements before capture returns.
- streaming commit inside trace_commit.zig (enqueue owns the file), native CUDA graphs, AIR-batched launches.
