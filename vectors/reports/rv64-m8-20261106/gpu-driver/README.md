# M8 GPU-native: driver stream (codex/rv64-m8-gpu-driver)

Design: `design/riscv-proving-stack/rv64-m8-gpu-native.md` §3.4–3.8, §6 (driver). Flag: `STWO_RV64_M8_GPU_NATIVE=1`, which requires `STWO_RV64_M8_JOBS=1`. It is default off, and the default and feeder paths are byte-unchanged.

## What landed

| piece | file | status |
|---|---|---|
| Request batches, no per-job host wait (`call`, `runBatch`, `finishBatch`, fenced `requestWait`), plan arena (`installPlanArena`, two-phase) | `rv64/jobs/worker.zig` | host D1 + pod D3 |
| Peer/slab/check/timing ops (additive symbols, ABI unchanged) | `NAT/rv64/jobs/peer_ops.cu`, `ops.zig Peer`, `fake.zig` | pod D3 |
| DAG and placement, global topological order, phase-B marks | `rv64/jobs/driver_dag.zig` | host |
| Two-phase memory plan per GPU | `rv64/jobs/driver_memory.zig` | host |
| `PeerExchange` with a per-request generation protocol | `rv64/jobs/driver_peer.zig` | host + pod |
| Install + request: classes, layout, prefix h2d, unset fills, batches, one D2H per GPU, final join, `exchange_complete` device check, ONE host wait, publish | `rv64/jobs/driver_request.zig` | host D1 + pod D3 |
| Capture hand-off (pinned ring, `CaptureSink`, Stage1 release per sealed segment) | `rv64/m8_capture_stream.zig` | host |
| Request switch (fails closed while the factories are stubs) | `rv64_combined_ethereum_main.zig`, `rv64/jobs/driver_serve.zig` | build |
| D2 lint: driver allocations and events only inside install fences | `rv64/jobs/lint.zig` | host |
| D3 probe (`rv64-jobs-channel-parity gpu-native N S [negative]`) | `rv64/jobs/driver_probe.zig` | pod |

## Evidence

**D1 (host, 2 fake GPUs, `zig build test-rv64-jobs`).** Each request has exactly 1 host wait, 2 slab D2H and 2 prefix h2d, with 0 device allocations after install. Further cases:
- the seal runs only after every root and claims slot was awaited;
- publication refuses an unset word, a reject code, an encoder overrun (even with an accepted bounds word) and a stale header;
- two pipelined requests do not cross slabs;
- a class that was never warmed fails closed before any device work;
- capture releases Stage1 per sealed segment, and a short capture poisons the unsealed segments.

The local run (Debug, under memguard) finished 14/14 build steps, with 388 of 393 tests passed and 5 pre-existing skips.

**D3 (pod, both RTX 5090s, Debug build), `d3-probe.json`.** Each request has 7 segments, 2 truths and 17 recursion nodes: 34 device jobs and 26 published proofs.
- **Positive: 6/6 requests byte-exact [M].** Each had host_waits = 1 and d2h = 2.
  - GPU span per device was 1.03–1.24 ms by CUDA events [M].
  - Request wall time was about 11.7 ms [M].
- **Negative [M]:** one claims publish is withheld. The seal's device check `global_seal` rejected with word `0x0103000b` (flag index 10 = claims of segment 3), and the request was refused.
- **Peer ping-pong:** 31.8 µs per hop over 1000 hops, with 1 host wait [M].
  - **P2P is unavailable on this pod:** `nvidia-smi topo -p2p r` reports CNS for the GPU0↔GPU1 pair. `cudaMemcpyPeerAsync` stages these copies through the host.
- **Host time per request [M, Debug build]:**

  | step | time |
  |---|---|
  | plan | 2.5 ms |
  | make (factory calls) | 2.4 ms |
  | enqueue | 1.3 ms (both GPUs in parallel) |
  | gate latches | ≤ 0.6 ms on GPU 1 |
  | wait (after enqueue) | ≤ 0.02 ms |
  | finish | 1.6 ms |
  | publish | 2.1 ms (copies 26 × 4 KB) |

  These are Debug numbers, so release numbers should be lower; this was not measured [E].

**Environment.** The orphan service (pid 3302210, from m8-native-hybrid) holds 30.1 GB on each GPU. The D3 run therefore needed `STWO_RV64_DEVICE_ARENA=0`, because the VMM arena could not initialize with 1.57 GB free [M].

## Not done here (blocked or owned elsewhere)

- **D4/D5 (real factories, 26235156 and 24628607 under GPU_NATIVE):** these need the native and recursion stream factories. `native_device` and `outer_device` are stubs, so selecting the flag fails closed at warm.
- **The gate proof step and the JOBS=1 gate:** blocked by the orphan GPU holder. See `gate-1` on the pod.
