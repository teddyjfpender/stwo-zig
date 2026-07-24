---
name: cuda-profiling
description: Attribute CUDA prover latency with product stage events, NVTX, Nsight Systems, and Nsight Compute while preserving an uninstrumented verified-request verdict. Use before changing CUDA schedules, memory passes, kernels, streams, graphs, allocation, or module loading.
---

# Profile CUDA proof execution

Use `autoresearch/cli/stwo-prof cuda` and the structural controller. The first
question is where complete verified-request time goes. Kernel tuning begins
only after lifecycle and device-stage attribution identify a dominant kernel.

## Inner loop

```bash
export PATH="$PWD/autoresearch/cli:$PATH"

stwo-prof cuda caps
stwo-prof cuda report product-report.json
stwo-prof cuda systems --output proof.nsys-rep -- \
  zig-out/bin/stwo-zig-native-cuda prove <fixed-arguments>
stwo-prof cuda compute --output commitment.ncu-rep \
  --kernel '<dominant-kernel-regex>' --set detailed -- \
  zig-out/bin/stwo-zig-native-cuda prove <fixed-arguments>
```

For production-shaped evidence:

```bash
python3 scripts/native_cuda_benchmark.py \
  --candidate-bin zig-out/bin/stwo-zig-native-cuda \
  --profile screen --output cuda-screen.json
```

Use `judge` only with immutable candidate and baseline products on the locked
CUDA host. Large captures are diagnostic and should use the smallest shape that
reproduces the mechanism.

## Order of attribution

1. Confirm exact proof identity, Zig verification, AOT identity, device
   identity, zero fallback, and one terminal D2H.
2. Separate cold process, runtime initialization, shape preparation, first
   request, warm steady request, verification, and teardown.
3. Rank CUDA-event proof stages.
4. Use Nsight Systems for launch gaps, implicit synchronization, allocation,
   module loads, stream overlap, transfers, and CPU starvation.
5. Use Nsight Compute only for kernels accounting for meaningful critical-path
   time.
6. Rerun the uninstrumented structural controller for the verdict.

## Nsight Systems questions

Record:

- context and module creation relative to the request boundary;
- kernel count and launch-gap distribution;
- stream count, concurrent kernel intervals, and dependency waits;
- `cudaDeviceSynchronize`, stream/event synchronizations, and blocking copies;
- H2D, D2H, and D2D operations and bytes;
- allocation/free calls and memory-pool behavior;
- graph instantiate, update, and launch activity;
- CPU submit-thread gaps;
- GPU active fraction over the resident proof.

Do not infer concurrency from stream count. Overlap exists only when timeline
intervals overlap and the critical path shrinks.

## Nsight Compute questions

For each dominant kernel retain:

- kernel identity, grid/block size, dynamic shared memory, and input shape;
- duration and contribution to complete device time;
- DRAM and L2 bytes, hit rate, and achieved bandwidth;
- arithmetic throughput and instruction mix;
- achieved occupancy, active warps, and limiting resource;
- registers/thread, local-memory traffic, and spills;
- warp divergence, issue stalls, and memory dependency stalls.

Translate counters into a falsifiable diagnosis: bandwidth, latency, compute,
occupancy, launch fragmentation, or dependency serialization. Occupancy alone
is not a performance objective.

## Experiment record

Every hypothesis states:

```text
program and shape:
binary/module/toolchain/device identities:
verified-request and device-stage baseline:
dominant mechanism:
predicted launches/passes/bytes/counter movement:
code change:
exact parity gates:
instrumented diagnostic result:
uninstrumented ABBA result:
peak memory and fallback delta:
decision: keep / reject / investigate
```

## Rejection rules

Reject or relabel evidence when:

- source, binary, module, toolchain, protocol, statement, or device drifts;
- a proof differs, fails independent verification, or misses the Rust oracle;
- PTX JIT, CPU fallback, compilation, or an intermediate D2H occurs;
- profiler replay time is quoted as production time;
- a large win moves work outside the measured verified-request boundary;
- temperature, power, or co-tenant load makes paired evidence nonstationary;
- one Fibonacci shape wins while another structural class regresses.

## Current priority

The retained-plan RTX 4090 profile attributes about 83% of `log20 x 100`
device time to trace commitment. Investigate commitment/Merkle global-memory
passes, launch topology, and tree residency before tuning trace construction.
Preserve this as a hypothesis until Nsight evidence is retained.
