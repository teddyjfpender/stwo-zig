# RV64 CUDA numerical qualification

These tests are based on PR310's native OM31/GKR construction. They do not
produce an Ethereum execution proof, a recursion root or a security certificate.
The production proof receiver and its fail-closed admission are unchanged.

## Host numerical checks

`independent_field.py` compiles the actual CUDA arithmetic header on the host
and checks basis, edge and random products against an independent schoolbook
Python polynomial tower. The host shim declares no CUDA driver functions and
cannot execute a GPU path.

```sh
python3 tests/cuda/rv64/independent_field.py
zig build test test-rv64-numerical --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseSafe -j2
zig build test test-rv64-numerical --build-file src/integrations/riscv_cuda/build.zig -Doptimize=ReleaseFast -j2
```

The Zig/C++ bridge checks full-coordinate multiplication and fractions against
native OM31, and the raw sumcheck arithmetic against the actual native GKR
polynomial for base and secure numerators at sizes 4, 8, 16, 256 and 1024.
These are numerical host checks, not device parity or the final pinned Rust
protocol oracle gate. That gate and full receiver parity remain pending.

## Compile and run on NVIDIA hardware

Use CUDA >=12.8 with support for `sm_89` and `sm_120`. Match toolkit headers,
compiler and libraries; install NVTX3 headers for the existing context runtime.
`CUDA_HOME` and `NVTX_INCLUDE` below are explicit toolchain locations.

```sh
"$CUDA_HOME/bin/nvcc" -O3 -std=c++17 \
  -gencode arch=compute_89,code=sm_89 \
  -gencode arch=compute_120,code=sm_120 \
  -Isrc/backends/cuda/native -I"$NVTX_INCLUDE" \
  src/backends/cuda/native/rv64/gkr.cu \
  src/backends/cuda/native/runtime/context.cu \
  tests/cuda/rv64/resident_smoke.cu \
  -Xcompiler=-pthread -ldl -o /tmp/rv64-resident-smoke

/tmp/rv64-resident-smoke 2 20
/tmp/rv64-resident-smoke 4 20
compute-sanitizer --tool memcheck /tmp/rv64-resident-smoke 2 10
compute-sanitizer --tool racecheck /tmp/rv64-resident-smoke 2 10
compute-sanitizer --tool synccheck /tmp/rv64-resident-smoke 2 10
```

Run sizes log2=2,3,4,8,9,10,16,20,22 to cover tiny/tail/multi-level reductions.
The harness uses the real existing context, async allocation registry, ingress
and compute streams, event dependency and joined teardown. One owner thread per
requested device enqueues independent work concurrently. A missing driver/device
exits **77 (skipped)**; an insufficient requested device count fails. No fallback.

Every device run checks projection, EqEvals, one/two-level trees, raw sumcheck
and half-split folding, both base and secure numerator paths, plus overlap,
lane, geometry, canonicality and sticky-pole rejection. Host reference evaluation
and readbacks are outside the timed region. Hot waves reuse every allocation
and transfer no host data; setup transfers and validation readbacks still occur.
Timings are median CUDA-event durations of 11 waves after 3 warmups. Each wave
contains projection, trees, Eq construction, sumcheck and folding; it is not a
single GKR proof, a throughput score or complete-block latency. Output records
explicitly set `full_block_verified=false`.

Before comparing 2/4x4090 against 2/4x5090, record UUIDs, GPU clocks/power,
PCIe topology, free/reserved/peak memory, driver/toolkit, source/binary digests,
CPU/NUMA placement, device timings and process wall time. Use Nsight Systems
to verify overlap and zero hot-loop copies, and Nsight Compute for achieved
occupancy, memory throughput, spills and launch distribution. Compilation's
register count alone is not a utilization measurement.

Custody checks can also run without a driver, using toolkit enum declarations:

```sh
g++ -std=c++17 -O2 -Wall -Wextra -Werror \
  -I"$CUDA_HOME/include" -Isrc/backends/cuda/native \
  tests/cuda/rv64/custody_test.cpp -o /tmp/rv64-custody-test
/tmp/rv64-custody-test
```

This intentionally mocks only the registry/stream boundary to exercise byte
units, bounds, overlap and error propagation. It does not authenticate real
CUDA allocation ownership; the hardware test exercises the actual registry.
