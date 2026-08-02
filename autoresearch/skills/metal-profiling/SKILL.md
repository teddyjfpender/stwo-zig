---
name: metal-profiling
description: Isolate a Metal kernel and measure real GPU time, pipeline reflection (occupancy limits, execution width, threadgroup memory), and approximate achieved bandwidth via the generic runner; wrap whole commands in Metal System Trace. Use for GPU performance questions — kernel cost, occupancy pressure, bandwidth ceilings, and submission-economics attribution — before touching backend code.
---

# Metal profiling for autoresearch

The tool is `autoresearch/cli/stwo-prof` (`metal` lane), backed by the
generic kernel runner in `autoresearch/tools/metal-prof-runner/`. It answers the two
questions every Metal change must answer: what does the kernel actually
cost on-device, and is the kernel even the problem?

Pair this evidence skill with `../metal-performance-design/SKILL.md` when the
task needs architecture, host-code, shader, synchronization, or render-pass
changes. Profile first, apply the relevant design pattern, then profile again.

## The loop

```bash
stwo-prof metal caps                              # device limits, once per host
stwo-prof metal isolate <name> [--from k.metal]   # scratch kernel dir
stwo-prof metal run <name> --entry <kernel> \
    --grid 1048576 --tg 256 \
    --buffers f32:1048576,f32:1048576,f32:1048576  # GPU ms + reflection
stwo-prof metal run <name> --entry <kernel> --sweep-tg  # occupancy curve
stwo-prof metal trace --output run.trace -- <cmd>  # full Metal System Trace
```

`run` and the sweep take `--json` and write `metal.json` / `sweep.json`
into the kernel dir for downstream reading.

The runner JIT-compiles the kernel (profiling lane only — production
admission still rejects JIT), binds buffers in declaration order with
deterministic fill, and times each dispatch with command-buffer
GPUStartTime/GPUEndTime: real device execution, not wall clock.

## Reading the numbers

- **`~GB/s touched` near the device ceiling** (measure the ceiling once with
  the demo add kernel at large sizes) → bandwidth-bound: fewer passes,
  smaller elements, better locality; more math per byte is free.
- **`maxTotalThreadsPerThreadgroup` in the PSO reflection below the device
  max** → register pressure is limiting occupancy: lower the declared max
  so the compiler widens registers, split the kernel only if spills persist.
- **`static_threadgroup_memory_bytes` near 32768** → threadgroup-memory
  bound: occupancy falls; on M3+ dynamic-caching parts, re-measure before
  assuming folklore tradeoffs.
- **GPU ms per dispatch below ~0.05 ms** → submission economics dominate in
  real use: the fix is fewer command buffers and waits (epochs), not a
  faster kernel. Check the whole-pipeline picture with `trace` before
  optimizing anything at kernel scope.

## Rules of engagement

- Kernel time under ~15% of request latency means kernel tuning cannot move
  the headline — attribute with `trace` (waits vs GPU busy) first; the
  playbook's submission-economics ordering is binding.
- The bandwidth estimate assumes each buffer element is touched once per
  dispatch — correct it for the kernel's real access pattern before quoting.
- A single point is not an occupancy conclusion: `--sweep-tg` runs the
  64..1024 threadgroup curve and marks the best point. Expect the optimum
  to move with the kernel — a memory-bound add peaks at a different width
  than a threadgroup-memory-heavy reduction.
- Device work must be provable: a "Metal win" without GPU-time evidence and
  dispatch counts is a hybrid-lane claim at best. Promotion-grade results go
  through `stwo-perf run`; this harness is the kernel-scope inner loop.
- Keep findings as `stwo-perf notes add` entries with device name, grid,
  threadgroup, and GPU medians inline.
