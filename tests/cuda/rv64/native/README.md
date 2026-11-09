# Standalone native CUDA tests and diagnostics

These programs are excluded from the production archive. Their bodies remain
with the live runtime policies they exercise.

`zig build test-cuda-runtime-contract` collects the four pure host C++ policy
programs through the pinned Zig toolchain, with assertions active in optimized
builds. They require no CUDA compiler, driver or device.

The admission fixture, preload observers and transform benchmarks retain their
separate hardware-harness ownership. Their include roots remain
`src/backends/cuda/native`, its `runtime` directory and its `rv64` directory.
Moving their sources does not qualify new binaries or authorize device runs.
