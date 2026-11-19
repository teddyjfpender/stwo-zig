# Native CUDA tests

[`contracts/`](contracts/) contains the Zig host tests assembled by the CUDA
tools build. They exercise Native application admission, proof structure and
terminal decoding through the real aggregate module graph. Run them from the
repository root with Zig 0.15.2.

```sh
zig build -Doptimize=ReleaseFast \
  test-cuda-blake-exact-structure test-cuda-plonk-logup-contract \
  test-cuda-poseidon-arena-contract test-cuda-state-machine-contract \
  test-cuda-xor-logup-contract
```

The C++ smoke entry points and their private reference headers live here.
[`cuda_device_smoke.py`](../../../scripts/cuda/cuda_device_smoke.py) discovers
`native_*_smoke.cpp` and builds each against the supplied CUDA archive.
It requires a CUDA toolkit and one visible NVIDIA device. The shared
fixtures used by the Native and Cairo suites live in [`../fixtures/`](../fixtures/).
The `.cu` and `native_oods_multiblock.cpp` harnesses are separate from the
smoke runner's automatic inventory.
