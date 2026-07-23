# Native CUDA Bring-Up Adapter

This isolated tool drives the exact copied
`teddyjfpender/stwo@1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
CUDA backend over the repository's Native proof-exchange workloads.

It is a migration and hardware-qualification instrument, not the final
Zig-owned CUDA proof engine. The adapter exists to establish:

- copied-source build viability on each supported NVIDIA SM;
- Native CUDA versus Zig CPU canonical proof parity;
- pinned Rust verifier acceptance;
- strict-AOT coverage and missing-kernel rejection; and
- same-process stability and baseline performance.

`--cuda-kernel-policy strict-aot` is the default. It closes runtime compilation
before proof work and rejects any missing or runtime-origin generated kernel.
`jit-diagnostic` is explicitly non-promotable; it is useful for discovering
Native AIR kernels that must be added to the copied AOT pack.

The tool fails before proving when it was built without CUDA. A successful
non-CUDA Cargo build is only source/build-contract evidence.

```sh
cargo +nightly-2025-07-14 run --release --locked \
  --manifest-path tools/stwo-cuda-adapter-rs/Cargo.toml -- \
  --mode bench \
  --backend cuda \
  --cuda-kernel-policy strict-aot \
  --example wide_fibonacci \
  --artifact /tmp/stwo-cuda-wide-fibonacci.json \
  --wf-log-n-rows 20 \
  --wf-sequence-len 100 \
  --bench-warmups 10 \
  --bench-repeats 7
```

The executable writes its standard benchmark report to stdout and a
`stwo-zig-cuda-kernel-receipt-v1` line to stderr. Neither is release evidence
without the repository-owned proof parity, oracle, residency, and device
receipts.
