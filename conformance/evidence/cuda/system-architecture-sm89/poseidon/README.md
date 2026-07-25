# Integrated Poseidon CUDA Evidence

Date: 2026-07-24
Source branch: `feature/cuda-system-architecture`
Source commit: `451dd5b5`
Device: NVIDIA GeForce RTX 4090, SM89
Driver/runtime/toolkit: 13.0 / 12.8 / 12.8

## Purpose

This is post-integration correctness evidence. It checks the Poseidon product
route after the authenticated-cubin ABI and single-stream scheduler changes
were present together. It is not a performance verdict: the source was copied
without its Git directory, so the embedded product report correctly marks the
remote tree dirty.

## Result

- Graph and direct modes produced identical `112,834`-byte canonical proofs.
- Canonical proof SHA-256:
  `af33240da8e7947362fdf7e78d306f2e11cb2e3df7e1b6f498a6e86ac3ae7b1b`.
- Repeated graph and direct requests were byte-stable.
- Zig verification passed in both modes.
- The local pinned Rust Stwo verifier accepted the copied graph artifact.
- Strict AOT loaded two functions with zero misses and zero launch failures.
- CPU fallback attempts and completions were both zero.
- Each request performed one terminal D2H operation.
- Accounted peak live device memory was `3,079,616` bytes.
- Steady graph resident samples were `2.396 ms` and `2.377 ms`.
- Steady direct resident samples were `2.477 ms` and `2.475 ms`.

The first repetition includes graph construction and other cold shape work and
is not reported as a steady request.

## Artifacts

- `graph-summary.json`
- `direct-summary.json`
