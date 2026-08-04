# CUDA source authority

The files under `vendor/host_authority/` preserve one self-contained, exact
projection of the upstream Cargo workspace:

- root Cargo lock, workspace manifest, toolchain, formatting, and license files;
- all workspace crates, including `backend-cuda` and its resident proof-stage
  tests; and
- the full `backend-cuda-kernels` crate, including its generated AOT sources.

The CUDA kernel authority used by the Zig build is the subtree at
`vendor/host_authority/crates/backend-cuda-kernels/cuda`. It is an exact,
unmodified import of:

- Repository: `https://github.com/teddyjfpender/stwo`
- Branch: `perf-optimizations`
- Commit: `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
- Git tree: `044f995e98ba6f2fdb5a1634a99c14927d7a93c0`
- Source path: `crates/backend-cuda-kernels/cuda`
- License: Apache-2.0

The repository previously tracked the same 458 kernel files a second time at
`vendor/upstream`. The two trees were byte-identical. Keeping the kernel
subtree inside the complete host authority preserves every source byte and
both immutable closure manifests without carrying a second 658,194-line
checkout.

The final Zig-owned CUDA proof engine does not compile or link this Rust
authority. The isolated `tools/stwo-cuda-adapter-rs` bring-up product does: it
is the same-source migration oracle used to qualify copied kernels, discover
missing AOT coverage, and compare canonical proofs while the Zig host
orchestration is ported.

This import deliberately includes the generated AOT CUDA sources. Do not
reformat, partially regenerate, or hand-edit it. Update it as one reviewed
source-authority change and refresh both manifests with:

```sh
python3 scripts/cuda_source_closure.py --write
python3 scripts/cuda_source_closure.py
```

Zig build policy, C ABI declarations, proof-session ownership, telemetry, and
fallback rejection live outside `vendor/`. Imported upstream files are exempt
from the repository's source-file size guidance; new repository-owned files
are not.
