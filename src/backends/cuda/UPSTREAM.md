# CUDA Source Authority

The files under `vendor/upstream/` are an exact, unmodified import of:

- Repository: `https://github.com/teddyjfpender/stwo`
- Branch: `perf-optimizations`
- Commit: `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
- Git tree: `044f995e98ba6f2fdb5a1634a99c14927d7a93c0`
- Source path: `crates/backend-cuda-kernels/cuda`
- License: Apache-2.0

The files under `vendor/host_authority/` preserve the exact Rust host
orchestration that owns those kernels upstream:

- `crates/backend-cuda/`, including its resident proof-stage tests
- `crates/backend-cuda-kernels/{Cargo.toml,build.rs,src/}`

The shipped Zig CUDA product does not compile or link that Rust authority. It
exists so every Zig/C++ ABI and proof-stage port can name and compare against
the exact implementation being translated.

These imports deliberately include the generated AOT CUDA sources. Do not
reformat, partially regenerate, or hand-edit either directory. Update them as
one reviewed source-authority change and refresh both manifests with:

```sh
python3 scripts/cuda_source_closure.py --write
python3 scripts/cuda_source_closure.py
```

Zig build policy, C ABI declarations, proof-session ownership, telemetry, and
fallback rejection live outside `vendor/`. Imported upstream files are exempt
from the repository's source-file size guidance; new repository-owned files
are not.
