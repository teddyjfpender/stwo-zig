# CUDA Source Authority

The files under `vendor/upstream/` are an exact, unmodified import of:

- Repository: `https://github.com/teddyjfpender/stwo`
- Branch: `perf-optimizations`
- Commit: `1d1d10c31fdac45c9ecb7aee9d3e8935b5cf8035`
- Git tree: `044f995e98ba6f2fdb5a1634a99c14927d7a93c0`
- Source path: `crates/backend-cuda-kernels/cuda`
- License: Apache-2.0

This import deliberately includes the generated AOT CUDA sources. Do not
reformat, partially regenerate, or hand-edit this directory. Update it as one
reviewed source-authority change and refresh `source_manifest.json` with:

```sh
python3 scripts/cuda_source_closure.py --write
python3 scripts/cuda_source_closure.py
```

Zig build policy, C ABI declarations, proof-session ownership, telemetry, and
fallback rejection live outside `vendor/upstream/`. Imported upstream files are exempt
from the repository's source-file size guidance; new repository-owned files are
not.
