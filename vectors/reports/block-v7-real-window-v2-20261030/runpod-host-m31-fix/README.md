# Corrected Linux source and shared CPU/GPU executable

The immutable original export remains at `/workspace/stwo-v7`. The corrected tree at `/workspace/stwo-v7-fixed` is an independently copied source tree, with no shared mutable inodes. The patch changes only four manifest-listed files: the x86 scalar M31 correction and its embedded regressions, the explicit CPU-reference wrapper, and the CLI plus its tests.

Reconstruct the corrected source by applying `source-patch.tar.gz` to the original archive pinned by `patch-manifest.json`. Verify every original file hash before replacement and every resulting file against `export-manifest.json`. The patch includes the resulting full export manifest. Original failing binaries and diagnostics remain unchanged.

The CUDA native archive is reused byte-for-byte because no CUDA kernel, ABI, native AOT generator, or explicit kernel build input changed. The host Zig scalar M31 correction requires rebuilding the numeric oracle and prover executable. It does not justify reusing the old host executables.

`numeric-build.json` records the corrected numeric executable. `wrapper-build.json` records the successful shared prover build (binary SHA `0a1289c345efa37f50a04f95a17d93c6f6ca097c1415f00b2f4c24e759dda48a`). Both builds rehashed all 9,360 exported files before and after code generation and confirmed the corrected snapshot unchanged. CPU-reference and CUDA selection use the same executable, with explicit mode attestation; a requested CUDA execution must not fall back to CPU. Numeric device parity does not by itself qualify a genuine execution proof.
