# Portable real-window experiment

The export is a dirty-worktree snapshot from the Lab checkout, not a Git commit. `scripts/v7_runpod_bundle.py` selects only `src`, `build_support`, source scripts, the two root Zig build files, explicit corpus files, and the existing CUDA graph’s exact `vectors/cairo/official` / `sn_pie_2_witness_programs.bin` AOT build inputs. Hidden files, cache/build outputs, other workspaces, audit records, host binaries and Git metadata are excluded. Symlinks are rejected. The archive contains a manifest and SHA256SUMS and detects source changes while reading the archive payload. Final packaging must happen after all participating source lanes are frozen.

```
python3 scripts/v7_runpod_bundle.py \
  --manifest /tmp/stwo-v7-export-manifest.json \
  --archive /tmp/stwo-v7-runpod-source-corpus.tar.gz
```

For corpus-only transport use `--corpus-only`. The five declared incoming/outgoing states preserve the exact ELF, original input provenance, capture manifests and selected-address artifacts. Every state identity is recomputed from the canonical capsule encoding. Source package generation does not provision a pod or upload data.

## Linux CPU baseline

Use Zig **0.15.2**, Python3, x86_64 Linux. All Zig dependencies are local package contracts. On the Linux machine:

```
sha256sum -c SHA256SUMS
python3 scripts/zig_protocol_test.py --lock /tmp/stwo-zig-build.lock \
  src/frontends/riscv/block_v7_real_window_v2_benchmark_root.zig \
  -target x86_64-linux-gnu -mcpu=native -OReleaseSafe -fstrip \
  --test-no-exec -femit-bin=/tmp/v7-original-window
python3 scripts/zig_protocol_test.py --lock /tmp/stwo-zig-build.lock \
  src/frontends/riscv/block_v7_real_window_root_test_root_v2.zig \
  -target x86_64-linux-gnu -mcpu=native -OReleaseSafe -fstrip \
  --test-filter 'v7 real nonterminal window' \
  --test-no-exec -femit-bin=/tmp/v7-recursive-window
```

Cross-compilation from macOS uses `-mcpu=baseline` and `--test-no-exec`; never run the resulting Linux binary on macOS. The direct protocol wrapper propagates `-target` into every module, rather than leaving imported modules on the host target. Record before/after source manifest, exact compiler identity, binary hashes, command, device/CPU identity and flags before benchmarking. Existing macOS build receipts cannot identify a newly built Linux binary.

## CUDA native archive

No matching current native archive was found in this checkout. Historical SM89 receipts are not sufficient to reuse a binary. The hybrid executor initially uses existing execution-context, addressed quotient-numerator, compact quotient-combination, device and build-identity ABIs. It accelerates DEEP quotient work only; CPU composition, transcript and Blake3 remain CPU work. No GPU performance or correctness result is claimed before hardware qualification.

Build the archive from the same frozen source and generated native AOT catalog; select the actual device SM (do not infer it from a pod product name):

```
zig build --build-file build_support/internal_build.zig \
  -Drepository-root="$PWD" -Dproduct-scope=cuda_tools cuda-native-archive \
  -Dcuda-nvcc=/usr/local/cuda/bin/nvcc \
  -Dcuda-host-cxx=/usr/bin/g++ -Dcuda-ar=/usr/bin/ar \
  -Dcuda-home=/usr/local/cuda \
  -Dcuda-library-dir=/usr/local/cuda/lib64 \
  -Dcuda-arch=90 -Dcuda-build-jobs=2
```

The existing internal product entry is intentional: the top-level dispatcher probes Git identity, whereas this export deliberately omits `.git`. Build identity is the full export manifest and its per-file hashes; no clean-commit claim is fabricated. The extracted package passed `cuda-build-plan` through this same entry, generating 48 native entries / 33 witness programs without external checkout files.

`90` (SM90) is an example, not a selected device. Link runtime tools with the exact installed C++ and unwind runtimes, normally `/usr/lib/x86_64-linux-gnu/libstdc++.so.6` and `/usr/lib/x86_64-linux-gnu/libgcc_s.so.1`. Capture compiler/CUDA version, architecture, active source/product manifests, generated catalog identity and archive SHA. A prebuilt archive is reusable only when all source/build/ABI/architecture identities match the requested adapter. The final CUDA wrapper command is supplied with its qualified build target; an unavailable generic `riscv` build product is not a substitute.

The selected incoming states are explicit benchmark inputs. Neither this export nor a successful window root proves the preceding skipped execution or a complete Ethereum block. Run both source-only and final-root paths, require fresh CPU verification and exact declared executor invocation counts, and report transfers/setup separately from kernel work. A selected GPU executor must return errors rather than silently use CPU numerical work.


## Qualified build handoff on the H200 host

The final export is 127,881,389 bytes, SHA256 `3d87bd0147fdd9bb30e240bafa1fa49bb211ccb51832645780ad21f2392e62d1`; its explicit source-tree digest is `30f30e2e98d3680d3b8e49b122831092fcea6287b4a1a04b26007b898270a2a9`. All 9,360 extracted file hashes were checked. The pod downloaded official Zig0.15.2 and verified tarball SHA `02aa270f183da276e5b5920b1dac44a63f1a49e55050ebde3aecc9eb82f93239` against the saved official index.

The exact SM90 native archive built in 170.015s with 16 nvcc jobs, CUDA12.8.93 and driver575.57.08. Its 20,322,342-byte static library has SHA256 `b7a38a6cc73fe5aeb61945fdfaddac2f4b06a7cfc9349e7277981a05fe726128`. All fourteen ABI exports required by the adapter are present. ccache is installed, but the qualified archive command uses the actual nvcc executable and the existing source-keyed AOT cache; it does not claim ccache hits.

Actual device-test codegen additionally requires `-L/usr/lib/x86_64-linux-gnu` for the driver library, and explicit `-target x86_64-linux-gnu.2.39` for this host's C++ runtime ABI. A generic GNU target selected an older glibc ABI and correctly failed linking; undefined-symbol checks were not relaxed. Use the detected host glibc version on another host. Link with `-lc`, the exact archive, `-L/usr/local/cuda/lib64 -lcudart -lcuda`, explicit libstdc++/libgcc shared libraries and a CUDA runtime rpath. These are build results, not GPU execution qualification.

Bootstrap, archive/AOT hashes, failed/successful build commands and tool versions are retained under `vectors/reports/block-v7-real-window-v2-20261030/runpod-bootstrap/`. The allocated 16 vCPU / 251GB host share must not be confused with the physical host's larger CPU and RAM totals.
