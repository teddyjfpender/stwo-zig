# RV64 M3 pod recipe (stream infra, 2026-11-04)

Copied to `/workspace/m3/RECIPE.md` on the pod. Harness: `scripts/rv64_m3_pod.py`
(branch `codex/rv64-m3-infra`). Owner rule: develop and measure only on
**26235156** and **24628607**. The harness refuses other blocks unless you pass
`--allow-scale-up`, which is reserved for the final ordered scale-up.

## 0. One-time per stream: merge the harness

```sh
cd ~/Coding/ge-wt/rv64-m3-<s>
git fetch origin codex/rv64-m3-infra && git merge --no-edit origin/codex/rv64-m3-infra   # or cherry-pick
```

You need `scripts/rv64_m3_pod.py` and the two updated `scripts/rv64_cuda_*_build.py`
in your tree, because the pod runs the copy that is in your synced source.

## 1. Sync (laptop)

```sh
cd ~/Coding/ge-wt/rv64-m3-<s> && git rev-parse --short HEAD > .m3-commit
~/Coding/ge-ops/bin/podsync ~/Coding/ge-wt/rv64-m3-<s> <s>        # -> /workspace/m3/src/<s>
```

`.m3-commit` is recorded in build and run receipts. Add it to `.git/info/exclude`.

## 2. Build (pod, CPU only, no GPU lock)

```sh
~/Coding/ge-ops/bin/pod 'tmux new -d -s <s>-build "cd /workspace/m3/src/<s> && python3 scripts/rv64_m3_pod.py build --stream <s> --jobs 24 > /workspace/m3/runs/<s>/build.log 2>&1; echo EXIT=\$? >> /workspace/m3/runs/<s>/build.log"'
```

Outputs go to `/workspace/m3/build/<s>/`:

- `zig-out/bin/rv64-word16-ethereum-gpu-combined` is the production driver. It is the
  `combined-batch` binary behind `assets/ready-fixed-driver`, built from
  `src/integrations/riscv_cuda/build.zig`, step `build-rv64-ethereum-gpu-combined`,
  with flags `-Dtarget=x86_64-linux-gnu -Dcpu=x86_64_v4+sha -Doptimize=ReleaseFast`. Do not
  drop `-Dcpu`: `-Dtarget` alone selects baseline x86-64 with no AVX-512 or SHA, while
  the accepted driver uses both.
- `zig-out/bin/rv64-word16-ethereum-recursion-receiver` is the independent CPU-only
  receiver (step `build-rv64-ethereum-recursion-receiver`).
- `cuda/native/libstwo-rv64-native.so` is the CUDA runtime image, built by
  `scripts/rv64_cuda_resident_image_build.py`.
- `build.json` records the hashes and timings.

Use `--only zig` or `--only cuda` to rebuild one half.

### Incremental behaviour

- **zig**: the per-tree cache is `/workspace/m3/src/<s>/.zig-cache`, which podsync
  preserves, and the global cache is `/workspace/m3/cache/zig-global`. A cold driver
  build took 342 s on a loaded pod. Zig compiles the driver as a single module, so
  **any `.zig` edit costs about 320 s** for the driver and about 270 s for the receiver.
  Batch your edits, and use `--only zig`.
- **CUDA**: every object goes into the shared, content-addressed store
  `/workspace/m3/cache/cuda-objects`.
  - The key is the nvcc version, the flags with tree prefixes tokenized
    (`@ROOT`, `@BUILD`, `@CAT`) and the source sha256.
  - On a hit, every dependency recorded by `nvcc -MD` is re-hashed inside *your* tree.
  - So a stream that changes one `.cu` file or header recompiles only the translation
    units that depend on it, then relinks. Any stream's first build reuses the
    objects that infra already compiled.
- **AOT catalogues** (`/workspace/m3/catalogues`, read-only) are frozen generated
  inputs, copied from `/workspace/rv64-native-cpu-rebuild-package/catalogues`; the tree
  sha256 is in the infra receipts. If your stream changes the native AIR or the outer
  circuit kernels, regenerate the catalogues into your own directory and build with
  the image script directly.

## 3. Prove (pod, takes the GPU lock itself)

```sh
~/Coding/ge-ops/bin/pod 'mkdir -p /workspace/m3/runs/<s>; tmux new -d -s <s>-p "cd /workspace/m3/src/<s> && python3 scripts/rv64_m3_pod.py bench 24628607 --gpus 2 --stream <s> --tag try1 > /workspace/m3/runs/<s>/try1.log 2>&1; echo EXIT=\$? >> /workspace/m3/runs/<s>/try1.log"'
~/Coding/ge-ops/bin/pod 'tail -30 /workspace/m3/runs/<s>/try1.log'
```

- `bench` runs `prove` and then `receive`. `prove` takes `fcntl` locks on
  `/workspace/m3/locks/gpu.lock` (both GPUs, 7200 s wait) for the producer only. The
  lock is compatible with `flock -w 7200 /workspace/m3/locks/gpu.lock`.
- Run directory: `/workspace/m3/runs/<s>/<block>-<n>gpu-<tag>/`. It contains `plan.json`,
  `request.json` and `case/` (producer logs, `batch/trial-0/<block>/proof/`), and its
  `receipt.json` holds:
  - `stages`: request wall, capture, setup, native prove, native verify and recursion,
    in seconds;
  - `producer_process`: wall, user, sys, RSS and faults;
  - `gpu` (kernel launches, device ms) and `physical_gpu_memory_peak`;
  - `recursion.numeric` and `recursion.counters`, which carry the full recursive report;
  - `proof_sha256`: native, bundle and every recursive proof plus the tree;
  - `parity_vs_accepted_v7`: `byte_identical`, with mismatched names;
  - `receiver`: verdict, process usage and argv. `accepted` is true only when the
    receiver accepts and the output matches the pin.
- Options:
  - `--env STWO_RV64_X=1` sets producer environment toggles; repeat it for several.
  - `--driver`, `--library` and `--receiver` override the binaries.
  - `--nsys` records an Nsight Systems timeline in `run/nsys/`.
  - `--gpus 1` runs one lane on GPU 0.
- `receive <block> --run <dir>` re-runs only the independent receiver. It is a separate
  process with `CUDA_VISIBLE_DEVICES=""`, PCS helper `/bin/false`,
  `STWO_ZIG_RV64_SETUP_CACHE` unset, mode `verify-recursion-candidate` and a 32 GiB live
  cap. It does not need the GPU lock. Measured wall: 44 s for 26235156 and 66 s for 24628607.
- `parity --run <dir>` recomputes byte parity against accepted v7.

## 3b. Reference numbers (infra, measured, 2x5090, one observation each)

All runs use the head-fbb6c6c76 source driver. Proofs are byte-identical to
accepted v7, and the fresh Linux receiver accepts.

| block | request | capture | setup | native prove | native verify | recursion |
|---|---:|---:|---:|---:|---:|---:|
| 26235156 | 65.4 s | 3.3 | 9.3 | 6.1 | 3.6 | 42.9 |
| 24628607 | 100.7 s | 4.8 | 13.0 | 10.8 | 5.6 | 66.4 |

These runs used the accepted library (25295868). For runs with the from-source
image, see `vectors/reports/rv64-m3-20261104/infra/`.

## 4. Parity rule

A scheduling-only change must give `parity_vs_accepted_v7.byte_identical == true` for
both dev blocks. A proof-changing change must use a new named profile or version. Its
receipt will show parity false: say so, write the soundness argument, and rely on
`receiver.accepted == true` from a receiver built from *your* tree.

## 5. Copy receipts back

```sh
~/Coding/ge-ops/bin/podget /workspace/m3/runs/<s>/<run>/receipt.json vectors/reports/rv64-m3-20261104/<s>/<name>.json
```
