# Bend second pass: larger transforms and complete backend calls

Continues [PR #199](https://github.com/teddyjfpender/stwo-zig/pull/199), stacked
on [PR #198](https://github.com/teddyjfpender/stwo-zig/pull/198) at
`1358234f1e8a2ac34241658dcd3505bad5feb1fc`. CPU only, pinned Bend 2.0.5,
Zig 0.15.2, existing Zig SIMD width 8. This host exposes an eight-CPU quota and
20 GiB memory limit; frequency and other host activity are uncontrolled.

## Result

Bend improves substantially over the first pass, but does **not** beat Zig.
Log22/log24 do not produce a crossover. The actual parity-checked backend and
combined 2x LDE are also slower. No GPU or full-proof throughput claim is made.

Changes remain arithmetic in Bend: flat-buffer butterfly loops, sequential fused
256-value subtransforms, 1024-value butterfly chunks, 4096-value normalization,
multiplication and prefix chunks. Canonical M31 addition/subtraction now use one
conditional reduction because their sums are below twice the modulus. No U64,
foreign arithmetic, generated-C edits, relaxed equality or oracle changes.

## Paired improvement over the original Bend implementation

Three alternating baseline/candidate pairs per cell, identical log20 input and
thread count; every output equals Zig. Speedup >1 means the candidate is faster.
These are repeat measurements, not ratios between separate historical runs.

| Operation | Threads | Compute speedup | Native process wall speedup |
|---|---:|---:|---:|
| fft | 1 | 5.46x | 4.18x |
| fft | 8 | 2.99x | 2.14x |
| ifft | 1 | 5.40x | 4.08x |
| ifft | 8 | 2.66x | 1.93x |
| multiply | 1 | 3.37x | 1.81x |
| multiply | 8 | 1.69x | 1.27x |
| prefix | 1 | 13.25x | 4.22x |
| prefix | 8 | 1.14x | 1.02x |

Eight-thread prefix has only a 1.14x kernel / 1.02x process improvement; this is
not a robust end-to-end gain. Single-thread prefix is much faster than before,
but remains slower than Zig. See `paired.json` for all raw samples and RSS.

## Kernel comparison with Zig

Three-sample medians, one column, eight Bend threads. Compute excludes request
and plan construction, process launch and serialization; IFFT includes scaling.
Zig uses the existing optimized implementation, not a new scalar reference.

| Operation | Log | Bend ms | Zig ms | Bend / Zig |
|---|---:|---:|---:|---:|
| fft | 20 | 52.815 | 5.780 | 9.14x |
| fft | 22 | 199.807 | 26.098 | 7.66x |
| fft | 24 | 2141.827 | 119.158 | 17.97x |
| ifft | 20 | 52.944 | 4.843 | 10.93x |
| ifft | 22 | 197.167 | 23.173 | 8.51x |
| ifft | 24 | 1168.097 | 97.051 | 12.04x |
| prefix | 20 | 14.955 | 0.913 | 16.38x |
| prefix | 22 | 48.937 | 3.656 | 13.39x |
| prefix | 24 | 189.228 | 14.685 | 12.89x |
| multiply | 20 | 11.886 | 0.147 | 80.95x |
| multiply | 22 | 49.500 | 0.580 | 85.33x |
| multiply | 24 | 155.264 | 2.513 | 61.79x |

Multiplication's log is input words: the product count is half that many.
The prefix lane is an inclusive M31 scan, not typed interaction generation.
Thread overhead matters: these cheap operations often favor one Bend thread.
Log24 timings vary substantially on this shared host; they do not support a
precise scaling law, but all observed cells remain slower than Zig.

## Actual backend-operation latency

Single-column medians of three fresh runs. Eight Bend threads, every Zig parity
check enabled. Includes request construction, subprocess, transport, decoding,
comparison and result copies. Domain/twiddle/input setup is excluded for both.
The direct Zig comparison uses its specialized 2x extension transform for LDE.
Bend runs first in each process; this is not an alternating speedup admission.

| Operation | Output log | Bend backend ms | Zig operation ms | Bend / Zig |
|---|---:|---:|---:|---:|
| fft | 16 | 14.191 | 0.325 | 43.61x |
| fft | 20 | 139.410 | 6.283 | 22.19x |
| fft | 22 | 612.296 | 28.357 | 21.59x |
| fft | 24 | 2675.138 | 124.592 | 21.47x |
| ifft | 16 | 15.842 | 0.276 | 57.45x |
| ifft | 20 | 136.025 | 5.422 | 25.09x |
| ifft | 22 | 532.767 | 24.866 | 21.43x |
| ifft | 24 | 2825.576 | 102.396 | 27.59x |
| lde2x | 16 | 18.277 | 0.472 | 38.71x |
| lde2x | 20 | 210.785 | 9.685 | 21.76x |
| lde2x | 22 | 786.072 | 39.571 | 19.87x |
| lde2x | 24 | 3707.225 | 186.246 | 19.91x |

LDE input log is output log minus one. This measures the complete existing
backend hook, **not an entire STARK proof**. The parity adapter necessarily adds
Zig work to Bend work. Even excluding that validation, the measured Bend kernels
lose; disabling the gate would not establish a win. Merkle, storage, transcript
and verifier paths remain untouched. FRI remains disabled because the original
Debug/ReleaseFast discrepancy is unresolved. GPU qualification and full typed
interaction lowering remain open; a prefix result cannot stand in for them.

## Correctness and retained evidence

- `matrix.json`: 2,048 seeded small fixtures plus 96 timed full-array comparisons
  covering FFT, IFFT, prefix and multiply at logs16/20/22/24 and 1/8 threads.
- `backend.json`: 36 full verified FFT/IFFT/LDE calls and an external equality
  check against Zig; largest LDE is log23 to log24.
- `paired.json`: original and candidate compare against the same Zig arrays.
- `build.json`: final Bend source/binary/generated-C hashes and toolchain pin.
- `trials.json`: exploratory flat-loop and chunk-size variants, including slower
  trials; embedded build-time hashes describe the binary under measurement.
  Current-worktree hashes in trial measurements are snapshots, not build attestations.
- Package-workspace audit still reports the same 15 pre-existing #198 issues,
  with no new Bend errors.
- Seven frozen concrete Bend boundary proofs pass; no universal proof or pinned
  Rust qualification is claimed. New native integration and boundary tests pass.

Raw receipts retain process wall time, user/system CPU, RSS and bytes. RSS is a
per-process high-water mark (for backend runs it is not an aggregate process-tree
memory bound). There are no device copies on the CPU lane. The log24 input-size
extension changes ABI admission only; the Zig oracle algorithm is unchanged.
The runner/prefix changes and new benchmark are an explicitly expanded human
experiment, not an admitted candidate under the original two-file search rules.

## Reproduce

From repository root, with the pinned tools on PATH:

```sh
python3 scripts/build_bend_experiment.py --bend-root /path/to/pinned/bend --output .zig-cache/bend-pass2/final
zig build --build-file src/backends/bend/build.zig -Doptimize=ReleaseFast -Dbend-executable="$PWD/.zig-cache/bend-pass2/final" --prefix "$PWD/.zig-cache/bend-pass2/zig"
python3 autoresearch/benchmarks/bend_circle_fft.py --bend .zig-cache/bend-pass2/final --oracle .zig-cache/bend-pass2/zig/bin/bend-oracle --output /tmp/matrix.json --logs 16,20,22,24 --threads 1,8 --columns 1 --ops fft,ifft,prefix,multiply --repeats 3 --fixtures 512
python3 autoresearch/benchmarks/bend_backend.py --bend .zig-cache/bend-pass2/final --oracle .zig-cache/bend-pass2/zig/bin/bend-oracle --benchmark .zig-cache/bend-pass2/zig/bin/bend-backend-bench --output /tmp/backend.json
python3 autoresearch/benchmarks/bend_compare.py --baseline /path/to/first-pass-binary --candidate .zig-cache/bend-pass2/final --oracle .zig-cache/bend-pass2/zig/bin/bend-oracle --output /tmp/paired.json
zig build test test-integration --build-file src/backends/bend/build.zig -Doptimize=ReleaseSafe -Dbend-executable="$PWD/.zig-cache/bend-pass2/final" -j2
```

Build the baseline from PR #199 commit
`d1233b38cc9ebf0c1821bbf4a0d303eca3051147` with the same pinned tools.
The first pass remains retained in the parent directory. A useful next experiment
would change runtime array ownership/copy behavior or qualify actual GPU hardware;
increasing CPU transform size alone did not solve the observed gap.
