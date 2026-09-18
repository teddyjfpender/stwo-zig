# Bend experiment against PR #198

Base: `1358234f1e8a2ac34241658dcd3505bad5feb1fc`. Bend: pinned 2.0.5.
Zig: 0.15.2. Scope: initial CPU experiment, not a production backend release.

See [complete CSP proof results](pass3/README.md) for the proof-capable backend
and current FRI qualification.

See [the second pass](pass2/README.md) for log24, faster Bend algorithms and
complete backend/LDE timings. This page preserves the initial checkpoint.

## Outcome

The initial balanced Bend Circle FFT scales across threads but remains much
slower than the existing optimized Zig/SIMD code. It is not a performance win.

| Operation | log size | Zig compute ms | Bend 1 thread ms | Bend 8 threads ms |
|---|---:|---:|---:|---:|
| fft | 16 | 0.375 | 26.767 | 13.402 |
| fft | 18 | 1.423 | 115.505 | 46.955 |
| fft | 20 | 6.126 | 516.569 | 164.602 |
| ifft | 16 | 0.269 | 26.781 | 14.032 |
| ifft | 18 | 1.124 | 116.563 | 39.428 |
| ifft | 20 | 4.833 | 521.343 | 136.005 |

Three samples per cell. Packed width 8 on x86_64; no separately compiled scalar
lane. Compute excludes input/plan construction and serialization. Raw reports
also retain process wall time, user/system CPU time, request/response byte counts,
per-child peak RSS and binary/source hashes. Compiler time is excluded. GPU time
is null; host/device copies are zero for CPU. Host frequency was uncontrolled.

The matrix includes 16/64/128-column batches at log16. These execute one fresh
child per column, serially: not a resident or fused multi-column benchmark.
2x LDE has live Zig-backend correctness tests at base logs 1/2/3/5/10, but no
retained standalone timing yet. Metal and Bend GPU lanes were unavailable here.

## Correctness and rejected evidence

- `cpu-smoke.json`: 2,048 seeded small fixtures (512 each FFT, IFFT, multiply,
  inclusive prefix), plus timed log10 samples; all exact output comparisons pass.
- `m31-large.json`: 2,097,152 products in four log20-word requests, each including
  the full 12x12 limb/carry boundary cross-product; all match.
- `cpu-matrix.json`: log16/18/20 FFT/IFFT, 1/2/4/8 threads and log16 batches; exact
  output equality in all retained cells. One final cell was re-run separately.
- `fri-debug-parity.json`: 1,024 seeded QM31 folding fixtures match Debug. Debug
  timing is correctness evidence only, not an optimized performance comparison.
- `fri-rejected-release.json`, `fri-reproducer.json`: identical requests disagree
  between Debug and ReleaseFast; Bend agrees with Debug. FRI capability remains
  false. Root cause is not established; no production-proof corruption is claimed.
- `prefix-matrix.json`: M31 inclusive prefix only. This is not the full typed
  interaction generator and does not measure a reduction of its 1.474-second phase.
- `pr198-extraction.json`: source-pinned historical phase observations, not new
  benchmark results or repeated phase medians.
- Seven boundary laws pass the Bend proof checker. Universal field/transform
  proofs and pinned Rust Stwo oracle parity remain unqualified.

## Reproduction

Use the exact clean Bend checkout specified in `bend/toolchain.json`, Node,
clang 14+ for CPU, and Zig 0.15.2. See the backend README for build commands.

```sh
python3 scripts/build_bend_experiment.py --bend-root /path/to/pinned/bend
zig build --build-file src/backends/bend/build.zig -Doptimize=ReleaseFast -j2
python3 autoresearch/benchmarks/bend_circle_fft.py --bend .zig-cache/bend/stwo-bend --oracle src/backends/bend/zig-out/bin/bend-oracle --output /tmp/matrix.json
python3 autoresearch/benchmarks/bend_circle_fft.py --bend .zig-cache/bend/stwo-bend --oracle src/backends/bend/zig-out/bin/bend-oracle --output /tmp/smoke.json --logs 10 --threads 1 --columns 1 --ops fft,ifft,multiply,prefix --fixtures 512
zig build --build-file src/backends/bend/build.zig -Doptimize=Debug -j2 --prefix /tmp/bend-debug
python3 autoresearch/benchmarks/bend_fri.py --bend .zig-cache/bend/stwo-bend --oracle /tmp/bend-debug/bin/bend-oracle --output /tmp/fri-debug.json --logs 10 --threads 1 --columns 1 --fixtures 512
```

The FRI gate with the ReleaseFast oracle is expected to reject this checkpoint.
The direct Zig bridge runs trusted pinned binaries synchronously; the Python
search harness additionally enforces a 60-second child deadline.

## Next experiment and promotion gates

Array splitting/joining in this compiler allocates and copies. Coarsen tasks and
reduce this traffic before pursuing a speed claim. The frozen autoresearch
surface permits only M31 and Circle FFT changes and requires exact parity,
proof-example checks and alternating paired performance measurements. No
improved autoresearch candidate is claimed by this initial checkpoint.

Resolve FRI's build-mode discrepancy against the pinned Rust oracle, qualify
GPU execution and memory, add cancellation, and replace process-per-column
transport before production admission. Full typed interaction lowering remains
separate work. No recursive semantics, Merkle ownership, transcript or verifier
changes are made here.
