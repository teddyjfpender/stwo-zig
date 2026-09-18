# Bend Circle FFT search environment

Start at PR #198's pinned head. This environment is an arithmetic experiment,
not a production proof or a speedup claim. See `src/backends/bend/README.md`.

Editable algorithm surface:

- `bend/stwo/m31.bend`
- `bend/stwo/circle_fft.bend`

Freeze everything else: Zig oracle and core/prover code, deterministic generator,
transport, runner, butterfly reference, `LAWS.bend`, `PROOF.bend`, build pin,
benchmark scripts and admission rules. An external reviewer/runner must compare
the frozen-file digests; a candidate cannot certify its own admission.

Admission is lexicographic, never a weighted score that trades correctness for
speed:

1. Pinned build and `bend bend/stwo/PROOF.bend` succeed. Current Bend laws prove
   seven boundary examples, not universal field correctness.
2. All 2,048 seeded small fixtures (512 each FFT/IFFT/multiply/prefix) match.
3. Large carry-boundary/random multiplication, log16/18/20 transforms and 2x LDE
   match; reject any timeout, malformed output, silent fallback or changed oracle.
4. Compare at least three alternating baseline/candidate pairs on the same host,
   thread count, source inputs, compiler and timing scope. Retain raw samples,
   hashes, latency and per-process RSS. Require an improvement greater than noise
   without exceeding the declared memory budget.
5. CPU qualification is not GPU qualification. `--target gpu` requires an actual
   device; the foreign boundary rejects runtime CPU fallback. Obtain pinned
   Rust Stwo oracle parity before production admission.

Useful mutations: subtree granularity, fewer array splits/joins, bounded fusion
of leaf stages, algebraically equivalent U32 limb decompositions. Never mutate
generated C or relax equality. Multi-column rows currently measure serial child
processes, not a resident/fused Bend batch; changing that requires a new benchmark
version and comparable baseline.

Run `scripts/build_bend_experiment.py --help` and
`autoresearch/benchmarks/bend_circle_fft.py --help` for build/matrix controls.

FRI is a separate rejected lane until the retained Debug/ReleaseFast discrepancy
is resolved against the independent oracle. `interactions.bend` only supplies an
M31 inclusive prefix. Full QM31 rational interaction generation, normalization,
projection and typed-program lowering require their own frozen corpus and gate.
