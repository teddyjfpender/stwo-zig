# Base-field barycentric context construction

Problem: parent opening setup reconstructs every circle-domain point by index
and computes base-field constants through QM31. The earlier canonical parent
stack sample identified barycentric context construction as a profiling lead.

Change: enumerate the same domain through its iterator, store into the existing
bit-reversed layout, compute vanishing-derivative constants in M31, and embed
only final values into QM31. Allocation shape, sampled-point handling, transcript,
proof parameters and opening equations are unchanged. No hash or protocol identity
changes are required because the resulting tables are exactly equal.

Validation: all eight focused ReleaseSafe evaluation tests pass. The added check
compares every point and derivative factor against the old indexed QM31 algorithm
for logs 1 through 10. Existing tests compare weights and evaluations against a
separate reference and reject points on the domain.

Paired ReleaseFast setup measurements alternate order, exclude an explicit first
warmup, and compare every resulting point/factor at logs 12 and 16. Log-16 median:
31.337 ms reference / 19.272 ms optimized (1.626x). This is a three-sample microbenchmark,
not proof latency or evidence for a 10x recursion speedup. Raw samples and source
are retained. Canonical q70/PoW26 recursive parent qualification passed; see the retained log.

Reproduction:

```sh
zig test -OReleaseSafe --dep stwo_core -Mroot=src/prover/barycentric_test_root.zig -Mstwo_core=src/core/mod.zig --test-filter 'prover poly circle evaluation'
zig build-exe -OReleaseFast --dep stwo_core -Mroot=src/prover/barycentric_context_benchmark.zig -Mstwo_core=src/core/mod.zig -femit-bin=/tmp/stwo-barycentric-context-benchmark
/tmp/stwo-barycentric-context-benchmark
```

The canonical guest-Poseidon leaf and BLAKE3 parent both verify at q70/PoW26,
including serialized parent verification after worker/row release. This gate
qualifies the opening-context change and is not a timing comparison.
