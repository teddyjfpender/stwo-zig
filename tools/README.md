# Correctness and soundness authorities

`tools/` is not a general utility directory. Every retained root supplies an
independent proof oracle, execution sidecar, qualification adapter, or
reproducible fixture generator that a current Zig product still consumes.

The exhaustive machine-readable inventory is
[`conformance/tooling-surface-v1.json`](../conformance/tooling-surface-v1.json).
Its production test rejects an unknown root, a missing caller, or an unbounded
CI mapping. The one exception to the oracle rule is `perf/`: the retained
`stwo-prof` profiling CLI and the frozen paired-ratio statistics
(`stwo_perf.stats`) that the Native CUDA benchmark runner imports. Product-native
Zig CLIs live with their owners under `src/products/<line>/tools/` and `src/backends/metal/tools/`.

These Rust tools remain implementation-independent on purpose. Rewriting a
proof oracle in Zig would remove the independence that gives it soundness
value. Extraction therefore means publishing an immutable, reproducible,
content-addressed authority artifact and switching every consumer fail-closed;
it does not mean deleting a working oracle first.
