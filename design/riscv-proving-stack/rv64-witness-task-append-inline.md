# Specialize witness task registration dispatch

The production change is one keyword: `inline fn append`. Existing gate-family
loops already supply a constant Kind, so inlining allows the compiler to remove
runtime dispatch through the existing inputs/outputs switches. Every bounds,
seeded/in-place skip, duplicate producer and complete coverage check remains.
No production capacity reservation, census or new data structure is included.
The negative capacity audit stays on its separate branch.

A dedicated bounded CPU qualification builds finalized original BlakeG+QM31
arithmetic graphs, checks every constraint and exact scheduled replay, compares
all tasks/seeds/level ends against independent DFS, and hashes those fields for
cross-executable comparison. It uses existing production BuildMetrics and the
page allocator, with no per-append timing/counters. The same graph was measured
control→inline→control→inline, three samples per graph in each invocation.

| Variables | Tasks | Control task phase | Inline task phase | Control plan | Inline plan |
|---:|---:|---:|---:|---:|---:|
|150,270|75,260|0.629ms|0.482ms|2.539ms|2.115ms|
|1,500,270|750,260|6.443ms|5.038ms|22.949ms|21.365ms|

These are medians of six samples per variant on local ARM. All fingerprints
match exactly across both control and both inline executables. Each invocation
passes95 tests, including original invalid/missing/duplicate/forward-reference
and cycle guards. Control/inline compilation took6s/7s, with518/510MiB maximum
compiler RSS; test maximum RSS remained95MiB. GNU combined-prover semantic
checking also passed.

The graphs are constructed cryptographic workloads, not captured production
CPU/Keccak/fold graphs. This establishes a narrow CPU improvement and unchanged
schedule semantics for the qualified graphs; it does not establish production
wall time, worst-shape memory or GPU proof parity. No hardware lease was used.
The compact receipt records source base, medians, fingerprints and log pins.
Per-run samples are retained separately with their full-receipt SHA256. The
three control fingerprints are frozen in the qualification fixture, so a
regression shared by both current schedulers cannot silently move the oracle.
