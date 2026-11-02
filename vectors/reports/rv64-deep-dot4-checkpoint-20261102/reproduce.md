This is a numerical combination experiment, not a whole-proof speed claim.

The frozen baseline authority is `664f8adc3:src/prover/pcs/quotients/combined_setup_family.zig`. Create a detached worktree at that commit and place this wrapper at `src/prover/deep_combine_baseline.zig`:

```zig
pub const ForCoordinates = @import("pcs/quotients/combined_setup_family.zig").ForCoordinates;
pub const Pools = @import("work_pool.zig");
```

Compile `src/prover/pcs_combined_dot4_benchmark.zig` with an explicit `baseline` module pointing to that wrapper, plus the normal `stwo_core` and `stwo_prover_api` modules. The benchmark binds both module-local pool authorities to identical worker counts; the baseline cannot lazily select all machine cores.

The retained JSONL contains six alternating samples per fixture; medians exclude sample zero. Every output is compared exactly outside the timer. Both the full same-view fixture and the deliberately interleaved mixed/partial fixture are synthetic; their branch coverage is reported explicitly and is not measured production coverage.

An earlier exploratory run bound only the candidate pool. Because the explicit old-source module has independent pool TLS, its baseline lazily used a different worker count. That run is invalid and excluded from all retained timings and conclusions.

Q/OM here mean four/eight base-coordinate accumulator planes, not a secure-field multiplication microbenchmark. Partial inputs, tails, mixed views, untouched destinations, pooled disjoint rows and exhaustive allocation failures are covered by focused Safe/Fast tests. The helper uses only the original output allocations. No production protocol or security profile changes.
