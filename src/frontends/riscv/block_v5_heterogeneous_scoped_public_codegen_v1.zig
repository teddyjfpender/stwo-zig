//! Actual bodies retained; never invokes proof or parent production.
const std = @import("std");
pub export fn stwo_heterogeneous_scoped_public_body_gate() void {
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_public_context_v1.zig").open);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_public_context_v1.zig").Context.deinit);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_public_plan_v1.zig").init);
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_heterogeneous_scoped_public_equations_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_public_preparation_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_public_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_scoped_public_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
}
