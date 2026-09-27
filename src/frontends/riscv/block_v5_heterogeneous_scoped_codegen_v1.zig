//! Real original leaf and compact parent producer/receiver bodies; no calls.
const std = @import("std");
pub export fn stwo_heterogeneous_scoped_body_gate() void {
    @import("block_v5_heterogeneous_recursive_codegen_v1.zig").stwo_heterogeneous_recursive_body_gate();
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_plan_v1.zig").init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_cohorts_v1.zig").init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_routes_v1.zig").init);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_receiver_v1.zig").verifyLeaf);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_scoped_preparation_v1.zig").prepareVerifierRows);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_scoped_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
}
