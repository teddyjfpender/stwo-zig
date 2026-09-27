//! Retain real hierarchy producer/fresh receiver; never call a prover.
const std = @import("std");
pub export fn stwo_heterogeneous_hierarchy_body_gate() void {
    @import("block_v5_heterogeneous_recursive_codegen_v1.zig").stwo_heterogeneous_recursive_body_gate();
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_hierarchy_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_hierarchy_receiver_v1.zig").verifyLeaf);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_hierarchy_preparation_v1.zig").prepareVerifierRows);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_hierarchy_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
}
