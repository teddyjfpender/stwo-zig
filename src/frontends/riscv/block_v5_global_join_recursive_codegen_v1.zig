//! Address retention only. No parent generation, proof or device invocation.
const std = @import("std");
pub export fn stwo_global_join_recursive_body_gate() void {
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_global_join_composition_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_global_join_composition_v1.zig").Prepared.publicWires);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_global_join_parent_preparation_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_parent_preparation_v1.zig").Prepared.attachGraph);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_recursive_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
}
