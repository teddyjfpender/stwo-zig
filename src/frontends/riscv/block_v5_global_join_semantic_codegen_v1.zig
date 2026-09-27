//! Address retention only. Never performs a cryptographic parent operation.
const std = @import("std");
const S = @import("recursion/block_v5_global_join_semantic_plan_v1.zig");
const Raw = @import("recursion/air/block_v5_global_join_source_values_v1.zig");
pub export fn stwo_global_join_semantic_body_gate() void {
    std.mem.doNotOptimizeAway(&S.derive);
    std.mem.doNotOptimizeAway(&S.Derived.validateAgainst);
    std.mem.doNotOptimizeAway(&S.Derived.recordOpen);
    std.mem.doNotOptimizeAway(&S.Derived.attachOpen);
    std.mem.doNotOptimizeAway(&S.Derived.requireComplete);
    std.mem.doNotOptimizeAway(&Raw.read);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_parent_preparation_v1.zig").Prepared.attachGraph);
}
