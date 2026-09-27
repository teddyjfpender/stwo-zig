//! Retain actual original typed leaf and parent verifier bodies, never invoke.
const std = @import("std");
const C = @import("prover/block_v5_recursive_coverage_plan_v1.zig");
const F = @import("recursion/block_v5_heterogeneous_child_frames_v1.zig");
fn Body(comptime subtype: C.Subtype) type {
    return struct {
        fn fresh(a: std.mem.Allocator, policy: F.PolicyForSubtype(subtype), bytes: []const u8, physical: C.Physical, recipe: @import("prover/block_v5_execution_recipe_v1.zig").Recipe, sealed: [32]u8) anyerror!F.Fresh {
            return policy.verify(a, bytes, physical, recipe, sealed);
        }
    };
}
pub export fn stwo_heterogeneous_recursive_body_gate() void {
    inline for ([_]C.Subtype{ .native_v3, .capacity_v1, .capacity_fused_v1, .caller_family11_v1, .caller_fused_v1, .ram_lanes_v1, .range16_v1, .rom_v1, .six_table_lookup_v1 }) |subtype| std.mem.doNotOptimizeAway(&Body(subtype).fresh);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_parent_receiver_v1.zig").verify);
    std.mem.doNotOptimizeAway(&@import("recursion/block_v5_heterogeneous_parent_preparation_v1.zig").prepareVerifierRows);
    std.mem.doNotOptimizeAway(&@import("recursion/air/block_v5_heterogeneous_pairing_v1.zig").prepare);
    std.mem.doNotOptimizeAway(&@import("prover/block_v5_heterogeneous_recursive_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).publish);
}
