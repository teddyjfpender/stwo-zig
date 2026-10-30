const std = @import("std");
const Fixed = @import("block_v6_page_auxiliary_fixed_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Live = @import("block_v6_auxiliary_direct_prepare_v1.zig");
fn exercise(comptime kind: Semantic.Kind, a: std.mem.Allocator, admitted: *const Admission.ForKind(kind).Prepared, claims: Semantic.Claims, live: *Live.Prepared) !void {
    var cold = try Fixed.ForKind(kind).Owned.derive(a, admitted, admitted.template_id, claims, 2, .diagnostic_q8_pow0, .{});
    defer cold.deinit();
    try cold.validateLive(live);
    var outer = try cold.outerNamespace(a, 1000);
    defer outer.deinit();
    _ = try outer.identity();
}
fn raw(a: std.mem.Allocator, admitted: *const Admission.ForKind(.raw).Prepared, claims: Semantic.Claims, live: *Live.Prepared) !void {
    return exercise(.raw, a, admitted, claims, live);
}
fn fold(a: std.mem.Allocator, admitted: *const Admission.ForKind(.fold).Prepared, claims: Semantic.Claims, live: *Live.Prepared) !void {
    return exercise(.fold, a, admitted, claims, live);
}
test "PAGE auxiliary fixed cold factory includes both original namespace schedules" {
    std.mem.doNotOptimizeAway(&raw);
    std.mem.doNotOptimizeAway(&fold);
}
test "caller fused fixed cold factory includes original transcript PCS and all equations" {
    std.mem.doNotOptimizeAway(&@import("block_v6_caller_fused_fixed_roster_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v6_caller_fused_fixed_roster_v1.zig").Owned.validateLive);
    std.mem.doNotOptimizeAway(&@import("block_v6_caller_fused_auxiliary_fixed_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v6_caller_fused_auxiliary_fixed_v1.zig").Owned.validateLive);
}
