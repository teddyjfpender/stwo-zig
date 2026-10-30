//! Finite explicit native clock protocols. Default V2 identities are unchanged.
const std = @import("std");
const Old = @import("block_v8_native_endpoint_layout_v1.zig");
const V3 = @import("block_v8_native_endpoint_layout_v3.zig");
const Halt = @import("block_v8_native_halt_policy_v1.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
pub const Profile = enum(u8) {
    endpoint_v2 = 2,
    direct_ram_clock_v3 = 3,
    direct_ram_clock_v3_wide = 4,
    pub fn isDirect(self: @This()) bool {
        return self != .endpoint_v2;
    }
    pub fn isWide(self: @This()) bool {
        return self == .direct_ram_clock_v3_wide;
    }
};
pub fn requireShape(shape: *const Shape, profile: Profile) !void {
    if (shape.native_shard_version != @as(u32, @intFromBool(profile.isWide()))) return error.NativeClockGeometryProfileMismatch;
}
pub fn layout(a: std.mem.Allocator, shape: *const Shape, profile: Profile) !Old.Layout {
    try requireShape(shape, profile);
    return switch (profile) {
        .endpoint_v2 => Old.Layout.init(a, shape, 0),
        .direct_ram_clock_v3, .direct_ram_clock_v3_wide => V3.init(a, shape, 0),
    };
}
pub fn mainLogs(a: std.mem.Allocator, shape: *const Shape, profile: Profile) ![]u32 {
    return switch (profile) {
        .endpoint_v2 => Halt.mainLogs(a, shape),
        .direct_ram_clock_v3, .direct_ram_clock_v3_wide => @import("block_v8_ram_clock_v3_stage.zig").mainLogs(a, shape),
    };
}
pub fn interactionLogs(a: std.mem.Allocator, shape: *const Shape, slots: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot, profile: Profile) ![]u32 {
    const projections = try Fused.interactionLogs(a, slots, &.{});
    if (profile == .endpoint_v2) return projections;
    defer a.free(projections);
    const count = Halt.count(shape);
    const logs = try a.alloc(u32, projections.len + 4 * count);
    var index: usize = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        @memset(logs[index..][0..4], desc.log_size);
        index += 4;
    };
    @memcpy(logs[index..], projections);
    return logs;
}
pub fn gapGroups(shape: *const Shape, profile: Profile) usize {
    return if (profile.isDirect()) Halt.count(shape) else 0;
}
pub fn gapRequests(shape: *const Shape, profile: Profile) !u32 {
    if (profile == .endpoint_v2) return 0;
    var accesses: u64 = 0;
    for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
        accesses = try std.math.add(u64, accesses, desc.n_rows);
    };
    const count = try std.math.mul(u64, accesses, 3);
    if (count >= @import("stwo_core").fields.m31.Modulus) return error.DirectRamClockRangeCountExceedsField;
    return @intCast(count);
}
pub fn nativeDemand(shape: *const Shape, profile: Profile) ![6]u64 {
    var counts = try @import("block_v5_native_lookup_plan_v1.zig").nativeDemand(shape, 0);
    if (profile.isDirect()) {
        var accesses: u64 = 0;
        for (shape.component_descs[0..shape.n_components]) |desc| if (desc.family == .load_store) {
            accesses = try std.math.add(u64, accesses, desc.n_rows);
        };
        const index = @intFromEnum(@import("../air/lookups/tables/schema.zig").Kind.range_check_20);
        counts[index] = try std.math.sub(u64, counts[index], accesses);
    }
    return counts;
}
