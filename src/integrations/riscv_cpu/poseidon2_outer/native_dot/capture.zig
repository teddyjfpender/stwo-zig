//! Eight-role geometry from the independently reconstructed R7 source key.
const std = @import("std");
const K = @import("outer_authority.zig");
const D = @import("row.zig");
const I = @import("input_row.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
pub fn geometry(a: std.mem.Allocator, key: *const K.Key) !V.Shape {
    const prior = try @import("../native_omul/capture.zig").geometry(a, &key.core);
    const logs = try a.alloc([]const u32, 4);
    for (0..3) |tree| logs[tree] = try key.treeLogs(a, tree);
    const composition = try a.alloc(u32, 16);
    @memset(composition, key.maxLog());
    logs[3] = composition;
    const offsets = try a.alloc([]const []const i32, 4);
    for (offsets, logs, 0..) |*tree, columns, t| {
        const out = try a.alloc([]const i32, columns.len);
        @memset(out, &.{0});
        @memcpy(out[0..prior.mask_offsets[t].len], prior.mask_offsets[t]);
        tree.* = out;
    }
    for (@constCast(offsets[1])[K.MAIN_START + D.ACC ..][0..8]) |*out| out.* = &.{ 0, -1 };
    for (@constCast(offsets[2])[K.INTER_START + 16 ..][0..8]) |*out| out.* = &.{ 0, -1 };
    for (@constCast(offsets[2])[K.INPUT_INTER_START..][0..I.INTER]) |*out| out.* = &.{ 0, -1 };
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = offsets, .global_log = key.maxLog(), .composition_log_split = 1, .pcs = key.core.base.profile.config() };
    try result.validate();
    return result;
}
