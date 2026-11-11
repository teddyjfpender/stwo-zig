//! Six-roster recursive verifier shape derived only from admitted R6 source key.
const std = @import("std");
const K = @import("authority.zig");
const A = @import("../authority.zig");
const R = @import("row.zig");
const L = @import("../layout.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const G = @import("stwo_circuit_cpu_integration").om31.geometry;
pub fn geometry(a: std.mem.Allocator, key: *const K.Key) !V.Shape {
    const global_log = key.maxLog();
    const logs = try a.alloc([]const u32, 4);
    for (0..3) |tree| logs[tree] = try key.treeLogs(a, @intCast(tree));
    const composition = try a.alloc(u32, 16);
    @memset(composition, global_log);
    logs[3] = composition;
    const offsets = try a.alloc([]const []const i32, 4);
    for (offsets, logs) |*tree, columns| {
        const out = try a.alloc([]const i32, columns.len);
        @memset(out, &.{0});
        tree.* = out;
    }
    inline for (A.OLD_SLOTS) |old| {
        const component = key.base.bound.components[old];
        for (1..3) |tree| {
            const span = try G.span(component, @intCast(tree));
            const lists = try G.offsets(a, component, @intCast(tree));
            defer G.freeOffsets(a, lists);
            if (span.end - span.start != lists.len) return error.InvalidPoseidonFoldGeometry;
            for (lists, @constCast(offsets[tree])[span.start..span.end]) |list, *out| out.* = try a.dupe(i32, list.items);
        }
    }
    for (@constCast(offsets[2])[A.INTER_START[3]..][0..L.CLASSIC_INTERACTION_COLUMNS], 0..) |*out, column| out.* = if (column >= 23 * 8) &.{ 0, -1 } else &.{0};
    for (@constCast(offsets[2])[K.INTER_START..][0..R.INTER], 0..) |*out, column| out.* = if (column >= 16) &.{ 0, -1 } else &.{0};
    const result = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = offsets, .global_log = global_log, .composition_log_split = 1, .pcs = key.base.profile.config() };
    try result.validate();
    return result;
}
