//! Full frontier CPU shape derives only from trusted setup + new source key.
const std = @import("std");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Key = @import("key.zig").Key;
const L = @import("equations.zig").Layout;
pub fn geometry(a: std.mem.Allocator, setup: *const R.CpuSetup, key: *const Key) !V.Shape {
    try key.require(setup);
    const base = try @import("../../rv64_recursion/om31_native/cpu_capture.zig").geometryForOp(a, setup, key.profile.config());
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    const global = @max(base.global_log, key.frontier_log);
    for (0..3) |tree| {
        const old = base.tree_column_log_sizes[tree];
        const columns = try a.alloc(u32, old.len + L.widths()[tree]);
        @memcpy(columns[0..old.len], old);
        @memset(columns[old.len..], key.frontier_log);
        logs[tree] = columns;
        const offsets = try a.alloc([]const i32, columns.len);
        @memcpy(offsets[0..old.len], base.mask_offsets[tree]);
        for (offsets[old.len..], 0..) |*offset, c| offset.* = L.shifts(tree, c);
        masks[tree] = offsets;
    }
    const comp = try a.alloc(u32, base.tree_column_log_sizes[3].len);
    @memset(comp, global);
    logs[3] = comp;
    masks[3] = base.mask_offsets[3];
    const shape = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global, .composition_log_split = base.composition_log_split, .pcs = key.profile.config() };
    try shape.validate();
    return shape;
}
