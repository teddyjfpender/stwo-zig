//! Source-only eight-role geometry. No proof-declared widths or masks.
const std = @import("std");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("authority.zig");
const Eq = @import("equations.zig");
const Key = @import("key.zig").Key;
pub fn geometry(a: std.mem.Allocator, g: R.Geometry, key: *const Key) !V.Shape {
    if (!g.detached) return error.SpongeLocalScopeFlavor;
    try key.require(g);
    const instances = try g.instances();
    var global: u32 = 0;
    for (instances) |v| global = @max(global, v.row_log);
    const logs = try a.alloc([]const u32, 4);
    const masks = try a.alloc([]const []const i32, 4);
    inline for (0..3) |tree| {
        var width: usize = 0;
        inline for (R.detached_roles) |role| width += Eq.Layout(role).widths()[tree];
        const columns = try a.alloc(u32, width);
        const shifts = try a.alloc([]const i32, width);
        var at: usize = 0;
        inline for (R.detached_roles, 0..) |role, i| {
            const n = Eq.Layout(role).widths()[tree];
            @memset(columns[at..][0..n], instances[i].row_log);
            for (shifts[at..][0..n], 0..) |*s, c| s.* = Eq.Layout(role).shifts(tree, c);
            at += n;
        }
        logs[tree] = columns;
        masks[tree] = shifts;
    }
    const composition = try a.alloc(u32, 16);
    @memset(composition, global);
    const shifts = try a.alloc([]const i32, 16);
    @memset(shifts, &.{0});
    logs[3] = composition;
    masks[3] = shifts;
    const shape = V.Shape{ .tree_column_log_sizes = logs, .mask_offsets = masks, .global_log = global, .composition_log_split = 1, .pcs = key.profile.config() };
    try shape.validate();
    return shape;
}
