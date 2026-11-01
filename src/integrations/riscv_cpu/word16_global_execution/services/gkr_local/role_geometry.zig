//! One geometry/mask authority for original arithmetic and table local bindings.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(O);
const Air = core.air.components.ForField(O);
pub fn bounds(self: anytype, a: std.mem.Allocator) !Air.TraceLogDegreeBounds {
    try self.validate();
    const shape = self.mainShape();
    const widths = [_]usize{ shape.fixed, shape.main, 16 };
    const trees = try a.alloc([]u32, 3);
    errdefer a.free(trees);
    var done: usize = 0;
    errdefer for (trees[0..done]) |tree| a.free(tree);
    for (trees, widths) |*tree, width| {
        tree.* = try a.alloc(u32, width);
        @memset(tree.*, self.data.instance.row_log);
        done += 1;
    }
    return Air.TraceLogDegreeBounds.initOwned(trees);
}
pub fn indices(self: anytype, a: std.mem.Allocator) ![]usize {
    try self.validate();
    const out = try a.alloc(usize, self.mainShape().fixed);
    for (out, 0..) |*v, i| v.* = self.columnOffsets()[0] + i;
    return out;
}
pub fn masks(self: anytype, a: std.mem.Allocator, point: Point, global_log: u32) !Air.MaskPoints {
    try self.validate();
    _ = try A.geometry.localPointFor(O, point, global_log, self.data.instance.row_log);
    const shape = self.mainShape();
    const widths = [_]usize{ shape.fixed, shape.main, 16 };
    const trees = try a.alloc([][]Point, 3);
    errdefer a.free(trees);
    var done: usize = 0;
    errdefer for (trees[0..done]) |tree| {
        for (tree) |column| a.free(column);
        a.free(tree);
    };
    const step = core.poly.circle.canonic.CanonicCoset.new(global_log).coset().step.double();
    const next2 = point.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) });
    const prior = A.geometry.previousPointFor(O, point, global_log);
    for (trees, widths, 0..) |*tree, width, t| {
        tree.* = try a.alloc([]Point, width);
        var assigned: usize = 0;
        errdefer {
            for (tree.*[0..assigned]) |column| a.free(column);
            a.free(tree.*);
        }
        for (tree.*, 0..) |*column, c| {
            column.* = if (t == 2)
                try a.dupe(Point, &.{ point, if (c < 8) next2 else prior })
            else if (t == 1 and self.previousMain(c))
                try a.dupe(Point, &.{ point, prior })
            else
                try a.dupe(Point, &.{point});
            assigned += 1;
        }
        done += 1;
    }
    return Air.MaskPoints.initOwned(trees);
}
