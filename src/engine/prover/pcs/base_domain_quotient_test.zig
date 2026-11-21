const std = @import("std");
const core = @import("stwo_core");
const base = @import("base_domain_quotient.zig");
const Poly = @import("../poly/circle/poly.zig").CircleCoefficients;
const Column = @import("quotient_column_geometry.zig").ColumnEvaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const TreeVec = core.pcs.TreeVec;

test "degree-domain DEEP extends to the original mixed-height and shifted-mask quotient" {
    const a = std.testing.allocator;
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    channel.mixU32s(&.{ 0x44454550, 6, 4 });
    const point = try core.circle.randomSecureFieldPointFor(O, &channel);
    const step = core.poly.circle.canonic.CanonicCoset.new(6).step();
    const shifted = point.add(.{ .x = O.fromBase(step.x), .y = O.fromBase(step.y) });
    var first: [16]M = undefined;
    var second: [4]M = undefined;
    for (&first, 0..) |*v, i| v.* = M.fromU64(3 * i * i + 31);
    for (&second, 0..) |*v, i| v.* = M.fromU64(7 * i * i * i + 19);
    var polys = [_]Poly{ try Poly.initBorrowed(&first), try Poly.initBorrowed(&second) };
    var columns = [_]Column{
        .{ .log_size = 6, .values = &.{}, .coefficient_values = &first },
        .{ .log_size = 4, .values = &.{}, .coefficient_values = &second },
    };
    var first_points = [_]Point{point};
    var second_points = [_]Point{ point, shifted };
    var first_samples = [_]O{polys[0].evalAtPointFor(O, point)};
    var second_samples = [_]O{
        polys[1].evalAtPointFor(O, point.repeatedDouble(2)),
        polys[1].evalAtPointFor(O, shifted.repeatedDouble(2)),
    };
    var point_columns = [_][]Point{ &first_points, &second_points };
    var sample_columns = [_][]O{ &first_samples, &second_samples };
    var point_trees = [_][][]Point{&point_columns};
    var sample_trees = [_][][]O{&sample_columns};
    var tree_columns = [_][]const Column{&columns};
    const points = TreeVec([][]Point).initOwned(&point_trees);
    const samples = TreeVec([][]O).initOwned(&sample_trees);
    const alpha = channel.drawSecureFelt();

    const Tree = struct { columns: []Column, coefficients: ?[]Poly };
    const trees = [_]Tree{.{ .columns = &columns, .coefficients = &polys }};
    var full = try @import("quotient_field.zig").ForField(O).computeFriQuotients(a, TreeVec([]const Column).initOwned(&tree_columns), points, samples, alpha, 6, 2);
    defer full.deinit(a);
    var result = (try base.produce(void, a, &trees, points, samples, alpha, 6, 2, null)).?;
    defer result.deinit(a);
    for (full.columns, result.columns) |expected, actual| {
        try std.testing.expectEqualSlices(M, expected, actual);
    }
}
