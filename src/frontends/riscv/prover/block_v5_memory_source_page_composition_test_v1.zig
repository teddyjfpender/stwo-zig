//! Real scalar component forwarding and allocation tests; no PCS/proofs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Composition = @import("block_v5_memory_source_page_composition_v1.zig");
const Input = @import("block_v5_memory_source_page_input_component_v1.zig").ForWidth(1);
const Point = core.circle.CirclePointQM31;
const Acc = core.air.accumulation.PointEvaluationAccumulator;
fn component(circuit: u32) Input.Component {
    return .{ .log_size = 1, .spec = .{
        .rows = 2,
        .requests = 1,
        .claim = .{ .sums = .{Q.fromU32Unchecked(circuit + 1, 0, 0, 0)}, .requests = 1 },
        .challenge = .{ .z = Q.fromU32Unchecked(11, 13, 17, 19), .powers = .{ Q.one(), Q.fromU32Unchecked(2, 0, 0, 0), Q.fromU32Unchecked(3, 0, 0, 0), Q.one(), Q.one(), Q.one() } },
    } };
}
const logs: [Composition.TREE_COUNT][]const u32 = .{ &.{1}, &.{1}, &.{}, &.{}, &.{}, &.{}, &.{ 1, 1, 1, 1, 1, 1 }, &.{}, &.{ 1, 1, 1, 1, 1, 1, 1, 1 } };
const first = [_]Composition.Placement{ .{ .tree = 6, .view_count = 3, .used_count = 3 }, .{ .tree = 1, .view_count = 1, .used_count = 1 }, .{ .tree = 8, .view_count = 4, .used_count = 4 } };
const second = [_]Composition.Placement{ .{ .tree = 6, .offset = 3, .view_count = 3, .used_count = 3 }, .{ .tree = 1, .view_count = 1, .used_count = 1 }, .{ .tree = 8, .offset = 4, .view_count = 4, .used_count = 4 } };
fn point() Point {
    return core.circle.SECURE_FIELD_CIRCLE_GEN;
}
fn fixture(a: std.mem.Allocator) !void {
    const left = component(1);
    const right = component(2);
    const children = [_]Composition.Child{ Composition.Child.from(&left, &first), Composition.Child.from(&right, &second) };
    const owner = try Composition.Owner.init(a, &children, logs, 2, .{});
    defer owner.deinit();
    var sizes = try owner.traceLogDegreeBounds(a);
    defer sizes.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 1), sizes.items[1].len); // shared main is not doubled.
    var masks = try owner.maskPoints(a, point(), 3);
    defer masks.deinitDeep(a);
    try std.testing.expectEqual(@as(usize, 1), masks.items[1].len);
    try std.testing.expectEqual(@as(usize, 1), masks.items[1][0].len);
    for (masks.items[8]) |column| try std.testing.expectEqual(@as(usize, 2), column.len);
    const trees = try a.alloc([][]Q, Composition.TREE_COUNT);
    for (trees) |*tree| tree.* = &.{};
    var values = core.air.components.MaskValues.initOwned(trees);
    defer values.deinitDeep(a);
    for (trees, masks.items, 0..) |*tree, columns, t| {
        tree.* = try a.alloc([]Q, columns.len);
        for (tree.*) |*column| column.* = &.{};
        for (tree.*, columns, 0..) |*column, positions, i| {
            column.* = try a.alloc(Q, positions.len);
            for (column.*, 0..) |*value, p| value.* = Q.fromU32Unchecked(@intCast(31 + t + 2 * i + p), 2, 3, 5);
        }
    }
    var actual = Acc.init(Q.fromU32Unchecked(23, 7, 11, 17));
    try owner.evaluateConstraintQuotientsAtPoint(point(), &values, &actual, 3);
    var expected = Acc.init(Q.fromU32Unchecked(23, 7, 11, 17));
    var left_trees = [_][][]Q{ values.items[6][0..3], values.items[1], values.items[8][0..4] };
    var right_trees = [_][][]Q{ values.items[6][3..6], values.items[1], values.items[8][4..8] };
    const left_values = core.air.components.MaskValues{ .items = &left_trees };
    const right_values = core.air.components.MaskValues{ .items = &right_trees };
    try left.evaluateConstraintQuotientsAtPoint(point(), &left_values, &expected, 3);
    try right.evaluateConstraintQuotientsAtPoint(point(), &right_values, &expected, 3);
    try std.testing.expect(actual.finalize().eql(expected.finalize()));
    // A mutation of the one aliased cell affects BOTH original equations.
    values.items[1][0][0] = values.items[1][0][0].add(Q.one());
    var changed = Acc.init(Q.fromU32Unchecked(23, 7, 11, 17));
    try owner.evaluateConstraintQuotientsAtPoint(point(), &values, &changed, 3);
    try std.testing.expect(!changed.finalize().eql(actual.finalize()));
}
test "source unified PAGE: exact shared masks and original scalar equations without duplicated main" {
    try fixture(std.testing.allocator);
}
test "source unified PAGE: every combined mask/point-owner allocation failure is transactional" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, fixture, .{});
}
test "source unified PAGE: mismatched alias geometry and bounded masks reject before equation evaluation" {
    const a = std.testing.allocator;
    const left = component(1);
    var invalid = first;
    invalid[1].used_count = 2;
    const children = [_]Composition.Child{Composition.Child.from(&left, &invalid)};
    try std.testing.expectError(error.InvalidSourcePageComposition, Composition.Owner.init(a, &children, logs, 2, .{}));
    const valid = [_]Composition.Child{Composition.Child.from(&left, &first)};
    const owner = try Composition.Owner.init(a, &valid, logs, 2, .{ .max_points_per_column = 1 });
    defer owner.deinit();
    try std.testing.expectError(error.SourcePageCompositionResourceLimit, owner.maskPoints(a, point(), 3));
}
