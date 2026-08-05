const std = @import("std");
const degree = @import("degree.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const test_support = @import("test_support.zig");

test "logical degree analysis follows the typed topological graph" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const lhs = try arena.input("lhs", .felt, generated);
    const rhs = try arena.input("rhs", .felt, generated);
    const selector = try arena.input("selector", .bit, generated);
    const product = try arena.mul(lhs, rhs, generated);
    const selected = try arena.select(selector, product, lhs, generated);
    const constraint = try arena.assertZero(
        "product",
        product,
        selector,
        .semantic,
        generated,
    );

    var analysis = try degree.analyze(std.testing.allocator, &arena);
    defer analysis.deinit();
    try std.testing.expectEqual(@as(degree.Degree, 1), analysis.value(lhs).?);
    try std.testing.expectEqual(@as(degree.Degree, 2), analysis.value(product).?);
    try std.testing.expectEqual(@as(degree.Degree, 3), analysis.value(selected).?);
    try std.testing.expectEqual(
        degree.ConstraintDegree{
            .expression = 2,
            .gate = 1,
            .total = 3,
        },
        analysis.constraint(constraint).?,
    );
    try std.testing.expectEqual(@as(degree.Degree, 3), analysis.maximumValueDegree());
    try std.testing.expectEqual(
        @as(degree.Degree, 3),
        analysis.maximumConstraintDegree(),
    );
}

test "logical degree treats hint and call outputs as committed values" {
    var fixture = try test_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var analysis = try degree.analyze(std.testing.allocator, &fixture.arena);
    defer analysis.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, 1),
        analysis.value(fixture.hint_output).?,
    );
    try std.testing.expectEqual(
        @as(degree.Degree, 1),
        analysis.value(fixture.call_output).?,
    );
}

test "logical degree rejects arithmetic overflow" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    var value = try arena.input("value", .felt, generated);
    for (0..32) |_| value = try arena.mul(value, value, generated);
    try std.testing.expectError(
        error.DegreeOverflow,
        degree.analyze(std.testing.allocator, &arena),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var fixture = try test_support.Fixture.init(allocator);
    defer fixture.deinit();
    var analysis = try degree.analyze(allocator, &fixture.arena);
    defer analysis.deinit();
}

test "logical degree analysis releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
