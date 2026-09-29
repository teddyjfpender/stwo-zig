//! Resizing plan scratch must invalidate released owners before fallible allocation.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const polynomial = @import("../poly/circle/mod.zig");
const plans = @import("sampled_coefficient_plans.zig");

fn resizeCase(allocator: std.mem.Allocator) !void {
    var storage: [128]M31 = undefined;
    for (&storage, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index * 7 + 3));
    var coefficients: [5]polynomial.CircleCoefficients = undefined;
    coefficients[0] = try polynomial.CircleCoefficients.initBorrowed(storage[0..16]);
    coefficients[1] = try polynomial.CircleCoefficients.initBorrowed(storage[16..32]);
    for (coefficients[2..], 0..) |*column, index| column.* = try polynomial.CircleCoefficients.initBorrowed(storage[32 + index * 32 ..][0..32]);
    var factors4 = [_]QM31{QM31.one()} ** 8;
    var factors5 = [_]QM31{QM31.one()} ** 10;
    var points = [_]core.circle.CirclePointQM31{core.circle.SECURE_FIELD_CIRCLE_GEN} ** 2;
    var first = [_]usize{ 0, 1 };
    var second = [_]usize{ 2, 3, 4 };
    const cases = [_]plans.CoefficientEvalPlan{
        .{ .coeff_log_size = 4, .fold_count = 0, .normalized_points = &points, .flat_factors = &factors4, .column_indices = .{ .items = &first, .capacity = first.len }, .next_same_hash = null },
        .{ .coeff_log_size = 5, .fold_count = 0, .normalized_points = &points, .flat_factors = &factors5, .column_indices = .{ .items = &second, .capacity = second.len }, .next_same_hash = null },
    };
    var values: [5][2]QM31 = undefined;
    var outputs: [5][]QM31 = undefined;
    for (&outputs, &values) |*output, *value| output.* = value;
    try plans.evaluateCoefficientPlans(allocator, &coefficients, &outputs, &cases, false, null);
    for (coefficients, values) |column, actual| {
        const expected = column.evalAtPointWithFactors(if (column.log_size == 4) factors4[0..4] else factors5[0..5]);
        for (actual) |value| try std.testing.expect(value.eql(expected));
    }
}

test "sampled coefficient plan allocation failures release resized scratch exactly once" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, resizeCase, .{});
}
