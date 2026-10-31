const std = @import("std");
const E = @import("../../evaluation.zig");
const byte = @import("../../range/provider.zig");
const tables = @import("../tables.zig");
const ByteComponent = @import("../byte.zig").Component;
const TableComponent = @import("../table_component.zig").Component;
const Q = E.Q;

test "lookup provider degree metadata includes cubic first-row multiplicity closure" {
    const typed = tables.Challenges{ .offset = E.q(13), .coefficients = @splat(E.q(17)) };
    const b = ByteComponent{ .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .alpha = E.q(19), .claim = E.q(23) };
    const table = TableComponent{ .kind = .byte_and, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .challenges = typed, .claim = E.q(23) };
    var results: [2][5][4]Q = undefined;
    for (0..5) |t| {
        var x: [10]Q = undefined;
        for (&x, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 1), @intCast(i + 2), @intCast(i + 3), @intCast(i + 4))
            .add(E.q(@intCast((i + 2) * t)));
        results[0][t] = byte.evaluate(x[0], x[1], x[2], x[3], x[4], x[5], x[6], E.q(23), E.q(19));
        results[1][t] = tables.evaluate(x[7..10], x[1], x[2], x[3], x[4], x[5], x[6], E.q(23), typed);
    }
    for (0..2) |family| {
        for (0..4) |constraint| {
            var values: [5]Q = undefined;
            for (&values, 0..) |*value, t| value.* = results[family][t][constraint];
            const degree = if (family == 0) try b.constraintDegreeBound(constraint) else try table.constraintDegreeBound(constraint);
            try std.testing.expectEqual(@as(u8, if (constraint == 2) 3 else 2), degree);
            for (0..degree) |order| for (0..4 - order) |row| {
                values[row] = values[row + 1].sub(values[row]);
            };
            try std.testing.expect(!values[0].isZero()); // Exact highest degree.
            try std.testing.expect(values[1].sub(values[0]).isZero());
        }
    }
    try std.testing.expectError(error.InvalidConstraintIndex, b.constraintDegreeBound(4));
    try std.testing.expectError(error.InvalidConstraintIndex, table.constraintDegreeBound(4));
}
