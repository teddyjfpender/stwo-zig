const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const C = @import("alu_component.zig");
const P = @import("alu_lookup.zig");
const Packed = @import("alu_packed_rows.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const N = 128;
fn q(x: u32) Q {
    return Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn scalar(c: *const C.Component, columns: []const []const M, inverses: []const M, output: *engine.air.accumulation.ColumnAccumulator) void {
    for (0..N) |row| {
        var values: [C.COLUMNS]Q = undefined;
        var previous: [P.INTERACTION]Q = @splat(Q.zero());
        for (columns, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, 6, 7);
        for (0..P.INTERACTION) |i| if (C.Component.needsPrevious(i)) {
            previous[i] = Q.fromBase(columns[2 + P.MAIN + i][prior]);
        };
        var accumulator = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
        c.emitFor(Q, values[0..2], values[2..][0..P.MAIN], values[2 + P.MAIN ..], &previous, &sink);
        output.accumulate(row, accumulator.accumulation.mulM31(inverses[row >> 6]));
    }
}
test "ALU16 SIMD complete row kernel matches scalar halos nonaligned tails and additive output" {
    var ch = P.Challenges{ .range16 = .{ .offset = q(3), .coefficient = q(7) }, .function = .{ .offset = q(11), .coefficients = undefined } };
    for (&ch.function.coefficients, 0..) |*v, i| v.* = q(@intCast(17 + 4 * i));
    const component = C.Component{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = .{ .range16 = q(73), .function = q(79) } };
    var storage: [C.COLUMNS][N]M = undefined;
    var columns: [C.COLUMNS][]const M = undefined;
    for (&storage, &columns, 0..) |*data, *view, c| {
        for (data, 0..) |*v, i| v.* = M.fromCanonical(@intCast(c * N + i + 1));
        view.* = data;
    }
    var powers: [P.CONSTRAINTS]Q = undefined;
    for (&powers, 0..) |*v, i| v.* = q(@intCast(101 + 4 * i));
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    var reference: [4][N]M = @splat(@splat(M.zero()));
    var actual: [4][N]M = @splat(@splat(M.zero()));
    var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &reference[0], &reference[1], &reference[2], &reference[3] }, .owns_columns = false };
    var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
    var ref_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &ref_col, .next_fresh_index = 0 };
    var actual_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &actual_col, .next_fresh_index = 0 };
    scalar(&component, &columns, &inverses, &ref_output);
    try Packed.evaluate(&component, &columns, 0, N, &inverses, &actual_output);
    for (reference, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
    scalar(&component, &columns, &inverses, &ref_output);
    for ([_][2]usize{ .{ 0, 7 }, .{ 7, 65 }, .{ 65, 113 }, .{ 113, N } }) |range| try Packed.evaluate(&component, &columns, range[0], range[1], &inverses, &actual_output);
    for (reference, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
    const before = actual;
    try std.testing.expectError(error.InvalidAluDomain, Packed.evaluate(&component, columns[0 .. columns.len - 1], 0, N, &inverses, &actual_output));
    for (before, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
}
