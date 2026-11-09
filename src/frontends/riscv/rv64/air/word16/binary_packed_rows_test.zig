const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const C = @import("binary_component.zig");
const P = @import("binary_lookup.zig");
const Packed = @import("binary_packed_rows.zig");
const T = @import("../providers/tables.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
const N = 128;
fn q(x: u32) Q {
    return Q.fromU32Unchecked(x, x + 1, x + 2, x + 3);
}
fn scalar(component: *const C.Component, evaluations: []const []const M, inverses: []const M, output: *engine.air.accumulation.ColumnAccumulator) void {
    const widths = component.widths();
    const inter_start = widths[0] + widths[1];
    for (0..N) |row| {
        var values: [72]Q = undefined;
        var previous: [P.INTERACTION]Q = @splat(Q.zero());
        for (evaluations, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, component.log_size, component.log_size + 1);
        for (0..widths[2]) |i| if (component.needsPrevious(i)) {
            previous[i] = Q.fromBase(evaluations[inter_start + i][prior]);
        };
        var accumulator = E.WeightedAccumulator{ .powers = output.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &accumulator };
        component.emitFor(Q, values[0..widths[0]], values[widths[0]..][0..widths[1]], values[inter_start..][0..widths[2]], previous[0..widths[2]], &sink);
        output.accumulate(row, accumulator.accumulation.mulM31(inverses[row >> @intCast(component.log_size)]));
    }
}
test "Word16 all three SIMD roles preserve arbitrary halos tails additive outputs and malformed-shape atomicity" {
    const claims = P.Claims{ .and_ = q(7), .function = q(11) };
    var ch = P.Challenges{ .and_ = .{ .offset = q(13), .coefficients = undefined }, .function = .{ .offset = q(17), .coefficients = undefined } };
    for (&ch.and_.coefficients, 0..) |*v, i| v.* = q(@intCast(23 + 4 * i));
    for (&ch.function.coefficients, 0..) |*v, i| v.* = q(@intCast(53 + 4 * i));
    var storage: [72][N]M = undefined;
    var evaluations: [72][]const M = undefined;
    for (&storage, &evaluations, 0..) |*column, *view, c| {
        for (column, 0..) |*v, i| v.* = M.fromCanonical(@intCast(1 + c * N + i));
        view.* = column;
    }
    var powers: [P.CONSTRAINTS]Q = undefined;
    for (&powers, 0..) |*v, i| v.* = q(@intCast(109 + 4 * i));
    const inverses = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    for ([_]C.Kind{ .binary, .expected, .and_table }) |kind| {
        const component = C.Component{ .kind = kind, .log_size = 6, .offsets = .{ 0, 0, 0 }, .challenges = ch, .claims = claims };
        const w = component.widths();
        const values = evaluations[0 .. w[0] + w[1] + w[2]];
        var reference: [4][N]M = @splat(@splat(M.zero()));
        var actual: [4][N]M = @splat(@splat(M.zero()));
        var ref_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &reference[0], &reference[1], &reference[2], &reference[3] }, .owns_columns = false };
        var actual_col = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
        var ref_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = powers[0..component.nConstraints()], .col = &ref_col, .next_fresh_index = 0 };
        var actual_output = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = powers[0..component.nConstraints()], .col = &actual_col, .next_fresh_index = 0 };
        scalar(&component, values, &inverses, &ref_output);
        try Packed.evaluate(&component, values, 0, N, &inverses, &actual_output);
        for (reference, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
        scalar(&component, values, &inverses, &ref_output);
        for ([_][2]usize{ .{ 0, 1 }, .{ 1, 17 }, .{ 17, 67 }, .{ 67, N } }) |range| try Packed.evaluate(&component, values, range[0], range[1], &inverses, &actual_output);
        for (reference, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
        const before = actual;
        try std.testing.expectError(error.InvalidWord16Domain, Packed.evaluate(&component, values[0 .. values.len - 1], 0, N, &inverses, &actual_output));
        for (before, actual) |expected, got| try std.testing.expectEqualSlices(M, &expected, &got);
    }
}
test "generic canonical table authority preserves the historical arbitrary-Q equations" {
    var ch = T.Challenges{ .offset = q(2), .coefficients = undefined };
    var tuple: [6]Q = undefined;
    for (&ch.coefficients, 0..) |*v, i| v.* = q(@intCast(19 + 4 * i));
    for (&tuple, 0..) |*v, i| v.* = q(@intCast(43 + 4 * i));
    const first = q(5);
    const last = q(9);
    const multiplicity = q(13);
    const inverse = q(17);
    const sum = q(21);
    const previous = q(25);
    const claim = q(29);
    for ([_]usize{ 3, 6 }) |arity| {
        const term = multiplicity.mul(inverse);
        const old = [4]Q{ inverse.mul(ch.denominator(tuple[0..arity])).sub(Q.one()), sum.sub(previous).add(first.mul(previous)).add(term), first.mul(sum.add(term)), last.mul(sum.sub(claim)) };
        const actual = T.evaluate(tuple[0..arity], first, last, multiplicity, inverse, sum, previous, claim, ch);
        for (old, actual) |expected, got| try std.testing.expect(expected.eql(got));
    }
}
