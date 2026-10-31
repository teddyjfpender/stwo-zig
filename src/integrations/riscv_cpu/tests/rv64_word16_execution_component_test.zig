const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const front = @import("stwo_riscv_frontend");
const X = front.rv64_air.word16_execution;
const E = front.rv64_air.evaluation;
const Q = E.Q;
const M = core.fields.m31.M31;
const C = X.component;
const L = X.layout;
fn draw() X.types.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var out: X.types.Challenges = undefined;
    inline for (.{ "register", "function", "rom", "owner" }) |name| {
        @field(out, name).offset = channel.drawSecureFelt();
        for (&@field(out, name).coefficients) |*v| v.* = channel.drawSecureFelt();
    }
    inline for (.{ "range16", "range8" }) |name| @field(out, name) = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    return out;
}
fn component() C.Component {
    return .{ .log_size = 6, .offsets = .{ 0, 0, 0 }, .public = .{ .steps = 1, .epoch = 1, .initial_pc = .{ 0x1000, 0, 0, 0 }, .final_pc = .{ 0x1004, 0, 0, 0 } }, .claim = Q.fromU32Unchecked(3, 5, 7, 11), .challenges = draw() };
}
test "full CPU component native adapters bind exact D3 geometry and masks" {
    const c = component();
    _ = c.asProverComponent();
    _ = c.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, 55), c.nConstraints());
    for (0..55) |index| try std.testing.expectEqual(@as(u8, 3), try c.constraintDegreeBound(index));
    try std.testing.expectError(error.InvalidConstraintIndex, c.constraintDegreeBound(55));
    var logs = try c.traceLogDegreeBounds(std.testing.allocator);
    defer logs.deinitDeep(std.testing.allocator);
    const indices = try c.preprocessedColumnIndices(std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, indices);
    const point = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var masks = try c.maskPoints(std.testing.allocator, point, 7);
    defer masks.deinitDeep(std.testing.allocator);
    for (c.widths(), 0..) |width, tree| for (0..width) |column| try std.testing.expectEqual(@as(usize, if (c.needsPrevious(tree, column)) 2 else 1), masks.items[tree][column].len);
}
fn scalar(c: *const C.Component, columns: []const []const M, inverses: []const M, out: *engine.air.accumulation.ColumnAccumulator) void {
    const n = columns[0].len;
    for (0..n) |row| {
        var values: [C.COLUMNS]Q = undefined;
        var pm: [53]Q = @splat(Q.zero());
        var pi: [40]Q = @splat(Q.zero());
        for (columns, 0..) |column, i| values[i] = Q.fromBase(column[row]);
        const prior = core.utils.previousBitReversedCircleDomainIndex(row, c.log_size, c.log_size + 1);
        for (0..53) |i| if (L.previousMain(i)) {
            pm[i] = Q.fromBase(columns[3 + i][prior]);
        };
        for (0..40) |i| if (L.previousInter(i)) {
            pi[i] = Q.fromBase(columns[56 + i][prior]);
        };
        var acc = E.WeightedAccumulator{ .powers = out.random_coeff_powers };
        var sink = E.Sink{ .values = null, .weighted_accumulator = &acc };
        c.emitFor(Q, values[0..3], values[3..56], &pm, values[56..96], &pi, &sink);
        out.accumulate(row, acc.accumulation.mulM31(inverses[row >> @intCast(c.log_size)]));
    }
}
test "full CPU packed complete weighted kernel equals scalar including prior masks tails and additive buckets" {
    const c = component();
    const n = 128;
    var data: [C.COLUMNS][n]M = undefined;
    var columns: [C.COLUMNS][]const M = undefined;
    for (&data, &columns, 0..) |*column, *view, i| {
        for (column, 0..) |*v, row| v.* = M.fromCanonical(@intCast(1 + i * n + row));
        view.* = column;
    }
    var powers: [55]Q = undefined;
    for (&powers, 0..) |*v, i| v.* = Q.fromU32Unchecked(@intCast(i + 3), 7, 11, 13);
    const inv = [_]M{ M.fromCanonical(3), M.fromCanonical(5) };
    var expected: [4][n]M = @splat(@splat(M.zero()));
    var actual: [4][n]M = @splat(@splat(M.zero()));
    var refcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &expected[0], &expected[1], &expected[2], &expected[3] }, .owns_columns = false };
    var gotcol = engine.secure_column.SecureColumnByCoords{ .columns = .{ &actual[0], &actual[1], &actual[2], &actual[3] }, .owns_columns = false };
    var refout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &refcol, .next_fresh_index = 0 };
    var gotout = engine.air.accumulation.ColumnAccumulator{ .random_coeff_powers = &powers, .col = &gotcol, .next_fresh_index = 0 };
    scalar(&c, &columns, &inv, &refout);
    try C.testing.packedRows.evaluate(&c, &columns, 0, n, &inv, &gotout);
    for (expected, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
    scalar(&c, &columns, &inv, &refout);
    for ([_][2]usize{ .{ 0, 7 }, .{ 7, 65 }, .{ 65, 113 }, .{ 113, n } }) |range| try C.testing.packedRows.evaluate(&c, &columns, range[0], range[1], &inv, &gotout);
    for (expected, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
    const before = actual;
    try std.testing.expectError(error.InvalidExecutionDomain, C.testing.packedRows.evaluate(&c, columns[0 .. columns.len - 1], 0, n, &inv, &gotout));
    for (before, actual) |a, b| try std.testing.expectEqualSlices(M, &a, &b);
}
