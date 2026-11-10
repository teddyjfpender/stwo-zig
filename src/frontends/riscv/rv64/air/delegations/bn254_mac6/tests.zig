const std = @import("std");
const C = @import("stwo_core");
const M = C.fields.m31.M31;
const O = C.fields.om31.OM31;
const S = @import("source.zig");
const W = @import("witness.zig");
const N = @import("normalize.zig");
const View = struct {
    row: *const S.Row,
    coefficients: W.Coefficients,
    pub fn main(v: @This(), i: usize) O {
        return O.fromBase(M.fromCanonical(v.row[i]));
    }
    pub fn fixed(v: @This(), i: usize) O {
        const x: i32 = if (i == S.FIX_ACTIVE) 1 else if (i >= S.COEFFICIENT and i < S.COEFFICIENT + 6) v.coefficients[i - S.COEFFICIENT] else 0;
        return if (x < 0) O.fromBase(M.fromCanonical(@intCast(-x))).neg() else O.fromBase(M.fromCanonical(@intCast(x)));
    }
};
const Sink = struct {
    values: [S.CONSTRAINTS]O = undefined,
    n: usize = 0,
    pub fn emit(s: *@This(), x: O) void {
        s.values[s.n] = x;
        s.n += 1;
    }
};
fn check(row: *const S.Row, c: W.Coefficients) !void {
    try std.testing.expect(W.valid(row, c));
    var sink = Sink{};
    S.emit(O, View{ .row = row, .coefficients = c }, &sink);
    try std.testing.expectEqual(@as(usize, S.CONSTRAINTS), sink.n);
    for (sink.values) |v| try std.testing.expect(v.isZero());
    const view = View{ .row = row, .coefficients = c };
    for (0..S.BYTE_QUERIES) |i| {
        const words = S.byteQuery(O, view, i).toM31Array();
        try std.testing.expect(words[0].v < 256);
        for (words[1..]) |top| try std.testing.expectEqual(@as(u32, 0), top.v);
    }
}
test "MAC6 independent signed interval and quotient envelopes" {
    const report = S.B.derive();
    try std.testing.expectEqual(@as(i64, 495174076), report.max_residual);
    try std.testing.expectEqual(@as(i64, 884951), report.max_valid_carry);
    try std.testing.expectEqual(@as(usize, 722), S.MAIN);
    try std.testing.expectEqual(@as(usize, 22), S.FIXED);
    try std.testing.expect(S.B.MAX_QUOTIENT < (@as(u272, 1) << 261));
}
test "MAC6 canonical signed quotient edge random and coherent output aliases" {
    const max = S.B.P - 1;
    for ([_]W.Coefficients{ .{ 18, 18, 18, 18, 18, 18 }, .{ -18, -18, -18, -18, -18, -18 }, .{ 18, -18, 17, -17, 1, -1 }, @splat(0) }) |c| {
        const input: W.Inputs = @splat(max);
        const row = try W.fill(&input, c);
        try check(&row, c);
        try std.testing.expectEqual(@as(u32, @intFromBool(W.expression(&input, c) < 0)), row[S.SIGN]);
        const alias = try W.aliasForTesting(&input, c);
        try std.testing.expect(W.arithmeticValid(&alias, c));
        try std.testing.expect(!W.valid(&alias, c));
        var sink = Sink{};
        S.emit(O, View{ .row = &alias, .coefficients = c }, &sink);
        var rejects = false;
        for (sink.values) |v| rejects = rejects or !v.isZero();
        try std.testing.expect(rejects);
        for ([_]usize{ S.SIGN, S.QUOTIENT, S.CARRY, S.DISTANCE, S.BORROW, S.OUTPUT }) |i| {
            if (i == S.SIGN and W.read(&row, S.QUOTIENT, 33) == 0) continue; // +/-zero is semantically permitted
            var forged = row;
            forged[i] ^= 1;
            try std.testing.expect(!W.valid(&forged, c));
        }
    }
    const zero: W.Inputs = @splat(0);
    const empty = try W.fill(&zero, @splat(0));
    try check(&empty, @splat(0));
    var rng = std.Random.DefaultPrng.init(0x6d616336);
    for (0..32) |_| {
        var input: W.Inputs = undefined;
        for (&input) |*v| v.* = rng.random().int(u256) % S.B.P;
        var coefficients: W.Coefficients = undefined;
        for (&coefficients) |*v| v.* = rng.random().intRangeAtMost(i32, -18, 18);
        const row = try W.fill(&input, coefficients);
        try check(&row, coefficients);
    }
    var noncanonical = zero;
    noncanonical[0] = S.B.P;
    try std.testing.expectError(error.Mac6NoncanonicalInput, W.fill(&noncanonical, @splat(1)));
    try std.testing.expectError(error.Mac6CoefficientBound, W.fill(&zero, .{ 19, 0, 0, 0, 0, 0 }));
}
test "MAC6 complete generic equations degree three with variable fixed coefficients" {
    const Samples = struct {
        step: u32,
        pub fn main(v: @This(), i: usize) O {
            return O.fromBase(M.fromCanonical(@intCast(i + 1))).add(O.fromBase(M.fromCanonical(v.step * (@as(u32, @intCast(i)) + 7))));
        }
        pub fn fixed(v: @This(), i: usize) O {
            return O.fromBase(M.fromCanonical(@intCast(i + 2))).add(O.fromBase(M.fromCanonical(v.step * (@as(u32, @intCast(i)) + 11))));
        }
    };
    var residuals: [5]Sink = undefined;
    for (&residuals, 0..) |*sink, i| {
        sink.* = .{};
        S.emit(O, Samples{ .step = @intCast(i) }, sink);
        try std.testing.expectEqual(@as(usize, S.CONSTRAINTS), sink.n);
    }
    for (0..S.CONSTRAINTS) |i| try std.testing.expect(residuals[0].values[i].sub(residuals[1].values[i].mulM31(M.fromCanonical(4))).add(residuals[2].values[i].mulM31(M.fromCanonical(6))).sub(residuals[3].values[i].mulM31(M.fromCanonical(4))).add(residuals[4].values[i]).isZero());
}
fn normalization(a: std.mem.Allocator) !void {
    const terms = [_]N.Term{ .{ .a = 2, .b = 3, .coefficient = 18 }, .{ .a = 3, .b = 3, .coefficient = -18 }, .{ .a = 2, .coefficient = 1 }, .{ .a = 3, .coefficient = -1 }, .{ .a = 2, .b = 2, .coefficient = 17 }, .{ .a = 2, .b = 3, .coefficient = -2 }, .{ .a = 3, .b = 2, .coefficient = 3 }, .{ .a = 2, .coefficient = 1 }, .{ .a = 3, .coefficient = 1 }, .{ .a = 3, .b = 3, .coefficient = 2 } };
    var next: N.ID = 4;
    const before = next;
    var plan = N.lower(a, &terms, &next, 0, 1) catch |err| {
        try std.testing.expectEqual(before, next);
        return err;
    };
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 2), plan.stages.len);
    var values: [6]u256 = .{ 0, 1, 7, 11, 0, 0 };
    for (plan.stages) |stage| {
        var input: W.Inputs = undefined;
        for (stage.input, &input) |id, *v| v.* = values[id];
        const row = try W.fill(&input, stage.coefficients);
        try std.testing.expect(W.valid(&row, stage.coefficients));
        values[stage.writer] = @intCast(W.read(&row, S.OUTPUT, 32));
    }
    var expected: i1024 = 0;
    for (terms) |t| expected += @as(i1024, t.coefficient) * @as(i1024, values[t.a]) * @as(i1024, if (t.b) |b| values[b] else 1);
    try std.testing.expectEqual(@as(u256, @intCast(@mod(expected, @as(i1024, S.B.P)))), values[plan.output()]);
}
test "MAC6 source normalization temp IDs and failure atomicity" {
    try normalization(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, normalization, .{});
    var next: N.ID = 2;
    try std.testing.expectError(error.Mac6ConstantAuthority, N.lower(std.testing.allocator, &.{}, &next, 0, 0));
    try std.testing.expectError(error.Mac6CoefficientBound, N.count(&.{.{ .a = 0, .b = 1, .coefficient = 19 }}));
}
test "MAC6 trusted fixed authority and inactive zero padding" {
    const ids: [13]u32 = @splat(1);
    _ = try S.fixed(true, @splat(18), ids, 2, 3);
    try std.testing.expectError(error.MacCoefficientBound, S.fixed(true, .{ 19, 0, 0, 0, 0, 0 }, ids, 2, 3));
    try std.testing.expectError(error.MacSourceIdBound, S.fixed(true, @splat(0), ids, 1, 3));
    try std.testing.expectError(error.MacSourceMassBound, S.fixed(true, @splat(0), ids, 2, 2147483647));
    try std.testing.expectError(error.MacInactiveAuthority, S.fixed(false, @splat(0), ids, 0, 0));
    const padding = try S.fixed(false, @splat(0), @splat(0), 0, 0);
    const Pad = struct {
        row: S.Row = @splat(0),
        pub fn main(v: @This(), i: usize) O {
            return O.fromBase(M.fromCanonical(v.row[i]));
        }
        pub fn fixed(_: @This(), _: usize) O {
            return O.zero();
        }
    };
    for (padding) |x| try std.testing.expectEqual(@as(i32, 0), x);
    var sink = Sink{};
    S.emit(O, Pad{}, &sink);
    for (sink.values) |v| try std.testing.expect(v.isZero());
    var bad = Pad{};
    bad.row[S.INPUT] = 1;
    sink = .{};
    S.emit(O, bad, &sink);
    try std.testing.expect(!sink.values[1].isZero());
    var zero = try W.fill(&@as(W.Inputs, @splat(0)), @splat(0));
    zero[S.SIGN] = 1; // negative zero has identical integer meaning
    try check(&zero, @splat(0));
    zero[S.CARRY + 2] = 32; // shifted top query becomes256, outside BYTE
    const v = View{ .row = &zero, .coefficients = @splat(0) };
    try std.testing.expectEqual(@as(u32, 256), S.byteQuery(O, v, 32 + 33 + 192).toM31Array()[0].v);
}
