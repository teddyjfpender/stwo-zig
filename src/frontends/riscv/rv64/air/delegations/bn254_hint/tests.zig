const std = @import("std");
const C = @import("stwo_core");
const M = C.fields.m31.M31;
const O = C.fields.om31.OM31;
const S = @import("source.zig");
const W = @import("witness.zig");
const View = struct {
    row: *const S.Row,
    fixed_words: S.Fixed,
    pub fn main(v: @This(), index: usize) O {
        return O.fromBase(M.fromCanonical(v.row[index]));
    }
    pub fn fixed(v: @This(), index: usize) O {
        return O.fromBase(M.fromCanonical(v.fixed_words[index]));
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
fn require(row: *const S.Row, fixed: S.Fixed) !void {
    try std.testing.expect(W.valid(row, fixed));
    var sink = Sink{};
    S.emitCanonical(O, View{ .row = row, .fixed_words = fixed }, &sink);
    try std.testing.expectEqual(@as(usize, S.CONSTRAINTS), sink.n);
    for (sink.values) |value| try std.testing.expect(value.isZero());
    const view = View{ .row = row, .fixed_words = fixed };
    const tuple = S.ssaTuple(O, view, O.fromBase(M.fromCanonical(17)), O.fromBase(M.fromCanonical(19)));
    try std.testing.expect(tuple[2].eql(O.fromBase(M.fromCanonical(fixed[S.WRITER_ID]))));
    try std.testing.expect(S.ssaWeight(O, view).eql(O.fromBase(M.fromCanonical(fixed[S.ACTIVE] * fixed[S.FANOUT]))));
    for (0..64) |i| try std.testing.expect(S.byteQuery(O, view, i).eql(view.main(i)));
}
test "BN254 canonical private hint exact source byte carries alias and inactive controls" {
    var rng = std.Random.DefaultPrng.init(0x70726976617465);
    for ([_]u256{ 0, 1, 255, 256, @as(u256, 1) << 200, S.MODULUS / 2, S.MODULUS - 2, S.MODULUS - 1 }) |value| {
        const row = try W.fill(value);
        try require(&row, .{ 1, 23, 7 });
        try std.testing.expectEqual(value, W.read(&row, 0));
    }
    for (0..64) |_| {
        const value = rng.random().int(u256) % S.MODULUS;
        const row = try W.fill(value);
        try require(&row, .{ 1, 23, 7 });
    }
    try std.testing.expectError(error.NonCanonicalPrivateHint, W.fill(S.MODULUS));
    try std.testing.expectError(error.NonCanonicalPrivateHint, W.fill(std.math.maxInt(u256)));
    const alias = W.rawForTesting(S.MODULUS + 7, std.math.maxInt(u256) - 7);
    try std.testing.expect(!W.valid(&alias, .{ 1, 23, 7 }));
    var sink = Sink{};
    S.emitCanonical(O, View{ .row = &alias, .fixed_words = .{ 1, 23, 7 } }, &sink);
    var rejected = false;
    for (sink.values) |r| rejected = rejected or !r.isZero();
    try std.testing.expect(rejected);
    var row = try W.fill(17);
    for (0..S.MAIN) |i| {
        var forged = row;
        forged[i] += 1;
        try std.testing.expect(!W.valid(&forged, .{ 1, 23, 7 }));
    }
    const zero = W.padding();
    try require(&zero, .{ 0, 0, 0 });
    row[0] = 1;
    try std.testing.expect(!W.valid(&row, .{ 0, 0, 0 }));
    var nonboolean = zero;
    nonboolean[S.CARRY] = 2;
    try std.testing.expect(!W.valid(&nonboolean, .{ 1, 23, 7 }));
}
test "BN254 canonical private hint complete equation degree two" {
    const Samples = struct {
        step: u32,
        pub fn main(v: @This(), i: usize) O {
            return O.fromBase(M.fromCanonical(@intCast(i + 7))).add(O.fromBase(M.fromCanonical(v.step * (@as(u32, @intCast(i)) + 13))));
        }
        pub fn fixed(v: @This(), i: usize) O {
            return O.fromBase(M.fromCanonical(@intCast(i + 3))).add(O.fromBase(M.fromCanonical(v.step * (@as(u32, @intCast(i)) + 2))));
        }
    };
    var rows: [4]Sink = undefined;
    for (&rows, 0..) |*sink, i| {
        sink.* = .{};
        S.emitCanonical(O, Samples{ .step = @intCast(i) }, sink);
        try std.testing.expectEqual(@as(usize, S.CONSTRAINTS), sink.n);
    }
    for (0..S.CONSTRAINTS) |i| try std.testing.expect(rows[0].values[i].sub(rows[1].values[i].mulM31(M.fromCanonical(3))).add(rows[2].values[i].mulM31(M.fromCanonical(3))).sub(rows[3].values[i]).isZero());
}
