//! Isolated research only. Does not alter or admit any MAC12 AIR/profile.
const std = @import("std");
const core = @import("stwo_core");
const S = @import("rv64/air/delegations/bn254_mac12/source.zig");
const W = @import("rv64/air/delegations/bn254_mac12/witness.zig");
const C = @import("rv64/air/delegations/bn254_pairing/fixture.zig");
const M = core.fields.m31.M31;
const Q = core.fields.om31.OM31;
const V = struct {
    row: *const S.Row,
    pub fn main(v: *const @This(), col: usize) Q {
        return Q.fromBase(M.fromCanonical(v.row[col]));
    }
    pub fn fixed(_: *const @This(), _: usize) Q {
        return Q.zero();
    }
};
const Sink = struct {
    values: [S.CONSTRAINTS]Q = undefined,
    count: usize = 0,
    pub fn emit(s: *@This(), value: Q) void {
        s.values[s.count] = value;
        s.count += 1;
    }
};
fn retainedOnly(row: *const S.Row) !void {
    var sink = Sink{};
    const v = V{ .row = row };
    S.emit(Q, &v, &sink);
    try std.testing.expectEqual(S.CONSTRAINTS, sink.count);
    var removed_nonzero: usize = 0;
    for (sink.values, 0..) |value, i| {
        if (i >= 1 and i < S.MAIN) {
            if (!value.isZero()) removed_nonzero += 1;
        } else try std.testing.expect(value.isZero());
    }
    try std.testing.expect(removed_nonzero > 0);
}
test "research inactive nonzero input has no retained residual but changes real SSA denominator" {
    var row: S.Row = @splat(0);
    row[S.INPUT] = 1;
    try retainedOnly(&row);
    try std.testing.expect(W.arithmeticValid(&row, @splat(0)));
    try std.testing.expect(!W.valid(&row, @splat(0)));
    const view = V{ .row = &row };
    const wire = C.Wire{ .offset = Q.fromBase(M.fromCanonical(11)), .coefficients = @splat(Q.one()) };
    const actual = C.ssaFraction(.arithmetic, Q, &view, wire, 0);
    try std.testing.expect(actual[0].isZero());
    try std.testing.expect(!actual[1].isZero());
    row[S.INPUT] = 0;
    const zero = C.ssaFraction(.arithmetic, Q, &view, wire, 0);
    try std.testing.expect(!actual[1].eql(zero[1]));
}
test "research padding need not satisfy BYTE or integer canonical bounds when all weights zero" {
    var row: S.Row = @splat(0);
    row[S.INPUT + 32 * 24] = 7;
    row[S.OUTPUT] = 7;
    row[S.DISTANCE] = 2147483647 - 7;
    try retainedOnly(&row);
    const view = V{ .row = &row };
    const beta = Q.fromBase(M.fromCanonical(13));
    for (0..S.BYTE_QUERIES) |lane| {
        const pair = C.byteFraction(.arithmetic, Q, &view, beta, lane);
        try std.testing.expect(pair[0].isZero());
    }
    try std.testing.expect(row[S.DISTANCE] > 255);
}
