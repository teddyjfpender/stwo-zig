//! Dense invalid advice too: SIMD and OODS must implement identical residuals.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const L = @import("layout.zig");
const P = @import("lookup.zig");
const Q = E.Q;
const M = core.fields.m31.M31;
test "new DIV mixed PackedM31 rows preserve every secure scalar residual" {
    const N = L.FIXED + L.MAIN + L.INTERACTION + 6;
    var channel = core.channel.blake2s.Blake2sChannel{};
    var data: [N][16]M = undefined;
    var vectors: [N]E.PackedBase = undefined;
    for (&data, &vectors) |*lanes, *v| {
        for (lanes) |*value| value.* = channel.drawSecureFelt().toM31Array()[0];
        v.* = E.PackedBase.fromLanes(lanes.*);
    }
    var ch: P.Challenges = undefined;
    ch.function.offset = channel.drawSecureFelt();
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    const claim = channel.drawSecureFelt();
    var actual: [L.CONSTRAINTS]E.PackedSecure = undefined;
    var sink = E.PackedSink{ .values = &actual };
    const public = vectors[N - 6 ..];
    P.emitFor(E.PackedBase, vectors[0..3], vectors[3..][0..L.MAIN], public[0], public[1], vectors[3 + L.MAIN ..][0..L.INTERACTION], E.secureFromCoordinatesFor(E.PackedBase, public[2..6].*), claim, ch, &sink);
    try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
    for (0..16) |lane| {
        var row: [N]Q = undefined;
        for (&row, data) |*v, values| v.* = Q.fromBase(values[lane]);
        var expected: [L.CONSTRAINTS]Q = undefined;
        var out = E.Sink{ .values = &expected };
        const p = row[N - 6 ..];
        P.emitFor(Q, row[0..3], row[3..][0..L.MAIN], p[0], p[1], row[3 + L.MAIN ..][0..L.INTERACTION], Q.fromPartialEvals(p[2..6].*), claim, ch, &out);
        for (expected, actual) |wanted, got| try std.testing.expect(wanted.eql(got.lane(lane)));
    }
}
