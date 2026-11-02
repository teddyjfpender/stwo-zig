const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const K = A.crypto.keccak;
const D = K.pair2n;
const V = A.evaluation;
const Q = V.Q;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn randomQ(r: std.Random) Q {
    return Q.fromM31(M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)), M.fromU64(r.int(u32)));
}
fn pack(comptime F: type, values: [V.LANES]Q) F {
    if (F == V.PackedSecure) return F.fromLanes(values);
    var base: [V.LANES]M = undefined;
    for (&base, values) |*v, q| v.* = q.toM31Array()[0];
    return F.fromLanes(base);
}
fn compare(comptime F: type) !void {
    var prng = std.Random.DefaultPrng.init(0x4b50324e);
    const random = prng.random();
    const packet = try a.create(D.component.ScratchFor(F));
    defer a.destroy(packet);
    const scalar = try a.alloc(D.component.ScratchFor(Q), V.LANES);
    defer a.free(scalar);
    inline for (.{ "fixed", "main", "previous_header" }) |field| {
        for (&@field(packet, field), 0..) |*v, c| {
            var values: [V.LANES]Q = undefined;
            for (&values, 0..) |*q, i| {
                q.* = if (F == V.PackedBase) Q.fromBase(M.fromU64(random.int(u32))) else randomQ(random);
                @field(scalar[i], field)[c] = q.*;
            }
            v.* = pack(F, values);
        }
    }
    for (&packet.shifted, 0..) |*state, j| for (state, 0..) |*v, c| {
        var values: [V.LANES]Q = undefined;
        for (&values, 0..) |*q, i| {
            q.* = if (F == V.PackedBase) Q.fromBase(M.fromU64(random.int(u32))) else randomQ(random);
            scalar[i].shifted[j][c] = q.*;
        }
        v.* = pack(F, values);
    };
    for (&packet.interaction, 0..) |*v, c| {
        var values: [V.LANES]Q = undefined;
        for (&values, 0..) |*q, i| {
            q.* = randomQ(random);
            scalar[i].interaction[c] = q.*;
        }
        v.* = V.PackedSecure.fromLanes(values);
    }
    var previous: [V.LANES]Q = undefined;
    for (&previous) |*q| q.* = randomQ(random);
    var channel = core.channel.blake2s.Blake2sChannel{};
    const ch = K.equations.Challenges.draw(&channel);
    const claim = randomQ(random);
    const actual = try a.alloc(V.PackedSecure, D.layout.CONSTRAINTS);
    defer a.free(actual);
    var ps = V.PackedSink{ .values = actual };
    D.equations.emitFor(F, packet.row(), &packet.interaction, V.PackedSecure.fromLanes(previous), claim, ch, .{ .calls = 5, .first_id = 19 }, &ps);
    const expected = try a.alloc(Q, D.layout.CONSTRAINTS);
    defer a.free(expected);
    for (scalar, 0..) |*s, i| {
        var sink = V.Sink{ .values = expected };
        D.equations.emitFor(Q, s.row(), &s.interaction, previous[i], claim, ch, .{ .calls = 5, .first_id = 19 }, &sink);
        try std.testing.expectEqual(D.layout.CONSTRAINTS, sink.count);
        try std.testing.expectEqual(sink.count, ps.count);
        for (actual, expected) |x, y| try std.testing.expect(x.lane(i).eql(y));
    }
}
test "pair2n every packet base residual equals scalar with arbitrary phase selectors" {
    try compare(V.PackedBase);
}
test "pair2n every packet secure residual equals arbitrary QM31 scalar OODS authority" {
    try compare(V.PackedSecure);
}
