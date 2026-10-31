//! Dense independent row lanes exercise both base-local equations and secure
//! polynomial/wire/BYTE/RAM/call residuals against the scalar OODS authority.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Secp = @import("../crypto/secp256k1/mod.zig");
const L = Secp.layout;
const B = Secp.bridge;
const Q = E.Q;
const M = core.fields.m31.M31;
const F = E.PackedBase;
const S = E.PackedSecure;
const a = std.testing.allocator;
fn randomQ(rng: std.Random) Q {
    return Q.fromU32Unchecked(rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus, rng.int(u32) % core.fields.m31.Modulus);
}
fn fill(rng: std.Random, values: []F) void {
    for (values) |*value| {
        var lanes: [E.LANES]M = undefined;
        for (&lanes) |*v| v.* = M.fromCanonical(rng.int(u32) % core.fields.m31.Modulus);
        value.* = F.fromLanes(lanes);
    }
}
fn fillSecure(rng: std.Random, values: []S) void {
    for (values) |*value| {
        var lanes: [E.LANES]Q = undefined;
        for (&lanes) |*v| v.* = randomQ(rng);
        value.* = S.fromLanes(lanes);
    }
}
fn extract(destination: []Q, source: []const F, lane: usize) void {
    for (destination, source) |*v, value| v.* = Q.fromBase(value.lane(lane));
}
fn check(packet_values: []const S, scalar: []const Q, lane: usize) !void {
    for (packet_values, scalar, 0..) |pv, sv, constraint| {
        if (!pv.lane(lane).eql(sv)) {
            std.debug.print("secp lane={d} constraint={d}\n", .{ lane, constraint });
            return error.SecpLaneResidualMismatch;
        }
    }
}
test "secp product and linear mixed lanes preserve every scalar residual" {
    var prng = std.Random.DefaultPrng.init(0x534543504c414e45);
    const rng = prng.random();
    var ch: Secp.equations.Challenges = .{ .polynomial = randomQ(rng), .bytes = randomQ(rng), .wire = undefined };
    ch.wire.offset = randomQ(rng);
    for (&ch.wire.coefficients) |*c| c.* = randomQ(rng);
    const fixed = try a.create([L.FIXED]F);
    defer a.destroy(fixed);
    fill(rng, fixed);
    inline for ([_]L.Kind{ .product, .linear }) |kind| {
        const main = try a.alloc(F, L.main(kind));
        defer a.free(main);
        fill(rng, main);
        const current = try a.alloc(S, L.batches(kind));
        defer a.free(current);
        fillSecure(rng, current);
        const previous = S.splat(randomQ(rng));
        const claim = randomQ(rng);
        const count = L.constraints(kind);
        const packet_values = try a.alloc(S, count);
        defer a.free(packet_values);
        var psink = E.PackedSink{ .values = packet_values };
        Secp.equations.emitGeneric(F, kind, &Secp.program.add, .{ .fixed = fixed, .main = main, .previous_active = main[7], .previous_id = main[8] }, current, previous, claim, ch, .{ .calls = 2, .first_id = 7 }, &psink);
        try std.testing.expectEqual(count, psink.count);
        const smain = try a.alloc(Q, main.len);
        defer a.free(smain);
        const scurrent = try a.alloc(Q, current.len);
        defer a.free(scurrent);
        const scalar = try a.alloc(Q, count);
        defer a.free(scalar);
        for (0..E.LANES) |lane| {
            var sfixed: [L.FIXED]Q = undefined;
            extract(&sfixed, fixed, lane);
            extract(smain, main, lane);
            for (scurrent, current) |*v, value| v.* = value.lane(lane);
            var sink = E.Sink{ .values = scalar };
            Secp.equations.emit(kind, &Secp.program.add, .{ .fixed = &sfixed, .main = smain, .previous_active = Q.fromBase(main[7].lane(lane)), .previous_id = Q.fromBase(main[8].lane(lane)) }, scurrent, previous.lane(lane), claim, ch, .{ .calls = 2, .first_id = 7 }, &sink);
            try std.testing.expectEqual(count, sink.count);
            try check(packet_values, scalar, lane);
        }
    }
}
test "secp bridge both packet formats preserve secure state and byte residuals" {
    var prng = std.Random.DefaultPrng.init(0x4252494447454c41);
    const rng = prng.random();
    var ch: B.equations.Challenges = undefined;
    ch.wire.offset = randomQ(rng);
    for (&ch.wire.coefficients) |*c| c.* = randomQ(rng);
    ch.ram.offset = randomQ(rng);
    for (&ch.ram.coefficients) |*c| c.* = randomQ(rng);
    ch.call.offset = randomQ(rng);
    for (&ch.call.coefficients) |*c| c.* = randomQ(rng);
    ch.bytes = randomQ(rng);
    const fixed = try a.create([B.layout.FIXED]F);
    defer a.destroy(fixed);
    const main = try a.create([B.layout.MAIN]F);
    defer a.destroy(main);
    const prior = try a.create([B.layout.PREVIOUS_MAIN]F);
    defer a.destroy(prior);
    const current = try a.create([B.layout.BATCHES]S);
    defer a.destroy(current);
    fill(rng, fixed);
    fill(rng, main);
    fill(rng, prior);
    fillSecure(rng, current);
    const header: [2]F = .{ main[4], main[5] };
    const previous = S.splat(randomQ(rng));
    const claim = randomQ(rng);
    const packet_values = try a.alloc(S, B.layout.CONSTRAINTS);
    defer a.free(packet_values);
    const scalar = try a.alloc(Q, B.layout.CONSTRAINTS);
    defer a.free(scalar);
    inline for ([_]B.equations.PacketFormat{ .big_endian_bytes_v1, .little_endian_words_v2 }) |format| {
        var sink = E.PackedSink{ .values = packet_values };
        B.equations.emitGeneric(F, &Secp.program.double, .{ .packet_format = format, .previous_header = &header, .fixed = fixed, .main = main, .previous_main = prior }, current, previous, claim, ch, .{ .calls = 3, .first_id = 13 }, &sink);
        try std.testing.expectEqual(B.layout.CONSTRAINTS, sink.count);
        for (0..E.LANES) |lane| {
            var sfixed: [B.layout.FIXED]Q = undefined;
            var smain: [B.layout.MAIN]Q = undefined;
            var sprior: [B.layout.PREVIOUS_MAIN]Q = undefined;
            var sheader: [2]Q = undefined;
            var scurrent: [B.layout.BATCHES]Q = undefined;
            extract(&sfixed, fixed, lane);
            extract(&smain, main, lane);
            extract(&sprior, prior, lane);
            extract(&sheader, &header, lane);
            for (&scurrent, current) |*v, value| v.* = value.lane(lane);
            var qsink = E.Sink{ .values = scalar };
            B.equations.emit(&Secp.program.double, .{ .packet_format = format, .previous_header = &sheader, .fixed = &sfixed, .main = &smain, .previous_main = &sprior }, &scurrent, previous.lane(lane), claim, ch, .{ .calls = 3, .first_id = 13 }, &qsink);
            try std.testing.expectEqual(B.layout.CONSTRAINTS, qsink.count);
            try check(packet_values, scalar, lane);
        }
    }
}
