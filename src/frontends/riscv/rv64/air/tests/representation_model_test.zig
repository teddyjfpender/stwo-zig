//! Representation accounting and projection identities, never proof authority.
const std = @import("std");
const E = @import("../evaluation.zig");
const L = E.L;
const Q = E.Q;
const Encoding = @import("../encoding.zig");
const Frame = @import("../full/frame.zig");
const Division = @import("../division_constraints.zig");
const ids = [_]u8{ 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 15, 16, 17, 18, 24, 26, 28, 29, 30, 31, 32, 35, 36, 37, 38, 39, 40, 43, 44, 45, 46, 47, 48, 49, 52 };
fn planForEcdsa() Encoding.Plan {
    var opcodes: [ids.len]E.O = undefined;
    for (&opcodes, ids) |*opcode, id| opcode.* = @enumFromInt(id);
    return Encoding.Plan.fromOpcodes(&opcodes);
}

test "RV64 geometry model: division has 95 zero residuals but a live tail at arbitrary selector points" {
    const plan = planForEcdsa();
    try std.testing.expect(!plan.support.words[@intFromEnum(L.Word.abs_a)]);
    var random = std.Random.DefaultPrng.init(0x4f4f445350524f4a);
    var physical: [L.MAIN]Q = undefined;
    var advice: Frame.Advice = undefined;
    var output: [256]Q = undefined;
    const zeros = divisionZeros();
    var seen_nonzero: [152]bool = @splat(false);
    for (0..16) |_| {
        for (physical[0..plan.main_count]) |*value| value.* = draw(random.random());
        for (&advice) |*value| value.* = draw(random.random());
        const main = plan.inflateMain(physical[0..plan.main_count]);
        const fixed = Frame.inflate(&advice, .{ draw(random.random()), draw(random.random()), draw(random.random()) });
        var sink = E.Sink{ .values = &output };
        Division.evaluate(.{ .f = &fixed, .m = &main }, &sink);
        try std.testing.expectEqual(@as(usize, 152), sink.count);
        for (output[0..sink.count], zeros, 0..) |value, zero, i| {
            if (zero) try std.testing.expect(value.isZero());
            seen_nonzero[i] = seen_nonzero[i] or !value.isZero();
        }
    }
    var zero_count: usize = 0;
    for (zeros, seen_nonzero) |zero, nonzero| {
        if (zero) zero_count += 1 else try std.testing.expect(nonzero);
    }
    try std.testing.expectEqual(@as(usize, 95), zero_count);
    // A forbidden selector is still a committed physical OODS coordinate.
    // Its separate zero equation does not make this tail polynomial zero.
    @memset(physical[0..plan.main_count], Q.zero());
    @memset(&advice, Q.zero());
    advice[Frame.SELECTORS + @intFromEnum(E.O.DIVU)] = Q.one();
    physical[plan.main_map[L.byte(.result, 0)]] = E.q(7);
    const main = plan.inflateMain(physical[0..plan.main_count]);
    const fixed = Frame.inflate(&advice, .{ Q.zero(), Q.zero(), Q.zero() });
    var sink = E.Sink{ .values = &output };
    Division.evaluate(.{ .f = &fixed, .m = &main }, &sink);
    try std.testing.expect(output[16].eql(E.q(7)));
}
fn divisionZeros() [152]bool {
    var zeros: [152]bool = @splat(false);
    zeros[4] = true;
    var cursor: usize = 9;
    for (0..8) |i| {
        cursor += 2;
        for (0..5) |_| {
            zeros[cursor] = true;
            cursor += 1;
        }
        cursor += 2;
        if (i >= 4) for (0..7) |_| {
            zeros[cursor] = true;
            cursor += 1;
        };
        zeros[cursor] = i != 0;
        cursor += 1;
        for (0..2) |_| {
            zeros[cursor] = true;
            cursor += 1;
        }
    }
    for (0..2) |_| {
        zeros[cursor] = true;
        cursor += 1;
    }
    cursor += 16;
    zeros[cursor] = true;
    std.debug.assert(cursor + 1 == zeros.len);
    return zeros;
}
fn draw(random: std.Random) Q {
    return Q.fromU32Unchecked(random.int(u32) % 2147483647, random.int(u32) % 2147483647, random.int(u32) % 2147483647, random.int(u32) % 2147483647);
}
