//! Independent product executor agreement with the real native JUMPDEST AIR.
const std = @import("std");
const testing = std.testing;
const native = @import("stwo_riscv_rv64").testing.bulk_memory;
const air = @import("stwo_riscv_frontend").rv64_air.crypto.bulk_memory;
const J = air.layout.jscan;
const Src = air.source;
const World = native.World;
const Verdict = native.Verdict;
const JFixture = native.JFixture;
const imageCode = native.imageCode;
const honestJ = native.honestJ;
const verdictJ = native.verdictJ;
test "jumpdest: known answers match the executor's reference walk" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // A: JUMPDESTs at 0, 3, 10 (2 is PUSH1 data, 64 and 70 are PUSH32 data).
    try testing.expectEqual(@as(u64, (1 << 0) | (1 << 3) | (1 << 10)), fx.world.states.get(0x9000).?.value);
    try testing.expectEqual(@as(u64, 0), fx.world.states.get(0x9008).?.value);
    // B: every 0x5b except PUSH2 data 51, 52 and the bytes 61..63 after the
    // truncated PUSH32 at 60; the PUSH opcodes at 50 and 60 are not JUMPDESTs.
    var want: u64 = 0;
    for (0..64) |i| if (i < 50 or i == 53 or (i > 53 and i < 60)) {
        want |= @as(u64, 1) << @intCast(i);
    };
    try testing.expectEqual(want, fx.world.states.get(0x9100).?.value);
    // The AIR rows write the same words, and the pending counter crosses the
    // row boundary of call A (PUSH32 at 40: 9 data bytes left at byte 64).
    try testing.expectEqual(@as(u64, (1 << 0) | (1 << 3) | (1 << 10)), Src.jscanBitmap(&fx.wit.jscan[0]));
    try testing.expectEqual(@as(u32, 9), fx.wit.jscan[1][J.pending].v);
    try testing.expectEqual(want, Src.jscanBitmap(&fx.wit.jscan[2]));
    try testing.expectEqual(@as(u32, 1), fx.wit.jscan[1][J.remaining].v);
    // Agreement with the executor's reference on the same bytes.
    const ref = @import("../ethereum_services/candidate_jumpdest.zig");
    var bytes: [64]u8 = undefined;
    for (0..8) |k| std.mem.writeInt(u64, bytes[8 * k ..][0..8], fx.world.states.get(0x5000 + 8 * k).?.value, .little);
    var out: [1]u64 = undefined;
    ref.bitmap(&bytes, &out);
    try testing.expectEqual(want, out[0]);
}

test "jumpdest: random codes of every remainder close and match the reference walk" {
    const a = testing.allocator;
    const ref = @import("../ethereum_services/candidate_jumpdest.zig");
    var prng = std.Random.DefaultPrng.init(0x5b60_7f00);
    const r = prng.random();
    var w = World.init(a);
    defer w.deinit();
    // 17 calls, 1..17 code words each (every last-row remainder 1..8 occurs),
    // biased towards JUMPDEST and PUSH opcodes.
    var expected: [17][3]u64 = undefined;
    for (0..17) |k| {
        const words = k + 1;
        const code = 0x10000 + 0x400 * @as(u64, k);
        var bytes: [17 * 8]u8 = undefined;
        for (bytes[0 .. 8 * words]) |*b| b.* = switch (r.uintLessThan(u8, 4)) {
            0 => 0x5b,
            1 => r.intRangeAtMost(u8, 0x60, 0x7f),
            else => r.int(u8),
        };
        try imageCode(&w, code, bytes[0 .. 8 * words]);
        var out: [3]u64 = @splat(0);
        ref.bitmap(bytes[0 .. 8 * words], out[0 .. (words + 7) / 8]);
        expected[k] = out;
        try w.call(.jumpdest, 0x1000 + 0x20 * @as(u64, k), 1, @intCast(8 + 4 * k), code, 0x30000 + 0x40 * @as(u64, k), 8 * words);
    }
    var wit = try honestJ(a, &w);
    defer wit.deinit(a);
    try testing.expectEqual(Verdict{}, try verdictJ(a, &w, &wit));
    for (0..17) |k| for (0..(k + 8) / 8) |j| {
        try testing.expectEqual(expected[k][j], w.states.get(0x30000 + 0x40 * @as(u64, k) + 8 * j).?.value);
    };
}
