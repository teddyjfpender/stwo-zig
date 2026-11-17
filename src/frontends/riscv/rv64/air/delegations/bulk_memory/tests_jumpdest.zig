//! jumpdest cases; fixture authority is shared with the other test owners.
//! Known-answer and adversarial tests for the bulk-memory AIR.
//!
//! A forged witness is accepted only if every local residual is zero, every
//! U16 lookup value lies in the table, RAM14 closes against the honest memory
//! chain endpoints (INIT/TERM of every touched word) and OWNER19 closes
//! against the honest CPU ECALL tuples. Each adversarial case names the check
//! that rejects it.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const B = @import("mod.zig");
const T = B.types;
const L = B.layout;
const Eq = B.equations;
const Src = B.source;
const M = core.fields.m31.M31;
const Q = T.Q;
const testing = std.testing;

const Support = @import("tests_support.zig");
const q = Support.q;
const challenges = Support.challenges;
const World = Support.World;
const Verdict = Support.Verdict;
const accepted = Support.accepted;
const mm = Support.mm;
const JLOG = Support.JLOG;
const J = Support.J;
const JFixture = Support.JFixture;

test "jumpdest: honest scenario satisfies every constraint and closes every relation" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    try testing.expectEqual([3]u32{ 3, 4, T.TABLE_ENTRIES }, fx.wit.rows);
    try testing.expectEqual(Verdict{}, try fx.check());
}

test "jumpdest adversarial: forged JUMPDEST inside PUSH data is rejected by the table" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // Byte 51 of call B is PUSH2 data 0x5b: claim it is a JUMPDEST, with the
    // environment's final bitmap agreeing and the table multiplicities redone.
    // (Call B's bitmap is not read later, so RAM closes with the forged word.)
    fx.wit.jscan[2][J.jd + 51] = M.one();
    try fx.acceptWrite(0x9100, &fx.wit.jscan[2]);
    fx.retable();
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ram);
    try testing.expect(!v.owner);
    // Same with the counter forged to 0 at byte 51 (as if PUSH2 had no data,
    // so byte 51 legitimately reads as a JUMPDEST): the PUSH2 transition of
    // byte 50 no longer matches.
    fx.wit.jscan[2][J.pending + 51] = M.zero();
    fx.wit.jscan[2][J.pending + 52] = M.zero();
    fx.wit.jscan[2][J.jd + 52] = M.one();
    try fx.acceptWrite(0x9100, &fx.wit.jscan[2]);
    fx.retable();
    try testing.expect(!(try fx.check()).owner);
}

test "jumpdest adversarial: missing JUMPDEST is rejected by the table" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    fx.wit.jscan[2][J.jd + 0] = M.zero();
    try fx.acceptWrite(0x9100, &fx.wit.jscan[2]);
    fx.retable();
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(v.ram);
    try testing.expect(!v.owner);
}

test "jumpdest adversarial: JUMPDEST in push data across rows needs a broken counter chain" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // Byte 64 (row 1, byte 0) is PUSH32 data: reset the carried counter so it
    // reads as a JUMPDEST. The continuity constraint pending_0 = prev pending_64 fails.
    const row = &fx.wit.jscan[1];
    row[J.pending] = M.zero();
    row[J.jd] = M.one();
    for (1..8) |k| row[J.pending + k] = M.zero();
    try fx.acceptWrite(0x9008, row);
    fx.retable();
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(v.local > 0);
}

test "jumpdest adversarial: bits past the code length are rejected" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // Call A's last row has one valid word: a JUMPDEST bit in word 1 (byte 72).
    fx.wit.jscan[1][J.jd + 8] = M.one();
    try fx.acceptWrite(0x9008, &fx.wit.jscan[1]);
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(v.local > 0);
}

test "jumpdest adversarial: wrong lengths are rejected" {
    const a = testing.allocator;
    {
        // Run ended after row 0 of call A (9 words): sum(valid) = remaining fails.
        var fx = try JFixture.init(a);
        defer fx.deinit();
        fx.wit.jscan[0][J.last] = M.one();
        try testing.expect((try fx.check()).local > 0);
    }
    {
        // Fewer valid words on the last row (word 0 only is honest; claim a
        // second valid word with remaining 1).
        var fx = try JFixture.init(a);
        defer fx.deinit();
        fx.wit.jscan[1][J.valid] = M.one();
        try testing.expect((try fx.check()).local > 0);
    }
    {
        // Packet length forged in the descriptor (16 words): RAM (packet read).
        var fx = try JFixture.init(a);
        defer fx.deinit();
        fx.wit.jdesc[0][L.jdesc.len_q0] = mm(16);
        const v = try fx.check();
        try testing.expect(!v.ram and !v.owner);
    }
    {
        // Remaining relabelled on call A's scan rows (pretend 16 words, 2 full
        // rows): the token's word count no longer matches the descriptor.
        var fx = try JFixture.init(a);
        defer fx.deinit();
        fx.wit.jscan[0][J.remaining] = mm(16);
        fx.wit.jscan[1][J.remaining] = mm(8);
        for (0..7) |w| fx.wit.jscan[1][J.valid + w] = M.one();
        const v = try fx.check();
        try testing.expect(!accepted(v));
        try testing.expect(!v.owner or !v.ram);
    }
}

test "jumpdest adversarial: counter carried into the next call is rejected" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // Call B starts with call A's leftover counter (1 data byte of A's PUSH32
    // after its last code byte); start rows have pending 0.
    try testing.expectEqual(@as(u32, 1), fx.wit.jscan[1][J.pending + 8].v);
    fx.wit.jscan[2][J.pending] = fx.wit.jscan[1][J.pending + 8];
    try testing.expect((try fx.check()).local > 0);
}

test "jumpdest adversarial: stale code read and forged code bytes are rejected by RAM" {
    const a = testing.allocator;
    {
        // Call C reads A's bitmap word 0x9000: pretend it still has its image value.
        var fx = try JFixture.init(a);
        defer fx.deinit();
        const row = &fx.wit.jscan[3];
        const old: u64 = @as(u64, 0x9000) *% 0x9E3779B97F4A7C15;
        for (0..8) |i| row[J.bytes + i] = mm(@as(u8, @truncate(old >> @intCast(8 * i))));
        var p: u8 = 0;
        for (0..16) |k| {
            const t = T.transition(p, @intCast(row[J.bytes + k].v));
            row[J.jd + k] = mm(t.jumpdest);
            p = t.next;
            row[J.pending + k + 1] = mm(p);
        }
        try fx.acceptWrite(0x9200, row);
        fx.retable();
        const v = try fx.check();
        try testing.expect(!accepted(v));
        try testing.expectEqual(@as(usize, 0), v.local);
        try testing.expect(v.owner);
        try testing.expect(!v.ram);
    }
    {
        // A code byte changed (table-consistent): the code read matches no token.
        var fx = try JFixture.init(a);
        defer fx.deinit();
        fx.wit.jscan[2][J.bytes + 5] = mm(0x02);
        fx.wit.jscan[2][J.jd + 5] = M.zero();
        try fx.acceptWrite(0x9100, &fx.wit.jscan[2]);
        fx.retable();
        const v = try fx.check();
        try testing.expectEqual(@as(usize, 0), v.local);
        try testing.expect(v.owner);
        try testing.expect(!v.ram);
    }
}

test "jumpdest adversarial: misaligned code, read-only bitmap and aliasing are refused natively" {
    const a = testing.allocator;
    const bad = [_]struct { code: u64, len: u64, bitmap: u64, e: anyerror }{
        .{ .code = 0x8008, .len = 64, .bitmap = 0x9000, .e = error.InvalidBulkMemoryRange },
        .{ .code = 0x8000, .len = 64, .bitmap = 0x9004, .e = error.InvalidBulkMemoryRange },
        .{ .code = 0x8000, .len = 60, .bitmap = 0x9000, .e = error.InvalidBulkMemoryLength },
        .{ .code = 0x8000, .len = 64, .bitmap = 0x5000, .e = error.InvalidBulkMemoryPredecessor },
        .{ .code = 0x8000, .len = 128, .bitmap = 0x8040, .e = error.BulkMemoryOverlap },
    };
    for (bad) |c| {
        var w = World.init(a);
        defer w.deinit();
        try w.call(.jumpdest, 0x1000, 1, 8, c.code, c.bitmap, c.len);
        try testing.expectError(c.e, Src.Source.init(a, .jdesc, w.calls.items, w.words.items, JLOG));
    }
    // AIR side of misalignment: code limb 0 = 64 q has no q below 1024.
    var fx = try JFixture.init(a);
    defer fx.deinit();
    const D = L.jdesc;
    fx.wit.jdesc[0][D.code_q] = M.fromCanonical(0x8008).div(M.fromCanonical(64)) catch unreachable;
    try testing.expect(!(try fx.check()).ranges);
}

test "jumpdest adversarial: bitmap write to a read-only word or a forged tick is rejected" {
    var fx = try JFixture.init(testing.allocator);
    defer fx.deinit();
    // Writes carry rights (1, 1): a read-only predecessor token never matches.
    fx.wit.jscan[0][J.before] = fx.wit.jscan[0][J.before].add(M.one());
    const v = try fx.check();
    try testing.expect(!v.ram);
    // Scan rows moved to a later tick than their descriptor: OWNER (token).
    var fx2 = try JFixture.init(testing.allocator);
    defer fx2.deinit();
    fx2.wit.jscan[2][J.tick_low] = fx2.wit.jscan[2][J.tick_low].add(mm(4));
    const v2 = try fx2.check();
    try testing.expect(!accepted(v2));
}

test "jumpdest: constraint degrees are at most three" {
    const ch = challenges();
    inline for (L.jumpdest_kinds) |kind| {
        const FW = comptime L.fixedWidth(kind);
        const W = comptime L.main(kind);
        const I = comptime L.interaction(kind);
        const total = FW + 2 * W + 2 * I;
        var samples: [5][1024]Q = undefined;
        var x: [total]Q = undefined;
        var y: [total]Q = undefined;
        for (&x, &y, 0..) |*xi, *yi, i| {
            xi.* = q(@intCast(1000 + i));
            yi.* = q(@intCast(5000 + i));
        }
        for (0..5) |t| {
            var z: [total]Q = undefined;
            for (&z, x, y) |*zi, xi, yi| zi.* = xi.add(yi.mul(E.q(@intCast(t))));
            var sink = E.Sink{ .values = &samples[t] };
            Eq.emitFor(Q, kind, z[0..FW], z[FW..][0..W], z[FW + W ..][0..W], z[FW + 2 * W ..][0..I], z[FW + 2 * W + I ..][0..I], 7, .{ .ram = q(1), .owner = q(2), .range16 = q(3) }, ch, &sink);
            try testing.expectEqual(L.constraints(kind), sink.count);
        }
        for (0..L.constraints(kind)) |c| {
            var d: [5]Q = undefined;
            for (0..5) |t| d[t] = samples[t][c];
            var level: usize = 5;
            while (level > 1) : (level -= 1) for (0..level - 1) |i| {
                d[i] = d[i + 1].sub(d[i]);
            };
            try testing.expect(d[0].isZero());
        }
    }
}
