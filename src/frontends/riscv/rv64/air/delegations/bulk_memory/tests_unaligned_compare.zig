//! unaligned compare cases; fixture authority is shared with the other test owners.
//! Known-answer and adversarial tests for the bulk-memory AIR.
//!
//! A forged witness is accepted only if every local residual is zero, every
//! U16 lookup value lies in the table, RAM14 closes against the honest memory
//! chain endpoints (INIT/TERM of every touched word) and OWNER19 closes
//! against the honest CPU ECALL tuples. Each adversarial case names the check
//! that rejects it.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("mod.zig");
const T = B.types;
const L = B.layout;
const Src = B.source;
const M = core.fields.m31.M31;
const testing = std.testing;

const Support = @import("tests_support.zig");
const N = Support.N;
const Verdict = Support.Verdict;
const accepted = Support.accepted;
const mm = Support.mm;
const neg = Support.neg;
const Fixture2 = Support.Fixture2;

test "bulk memory: unaligned copy and memcmp scenario satisfies every constraint and closes every relation" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    try testing.expectEqual([6]u32{ 3, 0, 0, 4 + 3 + 2, 3, 2 + 2 + 1 }, fx.wit.rows);
    try testing.expectEqual(Verdict{}, try fx.check());
}

test "bulk memory: known answers for unaligned copies and memcmp results" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    const w = &fx.world;
    // Byte-level reference of B: dst[i] = initial byte at 0x2003 + i.
    for (0..24) |i| {
        const s = w.initial.get((0x2003 + i) & ~@as(u64, 7)).?.value;
        const d = w.states.get((0x3000 + i) & ~@as(u64, 7)).?.value;
        try testing.expectEqual(@as(u8, @truncate(s >> @intCast(8 * ((0x2003 + i) & 7)))), @as(u8, @truncate(d >> @intCast(8 * (i & 7)))));
    }
    // C copies B's output: byte i of 0x3100.. = byte 5 + i of 0x3000..
    for (0..16) |i| {
        const s = w.states.get((0x3005 + i) & ~@as(u64, 7)).?.value;
        const d = w.states.get((0x3100 + i) & ~@as(u64, 7)).?.value;
        try testing.expectEqual(@as(u8, @truncate(s >> @intCast(8 * ((0x3005 + i) & 7)))), @as(u8, @truncate(d >> @intCast(8 * (i & 7)))));
    }
    const calls = w.calls.items;
    try testing.expectEqual(@as(i2, 0), calls[2].result);
    try testing.expectEqual(@as(u32, 2), calls[2].examined);
    try testing.expectEqual(@as(i2, -1), calls[3].result);
    try testing.expectEqual(@as(u32, 2), calls[3].examined);
    try testing.expectEqual(@as(i2, 1), calls[4].result);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), w.states.get(0x10C0 + 24).?.value);
    try testing.expectEqual(@as(u64, 1), w.states.get(0x1100 + 24).?.value);
    try testing.expectEqual(@as(u64, 0), w.states.get(0x1080 + 24).?.value);
    // AIR rows: E's differing row selects limb 2, high byte, lt.
    const e = fx.wit.cmp[3];
    try testing.expectEqual(@as(u32, 1), e[L.cmp.limbsel + 2].v);
    try testing.expectEqual(@as(u32, 1), e[L.cmp.hb].v);
    try testing.expectEqual(@as(u32, 1), e[L.cmp.lt].v);
    try testing.expectEqual(@as(u32, 1), fx.wit.ucopy[0][L.ucopy.sel + 2].v);
    try testing.expectEqual(@as(u32, 1), fx.wit.ucopy[7][L.ucopy.sel + 6].v);
}

test "bulk memory adversarial: unaligned copy with a wrong shift breaks the call token" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // Run B re-executed at shift 4 (locally consistent: sel and every written
    // limb recomputed): the token src = aligned + 4 differs from the packet's.
    for (0..4) |r| {
        fx.wit.ucopy[r][L.ucopy.sel + 2] = M.zero();
        fx.wit.ucopy[r][L.ucopy.sel + 3] = M.one();
    }
    for (1..4) |r| {
        const prev = fx.world.words.items[r - 1].src.value;
        const cur = fx.world.words.items[r].src.value;
        const v = T.shifted(prev, cur, 4);
        for (0..4) |i| fx.wit.ucopy[r][L.ucopy.out + i] = mm(@as(u16, @truncate(v >> @intCast(16 * i))));
    }
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ranges and !v.owner and !v.ram);
    // Shift changed on one continuation row only: local selector continuity.
    try fx.reset();
    fx.wit.ucopy[2][L.ucopy.sel + 2] = M.zero();
    fx.wit.ucopy[2][L.ucopy.sel + 3] = M.one();
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: unaligned copy with a wrong byte is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) Wrong written limb only: the shift equation fails locally.
    fx.wit.ucopy[2][L.ucopy.out + 1] = fx.wit.ucopy[2][L.ucopy.out + 1].add(M.one());
    const a = try fx.check();
    try testing.expect(a.local != 0);
    // (b) Wrong source byte with a consistent written word: the source read
    // matches no produced token.
    try fx.reset();
    fx.wit.ucopy[2][L.ucopy.bytes + 6] = fx.wit.ucopy[2][L.ucopy.bytes + 6].add(M.one());
    fx.wit.ucopy[2][L.ucopy.bytes + 6] = M.fromCanonical(fx.wit.ucopy[2][L.ucopy.bytes + 6].v & 0xff);
    for ([_]usize{ 2, 3 }) |r| {
        const sh: u3 = 3;
        var bytes_prev: u64 = 0;
        var bytes_cur: u64 = 0;
        for (0..8) |b| {
            bytes_prev |= @as(u64, fx.wit.ucopy[r - 1][L.ucopy.bytes + b].v) << @intCast(8 * b);
            bytes_cur |= @as(u64, fx.wit.ucopy[r][L.ucopy.bytes + b].v) << @intCast(8 * b);
        }
        const v = T.shifted(bytes_prev, bytes_cur, sh);
        for (0..4) |i| fx.wit.ucopy[r][L.ucopy.out + i] = mm(@as(u16, @truncate(v >> @intCast(16 * i))));
    }
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(b.ranges and b.owner and !b.ram);
    // (c) Non-canonical byte split of a correct limb (lo + 256, hi - 1): the
    // limb and RAM agree, but the low byte is out of range.
    try fx.reset();
    const r = 1;
    fx.wit.ucopy[r][L.ucopy.bytes + 2] = fx.wit.ucopy[r][L.ucopy.bytes + 2].add(mm(256));
    fx.wit.ucopy[r][L.ucopy.bytes + 3] = fx.wit.ucopy[r][L.ucopy.bytes + 3].sub(M.one());
    const c = try fx.check();
    try testing.expect(!c.ranges and !accepted(c));
}

test "bulk memory adversarial: unaligned copy skipped or extra words are rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    const honest_rows = fx.wit.ucopy;
    // (a) Drop B's last row: the run ends at remaining = 2.
    for (3..N - 1) |r| fx.wit.ucopy[r] = honest_rows[r + 1];
    fx.wit.rows[3] -= 1;
    try testing.expect((try fx.check()).local != 0);
    // (b) Also relabel remaining so the run is locally valid: the token's N
    // differs and destination word 2 is never written.
    for (0..3) |r| fx.wit.ucopy[r][L.ucopy.remaining] = mm(@intCast(3 - r));
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
    // (c) The lead row also writes (start = 0 on row 0 is a continuation of padding).
    fx.wit.ucopy = honest_rows;
    fx.wit.rows[3] = 9;
    fx.wit.ucopy[0][L.ucopy.start] = M.zero();
    try testing.expect((try fx.check()).local != 0);
    // (d) The destination does not advance after word 0 (same word twice).
    fx.wit.ucopy = honest_rows;
    for (0..4) |i| fx.wit.ucopy[2][L.ucopy.dst + i] = fx.wit.ucopy[1][L.ucopy.dst + i];
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp with a wrong result is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) E claims a > b at its first difference (lt flipped): the gap is negative.
    fx.wit.cmp[3][L.cmp.lt] = M.zero();
    const d = @as(i64, fx.wit.cmp[3][L.cmp.da].v) - @as(i64, fx.wit.cmp[3][L.cmp.db].v);
    fx.wit.cmp[3][L.cmp.gap] = if (d - 1 >= 0) mm(@intCast(d - 1)) else neg(@intCast(1 - d));
    fx.wit.cdesc[1][L.cdesc.neg] = M.zero();
    fx.wit.cdesc[1][L.cdesc.pos] = M.one();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = 1, .epoch = 1, .tick = 20, .rights = 3 });
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ranges);
    // (b) The descriptor writes 0 for E while the body reports -1.
    try fx.reset();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = 0, .epoch = 1, .tick = 20, .rights = 3 });
    fx.wit.cdesc[1][L.cdesc.neg] = M.zero();
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner);
    // (c) A later limb chosen as the first difference while an earlier byte
    // differs: E's row picks limb 3 instead of limb 2.
    try fx.reset();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = std.math.maxInt(u64), .epoch = 1, .tick = 20, .rights = 3 });
    const row = &fx.wit.cmp[3];
    row[L.cmp.limbsel + 2] = M.zero();
    row[L.cmp.limbsel + 3] = M.one();
    try testing.expect((try fx.check()).local != 0);
    // (d) The first difference placed in the high byte while the low bytes
    // differ (F: byte 0 differs).
    try fx.reset();
    fx.wit.cmp[4][L.cmp.hb] = M.one();
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp early or late stops are rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) D stops after its first (equal) word claiming a difference: no byte
    // differs, the gap would be -1.
    const r0 = &fx.wit.cmp[0];
    r0[L.cmp.last] = M.one();
    r0[L.cmp.diff] = M.one();
    r0[L.cmp.limbsel] = M.one();
    r0[L.cmp.alo] = M.fromCanonical(r0[L.cmp.va].v & 0xff);
    r0[L.cmp.ahi] = M.fromCanonical(r0[L.cmp.va].v >> 8);
    r0[L.cmp.blo] = r0[L.cmp.alo];
    r0[L.cmp.bhi] = r0[L.cmp.ahi];
    r0[L.cmp.da] = r0[L.cmp.alo];
    r0[L.cmp.db] = r0[L.cmp.blo];
    r0[L.cmp.gap] = neg(1);
    for (1..N - 1) |r| fx.wit.cmp[r] = fx.wit.cmp[r + 1];
    fx.wit.rows[5] -= 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and !a.ranges);
    // (b) D stops early with result 0 (last without a difference before remaining = 1).
    try fx.reset();
    fx.wit.cmp[0][L.cmp.last] = M.one();
    for (1..N - 1) |r| fx.wit.cmp[r] = fx.wit.cmp[r + 1];
    fx.wit.rows[5] -= 1;
    try testing.expect((try fx.check()).local != 0);
    // (c) E skips its differing word: diff = 0 on unequal words.
    try fx.reset();
    const e = &fx.wit.cmp[3];
    inline for (.{ L.cmp.diff, L.cmp.limbsel + 2, L.cmp.hb, L.cmp.lt, L.cmp.alo, L.cmp.ahi, L.cmp.blo, L.cmp.bhi, L.cmp.da, L.cmp.db, L.cmp.gap }) |col| e[col] = M.zero();
    try testing.expect((try fx.check()).local != 0);
    // (d) D runs past its length: a third row at remaining 0 (is_one = 1 on
    // row 1 forces it to be last).
    try fx.reset();
    const honest_rows = fx.wit.cmp;
    for (3..N) |r| fx.wit.cmp[r] = honest_rows[r - 1];
    fx.wit.cmp[1][L.cmp.last] = M.zero();
    var longer = fx.world.calls.items[2];
    longer.len = 24;
    longer.examined = 3;
    fx.wit.cmp[2] = Src.cmpRow(longer, 2, .{ .dst = .{ .value = 7, .rights = 3 }, .src = .{ .value = 9, .rights = 3 } });
    fx.wit.cmp[2][L.cmp.remaining] = M.zero();
    fx.wit.cmp[2][L.cmp.is_one] = M.zero();
    fx.wit.cmp[2][L.cmp.inv] = neg(1);
    fx.wit.rows[5] += 1;
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp result token without a descriptor or call is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // F's descriptor dropped (memcmp executed as nothing): OWNER and RAM fail.
    fx.wit.cdesc[2] = Src.cdescRow(null);
    fx.wit.rows[4] = 2;
    const v = try fx.check();
    try testing.expect(!v.owner and !v.ram);
}

// ---------------------------------------------------------------------------
// JUMPDEST analysis (`jdesc` + `jscan` + `jtab`). Scenario J: call A (2 scan
// rows, PUSH32 data crossing the row boundary), call B (read-only code, one
// full row, truncated PUSH32 at the end), call C (analyzes A's bitmap words:
// reads an earlier service write). Row map: jdesc 0..2 = A, B, C; jscan
// 0..1 = A, 2 = B, 3 = C.
