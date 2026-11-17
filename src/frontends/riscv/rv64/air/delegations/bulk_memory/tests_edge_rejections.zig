//! edge rejections cases; fixture authority is shared with the other test owners.
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
const L = B.layout;
const Src = B.source;
const M = core.fields.m31.M31;
const testing = std.testing;

const Support = @import("tests_support.zig");
const mm = Support.mm;
const neg = Support.neg;
const Fixture2 = Support.Fixture2;
const rewriteWord = Support.rewriteWord;
const inverse = Support.inverse;

test "bulk memory adversarial: zero-length memcmp claiming a difference is rejected only by the length inverse" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // F (packet 0x1100, one differing word) re-labelled as len = 0: the body
    // row starts at remaining 0 and still ends on its "difference". Every
    // relation closes; only `len * len_inv = 1` on the descriptor fails.
    try rewriteWord(&fx.world, 0x1100 + 16, 0);
    fx.wit.cdesc[2][L.cdesc.len_q0] = M.zero();
    fx.wit.cdesc[2][L.cdesc.len_inv] = M.one();
    fx.wit.cmp[4][L.cmp.remaining] = M.zero();
    fx.wit.cmp[4][L.cmp.is_one] = M.zero();
    fx.wit.cmp[4][L.cmp.inv] = neg(1);
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 1), v.local);
    try testing.expect(v.ranges and v.ram and v.owner);
}

test "bulk memory adversarial: zero-length unaligned memcpy (lead row only) is rejected only by the lead-row rule" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // G (packet 0x1140, shift 7, one word) re-labelled as len = 0: its run is
    // the lead row alone (remaining 1, token N = 0), source word 1 is not
    // read and the destination is not written.
    try rewriteWord(&fx.world, 0x1140 + 16, 0);
    for ([_]u64{ 0x5008, 0x6100 }) |address| try fx.world.states.put(address, fx.world.initial.get(address).?);
    fx.wit.desc[2][L.desc.len_q0] = M.zero();
    fx.wit.ucopy[7][L.ucopy.remaining] = M.one();
    fx.wit.ucopy[8] = Src.ucopyRow(null, 0, .{ .dst = .{ .value = 0, .rights = 0 } }, .{ .dst = .{ .value = 0, .rights = 0 } });
    fx.wit.rows[3] -= 1;
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 1), v.local);
    try testing.expect(v.ranges and v.ram and v.owner);
}

test "bulk memory adversarial: memcmp forged equal result is rejected by word equality" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // F claims equal (0) on its single differing word; descriptor and result
    // word agree with the forgery, so OWNER and RAM close.
    const f = &fx.wit.cmp[4];
    inline for (.{ L.cmp.diff, L.cmp.limbsel, L.cmp.limbsel + 1, L.cmp.limbsel + 2, L.cmp.limbsel + 3, L.cmp.hb, L.cmp.lt, L.cmp.alo, L.cmp.ahi, L.cmp.blo, L.cmp.bhi, L.cmp.da, L.cmp.db, L.cmp.gap }) |col| f[col] = M.zero();
    fx.wit.cdesc[2][L.cdesc.neg] = M.zero();
    fx.wit.cdesc[2][L.cdesc.pos] = M.zero();
    _ = try fx.world.states.put(0x1100 + 24, .{ .value = 0, .epoch = 2, .tick = 4, .rights = 3 });
    const v = try fx.check();
    try testing.expect(v.local != 0);
    try testing.expect(v.ranges and v.ram and v.owner);
    // E claims equal by reading all three words: word 1 differs, so the
    // equality constraint fails on that row whatever the later rows say.
    try fx.reset();
    const e = &fx.wit.cmp[3];
    inline for (.{ L.cmp.last, L.cmp.diff, L.cmp.limbsel + 2, L.cmp.hb, L.cmp.lt, L.cmp.alo, L.cmp.ahi, L.cmp.blo, L.cmp.bhi, L.cmp.da, L.cmp.db, L.cmp.gap }) |col| e[col] = M.zero();
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp body length differing from the descriptor length is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) E's body claims 4 words (remaining 4, 3) while the descriptor says
    // 3: locally valid (E ends on its difference), the call token differs.
    for (0..2) |j| {
        const row = &fx.wit.cmp[2 + j];
        const remaining: u32 = @intCast(4 - j);
        row[L.cmp.remaining] = mm(remaining);
        row[L.cmp.inv] = inverse(remaining - 1);
    }
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(a.ranges and a.ram and !a.owner);
    // (b) The descriptor also claims 4 words: the token matches again, but the
    // packet length read no longer matches memory.
    fx.wit.cdesc[1][L.cdesc.len_q0] = mm(4);
    fx.wit.cdesc[1][L.cdesc.len_inv] = inverse(4);
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(b.owner and !b.ram);
}
