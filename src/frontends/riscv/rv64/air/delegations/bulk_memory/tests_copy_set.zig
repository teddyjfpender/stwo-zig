//! copy set cases; fixture authority is shared with the other test owners.
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
const N = Support.N;
const Witness = Support.Witness;
const emptyWitness = Support.emptyWitness;
const honest = Support.honest;
const Verdict = Support.Verdict;
const verdict = Support.verdict;
const accepted = Support.accepted;
const setup = Support.setup;
const Fixture = Support.Fixture;
const mm = Support.mm;
const neg = Support.neg;

test "bulk memory: honest scenario satisfies every constraint and closes every relation" {
    const a = testing.allocator;
    var s = try setup(a);
    defer s.world.deinit();
    defer a.destroy(s.wit);
    try testing.expectEqual(@as(u32, 5), s.wit.rows[0]);
    try testing.expectEqual(@as(u32, 4 + 2 + 2), s.wit.rows[1]); // copy words
    try testing.expectEqual(@as(u32, 3 + 1), s.wit.rows[2]); // set words
    const v = try verdict(a, &s.world, s.wit);
    try testing.expectEqual(Verdict{}, v);
}

test "bulk memory: known answers for copied and filled words" {
    const a = testing.allocator;
    var s = try setup(a);
    defer s.world.deinit();
    defer a.destroy(s.wit);
    // memset 0xAB over 0x2000..0x2018, then memcpy 0x2000.. -> 0x3000..
    for (0..3) |j| try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x2000 + 8 * j).?.value);
    for (0..3) |j| try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x3000 + 8 * j).?.value);
    // Adjacent copy 0x3000..0x3010 -> 0x3010..0x3020 overwrote the word copied from 0x2018.
    try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x3018).?.value);
    try testing.expectEqual(@as(u64, 0x5008) *% 0x9E3779B97F4A7C15, s.world.states.get(0x6008).?.value);
    try testing.expectEqual(@as(u64, 0x3434343434343434), s.world.states.get(0x4000).?.value);
    // AIR rows: the copy row of word 0 carries limb 0xABAB as both src value and dst after.
    try testing.expectEqual(@as(u32, 0xABAB), s.wit.copy[0][L.copy.value].v);
    try testing.expectEqual(@as(u32, 0x34), s.wit.set[3][L.set.fill].v);
    try testing.expectEqual(@as(u32, 1), s.wit.set[3][L.set.remaining].v);
    try testing.expectEqual(@as(u32, 4), s.wit.copy[0][L.copy.remaining].v);
}

// ---------------------------------------------------------------------------
// Adversarial cases. Row map of the standard scenario:
// desc 0..4 = calls A..E; copy 0..3 = B, 4..5 = C, 6..7 = E; set 0..2 = A, 3 = D.

test "bulk memory adversarial: wrong copied word is rejected by RAM closure" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // The copied value column is shared by the src read and the dst write, so a
    // wrong dst value is also a wrong src read: no produced token matches it.
    fx.wit.copy[1][L.copy.value] = fx.wit.copy[1][L.copy.value].add(M.one());
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(!v.ram);
    try testing.expect(v.owner);
}

test "bulk memory adversarial: wrong memset fill is rejected by the call token and RAM" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    for (0..3) |r| fx.wit.set[r][L.set.fill] = mm(0xAC);
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(!v.owner and !v.ram);
}

test "bulk memory adversarial: skipped word fails the chain end or the token length" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const honest_copy = fx.wit.copy;
    // (a) Drop call B's last word: the chain ends at remaining = 2.
    for (3..N - 1) |r| fx.wit.copy[r] = honest_copy[r + 1];
    fx.wit.rows[1] -= 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and a.local != 0);
    // (b) Also relabel remaining 3, 2, 1 so the chain is locally valid: the
    // token still says 4 words and word 3 is never written.
    for (0..3) |r| fx.wit.copy[r][L.copy.remaining] = mm(@intCast(3 - r));
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: extra write fails the chain end or has no token" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const honest_copy = fx.wit.copy;
    // (a) Continue call B with a fifth word (remaining 0): the chain must end at 1.
    for (5..N) |r| fx.wit.copy[r] = honest_copy[r - 1];
    fx.wit.copy[4] = Src.copyRow(fx.world.calls.items[1], 4, .{ .dst = .{ .value = 0, .rights = 3 }, .src = .{ .value = 0, .rights = 3 } });
    fx.wit.copy[4][L.copy.remaining] = mm(0);
    fx.wit.rows[1] += 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and a.local != 0);
    // (b) A standalone one-word chain (start row) with a claimed public count:
    // locally valid, but no descriptor emitted its token and memory changed.
    fx.wit.copy = honest_copy;
    var extra = Src.copyRow(fx.world.calls.items[4], 0, .{ .dst = .{ .value = 0, .rights = 3 }, .src = .{ .value = 0, .rights = 1 } });
    extra[L.copy.remaining] = mm(1);
    fx.wit.copy[8] = extra;
    fx.wit.rows[1] = 9;
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: stale read before a prior write is rejected by RAM closure" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Call C (epoch 2) reads 0x3000, written by call B at (1, 16). Forge the
    // read to observe the initial image instead (a clock-valid cross-epoch gap).
    const r = 4;
    const k = L.copy.src_clock;
    fx.wit.copy[r][k + L.clock.epoch] = mm(0);
    fx.wit.copy[r][k + L.clock.low] = mm(0);
    fx.wit.copy[r][k + L.clock.same] = mm(0);
    fx.wit.copy[r][k + L.clock.gap16] = mm(1);
    const stale = fx.world.initial.get(0x3000).?.value;
    for (0..4) |i| fx.wit.copy[r][L.copy.value + i] = mm(@as(u16, @truncate(stale >> @as(u6, @intCast(16 * i)))));
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ranges and v.owner and !v.ram);
}

test "bulk memory adversarial: wrong clock order needs an out-of-range gap or breaks OWNER" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // (a) Predecessor at the call's own tick: the gap would be -1.
    const r = 0;
    const k = L.copy.dst_clock;
    fx.wit.copy[r][k + L.clock.epoch] = fx.wit.copy[r][L.copy.epoch];
    fx.wit.copy[r][k + L.clock.low] = fx.wit.copy[r][L.copy.tick_low];
    fx.wit.copy[r][k + L.clock.high] = fx.wit.copy[r][L.copy.tick_high];
    fx.wit.copy[r][k + L.clock.same] = mm(1);
    fx.wit.copy[r][k + L.clock.gap16] = neg(1);
    fx.wit.copy[r][k + L.clock.gap8] = mm(0);
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ranges and !a.ram);
    // (b) Move call B's accesses to a later CPU tick: the token/ECALL tick differs.
    fx.wit.* = try honest(fx.a, &fx.world);
    for (0..4) |row| {
        fx.wit.copy[row][L.copy.tick_low] = mm(40);
        if (fx.wit.copy[row][L.copy.dst_clock + L.clock.same].v == 1) fx.wit.copy[row][L.copy.dst_clock + L.clock.gap16] = fx.wit.copy[row][L.copy.dst_clock + L.clock.gap16].add(mm(24));
        if (fx.wit.copy[row][L.copy.src_clock + L.clock.same].v == 1) fx.wit.copy[row][L.copy.src_clock + L.clock.gap16] = fx.wit.copy[row][L.copy.src_clock + L.clock.gap16].add(mm(24));
    }
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: length that is not a multiple of eight needs an out-of-range quotient" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Make call B's packet say len = 36 and forge q0 = 36/8 in the field.
    const inv8 = try M.fromCanonical(8).inv();
    fx.wit.desc[1][L.desc.len_q0] = M.fromCanonical(36).mul(inv8);
    _ = try fx.world.states.put(0x1018 + 16, .{ .value = 36, .epoch = 1, .tick = 16, .rights = 3 });
    _ = try fx.world.initial.put(0x1018 + 16, .{ .value = 36, .rights = 3 });
    const v = try fx.check();
    try testing.expect(!v.ranges);
    // A len with a nonzero limb 2 cannot even be read: limbs 2 and 3 are constants 0.
    try testing.expect(!accepted(v));
}

test "bulk memory adversarial: non-canonical limbs are rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // (a) Copied value limb0 + 2^16, limb1 - 1: same integer, different tuple.
    fx.wit.copy[6][L.copy.value] = fx.wit.copy[6][L.copy.value].add(mm(65536));
    fx.wit.copy[6][L.copy.value + 1] = fx.wit.copy[6][L.copy.value + 1].sub(M.one());
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ram);
    // (b) memset fill byte 0x1AB (non-canonical byte split of limb0 0x1234 is
    // impossible with both bytes < 256): the fill ranges fail.
    fx.wit.* = try honest(fx.a, &fx.world);
    const inv256 = try M.fromCanonical(256).inv();
    fx.wit.desc[3][L.desc.fill_low] = mm(0x134);
    fx.wit.desc[3][L.desc.fill_high] = M.fromCanonical(0x1234 - 0x134).mul(inv256);
    fx.wit.set[3][L.set.fill] = mm(0x134);
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.ranges);
}

test "bulk memory adversarial: forged tag or packet field breaks OWNER or RAM" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // memcpy executed as memset (set bit flipped): a7 limb mismatch.
    fx.wit.desc[1][L.desc.set] = mm(1);
    const a = try fx.check();
    try testing.expect(!a.owner);
    fx.wit.* = try honest(fx.a, &fx.world);
    // Packet dst forged on the descriptor and every body row of call B.
    fx.wit.desc[1][L.desc.dst + 1] = fx.wit.desc[1][L.desc.dst + 1].add(M.one());
    for (0..4) |r| fx.wit.copy[r][L.copy.dst + 1] = fx.wit.copy[r][L.copy.dst + 1].add(M.one());
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(b.owner and !b.ram);
}

test "bulk memory adversarial: overlapping memcpy is rejected natively and by RAM order" {
    const a = testing.allocator;
    // Native admission refuses any alias among packet, src and dst words.
    var w = World.init(a);
    defer w.deinit();
    try w.call(.copy, 0x1000, 1, 8, 0x2008, 0x2000, 16);
    try testing.expectError(error.BulkMemoryOverlap, T.validateCall(w.calls.items[0], w.words.items));
    // AIR: build the rows anyway. Both 0x2008 accesses share tick 8.
    const wit = try a.create(Witness);
    defer a.destroy(wit);
    emptyWitness(wit);
    const call = w.calls.items[0];
    for (&wit.desc, 0..) |*r, i| r.* = Src.descRow(if (i == 0) call else null);
    for (&wit.copy, 0..) |*r, i| r.* = Src.copyRow(if (i < 2) call else null, i, if (i < 2) w.words.items[i] else .{ .dst = undefined });
    wit.rows[0] = 1;
    wit.rows[1] = 2;
    // (a) Snapshot semantics: the 0x2008 read and write consume the same token.
    const snapshot = try verdict(a, &w, wit);
    try testing.expectEqual(@as(usize, 0), snapshot.local);
    try testing.expect(!snapshot.ram);
    // (b) Chain the write after the read at the same tick: gap -1 is out of range.
    const k = L.copy.dst_clock;
    wit.copy[0][k + L.clock.epoch] = mm(1);
    wit.copy[0][k + L.clock.low] = mm(8);
    wit.copy[0][k + L.clock.high] = mm(0);
    wit.copy[0][k + L.clock.same] = mm(1);
    wit.copy[0][k + L.clock.gap16] = neg(1);
    const chained = try verdict(a, &w, wit);
    try testing.expect(!chained.ranges and !accepted(chained));
}

test "bulk memory: constraint degrees are at most three" {
    // Evaluate the residuals of a random point by polynomial-degree probing:
    // each constraint restricted to a line t -> x + t*y must have degree <= 3.
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();
    const ch = challenges();
    inline for (L.kinds) |kind| {
        const W = comptime L.main(kind);
        const I = comptime L.interaction(kind);
        var samples: [5][192]Q = undefined;
        var x: [3 + 2 * W + 2 * I]Q = undefined;
        var y: [3 + 2 * W + 2 * I]Q = undefined;
        for (&x, &y, 0..) |*xi, *yi, i| {
            xi.* = q(@intCast(1000 + i));
            yi.* = q(@intCast(5000 + i));
        }
        for (0..5) |t| {
            var z: [3 + 2 * W + 2 * I]Q = undefined;
            for (&z, x, y) |*zi, xi, yi| zi.* = xi.add(yi.mul(E.q(@intCast(t))));
            var sink = E.Sink{ .values = &samples[t] };
            Eq.emitFor(Q, kind, z[0..3], z[3..][0..W], z[3 + W ..][0..W], z[3 + 2 * W ..][0..I], z[3 + 2 * W + I ..][0..I], 7, .{ .ram = q(1), .owner = q(2), .range16 = q(3) }, ch, &sink);
        }
        // Fourth finite difference vanishes for degree <= 3.
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

// ---------------------------------------------------------------------------
// Unaligned memcpy (`ucopy`) and memcmp (`cdesc` + `cmp`). Scenario 2 row map:
// desc 0..2 = B, C, G; ucopy 0..3 = B (shift 3, 3 words), 4..6 = C (shift 5,
// 2 words, reads B's output), 7..8 = G (shift 7, read-only source);
// cdesc 0..2 = D, E, F; cmp 0..1 = D (equal, 2 words), 2..3 = E (first
// difference in word 1, byte 5: limb 2 high byte, a < b), 4 = F (word 0,
// byte 0, a > b).
