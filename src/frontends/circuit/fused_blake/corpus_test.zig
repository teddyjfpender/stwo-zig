//! Negative corpus v3 hooks BG01-BG08 for `fused_blake2s_v1` (stream
//! blake-gadget; case text: `python3 scripts/rv64_m5_negative_corpus.py spec`).
//! Each W test mutates ONE witness (or preprocessed) value of an honest row
//! and asserts the named check fails: a local constraint, an XOR table
//! lookup, the XOR LogUp balance, or Gate-wire consistency.

const std = @import("std");
const v1 = @import("fused_blake2s_v1.zig");

const F = v1.F;
const testing = std.testing;

/// Column offsets of the v1 row program.
const M_AT: usize = 0; // 16 x (lo, hi)
const H_AT: usize = 32; // 8 x 4 bytes
const G_AT: usize = 64; // 80 x 40 cells
const G_WIDTH: usize = 40;
const A2_IN_G: usize = 20;
const FINAL_AT: usize = G_AT + 80 * G_WIDTH; // 8 x (u 4, out 4)

/// Gate-wire consistency: what the Gate LogUp enforces once multiplicities
/// balance. Every Gate tuple with a non-zero numerator must be
/// (addr, lo, hi, 0, 0) of the wire's actual u32 value.
fn gateConsistent(lookups: []const v1.Lookup, wires: *const std.AutoHashMap(u32, u32)) bool {
    for (lookups) |l| {
        if (l.relation != .gate or l.numerator.v == 0) continue;
        const value = wires.get(l.tuple[0].v) orelse return false;
        if (l.tuple[1].v != (value & 0xffff) or l.tuple[2].v != (value >> 16) or l.tuple[3].v != 0 or l.tuple[4].v != 0) return false;
    }
    return true;
}

fn wiresFor(a: std.mem.Allocator, rec: v1.TapeRecord, pp: v1.Pp) !std.AutoHashMap(u32, u32) {
    var wires = std.AutoHashMap(u32, u32).init(a);
    try wires.put(0, 0); // the zero wire
    for (pp.addr_h, rec.h) |addr, w| if (addr != 0) try wires.put(addr, w);
    for (pp.addr_m, rec.m) |addr, w| if (addr != 0) try wires.put(addr, w);
    const out = v1.referenceCompress(rec);
    for (pp.addr_out, out) |addr, w| if (addr != 0) try wires.put(addr, w);
    return wires;
}

// ---------------------------------------------------------------------------
// XOR LogUp balance over M31 with fixed random challenges (the test's own
// false-pass probability is ~2^-31 per check).

fn inv(a: F) F {
    var r = F.one;
    var base = a;
    var e: u32 = v1.P - 2;
    while (e != 0) : (e >>= 1) {
        if (e & 1 == 1) r = r.mul(base);
        base = base.mul(base);
    }
    return r;
}

const Challenge = struct { z: F, alpha: F };

fn combine(ch: Challenge, relation: v1.Relation, tuple: []const F) F {
    var acc = F.from(relation.id());
    var power = ch.alpha;
    for (tuple) |t| {
        acc = acc.add(power.mul(t));
        power = power.mul(ch.alpha);
    }
    return acc;
}

/// Σ uses 1/(z - c) - Σ_table mult/(z - c) over the three XOR relations.
fn xorLogupSum(ch: Challenge, lookups: []const v1.Lookup, m: v1.Multiplicities) F {
    var sum = F.zero;
    for (lookups) |l| {
        if (l.relation == .gate) continue;
        sum = sum.add(l.numerator.mul(inv(ch.z.sub(combine(ch, l.relation, l.tuple[0..l.len])))));
    }
    for (0..1 << 16) |index| {
        const x: u32 = @intCast(index & 0xff);
        const y: u32 = @intCast(index >> 8);
        const z = x ^ y;
        const rows = [_]struct { rel: v1.Relation, mult: u32, tuple: [4]F, len: usize }{
            .{ .rel = .xor8, .mult = m.xor8[index], .tuple = .{ F.from(x), F.from(y), F.from(z), F.zero }, .len = 3 },
            .{ .rel = .xor8_split4, .mult = m.split4[index], .tuple = .{ F.from(x), F.from(y), F.from(z & 15), F.from(z >> 4) }, .len = 4 },
            .{ .rel = .xor8_split7, .mult = m.split7[index], .tuple = .{ F.from(x), F.from(y), F.from(z & 127), F.from(z >> 7) }, .len = 4 },
        };
        for (rows) |row| if (row.mult != 0) {
            sum = sum.sub(F.from(row.mult).mul(inv(ch.z.sub(combine(ch, row.rel, row.tuple[0..row.len])))));
        };
    }
    return sum;
}

/// The circuit's lookup-mass rule (profiles `requireBlakeLookupMass`): a
/// table key's multiplicity is at most the per-proof lookup count into that
/// table, which must stay below p so the LogUp sum cannot wrap.
fn requireLookupMass(compressions: u64, lookups_per_compression: u64) !void {
    const total = std.math.mul(u64, compressions, lookups_per_compression) catch return error.LookupMassWrap;
    if (total >= v1.P) return error.LookupMassWrap;
}

// ---------------------------------------------------------------------------

test "corpus BG01 fused gadget digest equals reference Blake2s-256 (RFC 7693, 0/1/63/64/65/128 B, random)" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    var abc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&abc, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    try testing.expectEqualSlices(u8, &abc, &(try v1.fusedBlake2s(s, "abc")));
    var empty: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&empty, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
    try testing.expectEqualSlices(u8, &empty, &(try v1.fusedBlake2s(s, "")));
    var prng = std.Random.DefaultPrng.init(0xb601);
    var buf: [4096]u8 = undefined;
    prng.random().bytes(&buf);
    for ([_]usize{ 0, 1, 63, 64, 65, 128, 129, 1000, 4096 }) |len| {
        var want: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(buf[0..len], &want, .{});
        try testing.expectEqualSlices(u8, &want, &(try v1.fusedBlake2s(s, buf[0..len])));
    }
}

test "corpus BG02 one G output word altered is rejected by its addition constraint" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const rec = v1.randomRecord(0xb602, 0);
    _ = v1.fillRow(s.cells, rec);
    // G #13 (round 1, G 5): its a2 output, low byte.
    const at = G_AT + 13 * G_WIDTH + A2_IN_G;
    s.cells[at] = (s.cells[at] + 1) & 0xff;
    const r = v1.checkRow(s.cells, v1.testPp(rec), s.row, s.lookups);
    try testing.expect(r.violations > 0);
}

test "corpus BG03 XOR multiplicity shifted between two table rows breaks the LogUp balance" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const m = try v1.Multiplicities.init(testing.allocator);
    defer m.deinit(testing.allocator);
    const all = try testing.allocator.alloc(v1.Lookup, 4 * v1.N_LOOKUPS);
    defer testing.allocator.free(all);
    var n: usize = 0;
    for (0..4) |i| {
        const rec = v1.randomRecord(0xb603, i);
        _ = v1.fillRow(s.cells, rec);
        const r = v1.checkRow(s.cells, v1.testPp(rec), s.row, s.lookups);
        try testing.expectEqual(@as(usize, 0), r.violations + r.bad_lookups);
        @memcpy(all[n..][0..r.n_lookups], s.lookups[0..r.n_lookups]);
        n += r.n_lookups;
    }
    m.count(all[0..n]);
    const ch = Challenge{ .z = F.from(0x1234_5678), .alpha = F.from(0x0bad_cafe) };
    try testing.expectEqual(@as(u32, 0), xorLogupSum(ch, all[0..n], m).v);
    // Shift one unit of multiplicity from a used row to an unused one.
    const from = for (m.xor8, 0..) |c, i| {
        if (c != 0) break i;
    } else unreachable;
    const to = for (m.xor8, 0..) |c, i| {
        if (c == 0) break i;
    } else unreachable;
    m.xor8[from] -= 1;
    m.xor8[to] += 1;
    try testing.expect(xorLogupSum(ch, all[0..n], m).v != 0);
}

test "corpus BG04 message schedule changed for one round row is rejected" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const rec = v1.randomRecord(0xb604, 0);
    var schedule = v1.SIGMA;
    // Round 3: swap two message indices.
    std.mem.swap(u8, &schedule[3][0], &schedule[3][5]);
    _ = v1.fillRowWithSchedule(s.cells, rec, &schedule);
    const r = v1.checkRow(s.cells, v1.testPp(rec), s.row, s.lookups);
    try testing.expect(r.violations + r.bad_lookups > 0);
}

test "corpus BG05 non-canonical u32 limbs are rejected (message w + 2^32 split; byte-limb borrow)" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const rec = v1.randomRecord(0xb605, 0);
    const pp = v1.testPp(rec);
    var wires = try wiresFor(testing.allocator, rec, pp);
    defer wires.deinit();
    // (a) Message word 3 as (lo + 2^16, hi - 1): same value mod 2^32 inside
    // the additions; the Gate tuple no longer equals the wire's limbs.
    _ = v1.fillRow(s.cells, rec);
    const k = 3;
    try testing.expect(s.cells[M_AT + 2 * k + 1] > 0); // a borrow is possible for this record
    s.cells[M_AT + 2 * k] += 1 << 16;
    s.cells[M_AT + 2 * k + 1] -= 1;
    const r = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r.violations + r.bad_lookups > 0 or !gateConsistent(s.lookups[0..r.n_lookups], &wires));
    // (b) An h word with a byte cell >= 256 (limb kept by a borrow).
    _ = v1.fillRow(s.cells, rec);
    const at = H_AT + 4 * 2;
    s.cells[at] += 256;
    const r2 = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r2.bad_lookups > 0);
}

test "corpus BG06 padding row with non-zero output multiplicity or non-zero output is rejected" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const rec = v1.TapeRecord.padding;
    var pp = v1.Pp.padding();
    var wires = try wiresFor(testing.allocator, rec, pp);
    defer wires.deinit();
    _ = v1.fillRow(s.cells, rec);
    const honest = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expectEqual(@as(usize, 0), honest.violations + honest.bad_lookups);
    try testing.expect(gateConsistent(s.lookups[0..honest.n_lookups], &wires));
    // (a) mult_out != 0: the padding row yields compress(0) at the zero wire.
    pp.mult_out[2] = 1;
    const r = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(!gateConsistent(s.lookups[0..r.n_lookups], &wires));
    // (b) a non-zero output cell in a padding row breaks its XOR lookup.
    pp = v1.Pp.padding();
    s.cells[FINAL_AT + 4] = (s.cells[FINAL_AT + 4] + 1) & 0xff;
    const r2 = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r2.bad_lookups > 0);
}

test "corpus BG07 finalization flag or byte counter of a compression changed is rejected" {
    const s = try v1.Scratch.init();
    defer s.deinit();
    const rec = v1.randomRecord(0xb607, 0);
    _ = v1.fillRow(s.cells, rec);
    var pp = v1.testPp(rec);
    pp.last ^= 1;
    const r = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r.violations + r.bad_lookups > 0);
    pp = v1.testPp(rec);
    pp.v12[1] ^= 0x40; // t0 + 2^14
    const r2 = v1.checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r2.violations + r2.bad_lookups > 0);
}

test "corpus BG08 XOR table mass stays below p at the gadget's max compressions per proof" {
    // Per compression and table: 704 plain byte XORs, 320 per split table.
    try testing.expectEqual(@as(usize, 704), v1.N_XOR8_LOOKUPS);
    const max = (v1.P - 1) / v1.N_XOR8_LOOKUPS; // 3,050,402 compressions per proof
    try requireLookupMass(max, v1.N_XOR8_LOOKUPS);
    try testing.expectError(error.LookupMassWrap, requireLookupMass(max + 1, v1.N_XOR8_LOOKUPS));
    // Largest node measured (24628607 CPU0 leaf, diet census bound): < 2^17 compressions.
    try requireLookupMass(1 << 17, v1.N_XOR8_LOOKUPS + v1.N_SPLIT4_LOOKUPS);
}
