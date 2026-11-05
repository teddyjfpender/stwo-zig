//! M7 cell-diet prototype (stream diet, 2026-11-04): a FUSED Blake2s
//! compression component AIR for the outer (circuit) STARK.
//!
//! CPU-side prototype only. No production wiring: nothing in the prover,
//! verifier, circuit builder or registry imports this file.
//!
//! Today (`builder/blake.zig`, `witness/components.zig`) one Blake2s
//! compression is 80 `blake_g_gate` rows (52 base + 52 interaction columns,
//! 11 preprocessed) plus 8 `triple_xor` rows (20 + 24, 5 preprocessed), and
//! every intermediate state word round-trips through the circuit's Gate wire
//! relation (6 uses + 4 yields per G). This component instead commits ONE row
//! per compression:
//!
//! * state words never leave the row: no Gate-relation traffic, no address
//!   or multiplicity preprocessed columns for intermediates;
//! * words are byte columns; XOR is a lookup into a 2^16-row byte table that
//!   doubles as the byte range check; rotations by 16 and 8 are free byte
//!   permutations; rotations by 12 and 7 use table variants that return the
//!   XOR result already split at bit 4 or bit 7 (no extra lookups);
//! * modular additions have NO carry columns: the carry of each 16-bit half
//!   is the linear expression (sum - result) / 2^16, constrained to {0,1}
//!   (2 operands, degree 2) or {0,1,2} (3 operands, degree 3);
//! * padding is avoided by splitting the row count into at most a few
//!   power-of-two instances of the same AIR (see `paddedRows`).
//!
//! Layout ("compression-level rows": all 10 rounds in one row). A
//! round-level layout (one round per row, state carried by next-row masks)
//! is costed analytically in `diet_census_test_root.zig`; it must repeat the
//! message limbs in every row and is strictly larger.
//!
//! Field: M31. The completeness test checks fill + evaluate against
//! `std.crypto.hash.blake2.Blake2s256`; the soundness smoke test flips every
//! single cell of an honest row and requires a local constraint, a table
//! lookup or the Gate-relation tuple to break.

const std = @import("std");

pub const P: u32 = 0x7fff_ffff;

/// Minimal M31 element (canonical representative in [0, P)).
pub const F = struct {
    v: u32,

    pub const zero: F = .{ .v = 0 };
    pub const one: F = .{ .v = 1 };

    pub fn from(x: u64) F {
        return .{ .v = @intCast(x % P) };
    }
    pub fn add(a: F, b: F) F {
        const s = @as(u64, a.v) + b.v;
        return .{ .v = @intCast(if (s >= P) s - P else s) };
    }
    pub fn sub(a: F, b: F) F {
        return a.add(.{ .v = if (b.v == 0) 0 else P - b.v });
    }
    pub fn neg(a: F) F {
        return zero.sub(a);
    }
    pub fn mul(a: F, b: F) F {
        return .{ .v = @intCast((@as(u64, a.v) * b.v) % P) };
    }
    pub fn mulc(a: F, c: u32) F {
        return a.mul(from(c));
    }
    pub fn pow(a: F, e: u64) F {
        var r = one;
        var base = a;
        var k = e;
        while (k != 0) : (k >>= 1) {
            if (k & 1 == 1) r = r.mul(base);
            base = base.mul(base);
        }
        return r;
    }
    pub fn inv(a: F) F {
        std.debug.assert(a.v != 0);
        return a.pow(P - 2);
    }
    pub fn eql(a: F, b: F) bool {
        return a.v == b.v;
    }
};

const INV_2_16: F = blk: {
    // 2^16 * 2^15 = 2^31 = 1 (mod P), so 2^-16 = 2^15.
    break :blk .{ .v = 1 << 15 };
};

/// Relation ids of this prototype (distinct from the circuit's ids; a
/// production version would take ids from `component_list.zig`).
pub const Relation = enum(u8) {
    /// (x, y, x ^ y) over bytes; 2^16 rows.
    xor8,
    /// (x, y, (x ^ y) & 15, (x ^ y) >> 4); 2^16 rows.
    xor8_split4,
    /// (x, y, (x ^ y) & 127, (x ^ y) >> 7); 2^16 rows.
    xor8_split7,
    /// The circuit's Gate wire relation (address, low u16, high u16).
    gate,
};

pub const Lookup = struct {
    relation: Relation,
    /// +1 for a use, -multiplicity for a yield.
    numerator: F,
    tuple: [4]F,
    len: u8,
};

/// Blake2s IV and message schedule (RFC 7693).
pub const IV = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };
pub const SIGMA = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};
const G_INDICES = [8][4]u8{
    .{ 0, 4, 8, 12 }, .{ 1, 5, 9, 13 }, .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 }, .{ 3, 4, 9, 14 },
};
/// The parameter block word for an unkeyed 32-byte digest.
pub const PARAM0: u32 = 0x0101_0020;

/// Per-row preprocessed (setup-fixed) values: wire addresses, output
/// multiplicities, and the counter/flag words that vary per compression.
pub const Pp = struct {
    addr_h: [8]u32,
    addr_m: [16]u32,
    addr_out: [8]u32,
    mult_out: [8]u32,
    /// Byte counter t0 of this compression (t1 is always 0 in the circuit).
    t0: u32,
    /// 1 for the last block of a message.
    last: u1,

    pub const N_COLUMNS: usize = 8 + 16 + 8 + 8 + 4 + 1;
};

/// One compression's honest inputs.
pub const Inputs = struct {
    h: [8]u32,
    m: [16]u32,
};

// ---------------------------------------------------------------------------
// The row program. `fill` (witness) and `Eval` (verifier view) walk the same
// cursor, so the column order is defined exactly once.

/// A word as four byte values (field elements; little endian).
const Bytes = [4]F;

fn limbsOf(b: Bytes) [2]F {
    return .{ b[0].add(b[1].mulc(256)), b[2].add(b[3].mulc(256)) };
}
fn constBytes(x: u32) Bytes {
    return .{ F.from(x & 0xff), F.from((x >> 8) & 0xff), F.from((x >> 16) & 0xff), F.from(x >> 24) };
}

/// The verifier/constraint view of one row: reads cells in program order and
/// records constraint residuals and lookups. It never sees witness integers.
pub const Eval = struct {
    row: []const F,
    at: usize = 0,
    /// Non-zero residuals found (each is a constraint violation).
    violations: usize = 0,
    n_constraints: usize = 0,
    max_degree: u8 = 0,
    lookups: std.ArrayListUnmanaged(Lookup) = .empty,
    gpa: std.mem.Allocator,

    fn col(self: *Eval) F {
        const v = self.row[self.at];
        self.at += 1;
        return v;
    }
    fn word(self: *Eval) Bytes {
        return .{ self.col(), self.col(), self.col(), self.col() };
    }
    fn constrain(self: *Eval, residual: F, degree: u8) void {
        self.n_constraints += 1;
        self.max_degree = @max(self.max_degree, degree);
        if (!residual.eql(F.zero)) self.violations += 1;
    }
    fn lookup(self: *Eval, relation: Relation, numerator: F, tuple: []const F) !void {
        var l = Lookup{ .relation = relation, .numerator = numerator, .tuple = undefined, .len = @intCast(tuple.len) };
        @memcpy(l.tuple[0..tuple.len], tuple);
        try self.lookups.append(self.gpa, l);
    }

    /// carry e in {0..max}: e (e-1) ... (e-max) = 0.
    fn carryConstraint(self: *Eval, e: F, max: u8) void {
        var r = e;
        var k: u32 = 1;
        while (k <= max) : (k += 1) r = r.mul(e.sub(F.from(k)));
        self.constrain(r, max + 1);
    }

    /// r = sum(operands) mod 2^32, r committed as 4 byte cells. Operands are
    /// u16 limb pairs; the carry of each half is linear (no carry cell).
    fn add(self: *Eval, operands: []const [2]F) Bytes {
        const r = self.word();
        const rl = limbsOf(r);
        var lo = F.zero;
        var hi = F.zero;
        for (operands) |o| {
            lo = lo.add(o[0]);
            hi = hi.add(o[1]);
        }
        const max: u8 = @intCast(operands.len - 1);
        const e_lo = lo.sub(rl[0]).mul(INV_2_16);
        self.carryConstraint(e_lo, max);
        const e_hi = hi.add(e_lo).sub(rl[1]).mul(INV_2_16);
        self.carryConstraint(e_hi, max);
        return r;
    }
    fn xor(self: *Eval, x: Bytes, y: Bytes) !Bytes {
        const z = self.word();
        for (0..4) |j| try self.lookup(.xor8, F.one, &.{ x[j], y[j], z[j] });
        return z;
    }
    /// x ^ y returned as (lo, hi) halves split at bit `split`.
    fn xorSplit(self: *Eval, x: Bytes, y: Bytes, comptime split: u5) !struct { lo: Bytes, hi: Bytes } {
        var lo: Bytes = undefined;
        var hi: Bytes = undefined;
        for (0..4) |j| {
            lo[j] = self.col();
            hi[j] = self.col();
            try self.lookup(if (split == 4) .xor8_split4 else .xor8_split7, F.one, &.{ x[j], y[j], lo[j], hi[j] });
        }
        return .{ .lo = lo, .hi = hi };
    }
    fn g(self: *Eval, a: Bytes, b: Bytes, c: Bytes, d: Bytes, f0: [2]F, f1: [2]F) ![4]Bytes {
        const a1 = self.add(&.{ limbsOf(a), limbsOf(b), f0 });
        const z = try self.xor(d, a1);
        const d1: Bytes = .{ z[2], z[3], z[0], z[1] }; // rotr 16
        const c1 = self.add(&.{ limbsOf(c), limbsOf(d1) });
        const x = try self.xorSplit(b, c1, 4);
        var b1: Bytes = undefined; // rotr 12
        for (0..4) |j| b1[j] = x.hi[(j + 1) % 4].add(x.lo[(j + 2) % 4].mulc(16));
        const a2 = self.add(&.{ limbsOf(a1), limbsOf(b1), f1 });
        const z2 = try self.xor(d1, a2);
        const d2: Bytes = .{ z2[1], z2[2], z2[3], z2[0] }; // rotr 8
        const c2 = self.add(&.{ limbsOf(c1), limbsOf(d2) });
        const y = try self.xorSplit(b1, c2, 7);
        var b2: Bytes = undefined; // rotr 7
        for (0..4) |j| b2[j] = y.hi[j].add(y.lo[(j + 1) % 4].mulc(2));
        return .{ a2, b2, c2, d2 };
    }

    /// Walks one row. Returns the output words' bytes (as field values).
    pub fn run(self: *Eval, pp: Pp) ![8]Bytes {
        var m: [16][2]F = undefined;
        for (&m) |*w| w.* = .{ self.col(), self.col() };
        var h: [8]Bytes = undefined;
        for (&h) |*w| w.* = self.word();
        var v: [16]Bytes = undefined;
        for (0..8) |i| v[i] = h[i];
        for (8..16) |i| v[i] = constBytes(IV[i - 8]);
        // v12 = IV4 ^ t0 (preprocessed bytes); v14 = IV6 or ~IV6 (flag-linear).
        v[12] = constBytes(IV[4] ^ pp.t0);
        const flag = F.from(pp.last);
        for (0..4) |j| {
            const iv = F.from((IV[6] >> @intCast(8 * j)) & 0xff);
            v[14][j] = iv.add(flag.mul(F.from(255).sub(iv).sub(iv)));
        }
        for (SIGMA) |s| for (G_INDICES, 0..) |idx, gi| {
            const out = try self.g(v[idx[0]], v[idx[1]], v[idx[2]], v[idx[3]], m[s[2 * gi]], m[s[2 * gi + 1]]);
            for (idx, out) |k, w| v[k] = w;
        };
        var out: [8]Bytes = undefined;
        for (0..8) |i| {
            const u = try self.xor(h[i], v[i]);
            out[i] = try self.xor(u, v[i + 8]);
        }
        // Gate-relation traffic: 24 uses, 8 yields.
        for (0..8) |i| {
            const l = limbsOf(h[i]);
            try self.lookup(.gate, F.one, &.{ F.from(pp.addr_h[i]), l[0], l[1] });
        }
        for (0..16) |k| try self.lookup(.gate, F.one, &.{ F.from(pp.addr_m[k]), m[k][0], m[k][1] });
        for (0..8) |i| {
            const l = limbsOf(out[i]);
            try self.lookup(.gate, F.from(pp.mult_out[i]).neg(), &.{ F.from(pp.addr_out[i]), l[0], l[1] });
        }
        std.debug.assert(self.at == self.row.len);
        return out;
    }

    pub fn deinit(self: *Eval) void {
        self.lookups.deinit(self.gpa);
    }
};

/// Base (main) columns per compression row.
pub const N_COLUMNS: usize = 16 * 2 + 8 * 4 + 80 * (4 + 4 + 4 + 8 + 4 + 4 + 4 + 8) + 8 * 8;
/// Lookups per row: 16 XOR byte lookups per G, 8 per output word, 32 Gate.
pub const N_LOOKUPS: usize = 80 * 16 + 8 * 8 + 32;

// ---------------------------------------------------------------------------
// Witness fill (honest prover). Mirrors `Eval` cell for cell.

const Fill = struct {
    row: []F,
    at: usize = 0,

    fn put(self: *Fill, x: u32) void {
        self.row[self.at] = F.from(x);
        self.at += 1;
    }
    fn word(self: *Fill, x: u32) void {
        for (0..4) |j| self.put((x >> @intCast(8 * j)) & 0xff);
    }
    fn add(self: *Fill, operands: []const u32) u32 {
        var r: u32 = 0;
        for (operands) |o| r +%= o;
        self.word(r);
        return r;
    }
    fn xor(self: *Fill, x: u32, y: u32) u32 {
        self.word(x ^ y);
        return x ^ y;
    }
    fn xorSplit(self: *Fill, x: u32, y: u32, comptime split: u5) u32 {
        const z = x ^ y;
        for (0..4) |j| {
            const byte = (z >> @intCast(8 * j)) & 0xff;
            self.put(byte & ((@as(u32, 1) << split) - 1));
            self.put(byte >> split);
        }
        return z;
    }
    fn g(self: *Fill, a: u32, b: u32, c: u32, d: u32, f0: u32, f1: u32) [4]u32 {
        const a1 = self.add(&.{ a, b, f0 });
        const d1 = std.math.rotr(u32, self.xor(d, a1), 16);
        const c1 = self.add(&.{ c, d1 });
        const b1 = std.math.rotr(u32, self.xorSplit(b, c1, 4), 12);
        const a2 = self.add(&.{ a1, b1, f1 });
        const d2 = std.math.rotr(u32, self.xor(d1, a2), 8);
        const c2 = self.add(&.{ c1, d2 });
        const b2 = std.math.rotr(u32, self.xorSplit(b1, c2, 7), 7);
        return .{ a2, b2, c2, d2 };
    }
};

/// Writes one honest row; returns the compression output (next chaining value).
pub fn fill(row: []F, in: Inputs, t0: u32, last: bool) [8]u32 {
    std.debug.assert(row.len == N_COLUMNS);
    var f = Fill{ .row = row };
    for (in.m) |w| {
        f.put(w & 0xffff);
        f.put(w >> 16);
    }
    for (in.h) |w| f.word(w);
    var v: [16]u32 = undefined;
    @memcpy(v[0..8], &in.h);
    @memcpy(v[8..16], &IV);
    v[12] ^= t0;
    if (last) v[14] = ~v[14];
    for (SIGMA) |s| for (G_INDICES, 0..) |idx, gi| {
        const out = f.g(v[idx[0]], v[idx[1]], v[idx[2]], v[idx[3]], in.m[s[2 * gi]], in.m[s[2 * gi + 1]]);
        for (idx, out) |k, w| v[k] = w;
    };
    var out: [8]u32 = undefined;
    for (0..8) |i| out[i] = f.xor(f.xor(in.h[i], v[i]), v[i + 8]);
    std.debug.assert(f.at == N_COLUMNS);
    return out;
}

/// Table membership (what the preprocessed tables contain).
pub fn inTable(l: Lookup) bool {
    switch (l.relation) {
        .gate => return true,
        .xor8, .xor8_split4, .xor8_split7 => {
            const x = l.tuple[0].v;
            const y = l.tuple[1].v;
            if (x >= 256 or y >= 256) return false;
            const z = x ^ y;
            return switch (l.relation) {
                .xor8 => l.tuple[2].v == z,
                .xor8_split4 => l.tuple[2].v == (z & 15) and l.tuple[3].v == (z >> 4),
                .xor8_split7 => l.tuple[2].v == (z & 127) and l.tuple[3].v == (z >> 7),
                .gate => unreachable,
            };
        },
    }
}

/// Smallest total row count >= n using at most `max_instances` power-of-two
/// instances of at least 2^min_log rows each (the circuit's N_LANES = 16).
pub fn paddedRows(n: u64, max_instances: u32, min_log: u6) u64 {
    if (n == 0) return 0;
    var remaining = n;
    var total: u64 = 0;
    var used: u32 = 0;
    while (remaining > 0) : (used += 1) {
        const floor_log: u6 = @intCast(63 - @clz(remaining));
        if (used + 1 == max_instances or floor_log < min_log) {
            const ceil = std.math.ceilPowerOfTwo(u64, @max(remaining, @as(u64, 1) << min_log)) catch unreachable;
            return total + ceil;
        }
        const piece = @as(u64, 1) << floor_log;
        total += piece;
        remaining -= piece;
    }
    return total;
}

// ---------------------------------------------------------------------------
// Reference Blake2s compression chain (independent of the row program).

pub fn referenceCompress(h: [8]u32, m: [16]u32, t0: u32, last: bool) [8]u32 {
    var v: [16]u32 = undefined;
    @memcpy(v[0..8], &h);
    @memcpy(v[8..16], &IV);
    v[12] ^= t0;
    if (last) v[14] = ~v[14];
    for (SIGMA) |s| for (G_INDICES, 0..) |idx, gi| {
        var a = v[idx[0]];
        var b = v[idx[1]];
        var c = v[idx[2]];
        var d = v[idx[3]];
        a = a +% b +% m[s[2 * gi]];
        d = std.math.rotr(u32, d ^ a, 16);
        c = c +% d;
        b = std.math.rotr(u32, b ^ c, 12);
        a = a +% b +% m[s[2 * gi + 1]];
        d = std.math.rotr(u32, d ^ a, 8);
        c = c +% d;
        b = std.math.rotr(u32, b ^ c, 7);
        v[idx[0]] = a;
        v[idx[1]] = b;
        v[idx[2]] = c;
        v[idx[3]] = d;
    };
    var out: [8]u32 = undefined;
    for (0..8) |i| out[i] = h[i] ^ v[i] ^ v[i + 8];
    return out;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn evalRow(row: []const F, pp: Pp) !struct { out: [8]Bytes, violations: usize, bad_lookups: usize, gate: [32][3]F, n_constraints: usize, max_degree: u8, n_lookups: usize } {
    var e = Eval{ .row = row, .gpa = testing.allocator };
    defer e.deinit();
    const out = try e.run(pp);
    var bad: usize = 0;
    var gate: [32][3]F = undefined;
    var gi: usize = 0;
    for (e.lookups.items) |l| {
        if (!inTable(l)) bad += 1;
        if (l.relation == .gate) {
            gate[gi] = l.tuple[0..3].*;
            gi += 1;
        }
    }
    return .{ .out = out, .violations = e.violations, .bad_lookups = bad, .gate = gate, .n_constraints = e.n_constraints, .max_degree = e.max_degree, .n_lookups = e.lookups.items.len };
}

fn wordFromBytes(b: Bytes) u32 {
    var x: u32 = 0;
    for (0..4) |j| x |= b[j].v << @intCast(8 * j);
    return x;
}

fn testPp(t0: u32, last: bool) Pp {
    var pp: Pp = .{ .addr_h = undefined, .addr_m = undefined, .addr_out = undefined, .mult_out = @splat(1), .t0 = t0, .last = @intFromBool(last) };
    for (&pp.addr_h, 0..) |*x, i| x.* = @intCast(100 + i);
    for (&pp.addr_m, 0..) |*x, i| x.* = @intCast(200 + i);
    for (&pp.addr_out, 0..) |*x, i| x.* = @intCast(300 + i);
    return pp;
}

/// Hashes `msg` through a chain of fused rows; checks every row is satisfied.
fn fusedBlake2s(msg: []const u8) ![32]u8 {
    var h: [8]u32 = IV;
    h[0] ^= PARAM0;
    const n_blocks = @max(1, (msg.len + 63) / 64);
    const row = try testing.allocator.alloc(F, N_COLUMNS);
    defer testing.allocator.free(row);
    for (0..n_blocks) |bi| {
        var block: [64]u8 = @splat(0);
        const start = bi * 64;
        const end = @min(msg.len, start + 64);
        if (end > start) @memcpy(block[0 .. end - start], msg[start..end]);
        var m: [16]u32 = undefined;
        for (&m, 0..) |*w, k| w.* = std.mem.readInt(u32, block[4 * k ..][0..4], .little);
        const t0: u32 = @intCast(@min(msg.len, (bi + 1) * 64));
        const last = bi == n_blocks - 1;
        const out = fill(row, .{ .h = h, .m = m }, t0, last);
        try testing.expectEqualSlices(u32, &referenceCompress(h, m, t0, last), &out);
        const r = try evalRow(row, testPp(t0, last));
        try testing.expectEqual(@as(usize, 0), r.violations);
        try testing.expectEqual(@as(usize, 0), r.bad_lookups);
        for (r.out, out) |b, w| try testing.expectEqual(w, wordFromBytes(b));
        h = out;
    }
    var digest: [32]u8 = undefined;
    for (h, 0..) |w, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], w, .little);
    return digest;
}

test "fused blake2s: completeness against std Blake2s256 (0..300 bytes, chained blocks)" {
    var prng = std.Random.DefaultPrng.init(0xd1e7_b1a4e);
    var buf: [300]u8 = undefined;
    prng.random().bytes(&buf);
    for ([_]usize{ 0, 1, 3, 4, 15, 16, 31, 32, 55, 63, 64, 65, 127, 128, 129, 191, 192, 255, 256, 300 }) |len| {
        var want: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(buf[0..len], &want, .{});
        try testing.expectEqualSlices(u8, &want, &(try fusedBlake2s(buf[0..len])));
    }
}

test "fused blake2s: row shape (columns, lookups, constraint degree)" {
    const row = try testing.allocator.alloc(F, N_COLUMNS);
    defer testing.allocator.free(row);
    var h: [8]u32 = IV;
    h[0] ^= PARAM0;
    const m: [16]u32 = @splat(0x0123_4567);
    _ = fill(row, .{ .h = h, .m = m }, 64, true);
    const r = try evalRow(row, testPp(64, true));
    try testing.expectEqual(@as(usize, 3328), N_COLUMNS);
    try testing.expectEqual(@as(usize, 1376), N_LOOKUPS);
    try testing.expectEqual(N_LOOKUPS, r.n_lookups);
    // 4 additions x 2 halves per G.
    try testing.expectEqual(@as(usize, 80 * 8), r.n_constraints);
    try testing.expectEqual(@as(u8, 3), r.max_degree);
}

test "fused blake2s: every single-cell change of an honest row is rejected" {
    const row = try testing.allocator.alloc(F, N_COLUMNS);
    defer testing.allocator.free(row);
    var prng = std.Random.DefaultPrng.init(7);
    var m: [16]u32 = undefined;
    for (&m) |*w| w.* = prng.random().int(u32);
    var h: [8]u32 = undefined;
    for (&h) |*w| w.* = prng.random().int(u32);
    _ = fill(row, .{ .h = h, .m = m }, 128, false);
    const pp = testPp(128, false);
    const honest = try evalRow(row, pp);
    try testing.expectEqual(@as(usize, 0), honest.violations + honest.bad_lookups);
    var local: usize = 0;
    var by_gate_only: usize = 0;
    for (0..N_COLUMNS) |c| {
        for ([_]u32{ 1, P - 1, 256, 1 << 16 }) |delta| {
            const saved = row[c];
            row[c] = saved.add(.{ .v = delta });
            defer row[c] = saved;
            const r = try evalRow(row, pp);
            const gate_changed = for (r.gate, honest.gate) |x, y| {
                if (!(x[0].eql(y[0]) and x[1].eql(y[1]) and x[2].eql(y[2]))) break true;
            } else false;
            if (r.violations + r.bad_lookups != 0) {
                local += 1;
            } else if (gate_changed) {
                by_gate_only += 1;
            } else {
                std.debug.print("undetected change: column {d} delta {d}\n", .{ c, delta });
                return error.UndetectedCellChange;
            }
        }
    }
    // Some message-limb changes (e.g. +2^16 on a high limb) keep every local
    // carry in range; those cells are bound through the Gate relation, exactly
    // as today's G gate binds f0/f1. Nothing else may escape.
    try testing.expectEqual(4 * N_COLUMNS, local + by_gate_only);
    try testing.expect(by_gate_only <= 4 * 32);
}

test "fused blake2s: a claimed wrong digest with valid byte encoding is rejected" {
    const row = try testing.allocator.alloc(F, N_COLUMNS);
    defer testing.allocator.free(row);
    var h: [8]u32 = IV;
    h[0] ^= PARAM0;
    const m: [16]u32 = @splat(0xdead_beef);
    _ = fill(row, .{ .h = h, .m = m }, 64, true);
    // Overwrite the last output word with another well-formed byte word.
    for (N_COLUMNS - 4..N_COLUMNS) |c| row[c] = F.from((row[c].v + 1) & 0xff);
    const r = try evalRow(row, testPp(64, true));
    try testing.expect(r.bad_lookups > 0);
}

test "fused blake2s: power-of-two instance splitting" {
    try testing.expectEqual(@as(u64, 131072), paddedRows(74_750, 1, 4));
    try testing.expectEqual(@as(u64, 65536 + 16384), paddedRows(74_750, 2, 4));
    try testing.expectEqual(@as(u64, 65536 + 8192 + 1024), paddedRows(74_750, 3, 4));
    try testing.expectEqual(@as(u64, 16), paddedRows(3, 3, 4));
    try testing.expectEqual(@as(u64, 1 << 20), paddedRows(1 << 20, 3, 4));
}
