//! `fused_blake2s_v1`: the production specification of the fused Blake2s
//! compression component of the outer (circuit) STARK (stream blake-gadget,
//! M5, an M7 lever pulled forward).
//!
//! Productionised from the diet prototype (`../diet/fused_blake2s.zig`,
//! x0.701 committed cells per compression). This file is the single
//! definition of the v1 row program; the CUDA fill kernel
//! (`backends/cuda/native/rv64/fused_blake2s.cu`) mirrors `fillRow` cell for
//! cell and is checked against it (`test "... GPU dump ..."`).
//!
//! What v1 fixes (all of it is AIR, nothing is a hash change):
//!
//! * One row per compression ("k = 1"): all 10 rounds live in the row, so no
//!   intermediate state word touches the circuit's Gate relation. The
//!   round-level k = 10 layout was measured worse (x1.107) and is not built.
//! * Words are byte cells. XOR is a lookup: plain XOR uses the circuit's
//!   existing `VerifyBitwiseXor_8` table (2^16 rows), which also range-checks
//!   both inputs and the output to bytes. `rotr12` / `rotr7` use two new
//!   2^16-row tables that return the XOR byte already split at bit 4 / 7.
//!   `rotr16` / `rotr8` are free byte permutations.
//! * Modular additions have no carry cells: each 16-bit half's carry is the
//!   linear expression `(sum - result) / 2^16`, constrained to {0,1}
//!   (two operands, degree 2) or {0,1,2} (three operands, degree 3).
//! * No power-of-two padding tax: a node's compressions are split over at
//!   most `MAX_INSTANCES` power-of-two instances of this AIR
//!   (`planInstances`); padding rows are honest fills of the zero compression
//!   wired to address 0 with output multiplicity 0.
//! * The witness is filled from a recorded hint tape (`TapeRecord`, 26 words
//!   per compression), never from the circuit's per-gate DAG.
//!
//! Interaction: lookups are paired two per secure interaction column, as in
//! every other circuit component, so `INTERACTION_COLUMNS = 4 * ceil(L/2)`.

const std = @import("std");

pub const VERSION = "fused_blake2s_v1";
/// Rows per compression (the "k" of the diet census).
pub const ROWS_PER_COMPRESSION: usize = 1;
/// Most power-of-two instances per node (`planInstances`).
pub const MAX_INSTANCES: u32 = 3;
/// `N_LANES`: the smallest instance is 2^4 rows.
pub const MIN_LOG_ROWS: u6 = 4;

pub const P: u32 = 0x7fff_ffff;

// ---------------------------------------------------------------------------
// Relation ids. GATE and XOR_8 are the circuit's (`common/component_list.zig`,
// cross-checked in `fused_blake_test_root.zig`). The two split tables are new:
// id = (first four little-endian bytes of blake2s256(name)) & 0x7fffffff,
// checked by `test "relation id derivation"`.

pub const GATE_RELATION_ID: u32 = 378353459;
pub const XOR_8_RELATION_ID: u32 = 112558620;
pub const XOR_8_SPLIT4_NAME = "VerifyBitwiseXor_8_Split4";
pub const XOR_8_SPLIT4_RELATION_ID: u32 = 734258691;
pub const XOR_8_SPLIT7_NAME = "VerifyBitwiseXor_8_Split7";
pub const XOR_8_SPLIT7_RELATION_ID: u32 = 1830449294;

/// Minimal M31 element (canonical representative in [0, P)). Self-contained so
/// this file tests standalone; semantics are those of `stwo_core` M31.
pub const F = struct {
    v: u32,

    pub const zero: F = .{ .v = 0 };
    pub const one: F = .{ .v = 1 };

    pub inline fn from(x: u64) F {
        return .{ .v = @intCast(x % P) };
    }
    pub inline fn add(a: F, b: F) F {
        const s = @as(u64, a.v) + b.v;
        return .{ .v = @intCast(if (s >= P) s - P else s) };
    }
    pub inline fn sub(a: F, b: F) F {
        return a.add(.{ .v = if (b.v == 0) 0 else P - b.v });
    }
    pub inline fn neg(a: F) F {
        return zero.sub(a);
    }
    pub inline fn mul(a: F, b: F) F {
        return .{ .v = @intCast((@as(u64, a.v) * b.v) % P) };
    }
    pub inline fn mulc(a: F, c: u32) F {
        return a.mul(from(c));
    }
    pub inline fn eql(a: F, b: F) bool {
        return a.v == b.v;
    }
};

/// 2^-16 mod P: 2^16 * 2^15 = 2^31 = 1.
const INV_2_16: F = .{ .v = 1 << 15 };

pub const Relation = enum(u8) {
    /// (x, y, x ^ y) over bytes: the circuit's VerifyBitwiseXor_8 table.
    xor8,
    /// (x, y, (x ^ y) & 15, (x ^ y) >> 4).
    xor8_split4,
    /// (x, y, (x ^ y) & 127, (x ^ y) >> 7).
    xor8_split7,
    /// The circuit's Gate wire relation: (address, low u16, high u16, 0, 0).
    gate,

    pub fn id(self: Relation) u32 {
        return switch (self) {
            .xor8 => XOR_8_RELATION_ID,
            .xor8_split4 => XOR_8_SPLIT4_RELATION_ID,
            .xor8_split7 => XOR_8_SPLIT7_RELATION_ID,
            .gate => GATE_RELATION_ID,
        };
    }
};

/// One lookup: numerator / (z - combine(relation_id, tuple)).
pub const Lookup = struct {
    relation: Relation,
    /// +1 for a use, -multiplicity for a yield.
    numerator: F,
    tuple: [5]F,
    len: u8,

    /// The full combined tuple, relation id first, as the circuit's
    /// `COMMON_LOOKUP_ELEMENTS` consume it.
    pub fn combinedTuple(self: Lookup, out: *[6]F) []const F {
        out[0] = F.from(self.relation.id());
        @memcpy(out[1 .. 1 + self.len], self.tuple[0..self.len]);
        return out[0 .. 1 + self.len];
    }
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
pub const G_INDICES = [8][4]u8{
    .{ 0, 4, 8, 12 },  .{ 1, 5, 9, 13 },  .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 },  .{ 3, 4, 9, 14 },
};
/// The parameter block word for an unkeyed 32-byte digest.
pub const PARAM0: u32 = 0x0101_0020;

// ---------------------------------------------------------------------------
// Hint tape: what the capturing verifier records per compression.

/// Words per tape record: h[8], m[16], t0, flags (bit 0 = last block).
pub const TAPE_WORDS: usize = 26;

pub const TapeRecord = struct {
    h: [8]u32,
    m: [16]u32,
    /// Byte counter t0 (t1 is always 0 in the circuit).
    t0: u32,
    last: bool,

    pub fn encode(self: TapeRecord, out: *[TAPE_WORDS]u32) void {
        @memcpy(out[0..8], &self.h);
        @memcpy(out[8..24], &self.m);
        out[24] = self.t0;
        out[25] = @intFromBool(self.last);
    }

    pub fn decode(words: *const [TAPE_WORDS]u32) TapeRecord {
        return .{ .h = words[0..8].*, .m = words[8..24].*, .t0 = words[24], .last = words[25] & 1 == 1 };
    }

    /// The zero compression used for padding rows.
    pub const padding: TapeRecord = .{ .h = @splat(0), .m = @splat(0), .t0 = 0, .last = false };
};

/// Per-row preprocessed (setup-fixed) values. For a padding row every
/// address is 0 (the zero wire) and every output multiplicity is 0.
pub const Pp = struct {
    addr_h: [8]u32,
    addr_m: [16]u32,
    addr_out: [8]u32,
    mult_out: [8]u32,
    /// Bytes of v12 = IV[4] ^ t0 (setup-fixed per compression).
    v12: [4]u8,
    /// 1 for the last block of a message (v14 = ~IV[6]).
    last: u1,

    pub const N_COLUMNS: usize = 8 + 16 + 8 + 8 + 4 + 1;

    pub fn padding() Pp {
        return .{ .addr_h = @splat(0), .addr_m = @splat(0), .addr_out = @splat(0), .mult_out = @splat(0), .v12 = bytesOf(IV[4]), .last = 0 };
    }

    pub fn forRecord(rec: TapeRecord, addr_h: [8]u32, addr_m: [16]u32, addr_out: [8]u32, mult_out: [8]u32) Pp {
        return .{ .addr_h = addr_h, .addr_m = addr_m, .addr_out = addr_out, .mult_out = mult_out, .v12 = bytesOf(IV[4] ^ rec.t0), .last = @intFromBool(rec.last) };
    }
};

fn bytesOf(x: u32) [4]u8 {
    return .{ @truncate(x), @truncate(x >> 8), @truncate(x >> 16), @truncate(x >> 24) };
}

// ---------------------------------------------------------------------------
// Shape.

/// Base (main) columns per row: m as 16 u16-limb pairs, h as 8 byte words,
/// then per G: a1 (4), d1-xor (4), c1 (4), b-xor split (8), a2 (4), d2-xor (4),
/// c2 (4), b-xor split (8); then 8 x (u, out) byte words.
pub const N_COLUMNS: usize = 16 * 2 + 8 * 4 + 80 * (4 + 4 + 4 + 8 + 4 + 4 + 4 + 8) + 8 * 8;
/// Lookups per row: 16 XOR byte lookups per G, 8 per output word, 32 Gate.
pub const N_XOR8_LOOKUPS: usize = 80 * 8 + 8 * 8;
pub const N_SPLIT4_LOOKUPS: usize = 80 * 4;
pub const N_SPLIT7_LOOKUPS: usize = 80 * 4;
pub const N_GATE_LOOKUPS: usize = 32;
pub const N_LOOKUPS: usize = N_XOR8_LOOKUPS + N_SPLIT4_LOOKUPS + N_SPLIT7_LOOKUPS + N_GATE_LOOKUPS;
/// Base interaction columns: lookups paired into secure (4 x M31) columns.
pub const INTERACTION_COLUMNS: usize = 4 * ((N_LOOKUPS + 1) / 2);
/// Constraints per row: 4 additions x 2 halves per G.
pub const N_CONSTRAINTS: usize = 80 * 8;
pub const MAX_DEGREE: u8 = 3;

/// Today's cost of one compression in the circuit AIR, for the census:
/// 80 `blake_g_gate` rows (52 + 52 columns) + 8 `triple_xor` rows (20 + 24).
pub const LEGACY_MAIN_PER_COMPRESSION: usize = 80 * 52 + 8 * 20;
pub const LEGACY_INTER_PER_COMPRESSION: usize = 80 * 52 + 8 * 24;
/// The two new 2^16-row tables: 4 preprocessed columns, 1 multiplicity
/// column and one secure interaction column each.
pub const SPLIT_TABLE_LOG_ROWS: u5 = 16;
pub const SPLIT_TABLE_MAIN: usize = 1;
pub const SPLIT_TABLE_INTER: usize = 4;

comptime {
    std.debug.assert(N_COLUMNS == 3328);
    std.debug.assert(N_LOOKUPS == 1376);
    std.debug.assert(INTERACTION_COLUMNS == 2752);
}

// ---------------------------------------------------------------------------
// The row program, verifier view. `Eval` and `fillRow` walk the same cursor,
// so the column order is defined exactly once per side and tested equal.

const Bytes = [4]F;

fn limbsOf(b: Bytes) [2]F {
    return .{ b[0].add(b[1].mulc(256)), b[2].add(b[3].mulc(256)) };
}
fn constBytes(x: u32) Bytes {
    return .{ F.from(x & 0xff), F.from((x >> 8) & 0xff), F.from((x >> 16) & 0xff), F.from(x >> 24) };
}

/// Constraint view of one row. Reads cells in program order, records
/// constraint residuals and lookups; never sees witness integers.
pub const Eval = struct {
    row: []const F,
    at: usize = 0,
    violations: usize = 0,
    n_constraints: usize = 0,
    max_degree: u8 = 0,
    lookups: []Lookup,
    n_lookups: usize = 0,

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
    fn lookup(self: *Eval, relation: Relation, numerator: F, tuple: []const F) void {
        var l = Lookup{ .relation = relation, .numerator = numerator, .tuple = @splat(F.zero), .len = @intCast(tuple.len) };
        @memcpy(l.tuple[0..tuple.len], tuple);
        self.lookups[self.n_lookups] = l;
        self.n_lookups += 1;
    }
    /// carry e in {0..max}: e (e-1) ... (e-max) = 0.
    fn carryConstraint(self: *Eval, e: F, max: u8) void {
        var r = e;
        var k: u32 = 1;
        while (k <= max) : (k += 1) r = r.mul(e.sub(F.from(k)));
        self.constrain(r, max + 1);
    }
    /// r = sum(operands) mod 2^32 with r committed as 4 byte cells.
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
    fn xor(self: *Eval, x: Bytes, y: Bytes) Bytes {
        const z = self.word();
        for (0..4) |j| self.lookup(.xor8, F.one, &.{ x[j], y[j], z[j] });
        return z;
    }
    fn xorSplit(self: *Eval, x: Bytes, y: Bytes, comptime split: u5) struct { lo: Bytes, hi: Bytes } {
        var lo: Bytes = undefined;
        var hi: Bytes = undefined;
        for (0..4) |j| {
            lo[j] = self.col();
            hi[j] = self.col();
            self.lookup(if (split == 4) .xor8_split4 else .xor8_split7, F.one, &.{ x[j], y[j], lo[j], hi[j] });
        }
        return .{ .lo = lo, .hi = hi };
    }
    fn g(self: *Eval, a: Bytes, b: Bytes, c: Bytes, d: Bytes, f0: [2]F, f1: [2]F) [4]Bytes {
        const a1 = self.add(&.{ limbsOf(a), limbsOf(b), f0 });
        const z = self.xor(d, a1);
        const d1: Bytes = .{ z[2], z[3], z[0], z[1] }; // rotr 16
        const c1 = self.add(&.{ limbsOf(c), limbsOf(d1) });
        const x = self.xorSplit(b, c1, 4);
        var b1: Bytes = undefined; // rotr 12
        for (0..4) |j| b1[j] = x.hi[(j + 1) % 4].add(x.lo[(j + 2) % 4].mulc(16));
        const a2 = self.add(&.{ limbsOf(a1), limbsOf(b1), f1 });
        const z2 = self.xor(d1, a2);
        const d2: Bytes = .{ z2[1], z2[2], z2[3], z2[0] }; // rotr 8
        const c2 = self.add(&.{ limbsOf(c1), limbsOf(d2) });
        const y = self.xorSplit(b1, c2, 7);
        var b2: Bytes = undefined; // rotr 7
        for (0..4) |j| b2[j] = y.hi[j].add(y.lo[(j + 1) % 4].mulc(2));
        return .{ a2, b2, c2, d2 };
    }

    /// Walks one row; returns the output words' bytes.
    pub fn run(self: *Eval, pp: Pp) [8]Bytes {
        std.debug.assert(self.lookups.len >= N_LOOKUPS);
        var m: [16][2]F = undefined;
        for (&m) |*w| w.* = .{ self.col(), self.col() };
        var h: [8]Bytes = undefined;
        for (&h) |*w| w.* = self.word();
        var v: [16]Bytes = undefined;
        for (0..8) |i| v[i] = h[i];
        for (8..16) |i| v[i] = constBytes(IV[i - 8]);
        for (0..4) |j| v[12][j] = F.from(pp.v12[j]);
        // v14 = IV6 or ~IV6: byte-wise iv + last * (255 - 2 iv), linear in the flag.
        const flag = F.from(pp.last);
        for (0..4) |j| {
            const iv = F.from((IV[6] >> @intCast(8 * j)) & 0xff);
            v[14][j] = iv.add(flag.mul(F.from(255).sub(iv).sub(iv)));
        }
        for (SIGMA) |s| for (G_INDICES, 0..) |idx, gi| {
            const out = self.g(v[idx[0]], v[idx[1]], v[idx[2]], v[idx[3]], m[s[2 * gi]], m[s[2 * gi + 1]]);
            for (idx, out) |k, w| v[k] = w;
        };
        var out: [8]Bytes = undefined;
        for (0..8) |i| {
            const u = self.xor(h[i], v[i]);
            out[i] = self.xor(u, v[i + 8]);
        }
        // Gate-relation traffic: 24 uses, 8 yields; tuple (addr, lo, hi, 0, 0).
        for (0..8) |i| {
            const l = limbsOf(h[i]);
            self.lookup(.gate, F.one, &.{ F.from(pp.addr_h[i]), l[0], l[1], F.zero, F.zero });
        }
        for (0..16) |k| self.lookup(.gate, F.one, &.{ F.from(pp.addr_m[k]), m[k][0], m[k][1], F.zero, F.zero });
        for (0..8) |i| {
            const l = limbsOf(out[i]);
            self.lookup(.gate, F.from(pp.mult_out[i]).neg(), &.{ F.from(pp.addr_out[i]), l[0], l[1], F.zero, F.zero });
        }
        std.debug.assert(self.at == self.row.len);
        return out;
    }
};

// ---------------------------------------------------------------------------
// Witness fill (honest prover). The CUDA kernel mirrors this exactly.

const Fill = struct {
    row: []u32,
    at: usize = 0,

    inline fn put(self: *Fill, x: u32) void {
        self.row[self.at] = x;
        self.at += 1;
    }
    inline fn word(self: *Fill, x: u32) void {
        inline for (0..4) |j| self.put((x >> (8 * j)) & 0xff);
    }
    inline fn add(self: *Fill, operands: []const u32) u32 {
        var r: u32 = 0;
        for (operands) |o| r +%= o;
        self.word(r);
        return r;
    }
    inline fn xor(self: *Fill, x: u32, y: u32) u32 {
        self.word(x ^ y);
        return x ^ y;
    }
    inline fn xorSplit(self: *Fill, x: u32, y: u32, comptime split: u5) u32 {
        const z = x ^ y;
        inline for (0..4) |j| {
            const byte = (z >> (8 * j)) & 0xff;
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

/// Writes one honest row (canonical M31 values, all < 2^16) and returns the
/// compression output (the next chaining value).
pub fn fillRow(row: []u32, rec: TapeRecord) [8]u32 {
    return fillRowWithSchedule(row, rec, &SIGMA);
}

/// `fillRow` with an explicit message schedule: tests only (negative corpus
/// BG04 fills a row with a wrong schedule and checks `Eval` rejects it).
pub fn fillRowWithSchedule(row: []u32, rec: TapeRecord, schedule: *const [10][16]u8) [8]u32 {
    std.debug.assert(row.len == N_COLUMNS);
    var f = Fill{ .row = row };
    for (rec.m) |w| {
        f.put(w & 0xffff);
        f.put(w >> 16);
    }
    for (rec.h) |w| f.word(w);
    var v: [16]u32 = undefined;
    @memcpy(v[0..8], &rec.h);
    @memcpy(v[8..16], &IV);
    v[12] ^= rec.t0;
    if (rec.last) v[14] = ~v[14];
    for (schedule) |s| for (G_INDICES, 0..) |idx, gi| {
        const out = f.g(v[idx[0]], v[idx[1]], v[idx[2]], v[idx[3]], rec.m[s[2 * gi]], rec.m[s[2 * gi + 1]]);
        for (idx, out) |k, w| v[k] = w;
    };
    var out: [8]u32 = undefined;
    for (0..8) |i| out[i] = f.xor(f.xor(rec.h[i], v[i]), v[i + 8]);
    std.debug.assert(f.at == N_COLUMNS);
    return out;
}

/// Table membership: what the preprocessed tables contain.
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

/// The table row that holds `(x, y, ...)`: `(x << 8) | y`, the circuit's
/// `bitwise_xor_8_*` convention (`core/preprocessed_tables.zig` `BitwiseXor`,
/// `witness/components.zig` `xorRow`: operand `a` in the high bits). The two
/// split tables use the same row order.
pub inline fn tableRow(x: u32, y: u32) u32 {
    return (x << 8) | y;
}

/// Table multiplicities: three 2^16 counters indexed by `tableRow`. `xor8`
/// counts add to the circuit's existing VerifyBitwiseXor_8 multiplicity
/// column (the `xor8` relation's column), so the index order must be the
/// circuit's: an `x | y << 8` index transposes the histogram and the shared
/// table's LogUp no longer balances.
pub const Multiplicities = struct {
    xor8: []u32,
    split4: []u32,
    split7: []u32,

    pub fn init(a: std.mem.Allocator) !Multiplicities {
        const xor8 = try a.alloc(u32, 1 << 16);
        errdefer a.free(xor8);
        const split4 = try a.alloc(u32, 1 << 16);
        errdefer a.free(split4);
        const split7 = try a.alloc(u32, 1 << 16);
        @memset(xor8, 0);
        @memset(split4, 0);
        @memset(split7, 0);
        return .{ .xor8 = xor8, .split4 = split4, .split7 = split7 };
    }
    pub fn deinit(self: Multiplicities, a: std.mem.Allocator) void {
        a.free(self.xor8);
        a.free(self.split4);
        a.free(self.split7);
    }
    pub fn count(self: Multiplicities, lookups: []const Lookup) void {
        for (lookups) |l| {
            const index = tableRow(l.tuple[0].v, l.tuple[1].v);
            switch (l.relation) {
                .xor8 => self.xor8[index] += 1,
                .xor8_split4 => self.split4[index] += 1,
                .xor8_split7 => self.split7[index] += 1,
                .gate => {},
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Instances (no power-of-two padding tax).

pub const InstancePlan = struct {
    n_instances: u32 = 0,
    log_rows: [MAX_INSTANCES]u6 = @splat(0),

    pub fn rows(self: InstancePlan) u64 {
        var total: u64 = 0;
        for (self.log_rows[0..self.n_instances]) |log| total += @as(u64, 1) << log;
        return total;
    }
};

/// Smallest total row count >= n with at most `MAX_INSTANCES` power-of-two
/// instances of at least 2^MIN_LOG_ROWS rows each, largest first.
pub fn planInstances(n: u64) InstancePlan {
    var plan = InstancePlan{};
    if (n == 0) return plan;
    var remaining = n;
    while (remaining > 0) {
        const floor_log: u6 = @intCast(63 - @clz(remaining));
        if (plan.n_instances + 1 == MAX_INSTANCES or floor_log < MIN_LOG_ROWS) {
            const ceil = std.math.ceilPowerOfTwo(u64, @max(remaining, @as(u64, 1) << MIN_LOG_ROWS)) catch unreachable;
            plan.log_rows[plan.n_instances] = @intCast(std.math.log2_int(u64, ceil));
            plan.n_instances += 1;
            return plan;
        }
        plan.log_rows[plan.n_instances] = floor_log;
        plan.n_instances += 1;
        remaining -= @as(u64, 1) << floor_log;
    }
    return plan;
}

/// Committed base cells (main + interaction) of the fused instances for `n`
/// compressions, excluding the two shared split tables.
pub fn fusedCells(n: u64) u64 {
    return planInstances(n).rows() * (N_COLUMNS + INTERACTION_COLUMNS);
}

/// Committed base cells of the two split tables (once per proof).
pub const SPLIT_TABLE_CELLS: u64 = 2 * (@as(u64, 1) << SPLIT_TABLE_LOG_ROWS) * (SPLIT_TABLE_MAIN + SPLIT_TABLE_INTER);

// ---------------------------------------------------------------------------
// Reference Blake2s compression (independent of the row program).

pub fn referenceCompress(rec: TapeRecord) [8]u32 {
    var v: [16]u32 = undefined;
    @memcpy(v[0..8], &rec.h);
    @memcpy(v[8..16], &IV);
    v[12] ^= rec.t0;
    if (rec.last) v[14] = ~v[14];
    for (SIGMA) |s| for (G_INDICES, 0..) |idx, gi| {
        var a = v[idx[0]];
        var b = v[idx[1]];
        var c = v[idx[2]];
        var d = v[idx[3]];
        a = a +% b +% rec.m[s[2 * gi]];
        d = std.math.rotr(u32, d ^ a, 16);
        c = c +% d;
        b = std.math.rotr(u32, b ^ c, 12);
        a = a +% b +% rec.m[s[2 * gi + 1]];
        d = std.math.rotr(u32, d ^ a, 8);
        c = c +% d;
        b = std.math.rotr(u32, b ^ c, 7);
        v[idx[0]] = a;
        v[idx[1]] = b;
        v[idx[2]] = c;
        v[idx[3]] = d;
    };
    var out: [8]u32 = undefined;
    for (0..8) |i| out[i] = rec.h[i] ^ v[i] ^ v[i + 8];
    return out;
}

/// SplitMix64: the random-tape generator shared with the CUDA self-test
/// (`fused_blake2s_selftest.cu`), so both sides can regenerate the same tape.
pub const SplitMix64 = struct {
    state: u64,
    pub fn next(self: *SplitMix64) u64 {
        self.state +%= 0x9E37_79B9_7F4A_7C15;
        var z = self.state;
        z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
        z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
        return z ^ (z >> 31);
    }
};

/// Random record `index` of the tape seeded by `seed` (counter-based, so any
/// record can be regenerated independently on host or device).
pub fn randomRecord(seed: u64, index: u64) TapeRecord {
    var rng = SplitMix64{ .state = seed ^ (index *% 0xD6E8_FEB8_6659_FD93) };
    var words: [TAPE_WORDS]u32 = undefined;
    for (words[0..25]) |*w| w.* = @truncate(rng.next());
    words[25] = @truncate(rng.next() & 1);
    return TapeRecord.decode(&words);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

pub const RowCheck = struct {
    out: [8]Bytes,
    violations: usize,
    bad_lookups: usize,
    gate: [32][5]F,
    n_constraints: usize,
    max_degree: u8,
    n_lookups: usize,
};

/// Evaluates a filled row (u32 cells) against `pp`.
pub fn checkRow(cells: []const u32, pp: Pp, scratch_row: []F, scratch_lookups: []Lookup) RowCheck {
    for (scratch_row, cells) |*f, c| f.* = F.from(c);
    var e = Eval{ .row = scratch_row, .lookups = scratch_lookups };
    const out = e.run(pp);
    var bad: usize = 0;
    var gate: [32][5]F = undefined;
    var gi: usize = 0;
    for (e.lookups[0..e.n_lookups]) |l| {
        if (!inTable(l)) bad += 1;
        if (l.relation == .gate) {
            gate[gi] = l.tuple;
            gi += 1;
        }
    }
    return .{ .out = out, .violations = e.violations, .bad_lookups = bad, .gate = gate, .n_constraints = e.n_constraints, .max_degree = e.max_degree, .n_lookups = e.n_lookups };
}

pub fn checkFieldRow(row: []const F, pp: Pp, scratch_lookups: []Lookup) RowCheck {
    var e = Eval{ .row = row, .lookups = scratch_lookups };
    const out = e.run(pp);
    var bad: usize = 0;
    var gate: [32][5]F = undefined;
    var gi: usize = 0;
    for (e.lookups[0..e.n_lookups]) |l| {
        if (!inTable(l)) bad += 1;
        if (l.relation == .gate) {
            gate[gi] = l.tuple;
            gi += 1;
        }
    }
    return .{ .out = out, .violations = e.violations, .bad_lookups = bad, .gate = gate, .n_constraints = e.n_constraints, .max_degree = e.max_degree, .n_lookups = e.n_lookups };
}

fn tupleWords(t: [5]F) [5]u32 {
    var out: [5]u32 = undefined;
    for (&out, t) |*o, f| o.* = f.v;
    return out;
}

fn wordFromBytes(b: Bytes) u32 {
    var x: u32 = 0;
    for (0..4) |j| x |= b[j].v << @intCast(8 * j);
    return x;
}

pub fn testPp(rec: TapeRecord) Pp {
    var addr_h: [8]u32 = undefined;
    var addr_m: [16]u32 = undefined;
    var addr_out: [8]u32 = undefined;
    for (&addr_h, 0..) |*x, i| x.* = @intCast(100 + i);
    for (&addr_m, 0..) |*x, i| x.* = @intCast(200 + i);
    for (&addr_out, 0..) |*x, i| x.* = @intCast(300 + i);
    return Pp.forRecord(rec, addr_h, addr_m, addr_out, @splat(1));
}

pub const Scratch = struct {
    cells: []u32,
    row: []F,
    lookups: []Lookup,
    pub fn init() !Scratch {
        const cells = try testing.allocator.alloc(u32, N_COLUMNS);
        errdefer testing.allocator.free(cells);
        const row = try testing.allocator.alloc(F, N_COLUMNS);
        errdefer testing.allocator.free(row);
        return .{ .cells = cells, .row = row, .lookups = try testing.allocator.alloc(Lookup, N_LOOKUPS) };
    }
    pub fn deinit(self: Scratch) void {
        testing.allocator.free(self.cells);
        testing.allocator.free(self.row);
        testing.allocator.free(self.lookups);
    }
};

/// Hashes `msg` through chained fused rows; every row must be satisfied.
pub fn fusedBlake2s(s: Scratch, msg: []const u8) ![32]u8 {
    var h: [8]u32 = IV;
    h[0] ^= PARAM0;
    const n_blocks = @max(1, (msg.len + 63) / 64);
    for (0..n_blocks) |bi| {
        var block: [64]u8 = @splat(0);
        const start = bi * 64;
        const end = @min(msg.len, start + 64);
        if (end > start) @memcpy(block[0 .. end - start], msg[start..end]);
        var m: [16]u32 = undefined;
        for (&m, 0..) |*w, k| w.* = std.mem.readInt(u32, block[4 * k ..][0..4], .little);
        const rec = TapeRecord{ .h = h, .m = m, .t0 = @intCast(@min(msg.len, (bi + 1) * 64)), .last = bi == n_blocks - 1 };
        const out = fillRow(s.cells, rec);
        try testing.expectEqualSlices(u32, &referenceCompress(rec), &out);
        const r = checkRow(s.cells, testPp(rec), s.row, s.lookups);
        try testing.expectEqual(@as(usize, 0), r.violations);
        try testing.expectEqual(@as(usize, 0), r.bad_lookups);
        for (r.out, out) |b, w| try testing.expectEqual(w, wordFromBytes(b));
        h = out;
    }
    var digest: [32]u8 = undefined;
    for (h, 0..) |w, i| std.mem.writeInt(u32, digest[4 * i ..][0..4], w, .little);
    return digest;
}

test "fused_blake2s_v1: completeness against std Blake2s256 (0..1024 bytes, chained blocks)" {
    const s = try Scratch.init();
    defer s.deinit();
    var prng = std.Random.DefaultPrng.init(0xb1a4e_5_001);
    var buf: [1024]u8 = undefined;
    prng.random().bytes(&buf);
    var len: usize = 0;
    while (len <= buf.len) : (len += if (len < 200) 1 else 61) {
        var want: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(buf[0..len], &want, .{});
        try testing.expectEqualSlices(u8, &want, &(try fusedBlake2s(s, buf[0..len])));
    }
    // RFC 7693 Appendix B.
    var abc: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&abc, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    try testing.expectEqualSlices(u8, &abc, &(try fusedBlake2s(s, "abc")));
}

// FUSED_BLAKE_RANDOM_ROWS (default 2^12) random compressions: the fill
// matches the reference, every row satisfies every constraint and lookup,
// and the table multiplicities account for every XOR lookup.
test "fused_blake2s_v1: completeness on random compressions (+ multiplicity balance)" {
    const s = try Scratch.init();
    defer s.deinit();
    const n: u64 = if (std.posix.getenv("FUSED_BLAKE_RANDOM_ROWS")) |v| try std.fmt.parseInt(u64, v, 10) else 1 << 12;
    const mults = try Multiplicities.init(testing.allocator);
    defer mults.deinit(testing.allocator);
    var violations: u64 = 0;
    for (0..n) |i| {
        const rec = randomRecord(0x5eed_f05e_db1a_4e01, i);
        const out = fillRow(s.cells, rec);
        try testing.expectEqualSlices(u32, &referenceCompress(rec), &out);
        const r = checkRow(s.cells, testPp(rec), s.row, s.lookups);
        violations += r.violations + r.bad_lookups;
        for (r.out, out) |b, w| try testing.expectEqual(w, wordFromBytes(b));
        mults.count(s.lookups[0..r.n_lookups]);
    }
    try testing.expectEqual(@as(u64, 0), violations);
    var sums: [3]u64 = @splat(0);
    for (mults.xor8, mults.split4, mults.split7) |a, b, c| {
        sums[0] += a;
        sums[1] += b;
        sums[2] += c;
    }
    try testing.expectEqual(n * N_XOR8_LOOKUPS, sums[0]);
    try testing.expectEqual(n * N_SPLIT4_LOOKUPS, sums[1]);
    try testing.expectEqual(n * N_SPLIT7_LOOKUPS, sums[2]);
    std.debug.print("FUSED_BLAKE2S_V1 cpu_random_rows={d} violations={d}\n", .{ n, violations });
}

// Edge records: all-ones / all-zero / alternating words (every addition at
// its largest carry), t0 at 0, 1, 64, 2^31 and 2^32 - 1, both flag values.
test "fused_blake2s_v1: completeness on edge records (max carries, t0 extremes)" {
    const s = try Scratch.init();
    defer s.deinit();
    const words = [_]u32{ 0, 0xffff_ffff, 0xaaaa_aaaa, 0x5555_5555, 0xffff_0000, 0x0000_ffff, 0x8000_0000, 1 };
    const t0s = [_]u32{ 0, 1, 64, 1 << 31, 0xffff_ffff };
    var n: usize = 0;
    for (words) |hw| for (words) |mw| for (t0s) |t0| for ([_]bool{ false, true }) |last| {
        const rec = TapeRecord{ .h = @splat(hw), .m = @splat(mw), .t0 = t0, .last = last };
        const out = fillRow(s.cells, rec);
        try testing.expectEqualSlices(u32, &referenceCompress(rec), &out);
        const r = checkRow(s.cells, testPp(rec), s.row, s.lookups);
        try testing.expectEqual(@as(usize, 0), r.violations + r.bad_lookups);
        for (r.out, out) |b, w| try testing.expectEqual(w, wordFromBytes(b));
        n += 1;
    };
    try testing.expectEqual(@as(usize, 8 * 8 * 5 * 2), n);
}

test "fused_blake2s_v1: row shape (columns, lookups, constraint degree)" {
    const s = try Scratch.init();
    defer s.deinit();
    const rec = randomRecord(1, 2);
    _ = fillRow(s.cells, rec);
    const r = checkRow(s.cells, testPp(rec), s.row, s.lookups);
    try testing.expectEqual(N_LOOKUPS, r.n_lookups);
    try testing.expectEqual(N_CONSTRAINTS, r.n_constraints);
    try testing.expectEqual(MAX_DEGREE, r.max_degree);
    // Every filled cell is below 2^16 (the GPU writes u32 words directly).
    for (s.cells) |c| try testing.expect(c < 1 << 16);
}

test "fused_blake2s_v1: padding rows are honest zero compressions wired to address 0" {
    const s = try Scratch.init();
    defer s.deinit();
    _ = fillRow(s.cells, TapeRecord.padding);
    const r = checkRow(s.cells, Pp.padding(), s.row, s.lookups);
    try testing.expectEqual(@as(usize, 0), r.violations + r.bad_lookups);
    // Uses read the zero wire; yields carry multiplicity 0.
    for (s.lookups[0..r.n_lookups]) |l| if (l.relation == .gate) {
        try testing.expectEqual(@as(u32, 0), l.tuple[0].v);
        if (l.numerator.v != 1) try testing.expectEqual(@as(u32, 0), l.numerator.v);
    };
}

test "fused_blake2s_v1: every single-cell change of an honest row is rejected" {
    const s = try Scratch.init();
    defer s.deinit();
    const rec = randomRecord(7, 11);
    _ = fillRow(s.cells, rec);
    const pp = testPp(rec);
    for (s.row, s.cells) |*f, c| f.* = F.from(c);
    const honest = checkFieldRow(s.row, pp, s.lookups);
    try testing.expectEqual(@as(usize, 0), honest.violations + honest.bad_lookups);
    var local: usize = 0;
    var by_gate_only: usize = 0;
    for (0..N_COLUMNS) |c| {
        for ([_]u32{ 1, P - 1, 256, 1 << 16 }) |delta| {
            const saved = s.row[c];
            s.row[c] = saved.add(.{ .v = delta });
            defer s.row[c] = saved;
            const r = checkFieldRow(s.row, pp, s.lookups);
            const gate_changed = for (r.gate, honest.gate) |x, y| {
                if (!std.mem.eql(u32, &tupleWords(x), &tupleWords(y))) break true;
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
    try testing.expectEqual(4 * N_COLUMNS, local + by_gate_only);
    // Only message-limb changes that keep carries in range escape the local
    // checks; the Gate tuple binds them, as today's G gate binds f0/f1.
    try testing.expect(by_gate_only <= 4 * 32);
}

test "fused_blake2s_v1: negative rows (wrong digest, non-byte cells, carry abuse, wrong flag) are rejected" {
    const s = try Scratch.init();
    defer s.deinit();
    const rec = randomRecord(3, 5);
    // 1. A claimed wrong digest word with a valid byte encoding.
    _ = fillRow(s.cells, rec);
    for (N_COLUMNS - 4..N_COLUMNS) |c| s.cells[c] = (s.cells[c] + 1) & 0xff;
    try testing.expect(checkRow(s.cells, testPp(rec), s.row, s.lookups).bad_lookups > 0);
    // 2. A byte cell replaced by its value + 256 with the next byte - 1
    //    (same limb value): the XOR table rejects the non-byte.
    _ = fillRow(s.cells, rec);
    const a1_at = 16 * 2 + 8 * 4; // first G's a1 word
    if (s.cells[a1_at + 1] > 0) {
        s.cells[a1_at] += 256;
        s.cells[a1_at + 1] -= 1;
    } else {
        s.cells[a1_at + 1] += 256;
        s.cells[a1_at + 2] -%= 1;
    }
    const r2 = checkRow(s.cells, testPp(rec), s.row, s.lookups);
    try testing.expect(r2.violations + r2.bad_lookups > 0);
    // 3. The last-block flag flipped in the preprocessed row.
    _ = fillRow(s.cells, rec);
    var pp = testPp(rec);
    pp.last ^= 1;
    const r3 = checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r3.violations + r3.bad_lookups > 0);
    // 4. A different t0 in the preprocessed row.
    pp = testPp(rec);
    pp.v12[0] ^= 1;
    const r4 = checkRow(s.cells, pp, s.row, s.lookups);
    try testing.expect(r4.violations + r4.bad_lookups > 0);
}

test "fused_blake2s_v1: instance plans (no power-of-two padding tax)" {
    try testing.expectEqual(@as(u64, 65536 + 8192 + 1024), planInstances(74_750).rows());
    try testing.expectEqual(@as(u32, 3), planInstances(74_750).n_instances);
    try testing.expectEqual(@as(u64, 16), planInstances(3).rows());
    try testing.expectEqual(@as(u64, 1 << 20), planInstances(1 << 20).rows());
    try testing.expectEqual(@as(u64, 0), planInstances(0).rows());
    // Worst case over all n in [2^10, 2^18]: three pieces leave at most
    // ~1/7 padding (n = 2^k + 2^(k-1) + 2^(k-2) + 1); the legacy single
    // power of two leaves up to ~1/1. Small n is dominated by the 2^4 floor.
    var worst: f64 = 0;
    var n: u64 = 1 << 10;
    while (n <= 1 << 18) : (n += 1) {
        const r = planInstances(n).rows();
        try testing.expect(r >= n);
        worst = @max(worst, @as(f64, @floatFromInt(r - n)) / @as(f64, @floatFromInt(n)));
    }
    try testing.expect(worst <= 0.15);
}

test "fused_blake2s_v1: table rows follow the circuit's bitwise_xor_8 order (a high, b low)" {
    // `BitwiseXor.value` (core/preprocessed_tables.zig): row 1000 holds
    // a = 1000 / 256 = 3, b = 1000 % 256 = 232 (upstream test_packed_at_bitwise_xor).
    try testing.expectEqual(@as(u32, 1000), tableRow(3, 232));
    try testing.expectEqual(@as(u32, 0x0100), tableRow(1, 0));
    const mults = try Multiplicities.init(testing.allocator);
    defer mults.deinit(testing.allocator);
    var lookups = [_]Lookup{.{ .relation = .xor8, .numerator = F.one, .tuple = .{ F.from(1), F.from(2), F.from(3), F.zero, F.zero }, .len = 3 }};
    mults.count(&lookups);
    try testing.expectEqual(@as(u32, 1), mults.xor8[0x0102]);
    try testing.expectEqual(@as(u32, 0), mults.xor8[0x0201]);
}

test "fused_blake2s_v1: tape record round trip" {
    const rec = randomRecord(9, 99);
    var words: [TAPE_WORDS]u32 = undefined;
    rec.encode(&words);
    const back = TapeRecord.decode(&words);
    try testing.expectEqualSlices(u32, &rec.h, &back.h);
    try testing.expectEqualSlices(u32, &rec.m, &back.m);
    try testing.expectEqual(rec.t0, back.t0);
    try testing.expectEqual(rec.last, back.last);
}

test "fused_blake2s_v1: relation id derivation" {
    inline for (.{ .{ XOR_8_SPLIT4_NAME, XOR_8_SPLIT4_RELATION_ID }, .{ XOR_8_SPLIT7_NAME, XOR_8_SPLIT7_RELATION_ID } }) |pair| {
        var d: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(pair[0], &d, .{});
        try testing.expectEqual(pair[1], std.mem.readInt(u32, d[0..4], .little) & 0x7fff_ffff);
    }
}

// FUSED_BLAKE_GPU_DUMP=<file>: compares a GPU fill dump written by
// `fused_blake2s_selftest` (header: magic, seed, n rows, column-major u32
// cells) cell for cell against `fillRow` on the same random tape.
test "fused_blake2s_v1: GPU fill dump equals the CPU fill" {
    const path = std.posix.getenv("FUSED_BLAKE_GPU_DUMP") orelse return error.SkipZigTest;
    const bytes = try std.fs.cwd().readFileAlloc(testing.allocator, path, 1 << 31);
    defer testing.allocator.free(bytes);
    const header = std.mem.bytesAsSlice(u64, bytes[0..32]);
    try testing.expectEqual(@as(u64, 0x3176_3273_656b_616c), header[0]); // "lakes2v1"
    const seed = header[1];
    const n = header[2];
    const first = header[3];
    const cells = std.mem.bytesAsSlice(u32, bytes[32..]);
    try testing.expectEqual(n * N_COLUMNS, cells.len);
    const row = try testing.allocator.alloc(u32, N_COLUMNS);
    defer testing.allocator.free(row);
    var mismatches: u64 = 0;
    for (0..n) |r| {
        _ = fillRow(row, randomRecord(seed, first + r));
        for (row, 0..) |c, col| {
            if (cells[col * n + r] != c) mismatches += 1;
        }
    }
    std.debug.print("FUSED_BLAKE2S_V1 gpu_dump rows={d} first={d} cells={d} mismatches={d}\n", .{ n, first, n * N_COLUMNS, mismatches });
    try testing.expectEqual(@as(u64, 0), mismatches);
}
