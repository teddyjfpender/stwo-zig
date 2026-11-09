//! Canonical binary wire format for tensor proofs, weight keys and statements
//! (design/tensor-frontend/wire.md).
//!
//! Container: MAGIC ("STZW"), VERSION (u8), kind (u8: proof / key /
//! statement), then sections `tag:u8 len:u32 body[len]` with strictly
//! increasing tags. Every section body has a fixed schema; optional fields are
//! optional sections (absent = null). Integers are little-endian; every
//! length is an explicit u32; field elements are u32 limbs that must be
//! canonical (< P); bools are 0 / 1. There is exactly one encoding of every
//! value: `encode(decode(b)) == b` for every accepted `b`.
//!
//! Decoding is strict and bounded: every length is checked against a cap
//! derived from the statement and config (`ProofCaps`, `keyCaps`) and against
//! the bytes left in the input before anything is allocated, so the decoder
//! never allocates more than a small multiple of its input. Decoded values
//! live in an arena owned by the returned `*File` value.
//!
//! Adding a proof field: give it a new section tag (optional when it is
//! absent in older proofs) and bump VERSION when old decoders must refuse
//! the new proofs. Unknown tags are always rejected.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const sc = @import("sumcheck.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const wk = @import("weight_key.zig");

const QM31 = f.QM31;
const M31 = f.M31;
const Hash = [32]u8;
const Allocator = std.mem.Allocator;
const GkrVerifier = engine.lookups.gkr_verifier.ForField(QM31);
const GkrBatchProof = GkrVerifier.GkrBatchProof;
const GkrMask = GkrVerifier.GkrMask;
const GkrSumcheck = std.meta.Child(@FieldType(GkrBatchProof, "sumcheck_proofs"));
const GkrPoly = std.meta.Child(@FieldType(GkrSumcheck, "round_polys"));

pub const MAGIC = "STZW".*;
/// 1: QM31 challenge field (the default build). 2: a degree-8 build
/// (-Dchallenge=om31); its header carries two more bytes after the kind:
/// the challenge-field degree (8) and the security level
/// (proto.SecurityLevel; for keys the level the key was proven at, and
/// decodeKey refuses a key whose level is not the statement's with
/// error.SecurityLevelMismatch). Each build accepts only its own
/// version: a QM31 verifier refuses OM31 files and vice versa
/// (error.ChallengeFieldMismatch), so a proof is never decoded under the
/// wrong field.
pub const VERSION: u8 = if (f.IS_OM31) 2 else 1;
pub const Kind = enum(u8) { proof = 1, key = 2, statement = 3 };

/// Largest file the CLI reads (the decoders' own caps are far tighter).
pub const MAX_FILE_BYTES: usize = 1 << 30;

pub const DecodeError = error{
    Truncated,
    TrailingBytes,
    BadMagic,
    BadVersion,
    BadKind,
    /// the file was written by a build with another challenge field
    ChallengeFieldMismatch,
    /// the proof's security level is not the statement config's
    SecurityLevelMismatch,
    UnknownTag,
    TagOrder,
    MissingSection,
    SectionLength,
    LengthCap,
    NonCanonicalField,
    NonCanonical,
    ShapeMismatch,
    OutOfMemory,
};

// ---------------------------------------------------------------------------
// Section tags.

const ProofTag = enum(u8) {
    witness_root = 0x01,
    witness_ood = 0x02,
    gkr = 0x03,
    lookup_in_values = 0x04,
    op_sumchecks = 0x05,
    op_finals = 0x06,
    batch_sumcheck = 0x07,
    witness_value = 0x08,
    witness_opening = 0x09,
    weight_opening = 0x0a,
    ext_values = 0x0b,
    ext_sumchecks = 0x0c,
    ext_finals = 0x0d,
};

const KeyTag = enum(u8) {
    root = 0x01,
    geometry = 0x02,
    infos = 0x03,
    offsets = 0x04,
    /// v_ood = W(z_ood), z_ood derived from the key transcript (PCS-1)
    ood_value = 0x05,
    histogram = 0x10,
    gkr = 0x11,
    value = 0x12,
    opening = 0x13,
};

const StTag = enum(u8) {
    config = 0x01,
    witness = 0x02,
    weights = 0x03,
    tables = 0x04,
    ops = 0x05,
    ext_ops = 0x06,
    ext_publics = 0x07,
    ext_tables = 0x08,
    /// optional: Statement.model_digest (P2); absent = null
    model_digest = 0x09,
};

const OPENING_FLAT: u8 = 0;
const OPENING_TWO: u8 = 1;

// ---------------------------------------------------------------------------
// Writer.

pub const EncodeError = error{ OutOfMemory, NonCanonical, Unsupported, TooLong };

const W = struct {
    a: Allocator,
    buf: std.ArrayList(u8) = .empty,
    /// test hook: byte offsets of every u32 length field written
    lens: ?*std.ArrayList(usize) = null,

    fn int(self: *W, comptime T: type, v: T) EncodeError!void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, v, .little);
        try self.buf.appendSlice(self.a, &b);
    }
    fn byte(self: *W, v: u8) EncodeError!void {
        try self.buf.append(self.a, v);
    }
    fn flag(self: *W, v: bool) EncodeError!void {
        try self.byte(@intFromBool(v));
    }
    fn bytes(self: *W, v: []const u8) EncodeError!void {
        try self.buf.appendSlice(self.a, v);
    }
    fn len(self: *W, n: usize) EncodeError!void {
        if (n > std.math.maxInt(u32)) return error.TooLong;
        if (self.lens) |l| try l.append(self.a, self.buf.items.len);
        try self.int(u32, @intCast(n));
    }
    fn u(self: *W, v: anytype) EncodeError!void {
        if (v > std.math.maxInt(u32)) return error.TooLong;
        try self.int(u32, @intCast(v));
    }
    fn felt(self: *W, v: QM31) EncodeError!void {
        for (f.limbs(v)) |l| {
            if (l >= f.P) return error.NonCanonical;
            try self.int(u32, l);
        }
    }
    fn felts(self: *W, v: []const QM31) EncodeError!void {
        try self.len(v.len);
        for (v) |x| try self.felt(x);
    }
    fn m31s(self: *W, v: []const M31) EncodeError!void {
        try self.len(v.len);
        for (v) |x| {
            if (x.v >= f.P) return error.NonCanonical;
            try self.int(u32, x.v);
        }
    }
    fn hashes(self: *W, v: []const Hash) EncodeError!void {
        try self.len(v.len);
        for (v) |h| try self.bytes(&h);
    }
    fn header(self: *W, kind: Kind, level: proto.SecurityLevel) EncodeError!void {
        try self.bytes(&MAGIC);
        try self.byte(VERSION);
        try self.byte(@intFromEnum(kind));
        if (f.IS_OM31) {
            try self.byte(@intCast(f.CHALLENGE_DEGREE));
            try self.byte(@intFromEnum(level));
        } else if (level != .custom) return error.Unsupported;
    }
    fn begin(self: *W, tag: anytype) EncodeError!usize {
        try self.byte(@intFromEnum(tag));
        if (self.lens) |l| try l.append(self.a, self.buf.items.len);
        try self.int(u32, 0);
        return self.buf.items.len;
    }
    fn end(self: *W, start: usize) EncodeError!void {
        const n = self.buf.items.len - start;
        if (n > std.math.maxInt(u32)) return error.TooLong;
        std.mem.writeInt(u32, self.buf.items[start - 4 ..][0..4], @intCast(n), .little);
    }
};

// ---------------------------------------------------------------------------
// Reader.

const R = struct {
    b: []const u8,
    pos: usize = 0,

    fn left(self: R) usize {
        return self.b.len - self.pos;
    }
    fn take(self: *R, n: usize) DecodeError![]const u8 {
        if (n > self.left()) return error.Truncated;
        const s = self.b[self.pos..][0..n];
        self.pos += n;
        return s;
    }
    fn int(self: *R, comptime T: type) DecodeError!T {
        const s = try self.take(@sizeOf(T));
        return std.mem.readInt(T, s[0..@sizeOf(T)], .little);
    }
    fn byte(self: *R) DecodeError!u8 {
        return (try self.take(1))[0];
    }
    fn flag(self: *R) DecodeError!bool {
        return switch (try self.byte()) {
            0 => false,
            1 => true,
            else => error.NonCanonical,
        };
    }
    /// A u32 at most `cap`.
    fn capped(self: *R, cap: u64) DecodeError!u32 {
        const v = try self.int(u32);
        if (v > cap) return error.LengthCap;
        return v;
    }
    /// A length field: at most `cap`, and `n * min_bytes` must fit in the
    /// remaining input (checked before the caller allocates n elements).
    fn len(self: *R, cap: u64, min_bytes: usize) DecodeError!usize {
        const n = try self.capped(cap);
        if (@as(u64, n) * min_bytes > self.left()) return error.Truncated;
        return n;
    }
    fn m31(self: *R) DecodeError!M31 {
        const v = try self.int(u32);
        if (v >= f.P) return error.NonCanonicalField;
        return M31.fromCanonical(v);
    }
    fn felt(self: *R) DecodeError!QM31 {
        var l: f.Limbs = undefined;
        for (&l) |*x| {
            x.* = try self.int(u32);
            if (x.* >= f.P) return error.NonCanonicalField;
        }
        return f.fromLimbs(l);
    }
    fn hash(self: *R) DecodeError!Hash {
        return (try self.take(32))[0..32].*;
    }
    fn felts(self: *R, a: Allocator, cap: u64) DecodeError![]QM31 {
        const n = try self.len(cap, 16);
        const out = try a.alloc(QM31, n);
        for (out) |*x| x.* = try self.felt();
        return out;
    }
    fn feltsExact(self: *R, a: Allocator, n: usize) DecodeError![]QM31 {
        const v = try self.felts(a, n);
        if (v.len != n) return error.ShapeMismatch;
        return v;
    }
    fn m31s(self: *R, a: Allocator, cap: u64) DecodeError![]M31 {
        const n = try self.len(cap, 4);
        const out = try a.alloc(M31, n);
        for (out) |*x| x.* = try self.m31();
        return out;
    }
    fn hashes(self: *R, a: Allocator, cap: u64) DecodeError![]Hash {
        const n = try self.len(cap, 32);
        const out = try a.alloc(Hash, n);
        for (out) |*x| x.* = try self.hash();
        return out;
    }
    fn done(self: R) DecodeError!void {
        if (self.left() != 0) return error.SectionLength;
    }
};

/// Section cursor: tags strictly increasing, unknown or trailing data rejected.
const Sections = struct {
    r: R,
    last: i16 = -1,
    level: proto.SecurityLevel = .custom,

    fn open(bytes: []const u8, kind: Kind) DecodeError!Sections {
        var r = R{ .b = bytes };
        const m = try r.take(4);
        if (!std.mem.eql(u8, m, &MAGIC)) return error.BadMagic;
        const v = try r.byte();
        if (v != VERSION) return if (v == 1 or v == 2) error.ChallengeFieldMismatch else error.BadVersion;
        if (try r.byte() != @intFromEnum(kind)) return error.BadKind;
        var level: proto.SecurityLevel = .custom;
        if (f.IS_OM31) {
            if (try r.byte() != f.CHALLENGE_DEGREE) return error.ChallengeFieldMismatch;
            level = std.meta.intToEnum(proto.SecurityLevel, try r.byte()) catch return error.NonCanonical;
        }
        return .{ .r = r, .level = level };
    }

    fn peekTag(self: *Sections) ?u8 {
        return if (self.r.left() == 0) null else self.r.b[self.r.pos];
    }

    /// The next section if its tag is `tag` (null when absent).
    fn optional(self: *Sections, tag: anytype) DecodeError!?R {
        const t: u8 = @intFromEnum(tag);
        const nt = self.peekTag() orelse return null;
        if (@as(i16, nt) <= self.last) return error.TagOrder;
        _ = std.meta.intToEnum(@TypeOf(tag), nt) catch return error.UnknownTag;
        if (nt != t) return null;
        _ = try self.r.byte();
        const n = try self.r.int(u32);
        const body = try self.r.take(n);
        self.last = t;
        return R{ .b = body };
    }

    fn required(self: *Sections, tag: anytype) DecodeError!R {
        return (try self.optional(tag)) orelse error.MissingSection;
    }

    /// Anything after the last section is rejected.
    fn finish(self: *Sections) DecodeError!void {
        if (self.r.left() != 0) return error.TrailingBytes;
    }
};

// ---------------------------------------------------------------------------
// Shared pieces: sumchecks, GKR, openings.

fn encSumcheck(w: *W, p: sc.Proof) EncodeError!void {
    if (p.deg == 0 or p.deg > sc.MAX_DEG) return error.NonCanonical;
    try w.byte(p.deg);
    try w.len(p.rounds.len);
    for (p.rounds) |rp| for (rp.evals[0..p.deg]) |v| try w.felt(v);
}

const ScCaps = struct { max_rounds: u64, min_rounds: u64 = 0, deg_lo: u8, deg_hi: u8 };

fn decSumcheck(r: *R, a: Allocator, c: ScCaps) DecodeError!sc.Proof {
    const deg = try r.byte();
    if (deg < c.deg_lo or deg > c.deg_hi) return error.ShapeMismatch;
    const n = try r.len(c.max_rounds, 16 * @as(usize, deg));
    if (n < c.min_rounds) return error.ShapeMismatch;
    const rounds = try a.alloc(sc.RoundPoly, n);
    for (rounds) |*rp| {
        rp.evals = [_]QM31{QM31.zero()} ** sc.MAX_DEG;
        for (rp.evals[0..deg]) |*v| v.* = try r.felt();
    }
    return .{ .rounds = rounds, .deg = deg };
}

fn encGkr(w: *W, g: GkrBatchProof) EncodeError!void {
    try w.len(g.sumcheck_proofs.len);
    for (g.sumcheck_proofs) |sp| {
        try w.len(sp.round_polys.len);
        for (sp.round_polys) |rp| {
            const cs = rp.coeffsSlice();
            if (cs.len > engine.lookups.verifier_kernel.MAX_DEGREE + 1) return error.NonCanonical;
            try w.byte(@intCast(cs.len));
            for (cs) |c| try w.felt(c);
        }
    }
    if (g.layer_masks_by_instance.len != g.output_claims_by_instance.len) return error.NonCanonical;
    try w.len(g.layer_masks_by_instance.len);
    for (g.layer_masks_by_instance, g.output_claims_by_instance) |ms, oc| {
        try w.len(ms.len);
        for (ms) |m| {
            const cols = m.columnsSlice();
            try w.len(cols.len);
            for (cols) |c| {
                try w.felt(c[0]);
                try w.felt(c[1]);
            }
        }
        try w.felts(oc);
    }
}

/// GKR batch proof of LogUp instances with the given variable counts:
/// layer l's sumcheck has l rounds, instance i has log_sizes[i] masks of 2
/// columns and 2 output claims.
fn decGkr(r: *R, a: Allocator, log_sizes: []const u32) DecodeError!GkrBatchProof {
    var n_layers: u32 = 0;
    for (log_sizes) |s| n_layers = @max(n_layers, s);
    const nl = try r.len(n_layers, 4);
    if (nl != n_layers) return error.ShapeMismatch;
    const sps = try a.alloc(GkrSumcheck, nl);
    const max_coeffs = engine.lookups.verifier_kernel.MAX_DEGREE + 1;
    for (sps, 0..) |*sp, layer| {
        const np = try r.len(layer, 1);
        if (np != layer) return error.ShapeMismatch;
        const polys = try a.alloc(GkrPoly, np);
        for (polys) |*p| {
            const nc = try r.byte();
            if (nc > max_coeffs) return error.LengthCap;
            const cs = try a.alloc(QM31, nc);
            for (cs) |*c| c.* = try r.felt();
            // canonical: no trailing zero coefficient (the polynomial is trimmed)
            if (nc > 0 and cs[nc - 1].isZero()) return error.NonCanonical;
            p.* = GkrPoly.initOwned(cs);
        }
        sp.* = .{ .round_polys = polys };
    }
    const ni = try r.len(log_sizes.len, 8);
    if (ni != log_sizes.len) return error.ShapeMismatch;
    const masks = try a.alloc([]GkrMask, ni);
    const outs = try a.alloc([]QM31, ni);
    for (masks, outs, log_sizes) |*ms, *oc, ls| {
        const nm = try r.len(ls, 4);
        if (nm != ls) return error.ShapeMismatch;
        ms.* = try a.alloc(GkrMask, nm);
        for (ms.*) |*m| {
            const ncol = try r.len(2, 32);
            if (ncol != 2) return error.ShapeMismatch;
            const cols = try a.alloc([2]QM31, ncol);
            for (cols) |*c| c.* = .{ try r.felt(), try r.felt() };
            m.* = GkrMask.initOwned(cols);
        }
        oc.* = try r.feltsExact(a, 2);
    }
    return .{ .sumcheck_proofs = sps, .layer_masks_by_instance = masks, .output_claims_by_instance = outs };
}

fn encOpening(w: *W, op: proto.Opening) EncodeError!void {
    switch (op) {
        .flat => |p| {
            try w.byte(OPENING_FLAT);
            try w.len(p.rows.len);
            for (p.rows) |row| try w.felts(row);
            try w.int(u64, p.pow_nonce);
            try w.len(p.columns.len);
            for (p.columns) |c| {
                try w.u(c.index);
                try w.m31s(c.values);
                try w.hashes(c.path);
            }
        },
        .two => |p| {
            try w.byte(OPENING_TWO);
            try w.len(p.levels.len);
            for (p.levels, 0..) |l, i| {
                const final = i + 1 == p.levels.len;
                try w.int(u64, l.pow_nonce);
                try w.m31s(l.col_values);
                try w.hashes(l.decommit);
                if (final) {
                    // the final level carries rows only
                    if (!std.mem.allEqual(u8, &l.inner_root, 0) or l.sumcheck.rounds.len != 0 or l.ood_value != null) return error.NonCanonical;
                    for (l.limb_vals) |v| if (!v.isZero()) return error.NonCanonical;
                    try w.len(l.rows.len);
                    for (l.rows) |row| try w.felts(row);
                } else {
                    if (l.rows.len != 0) return error.NonCanonical;
                    try w.bytes(&l.inner_root);
                    try encSumcheck(w, l.sumcheck);
                    for (l.limb_vals) |v| try w.felt(v);
                    try w.flag(l.ood_value != null);
                    if (l.ood_value) |v| try w.felt(v);
                }
            }
        },
    }
}

/// What an opening may look like: the PCS flavour and parameters of `cfg`,
/// the committed table's shape, the claim-group count range and whether a
/// proximity test is included.
pub const OpenCaps = struct {
    cfg: proto.Config,
    shape: pcs.Shape,
    groups_min: usize,
    groups_max: usize,
    with_proximity: bool,
};

/// Max log columns / blowup accepted anywhere (twiddle and row allocations
/// in the verifier are bounded by 2^(log_cols + log_blowup)).
const MAX_LOG_EXT: u32 = 30;

fn pow2(x: u32) u64 {
    return @as(u64, 1) << @intCast(x);
}

fn decOpening(r: *R, a: Allocator, c: OpenCaps) DecodeError!proto.Opening {
    const variant = try r.byte();
    if (c.cfg.two_level) |tl| {
        if (variant != OPENING_TWO) return error.ShapeMismatch;
        return .{ .two = try decPcs2(r, a, tl, c) };
    }
    if (variant != OPENING_FLAT) return error.ShapeMismatch;
    const p = c.cfg.pcs;
    const sh = c.shape;
    const log_ext = sh.log_cols + sh.log_blowup;
    if (log_ext > MAX_LOG_EXT) return error.LengthCap;
    const n_prox: usize = @intFromBool(c.with_proximity);
    const n_rows = try r.len(c.groups_max + n_prox, 4);
    if (n_rows < c.groups_min + n_prox) return error.ShapeMismatch;
    const rows = try a.alloc([]QM31, n_rows);
    for (rows) |*row| row.* = try r.feltsExact(a, pow2(sh.log_cols));
    const nonce = try r.int(u64);
    if (p.pow_bits == 0 and nonce != 0) return error.NonCanonical;
    const ru = sh.rows_used orelse pow2(sh.log_rows);
    const nq = try r.len(p.n_queries, 12);
    if (nq != p.n_queries) return error.ShapeMismatch;
    const cols = try a.alloc(pcs.OpenedColumn, nq);
    for (cols) |*col| {
        const idx = try r.int(u32);
        if (idx >= pow2(log_ext)) return error.LengthCap;
        const vals = try r.m31s(a, ru);
        if (vals.len != ru) return error.ShapeMismatch;
        const path = try r.hashes(a, log_ext);
        if (path.len != log_ext) return error.ShapeMismatch;
        col.* = .{ .index = idx, .values = vals, .path = path };
    }
    return .{ .flat = .{ .rows = rows, .pow_nonce = nonce, .columns = cols } };
}

const LevelBounds = struct {
    rows_lo: usize = std.math.maxInt(usize),
    rows_hi: usize = 0,
    lc_lo: u32 = std.math.maxInt(u32),
    lc_hi: u32 = 0,
    ru_lo: usize = std.math.maxInt(usize),
    ru_hi: usize = 0,
    sc_hi: u32 = 0,
    ext_hi: u32 = 0,
};

fn decPcs2(r: *R, a: Allocator, tl: pcs2.Params, c: OpenCaps) DecodeError!pcs2.Proof {
    if (tl.depth > 8) return error.LengthCap;
    const n_levels: usize = tl.depth + 1;
    var bounds: [9]LevelBounds = [_]LevelBounds{.{}} ** 9;
    // the level shapes the verifier will derive, for every possible group count
    var g = c.groups_min;
    while (g <= c.groups_max) : (g += 1) {
        const infos = pcs2.levelInfos(a, tl, c.shape, g, c.with_proximity) catch return error.OutOfMemory;
        for (infos, 0..) |li, i| {
            const b = &bounds[i];
            b.rows_lo = @min(b.rows_lo, li.n_rows);
            b.rows_hi = @max(b.rows_hi, li.n_rows);
            b.lc_lo = @min(b.lc_lo, li.log_cols);
            b.lc_hi = @max(b.lc_hi, li.log_cols);
            b.ru_lo = @min(b.ru_lo, li.rows_used);
            b.ru_hi = @max(b.ru_hi, li.rows_used);
            b.sc_hi = @max(b.sc_hi, li.log_g + li.log_cols);
            b.ext_hi = @max(b.ext_hi, li.log_cols + li.params.log_blowup);
        }
    }
    const nl = try r.len(n_levels, 8);
    if (nl != n_levels) return error.ShapeMismatch;
    const levels = try a.alloc(pcs2.LevelProof, nl);
    for (levels, 0..) |*lp, i| {
        const b = bounds[i];
        if (b.ext_hi > MAX_LOG_EXT) return error.LengthCap;
        const p = tl.level(i);
        const final = i + 1 == nl;
        lp.* = .{};
        lp.pow_nonce = try r.int(u64);
        if (p.pow_bits == 0 and lp.pow_nonce != 0) return error.NonCanonical;
        lp.col_values = try r.m31s(a, @as(u64, p.n_queries) * b.ru_hi);
        // one opened column = rows_used values (exact when the shape is unique)
        if (b.ru_lo == 0) return error.ShapeMismatch;
        if (b.ru_lo == b.ru_hi and lp.col_values.len % b.ru_hi != 0) return error.ShapeMismatch;
        lp.decommit = try r.hashes(a, @as(u64, p.n_queries) * b.ext_hi);
        if (final) {
            const n_rows = try r.len(b.rows_hi, 4);
            if (n_rows < b.rows_lo) return error.ShapeMismatch;
            lp.rows = try a.alloc([]QM31, n_rows);
            for (lp.rows) |*row| {
                row.* = try r.felts(a, pow2(b.lc_hi));
                if (row.len < pow2(b.lc_lo) or !std.math.isPowerOfTwo(row.len)) return error.ShapeMismatch;
            }
        } else {
            lp.inner_root = try r.hash();
            lp.sumcheck = try decSumcheck(r, a, .{ .max_rounds = b.sc_hi, .deg_lo = 2, .deg_hi = 2 });
            for (&lp.limb_vals) |*v| v.* = try r.felt();
            if (try r.flag()) {
                if (!tl.ood) return error.ShapeMismatch;
                lp.ood_value = try r.felt();
            } else if (tl.ood) return error.ShapeMismatch;
        }
    }
    return .{ .levels = levels };
}

// ---------------------------------------------------------------------------
// Proof.

/// Length caps of a proof for one statement, config and weight key.
pub const ProofCaps = struct {
    cfg: proto.Config,
    witness: OpenCaps,
    weight: ?OpenCaps,
    log_total: u32,
    inst_log_sizes: []u32,
    max_lookup_values: usize,
    max_op_sumchecks: usize,
    max_op_finals: usize,
    /// per ext einsum (in op order): max sumcheck rounds (n_out + n_k)
    ext_einsum_rounds: []u32,
    max_ext_values: usize,

    pub fn deinit(self: *ProofCaps, a: Allocator) void {
        a.free(self.inst_log_sizes);
        a.free(self.ext_einsum_rounds);
    }
};

pub fn proofCaps(a: Allocator, cfg: proto.Config, st: proto.Statement, key: proto.WeightKey) !ProofCaps {
    if (cfg.hiding) return error.Unsupported;
    var ws = try proto.wireShape(a, cfg, st);
    errdefer ws.deinit(a);
    var n_matmul: usize = 0;
    var n_sc: usize = 0;
    for (st.ops) |op| switch (op) {
        .matmul => {
            n_matmul += 1;
            n_sc += 1;
        },
        .hadamard, .product => n_sc += 1,
        else => {},
    };
    var rounds: std.ArrayList(u32) = .empty;
    errdefer rounds.deinit(a);
    var n_values: usize = 0;
    const countTerms = struct {
        fn c(e: xt.Expr) usize {
            var n: usize = 0;
            for (e.terms) |t| n += @intFromBool(!t.t.public);
            return n;
        }
    }.c;
    for (st.ext.ops) |op| switch (op) {
        .einsum => |e| {
            try rounds.append(a, @as(u32, e.n_out) + e.n_k);
            n_values += @intFromBool(e.shift == 0 and e.y != null);
        },
        .key => |k| {
            n_values += countTerms(k.input);
            if (k.output) |o| n_values += countTerms(o);
        },
        .lineq => |l| n_values += countTerms(l.expr),
    };
    const wcfg = try proto.weightOpenConfig(cfg);
    const kshape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = proto.outerParams(cfg).log_blowup, .rows_used = key.rows_used };
    return .{
        .cfg = cfg,
        .witness = .{ .cfg = cfg, .shape = ws.witness, .groups_min = ws.witness_groups, .groups_max = ws.witness_groups, .with_proximity = true },
        .weight = if (n_matmul == 0) null else .{ .cfg = wcfg, .shape = kshape, .groups_min = 1, .groups_max = n_matmul + 1, .with_proximity = cfg.weight_proximity },
        .log_total = ws.log_total,
        .inst_log_sizes = ws.inst_log_sizes,
        .max_lookup_values = 2 * ws.n_keys,
        .max_op_sumchecks = n_sc,
        .max_op_finals = @max(3, 2 * n_matmul),
        .ext_einsum_rounds = try rounds.toOwnedSlice(a),
        .max_ext_values = n_values,
    };
}

fn encProofInto(w: *W, p: proto.Proof) EncodeError!void {
    try w.header(.proof, p.security);
    var s = try w.begin(ProofTag.witness_root);
    try w.bytes(&p.witness_root);
    try w.end(s);
    if (p.witness_ood) |v| {
        s = try w.begin(ProofTag.witness_ood);
        try w.felt(v);
        try w.end(s);
    }
    if (p.gkr) |g| {
        s = try w.begin(ProofTag.gkr);
        try encGkr(w, g);
        try w.end(s);
    }
    s = try w.begin(ProofTag.lookup_in_values);
    try w.felts(p.lookup_in_values);
    try w.end(s);
    s = try w.begin(ProofTag.op_sumchecks);
    try w.len(p.op_sumchecks.len);
    for (p.op_sumchecks) |x| try encSumcheck(w, x);
    try w.end(s);
    s = try w.begin(ProofTag.op_finals);
    try w.len(p.op_finals.len);
    for (p.op_finals) |x| try w.felts(x);
    try w.end(s);
    s = try w.begin(ProofTag.batch_sumcheck);
    try encSumcheck(w, p.batch_sumcheck);
    try w.end(s);
    s = try w.begin(ProofTag.witness_value);
    try w.felt(p.witness_value);
    try w.end(s);
    s = try w.begin(ProofTag.witness_opening);
    try encOpening(w, p.witness_opening);
    try w.end(s);
    if (p.weight_opening) |o| {
        s = try w.begin(ProofTag.weight_opening);
        try encOpening(w, o);
        try w.end(s);
    }
    s = try w.begin(ProofTag.ext_values);
    try w.felts(p.ext.values);
    try w.end(s);
    s = try w.begin(ProofTag.ext_sumchecks);
    try w.len(p.ext.sumchecks.len);
    for (p.ext.sumchecks) |x| try encSumcheck(w, x);
    try w.end(s);
    s = try w.begin(ProofTag.ext_finals);
    try w.len(p.ext.finals.len);
    for (p.ext.finals) |x| {
        try w.felt(x[0]);
        try w.felt(x[1]);
    }
    try w.end(s);
}

/// Canonical encoding of a proof (caller owns the bytes).
pub fn encodeProof(a: Allocator, p: proto.Proof) EncodeError![]u8 {
    var w = W{ .a = a };
    errdefer w.buf.deinit(a);
    try encProofInto(&w, p);
    return w.buf.toOwnedSlice(a);
}

/// Encoding plus the offsets of every length field (fuzzing).
pub fn encodeProofTraced(a: Allocator, p: proto.Proof, lens: *std.ArrayList(usize)) EncodeError![]u8 {
    var w = W{ .a = a, .lens = lens };
    errdefer w.buf.deinit(a);
    try encProofInto(&w, p);
    return w.buf.toOwnedSlice(a);
}

/// A decoded proof; every slice lives in `arena`.
pub const ProofFile = struct {
    arena: std.heap.ArenaAllocator,
    proof: proto.Proof,

    pub fn deinit(self: *ProofFile) void {
        self.arena.deinit();
    }
};

pub fn decodeProof(gpa: Allocator, bytes: []const u8, caps: ProofCaps) DecodeError!ProofFile {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const proof = try decodeProofIn(arena.allocator(), bytes, caps);
    return .{ .arena = arena, .proof = proof };
}

fn decodeProofIn(a: Allocator, bytes: []const u8, c: ProofCaps) DecodeError!proto.Proof {
    var ss = try Sections.open(bytes, .proof);
    var p: proto.Proof = undefined;
    if (ss.level != c.cfg.security) return error.SecurityLevelMismatch;
    p.security = ss.level;
    var r = try ss.required(ProofTag.witness_root);
    p.witness_root = try r.hash();
    try r.done();

    p.witness_ood = null;
    if (try ss.optional(ProofTag.witness_ood)) |r0| {
        r = r0;
        if (!proto.witnessOod(c.cfg)) return error.ShapeMismatch;
        p.witness_ood = try r.felt();
        try r.done();
    } else if (proto.witnessOod(c.cfg)) return error.MissingSection;

    p.gkr = null;
    if (try ss.optional(ProofTag.gkr)) |r0| {
        r = r0;
        if (c.inst_log_sizes.len == 0) return error.ShapeMismatch;
        p.gkr = try decGkr(&r, a, c.inst_log_sizes);
        try r.done();
    } else if (c.inst_log_sizes.len != 0) return error.MissingSection;

    r = try ss.required(ProofTag.lookup_in_values);
    p.lookup_in_values = try r.felts(a, c.max_lookup_values);
    try r.done();

    r = try ss.required(ProofTag.op_sumchecks);
    const n_sc = try r.len(c.max_op_sumchecks, 5);
    p.op_sumchecks = try a.alloc(sc.Proof, n_sc);
    for (p.op_sumchecks) |*x| x.* = try decSumcheck(&r, a, .{ .max_rounds = c.log_total, .deg_lo = 2, .deg_hi = 3 });
    try r.done();

    r = try ss.required(ProofTag.op_finals);
    const n_fin = try r.len(n_sc, 4);
    if (n_fin != n_sc) return error.ShapeMismatch;
    p.op_finals = try a.alloc([]QM31, n_fin);
    for (p.op_finals) |*x| x.* = try r.felts(a, c.max_op_finals);
    try r.done();

    r = try ss.required(ProofTag.batch_sumcheck);
    p.batch_sumcheck = try decSumcheck(&r, a, .{ .max_rounds = c.log_total, .min_rounds = c.log_total, .deg_lo = 2, .deg_hi = 2 });
    try r.done();

    r = try ss.required(ProofTag.witness_value);
    p.witness_value = try r.felt();
    try r.done();

    r = try ss.required(ProofTag.witness_opening);
    p.witness_opening = try decOpening(&r, a, c.witness);
    try r.done();

    p.weight_opening = null;
    if (try ss.optional(ProofTag.weight_opening)) |r0| {
        r = r0;
        const wc = c.weight orelse return error.ShapeMismatch;
        p.weight_opening = try decOpening(&r, a, wc);
        try r.done();
    } else if (c.weight != null) return error.MissingSection;

    r = try ss.required(ProofTag.ext_values);
    p.ext.values = try r.felts(a, c.max_ext_values);
    try r.done();

    const n_e = c.ext_einsum_rounds.len;
    r = try ss.required(ProofTag.ext_sumchecks);
    if (try r.len(n_e, 5) != n_e) return error.ShapeMismatch;
    p.ext.sumchecks = try a.alloc(sc.Proof, n_e);
    for (p.ext.sumchecks, c.ext_einsum_rounds) |*x, mr| x.* = try decSumcheck(&r, a, .{ .max_rounds = mr, .deg_lo = 2, .deg_hi = 3 });
    try r.done();

    r = try ss.required(ProofTag.ext_finals);
    if (try r.len(n_e, 32) != n_e) return error.ShapeMismatch;
    p.ext.finals = try a.alloc([2]QM31, n_e);
    for (p.ext.finals) |*x| x.* = .{ try r.felt(), try r.felt() };
    try r.done();

    try ss.finish();
    return p;
}

// ---------------------------------------------------------------------------
// Weight key + key proof.

fn encInfo(w: *W, t: proto.TensorInfo) EncodeError!void {
    if (t.n_dims == 0 or t.n_dims > proto.MAX_DIMS) return error.NonCanonical;
    try w.byte(t.n_dims);
    for (t.log_dims, 0..) |d, i| {
        if (i >= t.n_dims) {
            if (d != 0) return error.NonCanonical;
            continue;
        }
        if (d > 31) return error.NonCanonical;
        try w.byte(@intCast(d));
    }
}

fn decInfo(r: *R) DecodeError!proto.TensorInfo {
    const nd = try r.byte();
    if (nd == 0 or nd > proto.MAX_DIMS) return error.NonCanonical;
    var t = proto.TensorInfo{ .n_dims = nd };
    var tot: u32 = 0;
    for (t.log_dims[0..nd]) |*d| {
        const v = try r.byte();
        if (v > 31) return error.LengthCap;
        d.* = v;
        tot += v;
    }
    if (tot > 40) return error.LengthCap;
    return t;
}

fn encKeyInto(w: *W, key: proto.WeightKey, kp: wk.KeyProof) EncodeError!void {
    try w.header(.key, kp.security);
    var s = try w.begin(KeyTag.root);
    try w.bytes(&key.root);
    try w.end(s);
    s = try w.begin(KeyTag.geometry);
    try w.u(key.log_rows);
    try w.u(key.log_cols);
    try w.int(u64, key.rows_used);
    try w.end(s);
    s = try w.begin(KeyTag.infos);
    try w.len(key.infos.len);
    for (key.infos) |t| try encInfo(w, t);
    try w.end(s);
    s = try w.begin(KeyTag.offsets);
    try w.len(key.offsets.len);
    for (key.offsets) |o| try w.int(u64, o);
    try w.end(s);
    s = try w.begin(KeyTag.ood_value);
    try w.felt(key.ood_value);
    try w.end(s);
    s = try w.begin(KeyTag.histogram);
    for (kp.histogram) |h| try w.int(u32, h);
    try w.end(s);
    s = try w.begin(KeyTag.gkr);
    try encGkr(w, kp.gkr);
    try w.end(s);
    s = try w.begin(KeyTag.value);
    try w.felt(kp.value);
    try w.end(s);
    s = try w.begin(KeyTag.opening);
    try encOpening(w, kp.opening);
    try w.end(s);
}

/// Canonical encoding of a weight key with its (one-time) key proof.
pub fn encodeKey(a: Allocator, key: proto.WeightKey, kp: wk.KeyProof) EncodeError![]u8 {
    var w = W{ .a = a };
    errdefer w.buf.deinit(a);
    try encKeyInto(&w, key, kp);
    return w.buf.toOwnedSlice(a);
}

pub fn encodeKeyTraced(a: Allocator, key: proto.WeightKey, kp: wk.KeyProof, lens: *std.ArrayList(usize)) EncodeError![]u8 {
    var w = W{ .a = a, .lens = lens };
    errdefer w.buf.deinit(a);
    try encKeyInto(&w, key, kp);
    return w.buf.toOwnedSlice(a);
}

pub const KeyFile = struct {
    arena: std.heap.ArenaAllocator,
    key: proto.WeightKey,
    proof: wk.KeyProof,

    pub fn deinit(self: *KeyFile) void {
        self.arena.deinit();
    }
};

/// Decodes a key file for a statement and config. The key's geometry is
/// fully determined by them (the weight layout of `st.weights` and
/// `cfg.weight_log_cols`); any other geometry is rejected.
pub fn decodeKey(gpa: Allocator, bytes: []const u8, cfg: proto.Config, st: proto.Statement) DecodeError!KeyFile {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var ss = try Sections.open(bytes, .key);
    if (ss.level != cfg.security) return error.SecurityLevelMismatch;
    var key: proto.WeightKey = undefined;
    var kp: wk.KeyProof = undefined;

    // expected geometry
    const lay = proto.layout(a, st.weights, &.{}) catch return error.OutOfMemory;
    const lc_exp = @min(cfg.weight_log_cols, lay.log_total);
    const lr_exp = lay.log_total - lc_exp;
    const ru_exp = (lay.used + (@as(usize, 1) << @intCast(lc_exp)) - 1) >> @intCast(lc_exp);
    const lb = proto.outerParams(cfg).log_blowup;
    if (lc_exp + lb > MAX_LOG_EXT or lay.log_total > 40) return error.LengthCap;

    var r = try ss.required(KeyTag.root);
    key.root = try r.hash();
    try r.done();

    r = try ss.required(KeyTag.geometry);
    key.log_rows = try r.capped(40);
    key.log_cols = try r.capped(40);
    key.rows_used = @intCast(try r.int(u64));
    try r.done();
    if (key.log_rows != lr_exp or key.log_cols != lc_exp or key.rows_used != ru_exp) return error.ShapeMismatch;

    r = try ss.required(KeyTag.infos);
    const ni = try r.len(st.weights.len, 2);
    if (ni != st.weights.len) return error.ShapeMismatch;
    const infos = try a.alloc(proto.TensorInfo, ni);
    for (infos, st.weights) |*t, sw| {
        t.* = try decInfo(&r);
        if (!std.meta.eql(t.*, sw)) return error.ShapeMismatch;
    }
    key.infos = infos;
    try r.done();

    r = try ss.required(KeyTag.offsets);
    const no = try r.len(ni, 8);
    if (no != ni) return error.ShapeMismatch;
    const offs = try a.alloc(usize, no);
    for (offs, lay.offsets) |*o, e| {
        const v = try r.int(u64);
        if (v != e) return error.ShapeMismatch;
        o.* = @intCast(v);
    }
    key.offsets = offs;
    try r.done();

    r = try ss.required(KeyTag.ood_value);
    key.ood_value = try r.felt();
    try r.done();

    const n_vars = key.log_rows + key.log_cols;
    r = try ss.required(KeyTag.histogram);
    for (&kp.histogram) |*h| {
        h.* = try r.int(u32);
        if (h.* > pow2(n_vars)) return error.LengthCap;
    }
    try r.done();

    const kcfg = proto.keyConfig(cfg) catch return error.ShapeMismatch;
    const n_alpha = wk.alphaCount(kcfg) catch return error.ShapeMismatch;
    var sizes: [4]u32 = undefined;
    for (0..n_alpha) |j| {
        sizes[2 * j] = n_vars;
        sizes[2 * j + 1] = 8;
    }
    r = try ss.required(KeyTag.gkr);
    kp.gkr = try decGkr(&r, a, sizes[0 .. 2 * n_alpha]);
    try r.done();

    r = try ss.required(KeyTag.value);
    kp.value = try r.felt();
    try r.done();

    r = try ss.required(KeyTag.opening);
    const kshape = pcs.Shape{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = lb, .rows_used = key.rows_used };
    kp.opening = try decOpening(&r, a, .{ .cfg = kcfg, .shape = kshape, .groups_min = 1, .groups_max = n_alpha + 1, .with_proximity = true });
    try r.done();

    try ss.finish();
    kp.security = ss.level;
    return .{ .arena = arena, .key = key, .proof = kp };
}

// ---------------------------------------------------------------------------
// Statement + verifier config.

fn encParams(w: *W, p: pcs.Params) EncodeError!void {
    try w.u(p.log_blowup);
    try w.u(p.n_queries);
    try w.u(p.pow_bits);
}

fn decParams(r: *R) DecodeError!pcs.Params {
    const lb = try r.capped(10);
    const q = try r.capped(4096);
    const pw = try r.capped(40);
    if (lb == 0 or q == 0) return error.ShapeMismatch;
    return .{ .log_blowup = lb, .n_queries = q, .pow_bits = pw };
}

fn encOptParams(w: *W, p: ?pcs.Params) EncodeError!void {
    try w.flag(p != null);
    if (p) |x| try encParams(w, x);
}

fn decOptParams(r: *R) DecodeError!?pcs.Params {
    return if (try r.flag()) try decParams(r) else null;
}

fn encConfig(w: *W, c: proto.Config) EncodeError!void {
    if (c.hiding) return error.Unsupported;
    try encParams(w, c.pcs);
    try w.flag(c.two_level != null);
    if (c.two_level) |tl| {
        try encParams(w, tl.outer);
        try encParams(w, tl.inner);
        try w.u(tl.depth);
        try w.u(tl.inner_work_shift);
        try w.u(tl.prox_rows);
        try encOptParams(w, tl.deep);
        try w.flag(tl.ood);
    }
    try w.flag(c.batch_matmuls);
    try encOptParams(w, c.weight_outer);
    try encOptParams(w, c.key_outer);
    try w.u(c.key_alphas);
    try w.u(c.weight_log_cols);
    try w.u(c.witness_log_cols_max);
}

fn decConfig(r: *R) DecodeError!proto.Config {
    var c = proto.Config{};
    c.pcs = try decParams(r);
    if (try r.flag()) {
        var tl = pcs2.Params{};
        tl.outer = try decParams(r);
        tl.inner = try decParams(r);
        tl.depth = try r.capped(8);
        tl.inner_work_shift = try r.capped(30);
        tl.prox_rows = try r.capped(16);
        if (tl.prox_rows == 0) return error.ShapeMismatch;
        tl.deep = try decOptParams(r);
        tl.ood = try r.flag();
        c.two_level = tl;
    }
    c.batch_matmuls = try r.flag();
    c.weight_outer = try decOptParams(r);
    c.key_outer = try decOptParams(r);
    c.key_alphas = try r.capped(2);
    if (c.key_alphas == 0) return error.ShapeMismatch;
    c.weight_log_cols = try r.capped(30);
    c.witness_log_cols_max = try r.capped(30);
    return c;
}

fn encRef(w: *W, x: xt.Ref) EncodeError!void {
    try w.flag(x.public);
    try w.u(x.id);
}

fn decRef(r: *R) DecodeError!xt.Ref {
    const p = try r.flag();
    return .{ .public = p, .id = try r.int(u32) };
}

fn encExpr(w: *W, e: xt.Expr) EncodeError!void {
    try w.len(e.terms.len);
    for (e.terms) |t| {
        try w.int(i64, t.coeff);
        try encRef(w, t.t);
        try w.bytes(&t.labels);
    }
    try w.int(i64, e.constant);
}

fn decExpr(r: *R, a: Allocator) DecodeError!xt.Expr {
    const n = try r.len(1 << 16, 8 + 5 + xt.MAXB);
    const terms = try a.alloc(xt.Term, n);
    for (terms) |*t| {
        t.coeff = try r.int(i64);
        t.t = try decRef(r);
        t.labels = (try r.take(xt.MAXB))[0..xt.MAXB].*;
    }
    return .{ .terms = terms, .constant = try r.int(i64) };
}

fn shift5(r: *R) DecodeError!u5 {
    const v = try r.byte();
    if (v > 31) return error.NonCanonical;
    return @intCast(v);
}

fn encStatementInto(w: *W, cfg: proto.Config, st: proto.Statement) EncodeError!void {
    try w.header(.statement, cfg.security);
    var s = try w.begin(StTag.config);
    try encConfig(w, cfg);
    try w.end(s);
    s = try w.begin(StTag.witness);
    try w.len(st.witness.len);
    for (st.witness) |t| try encInfo(w, t);
    try w.end(s);
    s = try w.begin(StTag.weights);
    try w.len(st.weights.len);
    for (st.weights) |t| try encInfo(w, t);
    try w.end(s);
    s = try w.begin(StTag.tables);
    try w.len(st.tables.len);
    for (st.tables) |t| try w.bytes(std.mem.asBytes(&t.values));
    try w.end(s);
    s = try w.begin(StTag.ops);
    try w.len(st.ops.len);
    for (st.ops) |op| switch (op) {
        .matmul => |m| {
            // int8 output: tag 1 (unchanged); wide output: tag 7 + out_bits
            try w.byte(if (m.out_bits == 8) 1 else 7);
            for ([_]u32{ m.x, m.w, m.y }) |v| try w.u(v);
            try w.byte(m.shift);
            if (m.out_bits != 8) try w.byte(m.out_bits);
        },
        .hadamard => |h| {
            try w.byte(2);
            for ([_]u32{ h.a, h.b, h.y }) |v| try w.u(v);
            try w.byte(h.shift);
        },
        .lookup => |l| {
            try w.byte(3);
            for ([_]u32{ l.in, l.out, l.table }) |v| try w.u(v);
        },
        .range8 => |x| {
            try w.byte(4);
            try w.u(x.in);
        },
        .product => |q| {
            try w.byte(5);
            for ([_]u32{ q.a, q.b, q.c }) |v| try w.u(v);
        },
        .glu => |g| {
            try w.byte(6);
            for ([_]u32{ g.g, g.u, g.h, g.table }) |v| try w.u(v);
            try w.byte(g.shift);
        },
    };
    try w.end(s);
    s = try w.begin(StTag.ext_ops);
    try w.len(st.ext.ops.len);
    for (st.ext.ops) |op| switch (op) {
        .einsum => |e| {
            try w.byte(1);
            try encRef(w, e.a);
            try encRef(w, e.b);
            try w.flag(e.y != null);
            if (e.y) |y| try w.u(y);
            try w.byte(e.n_out);
            try w.byte(e.n_k);
            try w.bytes(&e.a_labels);
            try w.bytes(&e.b_labels);
            try w.byte(e.shift);
            try w.byte(e.out_bits);
        },
        .key => |k| {
            try w.byte(2);
            try w.byte(k.n);
            try encExpr(w, k.input);
            try w.flag(k.output != null);
            if (k.output) |o| try encExpr(w, o);
            switch (k.table) {
                .range => |b| {
                    try w.byte(0);
                    try w.byte(b);
                },
                .lookup => |id| {
                    try w.byte(1);
                    try w.u(id);
                },
            }
        },
        .lineq => |l| {
            try w.byte(3);
            try w.byte(l.n);
            try encExpr(w, l.expr);
        },
    };
    try w.end(s);
    s = try w.begin(StTag.ext_publics);
    try w.len(st.ext.publics.len);
    for (st.ext.publics) |p| {
        try w.u(p.log_size);
        try w.len(p.values.len);
        for (p.values) |v| try w.int(i32, v);
    }
    try w.end(s);
    s = try w.begin(StTag.ext_tables);
    try w.len(st.ext.tables.len);
    for (st.ext.tables) |t| {
        try w.byte(t.log_size);
        try w.len(t.values.len);
        for (t.values) |v| try w.int(i32, v);
    }
    try w.end(s);
    if (st.model_digest) |d| {
        s = try w.begin(StTag.model_digest);
        try w.bytes(&d);
        try w.end(s);
    }
}

/// Canonical encoding of a statement together with the verifier config
/// (prover-only fields such as thread counts and accelerators are not
/// encoded; hiding mode is not supported by this format).
pub fn encodeStatement(a: Allocator, cfg: proto.Config, st: proto.Statement) EncodeError![]u8 {
    var w = W{ .a = a };
    errdefer w.buf.deinit(a);
    try encStatementInto(&w, cfg, st);
    return w.buf.toOwnedSlice(a);
}

pub const StatementFile = struct {
    arena: std.heap.ArenaAllocator,
    cfg: proto.Config,
    st: proto.Statement,

    pub fn deinit(self: *StatementFile) void {
        self.arena.deinit();
    }
};

const MAX_TENSORS = 4096;
const MAX_OPS = 1 << 16;
const MAX_PUBLIC_LOG = 24;

/// Decodes a statement file. Statement well-formedness (indices, shapes) is
/// checked by the verifier's own validation (protocol.validateStatement /
/// ext.validate), which `proofCaps` runs before any proof is decoded.
pub fn decodeStatement(gpa: Allocator, bytes: []const u8) DecodeError!StatementFile {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    var ss = try Sections.open(bytes, .statement);
    var st: proto.Statement = .{ .witness = &.{}, .weights = &.{}, .tables = &.{}, .ops = &.{} };

    var r = try ss.required(StTag.config);
    var cfg = try decConfig(&r);
    cfg.security = ss.level;
    try r.done();

    r = try ss.required(StTag.witness);
    const wi = try a.alloc(proto.TensorInfo, try r.len(MAX_TENSORS, 2));
    for (wi) |*t| t.* = try decInfo(&r);
    st.witness = wi;
    try r.done();

    r = try ss.required(StTag.weights);
    const wt = try a.alloc(proto.TensorInfo, try r.len(MAX_TENSORS, 2));
    for (wt) |*t| t.* = try decInfo(&r);
    st.weights = wt;
    try r.done();

    r = try ss.required(StTag.tables);
    const tabs = try a.alloc(proto.Table, try r.len(MAX_TENSORS, 256));
    for (tabs) |*t| @memcpy(std.mem.asBytes(&t.values), try r.take(256));
    st.tables = tabs;
    try r.done();

    r = try ss.required(StTag.ops);
    const ops = try a.alloc(proto.Op, try r.len(MAX_OPS, 5));
    for (ops) |*op| {
        op.* = switch (try r.byte()) {
            1 => .{ .matmul = .{ .x = try r.int(u32), .w = try r.int(u32), .y = try r.int(u32), .shift = try shift5(&r) } },
            2 => .{ .hadamard = .{ .a = try r.int(u32), .b = try r.int(u32), .y = try r.int(u32), .shift = try shift5(&r) } },
            3 => .{ .lookup = .{ .in = try r.int(u32), .out = try r.int(u32), .table = try r.int(u32) } },
            4 => .{ .range8 = .{ .in = try r.int(u32) } },
            5 => .{ .product = .{ .a = try r.int(u32), .b = try r.int(u32), .c = try r.int(u32) } },
            6 => .{ .glu = .{ .g = try r.int(u32), .u = try r.int(u32), .h = try r.int(u32), .table = try r.int(u32), .shift = try shift5(&r) } },
            7 => blk: {
                const m: @FieldType(proto.Op, "matmul") = .{ .x = try r.int(u32), .w = try r.int(u32), .y = try r.int(u32), .shift = try shift5(&r), .out_bits = try shift5(&r) };
                // canonical: tag 7 only for wide outputs
                if (m.out_bits == 8) return error.NonCanonical;
                break :blk .{ .matmul = m };
            },
            else => return error.NonCanonical,
        };
    }
    st.ops = ops;
    try r.done();

    r = try ss.required(StTag.ext_ops);
    const xops = try a.alloc(xt.Op, try r.len(MAX_OPS, 2));
    for (xops) |*op| {
        op.* = switch (try r.byte()) {
            1 => blk: {
                var e: xt.Einsum = undefined;
                e.a = try decRef(&r);
                e.b = try decRef(&r);
                e.y = if (try r.flag()) try r.int(u32) else null;
                e.n_out = try r.byte();
                e.n_k = try r.byte();
                e.a_labels = (try r.take(xt.MAXB))[0..xt.MAXB].*;
                e.b_labels = (try r.take(xt.MAXB))[0..xt.MAXB].*;
                e.shift = try shift5(&r);
                e.out_bits = try shift5(&r);
                break :blk .{ .einsum = e };
            },
            2 => blk: {
                const n = try r.byte();
                const input = try decExpr(&r, a);
                const output: ?xt.Expr = if (try r.flag()) try decExpr(&r, a) else null;
                const table: xt.TableRef = switch (try r.byte()) {
                    0 => .{ .range = try shift5(&r) },
                    1 => .{ .lookup = try r.int(u32) },
                    else => return error.NonCanonical,
                };
                break :blk .{ .key = .{ .n = n, .input = input, .output = output, .table = table } };
            },
            3 => blk: {
                const n = try r.byte();
                break :blk .{ .lineq = .{ .n = n, .expr = try decExpr(&r, a) } };
            },
            else => return error.NonCanonical,
        };
    }
    try r.done();

    r = try ss.required(StTag.ext_publics);
    const pubs = try a.alloc(xt.Public, try r.len(MAX_TENSORS, 8));
    for (pubs) |*p| {
        p.log_size = try r.capped(MAX_PUBLIC_LOG);
        const n = try r.len(pow2(p.log_size), 4);
        if (n != pow2(p.log_size)) return error.ShapeMismatch;
        const vals = try a.alloc(i32, n);
        for (vals) |*v| v.* = try r.int(i32);
        p.values = vals;
    }
    try r.done();

    r = try ss.required(StTag.ext_tables);
    const xtabs = try a.alloc(xt.LookupTable, try r.len(MAX_TENSORS, 5));
    for (xtabs) |*t| {
        const ls = try r.byte();
        if (ls > xt.MAX_TABLE_BITS) return error.LengthCap;
        t.log_size = @intCast(ls);
        const n = try r.len(pow2(ls), 4);
        if (n != pow2(ls)) return error.ShapeMismatch;
        const vals = try a.alloc(i32, n);
        for (vals) |*v| v.* = try r.int(i32);
        t.values = vals;
    }
    try r.done();
    st.ext = .{ .ops = xops, .publics = pubs, .tables = xtabs };

    if (try ss.optional(StTag.model_digest)) |rd| {
        var rm = rd;
        st.model_digest = try rm.hash();
        try rm.done();
    }

    try ss.finish();
    return .{ .arena = arena, .cfg = cfg, .st = st };
}

// ---------------------------------------------------------------------------
// Structural equality (decode(encode(p)) == p): slices element-wise, field
// elements by value, GKR polynomials by their trimmed coefficients, sumcheck
// rounds by their first `deg` evaluations.

pub fn deepEql(x: anytype, y: @TypeOf(x)) bool {
    const T = @TypeOf(x);
    if (T == QM31) return x.eql(y);
    if (T == M31) return x.v == y.v;
    if (T == sc.Proof) {
        if (x.deg != y.deg or x.rounds.len != y.rounds.len) return false;
        for (x.rounds, y.rounds) |p, q| for (p.evals[0..x.deg], q.evals[0..x.deg]) |u, v| if (!u.eql(v)) return false;
        return true;
    }
    if (T == GkrPoly) return deepEql(x.coeffsSlice(), y.coeffsSlice());
    switch (@typeInfo(T)) {
        .int, .bool, .@"enum" => return x == y,
        .array => {
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .pointer => |pi| {
            if (pi.size != .slice) @compileError("deepEql: " ++ @typeName(T));
            if (x.len != y.len) return false;
            for (x, y) |u, v| if (!deepEql(u, v)) return false;
            return true;
        },
        .optional => {
            if ((x == null) != (y == null)) return false;
            return if (x) |u| deepEql(u, y.?) else true;
        },
        .@"struct" => |si| {
            inline for (si.fields) |fld| if (!deepEql(@field(x, fld.name), @field(y, fld.name))) return false;
            return true;
        },
        .@"union" => {
            if (std.meta.activeTag(x) != std.meta.activeTag(y)) return false;
            switch (x) {
                inline else => |u, tag| return deepEql(u, @field(y, @tagName(tag))),
            }
        },
        else => @compileError("deepEql: " ++ @typeName(T)),
    }
}
