//! Transformer-coverage extension ops for the tensor protocol.
//!
//! Three generic op kinds cover a full Llama-style decoder layer (attention
//! with GQA + causal softmax, RoPE, RMSNorm, residuals); see
//! design/tensor-frontend/transformer.md for the integer model and the
//! soundness argument.
//!
//! All tensors are addressed at *bit* granularity: a tensor of 2^n entries has
//! n index bits, MSB-first. An op works over a "variable space" of m boolean
//! variables and every operand carries a label per index bit naming the
//! variable that drives it. This expresses batching, transposes, broadcasts,
//! head grouping (GQA) and pair-rotation (RoPE) uniformly.
//!
//!   einsum  Y[o] = requant_s( sum_k A[la(o,k)] * B[lb(o,k)] )   (s > 0)
//!           Y[o] =             sum_k A[..] * B[..]               (s = 0, exact;
//!                                                                 y = null means Y == 0)
//!           Vars 0..n_out-1 are Y's bits, n_out..n_out+n_k-1 are contracted.
//!           Output vars present in both A and B are "batch" vars (eq factor,
//!           degree-3 sumcheck); output vars present in one operand only are
//!           folded into that operand at the claim point.
//!   key     input(x) + beta * output(x) in table, x in {0,1}^n, where input
//!           and output are linear expressions (Expr) of committed and public
//!           tensors with broadcasting and SUM-reductions. Range tables
//!           [0, 2^b) and public lookup tables.
//!   lineq   expr(x) == 0 for all x in {0,1}^n (checked at a random point).
//!
//! Operands may be public tensors (verifier evaluates their MLEs directly).
//! Requant remainders stay virtual exactly as in the core protocol.
const std = @import("std");
const builtin = @import("builtin");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const proto = @import("protocol.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;

pub const MAXB = 32;
/// Label: this index bit is summed over (only in Expr terms).
pub const SUM: u8 = 0xFE;
/// Labels: this index bit is fixed to 0 / 1 (slicing; einsum operands and Expr terms).
pub const FIX0: u8 = 0xFC;
pub const FIX1: u8 = 0xFD;

pub inline fn isFix(l: u8) bool {
    return l == FIX0 or l == FIX1;
}

/// Constant part of an operand index from its fixed bits: (mask, value).
fn fixConst(lab: Labels, nb: u32) struct { mask: usize, val: usize } {
    var m: usize = 0;
    var v: usize = 0;
    for (0..nb) |p| if (isFix(lab[p])) {
        const bit = @as(usize, 1) << @intCast(nb - 1 - p);
        m |= bit;
        if (lab[p] == FIX1) v |= bit;
    };
    return .{ .mask = m, .val = v };
}
/// Label: unused (bits beyond the tensor's size).
pub const NONE: u8 = 0xFF;
pub const Labels = [MAXB]u8;
/// Largest range/lookup table and requant shift accepted by the verifier.
pub const MAX_TABLE_BITS = 20;

/// Test-only: when set (in test builds), the prover skips its own witness
/// checks so adversarial tests can exercise the verifier on invalid witnesses.
pub var test_unchecked_prover: bool = false;

fn unchecked() bool {
    return builtin.is_test and test_unchecked_prover;
}

pub fn labels(xs: []const u8) Labels {
    var l: Labels = [_]u8{NONE} ** MAXB;
    @memcpy(l[0..xs.len], xs);
    return l;
}

pub const Ref = struct {
    public: bool = false,
    id: u32,

    pub fn w(id: u32) Ref {
        return .{ .id = id };
    }
    pub fn p(id: u32) Ref {
        return .{ .public = true, .id = id };
    }
};

pub const Public = struct { log_size: u32, values: []const i32 };
pub const LookupTable = struct { log_size: u5, values: []const i32 };
pub const Term = struct { coeff: i64, t: Ref, labels: Labels };
pub const Expr = struct { terms: []const Term = &.{}, constant: i64 = 0 };
pub const TableRef = union(enum) { range: u5, lookup: u32 };

pub const Einsum = struct {
    a: Ref,
    b: Ref,
    y: ?u32,
    n_out: u8,
    n_k: u8,
    a_labels: Labels,
    b_labels: Labels,
    shift: u5 = 0,
    /// requant only: Y + 2^(out_bits-1) in [0, 2^out_bits)
    out_bits: u5 = 8,
};
pub const KeyOp = struct { n: u8, input: Expr, output: ?Expr = null, table: TableRef };
pub const LinEq = struct { n: u8, expr: Expr };
pub const Op = union(enum) { einsum: Einsum, key: KeyOp, lineq: LinEq };

pub const Ext = struct {
    ops: []const Op = &.{},
    publics: []const Public = &.{},
    tables: []const LookupTable = &.{},

    pub fn isEmpty(self: Ext) bool {
        return self.ops.len == 0 and self.publics.len == 0 and self.tables.len == 0;
    }
};

// ---------------------------------------------------------------------------
// Derived LogUp keys.

pub const KeyKind = enum { remainder, y_range, key };
pub const Key = struct { kind: KeyKind, op: u32, log_size: u32, table: TableRef };

pub fn deriveKeys(a: std.mem.Allocator, x: Ext) ![]Key {
    var out: std.ArrayList(Key) = .empty;
    errdefer out.deinit(a);
    for (x.ops, 0..) |op, i| switch (op) {
        .einsum => |e| if (e.shift > 0) {
            try out.append(a, .{ .kind = .remainder, .op = @intCast(i), .log_size = e.n_out, .table = .{ .range = e.shift } });
            try out.append(a, .{ .kind = .y_range, .op = @intCast(i), .log_size = e.n_out, .table = .{ .range = e.out_bits } });
        },
        .key => |k| try out.append(a, .{ .kind = .key, .op = @intCast(i), .log_size = k.n, .table = k.table }),
        .lineq => {},
    };
    return out.toOwnedSlice(a);
}

pub fn tableLogSize(x: Ext, t: TableRef) u32 {
    return switch (t) {
        .range => |b| b,
        .lookup => |id| x.tables[id].log_size,
    };
}

// ---------------------------------------------------------------------------
// Statement validation (verifier-side; malformed statements are rejected
// before any indexing).

pub fn refBits(st: proto.Statement, r: Ref) !u32 {
    if (r.public) {
        if (r.id >= st.ext.publics.len) return error.ExtStatement;
        return st.ext.publics[r.id].log_size;
    }
    if (r.id >= st.witness.len) return error.ExtStatement;
    return st.witness[r.id].logSize();
}

fn checkLabels(lab: Labels, nb: u32, n_vars: u32, allow_sum: bool) !void {
    if (nb > MAXB) return error.ExtStatement;
    var seen: u64 = 0;
    for (lab, 0..) |l, i| {
        if (i >= nb) {
            if (l != NONE) return error.ExtStatement;
            continue;
        }
        if (l == SUM) {
            if (!allow_sum) return error.ExtStatement;
            continue;
        }
        if (isFix(l)) continue;
        if (l >= n_vars) return error.ExtStatement;
        const bit = @as(u64, 1) << @intCast(l);
        if (seen & bit != 0) return error.ExtStatement;
        seen |= bit;
    }
}

fn labelMask(lab: Labels) u64 {
    var m: u64 = 0;
    for (lab) |l| if (l < MAXB) {
        m |= @as(u64, 1) << @intCast(l);
    };
    return m;
}

fn checkExpr(st: proto.Statement, e: Expr, n: u32) !void {
    for (e.terms) |t| try checkLabels(t.labels, try refBits(st, t.t), n, true);
}

pub fn validate(st: proto.Statement) !void {
    const x = st.ext;
    for (x.publics) |p| {
        if (p.log_size > MAXB or p.values.len != (@as(usize, 1) << @intCast(p.log_size))) return error.ExtStatement;
    }
    for (x.tables) |t| {
        if (t.log_size == 0 or t.log_size > MAX_TABLE_BITS or t.values.len != (@as(usize, 1) << t.log_size)) return error.ExtStatement;
    }
    for (x.ops) |op| switch (op) {
        .einsum => |e| {
            const nv: u32 = @as(u32, e.n_out) + e.n_k;
            if (nv > MAXB) return error.ExtStatement;
            try checkLabels(e.a_labels, try refBits(st, e.a), nv, false);
            try checkLabels(e.b_labels, try refBits(st, e.b), nv, false);
            const ma = labelMask(e.a_labels);
            const mb = labelMask(e.b_labels);
            const out_mask: u64 = (@as(u64, 1) << @intCast(e.n_out)) - 1;
            const all_mask: u64 = (@as(u64, 1) << @intCast(nv)) - 1;
            // every output var is driven by some operand; every contracted var by both
            if ((ma | mb) & out_mask != out_mask) return error.ExtStatement;
            if (ma & mb & (all_mask & ~out_mask) != (all_mask & ~out_mask)) return error.ExtStatement;
            if (e.y) |y| {
                if (y >= st.witness.len or st.witness[y].logSize() != e.n_out) return error.ExtStatement;
            }
            if (e.shift > 0) {
                if (e.y == null or e.shift > MAX_TABLE_BITS) return error.ExtStatement;
                if (e.out_bits == 0 or e.out_bits > MAX_TABLE_BITS) return error.ExtStatement;
            }
        },
        .key => |k| {
            if (k.n > MAXB) return error.ExtStatement;
            try checkExpr(st, k.input, k.n);
            switch (k.table) {
                .range => |b| {
                    if (b == 0 or b > MAX_TABLE_BITS) return error.ExtStatement;
                    if (k.output != null) return error.ExtStatement;
                },
                .lookup => |id| {
                    if (id >= x.tables.len) return error.ExtStatement;
                    if (k.output == null) return error.ExtStatement;
                },
            }
            if (k.output) |o| try checkExpr(st, o, k.n);
        },
        .lineq => |l| {
            if (l.n > MAXB) return error.ExtStatement;
            try checkExpr(st, l.expr, l.n);
        },
    };
}

// ---------------------------------------------------------------------------
// Statement binding.

fn mixLabels(tr: *Transcript, lab: Labels) void {
    var w: [MAXB / 4]u32 = undefined;
    for (0..MAXB / 4) |i| w[i] = @as(u32, lab[4 * i]) | (@as(u32, lab[4 * i + 1]) << 8) | (@as(u32, lab[4 * i + 2]) << 16) | (@as(u32, lab[4 * i + 3]) << 24);
    tr.mixU32s(&w);
}

fn mixRef(tr: *Transcript, r: Ref) void {
    tr.mixU32s(&.{ @intFromBool(r.public), r.id });
}

fn mixExpr(tr: *Transcript, e: Expr) void {
    tr.mixU64(e.terms.len);
    tr.mixU64(@bitCast(e.constant));
    for (e.terms) |t| {
        tr.mixU64(@bitCast(t.coeff));
        mixRef(tr, t.t);
        mixLabels(tr, t.labels);
    }
}

fn mixI32s(tr: *Transcript, v: []const i32) void {
    var i: usize = 0;
    var buf: [256]u32 = undefined;
    while (i < v.len) {
        const n = @min(buf.len, v.len - i);
        for (0..n) |j| buf[j] = @bitCast(v[i + j]);
        tr.mixU32s(buf[0..n]);
        i += n;
    }
}

pub fn mixStatement(tr: *Transcript, x: Ext) void {
    if (x.isEmpty()) return; // core transcripts are unchanged
    tr.mixU32s(&.{ 0x45585431, @intCast(x.ops.len), @intCast(x.publics.len), @intCast(x.tables.len) });
    for (x.publics) |p| {
        tr.mixU64(p.log_size);
        mixI32s(tr, p.values);
    }
    for (x.tables) |t| {
        tr.mixU64(t.log_size);
        mixI32s(tr, t.values);
    }
    for (x.ops) |op| switch (op) {
        .einsum => |e| {
            tr.mixU32s(&.{ 11, if (e.y) |y| y else 0xffff_ffff, e.n_out, e.n_k, e.shift, e.out_bits });
            mixRef(tr, e.a);
            mixRef(tr, e.b);
            mixLabels(tr, e.a_labels);
            mixLabels(tr, e.b_labels);
        },
        .key => |k| {
            switch (k.table) {
                .range => |b| tr.mixU32s(&.{ 12, k.n, 0, b }),
                .lookup => |id| tr.mixU32s(&.{ 12, k.n, 1, id }),
            }
            mixExpr(tr, k.input);
            tr.mixU64(@intFromBool(k.output != null));
            if (k.output) |o| mixExpr(tr, o);
        },
        .lineq => |l| {
            tr.mixU32s(&.{ 13, l.n });
            mixExpr(tr, l.expr);
        },
    };
}

// ---------------------------------------------------------------------------
// Bit gathers: map a source index (nsrc bits) to a destination bit pattern
// through per-bit masks, using 11-bit chunk tables.

const Gather = struct {
    tabs: [3][]u64,
    n_chunks: usize,

    /// masks[q] = destination mask for source bit q (LSB-first).
    fn init(a: std.mem.Allocator, masks: []const u64) !Gather {
        var g: Gather = .{ .tabs = undefined, .n_chunks = (masks.len + 10) / 11 };
        std.debug.assert(g.n_chunks <= 3);
        var built: usize = 0;
        errdefer for (g.tabs[0..built]) |t| a.free(t);
        for (0..g.n_chunks) |c| {
            const lo = c * 11;
            const nb = @min(11, masks.len - lo);
            const t = try a.alloc(u64, @as(usize, 1) << @intCast(nb));
            t[0] = 0;
            for (1..t.len) |v| {
                const low = @ctz(v);
                t[v] = t[v & (v - 1)] | masks[lo + low];
            }
            g.tabs[c] = t;
            built += 1;
        }
        return g;
    }

    fn deinit(self: *Gather, a: std.mem.Allocator) void {
        for (self.tabs[0..self.n_chunks]) |t| a.free(t);
    }

    inline fn get(self: *const Gather, i: usize) u64 {
        var r: u64 = 0;
        for (0..self.n_chunks) |c| r |= self.tabs[c][(i >> @intCast(11 * c)) & (self.tabs[c].len - 1)];
        return r;
    }
};

/// Masks mapping the einsum index x = (o, k) (n_out + n_k bits, MSB-first)
/// to an operand index with `nb` bits and labels `lab`.
fn opIndexMasks(a: std.mem.Allocator, nv: u32, nb: u32, lab: Labels) ![]u64 {
    const m = try a.alloc(u64, nv);
    @memset(m, 0);
    for (0..nb) |pbit| {
        const v = lab[pbit];
        if (isFix(v)) continue; // constant bit (fixConst)
        // var v is x bit (MSB-first) v -> LSB-first position nv-1-v
        m[nv - 1 - v] |= @as(u64, 1) << @intCast(nb - 1 - pbit);
    }
    return m;
}

pub fn refValues(st: proto.Statement, w: []const []const i32, r: Ref) []const i32 {
    return if (r.public) st.ext.publics[r.id].values else w[r.id];
}

/// Integer einsum accumulator (prover / builder): acc[o] = sum_k A * B.
pub fn einsumAcc(a: std.mem.Allocator, pool: *f.Pool, e: Einsum, av: []const i32, bv: []const i32) ![]i64 {
    const nv: u32 = @as(u32, e.n_out) + e.n_k;
    const ma = try opIndexMasks(a, nv, f.log2Exact(av.len), e.a_labels);
    defer a.free(ma);
    const mb = try opIndexMasks(a, nv, f.log2Exact(bv.len), e.b_labels);
    defer a.free(mb);
    var ga = try Gather.init(a, ma);
    defer ga.deinit(a);
    var gb = try Gather.init(a, mb);
    defer gb.deinit(a);
    const n_o = @as(usize, 1) << @intCast(e.n_out);
    const kn = @as(usize, 1) << @intCast(e.n_k);
    const acc = try a.alloc(i64, n_o);
    errdefer a.free(acc);
    // gathers are ORs of disjoint per-bit contributions: index(o, k) =
    // index(o, 0) | index(0, k); precompute the k offsets once.
    const offs = try a.alloc(u32, 2 * kn);
    defer a.free(offs);
    for (0..kn) |k| {
        offs[k] = @intCast(ga.get(k));
        offs[kn + k] = @intCast(gb.get(k));
    }
    const Ctx = struct { ga: *const Gather, gb: *const Gather, av: []const i32, bv: []const i32, acc: []i64, nk: u32, offa: []const u32, offb: []const u32, ca: usize, cb: usize };
    const ctx = Ctx{ .ga = &ga, .gb = &gb, .av = av, .bv = bv, .acc = acc, .nk = e.n_k, .offa = offs[0..kn], .offb = offs[kn..], .ca = fixConst(e.a_labels, f.log2Exact(av.len)).val, .cb = fixConst(e.b_labels, f.log2Exact(bv.len)).val };
    pool.parallelFor(n_o, 16, &ctx, struct {
        fn run(c: *const Ctx, s: usize, end: usize) void {
            for (s..end) |o| {
                var sum: i64 = 0;
                const base = o << @intCast(c.nk);
                const ba = c.ga.get(base) | c.ca;
                const bb = c.gb.get(base) | c.cb;
                for (c.offa, c.offb) |oa, ob| {
                    sum += @as(i64, c.av[ba | oa]) * @as(i64, c.bv[bb | ob]);
                }
                c.acc[o] = sum;
            }
        }
    }.run);
    return acc;
}

/// Integer value of an expression over {0,1}^n (prover / builder).
pub fn materialize(a: std.mem.Allocator, st: proto.Statement, w: []const []const i32, e: Expr, n: u32) ![]i64 {
    const N = @as(usize, 1) << @intCast(n);
    const out = try a.alloc(i64, N);
    errdefer a.free(out);
    @memset(out, e.constant);
    for (e.terms) |t| {
        const vals = refValues(st, w, t.t);
        const nb = f.log2Exact(vals.len);
        // reduced tensor R over the mapped vars (in var order), summing SUM bits
        var mapped: u64 = 0;
        for (t.labels[0..nb]) |l| if (l != SUM and !isFix(l)) {
            mapped |= @as(u64, 1) << @intCast(l);
        };
        const nm: u32 = @popCount(mapped);
        // position of var v among mapped vars (MSB-first in var order)
        var pos: [MAXB]u8 = undefined;
        var cnt: u8 = 0;
        for (0..n) |v| if (mapped & (@as(u64, 1) << @intCast(v)) != 0) {
            pos[v] = cnt;
            cnt += 1;
        };
        const R = try a.alloc(i64, @as(usize, 1) << @intCast(nm));
        defer a.free(R);
        @memset(R, 0);
        const m1 = try a.alloc(u64, nb);
        defer a.free(m1);
        @memset(m1, 0);
        for (0..nb) |pb| {
            const l = t.labels[pb];
            if (l == SUM or isFix(l)) continue;
            m1[nb - 1 - pb] = @as(u64, 1) << @intCast(nm - 1 - pos[l]);
        }
        var g1 = try Gather.init(a, m1);
        defer g1.deinit(a);
        const fc = fixConst(t.labels, nb);
        for (vals, 0..) |v, i| {
            if (i & fc.mask != fc.val) continue;
            R[g1.get(i)] += v;
        }
        // broadcast into key space
        const m2 = try a.alloc(u64, n);
        defer a.free(m2);
        @memset(m2, 0);
        for (0..n) |v| if (mapped & (@as(u64, 1) << @intCast(v)) != 0) {
            m2[n - 1 - v] = @as(u64, 1) << @intCast(nm - 1 - pos[v]);
        };
        var g2 = try Gather.init(a, m2);
        defer g2.deinit(a);
        for (out, 0..) |*o, x| o.* += t.coeff * R[g2.get(x)];
    }
    return out;
}

// ---------------------------------------------------------------------------
// MLE helpers.

pub const HALF = QM31.fromU32Unchecked(1 << 30, 0, 0, 0);

/// Point for a term's tensor at key point rho (SUM bits -> 1/2).
pub fn termPoint(a: std.mem.Allocator, t: Term, nb: u32, rho: []const QM31) ![]QM31 {
    const pt = try a.alloc(QM31, nb);
    for (0..nb) |i| pt[i] = switch (t.labels[i]) {
        SUM => HALF,
        FIX0 => QM31.zero(),
        FIX1 => QM31.one(),
        else => |l| rho[l],
    };
    return pt;
}

pub fn termScale(t: Term, nb: u32) QM31 {
    var n_sum: u32 = 0;
    for (t.labels[0..nb]) |l| n_sum += @intFromBool(l == SUM);
    return f.qFromI64(t.coeff).mulM31(M31.fromCanonical(@as(u32, 1) << @intCast(n_sum)));
}

pub fn mlePar(a: std.mem.Allocator, pool: *f.Pool, vals: []const i32, pt: []const QM31) !QM31 {
    const eq = try f.eqTablePar(a, pool, pt, QM31.one());
    defer a.free(eq);
    const CH = 1 << 14;
    const n_ch = (vals.len + CH - 1) / CH;
    const parts = try a.alloc(QM31, n_ch);
    defer a.free(parts);
    const Ctx = struct { vals: []const i32, eq: []const QM31, parts: []QM31 };
    const ctx = Ctx{ .vals = vals, .eq = eq, .parts = parts };
    pool.parallelFor(n_ch, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |ch| {
                const lo = ch * CH;
                const hi = @min(c.vals.len, lo + CH);
                var acc = QM31.zero();
                for (c.vals[lo..hi], c.eq[lo..hi]) |v, w| {
                    if (v != 0) acc = acc.add(w.mulM31(f.fromI32(v)));
                }
                c.parts[ch] = acc;
            }
        }
    }.run);
    var acc = QM31.zero();
    for (parts) |x| acc = acc.add(x);
    return acc;
}

pub fn publicMle(a: std.mem.Allocator, x: Ext, id: u32, pt: []const QM31) !QM31 {
    return f.mleEvalI32(a, x.publics[id].values, pt);
}

// ---------------------------------------------------------------------------
// Proof part.

pub const ProofPart = struct {
    /// witness MLE values sent by the prover (terminal keys, lineqs, exact y)
    values: []QM31 = &.{},
    sumchecks: []sc.Proof = &.{},
    /// per einsum: [A'(r), B'(r)]
    finals: [][2]QM31 = &.{},

    pub fn deinit(self: *ProofPart, a: std.mem.Allocator) void {
        a.free(self.values);
        for (self.sumchecks) |*p| p.deinit(a);
        a.free(self.sumchecks);
        a.free(self.finals);
    }

    pub fn byteSize(self: ProofPart) usize {
        var s = self.values.len * 16 + self.finals.len * 32;
        for (self.sumchecks) |p| s += p.byteSize();
        return s;
    }
};

// ---------------------------------------------------------------------------
// Prover state.

pub const ProverState = struct {
    keys: []Key,
    /// per op: integer accumulator of requant einsums
    acc: []?[]i64,
    /// per key: integer input / output column
    col0: [][]i64,
    col1: []?[]i64,

    pub fn deinit(self: *ProverState, a: std.mem.Allocator) void {
        for (self.acc) |x| if (x) |v| a.free(v);
        a.free(self.acc);
        for (self.col0) |c| a.free(c);
        a.free(self.col0);
        for (self.col1) |c| if (c) |v| a.free(v);
        a.free(self.col1);
        a.free(self.keys);
    }
};

/// Compute accumulators and key columns; refuses witnesses that violate an
/// exact einsum or a linear equality (the prover-side sanity check).
pub fn proverInit(a: std.mem.Allocator, pool: *f.Pool, st: proto.Statement, w: []const []const i32) !ProverState {
    try validate(st);
    const x = st.ext;
    const keys = try deriveKeys(a, x);
    errdefer a.free(keys);
    const acc = try a.alloc(?[]i64, x.ops.len);
    @memset(acc, null);
    errdefer {
        for (acc) |v| if (v) |vv| a.free(vv);
        a.free(acc);
    }
    for (x.ops, 0..) |op, i| switch (op) {
        .einsum => |e| {
            const v = try einsumAcc(a, pool, e, refValues(st, w, e.a), refValues(st, w, e.b));
            if (e.shift == 0) {
                defer a.free(v);
                for (v, 0..) |s, j| {
                    const want: i64 = if (e.y) |y| w[y][j] else 0;
                    if (s != want and !unchecked()) return error.EinsumMismatch;
                }
            } else acc[i] = v;
        },
        .lineq => |l| {
            const v = try materialize(a, st, w, l.expr, l.n);
            defer a.free(v);
            for (v) |s| if (s != 0 and !unchecked()) return error.LinEqViolated;
        },
        .key => {},
    };
    const col0 = try a.alloc([]i64, keys.len);
    errdefer a.free(col0);
    const col1 = try a.alloc(?[]i64, keys.len);
    errdefer a.free(col1);
    var n_done: usize = 0;
    errdefer for (0..n_done) |i| {
        a.free(col0[i]);
        if (col1[i]) |v| a.free(v);
    };
    for (keys, 0..) |k, i| {
        col1[i] = null;
        switch (k.kind) {
            .remainder => {
                const e = x.ops[k.op].einsum;
                const y = w[e.y.?];
                const c = try a.alloc(i64, y.len);
                const half = @as(i64, 1) << (e.shift - 1);
                for (c, acc[k.op].?, y) |*o, s, yy| o.* = s + half - (@as(i64, yy) << e.shift);
                col0[i] = c;
            },
            .y_range => {
                const e = x.ops[k.op].einsum;
                const y = w[e.y.?];
                const c = try a.alloc(i64, y.len);
                const off = @as(i64, 1) << (e.out_bits - 1);
                for (c, y) |*o, yy| o.* = @as(i64, yy) + off;
                col0[i] = c;
            },
            .key => {
                const ko = x.ops[k.op].key;
                col0[i] = try materialize(a, st, w, ko.input, ko.n);
                if (ko.output) |o| col1[i] = materialize(a, st, w, o, ko.n) catch |err| {
                    a.free(col0[i]);
                    return err;
                };
            },
        }
        n_done = i + 1;
    }
    return .{ .keys = keys, .acc = acc, .col0 = col0, .col1 = col1 };
}

pub fn keyDen(a: std.mem.Allocator, pool: *f.Pool, ps: *const ProverState, ki: usize, alpha: QM31, beta: QM31) ![]QM31 {
    const c0 = ps.col0[ki];
    const out = try a.alloc(QM31, c0.len);
    const Ctx = struct { out: []QM31, c0: []const i64, c1: ?[]const i64, alpha: QM31, beta: QM31 };
    const ctx = Ctx{ .out = out, .c0 = c0, .c1 = ps.col1[ki], .alpha = alpha, .beta = beta };
    pool.parallelFor(c0.len, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            if (c.c1) |c1| {
                for (s..e) |i| c.out[i] = c.alpha.sub(f.qFromI64(c.c0[i]).add(c.beta.mul(f.qFromI64(c1[i]))));
            } else {
                for (s..e) |i| c.out[i] = c.alpha.sub(f.qFromI64(c.c0[i]));
            }
        }
    }.run);
    return out;
}

pub fn addMultiplicities(st: proto.Statement, ps: *const ProverState, ki: usize, mult: []i32) !void {
    const k = ps.keys[ki];
    const c0 = ps.col0[ki];
    for (c0, 0..) |v, i| {
        if (v < 0 or v >= mult.len) {
            if (unchecked()) continue;
        }
        if (v < 0 or v >= mult.len) return switch (k.kind) {
            .remainder => error.RemainderOutOfRange,
            else => error.ValueOutOfRange,
        };
        if (ps.col1[ki]) |c1| {
            const t = st.ext.tables[k.table.lookup];
            if (t.values[@intCast(v)] != c1[i] and !unchecked()) return error.LookupMismatch;
        }
        mult[@intCast(v)] += 1;
    }
}

// ---------------------------------------------------------------------------
// Terminal claims of the ext keys.

pub const GkrView = struct {
    ood: []const QM31,
    cv: []const []const QM31,
    /// index of the first ext key among all GKR instances
    key_base: usize,
};

/// Prover: send witness term values of an expression at rho, add claims,
/// return the expression's value at rho.
fn proveExpr(a: std.mem.Allocator, pool: *f.Pool, st: proto.Statement, w: []const []const i32, e: Expr, rho: []const QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), values: *std.ArrayList(QM31)) !QM31 {
    var tot = f.qFromI64(e.constant);
    for (e.terms) |t| {
        const vals = refValues(st, w, t.t);
        const nb = f.log2Exact(vals.len);
        const pt = try termPoint(a, t, nb, rho);
        var keep = false;
        defer if (!keep) a.free(pt);
        const v = if (t.t.public) try publicMle(a, st.ext, t.t.id, pt) else try mlePar(a, pool, vals, pt);
        if (!t.t.public) {
            tr.mixFelt(v);
            try values.append(a, v);
            try claims.append(a, .{ .tensor = t.t.id, .point = pt, .value = v });
            keep = true;
        }
        tot = tot.add(termScale(t, nb).mul(v));
    }
    return tot;
}

const Cursor = struct {
    vals: []const QM31,
    i: usize = 0,
    fn next(self: *Cursor) !QM31 {
        if (self.i >= self.vals.len) return error.ProofShape;
        self.i += 1;
        return self.vals[self.i - 1];
    }
};

fn verifyExpr(a: std.mem.Allocator, st: proto.Statement, e: Expr, rho: []const QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), cur: *Cursor) !QM31 {
    var tot = f.qFromI64(e.constant);
    for (e.terms) |t| {
        const nb = try refBits(st, t.t);
        const pt = try termPoint(a, t, nb, rho);
        var keep = false;
        defer if (!keep) a.free(pt);
        var v: QM31 = undefined;
        if (t.t.public) {
            v = try publicMle(a, st.ext, t.t.id, pt);
        } else {
            v = try cur.next();
            tr.mixFelt(v);
            try claims.append(a, .{ .tensor = t.t.id, .point = pt, .value = v });
            keep = true;
        }
        tot = tot.add(termScale(t, nb).mul(v));
    }
    return tot;
}

fn yRangeClaim(e: Einsum, den: QM31, alpha: QM31) QM31 {
    return alpha.sub(den).sub(f.qFromI64(@as(i64, 1) << (e.out_bits - 1)));
}

pub fn proveTerminal(a: std.mem.Allocator, pool: *f.Pool, st: proto.Statement, w: []const []const i32, ps: *const ProverState, g: GkrView, alpha: QM31, beta: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), values: *std.ArrayList(QM31)) !void {
    const L = g.ood.len;
    for (ps.keys, 0..) |k, i| {
        const pt = g.ood[L - k.log_size ..];
        const den = g.cv[g.key_base + i][1];
        switch (k.kind) {
            .remainder => {},
            .y_range => {
                const e = st.ext.ops[k.op].einsum;
                try claims.append(a, .{ .tensor = e.y.?, .point = try a.dupe(QM31, pt), .value = yRangeClaim(e, den, alpha) });
            },
            .key => {
                const ko = st.ext.ops[k.op].key;
                _ = try proveExpr(a, pool, st, w, ko.input, pt, tr, claims, values);
                if (ko.output) |o| _ = try proveExpr(a, pool, st, w, o, pt, tr, claims, values);
            },
        }
    }
    _ = beta;
}

pub fn verifyTerminal(a: std.mem.Allocator, st: proto.Statement, keys: []const Key, g: GkrView, alpha: QM31, beta: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), part: *const ProofPart, cur_i: *usize) !void {
    const L = g.ood.len;
    var cur = Cursor{ .vals = part.values, .i = cur_i.* };
    for (keys, 0..) |k, i| {
        const pt = g.ood[L - k.log_size ..];
        const cv = g.cv[g.key_base + i];
        if (cv.len != 2) return error.GkrShape;
        const den = cv[1];
        switch (k.kind) {
            .remainder => {},
            .y_range => {
                const e = st.ext.ops[k.op].einsum;
                try claims.append(a, .{ .tensor = e.y.?, .point = try a.dupe(QM31, pt), .value = yRangeClaim(e, den, alpha) });
            },
            .key => {
                const ko = st.ext.ops[k.op].key;
                var v = try verifyExpr(a, st, ko.input, pt, tr, claims, &cur);
                if (ko.output) |o| v = v.add(beta.mul(try verifyExpr(a, st, o, pt, tr, claims, &cur)));
                if (!v.eql(alpha.sub(den))) return error.ExtKeyTerminal;
            },
        }
    }
    cur_i.* = cur.i;
}

// ---------------------------------------------------------------------------
// Einsum sumcheck layout.

pub const Layout = struct {
    /// var -> sumcheck position (NONE for operand-only output vars)
    sc_pos: [MAXB]u8,
    batch: [MAXB]u8,
    n_batch: u32,
    ns: u32,

    pub fn init(e: Einsum) Layout {
        var l: Layout = .{ .sc_pos = [_]u8{NONE} ** MAXB, .batch = undefined, .n_batch = 0, .ns = 0 };
        const ma = labelMask(e.a_labels);
        const mb = labelMask(e.b_labels);
        for (0..e.n_out) |v| if ((ma & mb) & (@as(u64, 1) << @intCast(v)) != 0) {
            l.batch[l.n_batch] = @intCast(v);
            l.sc_pos[v] = @intCast(l.n_batch);
            l.n_batch += 1;
        };
        for (0..e.n_k) |j| l.sc_pos[e.n_out + j] = @intCast(l.n_batch + j);
        l.ns = l.n_batch + e.n_k;
        return l;
    }

    /// Operand point after the sumcheck (rho for folded output vars, r otherwise).
    pub fn operandPoint(self: Layout, a: std.mem.Allocator, lab: Labels, nb: u32, rho: []const QM31, r: []const QM31) ![]QM31 {
        const pt = try a.alloc(QM31, nb);
        for (0..nb) |i| {
            const v = lab[i];
            pt[i] = if (v == FIX0) QM31.zero() else if (v == FIX1) QM31.one() else if (self.sc_pos[v] != NONE) r[self.sc_pos[v]] else rho[v];
        }
        return pt;
    }
};

/// A'(b, k) = sum over operand-only output bits u of eq(rho_u, u) * A[..].
/// Parallel over the target index t: source(t, u) = gT(t) | gU(u).
pub fn foldOperand(a: std.mem.Allocator, pool: *f.Pool, lay: Layout, vals: []const i32, lab: Labels, rho: []const QM31) ![]QM31 {
    const nb = f.log2Exact(vals.len);
    var upt: [MAXB]QM31 = undefined;
    var nu: u32 = 0;
    for (0..nb) |pb| if (!isFix(lab[pb]) and lay.sc_pos[lab[pb]] == NONE) {
        upt[nu] = rho[lab[pb]];
        nu += 1;
    };
    // masks from target bits (LSB-first) and u bits (LSB-first) to source bits
    const mt = try a.alloc(u64, lay.ns);
    defer a.free(mt);
    @memset(mt, 0);
    const mu = try a.alloc(u64, nu);
    defer a.free(mu);
    var ui: u32 = 0;
    for (0..nb) |pb| {
        const v = lab[pb];
        if (isFix(v)) continue;
        const src = @as(u64, 1) << @intCast(nb - 1 - pb);
        if (lay.sc_pos[v] != NONE) {
            mt[lay.ns - 1 - lay.sc_pos[v]] = src;
        } else {
            mu[nu - 1 - ui] = src;
            ui += 1;
        }
    }
    var gt = try Gather.init(a, mt);
    defer gt.deinit(a);
    const nU = @as(usize, 1) << @intCast(nu);
    const uoff = try a.alloc(u32, nU);
    defer a.free(uoff);
    {
        var gu = try Gather.init(a, mu);
        defer gu.deinit(a);
        for (uoff, 0..) |*o, u| o.* = @intCast(gu.get(u));
    }
    const equ = try f.eqTable(a, upt[0..nu], QM31.one());
    defer a.free(equ);
    const out = try a.alloc(QM31, @as(usize, 1) << @intCast(lay.ns));
    const Ctx = struct { gt: *const Gather, uoff: []const u32, equ: []const QM31, vals: []const i32, out: []QM31, cst: usize };
    const ctx = Ctx{ .gt = &gt, .uoff = uoff, .equ = equ, .vals = vals, .out = out, .cst = fixConst(lab, nb).val };
    pool.parallelFor(out.len, 1024, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |t| {
                const base = c.gt.get(t) | c.cst;
                var acc = QM31.zero();
                for (c.uoff, c.equ) |uo, w| {
                    const v = c.vals[base | uo];
                    if (v != 0) acc = acc.add(w.mulM31(f.fromI32(v)));
                }
                c.out[t] = acc;
            }
        }
    }.run);
    return out;
}

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};

fn proveEinsum(a: std.mem.Allocator, pool: *f.Pool, st: proto.Statement, w: []const []const i32, e: Einsum, rho: []const QM31, claim: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), sumchecks: *std.ArrayList(sc.Proof), finals: *std.ArrayList([2]QM31)) !void {
    const lay = Layout.init(e);
    const av = refValues(st, w, e.a);
    const bv = refValues(st, w, e.b);
    const fa = try foldOperand(a, pool, lay, av, e.a_labels, rho);
    defer a.free(fa);
    const fb = try foldOperand(a, pool, lay, bv, e.b_labels, rho);
    defer a.free(fb);
    var res: sc.ProveResult = undefined;
    var fin: [2]QM31 = undefined;
    if (lay.n_batch == 0) {
        res = try sc.proveActive(2, &T_PROD2, a, pool, tr, claim, .{ fa, fb }, fa.len);
        fin = .{ res.finals[0], res.finals[1] };
    } else {
        var bpt: [MAXB]QM31 = undefined;
        for (0..lay.n_batch) |i| bpt[i] = rho[lay.batch[i]];
        const eqb = try f.eqTablePar(a, pool, bpt[0..lay.n_batch], QM31.one());
        defer a.free(eqb);
        const eqf = try a.alloc(QM31, fa.len);
        defer a.free(eqf);
        const BCtx = struct { eqf: []QM31, eqb: []const QM31, nk: u32 };
        const bctx = BCtx{ .eqf = eqf, .eqb = eqb, .nk = e.n_k };
        pool.parallelFor(eqf.len, 1 << 14, &bctx, struct {
            fn run(c: *const BCtx, s: usize, end: usize) void {
                for (s..end) |i| c.eqf[i] = c.eqb[i >> @intCast(c.nk)];
            }
        }.run);
        res = try sc.proveActive(3, &T_EQ3, a, pool, tr, claim, .{ eqf, fa, fb }, fa.len);
        fin = .{ res.finals[1], res.finals[2] };
    }
    defer a.free(res.point);
    a.free(res.finals);
    try sumchecks.append(a, res.proof);
    tr.mixFelts(&fin);
    try finals.append(a, fin);
    if (!e.a.public) try claims.append(a, .{ .tensor = e.a.id, .point = try lay.operandPoint(a, e.a_labels, f.log2Exact(av.len), rho, res.point), .value = fin[0] });
    if (!e.b.public) try claims.append(a, .{ .tensor = e.b.id, .point = try lay.operandPoint(a, e.b_labels, f.log2Exact(bv.len), rho, res.point), .value = fin[1] });
}

fn verifyEinsum(a: std.mem.Allocator, st: proto.Statement, e: Einsum, rho: []const QM31, claim: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), proof: sc.Proof, fin: [2]QM31) !void {
    const lay = Layout.init(e);
    const deg: u8 = if (lay.n_batch == 0) 2 else 3;
    const vr = try sc.verify(a, tr, claim, lay.ns, deg, proof);
    defer a.free(vr.point);
    var bpt: [MAXB]QM31 = undefined;
    for (0..lay.n_batch) |i| bpt[i] = rho[lay.batch[i]];
    const eqb = f.eqEval(bpt[0..lay.n_batch], vr.point[0..lay.n_batch]);
    if (!vr.final_claim.eql(eqb.mul(fin[0]).mul(fin[1]))) return error.ExtEinsum;
    tr.mixFelts(&fin);
    inline for (.{ .{ e.a, e.a_labels, 0 }, .{ e.b, e.b_labels, 1 } }) |op| {
        const r: Ref = op[0];
        const nb = try refBits(st, r);
        const pt = try lay.operandPoint(a, op[1], nb, rho, vr.point);
        if (r.public) {
            defer a.free(pt);
            if (!fin[op[2]].eql(try publicMle(a, st.ext, r.id, pt))) return error.ExtEinsumPublic;
        } else {
            try claims.append(a, .{ .tensor = r.id, .point = pt, .value = fin[op[2]] });
        }
    }
}

fn requantAccClaim(e: Einsum, den_r: QM31, den_y: QM31, alpha: QM31) QM31 {
    const r_val = alpha.sub(den_r);
    const y_val = yRangeClaim(e, den_y, alpha);
    return r_val.sub(f.qFromI64(@as(i64, 1) << (e.shift - 1))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << e.shift)));
}

/// Index of the remainder key of a requant einsum op.
fn remainderKey(keys: []const Key, op: usize) usize {
    for (keys, 0..) |k, i| if (k.kind == .remainder and k.op == op) return i;
    unreachable;
}

pub fn proveOps(a: std.mem.Allocator, pool: *f.Pool, st: proto.Statement, w: []const []const i32, ps: *const ProverState, g: GkrView, alpha: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), values: *std.ArrayList(QM31), sumchecks: *std.ArrayList(sc.Proof), finals: *std.ArrayList([2]QM31)) !void {
    for (st.ext.ops, 0..) |op, oi| switch (op) {
        .einsum => |e| {
            if (e.shift > 0) {
                const ki = remainderKey(ps.keys, oi);
                const rho = g.ood[g.ood.len - e.n_out ..];
                const claim = requantAccClaim(e, g.cv[g.key_base + ki][1], g.cv[g.key_base + ki + 1][1], alpha);
                try proveEinsum(a, pool, st, w, e, rho, claim, tr, claims, sumchecks, finals);
            } else {
                const rho = try a.alloc(QM31, e.n_out);
                defer a.free(rho);
                tr.drawN(rho);
                var claim = QM31.zero();
                if (e.y) |y| {
                    claim = try mlePar(a, pool, w[y], rho);
                    tr.mixFelt(claim);
                    try values.append(a, claim);
                    try claims.append(a, .{ .tensor = y, .point = try a.dupe(QM31, rho), .value = claim });
                }
                try proveEinsum(a, pool, st, w, e, rho, claim, tr, claims, sumchecks, finals);
            }
        },
        .lineq => |l| {
            const rho = try a.alloc(QM31, l.n);
            defer a.free(rho);
            tr.drawN(rho);
            _ = try proveExpr(a, pool, st, w, l.expr, rho, tr, claims, values);
        },
        .key => {},
    };
}

pub fn verifyOps(a: std.mem.Allocator, st: proto.Statement, keys: []const Key, g: GkrView, alpha: QM31, tr: *Transcript, claims: *std.ArrayList(proto.WitnessClaim), part: *const ProofPart, cur_i: *usize) !void {
    var cur = Cursor{ .vals = part.values, .i = cur_i.* };
    var si: usize = 0;
    for (st.ext.ops, 0..) |op, oi| switch (op) {
        .einsum => |e| {
            if (si >= part.sumchecks.len or si >= part.finals.len) return error.ProofShape;
            if (e.shift > 0) {
                const ki = remainderKey(keys, oi);
                if (g.ood.len < e.n_out) return error.GkrShape;
                const rho = g.ood[g.ood.len - e.n_out ..];
                const claim = requantAccClaim(e, g.cv[g.key_base + ki][1], g.cv[g.key_base + ki + 1][1], alpha);
                try verifyEinsum(a, st, e, rho, claim, tr, claims, part.sumchecks[si], part.finals[si]);
            } else {
                const rho = try a.alloc(QM31, e.n_out);
                defer a.free(rho);
                tr.drawN(rho);
                var claim = QM31.zero();
                if (e.y) |y| {
                    claim = try cur.next();
                    tr.mixFelt(claim);
                    try claims.append(a, .{ .tensor = y, .point = try a.dupe(QM31, rho), .value = claim });
                }
                try verifyEinsum(a, st, e, rho, claim, tr, claims, part.sumchecks[si], part.finals[si]);
            }
            si += 1;
        },
        .lineq => |l| {
            const rho = try a.alloc(QM31, l.n);
            defer a.free(rho);
            tr.drawN(rho);
            const v = try verifyExpr(a, st, l.expr, rho, tr, claims, &cur);
            if (!v.isZero()) return error.ExtLinEq;
        },
        .key => {},
    };
    if (si != part.sumchecks.len or si != part.finals.len) return error.ProofShape;
    if (cur.i != part.values.len) return error.ProofShape;
    cur_i.* = cur.i;
}

test "gather and einsum acc match naive" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // Y[h, t, j] = sum_e Q[t, h, e] * K[j, e] ; h:1 bit, t:2, j:2, e:2
    var q: [32]i32 = undefined;
    var k: [16]i32 = undefined;
    for (&q, 0..) |*v, i| v.* = @as(i32, @intCast(i * 7 % 13)) - 6;
    for (&k, 0..) |*v, i| v.* = @as(i32, @intCast(i * 5 % 11)) - 5;
    // vars: h=0, t=1,2, j=3,4, e=5,6
    const e = Einsum{ .a = Ref.w(0), .b = Ref.w(1), .y = null, .n_out = 5, .n_k = 2, .a_labels = labels(&.{ 1, 2, 0, 5, 6 }), .b_labels = labels(&.{ 3, 4, 5, 6 }) };
    const acc = try einsumAcc(a, &pool, e, &q, &k);
    defer a.free(acc);
    for (0..2) |h| for (0..4) |t| for (0..4) |j| {
        var s: i64 = 0;
        for (0..4) |ee| s += @as(i64, q[(t * 2 + h) * 4 + ee]) * k[j * 4 + ee];
        try std.testing.expectEqual(s, acc[(h * 4 + t) * 4 + j]);
    };
}

test "fixed-bit labels: einsum on a slice and an expression on a slice prove/verify" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // W [4 rows, 8 cols] witness; use only cols 4..7 (first col bit fixed 1):
    // y[r] = sum_c W[r, 1, c] * v[c]  (c: 2 bits)
    var wv: [32]i32 = undefined;
    for (&wv, 0..) |*x, i| x.* = @as(i32, @intCast(i % 7)) - 3;
    var vv: [4]i32 = .{ 1, -2, 3, 5 };
    var y: [4]i32 = undefined;
    for (0..4) |r| {
        var s: i32 = 0;
        for (0..4) |c| s += wv[r * 8 + 4 + c] * vv[c];
        y[r] = s;
    }
    // z[r, c] = W[r, 0, c] (slice copy via lineq)
    var z: [16]i32 = undefined;
    for (0..4) |r| for (0..4) |c| {
        z[r * 4 + c] = wv[r * 8 + c];
    };
    const infos = [_]proto.TensorInfo{ proto.TensorInfo.vec(5), proto.TensorInfo.vec(2), proto.TensorInfo.vec(2), proto.TensorInfo.vec(4) };
    const ops = [_]Op{
        .{ .einsum = .{ .a = Ref.w(0), .b = Ref.w(1), .y = 2, .n_out = 2, .n_k = 2, .a_labels = labels(&.{ 0, 1, FIX1, 2, 3 }), .b_labels = labels(&.{ 2, 3 }) } },
        .{ .lineq = .{ .n = 4, .expr = .{ .terms = &.{ .{ .coeff = 1, .t = Ref.w(3), .labels = labels(&.{ 0, 1, 2, 3 }) }, .{ .coeff = -1, .t = Ref.w(0), .labels = labels(&.{ 0, 1, FIX0, 2, 3 }) } } } } },
    };
    const st = proto.Statement{ .witness = &infos, .weights = &.{proto.TensorInfo.mat(2, 2)}, .tables = &.{}, .ops = &.{}, .ext = .{ .ops = &ops } };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 4, .gkr_threads = 1 };
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, st.weights, &dv);
    defer ws.deinit(a);
    const wit = [_][]const i32{ &wv, &vv, &y, &z };
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &ws, &wit, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
    // the other slice must not verify (statement tamper)
    var ops2 = ops;
    ops2[0].einsum.a_labels[2] = FIX0;
    var st2 = st;
    st2.ext.ops = &ops2;
    if (proto.verify(a, pc, st2, proto.weightKey(&ws), &proof)) |_| return error.TamperAccepted else |_| {}
    // and the honest prover refuses the wrong slice
    try std.testing.expectError(error.EinsumMismatch, proto.prove(a, &pool, pc, st2, &ws, &wit, &tm));
}
