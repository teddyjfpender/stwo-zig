//! Zero-knowledge tensor proofs (`Config.hiding = true`).
//!
//! Same statements as protocol.zig, different proof system (design and ZK
//! argument: design/tensor-frontend/zk.md):
//!
//!  * Table 1 (committed first, hiding PCS of zk_pcs.zig): the witness tensors,
//!    the requant remainders (committed here, virtual in v1), LogUp
//!    multiplicities, a 16-cell pad per hatted tensor, the coefficients of
//!    every hiding polynomial, the batch pad row and 16 mask rows.
//!  * Table 2 (committed after the LogUp challenges alpha, beta): the inverses
//!    h_k = 1/(alpha - key_k) of every LogUp key instance (4 M31 limb tensors)
//!    with their pads. LogUp is proved with committed inverses instead of GKR:
//!    a masked zero-check  sum eq(rho,x) h(x) (alpha - key(x)) = 1  per key
//!    instance and a public-value linear claim  sum h - sum m/(alpha - t) = 0
//!    per relation. (GKR layer messages are not hidden by any of the masks
//!    used here; see zk.md for what the non-hiding GKR reveals.)
//!  * Every constraint is a masked zero-check (zk_sumcheck.zig) with a public
//!    claim: products, hadamard/matmul with requant (acc - 2^s y - r = -2^(s-1)),
//!    the inverse checks. Matmul folds the weight side as in v1 and binds the
//!    hat of W(., rho_n) to the hiding weight commitment.
//!  * All linear claims (hats, hiding-polynomial claims, LogUp sums) on tables
//!    1 and 2 are reduced by one masked batch sumcheck to one hat claim per
//!    table (pad row R_b) plus one claim on the batch hiding polynomial; these
//!    are opened together (one multi-table opening, shared queries).
//!  * Weight claims (one hat per matmul, sharing the column point) are opened
//!    against the weight commitment together with a fresh per-proof mask table.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const zkp = @import("zk_pcs.zig");
const zks = @import("zk_sumcheck.zig");
const proto = @import("protocol.zig");
const linalg = @import("linalg.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const TensorInfo = proto.TensorInfo;
const Statement = proto.Statement;
const Hash = [32]u8;
const NONE: u32 = std.math.maxInt(u32);
const PAD_LOG: u32 = 4;
const WPAD_ROWS: usize = 4; // 2 row variables
const N_MASK_ROWS: u32 = 4; // log2(16) mask rows in table 1

fn qi(v: i64) QM31 {
    return f.qFromI64(v);
}

fn log2Ceil(n: usize) u32 {
    var l: u32 = 0;
    while ((@as(usize, 1) << @intCast(l)) < n) l += 1;
    return l;
}

fn shiftHalf(s: u5) i64 {
    return @as(i64, 1) << (s - 1);
}

// ---------------------------------------------------------------------------
// Plan: tensor ids, sumchecks and layouts (shared by prover and verifier).

const RelKind = union(enum) { range: u5, act: u32 };
const Rel = struct { kind: RelKind, log_size: u32, mult: u32 };
const KeyKind = enum { remainder, y_range, plain_range, lookup_pair };
const Key = struct { kind: KeyKind, op: u32, log_size: u32, rel: u32, h: u32 };
const CheckKind = enum { product, hadamard, matmul, key };
const Check = struct { kind: CheckKind, idx: u32, n: u32, deg: u32, u: u32 };
const Lay = struct { offsets: []usize, log_total: u32, used: usize };
/// One layer k (1..n) of a hiding GKR tree: its hiding polynomial and the pads of its 4 finals.
const GLayer = struct { u: u32, pads: [4]u32 };
const GRel = struct {
    rel: u32,
    /// log2 of the number of leaves
    n: u32,
    /// key indices of this relation (segments 0..nk), then the table segment, then the blinder leaf
    keys: []u32,
    seg_off: []usize,
    seg_log: []u32,
    blinder: u32,
    layers: []GLayer,
};

const Plan = struct {
    nw: u32,
    rem: []u32,
    rels: []Rel,
    keys: []Key,
    checks: []Check,
    /// hiding LogUp-GKR trees (one per relation), empty in committed-inverse mode
    grels: []GRel,
    batch_u: u32,
    batch_n: u32,
    infos: [2][]TensorInfo,
    pad: [2][]u32,
    rb: [2]u32,
    masks: u32,
    lay: [2]Lay,
    has2: bool,
    lc: u32,
    slots: u32,
    rho_len: u32,

    fn nCols(self: Plan) usize {
        return @as(usize, 1) << @intCast(self.lc);
    }
    fn rowsUsed(self: Plan, t: usize) usize {
        return (self.lay[t].used + self.nCols() - 1) >> @intCast(self.lc);
    }
    fn off(self: Plan, t: usize, id: u32) usize {
        return self.lay[t].offsets[id];
    }
    fn ls(self: Plan, t: usize, id: u32) u32 {
        return self.infos[t][id].logSize();
    }
    fn maskRow(self: Plan) usize {
        return self.off(0, self.masks) >> @intCast(self.lc);
    }
    fn shape(self: Plan, t: usize, log_blowup: u32) zkp.Shape {
        return .{ .log_cols = self.lc, .log_blowup = log_blowup, .slots = self.slots, .n_rows = self.rowsUsed(t) };
    }
};

/// PCS parameters of the (committed-once) hiding weight table.
pub fn wpcs(cfg: proto.Config) pcs.Params {
    return cfg.weight_pcs orelse cfg.pcs;
}

fn uLog(n: u32, deg: u32) u32 {
    return log2Ceil(zks.Hp.entries(n, deg) * 4);
}

fn findRel(rels: *std.ArrayList(Rel), a: std.mem.Allocator, inf1: *std.ArrayList(TensorInfo), kind: RelKind) !u32 {
    for (rels.items, 0..) |r, i| if (std.meta.eql(r.kind, kind)) return @intCast(i);
    const log_size: u32 = switch (kind) {
        .range => |s| @max(@as(u32, s), 1),
        .act => 8,
    };
    const id: u32 = @intCast(inf1.items.len);
    try inf1.append(a, TensorInfo.vec(log_size));
    try rels.append(a, .{ .kind = kind, .log_size = log_size, .mult = id });
    return @intCast(rels.items.len - 1);
}

fn opY(op: proto.Op) u32 {
    return switch (op) {
        .matmul => |m| m.y,
        .hadamard => |h| h.y,
        else => unreachable,
    };
}

fn opShift(op: proto.Op) u5 {
    return switch (op) {
        .matmul => |m| m.shift,
        .hadamard => |h| h.shift,
        else => unreachable,
    };
}

fn makePlan(a: std.mem.Allocator, st: Statement, wkey: ?WeightKey, cfg: proto.Config) !Plan {
    var inf1: std.ArrayList(TensorInfo) = .empty;
    var inf2: std.ArrayList(TensorInfo) = .empty;
    const nw: u32 = @intCast(st.witness.len);
    try inf1.appendSlice(a, st.witness);
    const rem = try a.alloc(u32, st.ops.len);
    @memset(rem, NONE);
    for (st.ops, 0..) |op, i| switch (op) {
        .matmul, .hadamard => {
            rem[i] = @intCast(inf1.items.len);
            try inf1.append(a, st.witness[opY(op)]);
        },
        else => {},
    };
    const n_hat1: u32 = @intCast(inf1.items.len);
    var rels: std.ArrayList(Rel) = .empty;
    var keys: std.ArrayList(Key) = .empty;
    for (st.ops, 0..) |op, i| {
        const oi: u32 = @intCast(i);
        switch (op) {
            .matmul, .hadamard => {
                const s = opShift(op);
                if (s == 0) return error.StatementShape;
                const lsz = st.witness[opY(op)].logSize();
                try keys.append(a, .{ .kind = .remainder, .op = oi, .log_size = lsz, .rel = try findRel(&rels, a, &inf1, .{ .range = s }), .h = 0 });
                // y in [-128, 128) is implied when y is also the input of a lookup
                // (a LogUp match against the int8 table forces it); skip the key then.
                var implied = false;
                for (st.ops) |o2| switch (o2) {
                    .lookup => |l| implied = implied or l.in == opY(op),
                    else => {},
                };
                if (!implied) try keys.append(a, .{ .kind = .y_range, .op = oi, .log_size = lsz, .rel = try findRel(&rels, a, &inf1, .{ .range = 8 }), .h = 0 });
            },
            .lookup => |l| {
                if (l.table >= st.tables.len) return error.StatementShape;
                if (st.witness[l.in].logSize() != st.witness[l.out].logSize()) return error.StatementShape;
                try keys.append(a, .{ .kind = .lookup_pair, .op = oi, .log_size = st.witness[l.in].logSize(), .rel = try findRel(&rels, a, &inf1, .{ .act = l.table }), .h = 0 });
            },
            .range8 => |r| try keys.append(a, .{ .kind = .plain_range, .op = oi, .log_size = st.witness[r.in].logSize(), .rel = try findRel(&rels, a, &inf1, .{ .range = 8 }), .h = 0 }),
            .product => |p| {
                const lsz = st.witness[p.c].logSize();
                if (st.witness[p.a].logSize() != lsz or st.witness[p.b].logSize() != lsz) return error.StatementShape;
            },
        }
    }
    // pads for hatted table-1 tensors (witness + remainders)
    const n_pre_pad: u32 = @intCast(inf1.items.len);
    const pad1 = try a.alloc(u32, n_pre_pad);
    @memset(pad1, NONE);
    for (0..n_hat1) |i| {
        pad1[i] = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(@min(PAD_LOG, inf1.items[i].logSize())));
    }
    // table 2: inverse limbs + pads (committed-inverse LogUp only)
    const gkr = cfg.zk_logup_gkr;
    if (!gkr) for (keys.items) |*k| {
        k.h = @intCast(inf2.items.len);
        for (0..4) |_| try inf2.append(a, TensorInfo.vec(k.log_size));
    };
    const n_limbs: u32 = @intCast(inf2.items.len);
    const pad2 = try a.alloc(u32, n_limbs);
    for (0..n_limbs) |i| {
        pad2[i] = @intCast(inf2.items.len);
        try inf2.append(a, TensorInfo.vec(@min(PAD_LOG, inf2.items[i].logSize())));
    }
    // checks
    var checks: std.ArrayList(Check) = .empty;
    var rho_len: u32 = 1;
    for (st.ops, 0..) |op, i| {
        const oi: u32 = @intCast(i);
        switch (op) {
            .product => |p| try checks.append(a, .{ .kind = .product, .idx = oi, .n = st.witness[p.c].logSize(), .deg = 3, .u = 0 }),
            .hadamard => |h| {
                const lsz = st.witness[h.y].logSize();
                if (st.witness[h.a].logSize() != lsz or st.witness[h.b].logSize() != lsz) return error.StatementShape;
                try checks.append(a, .{ .kind = .hadamard, .idx = oi, .n = lsz, .deg = 3, .u = 0 });
            },
            .matmul => |m| {
                const wk = wkey orelse return error.StatementShape;
                if (m.w >= wk.infos.len) return error.StatementShape;
                const xi = st.witness[m.x];
                const wi = wk.infos[m.w];
                const yi = st.witness[m.y];
                if (xi.n_dims != 2 or wi.log_dims[0] != xi.log_dims[1] or yi.logSize() != xi.log_dims[0] + wi.log_dims[1]) return error.StatementShape;
                if (wi.log_dims[1] < wk.log_cols or xi.log_dims[1] < 2) return error.StatementShape;
                const n = @max(xi.log_dims[1], yi.logSize());
                try checks.append(a, .{ .kind = .matmul, .idx = oi, .n = n, .deg = 2, .u = 0 });
            },
            else => {},
        }
    }
    if (!gkr) for (keys.items, 0..) |k, i| try checks.append(a, .{ .kind = .key, .idx = @intCast(i), .n = k.log_size, .deg = 3, .u = 0 });
    for (checks.items) |*c| {
        c.u = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(uLog(c.n, c.deg)));
        const need: u32 = switch (c.kind) {
            .matmul => st.witness[st.ops[c.idx].matmul.y].logSize(),
            else => c.n,
        };
        rho_len = @max(rho_len, need);
    }
    var grels: std.ArrayList(GRel) = .empty;
    if (gkr) for (rels.items, 0..) |rel, ri| {
        var ks: std.ArrayList(u32) = .empty;
        var sizes: std.ArrayList(TensorInfo) = .empty;
        for (keys.items, 0..) |k, ki| if (k.rel == ri) {
            try ks.append(a, @intCast(ki));
            try sizes.append(a, TensorInfo.vec(k.log_size));
        };
        try sizes.append(a, TensorInfo.vec(rel.log_size));
        try sizes.append(a, TensorInfo.vec(0));
        const lay = try proto.layout(a, sizes.items, &.{});
        const seg_log = try a.alloc(u32, sizes.items.len);
        for (sizes.items, 0..) |x, i| seg_log[i] = x.logSize();
        const blinder: u32 = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(0));
        const n = @max(lay.log_total, 1);
        const layers = try a.alloc(GLayer, n);
        for (layers, 0..) |*l, k0| {
            l.u = @intCast(inf1.items.len);
            try inf1.append(a, TensorInfo.vec(uLog(@intCast(k0), 3)));
            for (&l.pads) |*pd| {
                pd.* = @intCast(inf1.items.len);
                try inf1.append(a, TensorInfo.vec(PAD_LOG));
            }
        }
        try grels.append(a, .{ .rel = @intCast(ri), .n = n, .keys = try ks.toOwnedSlice(a), .seg_off = lay.offsets, .seg_log = seg_log, .blinder = blinder, .layers = layers });
    };
    const has2 = !gkr and keys.items.len > 0;
    // column split from table 1 without the C-dependent tensors
    const est = try proto.layout(a, inf1.items, &.{});
    var lc: u32 = (est.log_total + 3) / 2;
    if (lc > cfg.witness_log_cols_max) lc = cfg.witness_log_cols_max;
    const slots = zkp.slotsFor(cfg.pcs.n_queries);
    lc = @max(lc, log2Ceil(slots));
    var ub_log: u32 = 6;
    const base1 = inf1.items.len;
    const base2 = inf2.items.len;
    while (true) {
        lc = @max(lc, ub_log);
        inf1.shrinkRetainingCapacity(base1);
        inf2.shrinkRetainingCapacity(base2);
        const batch_u: u32 = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(ub_log));
        const rb1: u32 = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(lc));
        const masks: u32 = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(lc + N_MASK_ROWS));
        var rb2: u32 = NONE;
        if (has2) {
            rb2 = @intCast(inf2.items.len);
            try inf2.append(a, TensorInfo.vec(lc));
        }
        const l1 = try proto.layout(a, inf1.items, &.{});
        var l2: Lay = .{ .offsets = &.{}, .log_total = 0, .used = 0 };
        if (has2) {
            const t = try proto.layout(a, inf2.items, &.{});
            l2 = .{ .offsets = t.offsets, .log_total = t.log_total, .used = t.used };
        }
        const N = @max(l1.log_total, l2.log_total);
        const need = uLog(N, 2);
        if (need > ub_log) {
            ub_log = need;
            continue;
        }
        return .{
            .nw = nw,
            .rem = rem,
            .rels = try rels.toOwnedSlice(a),
            .keys = try keys.toOwnedSlice(a),
            .checks = try checks.toOwnedSlice(a),
            .grels = grels.items,
            .batch_u = batch_u,
            .batch_n = N,
            .infos = .{ try inf1.toOwnedSlice(a), try inf2.toOwnedSlice(a) },
            .pad = .{ pad1, pad2 },
            .rb = .{ rb1, rb2 },
            .masks = masks,
            .lay = .{ .{ .offsets = l1.offsets, .log_total = l1.log_total, .used = l1.used }, l2 },
            .has2 = has2,
            .lc = lc,
            .slots = slots,
            .rho_len = rho_len,
        };
    }
}

// ---------------------------------------------------------------------------
// Linear claims on the committed tables.

const Sparse = struct { idx: u32, v: QM31 };
const Form = union(enum) { eq: []const QM31, ones, dense: []const QM31, sparse: []const Sparse };
const LTerm = struct { table: u8, id: u32, coeff: QM31, form: Form };
const LClaim = struct { terms: []const LTerm, value: QM31 };

/// Weight-table hat claim: c_data * W_w(local) + c_pad * R_W(s, colpoint).
const WClaim = struct { w: u32, local: []const QM31, c_data: QM31, s: [2]QM31, c_pad: QM31, value: QM31 };

const Part = struct { table: u8, id: u32, coeff: QM31, prefix: []const QM31 = &.{}, suffix: []const QM31 = &.{}, weight: bool = false };
const FSpec = struct {
    public: bool = false,
    pub_point: []const QM31 = &.{},
    konst: QM31 = QM31.zero(),
    parts: []const Part = &.{},
    /// number of trailing sumcheck coordinates used by this factor (top-zero-extension below)
    m: u32,
};

fn zeroExtScale(r: []const QM31, m: u32) QM31 {
    var s = QM31.one();
    for (r[0 .. r.len - m]) |x| s = s.mul(QM31.one().sub(x));
    return s;
}

fn localPoint(a: std.mem.Allocator, p: Part, r: []const QM31, m: u32) ![]QM31 {
    const out = try a.alloc(QM31, p.prefix.len + m + p.suffix.len);
    @memcpy(out[0..p.prefix.len], p.prefix);
    @memcpy(out[p.prefix.len..][0..m], r[r.len - m ..]);
    @memcpy(out[p.prefix.len + m ..], p.suffix);
    return out;
}

fn sparseOfForm(a: std.mem.Allocator, form: []const QM31) ![]Sparse {
    const out = try a.alloc(Sparse, form.len * 4);
    for (form, 0..) |v, e| for (0..4) |k| {
        out[e * 4 + k] = .{ .idx = @intCast(e * 4 + k), .v = v.mul(zkp.basis(k)) };
    };
    return out;
}

/// Claims produced by one masked sumcheck (identical on both sides).
fn checkClaims(
    a: std.mem.Allocator,
    plan: Plan,
    specs: []const FSpec,
    u_id: u32,
    n: u32,
    deg: u32,
    point: []const QM31,
    proof: zks.MaskedProof,
    claims: *std.ArrayList(LClaim),
    wclaims: *std.ArrayList(WClaim),
    wkey: ?WeightKey,
) !void {
    const ne = zks.Hp.entries(n, deg);
    const fs = try a.alloc(QM31, ne);
    zks.Hp.sumForm(n, deg, fs);
    const fe = try a.alloc(QM31, ne);
    zks.Hp.evalForm(n, deg, point, fe);
    const t_sig = try a.alloc(LTerm, 1);
    t_sig[0] = .{ .table = 0, .id = u_id, .coeff = QM31.one(), .form = .{ .sparse = try sparseOfForm(a, fs) } };
    try claims.append(a, .{ .terms = t_sig, .value = proof.sigma });
    const t_u = try a.alloc(LTerm, 1);
    t_u[0] = .{ .table = 0, .id = u_id, .coeff = QM31.one(), .form = .{ .sparse = try sparseOfForm(a, fe) } };
    try claims.append(a, .{ .terms = t_u, .value = proof.u_val });
    const r = point[0..n];
    const g = point[n];
    const one_m_g = QM31.one().sub(g);
    var hi: usize = 0;
    for (specs) |sp| {
        if (sp.public) continue;
        const hat = proof.hats[hi];
        hi += 1;
        const scale = zeroExtScale(r, sp.m);
        if (sp.m < n and !sp.konst.isZero()) return error.StatementShape;
        if (sp.parts.len == 1 and sp.parts[0].weight) {
            const p = sp.parts[0];
            const wk = wkey orelse return error.StatementShape;
            _ = wk;
            try wclaims.append(a, .{
                .w = p.id,
                .local = try localPoint(a, p, r, sp.m),
                .c_data = p.coeff.mul(one_m_g).mul(scale),
                .s = .{ r[n - 2], r[n - 1] },
                .c_pad = p.coeff.mul(g),
                .value = hat.sub(sp.konst),
            });
            continue;
        }
        const terms = try a.alloc(LTerm, 2 * sp.parts.len);
        for (sp.parts, 0..) |p, pi| {
            std.debug.assert(!p.weight);
            const loc = try localPoint(a, p, r, sp.m);
            const pid = plan.pad[p.table][p.id];
            const plog = plan.ls(p.table, pid);
            terms[2 * pi] = .{ .table = p.table, .id = p.id, .coeff = p.coeff.mul(one_m_g).mul(scale), .form = .{ .eq = loc } };
            terms[2 * pi + 1] = .{ .table = p.table, .id = pid, .coeff = p.coeff.mul(g), .form = .{ .eq = loc[loc.len - plog ..] } };
        }
        try claims.append(a, .{ .terms = terms, .value = hat.sub(sp.konst) });
    }
}

fn keyFactorD(a: std.mem.Allocator, plan: Plan, st: Statement, k: Key, alpha: QM31, beta: QM31, n: u32) !FSpec {
    const op = st.ops[k.op];
    var parts: []Part = undefined;
    var konst = alpha;
    switch (k.kind) {
        .remainder => {
            parts = try a.alloc(Part, 1);
            parts[0] = .{ .table = 0, .id = plan.rem[k.op], .coeff = qi(-1) };
        },
        .y_range => {
            parts = try a.alloc(Part, 1);
            parts[0] = .{ .table = 0, .id = opY(op), .coeff = qi(-1) };
            konst = alpha.sub(qi(128));
        },
        .plain_range => {
            parts = try a.alloc(Part, 1);
            parts[0] = .{ .table = 0, .id = op.range8.in, .coeff = qi(-1) };
            konst = alpha.sub(qi(128));
        },
        .lookup_pair => {
            parts = try a.alloc(Part, 2);
            parts[0] = .{ .table = 0, .id = op.lookup.in, .coeff = qi(-1) };
            parts[1] = .{ .table = 0, .id = op.lookup.out, .coeff = beta.neg() };
        },
    }
    return .{ .konst = konst, .parts = parts, .m = n };
}

/// Factor specs of a check (prover and verifier).
fn checkSpecs(a: std.mem.Allocator, plan: Plan, st: Statement, wkey: ?WeightKey, c: Check, rho: []const QM31, alpha: QM31, beta: QM31) ![]FSpec {
    const n = c.n;
    switch (c.kind) {
        .product => {
            const p = st.ops[c.idx].product;
            const sp = try a.alloc(FSpec, 4);
            const pt = rho[rho.len - n ..];
            sp[0] = .{ .public = true, .pub_point = pt, .m = n };
            sp[1] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = p.a, .coeff = QM31.one() }}), .m = n };
            sp[2] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = p.b, .coeff = QM31.one() }}), .m = n };
            sp[3] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = p.c, .coeff = qi(-1) }}), .m = n };
            return sp;
        },
        .hadamard => {
            const h = st.ops[c.idx].hadamard;
            const sp = try a.alloc(FSpec, 5);
            const pt = rho[rho.len - n ..];
            sp[0] = .{ .public = true, .pub_point = pt, .m = n };
            sp[1] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = h.a, .coeff = QM31.one() }}), .m = n };
            sp[2] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = h.b, .coeff = QM31.one() }}), .m = n };
            sp[3] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = h.y, .coeff = qi(-(@as(i64, 1) << h.shift)) }}), .m = n };
            sp[4] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = plan.rem[c.idx], .coeff = qi(-1) }}), .m = n };
            return sp;
        },
        .matmul => {
            const m = st.ops[c.idx].matmul;
            const wk = wkey.?;
            const xi = st.witness[m.x];
            const lt = xi.log_dims[0];
            const lk = xi.log_dims[1];
            const ln = wk.infos[m.w].log_dims[1];
            const pt = rho[rho.len - (lt + ln) ..];
            const sp = try a.alloc(FSpec, 5);
            sp[0] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = m.x, .coeff = QM31.one(), .prefix = pt[0..lt] }}), .m = lk };
            sp[1] = .{ .parts = try a.dupe(Part, &.{.{ .table = 2, .id = m.w, .coeff = QM31.one(), .suffix = pt[lt..], .weight = true }}), .m = lk };
            sp[2] = .{ .public = true, .pub_point = pt, .m = lt + ln };
            sp[3] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = m.y, .coeff = qi(-(@as(i64, 1) << m.shift)) }}), .m = lt + ln };
            sp[4] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = plan.rem[c.idx], .coeff = qi(-1) }}), .m = lt + ln };
            return sp;
        },
        .key => {
            const k = plan.keys[c.idx];
            const sp = try a.alloc(FSpec, 3);
            const pt = rho[rho.len - n ..];
            sp[0] = .{ .public = true, .pub_point = pt, .m = n };
            const hp = try a.alloc(Part, 4);
            for (0..4) |q| hp[q] = .{ .table = 1, .id = k.h + @as(u32, @intCast(q)), .coeff = zkp.basis(q) };
            sp[1] = .{ .parts = hp, .m = n };
            sp[2] = try keyFactorD(a, plan, st, k, alpha, beta, n);
            return sp;
        },
    }
}

fn checkClaim(st: Statement, c: Check) QM31 {
    return switch (c.kind) {
        .product => QM31.zero(),
        .hadamard, .matmul => qi(-shiftHalf(opShift(st.ops[c.idx]))),
        .key => QM31.one(),
    };
}

const T_PRODUCT = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 3 } } };
const T_HAD = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 3 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 4 } } };
const T_MM = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 3 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 4 } } };
const T_KEY = [_]zks.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_B2 = [_]zks.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_B4 = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 3 } } };

fn evalCheckTerms(kind: CheckKind, vals: []const QM31) QM31 {
    return switch (kind) {
        .product => zks.evalTermsRt(&T_PRODUCT, 4, vals[0..4].*),
        .hadamard => zks.evalTermsRt(&T_HAD, 5, vals[0..5].*),
        .matmul => zks.evalTermsRt(&T_MM, 5, vals[0..5].*),
        .key => zks.evalTermsRt(&T_KEY, 3, vals[0..3].*),
    };
}

fn nSpecs(kind: CheckKind) usize {
    return switch (kind) {
        .product => 4,
        .hadamard, .matmul => 5,
        .key => 3,
    };
}

// ---------------------------------------------------------------------------
// Hiding weight store.

pub const WeightKey = struct {
    root: Hash,
    infos: []const TensorInfo,
    offsets: []const usize,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
    slots: u32,

    fn shape(self: WeightKey, log_blowup: u32) zkp.Shape {
        return .{ .log_cols = self.log_cols, .log_blowup = log_blowup, .slots = self.slots, .n_rows = self.rows_used + 2 * WPAD_ROWS };
    }
};

pub const ZkWeights = struct {
    infos: []const TensorInfo,
    offsets: []usize,
    table: []i8,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
    /// extra M31 rows: 0..3 pad R_W, 4..7 proximity masks
    extra: []M31,
    com: zkp.Commitment,

    pub fn deinit(self: *ZkWeights, a: std.mem.Allocator) void {
        a.free(self.offsets);
        a.free(self.table);
        a.free(self.extra);
        self.com.deinit(a);
    }
    pub fn matrix(self: *const ZkWeights, id: usize) pcs.Matrix(i8) {
        const info = self.infos[id];
        return .{ .data = self.table[self.offsets[id]..][0..info.size()], .log_rows = info.log_dims[0], .log_cols = info.log_dims[1] };
    }
    pub fn tableMatrix(self: *const ZkWeights) pcs.Matrix(i8) {
        return .{ .data = self.table, .log_rows = self.log_rows, .log_cols = self.log_cols, .rows_used = self.rows_used };
    }
    pub fn key(self: *const ZkWeights) WeightKey {
        return .{ .root = self.com.root(), .infos = self.infos, .offsets = self.offsets, .log_rows = self.log_rows, .log_cols = self.log_cols, .rows_used = self.rows_used, .slots = self.com.shape.slots };
    }
    /// View usable by model builders (forward pass only; has no commitment).
    pub fn plainView(self: *const ZkWeights) proto.WeightStore {
        return .{ .infos = self.infos, .offsets = self.offsets, .table = self.table, .log_rows = self.log_rows, .log_cols = self.log_cols, .rows_used = self.rows_used, .com = undefined };
    }
    /// Columns still openable; re-randomize (rerandomizeWeights) while this is >= one opening.
    pub fn budgetLeft(self: *const ZkWeights) usize {
        const b = self.com.budget.?;
        return b.limit - b.count;
    }
    /// Distinct weight columns opened so far / budget.
    pub fn budgetUsed(self: *const ZkWeights) [2]usize {
        const b = self.com.budget.?;
        return .{ b.count, b.limit };
    }
};

pub fn commitWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, infos: []const TensorInfo, data: []const []const i8) !ZkWeights {
    const lay = try proto.layout(a, infos, &.{});
    errdefer a.free(lay.offsets);
    const total = @as(usize, 1) << @intCast(lay.log_total);
    const table = try a.alloc(i8, total);
    errdefer a.free(table);
    @memset(table, 0);
    for (infos, 0..) |t, i| @memcpy(table[lay.offsets[i]..][0..t.size()], data[i]);
    var lc = cfg.weight_log_cols;
    if (lc > lay.log_total) lc = lay.log_total;
    const lr = lay.log_total - lc;
    const C = @as(usize, 1) << @intCast(lc);
    const slots = cfg.weight_mask_slots;
    if (slots < zkp.slotsFor(wpcs(cfg).n_queries) or !std.math.isPowerOfTwo(slots)) return error.WeightMaskSlots;
    if (C + slots > (C << @intCast(wpcs(cfg).log_blowup)) / 2) return error.WeightMaskSlots;
    var tw = try pcs.Twiddles.init(a, lc + wpcs(cfg).log_blowup);
    defer tw.deinit(a);
    const ru = (lay.used + C - 1) >> @intCast(lc);
    var rng = zkp.Rng.initOs();
    const extra = try a.alloc(M31, 2 * WPAD_ROWS * C);
    errdefer a.free(extra);
    rng.fillM31(extra);
    const m = pcs.Matrix(i8){ .data = table, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    var com = try zkp.commit(i8, a, pool, &tw, &rng, m, extra, slots, wpcs(cfg).log_blowup);
    try com.enableBudget(a);
    return .{ .infos = infos, .offsets = lay.offsets, .table = table, .log_rows = lr, .log_cols = lc, .rows_used = ru, .extra = extra, .com = com };
}

/// Proximity of the hiding weight table, once per commitment (consumes n_queries of the budget).
pub fn proveWeightProximity(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, zw: *const ZkWeights) !zkp.Opening {
    var tr = Transcript.initDomain("stwo-tensor-zk-weights-v1");
    tr.mixDigest(zw.com.root());
    const shapes = [_]zkp.Shape{zw.com.shape};
    const pm = zkp.MaskRef{ .table = 0, .row = zw.rows_used + WPAD_ROWS };
    var co = try zkp.drawCoeffs(a, &tr, &shapes, &.{}, &.{}, pm);
    defer co.deinit(a);
    const cv = [_][]const QM31{co.v[0][0]};
    const rows = try zkp.combine(i8, a, pool, &zw.com, zw.tableMatrix(), zw.extra, &cv);
    const coms = [_]*const zkp.Commitment{&zw.com};
    return zkp.finish(a, &tr, wpcs(cfg), &coms, try a.alloc(QM31, 0), rows);
}

pub fn verifyWeightProximity(a: std.mem.Allocator, cfg: proto.Config, key: WeightKey, proof: zkp.Opening) !void {
    var tr = Transcript.initDomain("stwo-tensor-zk-weights-v1");
    tr.mixDigest(key.root);
    var tw = try pcs.Twiddles.init(a, key.log_cols + wpcs(cfg).log_blowup);
    defer tw.deinit(a);
    const shapes = [_]zkp.Shape{key.shape(wpcs(cfg).log_blowup)};
    const roots = [_]Hash{key.root};
    try zkp.verifyOpening(a, &tr, wpcs(cfg), &tw, &shapes, &roots, &.{}, .{ .table = 0, .row = key.rows_used + WPAD_ROWS }, proof);
}

// ---------------------------------------------------------------------------
// Weight re-randomization with a link proof.
//
// A hiding weight commitment can only open `slots/2` distinct columns. To keep
// serving proofs, the prover commits the same weights again with fresh
// randomness (new tau, pads, masks) and links the two commitments: a 2-table
// hiding opening (old, new, plus a fresh 4-row mask table) of the single claim
//   W_old~(z) - W_new~(z) = 0        at a random point z (rows: data rows only)
// Soundness: both tables are close to the code (commit-time proximity of each,
// verified separately), so the claim binds the decoded tables, and a non-zero
// difference has a non-zero MLE at a random z except with prob. (lr+lc)/|F|.
// ZK: the claim value is the public 0; the opening is simulatable (Lemma 2) and
// charges t_w columns of both budgets.

pub const WeightLink = struct {
    mask_root: Hash,
    opening: zkp.Opening,

    pub fn deinit(self: *WeightLink, a: std.mem.Allocator) void {
        self.opening.deinit(a);
    }
    pub fn byteSize(self: WeightLink) usize {
        return 32 + self.opening.byteSize();
    }
};

fn linkGroup(a: std.mem.Allocator, tr: *Transcript, old: WeightKey, new: WeightKey) ![]zkp.Group {
    if (old.log_rows != new.log_rows or old.log_cols != new.log_cols or old.rows_used != new.rows_used or old.slots != new.slots or old.infos.len != new.infos.len) return error.WeightLinkShape;
    for (old.infos, new.infos, old.offsets, new.offsets) |x, y, ox, oy| if (!std.meta.eql(x, y) or ox != oy) return error.WeightLinkShape;
    const z = try a.alloc(QM31, old.log_rows + old.log_cols);
    tr.drawN(z);
    const eqr = try f.eqTable(a, z[0..old.log_rows], QM31.one());
    const nr = old.rows_used + 2 * WPAD_ROWS;
    const ro = try a.alloc(QM31, nr);
    const rn = try a.alloc(QM31, nr);
    @memset(ro, QM31.zero());
    @memset(rn, QM31.zero());
    for (0..old.rows_used) |i| {
        ro[i] = eqr[i];
        rn[i] = eqr[i].neg();
    }
    const rows = try a.alloc([]const QM31, 3);
    rows[0] = ro;
    rows[1] = rn;
    rows[2] = &.{};
    const claims = try a.alloc(zkp.Claim, 1);
    claims[0] = .{ .rows = rows, .value = QM31.zero() };
    const groups = try a.alloc(zkp.Group, 1);
    groups[0] = .{ .col = try f.eqTable(a, z[old.log_rows..], QM31.one()), .claims = claims, .mask = .{ .table = 2, .row = 0 } };
    return groups;
}

fn linkTranscript(old: WeightKey, new: WeightKey, mask_root: Hash) Transcript {
    var tr = Transcript.initDomain("stwo-tensor-zk-weight-link-v1");
    tr.mixDigest(old.root);
    tr.mixDigest(new.root);
    tr.mixDigest(mask_root);
    return tr;
}

/// Commit the same weights again with fresh randomness and link the two commitments.
/// The new commitment still needs its own `proveWeightProximity`.
pub fn rerandomizeWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, old: *const ZkWeights) !struct { new: ZkWeights, link: WeightLink } {
    const data = try a.alloc([]const i8, old.infos.len);
    defer a.free(data);
    for (0..old.infos.len) |i| data[i] = old.matrix(i).data;
    var new = try commitWeights(a, pool, cfg, old.infos, data);
    errdefer new.deinit(a);
    var link = try proveWeightLink(a, pool, cfg, old, &new);
    _ = &link;
    return .{ .new = new, .link = link };
}

pub fn proveWeightLink(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, old: *const ZkWeights, new: *const ZkWeights) !WeightLink {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const wp = wpcs(cfg);
    var rng = zkp.Rng.initOs();
    var tw = try pcs.Twiddles.init(a, old.log_cols + wp.log_blowup);
    defer tw.deinit(a);
    const mdata = try randVec(ar, &rng, @as(usize, 4) << @intCast(old.log_cols));
    const mm = pcs.Matrix(i32){ .data = mdata, .log_rows = 2, .log_cols = old.log_cols };
    var mcom = try zkp.commit(i32, a, pool, &tw, &rng, mm, &.{}, old.com.shape.slots, wp.log_blowup);
    defer mcom.deinit(a);
    var tr = linkTranscript(old.key(), new.key(), mcom.root());
    const groups = try linkGroup(ar, &tr, old.key(), new.key());
    const mus = try a.alloc(QM31, 1);
    mus[0] = zkp.maskValue(i32, mm, 0, groups[0].col);
    const shapes = [_]zkp.Shape{ old.com.shape, new.com.shape, mcom.shape };
    var co = try zkp.drawCoeffs(a, &tr, &shapes, groups, mus, null);
    defer co.deinit(a);
    const c0 = [_][]const QM31{co.v[0][0]};
    const c1 = [_][]const QM31{co.v[0][1]};
    const c2 = [_][]const QM31{co.v[0][2]};
    const r0 = try zkp.combine(i8, a, pool, &old.com, old.tableMatrix(), old.extra, &c0);
    const r1 = try zkp.combine(i8, a, pool, &new.com, new.tableMatrix(), new.extra, &c1);
    const r2 = try zkp.combine(i32, a, pool, &mcom, mm, &.{}, &c2);
    for (r0[0], r1[0], r2[0]) |*x, y, w| x.* = x.*.add(y).add(w);
    a.free(r1[0]);
    a.free(r1);
    a.free(r2[0]);
    a.free(r2);
    const coms = [_]*const zkp.Commitment{ &old.com, &new.com, &mcom };
    const opening = try zkp.finish(a, &tr, wp, &coms, mus, r0);
    return .{ .mask_root = mcom.root(), .opening = opening };
}

pub fn verifyWeightLink(a: std.mem.Allocator, cfg: proto.Config, old: WeightKey, new: WeightKey, link: WeightLink) !void {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const wp = wpcs(cfg);
    var tr = linkTranscript(old, new, link.mask_root);
    const groups = try linkGroup(ar, &tr, old, new);
    var tw = try pcs.Twiddles.init(a, old.log_cols + wp.log_blowup);
    defer tw.deinit(a);
    const mshape = zkp.Shape{ .log_cols = old.log_cols, .log_blowup = wp.log_blowup, .slots = old.slots, .n_rows = 4 };
    const shapes = [_]zkp.Shape{ old.shape(wp.log_blowup), new.shape(wp.log_blowup), mshape };
    const roots = [_]Hash{ old.root, new.root, link.mask_root };
    try zkp.verifyOpening(ar, &tr, wp, &tw, &shapes, &roots, groups, null, link.opening);
}

// ---------------------------------------------------------------------------
// Proof.

pub const Proof = struct {
    root1: Hash,
    root2: ?Hash,
    wmask_root: ?Hash,
    checks: []zks.MaskedProof,
    batch: zks.MaskedProof,
    opening: zkp.Opening,
    weight_opening: ?zkp.Opening,
    /// hiding GKR: root denominators (numerators are 0) and layer sumchecks, relation-major
    gkr_roots: []QM31 = &.{},
    gkr_layers: []zks.MaskedProof = &.{},

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        for (self.gkr_layers) |*c| c.deinit(a);
        a.free(self.gkr_layers);
        a.free(self.gkr_roots);
        for (self.checks) |*c| c.deinit(a);
        a.free(self.checks);
        self.batch.deinit(a);
        self.opening.deinit(a);
        if (self.weight_opening) |*w| w.deinit(a);
    }

    pub const Sizes = struct { sumchecks: usize, logup: usize, witness_opening: usize, weight_opening: usize, total: usize };

    pub fn sizes(self: Proof) Sizes {
        var s: usize = self.batch.byteSize();
        for (self.checks) |c| s += c.byteSize();
        var lg: usize = self.gkr_roots.len * 16;
        for (self.gkr_layers) |c| lg += c.byteSize();
        s += lg;
        const wo = self.opening.byteSize();
        const wto = if (self.weight_opening) |w| w.byteSize() else 0;
        const roots: usize = 32 * (1 + @as(usize, @intFromBool(self.root2 != null)) + @intFromBool(self.wmask_root != null));
        return .{ .sumchecks = s, .logup = lg, .witness_opening = wo, .weight_opening = wto, .total = roots + s + wo + wto };
    }
};

fn mixStatement(tr: *Transcript, st: Statement, weight_root: Hash, cfg: proto.Config) void {
    tr.mixDigest(weight_root);
    tr.mixU64(cfg.pcs.n_queries);
    tr.mixU64(cfg.pcs.log_blowup);
    tr.mixU64(wpcs(cfg).n_queries);
    tr.mixU64(wpcs(cfg).log_blowup);
    tr.mixU64(st.witness.len);
    for (st.witness) |t| {
        tr.mixU64(t.n_dims);
        for (t.log_dims) |d| tr.mixU64(d);
    }
    tr.mixU64(st.weights.len);
    for (st.weights) |t| for (t.log_dims) |d| tr.mixU64(d);
    for (st.tables) |t| {
        var w: [64]u32 = undefined;
        for (0..64) |i| {
            var x: u32 = 0;
            for (0..4) |b| x |= @as(u32, @as(u8, @bitCast(t.values[i * 4 + b]))) << @intCast(8 * b);
            w[i] = x;
        }
        tr.mixU32s(&w);
    }
    for (st.ops) |op| switch (op) {
        .matmul => |m| tr.mixU32s(&.{ 1, m.x, m.w, m.y, m.shift }),
        .hadamard => |h| tr.mixU32s(&.{ 2, h.a, h.b, h.y, h.shift }),
        .lookup => |l| tr.mixU32s(&.{ 3, l.in, l.out, l.table }),
        .range8 => |r| tr.mixU32s(&.{ 4, r.in }),
        .product => |q| tr.mixU32s(&.{ 5, q.a, q.b, q.c }),
    };
}

fn relKey(st: Statement, kind: RelKind, t: usize, beta: QM31) QM31 {
    return switch (kind) {
        .range => qi(@intCast(t)),
        .act => |ti| qi(@as(i64, @intCast(t)) - 128).add(beta.mul(qi(st.tables[ti].values[t]))),
    };
}

/// Parallel batch inversion (Montgomery's trick per chunk).
fn batchInversePar(a: std.mem.Allocator, pool: *f.Pool, v: []QM31) !void {
    const Ctx = struct { v: []QM31, a: std.mem.Allocator, failed: *std.atomic.Value(bool) };
    var failed = std.atomic.Value(bool).init(false);
    const ctx = Ctx{ .v = v, .a = a, .failed = &failed };
    pool.parallelFor(v.len, 1 << 14, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            batchInverse(std.heap.page_allocator, c.v[s..e]) catch c.failed.store(true, .monotonic);
        }
    }.run);
    if (failed.load(.monotonic)) return error.ZeroDenominator;
}

fn batchInverse(a: std.mem.Allocator, v: []QM31) !void {
    const pre = try a.alloc(QM31, v.len);
    defer a.free(pre);
    var acc = QM31.one();
    for (v, 0..) |x, i| {
        pre[i] = acc;
        acc = acc.mul(x);
    }
    var inv = acc.inv() catch return error.ZeroDenominator;
    var i: usize = v.len;
    while (i > 0) {
        i -= 1;
        const x = v[i];
        v[i] = inv.mul(pre[i]);
        inv = inv.mul(x);
    }
}

/// Dense LogUp table-side coefficients 1/(alpha - key_t).
fn relInverses(a: std.mem.Allocator, st: Statement, rel: Rel, alpha: QM31, beta: QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(rel.log_size);
    const v = try a.alloc(QM31, n);
    for (v, 0..) |*x, t| x.* = alpha.sub(relKey(st, rel.kind, t, beta));
    try batchInverse(a, v);
    return v;
}

fn logupClaims(a: std.mem.Allocator, plan: Plan, st: Statement, alpha: QM31, beta: QM31, claims: *std.ArrayList(LClaim)) !void {
    for (plan.rels, 0..) |rel, ri| {
        var terms: std.ArrayList(LTerm) = .empty;
        for (plan.keys) |k| {
            if (k.rel != ri) continue;
            for (0..4) |q| try terms.append(a, .{ .table = 1, .id = k.h + @as(u32, @intCast(q)), .coeff = zkp.basis(q), .form = .ones });
        }
        try terms.append(a, .{ .table = 0, .id = rel.mult, .coeff = qi(-1), .form = .{ .dense = try relInverses(a, st, rel, alpha, beta) } });
        try claims.append(a, .{ .terms = try terms.toOwnedSlice(a), .value = QM31.zero() });
    }
}

fn bitsPoint(out: []QM31, v: usize) void {
    const n = out.len;
    for (0..n) |k| out[k] = if ((v >> @intCast(n - 1 - k)) & 1 == 1) QM31.one() else QM31.zero();
}

/// Value at table point r (len log_total of the table) of a term's form, block factor included.
fn termAt(a: std.mem.Allocator, plan: Plan, t: LTerm, r: []const QM31) !QM31 {
    const n = plan.ls(t.table, t.id);
    const offv = plan.off(t.table, t.id);
    const nb = r.len - n;
    const bp = try a.alloc(QM31, nb);
    defer a.free(bp);
    bitsPoint(bp, offv >> @intCast(n));
    const blk = f.eqEval(r[0..nb], bp);
    const loc = r[nb..];
    const v: QM31 = switch (t.form) {
        .eq => |p| f.eqEval(p, loc),
        .ones => QM31.one(),
        .dense => |d| blk2: {
            const eq = try f.eqTable(a, loc, QM31.one());
            defer a.free(eq);
            var acc = QM31.zero();
            for (d, eq) |x, e| acc = acc.add(x.mul(e));
            break :blk2 acc;
        },
        .sparse => |sp| blk2: {
            var acc = QM31.zero();
            const bits = try a.alloc(QM31, n);
            defer a.free(bits);
            for (sp) |s| {
                bitsPoint(bits, s.idx);
                acc = acc.add(s.v.mul(f.eqEval(loc, bits)));
            }
            break :blk2 acc;
        },
    };
    return blk.mul(v).mul(t.coeff);
}

/// Prover: add gamma * term into the dense E vector of the term's table.
fn addTerm(a: std.mem.Allocator, pool: *f.Pool, plan: Plan, E: []QM31, t: LTerm, gamma: QM31) !void {
    const n = plan.ls(t.table, t.id);
    const o = plan.off(t.table, t.id);
    const dst = E[o..][0 .. @as(usize, 1) << @intCast(n)];
    const c = gamma.mul(t.coeff);
    switch (t.form) {
        .eq => |p| {
            const eq = try f.eqTablePar(a, pool, p, c);
            defer a.free(eq);
            for (dst, eq) |*x, y| x.* = x.*.add(y);
        },
        .ones => for (dst) |*x| {
            x.* = x.*.add(c);
        },
        .dense => |d| for (dst, d) |*x, y| {
            x.* = x.*.add(c.mul(y));
        },
        .sparse => |sp| for (sp) |s| {
            dst[s.idx] = dst[s.idx].add(c.mul(s.v));
        },
    }
}

// ---------------------------------------------------------------------------
// Prover.

fn randVec(a: std.mem.Allocator, rng: *zkp.Rng, n: usize) ![]i32 {
    const v = try a.alloc(i32, n);
    for (v) |*x| x.* = @intCast(rng.m31().v);
    return v;
}

fn toQ(a: std.mem.Allocator, pool: *f.Pool, v: []const i32, len: usize, coeff: QM31) ![]QM31 {
    const out = try a.alloc(QM31, len);
    @memset(out[v.len..], QM31.zero());
    const Ctx = struct { v: []const i32, out: []QM31, c: QM31 };
    const ctx = Ctx{ .v = v, .out = out, .c = coeff };
    pool.parallelFor(v.len, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            if (c.c.eql(QM31.one())) {
                for (s..e) |i| c.out[i] = QM31.fromBase(f.fromI32(c.v[i]));
            } else {
                for (s..e) |i| c.out[i] = c.c.mulM31(f.fromI32(c.v[i]));
            }
        }
    }.run);
    return out;
}

fn zeroExt(a: std.mem.Allocator, v: []QM31, len: usize) ![]QM31 {
    if (v.len == len) return v;
    const out = try a.alloc(QM31, len);
    @memcpy(out[0..v.len], v);
    @memset(out[v.len..], QM31.zero());
    a.free(v);
    return out;
}

const ProverCtx = struct {
    a: std.mem.Allocator,
    plan: Plan,
    vecs: [2][]const []const i32,
    zw: ?*const ZkWeights,
    colpoint: []const QM31,

    fn padValue(self: *const ProverCtx, sp: FSpec, r: []const QM31) QM31 {
        var v = sp.konst;
        for (sp.parts) |p| {
            const loc = localPoint(self.a, p, r, sp.m) catch @panic("oom");
            defer self.a.free(loc);
            if (p.weight) {
                const zw = self.zw.?;
                const C = @as(usize, 1) << @intCast(zw.log_cols);
                const eqc = f.eqTable(self.a, self.colpoint, QM31.one()) catch @panic("oom");
                defer self.a.free(eqc);
                const eqs = f.eqTable(self.a, &.{ r[r.len - 2], r[r.len - 1] }, QM31.one()) catch @panic("oom");
                defer self.a.free(eqs);
                var acc = QM31.zero();
                for (0..WPAD_ROWS) |i| {
                    var row = QM31.zero();
                    for (0..C) |j| row = row.add(eqc[j].mulM31(zw.extra[i * C + j]));
                    acc = acc.add(eqs[i].mul(row));
                }
                v = v.add(p.coeff.mul(acc));
            } else {
                const pid = self.plan.pad[p.table][p.id];
                const plog = self.plan.ls(p.table, pid);
                const pv = f.mleEvalI32(self.a, self.vecs[p.table][pid], loc[loc.len - plog ..]) catch @panic("oom");
                v = v.add(p.coeff.mul(pv));
            }
        }
        return v;
    }
};

fn PadCtx(comptime NF: usize) type {
    return struct {
        pc: *const ProverCtx,
        specs: []const FSpec,
        pub fn pads(self: @This(), r: []const QM31, fin: [NF]QM31) [NF]QM31 {
            var out: [NF]QM31 = undefined;
            for (0..NF) |j| out[j] = if (self.specs[j].public) fin[j] else self.pc.padValue(self.specs[j], r);
            return out;
        }
    };
}

fn hpOf(plan: Plan, vecs: []const []const i32, u_id: u32, n: u32, deg: u32, buf: []QM31) zks.Hp {
    const cells = vecs[u_id];
    _ = plan;
    for (buf, 0..) |*x, e| x.* = f.fromLimbs(.{ @intCast(cells[4 * e]), @intCast(cells[4 * e + 1]), @intCast(cells[4 * e + 2]), @intCast(cells[4 * e + 3]) });
    return .{ .n = n, .d = deg, .c = buf };
}

fn runMasked(
    comptime NF: usize,
    comptime terms: []const zks.Term,
    a: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    claim: QM31,
    fac: [NF][]QM31,
    active: usize,
    specs: []const FSpec,
    hp: zks.Hp,
    pc: *const ProverCtx,
) !zks.ProveOut {
    var public: [NF]bool = undefined;
    for (0..NF) |j| public[j] = specs[j].public;
    return zks.prove(NF, terms, a, pool, tr, claim, fac, active, public, hp, PadCtx(NF){ .pc = pc, .specs = specs });
}

pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: proto.Config,
    st: Statement,
    zw: ?*const ZkWeights,
    witness: []const []const i32,
    timings: *proto.Timings,
) !Proof {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const wkey: ?WeightKey = if (zw) |w| w.key() else null;
    const plan = try makePlan(ar, st, wkey, cfg);
    var rng = zkp.Rng.initOs();

    // --- accumulators, remainders, multiplicities
    var t0 = try std.time.Instant.now();
    const acc = try ar.alloc(?[]i64, st.ops.len);
    for (st.ops, 0..) |op, i| {
        acc[i] = null;
        switch (op) {
            .matmul => |m| acc[i] = try proto.matmulAcc(ar, pool, st.witness[m.x], witness[m.x], zw.?.matrix(m.w)),
            .hadamard => |h| {
                const n = st.witness[h.y].size();
                const v = try ar.alloc(i64, n);
                for (v, witness[h.a], witness[h.b]) |*o, x, y| o.* = @as(i64, x) * y;
                acc[i] = v;
            },
            else => {},
        }
    }
    const vecs1 = try ar.alloc([]const i32, plan.infos[0].len);
    @memset(vecs1, &.{});
    for (0..plan.nw) |i| vecs1[i] = witness[i];
    for (st.ops, 0..) |op, i| {
        if (plan.rem[i] == NONE) continue;
        const s = opShift(op);
        const y = witness[opY(op)];
        const r = try ar.alloc(i32, y.len);
        for (r, acc[i].?, y) |*o, av, yv| {
            const rv = av + shiftHalf(s) - (@as(i64, yv) << s);
            if (rv < 0 or rv >= (@as(i64, 1) << s)) return error.RemainderOutOfRange;
            o.* = @intCast(rv);
        }
        vecs1[plan.rem[i]] = r;
    }
    for (plan.rels) |rel| {
        const m = try ar.alloc(i32, @as(usize, 1) << @intCast(rel.log_size));
        @memset(m, 0);
        vecs1[rel.mult] = m;
    }
    for (plan.keys) |k| {
        const mult: []i32 = @constCast(vecs1[plan.rels[k.rel].mult]);
        const op = st.ops[k.op];
        switch (k.kind) {
            .remainder => for (vecs1[plan.rem[k.op]]) |v| {
                mult[@intCast(v)] += 1;
            },
            .y_range, .plain_range => {
                const src = if (k.kind == .y_range) opY(op) else op.range8.in;
                for (witness[src]) |v| {
                    if (v < -128 or v > 127) return error.ValueOutOfRange;
                    mult[@intCast(v + 128)] += 1;
                }
            },
            .lookup_pair => {
                const l = op.lookup;
                for (witness[l.in], witness[l.out]) |v, o| {
                    if (v < -128 or v > 127) return error.ValueOutOfRange;
                    if (st.tables[l.table].values[@intCast(v + 128)] != o) return error.LookupMismatch;
                    mult[@intCast(v + 128)] += 1;
                }
            },
        }
    }
    for (st.ops) |op| if (op == .product) {
        const q = op.product;
        for (witness[q.a], witness[q.b], witness[q.c]) |x, y, z| {
            if (!f.fromI32(x).mul(f.fromI32(y)).eql(f.fromI32(z))) return error.ProductMismatch;
        }
    };
    // random tensors of table 1
    for (vecs1, 0..) |*v, i| {
        if (v.len == 0) v.* = try randVec(ar, &rng, plan.infos[0][i].size());
    }
    for (plan.grels) |g| {
        const b: []i32 = @constCast(vecs1[g.blinder]);
        while (b[0] == 0) b[0] = @intCast(rng.m31().v);
    }
    // --- table 1 commit
    const C = plan.nCols();
    const tw_log = plan.lc + cfg.pcs.log_blowup;
    var tw = try pcs.Twiddles.init(a, tw_log);
    defer tw.deinit(a);
    const tab1 = try buildTable(ar, plan, 0, vecs1);
    const m1 = pcs.Matrix(i32){ .data = tab1, .log_rows = plan.lay[0].log_total - plan.lc, .log_cols = plan.lc, .rows_used = plan.rowsUsed(0) };
    var com1 = try zkp.commit(i32, a, pool, &tw, &rng, m1, &.{}, plan.slots, cfg.pcs.log_blowup);
    defer com1.deinit(a);
    // per-proof weight mask table
    var wmask_com: ?zkp.Commitment = null;
    defer if (wmask_com) |*w| w.deinit(a);
    var wtw: ?pcs.Twiddles = null;
    defer if (wtw) |*w| w.deinit(a);
    var wmask_data: []i32 = &.{};
    var has_matmul = false;
    for (st.ops) |op| has_matmul = has_matmul or op == .matmul;
    if (has_matmul) {
        const w = zw.?;
        wtw = try pcs.Twiddles.init(a, w.log_cols + wpcs(cfg).log_blowup);
        wmask_data = try randVec(ar, &rng, @as(usize, 4) << @intCast(w.log_cols));
        const mm = pcs.Matrix(i32){ .data = wmask_data, .log_rows = 2, .log_cols = w.log_cols };
        wmask_com = try zkp.commit(i32, a, pool, &wtw.?, &rng, mm, &.{}, w.com.shape.slots, wpcs(cfg).log_blowup);
    }
    timings.witness_commit_ns = nowNs(t0);
    timings.witness_table_elems = plan.rowsUsed(0) * C;
    for (witness) |v| timings.witness_elems += v.len;

    var tr = Transcript.initDomain("stwo-tensor-zk-v1");
    mixStatement(&tr, st, if (wkey) |k| k.root else [_]u8{0} ** 32, cfg);
    tr.mixDigest(com1.root());
    if (wmask_com) |*w| tr.mixDigest(w.root());
    const alpha = tr.draw();
    const beta = tr.draw();

    // --- table 2: inverses
    t0 = try std.time.Instant.now();
    var com2: ?zkp.Commitment = null;
    defer if (com2) |*c| c.deinit(a);
    const vecs2 = try ar.alloc([]const i32, plan.infos[1].len);
    @memset(vecs2, &.{});
    const hvecs = try ar.alloc([]QM31, plan.keys.len);
    var tab2: []i32 = &.{};
    if (plan.has2) {
        for (plan.keys, 0..) |k, ki| {
            const n = @as(usize, 1) << @intCast(k.log_size);
            const h = try keyDenoms(ar, pool, plan, st, witness, vecs1, k, alpha, beta);
            try batchInversePar(ar, pool, h);
            hvecs[ki] = h;
            for (0..4) |q| {
                const limb = try ar.alloc(i32, n);
                for (limb, h) |*o, x| o.* = @intCast(f.limbs(x)[q]);
                vecs2[k.h + q] = limb;
            }
        }
        for (vecs2, 0..) |*v, i| {
            if (i < plan.keys.len * 4) continue;
            v.* = try randVec(ar, &rng, plan.infos[1][i].size());
        }
        tab2 = try buildTable(ar, plan, 1, vecs2);
        const m2 = pcs.Matrix(i32){ .data = tab2, .log_rows = plan.lay[1].log_total - plan.lc, .log_cols = plan.lc, .rows_used = plan.rowsUsed(1) };
        com2 = try zkp.commit(i32, a, pool, &tw, &rng, m2, &.{}, plan.slots, cfg.pcs.log_blowup);
        tr.mixDigest(com2.?.root());
    }
    timings.witness_commit_ns += nowNs(t0);

    const rho = try ar.alloc(QM31, plan.rho_len);
    tr.drawN(rho);
    const colpoint: []const QM31 = if (wkey) |k| rho[rho.len - k.log_cols ..] else &.{};
    const pc = ProverCtx{ .a = ar, .plan = plan, .vecs = .{ vecs1, vecs2 }, .zw = zw, .colpoint = colpoint };

    var claims: std.ArrayList(LClaim) = .empty;
    var wclaims: std.ArrayList(WClaim) = .empty;
    const check_proofs = try a.alloc(zks.MaskedProof, plan.checks.len);
    var n_done: usize = 0;
    errdefer {
        for (check_proofs[0..n_done]) |*c| c.deinit(a);
        a.free(check_proofs);
    }
    var hpbuf: [256]QM31 = undefined;
    for (plan.checks) |c| {
        const tc = try std.time.Instant.now();
        const specs = try checkSpecs(ar, plan, st, wkey, c, rho, alpha, beta);
        const hp = hpOf(plan, vecs1, c.u, c.n, c.deg, hpbuf[0..zks.Hp.entries(c.n, c.deg)]);
        const len = @as(usize, 1) << @intCast(c.n);
        const claim = checkClaim(st, c);
        var out: zks.ProveOut = undefined;
        switch (c.kind) {
            .product => {
                const p = st.ops[c.idx].product;
                const eq = try f.eqTablePar(a, pool, specs[0].pub_point, QM31.one());
                defer a.free(eq);
                const fa = try toQ(a, pool, witness[p.a], len, QM31.one());
                defer a.free(fa);
                const fb = try toQ(a, pool, witness[p.b], len, QM31.one());
                defer a.free(fb);
                const fc = try toQ(a, pool, witness[p.c], len, qi(-1));
                defer a.free(fc);
                out = try runMasked(4, &T_PRODUCT, a, pool, &tr, claim, .{ eq, fa, fb, fc }, len, specs, hp, &pc);
            },
            .hadamard => {
                const h = st.ops[c.idx].hadamard;
                const eq = try f.eqTablePar(a, pool, specs[0].pub_point, QM31.one());
                defer a.free(eq);
                const fa = try toQ(a, pool, witness[h.a], len, QM31.one());
                defer a.free(fa);
                const fb = try toQ(a, pool, witness[h.b], len, QM31.one());
                defer a.free(fb);
                const fy = try toQ(a, pool, witness[h.y], len, qi(-(@as(i64, 1) << h.shift)));
                defer a.free(fy);
                const fr = try toQ(a, pool, vecs1[plan.rem[c.idx]], len, qi(-1));
                defer a.free(fr);
                out = try runMasked(5, &T_HAD, a, pool, &tr, claim, .{ eq, fa, fb, fy, fr }, len, specs, hp, &pc);
            },
            .matmul => {
                const m = st.ops[c.idx].matmul;
                const w = zw.?;
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const lk = xi.log_dims[1];
                const pt = specs[2].pub_point;
                const tw0 = try std.time.Instant.now();
                const eq_t = try f.eqTablePar(a, pool, pt[0..lt], QM31.one());
                defer a.free(eq_t);
                const xm = pcs.Matrix(i32){ .data = witness[m.x], .log_rows = lt, .log_cols = lk };
                const fx = try zeroExt(a, try linalg.colCombine(i32, a, pool, xm, eq_t, 8), len);
                defer a.free(fx);
                const eq_n = try f.eqTablePar(a, pool, pt[lt..], QM31.one());
                defer a.free(eq_n);
                const gw = try zeroExt(a, try linalg.rowDots(i8, a, pool, w.matrix(m.w), eq_n, 7), len);
                defer a.free(gw);
                timings.weight_fold_ns += nowNs(tw0);
                const eq = try zeroExt(a, try f.eqTablePar(a, pool, pt, QM31.one()), len);
                defer a.free(eq);
                const fy = try toQ(a, pool, witness[m.y], len, qi(-(@as(i64, 1) << m.shift)));
                defer a.free(fy);
                const fr = try toQ(a, pool, vecs1[plan.rem[c.idx]], len, qi(-1));
                defer a.free(fr);
                out = try runMasked(5, &T_MM, a, pool, &tr, claim, .{ fx, gw, eq, fy, fr }, len, specs, hp, &pc);
            },
            .key => {
                const k = plan.keys[c.idx];
                const eq = try f.eqTablePar(a, pool, specs[0].pub_point, QM31.one());
                defer a.free(eq);
                const h = try a.dupe(QM31, hvecs[c.idx]);
                defer a.free(h);
                const d = try keyDenoms(a, pool, plan, st, witness, vecs1, k, alpha, beta);
                defer a.free(d);
                out = try runMasked(3, &T_KEY, a, pool, &tr, claim, .{ eq, h, d }, len, specs, hp, &pc);
            },
        }
        defer a.free(out.point);
        check_proofs[n_done] = out.proof;
        n_done += 1;
        try checkClaims(ar, plan, specs, c.u, c.n, c.deg, out.point, out.proof, &claims, &wclaims, wkey);
        const dt = nowNs(tc);
        if (c.kind == .key) timings.gkr_ns += dt else timings.op_sumcheck_ns += dt;
    }
    var gkr_roots: std.ArrayList(QM31) = .empty;
    var gkr_layers: std.ArrayList(zks.MaskedProof) = .empty;
    errdefer {
        for (gkr_layers.items) |*l| l.deinit(a);
        gkr_layers.deinit(a);
        gkr_roots.deinit(a);
    }
    if (plan.grels.len > 0) {
        const tg = try std.time.Instant.now();
        for (plan.grels) |g| try gkrProveRel(a, ar, pool, &tr, plan, st, witness, vecs1, alpha, beta, g, &claims, &gkr_roots, &gkr_layers);
        timings.gkr_ns += nowNs(tg);
    } else try logupClaims(ar, plan, st, alpha, beta, &claims);

    // --- masked batch sumcheck
    t0 = try std.time.Instant.now();
    const gammas = try ar.alloc(QM31, claims.items.len);
    tr.drawN(gammas);
    const N = plan.batch_n;
    const tabs = [2][]const i32{ tab1, tab2 };
    var active: usize = 0;
    for (0..(if (plan.has2) @as(usize, 2) else 1)) |t| active = @max(active, plan.lay[t].used);
    const NL = active; // factors are zero beyond the larger table's used length
    var Ev: [2][]QM31 = .{ &.{}, &.{} };
    var Tv: [2][]QM31 = .{ &.{}, &.{} };
    const n_tabs: usize = if (plan.has2) 2 else 1;
    defer for (0..n_tabs) |t| {
        a.free(Ev[t]);
        a.free(Tv[t]);
    };
    for (0..n_tabs) |t| {
        Ev[t] = try a.alloc(QM31, NL);
        @memset(Ev[t], QM31.zero());
        Tv[t] = try toQ(a, pool, tabs[t][0..plan.lay[t].used], NL, QM31.one());
    }
    for (claims.items, gammas) |cl, g| for (cl.terms) |term| try addTerm(a, pool, plan, Ev[term.table], term, g);
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |cl, g| batch_claim = batch_claim.add(g.mul(cl.value));
    const bhp = hpOf(plan, vecs1, plan.batch_u, N, 2, hpbuf[0..zks.Hp.entries(N, 2)]);
    const bpad = BatchPad{ .plan = plan, .tabs = .{ vecs1[plan.rb[0]], if (plan.has2) vecs2[plan.rb[1]] else &.{} }, .a = ar };
    var bout: zks.ProveOut = undefined;
    if (plan.has2) {
        bout = try zks.prove(4, &T_B4, a, pool, &tr, batch_claim, .{ Tv[0], Ev[0], Tv[1], Ev[1] }, active, .{ false, true, false, true }, bhp, bpad);
    } else {
        bout = try zks.prove(2, &T_B2, a, pool, &tr, batch_claim, .{ Tv[0], Ev[0] }, active, .{ false, true }, bhp, bpad);
    }
    defer a.free(bout.point);
    errdefer bout.proof.deinit(a);
    timings.batch_ns = nowNs(t0);

    // --- witness opening (tables 1 [+ 2]): group A = batch hats, group B = batch hiding polynomial
    t0 = try std.time.Instant.now();
    const zeta = tr.draw(); // combines the two claims on the batch hiding polynomial; drawn after u_val is mixed
    const ospec = try openingSpec(ar, plan, bout.point, bout.proof, zeta);
    const mus = try a.alloc(QM31, 2);
    mus[0] = zkp.maskValue(i32, m1, plan.maskRow() + 4, ospec.groups[0].col);
    mus[1] = zkp.maskValue(i32, m1, plan.maskRow() + 8, ospec.groups[1].col);
    const shapes = [2]zkp.Shape{ plan.shape(0, cfg.pcs.log_blowup), plan.shape(1, cfg.pcs.log_blowup) };
    var co = try zkp.drawCoeffs(a, &tr, shapes[0..n_tabs], ospec.groups, mus, .{ .table = 0, .row = plan.maskRow() });
    defer co.deinit(a);
    const rows = try combineTables(a, pool, co, .{ &com1, if (com2) |*c| c else null }, .{ m1, pcs.Matrix(i32){ .data = tab2, .log_rows = if (plan.has2) plan.lay[1].log_total - plan.lc else 0, .log_cols = plan.lc, .rows_used = plan.rowsUsed(1) } }, n_tabs);
    var coms_buf: [2]*const zkp.Commitment = .{ &com1, &com1 };
    if (com2) |*c| coms_buf[1] = c;
    var opening = try zkp.finish(a, &tr, cfg.pcs, coms_buf[0..n_tabs], mus, rows);
    errdefer opening.deinit(a);
    timings.witness_open_ns = nowNs(t0);

    // --- weight opening
    t0 = try std.time.Instant.now();
    var wopen: ?zkp.Opening = null;
    if (has_matmul) {
        const w = zw.?;
        const wg = try weightGroup(ar, w.key(), wclaims.items, colpoint);
        const wmm = pcs.Matrix(i32){ .data = wmask_data, .log_rows = 2, .log_cols = w.log_cols };
        const wmus = try a.alloc(QM31, 1);
        wmus[0] = zkp.maskValue(i32, wmm, 0, wg[0].col);
        const wshapes = [_]zkp.Shape{ w.key().shape(wpcs(cfg).log_blowup), wmask_com.?.shape };
        var wco = try zkp.drawCoeffs(a, &tr, &wshapes, wg, wmus, null);
        defer wco.deinit(a);
        const c0 = [_][]const QM31{wco.v[0][0]};
        const c1 = [_][]const QM31{wco.v[0][1]};
        const r0 = try zkp.combine(i8, a, pool, &w.com, w.tableMatrix(), w.extra, &c0);
        const r1 = try zkp.combine(i32, a, pool, &wmask_com.?, wmm, &.{}, &c1);
        for (r0[0], r1[0]) |*x, y| x.* = x.*.add(y);
        a.free(r1[0]);
        a.free(r1);
        const wcoms = [_]*const zkp.Commitment{ &w.com, &wmask_com.? };
        wopen = try zkp.finish(a, &tr, wpcs(cfg), &wcoms, wmus, r0);
    }
    timings.weight_open_ns = nowNs(t0);

    return .{
        .root1 = com1.root(),
        .root2 = if (com2) |*c| c.root() else null,
        .wmask_root = if (wmask_com) |*w| w.root() else null,
        .checks = check_proofs,
        .batch = bout.proof,
        .opening = opening,
        .weight_opening = wopen,
        .gkr_roots = try gkr_roots.toOwnedSlice(a),
        .gkr_layers = try gkr_layers.toOwnedSlice(a),
    };
}

/// alpha - key(x) for a key instance (prover).
fn keyDenoms(a: std.mem.Allocator, pool: *f.Pool, plan: Plan, st: Statement, witness: []const []const i32, vecs1: []const []const i32, k: Key, alpha: QM31, beta: QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(k.log_size);
    const out = try a.alloc(QM31, n);
    const op = st.ops[k.op];
    const Ctx = struct { out: []QM31, k: Key, x: []const i32, y: []const i32, alpha: QM31, beta: QM31 };
    var ctx = Ctx{ .out = out, .k = k, .x = &.{}, .y = &.{}, .alpha = alpha, .beta = beta };
    switch (k.kind) {
        .remainder => ctx.x = vecs1[plan.rem[k.op]],
        .y_range => ctx.x = witness[opY(op)],
        .plain_range => ctx.x = witness[op.range8.in],
        .lookup_pair => {
            ctx.x = witness[op.lookup.in];
            ctx.y = witness[op.lookup.out];
        },
    }
    pool.parallelFor(n, 4096, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| {
                const key: QM31 = switch (c.k.kind) {
                    .remainder => qi(c.x[i]),
                    .y_range, .plain_range => qi(@as(i64, c.x[i]) + 128),
                    .lookup_pair => qi(c.x[i]).add(c.beta.mul(qi(c.y[i]))),
                };
                c.out[i] = c.alpha.sub(key);
            }
        }
    }.run);
    return out;
}

fn nowNs(t0: std.time.Instant) u64 {
    const t1 = std.time.Instant.now() catch return 0;
    return t1.since(t0);
}

fn buildTable(a: std.mem.Allocator, plan: Plan, t: usize, vecs: []const []const i32) ![]i32 {
    const total = @as(usize, 1) << @intCast(plan.lay[t].log_total);
    const tab = try a.alloc(i32, total);
    @memset(tab, 0);
    for (vecs, 0..) |v, i| {
        std.debug.assert(v.len == plan.infos[t][i].size());
        @memcpy(tab[plan.lay[t].offsets[i]..][0..v.len], v);
    }
    return tab;
}

fn combineTables(a: std.mem.Allocator, pool: *f.Pool, co: zkp.Coeffs, coms: [2]?*const zkp.Commitment, ms: [2]pcs.Matrix(i32), n_tabs: usize) ![][]QM31 {
    const n_out = co.v.len;
    var out: [][]QM31 = undefined;
    for (0..n_tabs) |t| {
        const cv = try a.alloc([]const QM31, n_out);
        defer a.free(cv);
        for (0..n_out) |o| cv[o] = co.v[o][t];
        const r = try zkp.combine(i32, a, pool, coms[t].?, ms[t], &.{}, cv);
        if (t == 0) {
            out = r;
        } else {
            for (out, r) |x, y| {
                for (x, y) |*p, q| p.* = p.*.add(q);
                a.free(y);
            }
            a.free(r);
        }
    }
    return out;
}

const BatchPad = struct {
    plan: Plan,
    tabs: [2][]const i32,
    a: std.mem.Allocator,
    pub fn pads(self: @This(), r: []const QM31, fin: anytype) @TypeOf(fin) {
        var out = fin;
        const lc = self.plan.lc;
        const n_t = out.len / 2;
        for (0..n_t) |t| {
            out[2 * t] = f.mleEvalI32(self.a, self.tabs[t], r[r.len - lc ..]) catch @panic("oom");
        }
        return out;
    }
};

const OpeningSpec = struct { groups: []zkp.Group };

/// Groups of the witness opening, from the batch sumcheck output (both sides).
fn openingSpec(a: std.mem.Allocator, plan: Plan, point: []const QM31, bp: zks.MaskedProof, zeta: QM31) !OpeningSpec {
    const N = plan.batch_n;
    const r = point[0..N];
    const g = point[N];
    const C = plan.nCols();
    const n_tabs: usize = if (plan.has2) 2 else 1;
    const rcol = r[N - plan.lc ..];
    const colA = try f.eqTable(a, rcol, QM31.one());
    const claimsA = try a.alloc(zkp.Claim, n_tabs);
    for (0..n_tabs) |t| {
        const Nt = plan.lay[t].log_total;
        const rt = r[N - Nt ..];
        const scale = zeroExtScale(r, Nt);
        const nr = plan.rowsUsed(t);
        const rowv = try f.eqTable(a, rt[0 .. Nt - plan.lc], QM31.one().sub(g).mul(scale));
        const rv = try a.alloc(QM31, nr);
        @memcpy(rv, rowv[0..nr]);
        const rbrow = plan.off(t, plan.rb[t]) >> @intCast(plan.lc);
        rv[rbrow] = rv[rbrow].add(g);
        const rows = try a.alloc([]const QM31, n_tabs);
        for (rows, 0..) |*x, tt| x.* = if (tt == t) rv else &.{};
        claimsA[t] = .{ .rows = rows, .value = bp.hats[t] };
    }
    // group B: batch hiding polynomial claims sigma + zeta u_val (zeta = fixed derivation from gamma_Y)
    const ne = zks.Hp.entries(N, 2);
    const fs = try a.alloc(QM31, ne);
    zks.Hp.sumForm(N, 2, fs);
    const fe = try a.alloc(QM31, ne);
    zks.Hp.evalForm(N, 2, point, fe);
    const colB = try a.alloc(QM31, C);
    @memset(colB, QM31.zero());
    const uoff = plan.off(0, plan.batch_u);
    const ucol = uoff & (C - 1);
    for (0..ne) |e| for (0..4) |k| {
        colB[ucol + 4 * e + k] = fs[e].add(zeta.mul(fe[e])).mul(zkp.basis(k));
    };
    const rvB = try a.alloc(QM31, plan.rowsUsed(0));
    @memset(rvB, QM31.zero());
    rvB[uoff >> @intCast(plan.lc)] = QM31.one();
    const rowsB = try a.alloc([]const QM31, n_tabs);
    for (rowsB, 0..) |*x, tt| x.* = if (tt == 0) rvB else &.{};
    const claimsB = try a.alloc(zkp.Claim, 1);
    claimsB[0] = .{ .rows = rowsB, .value = bp.sigma.add(zeta.mul(bp.u_val)) };
    const groups = try a.alloc(zkp.Group, 2);
    groups[0] = .{ .col = colA, .claims = claimsA, .mask = .{ .table = 0, .row = plan.maskRow() + 4 } };
    groups[1] = .{ .col = colB, .claims = claimsB, .mask = .{ .table = 0, .row = plan.maskRow() + 8 } };
    return .{ .groups = groups };
}

fn weightGroup(a: std.mem.Allocator, key: WeightKey, wcl: []const WClaim, colpoint: []const QM31) ![]zkp.Group {
    const lr = key.log_rows;
    const nr = key.rows_used + 2 * WPAD_ROWS;
    const claims = try a.alloc(zkp.Claim, wcl.len);
    for (wcl, 0..) |c, i| {
        const info = key.infos[c.w];
        const full = try a.alloc(QM31, lr + key.log_cols);
        const nb = lr + key.log_cols - info.logSize();
        bitsPoint(full[0..nb], key.offsets[c.w] >> @intCast(info.logSize()));
        @memcpy(full[nb..], c.local);
        for (full[lr..], colpoint) |x, y| if (!x.eql(y)) return error.WeightColumnPoint;
        const eqr = try f.eqTable(a, full[0..lr], c.c_data);
        const rv = try a.alloc(QM31, nr);
        @memcpy(rv[0..key.rows_used], eqr[0..key.rows_used]);
        @memset(rv[key.rows_used..], QM31.zero());
        const eqs = try f.eqTable(a, &c.s, c.c_pad);
        for (0..WPAD_ROWS) |k| rv[key.rows_used + k] = eqs[k];
        const rows = try a.alloc([]const QM31, 2);
        rows[0] = rv;
        rows[1] = &.{};
        claims[i] = .{ .rows = rows, .value = c.value };
    }
    const groups = try a.alloc(zkp.Group, 1);
    groups[0] = .{ .col = try f.eqTable(a, colpoint, QM31.one()), .claims = claims, .mask = .{ .table = 1, .row = 0 } };
    return groups;
}

// ---------------------------------------------------------------------------
// Verifier.

pub fn verify(a: std.mem.Allocator, cfg: proto.Config, st: Statement, wkey: ?WeightKey, proof: *const Proof) !void {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const plan = try makePlan(ar, st, wkey, cfg);
    var has_matmul = false;
    for (st.ops) |op| has_matmul = has_matmul or op == .matmul;
    if (has_matmul != (proof.wmask_root != null) or has_matmul != (proof.weight_opening != null)) return error.ProofShape;
    if (plan.has2 != (proof.root2 != null)) return error.ProofShape;
    if (proof.checks.len != plan.checks.len) return error.ProofShape;

    var tr = Transcript.initDomain("stwo-tensor-zk-v1");
    mixStatement(&tr, st, if (wkey) |k| k.root else [_]u8{0} ** 32, cfg);
    tr.mixDigest(proof.root1);
    if (proof.wmask_root) |r| tr.mixDigest(r);
    const alpha = tr.draw();
    const beta = tr.draw();
    if (proof.root2) |r| tr.mixDigest(r);
    const rho = try ar.alloc(QM31, plan.rho_len);
    tr.drawN(rho);
    const colpoint: []const QM31 = if (wkey) |k| rho[rho.len - k.log_cols ..] else &.{};

    var claims: std.ArrayList(LClaim) = .empty;
    var wclaims: std.ArrayList(WClaim) = .empty;
    for (plan.checks, proof.checks) |c, cp| {
        const specs = try checkSpecs(ar, plan, st, wkey, c, rho, alpha, beta);
        var n_hats: usize = 0;
        for (specs) |s| n_hats += @intFromBool(!s.public);
        const vo = try zks.verify(ar, &tr, checkClaim(st, c), c.n, @intCast(c.deg), n_hats, cp);
        const r = vo.point[0..c.n];
        var vals: [5]QM31 = undefined;
        var hi: usize = 0;
        for (specs, 0..) |s, j| {
            if (s.public) {
                vals[j] = zeroExtScale(r, s.m).mul(f.eqEval(s.pub_point, r[r.len - s.m ..]));
            } else {
                vals[j] = cp.hats[hi];
                hi += 1;
            }
        }
        if (!vo.final_claim.eql(cp.u_val.add(vo.eps.mul(evalCheckTerms(c.kind, vals[0..nSpecs(c.kind)]))))) return error.MaskedSumcheck;
        try checkClaims(ar, plan, specs, c.u, c.n, c.deg, vo.point, cp, &claims, &wclaims, wkey);
    }
    if (plan.grels.len > 0) {
        if (proof.gkr_roots.len != plan.grels.len) return error.ProofShape;
        var n_layers: usize = 0;
        for (plan.grels) |g| n_layers += g.n;
        if (proof.gkr_layers.len != n_layers) return error.ProofShape;
        var li: usize = 0;
        for (plan.grels, proof.gkr_roots) |g, d_root| {
            try gkrVerifyRel(ar, &tr, plan, st, alpha, beta, g, d_root, proof.gkr_layers[li..][0..g.n], &claims);
            li += g.n;
        }
    } else {
        if (proof.gkr_roots.len != 0 or proof.gkr_layers.len != 0) return error.ProofShape;
        try logupClaims(ar, plan, st, alpha, beta, &claims);
    }

    // batch
    const gammas = try ar.alloc(QM31, claims.items.len);
    tr.drawN(gammas);
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |cl, g| batch_claim = batch_claim.add(g.mul(cl.value));
    const N = plan.batch_n;
    const n_tabs: usize = if (plan.has2) 2 else 1;
    const bv = try zks.verify(ar, &tr, batch_claim, N, 2, n_tabs, proof.batch);
    const r = bv.point[0..N];
    var e_at: [2]QM31 = .{ QM31.zero(), QM31.zero() };
    for (claims.items, gammas) |cl, g| for (cl.terms) |term| {
        const Nt = plan.lay[term.table].log_total;
        e_at[term.table] = e_at[term.table].add(g.mul(try termAt(ar, plan, term, r[N - Nt ..])));
    };
    var gval = QM31.zero();
    for (0..n_tabs) |t| gval = gval.add(proof.batch.hats[t].mul(zeroExtScale(r, plan.lay[t].log_total).mul(e_at[t])));
    if (!bv.final_claim.eql(proof.batch.u_val.add(bv.eps.mul(gval)))) return error.BatchSumcheck;

    // witness opening
    const zeta = tr.draw();
    const ospec = try openingSpec(ar, plan, bv.point, proof.batch, zeta);
    var tw = try pcs.Twiddles.init(a, plan.lc + cfg.pcs.log_blowup);
    defer tw.deinit(a);
    const shapes = [2]zkp.Shape{ plan.shape(0, cfg.pcs.log_blowup), plan.shape(1, cfg.pcs.log_blowup) };
    const roots = [2]Hash{ proof.root1, proof.root2 orelse proof.root1 };
    try zkp.verifyOpening(ar, &tr, cfg.pcs, &tw, shapes[0..n_tabs], roots[0..n_tabs], ospec.groups, .{ .table = 0, .row = plan.maskRow() }, proof.opening);

    // weight opening
    if (proof.weight_opening) |wop| {
        const wk = wkey.?;
        const wg = try weightGroup(ar, wk, wclaims.items, colpoint);
        var wtw = try pcs.Twiddles.init(a, wk.log_cols + wpcs(cfg).log_blowup);
        defer wtw.deinit(a);
        const wshape = wk.shape(wpcs(cfg).log_blowup);
        const mshape = zkp.Shape{ .log_cols = wk.log_cols, .log_blowup = wpcs(cfg).log_blowup, .slots = wk.slots, .n_rows = 4 };
        const wshapes = [_]zkp.Shape{ wshape, mshape };
        const wroots = [_]Hash{ wk.root, proof.wmask_root.? };
        try zkp.verifyOpening(ar, &tr, wpcs(cfg), &wtw, &wshapes, &wroots, wg, null, wop);
    } else if (wclaims.items.len != 0) return error.ProofShape;
}

// ---------------------------------------------------------------------------
// Hiding LogUp-GKR (default LogUp of the hiding mode).
//
// One fraction tree per relation: leaves = key segments (1, alpha - key),
// the table segment (-m(t), alpha - key_t), one blinder leaf (0, rho) with a
// committed uniform rho != 0, and padding (0, 1); MSB split
// (node x of layer k-1 = node x (+) node x + 2^(k-1) of layer k). The root
// numerator must be 0 (it is not sent); the root denominator is uniform
// because of rho. Each layer k = 1..n is a masked sumcheck over k-1 variables
//   (lambda a^ + b^) / (1 - g') = sum_x eq(r, x) [lam n0 d1 + lam n1 d0 + d0 d1](x)
//                               + sum_x et(x) Q(x)
// whose four finals are revealed as hats padded by fresh 16-cell pads at
// t_k = last 4 coords of (aux ++ r'), and whose Q term absorbs the previous
// layer's pad part g' (lam P_a + P_b)(t_{k-1}) / (1 - g'); Q's final value is one
// more (independent) linear claim on those pads. The last layer's hats become
// linear claims on the committed tensors (keys, multiplicities, blinder) and pads.

const T_GKR = [_]zks.Term{
    .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 4 } },
    .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 2, 3 } },
    .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 3, 4 } },
    .{ .coeff = QM31.one(), .factors = &[_]u8{ 5, 6 } },
};
const GKR_PUBLIC = [7]bool{ true, false, false, false, false, true, false };

/// eq (A0 D1 + A1 D0 + D0 D1) + et Q with 4 multiplications (T_GKR uses 7).
const GkrEval = struct {
    pub inline fn eval(c: *const [7]QM31) QM31 {
        return c[0].mul(c[1].mul(c[4]).add(c[3].mul(c[2].add(c[4])))).add(c[5].mul(c[6]));
    }
};

fn gkrPadPoint(aux: [4]QM31, r: []const QM31) [4]QM31 {
    var t: [4]QM31 = undefined;
    const total = 4 + r.len;
    for (0..4) |i| {
        const pos = total - 4 + i;
        t[i] = if (pos < 4) aux[pos] else r[pos - 4];
    }
    return t;
}

const QShape = struct { mp: usize, t_lead: []const QM31, t_tail: []const QM31 };

fn qShape(m: usize, t: *const [4]QM31) QShape {
    const mp = @min(m, 4);
    return .{ .mp = mp, .t_lead = t[0 .. 4 - mp], .t_tail = t[4 - mp ..] };
}

fn etPoint(a: std.mem.Allocator, m: usize, qs: QShape) ![]QM31 {
    const p = try a.alloc(QM31, m);
    @memset(p[0 .. m - qs.mp], QM31.zero());
    @memcpy(p[m - qs.mp ..], qs.t_tail);
    return p;
}

fn uClaims(a: std.mem.Allocator, u_id: u32, n: u32, deg: u32, point: []const QM31, proof: zks.MaskedProof, claims: *std.ArrayList(LClaim)) !void {
    const ne = zks.Hp.entries(n, deg);
    const fs = try a.alloc(QM31, ne);
    zks.Hp.sumForm(n, deg, fs);
    const fe = try a.alloc(QM31, ne);
    zks.Hp.evalForm(n, deg, point, fe);
    const t_sig = try a.alloc(LTerm, 1);
    t_sig[0] = .{ .table = 0, .id = u_id, .coeff = QM31.one(), .form = .{ .sparse = try sparseOfForm(a, fs) } };
    try claims.append(a, .{ .terms = t_sig, .value = proof.sigma });
    const t_u = try a.alloc(LTerm, 1);
    t_u[0] = .{ .table = 0, .id = u_id, .coeff = QM31.one(), .form = .{ .sparse = try sparseOfForm(a, fe) } };
    try claims.append(a, .{ .terms = t_u, .value = proof.u_val });
}

fn gkrWeights(lam: QM31, c: QM31) [4]QM31 {
    const omc = QM31.one().sub(c);
    return .{ lam.mul(omc), lam.mul(c), omc, c };
}

/// Q(r') = coefQ * eq(r'_head, 0) * sum_j w_j P_j(t_lead, r'_tail)
fn qClaim(a: std.mem.Allocator, pads: [4]u32, w: [4]QM31, coef_q: QM31, qs: QShape, r: []const QM31, value: QM31, claims: *std.ArrayList(LClaim)) !void {
    const pt = try a.alloc(QM31, 4);
    @memcpy(pt[0..qs.t_lead.len], qs.t_lead);
    @memcpy(pt[qs.t_lead.len..], r[r.len - qs.mp ..]);
    const scale = coef_q.mul(zeroExtScale(r, @intCast(qs.mp)));
    const terms = try a.alloc(LTerm, 4);
    for (0..4) |j| terms[j] = .{ .table = 0, .id = pads[j], .coeff = scale.mul(w[j]), .form = .{ .eq = pt } };
    try claims.append(a, .{ .terms = terms, .value = value });
}

fn relKeyMle(a: std.mem.Allocator, st: Statement, rel: Rel, local: []const QM31, beta: QM31) !QM31 {
    switch (rel.kind) {
        .range => return f.identityMle(local),
        .act => |ti| {
            var outv: [256]i32 = undefined;
            for (0..256) |i| outv[i] = st.tables[ti].values[i];
            return f.identityMle(local).sub(qi(128)).add(beta.mul(try f.mleEvalI32(a, &outv, local)));
        },
    }
}

/// Claims on the committed tensors from the last layer's hats (both sides).
fn gkrLeafClaims(a: std.mem.Allocator, plan: Plan, st: Statement, g: GRel, alpha: QM31, beta: QM31, p: []const QM31, gam: QM31, c: QM31, t: [4]QM31, pads: [4]u32, ahat: QM31, bhat: QM31, claims: *std.ArrayList(LClaim)) !void {
    const n = g.n;
    const omg = QM31.one().sub(gam);
    var nterms: std.ArrayList(LTerm) = .empty;
    var dterms: std.ArrayList(LTerm) = .empty;
    var num_pub = QM31.zero();
    var den_pub = QM31.zero();
    var sum_blk = QM31.zero();
    const nk = g.keys.len;
    for (g.seg_log, g.seg_off, 0..) |l, o, i| {
        const bits = try a.alloc(QM31, n - l);
        bitsPoint(bits, o >> @intCast(l));
        const blk = f.eqEval(p[0 .. n - l], bits);
        const local = p[n - l ..];
        sum_blk = sum_blk.add(blk);
        if (i < nk) {
            const k = plan.keys[g.keys[i]];
            const d = try keyFactorD(a, plan, st, k, alpha, beta, k.log_size);
            num_pub = num_pub.add(blk);
            den_pub = den_pub.add(blk.mul(d.konst));
            for (d.parts) |pt| try dterms.append(a, .{ .table = 0, .id = pt.id, .coeff = omg.mul(blk).mul(pt.coeff), .form = .{ .eq = local } });
        } else if (i == nk) {
            const rel = plan.rels[g.rel];
            try nterms.append(a, .{ .table = 0, .id = rel.mult, .coeff = omg.mul(blk).neg(), .form = .{ .eq = local } });
            den_pub = den_pub.add(blk.mul(alpha.sub(try relKeyMle(a, st, rel, local, beta))));
        } else {
            try dterms.append(a, .{ .table = 0, .id = g.blinder, .coeff = omg.mul(blk), .form = .{ .eq = local } });
        }
    }
    den_pub = den_pub.add(QM31.one().sub(sum_blk));
    const tp = try a.dupe(QM31, &t);
    const omc = QM31.one().sub(c);
    try nterms.append(a, .{ .table = 0, .id = pads[0], .coeff = gam.mul(omc), .form = .{ .eq = tp } });
    try nterms.append(a, .{ .table = 0, .id = pads[1], .coeff = gam.mul(c), .form = .{ .eq = tp } });
    try dterms.append(a, .{ .table = 0, .id = pads[2], .coeff = gam.mul(omc), .form = .{ .eq = tp } });
    try dterms.append(a, .{ .table = 0, .id = pads[3], .coeff = gam.mul(c), .form = .{ .eq = tp } });
    try claims.append(a, .{ .terms = try nterms.toOwnedSlice(a), .value = ahat.sub(omg.mul(num_pub)) });
    try claims.append(a, .{ .terms = try dterms.toOwnedSlice(a), .value = bhat.sub(omg.mul(den_pub)) });
}

const GkrPad = struct {
    a: std.mem.Allocator,
    vecs1: []const []const i32,
    pad_ids: [4]u32,
    lam: QM31,
    aux: [4]QM31,
    pub fn pads(self: @This(), r: []const QM31, fin: [7]QM31) [7]QM31 {
        const t = gkrPadPoint(self.aux, r);
        var out = fin;
        for (0..4) |j| {
            const v = f.mleEvalI32(self.a, self.vecs1[self.pad_ids[j]], &t) catch @panic("oom");
            out[1 + j] = if (j < 2) self.lam.mul(v) else v;
        }
        return out;
    }
};

/// Partial evaluation of a 16-cell pad at its leading coordinates (MSB first).
fn padPartial(a: std.mem.Allocator, cells: []const i32, lead: []const QM31) ![]QM31 {
    var buf = try a.alloc(QM31, cells.len);
    for (buf, cells) |*x, v| x.* = QM31.fromBase(f.fromI32(v));
    var len = buf.len;
    for (lead) |r| {
        const half = len / 2;
        for (0..half) |i| buf[i] = buf[i].add(r.mul(buf[i + half].sub(buf[i])));
        len = half;
    }
    return buf[0..len];
}

fn gkrProveRel(
    a: std.mem.Allocator,
    ar: std.mem.Allocator,
    pool: *f.Pool,
    tr: *Transcript,
    plan: Plan,
    st: Statement,
    witness: []const []const i32,
    vecs1: []const []const i32,
    alpha: QM31,
    beta: QM31,
    g: GRel,
    claims: *std.ArrayList(LClaim),
    roots: *std.ArrayList(QM31),
    layers_out: *std.ArrayList(zks.MaskedProof),
) !void {
    const n = g.n;
    const L = @as(usize, 1) << @intCast(n);
    const lnum = try a.alloc([]QM31, n + 1);
    const lden = try a.alloc([]QM31, n + 1);
    defer {
        for (lnum, lden) |x, y| {
            a.free(x);
            a.free(y);
        }
        a.free(lnum);
        a.free(lden);
    }
    for (lnum, lden) |*x, *y| {
        x.* = &.{};
        y.* = &.{};
    }
    lnum[n] = try a.alloc(QM31, L);
    lden[n] = try a.alloc(QM31, L);
    @memset(lnum[n], QM31.zero());
    @memset(lden[n], QM31.one());
    const nk = g.keys.len;
    for (g.keys, 0..) |ki, i| {
        const d = try keyDenoms(a, pool, plan, st, witness, vecs1, plan.keys[ki], alpha, beta);
        defer a.free(d);
        @memcpy(lden[n][g.seg_off[i]..][0..d.len], d);
        @memset(lnum[n][g.seg_off[i]..][0..d.len], QM31.one());
    }
    const rel = plan.rels[g.rel];
    {
        const o = g.seg_off[nk];
        for (vecs1[rel.mult], 0..) |m, t| {
            lnum[n][o + t] = qi(-@as(i64, m));
            lden[n][o + t] = alpha.sub(relKey(st, rel.kind, t, beta));
        }
        lden[n][g.seg_off[nk + 1]] = QM31.fromBase(f.fromI32(vecs1[g.blinder][0]));
    }
    var k: usize = n;
    while (k > 0) : (k -= 1) {
        const half = @as(usize, 1) << @intCast(k - 1);
        lnum[k - 1] = try a.alloc(QM31, half);
        lden[k - 1] = try a.alloc(QM31, half);
        const Ctx = struct { n0: []const QM31, d0: []const QM31, on: []QM31, od: []QM31, half: usize };
        const ctx = Ctx{ .n0 = lnum[k], .d0 = lden[k], .on = lnum[k - 1], .od = lden[k - 1], .half = half };
        pool.parallelFor(half, 4096, &ctx, struct {
            fn run(c: *const Ctx, s: usize, e: usize) void {
                for (s..e) |x| {
                    const a0 = c.n0[x];
                    const a1 = c.n0[x + c.half];
                    const b0 = c.d0[x];
                    const b1 = c.d0[x + c.half];
                    c.on[x] = a0.mul(b1).add(a1.mul(b0));
                    c.od[x] = b0.mul(b1);
                }
            }
        }.run);
    }
    if (!lnum[0][0].isZero()) return error.LogUpMismatch;
    const d_root = lden[0][0];
    tr.mixFelt(d_root);
    try roots.append(a, d_root);
    var aux: [4]QM31 = undefined;
    tr.drawN(&aux);
    var ca = QM31.zero();
    var cb = d_root;
    var gam = QM31.zero();
    var r_prev: []QM31 = &.{};
    var c_prev = QM31.zero();
    var t_prev: [4]QM31 = undefined;
    var pads_prev: [4]u32 = undefined;
    var lam_prev = QM31.zero();
    _ = &lam_prev;
    var hpbuf: [256]QM31 = undefined;
    for (1..n + 1) |kk| {
        const lam = tr.draw();
        const m = kk - 1;
        const half = @as(usize, 1) << @intCast(m);
        const inv_omg = QM31.one().sub(gam).inv() catch return error.GkrChallenge;
        const claim = lam.mul(ca).add(cb).mul(inv_omg);
        const eq = try f.eqTablePar(a, pool, r_prev, QM31.one());
        defer a.free(eq);
        const A0 = try a.alloc(QM31, half);
        defer a.free(A0);
        const A1 = try a.alloc(QM31, half);
        defer a.free(A1);
        for (A0, A1, lnum[kk][0..half], lnum[kk][half..]) |*x, *y, u, v| {
            x.* = lam.mul(u);
            y.* = lam.mul(v);
        }
        const D0 = try a.dupe(QM31, lden[kk][0..half]);
        defer a.free(D0);
        const D1 = try a.dupe(QM31, lden[kk][half..]);
        defer a.free(D1);
        const et = try a.alloc(QM31, half);
        defer a.free(et);
        const Q = try a.alloc(QM31, half);
        defer a.free(Q);
        @memset(Q, QM31.zero());
        var qs: QShape = undefined;
        var coef_q = QM31.zero();
        var w: [4]QM31 = undefined;
        if (kk == 1) {
            et[0] = QM31.one();
        } else {
            qs = qShape(m, &t_prev);
            const etp = try etPoint(a, m, qs);
            defer a.free(etp);
            const ett = try f.eqTable(a, etp, QM31.one());
            defer a.free(ett);
            @memcpy(et, ett);
            coef_q = gam.mul(inv_omg);
            w = gkrWeights(lam, c_prev);
            for (0..4) |j| {
                const part = try padPartial(a, vecs1[pads_prev[j]], qs.t_lead);
                defer a.free(part.ptr[0..16]);
                for (part, 0..) |v, x| Q[x] = Q[x].add(coef_q.mul(w[j]).mul(v));
            }
        }
        const layer = g.layers[m];
        const hp = hpOf(plan, vecs1, layer.u, @intCast(m), 3, hpbuf[0..zks.Hp.entries(m, 3)]);
        const pctx = GkrPad{ .a = ar, .vecs1 = vecs1, .pad_ids = layer.pads, .lam = lam, .aux = aux };
        var out = try zks.proveWith(7, &T_GKR, GkrEval, a, pool, tr, claim, .{ eq, A0, A1, D0, D1, et, Q }, half, GKR_PUBLIC, hp, pctx);
        defer a.free(out.point);
        errdefer out.proof.deinit(a);
        const hats = out.proof.hats;
        const rp = out.point[0..m];
        try uClaims(ar, layer.u, @intCast(m), 3, out.point, out.proof, claims);
        if (kk >= 2) try qClaim(ar, pads_prev, w, coef_q, qs, try ar.dupe(QM31, rp), hats[4], claims);
        const c = tr.draw();
        const inv_lam = lam.inv() catch return error.GkrChallenge;
        const omc = QM31.one().sub(c);
        ca = omc.mul(hats[0]).add(c.mul(hats[1])).mul(inv_lam);
        cb = omc.mul(hats[2]).add(c.mul(hats[3]));
        gam = out.point[m];
        const nr = try ar.alloc(QM31, kk);
        nr[0] = c;
        @memcpy(nr[1..], rp);
        r_prev = nr;
        t_prev = gkrPadPoint(aux, rp);
        pads_prev = layer.pads;
        c_prev = c;
        try layers_out.append(a, out.proof);
    }
    try gkrLeafClaims(ar, plan, st, g, alpha, beta, r_prev, gam, c_prev, t_prev, pads_prev, ca, cb, claims);
}

fn gkrVerifyRel(ar: std.mem.Allocator, tr: *Transcript, plan: Plan, st: Statement, alpha: QM31, beta: QM31, g: GRel, d_root: QM31, layers: []const zks.MaskedProof, claims: *std.ArrayList(LClaim)) !void {
    if (d_root.isZero()) return error.GkrRoot;
    if (layers.len != g.n) return error.ProofShape;
    tr.mixFelt(d_root);
    var aux: [4]QM31 = undefined;
    tr.drawN(&aux);
    var ca = QM31.zero();
    var cb = d_root;
    var gam = QM31.zero();
    var r_prev: []QM31 = &.{};
    var c_prev = QM31.zero();
    var t_prev: [4]QM31 = undefined;
    var pads_prev: [4]u32 = undefined;
    for (1..g.n + 1) |kk| {
        const lam = tr.draw();
        const m = kk - 1;
        const inv_omg = QM31.one().sub(gam).inv() catch return error.GkrChallenge;
        const claim = lam.mul(ca).add(cb).mul(inv_omg);
        const lp = layers[m];
        const vo = try zks.verify(ar, tr, claim, m, 3, 5, lp);
        const rp = vo.point[0..m];
        const hats = lp.hats;
        var etv = QM31.one();
        var qs: QShape = undefined;
        var coef_q = QM31.zero();
        var w: [4]QM31 = undefined;
        if (kk == 1) {
            if (!hats[4].isZero()) return error.GkrLayer;
        } else {
            qs = qShape(m, &t_prev);
            etv = f.eqEval(try etPoint(ar, m, qs), rp);
            coef_q = gam.mul(inv_omg);
            w = gkrWeights(lam, c_prev);
        }
        const vals = [7]QM31{ f.eqEval(r_prev, rp), hats[0], hats[1], hats[2], hats[3], etv, hats[4] };
        if (!vo.final_claim.eql(lp.u_val.add(vo.eps.mul(zks.evalTermsRt(&T_GKR, 7, vals))))) return error.GkrLayer;
        const layer = g.layers[m];
        try uClaims(ar, layer.u, @intCast(m), 3, vo.point, lp, claims);
        if (kk >= 2) try qClaim(ar, pads_prev, w, coef_q, qs, rp, hats[4], claims);
        const c = tr.draw();
        const inv_lam = lam.inv() catch return error.GkrChallenge;
        const omc = QM31.one().sub(c);
        ca = omc.mul(hats[0]).add(c.mul(hats[1])).mul(inv_lam);
        cb = omc.mul(hats[2]).add(c.mul(hats[3]));
        gam = vo.point[m];
        const nr = try ar.alloc(QM31, kk);
        nr[0] = c;
        @memcpy(nr[1..], rp);
        r_prev = nr;
        t_prev = gkrPadPoint(aux, rp);
        pads_prev = layer.pads;
        c_prev = c;
    }
    try gkrLeafClaims(ar, plan, st, g, alpha, beta, r_prev, gam, c_prev, t_prev, pads_prev, ca, cb, claims);
}

// ---------------------------------------------------------------------------
// Tests.

const model = @import("model.zig");

fn testCfg() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 6, .witness_log_cols_max = 7, .gkr_threads = 1, .hiding = true, .weight_mask_slots = 64 };
}

fn wview(a: std.mem.Allocator, w: [][]i32) ![]const []const i32 {
    const v = try a.alloc([]const i32, w.len);
    for (w, 0..) |x, i| v[i] = x;
    return v;
}

test "zk product: proves, verifies, rejects tampering, randomized" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = testCfg();
    var built = try model.buildProduct(a, 9, 3);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try wview(a, built.witness);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try prove(a, &pool, cfg, st, null, wv, &tm);
    defer proof.deinit(a);
    try verify(a, cfg, st, null, &proof);
    // tamper: hat, sigma, u_val, round message, batch hat, opening row/column/mu
    const H = struct {
        fn expectReject(al: std.mem.Allocator, c: proto.Config, s: Statement, p: *const Proof) !void {
            try std.testing.expect(std.meta.isError(verify(al, c, s, null, p)));
        }
    };
    const one = QM31.one();
    inline for (.{ "hat", "sigma", "u_val", "round", "bhat", "bsigma", "row", "mu" }) |what| {
        const ptr: *QM31 = if (comptime std.mem.eql(u8, what, "hat")) &proof.checks[0].hats[1] else if (comptime std.mem.eql(u8, what, "sigma")) &proof.checks[0].sigma else if (comptime std.mem.eql(u8, what, "u_val")) &proof.checks[0].u_val else if (comptime std.mem.eql(u8, what, "round")) &proof.checks[0].rounds[2][1] else if (comptime std.mem.eql(u8, what, "bhat")) &proof.batch.hats[0] else if (comptime std.mem.eql(u8, what, "bsigma")) &proof.batch.sigma else if (comptime std.mem.eql(u8, what, "row")) &proof.opening.rows[1][3] else &proof.opening.mus[1];
        ptr.* = ptr.*.add(one);
        try H.expectReject(a, cfg, st, &proof);
        ptr.* = ptr.*.sub(one);
    }
    proof.opening.tables[0].values[5] = proof.opening.tables[0].values[5].add(M31.one());
    try H.expectReject(a, cfg, st, &proof);
    proof.opening.tables[0].values[5] = proof.opening.tables[0].values[5].sub(M31.one());
    proof.root1[0] ^= 1;
    try H.expectReject(a, cfg, st, &proof);
    proof.root1[0] ^= 1;
    try verify(a, cfg, st, null, &proof);
    // a second proof of the same statement uses fresh randomness
    var proof2 = try prove(a, &pool, cfg, st, null, wv, &tm);
    defer proof2.deinit(a);
    try verify(a, cfg, st, null, &proof2);
    try std.testing.expect(!std.mem.eql(u8, &proof.root1, &proof2.root1));
    try std.testing.expect(!proof.checks[0].hats[0].eql(proof2.checks[0].hats[0]));
    // a wrong witness is refused by the prover
    built.witness[2][7] +%= 1;
    try std.testing.expectError(error.ProductMismatch, prove(a, &pool, cfg, st, null, wv, &tm));
}

test "zk mlp: hiding weights + witness, verify, tamper, opening budget" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = testCfg();
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7 };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
    defer zw.deinit(a);
    var prox = try proveWeightProximity(a, &pool, cfg, &zw);
    defer prox.deinit(a);
    const key = zw.key();
    try verifyWeightProximity(a, cfg, key, prox);
    prox.rows[0][2] = prox.rows[0][2].add(QM31.one());
    try std.testing.expect(std.meta.isError(verifyWeightProximity(a, cfg, key, prox)));

    const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
    defer a.free(x);
    const pv = zw.plainView();
    var built = try model.buildMlp(a, &pool, &pv, mc, x);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try wview(a, built.witness);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try prove(a, &pool, cfg, st, &zw, wv, &tm);
    defer proof.deinit(a);
    try verify(a, cfg, st, key, &proof);
    // tamper: masked weight hat (matmul check 2 = first matmul, factor W is hat index 1)
    proof.checks[0].hats[1] = proof.checks[0].hats[1].add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, key, &proof)));
    proof.checks[0].hats[1] = proof.checks[0].hats[1].sub(QM31.one());
    // tamper: a key (LogUp) check message
    const last = proof.checks.len - 1;
    proof.checks[last].rounds[0][0] = proof.checks[last].rounds[0][0].add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, key, &proof)));
    proof.checks[last].rounds[0][0] = proof.checks[last].rounds[0][0].sub(QM31.one());
    // tamper: hiding GKR root, layer hat, layer round, layer u_val, Q value
    try std.testing.expect(proof.gkr_roots.len > 0 and proof.gkr_layers.len > 0);
    {
        const one = QM31.one();
        const L = proof.gkr_layers.len;
        const targets = [_]*QM31{ &proof.gkr_roots[0], &proof.gkr_layers[0].hats[2], &proof.gkr_layers[L - 1].hats[0], &proof.gkr_layers[L / 2].rounds[0][0], &proof.gkr_layers[L / 2].u_val, &proof.gkr_layers[L / 2].hats[4], &proof.gkr_layers[0].hats[4], &proof.gkr_layers[3].sigma };
        for (targets) |ptr| {
            ptr.* = ptr.*.add(one);
            try std.testing.expect(std.meta.isError(verify(a, cfg, st, key, &proof)));
            ptr.* = ptr.*.sub(one);
        }
        try verify(a, cfg, st, key, &proof);
    }
    // tamper: weight opening row
    proof.weight_opening.?.rows[0][1] = proof.weight_opening.?.rows[0][1].add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, key, &proof)));
    proof.weight_opening.?.rows[0][1] = proof.weight_opening.?.rows[0][1].sub(QM31.one());
    // statement change (shift) and wrong weight root are rejected
    const ops2 = try a.dupe(proto.Op, st.ops);
    defer a.free(ops2);
    ops2[1].matmul.shift += 1;
    var st2 = st;
    st2.ops = ops2;
    try std.testing.expect(std.meta.isError(verify(a, cfg, st2, key, &proof)));
    var key2 = key;
    key2.root[3] ^= 1;
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, key2, &proof)));
    try verify(a, cfg, st, key, &proof);
    // budget: 32 distinct columns; proximity used <= 8, each proof <= 8 more
    var n_ok: usize = 1;
    while (n_ok < 10) : (n_ok += 1) {
        var p = prove(a, &pool, cfg, st, &zw, wv, &tm) catch |e| {
            try std.testing.expectEqual(error.OpeningBudgetExceeded, e);
            break;
        };
        defer p.deinit(a);
        try verify(a, cfg, st, key, &p);
    }
    try std.testing.expect(n_ok >= 3 and n_ok < 10);
    const used = zw.budgetUsed();
    try std.testing.expect(used[0] <= used[1]);
    // a wrong forward value is refused by the prover
    built.witness[5][3] += 1;
    try std.testing.expect(std.meta.isError(prove(a, &pool, cfg, st, &zw, wv, &tm)));
    built.witness[5][3] -= 1;

    // committed-inverse LogUp mode still proves and verifies; modes are not interchangeable
    {
        var cfgi = cfg;
        cfgi.zk_logup_gkr = false;
        var zwi = try commitWeights(a, &pool, cfgi, &winfos, &wvv);
        defer zwi.deinit(a);
        var pi = try prove(a, &pool, cfgi, st, &zwi, wv, &tm);
        defer pi.deinit(a);
        try verify(a, cfgi, st, zwi.key(), &pi);
        try std.testing.expect(pi.root2 != null and pi.gkr_layers.len == 0);
        try std.testing.expect(std.meta.isError(verify(a, cfg, st, zwi.key(), &pi)));
        pi.checks[pi.checks.len - 1].rounds[0][0] = pi.checks[pi.checks.len - 1].rounds[0][0].add(QM31.one());
        try std.testing.expect(std.meta.isError(verify(a, cfgi, st, zwi.key(), &pi)));
    }

    // re-randomized weights with a link proof: new commitment serves new proofs
    {
        var zw0 = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zw0.deinit(a);
        var rr = try rerandomizeWeights(a, &pool, cfg, &zw0);
        defer rr.new.deinit(a);
        defer rr.link.deinit(a);
        try verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link);
        try std.testing.expect(!std.mem.eql(u8, &zw0.key().root, &rr.new.key().root));
        var pn = try prove(a, &pool, cfg, st, &rr.new, wv, &tm);
        defer pn.deinit(a);
        try verify(a, cfg, st, rr.new.key(), &pn);
        // tampered link / swapped roots rejected
        rr.link.opening.rows[0][0] = rr.link.opening.rows[0][0].add(QM31.one());
        try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link)));
        rr.link.opening.rows[0][0] = rr.link.opening.rows[0][0].sub(QM31.one());
        try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, rr.new.key(), zw0.key(), rr.link)));
        // a link between commitments of different weights is rejected
        const other = try model.randomWeights(a, winfos[1].size(), 999, -8, 7);
        defer a.free(other);
        const wvo = [_][]const i8{ wdata[0], other, wdata[2] };
        var zo = try commitWeights(a, &pool, cfg, &winfos, &wvo);
        defer zo.deinit(a);
        var bad = try proveWeightLink(a, &pool, cfg, &zw0, &zo);
        defer bad.deinit(a);
        try std.testing.expectError(error.OpeningEvalMismatch, verifyWeightLink(a, cfg, zw0.key(), zo.key(), bad));
    }

    // separate weight PCS parameters (higher blowup, fewer queries, larger budget)
    var cfg2 = cfg;
    cfg2.weight_pcs = .{ .log_blowup = 3, .n_queries = 6, .pow_bits = 1 };
    cfg2.weight_mask_slots = 64;
    var zw2 = try commitWeights(a, &pool, cfg2, &winfos, &wvv);
    defer zw2.deinit(a);
    var prox2 = try proveWeightProximity(a, &pool, cfg2, &zw2);
    defer prox2.deinit(a);
    try verifyWeightProximity(a, cfg2, zw2.key(), prox2);
    var proof3 = try prove(a, &pool, cfg2, st, &zw2, wv, &tm);
    defer proof3.deinit(a);
    try verify(a, cfg2, st, zw2.key(), &proof3);
    // the verifier must use the same weight parameters
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, zw2.key(), &proof3)));
    try std.testing.expectEqual(@as(usize, 6), proof3.weight_opening.?.tables[0].salts.len);
}

// Best-effort statistical sanity check: everything a verifier sees from the
// witness opening of an all-zero witness and of a uniformly random witness
// should look like uniform field elements (with no masking, the all-zero
// witness gives all-zero data columns and zero final values).
test "zk statistical sanity: opened values of zero vs random witness look uniform" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var cfg = testCfg();
    cfg.pcs.n_queries = 16;
    var stats: [2][3]f64 = undefined;
    for (0..2) |case| {
        var built = try model.buildProduct(a, 10, 21);
        defer built.deinit(a);
        if (case == 0) for (built.witness) |w| @memset(w, 0);
        const st = built.statement();
        const wv = try wview(a, built.witness);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        var n_vals: f64 = 0;
        var top: f64 = 0;
        var zeros: f64 = 0;
        var mean: f64 = 0;
        for (0..4) |_| {
            var proof = try prove(a, &pool, cfg, st, null, wv, &tm);
            defer proof.deinit(a);
            try verify(a, cfg, st, null, &proof);
            // opened columns (all rows), combined rows, hats
            const Acc = struct {
                fn add(n: *f64, t: *f64, z: *f64, m: *f64, v: u32) void {
                    n.* += 1;
                    if (v >= f.P / 2) t.* += 1;
                    if (v == 0) z.* += 1;
                    m.* += @as(f64, @floatFromInt(v)) / @as(f64, @floatFromInt(f.P));
                }
            };
            for (proof.opening.tables[0].values) |v| Acc.add(&n_vals, &top, &zeros, &mean, v.v);
            for (proof.opening.rows) |r| for (r) |q| for (f.limbs(q)) |l| Acc.add(&n_vals, &top, &zeros, &mean, l);
            for (proof.checks[0].hats) |q| for (f.limbs(q)) |l| Acc.add(&n_vals, &top, &zeros, &mean, l);
            for (proof.batch.hats) |q| for (f.limbs(q)) |l| Acc.add(&n_vals, &top, &zeros, &mean, l);
        }
        stats[case] = .{ top / n_vals, zeros / n_vals, mean / n_vals };
    }
    for (stats) |s| {
        try std.testing.expect(@abs(s[0] - 0.5) < 0.02);
        try std.testing.expect(s[1] < 0.001);
        try std.testing.expect(@abs(s[2] - 0.5) < 0.02);
    }
    try std.testing.expect(@abs(stats[0][0] - stats[1][0]) < 0.03);
    try std.testing.expect(@abs(stats[0][2] - stats[1][2]) < 0.03);
}

// Same sanity check for the hiding GKR and the op checks of an MLP: an all-zero
// input (every activation, remainder pattern and key multiset degenerate) vs a
// random input. GKR roots, all layer hats (incl. Q values) and op-check hats
// should look uniform in both cases.
test "zk statistical sanity: MLP GKR / sumcheck values for zero vs random input" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var cfg = testCfg();
    cfg.weight_mask_slots = 64;
    cfg.weight_pcs = .{ .log_blowup = 3, .n_queries = 4, .pow_bits = 1 };
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7 };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 300 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var stats: [2][2]f64 = undefined;
    for (0..2) |case| {
        const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 77);
        defer a.free(x);
        if (case == 0) @memset(x, 0);
        var n_vals: f64 = 0;
        var top: f64 = 0;
        var mean: f64 = 0;
        for (0..3) |_| {
            var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
            defer zw.deinit(a);
            const pv = zw.plainView();
            var built = try model.buildMlp(a, &pool, &pv, mc, x);
            defer built.deinit(a);
            const st = built.statement();
            const wv = try wview(a, built.witness);
            defer a.free(wv);
            var tm: proto.Timings = .{};
            var proof = try prove(a, &pool, cfg, st, &zw, wv, &tm);
            defer proof.deinit(a);
            try verify(a, cfg, st, zw.key(), &proof);
            var vals: std.ArrayList(QM31) = .empty;
            defer vals.deinit(a);
            try vals.appendSlice(a, proof.gkr_roots);
            for (proof.gkr_layers, 0..) |l, li| {
                // layer 1 of each tree has Q = 0 by construction
                for (l.hats, 0..) |h, hi| if (!(hi == 4 and h.isZero())) try vals.append(a, h);
                _ = li;
                try vals.append(a, l.sigma);
            }
            for (proof.checks) |c| try vals.appendSlice(a, c.hats);
            for (vals.items) |q| for (f.limbs(q)) |l| {
                n_vals += 1;
                if (l >= f.P / 2) top += 1;
                mean += @as(f64, @floatFromInt(l)) / @as(f64, @floatFromInt(f.P));
            };
        }
        stats[case] = .{ top / n_vals, mean / n_vals };
    }
    for (stats) |s| {
        try std.testing.expect(@abs(s[0] - 0.5) < 0.04);
        try std.testing.expect(@abs(s[1] - 0.5) < 0.04);
    }
    try std.testing.expect(@abs(stats[0][0] - stats[1][0]) < 0.05);
}
