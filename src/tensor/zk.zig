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
const canonical = @import("canonical.zig");
const pcs = @import("pcs.zig");
const zkp = @import("zk_pcs.zig");
const zkp2 = @import("zk_pcs2.zig");
const pcs2 = @import("pcs2.zig");
const zks = @import("zk_sumcheck.zig");
const proto = @import("protocol.zig");
const linalg = @import("linalg.zig");
const xt = @import("ext.zig");
const accel = @import("accel.zig");
const Transcript = @import("transcript.zig").Transcript;
const core = @import("stwo_core");

const M31 = f.M31;
const QM31 = f.QM31;
const TensorInfo = proto.TensorInfo;
const Statement = proto.Statement;
const Hash = [32]u8;
const NONE: u32 = std.math.maxInt(u32);
const PAD_LOG: u32 = 4;
const WPAD_ROWS: usize = 4; // 2 row variables
const N_MASK_ROWS: u32 = 3; // log2(8) mask rows in table 1 (proximity, group A)

// Aux table (per proof): row 0 = batch hiding-polynomial coefficients,
// rows 1..4 proximity masks, rows 5..8 group masks; 256 columns.
const AUX_LC: u32 = 8;
const AUX_LB: u32 = 4;
const AUX_ROWS: usize = 9;

/// Aux-table opening parameters: no grinding, queries for >= 128 conjectured bits.
pub fn auxParams() struct { params: pcs.Params, slots: u32 } {
    var q: usize = 1;
    while (true) : (q += 1) {
        const s = zkp.slotsFor(q);
        const e: f64 = @floatFromInt(@as(u64, 1) << (AUX_LC + AUX_LB));
        const bits = std.math.log2(e / @as(f64, @floatFromInt((@as(u64, 1) << AUX_LC) + s)));
        if (@as(f64, @floatFromInt(q)) * bits >= 128.0) return .{ .params = .{ .log_blowup = AUX_LB, .n_queries = q, .pow_bits = 0 }, .slots = s };
    }
}

fn auxShape() zkp.Shape {
    return .{ .log_cols = AUX_LC, .log_blowup = AUX_LB, .slots = auxParams().slots, .n_rows = AUX_ROWS };
}

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

const RelKind = union(enum) { range: u5, act: u32, glu: struct { table: u32, shift: u5 }, ext_lookup: u32 };
const Rel = struct { kind: RelKind, log_size: u32, mult: u32 };
/// `.ext`: an ext-op key (`op` indexes `plan.xkeys`): einsum remainder (virtual),
/// einsum output range, or a linear-expression key (ext.zig).
const KeyKind = enum { remainder, y_range, plain_range, lookup_pair, glu_triple, ext };
const Key = struct { kind: KeyKind, op: u32, log_size: u32, rel: u32, h: u32 };
const CheckKind = enum { product, hadamard, matmul, key, matmul_v, hadamard_v, einsum_v, einsum_x };
/// A masked sumcheck. `matmul_v` / `hadamard_v` (virtual remainders) run after the
/// GKR at their remainder leaf point: `key` is the remainder key, `apad` the
/// 16-cell pad of the accumulator hat, `tree` the GKR tree holding the key.
const Check = struct { kind: CheckKind, idx: u32, n: u32, deg: u32, u: u32, key: u32 = 0, apad: u32 = 0, tree: u32 = 0 };
const Lay = struct { offsets: []usize, log_total: u32, used: usize };
/// One layer k (1..n) of a hiding GKR tree: its hiding polynomial and the pads of its 4 finals.
const GLayer = struct { u: u32, pads: [4]u32 };
const SegKind = enum { key, table, blinder };
/// A leaf segment: a key instance, a relation's table, or the blinder leaf.
const Seg = struct { kind: SegKind, idx: u32, rel: u32 };
const GRel = struct {
    /// log2 of the number of leaves
    n: u32,
    segs: []Seg,
    seg_off: []usize,
    seg_log: []u32,
    blinder: u32,
    layers: []GLayer,
    /// several relations in one tree, separated by tags tau * rel_index
    tagged: bool,
};

/// Tag shift tau * rel of a relation inside a tagged tree.
fn relTag(g: GRel, tau: QM31, rel: u32) QM31 {
    return if (g.tagged) tau.mul(qi(rel)) else QM31.zero();
}

const Plan = struct {
    nw: u32,
    rem: []u32,
    rels: []Rel,
    keys: []Key,
    checks: []Check,
    /// hiding LogUp-GKR trees (one per relation), empty in committed-inverse mode
    grels: []GRel,
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
    /// virtual remainders: post-GKR checks in (tree, segment) order
    virt: bool = false,
    vchecks: []Check = &.{},
    /// GKR tree of each op's remainder key (virtual mode, NONE otherwise)
    op_tree: []u32 = &.{},
    /// ext ops: derived keys and the exact-einsum checks (run after the virtual checks)
    xkeys: []xt.Key = &.{},
    xchecks: []Check = &.{},

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

/// Witness column split of the recursive hiding mode: minimizes the predicted
/// opening bytes (outer columns + committed-row levels, zk_pcs2.predictBytes)
/// over 2^lc >= slots, with the committed-row encoding (2 rows x 4 limbs x 2C
/// coefficients at the inner blowup) bounded by the table size as in pcs2
/// (`inner_work_shift`). A deterministic function of public sizes.
fn recLogCols(cfg: proto.Config, p2: pcs2.Params, used0: usize, log_total: u32, slots: u32) u32 {
    const lo = log2Ceil(slots);
    var best_lc = lo;
    var best = std.math.inf(f64);
    var l = lo;
    while (l <= @max(lo, log_total + 1)) : (l += 1) {
        const C = @as(usize, 1) << @intCast(l);
        const used = used0 + 9 * C; // + batch pad row and 8 mask rows
        const rows = (used + C - 1) / C;
        const budget = @max(used >> @intCast(p2.inner_work_shift), @as(usize, 1) << 14);
        if (l > lo and ((8 * C) << @intCast(p2.inner.log_blowup)) > budget) break;
        const b = zkp2.predictBytes(cfg.pcs, p2, rows, l, 2);
        if (b < best) {
            best = b;
            best_lc = l;
        }
    }
    return best_lc;
}

/// Column split (log2) and slots of the witness tables for a statement (both sides).
pub fn witnessShape(a: std.mem.Allocator, cfg: proto.Config, st: Statement, wkey: ?WeightKey) !struct { log_cols: u32, slots: u32 } {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const plan = try makePlan(arena_state.allocator(), st, wkey, cfg);
    return .{ .log_cols = plan.lc, .slots = plan.slots };
}

/// PCS parameters of the (committed-once) hiding weight table.
pub fn wpcs(cfg: proto.Config) pcs.Params {
    return cfg.weight_pcs orelse cfg.pcs;
}

fn uLog(n: u32, deg: u32) u32 {
    return log2Ceil(zks.Hp.entries(n, deg) * 4);
}

fn findRel(rels: *std.ArrayList(Rel), a: std.mem.Allocator, inf1: *std.ArrayList(TensorInfo), kind: RelKind) !u32 {
    return findRelX(rels, a, inf1, kind, .{});
}

fn findRelX(rels: *std.ArrayList(Rel), a: std.mem.Allocator, inf1: *std.ArrayList(TensorInfo), kind: RelKind, x: xt.Ext) !u32 {
    for (rels.items, 0..) |r, i| if (std.meta.eql(r.kind, kind)) return @intCast(i);
    const log_size: u32 = switch (kind) {
        .range => |s| @max(@as(u32, s), 1),
        .act => 8,
        .glu => 16,
        .ext_lookup => |id| @max(@as(u32, x.tables[id].log_size), 1),
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
    // the statement's weight shapes must be those of the weight key
    if (wkey) |wk| {
        if (st.weights.len != wk.infos.len) return error.StatementShape;
        for (st.weights, wk.infos) |x, y| if (!std.meta.eql(x.log_dims, y.log_dims) or x.n_dims != y.n_dims) return error.StatementShape;
    }
    try inf1.appendSlice(a, st.witness);
    const virt = cfg.zk_virtual_remainders;
    if (virt and !cfg.zk_logup_gkr) return error.ZkVirtualNeedsGkr;
    const rem = try a.alloc(u32, st.ops.len);
    @memset(rem, NONE);
    if (!virt) for (st.ops, 0..) |op, i| switch (op) {
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
            .glu => |g| {
                // fused gated activation: one LogUp key (g, u, h) into the public
                // 2^16-entry table {(vg, vu, glu(vg, vu))}; it also range-checks g and u.
                if (g.table >= st.tables.len or g.shift == 0) return error.StatementShape;
                const lsz = st.witness[g.h].logSize();
                if (st.witness[g.g].logSize() != lsz or st.witness[g.u].logSize() != lsz) return error.StatementShape;
                try keys.append(a, .{ .kind = .glu_triple, .op = oi, .log_size = lsz, .rel = try findRel(&rels, a, &inf1, .{ .glu = .{ .table = g.table, .shift = g.shift } }), .h = 0 });
            },
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
                    .glu => |g2| implied = implied or g2.g == opY(op) or g2.u == opY(op),
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
    // ext ops: validated, their keys appended after the core keys (masked GKR only;
    // requant-einsum remainders are always virtual)
    var xkeys: []xt.Key = &.{};
    if (!st.ext.isEmpty()) {
        try xt.validate(st);
        if (!cfg.zk_logup_gkr) return error.ZkVirtualNeedsGkr;
        xkeys = try xt.deriveKeys(a, st.ext);
        for (xkeys, 0..) |xk, xi| {
            const kind: RelKind = switch (xk.table) {
                .range => |b| .{ .range = b },
                .lookup => |id| .{ .ext_lookup = id },
            };
            try keys.append(a, .{ .kind = .ext, .op = @intCast(xi), .log_size = xk.log_size, .rel = try findRelX(&rels, a, &inf1, kind, st.ext), .h = 0 });
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
                if (!virt) try checks.append(a, .{ .kind = .hadamard, .idx = oi, .n = lsz, .deg = 3, .u = 0 });
            },
            .matmul => |m| {
                const wk = wkey orelse return error.StatementShape;
                if (m.w >= wk.infos.len) return error.StatementShape;
                const xi = st.witness[m.x];
                const wi = wk.infos[m.w];
                const yi = st.witness[m.y];
                if (xi.n_dims != 2 or wi.log_dims[0] != xi.log_dims[1] or yi.logSize() != xi.log_dims[0] + wi.log_dims[1]) return error.StatementShape;
                if (xi.log_dims[1] < 2) return error.StatementShape;
                const n = @max(xi.log_dims[1], yi.logSize());
                if (!virt) try checks.append(a, .{ .kind = .matmul, .idx = oi, .n = n, .deg = 2, .u = 0 });
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
    if (gkr and rels.items.len > 0) {
        // Trees: one per relation, or all relations in one tagged tree if that pads less
        // (key counts are powers of two, so table + blinder leaves often double a tree).
        var sep_leaves: usize = 0;
        for (rels.items, 0..) |rel, ri| {
            var cnt: usize = 1 + (@as(usize, 1) << @intCast(rel.log_size));
            for (keys.items) |k| if (k.rel == ri) {
                cnt += @as(usize, 1) << @intCast(k.log_size);
            };
            sep_leaves += std.math.ceilPowerOfTwo(usize, cnt) catch unreachable;
        }
        var all: usize = 1;
        for (rels.items) |rel| all += @as(usize, 1) << @intCast(rel.log_size);
        for (keys.items) |k| all += @as(usize, 1) << @intCast(k.log_size);
        const merged = rels.items.len > 1 and (std.math.ceilPowerOfTwo(usize, all) catch unreachable) < sep_leaves;
        const n_trees: usize = if (merged) 1 else rels.items.len;
        for (0..n_trees) |ti| {
            var segs: std.ArrayList(Seg) = .empty;
            var sizes: std.ArrayList(TensorInfo) = .empty;
            for (keys.items, 0..) |k, ki| if (merged or k.rel == ti) {
                try segs.append(a, .{ .kind = .key, .idx = @intCast(ki), .rel = k.rel });
                try sizes.append(a, TensorInfo.vec(k.log_size));
            };
            for (rels.items, 0..) |rel, ri| if (merged or ri == ti) {
                try segs.append(a, .{ .kind = .table, .idx = @intCast(ri), .rel = @intCast(ri) });
                try sizes.append(a, TensorInfo.vec(rel.log_size));
            };
            try segs.append(a, .{ .kind = .blinder, .idx = 0, .rel = 0 });
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
            try grels.append(a, .{ .n = n, .segs = try segs.toOwnedSlice(a), .seg_off = lay.offsets, .seg_log = seg_log, .blinder = blinder, .layers = layers, .tagged = merged });
        }
    }
    // virtual remainders: one post-GKR check per remainder key, in (tree, segment) order
    var vchecks: std.ArrayList(Check) = .empty;
    const op_tree = try a.alloc(u32, st.ops.len);
    @memset(op_tree, NONE);
    for (grels.items, 0..) |g, ti| for (g.segs) |sg| {
        if (sg.kind != .key) continue;
        const k = keys.items[sg.idx];
        if (k.kind == .ext and xkeys[k.op].kind == .remainder) {
            const lay = xt.Layout.init(st.ext.ops[xkeys[k.op].op].einsum);
            var c: Check = .{ .kind = .einsum_v, .idx = xkeys[k.op].op, .n = lay.ns, .deg = 3, .u = 0, .key = sg.idx, .tree = @intCast(ti) };
            c.u = @intCast(inf1.items.len);
            try inf1.append(a, TensorInfo.vec(uLog(c.n, c.deg)));
            c.apad = @intCast(inf1.items.len);
            try inf1.append(a, TensorInfo.vec(PAD_LOG));
            try vchecks.append(a, c);
            continue;
        }
        if (!virt or k.kind != .remainder) continue;
        const op = st.ops[k.op];
        var c: Check = .{ .kind = .hadamard_v, .idx = k.op, .n = k.log_size, .deg = 3, .u = 0, .key = sg.idx, .tree = @intCast(ti) };
        if (op == .matmul) {
            c.kind = .matmul_v;
            c.n = st.witness[op.matmul.x].log_dims[1];
            c.deg = 2;
        }
        c.u = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(uLog(c.n, c.deg)));
        c.apad = @intCast(inf1.items.len);
        try inf1.append(a, TensorInfo.vec(PAD_LOG));
        op_tree[k.op] = @intCast(ti);
        try vchecks.append(a, c);
    };
    // exact einsums: masked output hat + sumcheck at a fresh point
    var xchecks: std.ArrayList(Check) = .empty;
    for (st.ext.ops, 0..) |xop, oi| switch (xop) {
        .einsum => |e| if (e.shift == 0) {
            const lay = xt.Layout.init(e);
            var c: Check = .{ .kind = .einsum_x, .idx = @intCast(oi), .n = lay.ns, .deg = 3, .u = 0 };
            c.u = @intCast(inf1.items.len);
            try inf1.append(a, TensorInfo.vec(uLog(c.n, c.deg)));
            c.apad = @intCast(inf1.items.len);
            try inf1.append(a, TensorInfo.vec(PAD_LOG));
            try xchecks.append(a, c);
        },
        else => {},
    };
    const has2 = !gkr and keys.items.len > 0;
    // column split from table 1 without the C-dependent tensors
    const est = try proto.layout(a, inf1.items, &.{});
    var lc: u32 = (est.log_total + 3) / 2;
    if (lc > cfg.witness_log_cols_max) lc = cfg.witness_log_cols_max;
    const slots = zkp.slotsFor(cfg.pcs.n_queries);
    lc = @max(lc, log2Ceil(slots));
    if (try zk2(cfg)) |p2| lc = recLogCols(cfg, p2, est.used, est.log_total, slots);
    {
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
        if (zks.Hp.entries(N, 2) * 4 > (@as(usize, 1) << AUX_LC)) return error.StatementShape;
        return .{
            .nw = nw,
            .rem = rem,
            .rels = try rels.toOwnedSlice(a),
            .keys = try keys.toOwnedSlice(a),
            .checks = try checks.toOwnedSlice(a),
            .grels = grels.items,
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
            .virt = virt,
            .vchecks = try vchecks.toOwnedSlice(a),
            .op_tree = op_tree,
            .xkeys = xkeys,
            .xchecks = try xchecks.toOwnedSlice(a),
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

/// Operand point of an ext einsum factor: rho on folded output vars, the sumcheck point elsewhere.
const LabMap = struct { labels: xt.Labels, nb: u32, rho: []const QM31, lay: xt.Layout };
const Part = struct { table: u8, id: u32, coeff: QM31, prefix: []const QM31 = &.{}, suffix: []const QM31 = &.{}, weight: bool = false, lab: ?LabMap = null };
/// A public ext tensor read at a label point.
const PubMle = struct { id: u32, lab: LabMap };
const FSpec = struct {
    public: bool = false,
    pub_point: []const QM31 = &.{},
    konst: QM31 = QM31.zero(),
    parts: []const Part = &.{},
    /// number of trailing sumcheck coordinates used by this factor (top-zero-extension below)
    m: u32,
    /// Q factor of a virtual-remainder check: Q(x) = [x_head = 0] P(qlead, x_tail) for the
    /// 16-cell pad `qpad`; its hat is its own value (a pad functional, no data part)
    qpad: ?u32 = null,
    qlead: []const QM31 = &.{},
    /// public eq over the leading pub_point.len sumcheck coordinates (einsum batch vars)
    pub_prefix: bool = false,
    /// public ext operand
    pub_mle: ?PubMle = null,
};

/// Value of a public factor at the sumcheck point r (verifier).
fn publicValue(a: std.mem.Allocator, st: Statement, sp: FSpec, r: []const QM31) !QM31 {
    if (sp.pub_mle) |pm| return xt.publicMle(a, st.ext, pm.id, try pm.lab.lay.operandPoint(a, pm.lab.labels, pm.lab.nb, pm.lab.rho, r));
    if (sp.pub_prefix) return f.eqEval(sp.pub_point, r[0..sp.pub_point.len]);
    return zeroExtScale(r, sp.m).mul(f.eqEval(sp.pub_point, r[r.len - sp.m ..]));
}

/// Pad point of a hatted part: the last plog coordinates of its local point, or for
/// label-driven (ext) parts of (local ++ r), so that every hat's pad point carries
/// fresh sumcheck coordinates.
fn padPoint(a: std.mem.Allocator, p: Part, loc: []const QM31, r: []const QM31, plog: u32) ![]const QM31 {
    if (p.lab == null) return loc[loc.len - plog ..];
    const cat = try a.alloc(QM31, loc.len + r.len);
    @memcpy(cat[0..loc.len], loc);
    @memcpy(cat[loc.len..], r);
    return cat[cat.len - plog ..];
}

/// Q~(r) of a Q factor: eq(r_head, 0) * P~(qlead, r_tail).
fn qPoint(a: std.mem.Allocator, sp: FSpec, r: []const QM31) !struct { scale: QM31, pt: []QM31 } {
    const mp = 4 - sp.qlead.len;
    const pt = try a.alloc(QM31, 4);
    @memcpy(pt[0..sp.qlead.len], sp.qlead);
    @memcpy(pt[sp.qlead.len..], r[r.len - mp ..]);
    return .{ .scale = zeroExtScale(r, @intCast(mp)), .pt = pt };
}

fn zeroExtScale(r: []const QM31, m: u32) QM31 {
    var s = QM31.one();
    for (r[0 .. r.len - m]) |x| s = s.mul(QM31.one().sub(x));
    return s;
}

fn localPoint(a: std.mem.Allocator, p: Part, r: []const QM31, m: u32) ![]QM31 {
    if (p.lab) |l| return l.lay.operandPoint(a, l.labels, l.nb, l.rho, r);
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
        if (sp.qpad) |qp| {
            const q = try qPoint(a, sp, r);
            const terms = try a.alloc(LTerm, 1);
            terms[0] = .{ .table = 0, .id = qp, .coeff = q.scale, .form = .{ .eq = q.pt } };
            try claims.append(a, .{ .terms = terms, .value = hat });
            continue;
        }
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
            terms[2 * pi + 1] = .{ .table = p.table, .id = pid, .coeff = p.coeff.mul(g), .form = .{ .eq = try padPoint(a, p, loc, r, plog) } };
        }
        try claims.append(a, .{ .terms = terms, .value = hat.sub(sp.konst) });
    }
}

fn keyFactorD(a: std.mem.Allocator, plan: Plan, st: Statement, k: Key, alpha: QM31, beta: QM31, n: u32) !FSpec {
    if (k.kind == .ext) return error.StatementShape; // ext keys: GKR leaf claims only
    const op = st.ops[k.op];
    var parts: []Part = undefined;
    var konst = alpha;
    switch (k.kind) {
        .ext => unreachable,
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
        .glu_triple => {
            parts = try a.alloc(Part, 3);
            parts[0] = .{ .table = 0, .id = op.glu.g, .coeff = qi(-1) };
            parts[1] = .{ .table = 0, .id = op.glu.u, .coeff = beta.neg() };
            parts[2] = .{ .table = 0, .id = op.glu.h, .coeff = beta.mul(beta).neg() };
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
        .matmul_v, .hadamard_v, .einsum_v, .einsum_x => unreachable, // vcheckSpecs
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

/// A virtual remainder after its GKR tree: leaf point of the remainder key,
/// accumulator-pad point and the accumulator hat A^ = acc~(local) + P_A~(t_a).
const VRem = struct { local: []const QM31, t_a: [4]QM31, ahat: QM31 };

/// Factor specs of a virtual-remainder check at its GKR leaf point (both sides).
fn vcheckSpecs(a: std.mem.Allocator, st: Statement, wkey: ?WeightKey, c: Check, vr: VRem) ![]FSpec {
    const n = c.n;
    const qs = qShape(n, &vr.t_a);
    const et = try etPoint(a, n, qs);
    const lead = try a.dupe(QM31, qs.t_lead);
    switch (c.kind) {
        .matmul_v => {
            const m = st.ops[c.idx].matmul;
            const wk = wkey orelse return error.StatementShape;
            const lt = st.witness[m.x].log_dims[0];
            const sp = try a.alloc(FSpec, 4);
            sp[0] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = m.x, .coeff = QM31.one(), .prefix = vr.local[0..lt] }}), .m = n };
            sp[1] = .{ .parts = try a.dupe(Part, &.{.{ .table = 2, .id = m.w, .coeff = QM31.one(), .suffix = vr.local[lt..], .weight = true }}), .m = n };
            _ = wk;
            sp[2] = .{ .public = true, .pub_point = et, .m = n };
            sp[3] = .{ .qpad = c.apad, .qlead = lead, .m = n };
            return sp;
        },
        .einsum_v, .einsum_x => {
            // eq(rho_B, r_B) * A'(r) * B'(r) + et * Q   (rho = vr.local: the leaf point / fresh point)
            const e = st.ext.ops[c.idx].einsum;
            const lay = xt.Layout.init(e);
            const sp = try a.alloc(FSpec, 5);
            const bpt = try a.alloc(QM31, lay.n_batch);
            for (bpt, 0..) |*x, i| x.* = vr.local[lay.batch[i]];
            sp[0] = .{ .public = true, .pub_point = bpt, .pub_prefix = true, .m = n };
            inline for (.{ .{ e.a, e.a_labels, 1 }, .{ e.b, e.b_labels, 2 } }) |op| {
                const ref: xt.Ref = op[0];
                const lm = LabMap{ .labels = op[1], .nb = try xt.refBits(st, ref), .rho = vr.local, .lay = lay };
                sp[op[2]] = if (ref.public)
                    .{ .public = true, .pub_mle = .{ .id = ref.id, .lab = lm }, .m = n }
                else
                    .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = ref.id, .coeff = QM31.one(), .lab = lm }}), .m = n };
            }
            sp[3] = .{ .public = true, .pub_point = et, .m = n };
            sp[4] = .{ .qpad = c.apad, .qlead = lead, .m = n };
            return sp;
        },
        .hadamard_v => {
            const h = st.ops[c.idx].hadamard;
            const sp = try a.alloc(FSpec, 5);
            sp[0] = .{ .public = true, .pub_point = vr.local, .m = n };
            sp[1] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = h.a, .coeff = QM31.one() }}), .m = n };
            sp[2] = .{ .parts = try a.dupe(Part, &.{.{ .table = 0, .id = h.b, .coeff = QM31.one() }}), .m = n };
            sp[3] = .{ .public = true, .pub_point = et, .m = n };
            sp[4] = .{ .qpad = c.apad, .qlead = lead, .m = n };
            return sp;
        },
        else => unreachable,
    }
}

/// Verifier side of one masked check: sumcheck, final-value check from the hats and
/// public factors, then the hats' linear claims.
fn verifyCheck(ar: std.mem.Allocator, tr: *Transcript, plan: Plan, st: Statement, c: Check, specs: []const FSpec, claim: QM31, cp: zks.MaskedProof, claims: *std.ArrayList(LClaim), wclaims: *std.ArrayList(WClaim), wkey: ?WeightKey) !void {
    var n_hats: usize = 0;
    for (specs) |s| n_hats += @intFromBool(!s.public);
    const vo = try zks.verify(ar, tr, claim, c.n, @intCast(c.deg), n_hats, cp);
    const r = vo.point[0..c.n];
    var vals: [5]QM31 = undefined;
    var hi: usize = 0;
    for (specs, 0..) |s, j| {
        if (s.public) {
            vals[j] = try publicValue(ar, st, s, r);
        } else {
            if (hi >= cp.hats.len) return error.ProofShape;
            vals[j] = cp.hats[hi];
            hi += 1;
        }
    }
    if (!vo.final_claim.eql(cp.u_val.add(vo.eps.mul(evalCheckTerms(c.kind, vals[0..nSpecs(c.kind)]))))) return error.MaskedSumcheck;
    try checkClaims(ar, plan, specs, c.u, c.n, c.deg, vo.point, cp, claims, wclaims, wkey);
}

fn checkClaim(st: Statement, c: Check) QM31 {
    return switch (c.kind) {
        .product => QM31.zero(),
        .hadamard, .matmul => qi(-shiftHalf(opShift(st.ops[c.idx]))),
        .key => QM31.one(),
        .matmul_v, .hadamard_v, .einsum_v, .einsum_x => unreachable, // claim = the accumulator / output hat

    };
}

const T_PRODUCT = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 3 } } };
const T_HAD = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 3 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 4 } } };
const T_MM = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 3 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 4 } } };
const T_KEY = [_]zks.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
/// virtual-remainder checks: X W + et Q  /  eq a b + et Q
const T_MMV = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 3 } } };
const T_HADV = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 3, 4 } } };
const T_B2 = [_]zks.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_B4 = [_]zks.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }, .{ .coeff = QM31.one(), .factors = &[_]u8{ 2, 3 } } };

fn evalCheckTerms(kind: CheckKind, vals: []const QM31) QM31 {
    return switch (kind) {
        .product => zks.evalTermsRt(&T_PRODUCT, 4, vals[0..4].*),
        .hadamard => zks.evalTermsRt(&T_HAD, 5, vals[0..5].*),
        .matmul => zks.evalTermsRt(&T_MM, 5, vals[0..5].*),
        .key => zks.evalTermsRt(&T_KEY, 3, vals[0..3].*),
        .matmul_v => zks.evalTermsRt(&T_MMV, 4, vals[0..4].*),
        .hadamard_v, .einsum_v, .einsum_x => zks.evalTermsRt(&T_HADV, 5, vals[0..5].*),
    };
}

fn nSpecs(kind: CheckKind) usize {
    return switch (kind) {
        .product, .matmul_v => 4,
        .hadamard, .matmul, .hadamard_v, .einsum_v, .einsum_x => 5,
        .key => 3,
    };
}

// ---------------------------------------------------------------------------
// Prover randomness.

/// Test builds only: fixed prover randomness, for CPU / device proof-equality tests.
/// Ignored outside test builds: production proofs always draw fresh OS entropy
/// (zk.md §1), and the proving API has no seed parameter.
pub var test_rng_seed: ?[32]u8 = null;
var test_rng_ctr: u8 = 0;

/// Sets (or clears) the test seed and restarts its stream counter.
pub fn setTestSeed(seed: ?[32]u8) void {
    test_rng_seed = seed;
    test_rng_ctr = 0;
}

fn proverRng() zkp.Rng {
    if (@import("builtin").is_test) if (test_rng_seed) |sd| {
        var x = sd;
        x[31] ^= test_rng_ctr;
        test_rng_ctr +%= 1;
        return zkp.Rng.initSeed(x);
    };
    return zkp.Rng.initOs();
}

// ---------------------------------------------------------------------------
// Openings: flat (zk_pcs: combined rows sent) or recursive (zk_pcs2: combined
// rows committed and opened with pcs2 levels; selected by `Config.two_level`).

pub const Opening = union(enum) {
    flat: zkp.Opening,
    rec: zkp2.Opening,

    pub fn deinit(self: *Opening, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*o| o.deinit(a),
        }
    }
    pub fn byteSize(self: Opening) usize {
        return switch (self) {
            inline else => |o| o.byteSize(),
        };
    }
};

/// Recursive hiding PCS parameters, or null for the flat hiding PCS.
/// The non-hiding pcs2's beyond-unique-decoding extensions (`Params.ood`,
/// `Params.deep`, security.md 3.4/3.5) are refused here: the hiding outer
/// tables carry no OOD sample (an unmasked OOD answer would reveal a witness
/// MLE value), so the Johnson-regime argument does not apply to zk_pcs2, and
/// its soundness claims stay those of zk.md 3.5 (conjectured and unique
/// decoding), which do not need an OOD sample. `deep` is not bound by the
/// hiding transcript header. Refusing keeps a config from silently claiming
/// what this mode does not prove.
fn zk2(cfg: proto.Config) !?pcs2.Params {
    const p = cfg.two_level orelse return null;
    if (p.depth == 0) return error.ZkTwoLevelDepth;
    if (p.ood) return error.ZkOodUnsupported;
    if (p.deep != null) return error.ZkDeepUnsupported;
    return p;
}

/// Prover side of an opening after `zkp.drawCoeffs` and combining the rows
/// (takes ownership of `mus` and `rows`).
fn finishAny(a: std.mem.Allocator, pool: *f.Pool, tr: *Transcript, cfg: proto.Config, outer: pcs.Params, coms: []const *const zkp.Commitment, co: *const zkp.Coeffs, groups: []const zkp.Group, k0: usize, mus: []QM31, rows: [][]QM31) !Opening {
    if (try zk2(cfg)) |p2| return .{ .rec = try zkp2.finish(a, pool, tr, outer, p2, coms, co, groups, k0, mus, rows, cfg.accel) };
    return .{ .flat = try zkp.finish(a, tr, outer, coms, mus, rows) };
}

fn verifyAny(a: std.mem.Allocator, tr: *Transcript, cfg: proto.Config, outer: pcs.Params, shapes: []const zkp.Shape, roots: []const Hash, groups: []const zkp.Group, prox: ?zkp.MaskRef, op: Opening) !void {
    if (try zk2(cfg)) |p2| {
        if (op != .rec) return error.ProofShape;
        return zkp2.verify(a, tr, outer, p2, shapes, roots, groups, prox, op.rec);
    }
    if (op != .flat or shapes.len == 0) return error.ProofShape;
    var tw = try pcs.Twiddles.init(a, shapes[0].logExt());
    defer tw.deinit(a);
    return zkp.verifyOpening(a, tr, outer, &tw, shapes, roots, groups, prox, op.flat);
}

/// Combined rows over several tables: rows[o] = sum_t combine(table t, co.v[o][t]).
fn combineMulti(a: std.mem.Allocator, pool: *f.Pool, co: zkp.Coeffs, parts: anytype) ![][]QM31 {
    const n_out = co.v.len;
    var out: [][]QM31 = undefined;
    inline for (parts, 0..) |pt, t| {
        const cv = try a.alloc([]const QM31, n_out);
        defer a.free(cv);
        for (0..n_out) |o| cv[o] = co.v[o][t];
        const r = try zkp.combine(std.meta.Elem(@TypeOf(pt.m.data)), a, pool, pt.com, pt.m, pt.extra, cv);
        if (t == 0) {
            out = r;
        } else {
            for (out, r) |x, y| {
                for (x, y) |*u, v| u.* = u.*.add(v);
                a.free(y);
            }
            a.free(r);
        }
    }
    return out;
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
    var rng = proverRng();
    const extra = try a.alloc(M31, 2 * WPAD_ROWS * C);
    errdefer a.free(extra);
    rng.fillM31(extra);
    const m = pcs.Matrix(i8){ .data = table, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    var com = try zkp.commit(i8, a, pool, &tw, &rng, m, extra, slots, wpcs(cfg).log_blowup);
    try com.enableBudget(a);
    return .{ .infos = infos, .offsets = lay.offsets, .table = table, .log_rows = lr, .log_cols = lc, .rows_used = ru, .extra = extra, .com = com };
}

/// Proximity of the hiding weight table, once per commitment (consumes n_queries of the budget).
pub fn proveWeightProximity(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, zw: *const ZkWeights) !Opening {
    var tr = Transcript.initDomain("stwo-tensor-zk-weights-v1");
    tr.mixDigest(zw.com.root());
    const shapes = [_]zkp.Shape{zw.com.shape};
    const pm = zkp.MaskRef{ .table = 0, .row = zw.rows_used + WPAD_ROWS };
    var co = try zkp.drawCoeffs(a, &tr, &shapes, &.{}, &.{}, pm);
    defer co.deinit(a);
    const cv = [_][]const QM31{co.v[0][0]};
    const rows = try zkp.combine(i8, a, pool, &zw.com, zw.tableMatrix(), zw.extra, &cv);
    const coms = [_]*const zkp.Commitment{&zw.com};
    return finishAny(a, pool, &tr, cfg, wpcs(cfg), &coms, &co, &.{}, 1, try a.alloc(QM31, 0), rows);
}

pub fn verifyWeightProximity(a: std.mem.Allocator, cfg: proto.Config, key: WeightKey, proof: Opening) !void {
    try canonical.check(proof);
    var tr = Transcript.initDomain("stwo-tensor-zk-weights-v1");
    tr.mixDigest(key.root);
    const shapes = [_]zkp.Shape{key.shape(wpcs(cfg).log_blowup)};
    const roots = [_]Hash{key.root};
    try verifyAny(a, &tr, cfg, wpcs(cfg), &shapes, &roots, &.{}, .{ .table = 0, .row = key.rows_used + WPAD_ROWS }, proof);
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
    opening: Opening,

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
    var rng = proverRng();
    var tw = try pcs.Twiddles.init(a, old.log_cols + wp.log_blowup);
    defer tw.deinit(a);
    // mask table: 4 group mask rows (+ 4 proximity mask rows in the recursive mode,
    // whose proximity row also covers this otherwise untested table)
    const rec = (try zk2(cfg)) != null;
    const mrows: u32 = if (rec) 3 else 2;
    const mdata = try randVec(ar, &rng, @as(usize, 1) << @intCast(old.log_cols + mrows));
    const mm = pcs.Matrix(i32){ .data = mdata, .log_rows = mrows, .log_cols = old.log_cols };
    var mcom = try zkp.commit(i32, a, pool, &tw, &rng, mm, &.{}, old.com.shape.slots, wp.log_blowup);
    defer mcom.deinit(a);
    var tr = linkTranscript(old.key(), new.key(), mcom.root());
    const groups = try linkGroup(ar, &tr, old.key(), new.key());
    const mus = try a.alloc(QM31, 1);
    mus[0] = zkp.maskValue(i32, mm, 0, groups[0].col);
    const shapes = [_]zkp.Shape{ old.com.shape, new.com.shape, mcom.shape };
    const prox: ?zkp.MaskRef = if (rec) .{ .table = 2, .row = 4 } else null;
    var co = try zkp.drawCoeffs(a, &tr, &shapes, groups, mus, prox);
    defer co.deinit(a);
    const rows = try combineMulti(a, pool, co, .{
        .{ .com = &old.com, .m = old.tableMatrix(), .extra = old.extra },
        .{ .com = &new.com, .m = new.tableMatrix(), .extra = new.extra },
        .{ .com = &mcom, .m = mm, .extra = @as([]const M31, &.{}) },
    });
    const coms = [_]*const zkp.Commitment{ &old.com, &new.com, &mcom };
    const opening = try finishAny(a, pool, &tr, cfg, wp, &coms, &co, groups, @intFromBool(rec), mus, rows);
    return .{ .mask_root = mcom.root(), .opening = opening };
}

pub fn verifyWeightLink(a: std.mem.Allocator, cfg: proto.Config, old: WeightKey, new: WeightKey, link: WeightLink) !void {
    try canonical.check(link);
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const wp = wpcs(cfg);
    var tr = linkTranscript(old, new, link.mask_root);
    const groups = try linkGroup(ar, &tr, old, new);
    const rec = (try zk2(cfg)) != null;
    const mshape = zkp.Shape{ .log_cols = old.log_cols, .log_blowup = wp.log_blowup, .slots = old.slots, .n_rows = if (rec) 8 else 4 };
    const shapes = [_]zkp.Shape{ old.shape(wp.log_blowup), new.shape(wp.log_blowup), mshape };
    const roots = [_]Hash{ old.root, new.root, link.mask_root };
    const prox: ?zkp.MaskRef = if (rec) .{ .table = 2, .row = 4 } else null;
    try verifyAny(ar, &tr, cfg, wp, &shapes, &roots, groups, prox, link.opening);
}

// ---------------------------------------------------------------------------
// Proof.

pub const Proof = struct {
    root1: Hash,
    root2: ?Hash,
    wmask_root: ?Hash,
    checks: []zks.MaskedProof,
    batch: zks.MaskedProof,
    opening: Opening,
    weight_opening: ?Opening,
    /// hiding GKR: root denominators (numerators are 0) and layer sumchecks, relation-major
    gkr_roots: []QM31 = &.{},
    gkr_layers: []zks.MaskedProof = &.{},
    /// aux table (batch hiding polynomial): root and its opening
    aux_root: Hash = [_]u8{0} ** 32,
    aux_opening: ?zkp.Opening = null,
    /// virtual remainders: accumulator hats and the post-GKR checks (plan.vchecks order)
    vrem_hats: []QM31 = &.{},
    vchecks: []zks.MaskedProof = &.{},
    /// exact ext einsums: output hats and their checks (plan.xchecks order)
    xhats: []QM31 = &.{},
    xchecks: []zks.MaskedProof = &.{},

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        for (self.xchecks) |*c| c.deinit(a);
        a.free(self.xchecks);
        a.free(self.xhats);
        for (self.vchecks) |*c| c.deinit(a);
        a.free(self.vchecks);
        a.free(self.vrem_hats);
        for (self.gkr_layers) |*c| c.deinit(a);
        a.free(self.gkr_layers);
        a.free(self.gkr_roots);
        if (self.aux_opening) |*o| o.deinit(a);
        for (self.checks) |*c| c.deinit(a);
        a.free(self.checks);
        self.batch.deinit(a);
        self.opening.deinit(a);
        if (self.weight_opening) |*w| w.deinit(a);
    }

    pub const Sizes = struct { sumchecks: usize, logup: usize, witness_opening: usize, weight_opening: usize, total: usize };

    pub fn sizes(self: Proof) Sizes {
        var s: usize = self.batch.byteSize() + (self.vrem_hats.len + self.xhats.len) * 16;
        for (self.checks) |c| s += c.byteSize();
        for (self.vchecks) |c| s += c.byteSize();
        for (self.xchecks) |c| s += c.byteSize();
        var lg: usize = self.gkr_roots.len * 16;
        for (self.gkr_layers) |c| lg += c.byteSize();
        s += lg;
        const wo = self.opening.byteSize() + 32 + (if (self.aux_opening) |o| o.byteSize() else 0);
        const wto = if (self.weight_opening) |w| w.byteSize() else 0;
        const roots: usize = 32 * (1 + @as(usize, @intFromBool(self.root2 != null)) + @intFromBool(self.wmask_root != null));
        return .{ .sumchecks = s, .logup = lg, .witness_opening = wo, .weight_opening = wto, .total = roots + s + wo + wto };
    }
};

/// Blake2s digest of every proof field (CPU / device proof-equality tests).
pub fn proofDigest(p: *const Proof) Hash {
    const H = core.vcs.blake2_hash.Blake2sHasher;
    var h = H.init();
    const W = struct {
        fn q(hh: *H, v: []const QM31) void {
            hh.update(std.mem.sliceAsBytes(v));
        }
        fn mp(hh: *H, m: zks.MaskedProof) void {
            q(hh, &.{ m.sigma, m.u_val });
            for (m.rounds) |r| q(hh, &r);
            q(hh, m.hats);
        }
        fn flat(hh: *H, o: zkp.Opening) void {
            q(hh, o.mus);
            for (o.rows) |r| q(hh, r);
            hh.update(std.mem.asBytes(&o.pow_nonce));
            for (o.tables) |t| {
                hh.update(std.mem.sliceAsBytes(t.values));
                hh.update(std.mem.sliceAsBytes(t.salts));
                hh.update(std.mem.sliceAsBytes(t.paths));
            }
        }
        fn rec(hh: *H, o: zkp2.Opening) void {
            q(hh, o.mus);
            hh.update(std.mem.asBytes(&o.pow_nonce));
            for (o.tables) |t| {
                hh.update(std.mem.sliceAsBytes(t.values));
                hh.update(std.mem.sliceAsBytes(t.salts));
                hh.update(std.mem.sliceAsBytes(t.decommit));
            }
            hh.update(&o.inner_root);
            for (o.sumcheck.rounds) |r| q(hh, &r.evals);
            q(hh, &o.limb_vals);
            for (o.inner.levels) |l| {
                hh.update(std.mem.asBytes(&l.pow_nonce));
                hh.update(std.mem.sliceAsBytes(l.col_values));
                hh.update(std.mem.sliceAsBytes(l.decommit));
                for (l.rows) |r| q(hh, r);
                hh.update(&l.inner_root);
                for (l.sumcheck.rounds) |r| q(hh, &r.evals);
                q(hh, &l.limb_vals);
            }
        }
        fn any(hh: *H, o: Opening) void {
            switch (o) {
                .flat => |x| flat(hh, x),
                .rec => |x| rec(hh, x),
            }
        }
    };
    h.update(&p.root1);
    if (p.root2) |r| h.update(&r);
    if (p.wmask_root) |r| h.update(&r);
    for (p.checks) |c| W.mp(&h, c);
    W.mp(&h, p.batch);
    W.any(&h, p.opening);
    if (p.weight_opening) |o| W.any(&h, o);
    W.q(&h, p.gkr_roots);
    for (p.gkr_layers) |c| W.mp(&h, c);
    h.update(&p.aux_root);
    if (p.aux_opening) |o| W.flat(&h, o);
    W.q(&h, p.vrem_hats);
    for (p.vchecks) |c| W.mp(&h, c);
    W.q(&h, p.xhats);
    for (p.xchecks) |c| W.mp(&h, c);
    return h.finalize();
}

fn mixStatement(tr: *Transcript, st: Statement, weight_root: Hash, cfg: proto.Config) void {
    tr.mixDigest(weight_root);
    tr.mixU64(cfg.pcs.n_queries);
    tr.mixU64(cfg.pcs.log_blowup);
    tr.mixU64(wpcs(cfg).n_queries);
    tr.mixU64(wpcs(cfg).log_blowup);
    if (cfg.zk_virtual_remainders) tr.mixU64(0x7672_656d); // "vrem"
    if (!st.ext.isEmpty()) xt.mixStatement(tr, st.ext);
    if (cfg.two_level) |p| {
        // recursive hiding PCS: bind its shape parameters (flat mode transcript unchanged)
        tr.mixU64(0x7a6b_7063_7332); // "zkpcs2"
        tr.mixU64(p.depth);
        tr.mixU64(p.inner.n_queries);
        tr.mixU64(p.inner.log_blowup);
        tr.mixU64(p.inner.pow_bits);
        tr.mixU64(p.inner_work_shift);
        tr.mixU64(p.prox_rows);
    }
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
        .glu => |g| tr.mixU32s(&.{ 6, g.g, g.u, g.h, g.table, g.shift }),
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
        .ext_lookup => |id| qi(@intCast(t)).add(beta.mul(qi(st.ext.tables[id].values[t]))),
        .glu => |g| blk: {
            const vg = @as(i64, @intCast(t >> 8)) - 128;
            const vu = @as(i64, @intCast(t & 255)) - 128;
            break :blk qi(vg).add(beta.mul(qi(vu))).add(beta.mul(beta).mul(qi(proto.gluValue(st, g.table, g.shift, vg, vu))));
        },
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
    acc: ?*const accel.Accel = null,

    fn padValue(self: *const ProverCtx, sp: FSpec, r: []const QM31) QM31 {
        if (sp.qpad) |qp| {
            // the Q factor's "pad" is its own final value, so its hat is Q~(r)
            const q = qPoint(self.a, sp, r) catch @panic("oom");
            defer self.a.free(q.pt);
            return q.scale.mul(f.mleEvalI32(self.a, self.vecs[0][qp], q.pt) catch @panic("oom"));
        }
        var v = sp.konst;
        for (sp.parts) |p| {
            const loc = localPoint(self.a, p, r, sp.m) catch @panic("oom");
            defer self.a.free(loc);
            if (p.weight) {
                const zw = self.zw.?;
                const C = @as(usize, 1) << @intCast(zw.log_cols);
                const full = weightFull(self.a, zw.key(), p.id, loc) catch @panic("oom");
                defer self.a.free(full);
                const eqc = f.eqTable(self.a, full[zw.log_rows..], QM31.one()) catch @panic("oom");
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
                const pv = f.mleEvalI32(self.a, self.vecs[p.table][pid], padPoint(self.a, p, loc, r, plog) catch @panic("oom")) catch @panic("oom");
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
    return zks.proveAccel(pc.acc, NF, terms, a, pool, tr, claim, fac, active, public, hp, PadCtx(NF){ .pc = pc, .specs = specs });
}

/// A witness tensor whose values are public (e.g. the model's input and output):
/// the proof binds the committed tensor to these values, everything else stays hidden.
pub const PublicTensor = struct { id: u32, values: []const i32 };

fn mixPublic(tr: *Transcript, st: Statement, public: []const PublicTensor) !void {
    tr.mixU64(public.len);
    for (public) |pt| {
        if (pt.id >= st.witness.len or pt.values.len != st.witness[pt.id].size()) return error.StatementShape;
        tr.mixU64(pt.id);
        tr.mixDigest(core.vcs.blake2_hash.Blake2sHasher.hash(std.mem.sliceAsBytes(pt.values)));
    }
}

/// Public-tensor claims: T~(z) = MLE(values)(z) at fresh random z (value public).
fn publicClaims(a: std.mem.Allocator, tr: *Transcript, st: Statement, public: []const PublicTensor, claims: *std.ArrayList(LClaim)) !void {
    for (public) |pt| {
        const z = try a.alloc(QM31, st.witness[pt.id].logSize());
        tr.drawN(z);
        const terms = try a.alloc(LTerm, 1);
        terms[0] = .{ .table = 0, .id = pt.id, .coeff = QM31.one(), .form = .{ .eq = z } };
        try claims.append(a, .{ .terms = terms, .value = try mleFoldI32(a, pt.values, z) });
    }
}

/// MLE of an integer vector at a point by folding (MSB first); the first fold
/// multiplies QM31 by M31 differences only.
fn mleFoldI32(a: std.mem.Allocator, v: []const i32, z: []const QM31) !QM31 {
    if (z.len == 0) return QM31.fromBase(f.fromI32(v[0]));
    const half = v.len / 2;
    const buf = try a.alloc(QM31, half);
    defer a.free(buf);
    for (buf, v[0..half], v[half..]) |*o, lo, hi| {
        const l = f.fromI32(lo);
        o.* = QM31.fromBase(l).add(z[0].mulM31(f.fromI32(hi).sub(l)));
    }
    var len = half;
    for (z[1..]) |r| {
        const h = len / 2;
        for (0..h) |i| buf[i] = buf[i].add(r.mul(buf[i + h].sub(buf[i])));
        len = h;
    }
    return buf[0];
}

test "mleFoldI32 matches mleEvalI32" {
    const a = std.testing.allocator;
    var v: [64]i32 = undefined;
    for (&v, 0..) |*x, i| x.* = @as(i32, @intCast(i * 37 % 101)) - 50;
    var z: [6]QM31 = undefined;
    for (&z, 0..) |*x, i| x.* = QM31.fromU32Unchecked(@intCast(i * 7 + 3), 11, @intCast(i), 5);
    try std.testing.expect((try mleFoldI32(a, &v, &z)).eql(try f.mleEvalI32(a, &v, &z)));
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
    return provePublic(a, pool, cfg, st, zw, witness, &.{}, timings);
}

pub fn verify(a: std.mem.Allocator, cfg: proto.Config, st: Statement, wkey: ?WeightKey, proof: *const Proof) !void {
    return verifyPublic(a, cfg, st, wkey, &.{}, proof);
}

/// As `prove`, binding the given witness tensors to public values.
pub fn provePublic(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: proto.Config,
    st: Statement,
    zw: ?*const ZkWeights,
    witness: []const []const i32,
    public: []const PublicTensor,
    timings: *proto.Timings,
) !Proof {
    for (public) |pt| {
        if (pt.id >= witness.len or !std.mem.eql(i32, witness[pt.id], pt.values)) return error.PublicMismatch;
    }
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const wkey: ?WeightKey = if (zw) |w| w.key() else null;
    const plan = try makePlan(ar, st, wkey, cfg);
    const rec = (try zk2(cfg)) != null;
    var rng = proverRng();

    // --- accumulators, remainders, multiplicities
    var t0 = try std.time.Instant.now();
    const acc = try ar.alloc(?[]i64, st.ops.len);
    for (st.ops, 0..) |op, i| {
        acc[i] = null;
        switch (op) {
            .matmul => |m| acc[i] = (try accel.matmulAcc(cfg.accel, ar, st.witness[m.x].log_dims[0], witness[m.x], zw.?.matrix(m.w))) orelse try proto.matmulAcc(ar, pool, st.witness[m.x], witness[m.x], zw.?.matrix(m.w)),
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
    // ext ops: accumulators and key columns (refuses violated exact einsums / lineqs)
    var xps_store: xt.ProverState = undefined;
    var xps: ?*const xt.ProverState = null;
    if (!st.ext.isEmpty()) {
        xps_store = try xt.proverInit(ar, pool, st, witness);
        xps = &xps_store;
    }
    // requant remainders (committed in table 1, or kept by the prover only when virtual)
    const rvals = try ar.alloc([]const i32, st.ops.len);
    @memset(rvals, &.{});
    for (st.ops, 0..) |op, i| {
        if (acc[i] == null) continue;
        const s = opShift(op);
        const y = witness[opY(op)];
        const r = try ar.alloc(i32, y.len);
        for (r, acc[i].?, y) |*o, av, yv| {
            const rv = av + shiftHalf(s) - (@as(i64, yv) << s);
            if (rv < 0 or rv >= (@as(i64, 1) << s)) return error.RemainderOutOfRange;
            o.* = @intCast(rv);
        }
        rvals[i] = r;
        if (plan.rem[i] != NONE) vecs1[plan.rem[i]] = r;
    }
    for (plan.rels) |rel| {
        const m = try ar.alloc(i32, @as(usize, 1) << @intCast(rel.log_size));
        @memset(m, 0);
        vecs1[rel.mult] = m;
    }
    for (plan.keys) |k| {
        const mult: []i32 = @constCast(vecs1[plan.rels[k.rel].mult]);
        const op = if (k.kind == .ext) undefined else st.ops[k.op];
        switch (k.kind) {
            .remainder => for (rvals[k.op]) |v| {
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
            .ext => try xt.addMultiplicities(st, xps.?, k.op, mult),
            .glu_triple => {
                const g = op.glu;
                for (witness[g.g], witness[g.u], witness[g.h]) |vg, vu, vh| {
                    if (vg < -128 or vg > 127 or vu < -128 or vu > 127) return error.ValueOutOfRange;
                    if (proto.gluValue(st, g.table, g.shift, vg, vu) != vh) return error.LookupMismatch;
                    mult[@intCast((vg + 128) * 256 + (vu + 128))] += 1;
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
    // aux table: batch hiding polynomial + its own masks
    const aux_data = try randVec(ar, &rng, @as(usize, 16) << AUX_LC);
    const maux = pcs.Matrix(i32){ .data = aux_data, .log_rows = 4, .log_cols = AUX_LC, .rows_used = AUX_ROWS };
    var auxtw = try pcs.Twiddles.init(a, AUX_LC + AUX_LB);
    defer auxtw.deinit(a);
    var comx = try zkp.commit(i32, a, pool, &auxtw, &rng, maux, &.{}, auxParams().slots, AUX_LB);
    defer comx.deinit(a);
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
        const wmr = wmaskRows(plan, st, w.key(), rec);
        wmask_data = try randVec(ar, &rng, wmr << @intCast(w.log_cols));
        const mm = pcs.Matrix(i32){ .data = wmask_data, .log_rows = log2Ceil(wmr), .log_cols = w.log_cols, .rows_used = wmr };
        wmask_com = try zkp.commit(i32, a, pool, &wtw.?, &rng, mm, &.{}, w.com.shape.slots, wpcs(cfg).log_blowup);
    }
    timings.witness_commit_ns = nowNs(t0);
    timings.witness_table_elems = plan.rowsUsed(0) * C;
    for (witness) |v| timings.witness_elems += v.len;

    var tr = Transcript.initDomain("stwo-tensor-zk-v1");
    mixStatement(&tr, st, if (wkey) |k| k.root else [_]u8{0} ** 32, cfg);
    try mixPublic(&tr, st, public);
    tr.mixDigest(com1.root());
    tr.mixDigest(comx.root());
    if (wmask_com) |*w| tr.mixDigest(w.root());
    const alpha = tr.draw();
    const beta = tr.draw();
    const tau = tr.draw(); // relation tags in a merged LogUp-GKR tree

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
            const h = try keyDenoms(ar, pool, plan, st, witness, rvals, k, alpha, beta);
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
    const pc = ProverCtx{ .a = ar, .plan = plan, .vecs = .{ vecs1, vecs2 }, .zw = zw, .acc = cfg.accel };

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
                const fx = try zeroExt(a, try accel.colCombine(cfg.accel, i32, a, pool, xm, eq_t, proto.operandBoundLog2(st, m.x)), len);
                defer a.free(fx);
                const eq_n = try f.eqTablePar(a, pool, pt[lt..], QM31.one());
                defer a.free(eq_n);
                const gw = try zeroExt(a, try accel.rowDots(cfg.accel, a, pool, w.matrix(m.w), eq_n, 7), len);
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
                const d = try keyDenoms(a, pool, plan, st, witness, rvals, k, alpha, beta);
                defer a.free(d);
                out = try runMasked(3, &T_KEY, a, pool, &tr, claim, .{ eq, h, d }, len, specs, hp, &pc);
            },
            .matmul_v, .hadamard_v, .einsum_v, .einsum_x => unreachable, // run after the GKR
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
    var vrems: std.ArrayList(VRem) = .empty;
    if (plan.grels.len > 0) {
        const tg = try std.time.Instant.now();
        for (plan.grels) |g| try gkrProveRel(a, ar, pool, &tr, plan, st, witness, vecs1, rvals, xps, alpha, beta, tau, g, &claims, &gkr_roots, &gkr_layers, &vrems);
        timings.gkr_ns += nowNs(tg);
    } else try logupClaims(ar, plan, st, alpha, beta, &claims);
    // --- virtual remainders: matmul / hadamard checks at the remainder leaf points
    const vcheck_proofs = try a.alloc(zks.MaskedProof, plan.vchecks.len);
    var n_vdone: usize = 0;
    errdefer {
        for (vcheck_proofs[0..n_vdone]) |*c| c.deinit(a);
        a.free(vcheck_proofs);
    }
    std.debug.assert(vrems.items.len == plan.vchecks.len);
    for (plan.vchecks, vrems.items) |c, vr| {
        const tc = try std.time.Instant.now();
        const specs = try vcheckSpecs(ar, st, wkey, c, vr);
        const hp = hpOf(plan, vecs1, c.u, c.n, c.deg, hpbuf[0..zks.Hp.entries(c.n, c.deg)]);
        const len = @as(usize, 1) << @intCast(c.n);
        // et = eq((0, t_tail), .) and Q = [head = 0] P_A(t_lead, tail): supported on the first 2^mp entries
        const qs = qShape(c.n, &vr.t_a);
        const et = try a.alloc(QM31, len);
        defer a.free(et);
        @memset(et, QM31.zero());
        const ett = try f.eqTable(a, qs.t_tail, QM31.one());
        defer a.free(ett);
        @memcpy(et[0..ett.len], ett);
        const Q = try a.alloc(QM31, len);
        defer a.free(Q);
        @memset(Q, QM31.zero());
        const part = try padPartial(a, vecs1[c.apad], qs.t_lead);
        defer a.free(part.ptr[0..16]);
        @memcpy(Q[0..part.len], part);
        var out: zks.ProveOut = undefined;
        switch (c.kind) {
            .matmul_v => {
                const m = st.ops[c.idx].matmul;
                const w = zw.?;
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const tw0 = try std.time.Instant.now();
                const eq_t = try f.eqTablePar(a, pool, vr.local[0..lt], QM31.one());
                defer a.free(eq_t);
                const xm = pcs.Matrix(i32){ .data = witness[m.x], .log_rows = lt, .log_cols = xi.log_dims[1] };
                const fx = try accel.colCombine(cfg.accel, i32, a, pool, xm, eq_t, 8);
                defer a.free(fx);
                const eq_n = try f.eqTablePar(a, pool, vr.local[lt..], QM31.one());
                defer a.free(eq_n);
                const gw = try accel.rowDots(cfg.accel, a, pool, w.matrix(m.w), eq_n, 7);
                defer a.free(gw);
                timings.weight_fold_ns += nowNs(tw0);
                out = try runMasked(4, &T_MMV, a, pool, &tr, vr.ahat, .{ fx, gw, et, Q }, len, specs, hp, &pc);
            },
            .hadamard_v => {
                const h = st.ops[c.idx].hadamard;
                const eq = try f.eqTablePar(a, pool, vr.local, QM31.one());
                defer a.free(eq);
                const fa = try toQ(a, pool, witness[h.a], len, QM31.one());
                defer a.free(fa);
                const fb = try toQ(a, pool, witness[h.b], len, QM31.one());
                defer a.free(fb);
                out = try runMasked(5, &T_HADV, a, pool, &tr, vr.ahat, .{ eq, fa, fb, et, Q }, len, specs, hp, &pc);
            },
            .einsum_v => out = try proveEinsumMasked(a, pool, &tr, st, witness, c, vr, et, Q, specs, hp, &pc),
            else => unreachable,
        }
        defer a.free(out.point);
        vcheck_proofs[n_vdone] = out.proof;
        n_vdone += 1;
        try checkClaims(ar, plan, specs, c.u, c.n, c.deg, out.point, out.proof, &claims, &wclaims, wkey);
        timings.op_sumcheck_ns += nowNs(tc);
    }
    const vrem_hats = try a.alloc(QM31, vrems.items.len);
    errdefer a.free(vrem_hats);
    for (vrem_hats, vrems.items) |*o, vr| o.* = vr.ahat;
    // --- exact einsums: Y^ = Y~(rho) + P(t) and sum eq A' B' + et Q = Y^ at a fresh rho
    const xcheck_proofs = try a.alloc(zks.MaskedProof, plan.xchecks.len);
    var n_xdone: usize = 0;
    errdefer {
        for (xcheck_proofs[0..n_xdone]) |*c| c.deinit(a);
        a.free(xcheck_proofs);
    }
    const xhats = try a.alloc(QM31, plan.xchecks.len);
    errdefer a.free(xhats);
    for (plan.xchecks, 0..) |c, ci| {
        const tc = try std.time.Instant.now();
        const e = st.ext.ops[c.idx].einsum;
        const rho_x = try ar.alloc(QM31, e.n_out);
        tr.drawN(rho_x);
        var t_a: [4]QM31 = undefined;
        tr.drawN(&t_a);
        var yv = QM31.zero();
        if (e.y) |y| yv = try xt.mlePar(a, pool, witness[y], rho_x);
        const yhat = yv.add(try f.mleEvalI32(a, vecs1[c.apad], &t_a));
        tr.mixFelt(yhat);
        xhats[ci] = yhat;
        const vr = VRem{ .local = rho_x, .t_a = t_a, .ahat = yhat };
        try exactHatClaim(ar, e, c, vr, &claims);
        const specs = try vcheckSpecs(ar, st, wkey, c, vr);
        const hp = hpOf(plan, vecs1, c.u, c.n, c.deg, hpbuf[0..zks.Hp.entries(c.n, c.deg)]);
        const qv = try qVectors(a, c.n, vr.t_a, vecs1[c.apad]);
        defer a.free(qv.et);
        defer a.free(qv.q);
        const out = try proveEinsumMasked(a, pool, &tr, st, witness, c, vr, qv.et, qv.q, specs, hp, &pc);
        defer a.free(out.point);
        xcheck_proofs[n_xdone] = out.proof;
        n_xdone += 1;
        try checkClaims(ar, plan, specs, c.u, c.n, c.deg, out.point, out.proof, &claims, &wclaims, wkey);
        timings.op_sumcheck_ns += nowNs(tc);
    }
    try lineqClaims(ar, &tr, st, &claims);
    try publicClaims(ar, &tr, st, public, &claims);

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
    const bhp = hpFromCells(aux_data, N, 2, hpbuf[0..zks.Hp.entries(N, 2)]);
    const bpad = BatchPad{ .plan = plan, .tabs = .{ vecs1[plan.rb[0]], if (plan.has2) vecs2[plan.rb[1]] else &.{} }, .a = ar };
    var bout: zks.ProveOut = undefined;
    if (plan.has2) {
        bout = try zks.proveAccel(cfg.accel, 4, &T_B4, a, pool, &tr, batch_claim, .{ Tv[0], Ev[0], Tv[1], Ev[1] }, active, .{ false, true, false, true }, bhp, bpad);
    } else {
        bout = try zks.proveAccel(cfg.accel, 2, &T_B2, a, pool, &tr, batch_claim, .{ Tv[0], Ev[0] }, active, .{ false, true }, bhp, bpad);
    }
    defer a.free(bout.point);
    errdefer bout.proof.deinit(a);
    timings.batch_ns = nowNs(t0);

    // --- witness opening (tables 1 [+ 2]): group A = batch hats
    t0 = try std.time.Instant.now();
    const ospec = try openingSpec(ar, plan, bout.point, bout.proof);
    const mus = try a.alloc(QM31, 1);
    mus[0] = zkp.maskValue(i32, m1, plan.maskRow() + 4, ospec.groups[0].col);
    const shapes = [2]zkp.Shape{ plan.shape(0, cfg.pcs.log_blowup), plan.shape(1, cfg.pcs.log_blowup) };
    var co = try zkp.drawCoeffs(a, &tr, shapes[0..n_tabs], ospec.groups, mus, .{ .table = 0, .row = plan.maskRow() });
    defer co.deinit(a);
    const rows = try combineTables(a, pool, co, .{ &com1, if (com2) |*c| c else null }, .{ m1, pcs.Matrix(i32){ .data = tab2, .log_rows = if (plan.has2) plan.lay[1].log_total - plan.lc else 0, .log_cols = plan.lc, .rows_used = plan.rowsUsed(1) } }, n_tabs);
    var coms_buf: [2]*const zkp.Commitment = .{ &com1, &com1 };
    if (com2) |*c| coms_buf[1] = c;
    var opening = try finishAny(a, pool, &tr, cfg, cfg.pcs, coms_buf[0..n_tabs], &co, ospec.groups, 1, mus, rows);
    errdefer opening.deinit(a);
    // aux opening: sigma_b + zeta u_b on row 0 (zeta drawn after u_b is mixed)
    var aux_open: zkp.Opening = undefined;
    {
        const zeta = tr.draw();
        const xg = try auxGroup(ar, plan, bout.point, bout.proof, zeta);
        const xmus = try a.alloc(QM31, 1);
        xmus[0] = zkp.maskValue(i32, maux, 5, xg[0].col);
        const xshapes = [_]zkp.Shape{comx.shape};
        var xco = try zkp.drawCoeffs(a, &tr, &xshapes, xg, xmus, .{ .table = 0, .row = 1 });
        defer xco.deinit(a);
        const cv = [_][]const QM31{ xco.v[0][0], xco.v[1][0] };
        const xrows = try zkp.combine(i32, a, pool, &comx, maux, &.{}, &cv);
        const xcoms = [_]*const zkp.Commitment{&comx};
        aux_open = try zkp.finish(a, &tr, auxParams().params, &xcoms, xmus, xrows);
    }
    errdefer aux_open.deinit(a);
    timings.witness_open_ns = nowNs(t0);

    // --- weight opening
    t0 = try std.time.Instant.now();
    var wopen: ?Opening = null;
    if (has_matmul) {
        const w = zw.?;
        const wmr = wmaskRows(plan, st, w.key(), rec);
        const ng = weightGroupCount(plan, st, w.key());
        const wg = try weightGroup(ar, w.key(), wclaims.items, ng);
        const wmm = pcs.Matrix(i32){ .data = wmask_data, .log_rows = log2Ceil(wmr), .log_cols = w.log_cols, .rows_used = wmr };
        const wmus = try a.alloc(QM31, wg.len);
        for (wg, 0..) |g, gi| wmus[gi] = zkp.maskValue(i32, wmm, g.mask.row, g.col);
        const wshapes = [_]zkp.Shape{ w.key().shape(wpcs(cfg).log_blowup), wmask_com.?.shape };
        const wprox: ?zkp.MaskRef = if (rec) .{ .table = 1, .row = 4 * ng } else null;
        var wco = try zkp.drawCoeffs(a, &tr, &wshapes, wg, wmus, wprox);
        defer wco.deinit(a);
        const r0 = try combineMulti(a, pool, wco, .{
            .{ .com = &w.com, .m = w.tableMatrix(), .extra = @as([]const M31, w.extra) },
            .{ .com = &wmask_com.?, .m = wmm, .extra = @as([]const M31, &.{}) },
        });
        const wcoms = [_]*const zkp.Commitment{ &w.com, &wmask_com.? };
        wopen = try finishAny(a, pool, &tr, cfg, wpcs(cfg), &wcoms, &wco, wg, @intFromBool(rec), wmus, r0);
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
        .aux_root = comx.root(),
        .aux_opening = aux_open,
        .vrem_hats = vrem_hats,
        .vchecks = vcheck_proofs,
        .xhats = xhats,
        .xchecks = xcheck_proofs,
    };
}

/// alpha - key(x) for a key instance (prover).
fn keyDenoms(a: std.mem.Allocator, pool: *f.Pool, plan: Plan, st: Statement, witness: []const []const i32, rvals: []const []const i32, k: Key, alpha_in: QM31, beta: QM31) ![]QM31 {
    return keyDenomsShift(a, pool, plan, st, witness, rvals, k, alpha_in, beta);
}

/// alpha - key(x), where `alpha` may already include a tag shift (alpha - tau * rel).
fn keyDenomsShift(a: std.mem.Allocator, pool: *f.Pool, plan: Plan, st: Statement, witness: []const []const i32, rvals: []const []const i32, k: Key, alpha: QM31, beta: QM31) ![]QM31 {
    _ = plan;
    const n = @as(usize, 1) << @intCast(k.log_size);
    const out = try a.alloc(QM31, n);
    const op = if (k.kind == .ext) undefined else st.ops[k.op];
    const Ctx = struct { out: []QM31, k: Key, x: []const i32, y: []const i32, z: []const i32 = &.{}, alpha: QM31, beta: QM31, beta2: QM31 };
    var ctx = Ctx{ .out = out, .k = k, .x = &.{}, .y = &.{}, .alpha = alpha, .beta = beta, .beta2 = beta.mul(beta) };
    switch (k.kind) {
        .remainder => ctx.x = rvals[k.op],
        .y_range => ctx.x = witness[opY(op)],
        .plain_range => ctx.x = witness[op.range8.in],
        .lookup_pair => {
            ctx.x = witness[op.lookup.in];
            ctx.y = witness[op.lookup.out];
        },
        .glu_triple => {
            ctx.x = witness[op.glu.g];
            ctx.y = witness[op.glu.u];
            ctx.z = witness[op.glu.h];
        },
        .ext => unreachable, // xt.keyDen
    }
    pool.parallelFor(n, 4096, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| {
                const key: QM31 = switch (c.k.kind) {
                    .remainder => qi(c.x[i]),
                    .y_range, .plain_range => qi(@as(i64, c.x[i]) + 128),
                    .lookup_pair => qi(c.x[i]).add(c.beta.mul(qi(c.y[i]))),
                    .glu_triple => qi(c.x[i]).add(c.beta.mul(qi(c.y[i]))).add(c.beta2.mul(qi(c.z[i]))),
                    .ext => unreachable,
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
    // only the committed rows are materialized (rows >= rows_used are zero)
    const total = plan.rowsUsed(t) << @intCast(plan.lc);
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
fn openingSpec(a: std.mem.Allocator, plan: Plan, point: []const QM31, bp: zks.MaskedProof) !OpeningSpec {
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
    _ = C;
    const groups = try a.alloc(zkp.Group, 1);
    groups[0] = .{ .col = colA, .claims = claimsA, .mask = .{ .table = 0, .row = plan.maskRow() + 4 } };
    return .{ .groups = groups };
}

/// Aux-table group: the batch hiding polynomial claims sigma + zeta u_val on row 0.
fn auxGroup(a: std.mem.Allocator, plan: Plan, point: []const QM31, bp: zks.MaskedProof, zeta: QM31) ![]zkp.Group {
    const N = plan.batch_n;
    const ne = zks.Hp.entries(N, 2);
    const fs = try a.alloc(QM31, ne);
    zks.Hp.sumForm(N, 2, fs);
    const fe = try a.alloc(QM31, ne);
    zks.Hp.evalForm(N, 2, point, fe);
    const col = try a.alloc(QM31, @as(usize, 1) << AUX_LC);
    @memset(col, QM31.zero());
    for (0..ne) |e| for (0..4) |k| {
        col[4 * e + k] = fs[e].add(zeta.mul(fe[e])).mul(zkp.basis(k));
    };
    const rv = try a.alloc(QM31, AUX_ROWS);
    @memset(rv, QM31.zero());
    rv[0] = QM31.one();
    const rows = try a.alloc([]const QM31, 1);
    rows[0] = rv;
    const claims = try a.alloc(zkp.Claim, 1);
    claims[0] = .{ .rows = rows, .value = bp.sigma.add(zeta.mul(bp.u_val)) };
    const groups = try a.alloc(zkp.Group, 1);
    groups[0] = .{ .col = col, .claims = claims, .mask = .{ .table = 0, .row = 5 } };
    return groups;
}

fn hpFromCells(cells: []const i32, n: u32, deg: u32, buf: []QM31) zks.Hp {
    for (buf, 0..) |*x, e| x.* = f.fromLimbs(.{ @intCast(cells[4 * e]), @intCast(cells[4 * e + 1]), @intCast(cells[4 * e + 2]), @intCast(cells[4 * e + 3]) });
    return .{ .n = n, .d = deg, .c = buf };
}

/// Full weight-table point of a local point of weight tensor `w`.
fn weightFull(a: std.mem.Allocator, key: WeightKey, w: u32, local: []const QM31) ![]QM31 {
    const info = key.infos[w];
    const full = try a.alloc(QM31, key.log_rows + key.log_cols);
    const nb = key.log_rows + key.log_cols - info.logSize();
    bitsPoint(full[0..nb], key.offsets[w] >> @intCast(info.logSize()));
    @memcpy(full[nb..], local);
    return full;
}

/// Number of weight-opening groups (distinct column points): matmuls whose output
/// dimension covers the table's columns share the column point (suffix of rho);
/// each other matmul has its own (it contains sumcheck coordinates).
fn weightGroupCount(plan: Plan, st: Statement, key: WeightKey) usize {
    // shared column points: one suffix of rho, or (virtual remainders) one suffix
    // of each GKR tree's leaf point
    var shared = std.StaticBitSet(64).initEmpty();
    var own: usize = 0;
    for (st.ops, 0..) |op, i| switch (op) {
        .matmul => |m| {
            if (key.infos[m.w].log_dims[1] >= key.log_cols) {
                shared.set(if (plan.virt) plan.op_tree[i] % 64 else 0);
            } else own += 1;
        },
        else => {},
    };
    return own + shared.count();
}

/// Rows of the per-proof weight mask table: 4 per group, plus 4 proximity mask
/// rows in the recursive mode (its proximity row also tests the mask table).
fn wmaskRows(plan: Plan, st: Statement, key: WeightKey, rec: bool) usize {
    return 4 * weightGroupCount(plan, st, key) + @as(usize, if (rec) 4 else 0);
}

fn weightGroup(a: std.mem.Allocator, key: WeightKey, wcl: []const WClaim, max_groups: usize) ![]zkp.Group {
    const lr = key.log_rows;
    const nr = key.rows_used + 2 * WPAD_ROWS;
    var cols: std.ArrayList([]const QM31) = .empty;
    var members: std.ArrayList(std.ArrayList(zkp.Claim)) = .empty;
    for (wcl) |c| {
        const full = try weightFull(a, key, c.w, c.local);
        const cp = full[lr..];
        var gi: ?usize = null;
        for (cols.items, 0..) |x, i| {
            var same = true;
            for (x, cp) |u, v| same = same and u.eql(v);
            if (same) {
                gi = i;
                break;
            }
        }
        if (gi == null) {
            try cols.append(a, cp);
            try members.append(a, .empty);
            gi = cols.items.len - 1;
        }
        const eqr = try f.eqTable(a, full[0..lr], c.c_data);
        const rv = try a.alloc(QM31, nr);
        @memcpy(rv[0..key.rows_used], eqr[0..key.rows_used]);
        @memset(rv[key.rows_used..], QM31.zero());
        const eqs = try f.eqTable(a, &c.s, c.c_pad);
        for (0..WPAD_ROWS) |k| rv[key.rows_used + k] = eqs[k];
        const rows = try a.alloc([]const QM31, 2);
        rows[0] = rv;
        rows[1] = &.{};
        try members.items[gi.?].append(a, .{ .rows = rows, .value = c.value });
    }
    if (cols.items.len > max_groups) return error.WeightColumnPoint;
    const groups = try a.alloc(zkp.Group, cols.items.len);
    for (groups, cols.items, members.items, 0..) |*g, cp, *mem, gi| {
        g.* = .{ .col = try f.eqTable(a, cp, QM31.one()), .claims = mem.items, .mask = .{ .table = 1, .row = 4 * gi } };
    }
    return groups;
}

// ---------------------------------------------------------------------------
// Verifier.

pub fn verifyPublic(a: std.mem.Allocator, cfg: proto.Config, st: Statement, wkey: ?WeightKey, public: []const PublicTensor, proof: *const Proof) !void {
    // every transmitted limb in [0, P) before any arithmetic (KERN-1)
    try canonical.check(proof);
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
    try mixPublic(&tr, st, public);
    tr.mixDigest(proof.root1);
    tr.mixDigest(proof.aux_root);
    if (proof.wmask_root) |r| tr.mixDigest(r);
    const alpha = tr.draw();
    const beta = tr.draw();
    const tau = tr.draw(); // relation tags in a merged LogUp-GKR tree
    if (proof.root2) |r| tr.mixDigest(r);
    const rho = try ar.alloc(QM31, plan.rho_len);
    tr.drawN(rho);

    var claims: std.ArrayList(LClaim) = .empty;
    var wclaims: std.ArrayList(WClaim) = .empty;
    var vrems: std.ArrayList(VRem) = .empty;
    for (plan.checks, proof.checks) |c, cp| {
        const specs = try checkSpecs(ar, plan, st, wkey, c, rho, alpha, beta);
        try verifyCheck(ar, &tr, plan, st, c, specs, checkClaim(st, c), cp, &claims, &wclaims, wkey);
    }
    if (plan.grels.len > 0) {
        if (proof.gkr_roots.len != plan.grels.len) return error.ProofShape;
        var n_layers: usize = 0;
        for (plan.grels) |g| n_layers += g.n;
        if (proof.gkr_layers.len != n_layers) return error.ProofShape;
        var li: usize = 0;
        for (plan.grels, proof.gkr_roots) |g, d_root| {
            try gkrVerifyRel(ar, &tr, plan, st, alpha, beta, tau, g, d_root, proof.gkr_layers[li..][0..g.n], proof.vrem_hats, &vrems, &claims);
            li += g.n;
        }
    } else {
        if (proof.gkr_roots.len != 0 or proof.gkr_layers.len != 0) return error.ProofShape;
        try logupClaims(ar, plan, st, alpha, beta, &claims);
    }
    // virtual remainders: post-GKR matmul / hadamard checks with claim A^
    if (vrems.items.len != plan.vchecks.len or proof.vrem_hats.len != plan.vchecks.len or proof.vchecks.len != plan.vchecks.len) return error.ProofShape;
    for (plan.vchecks, vrems.items, proof.vchecks) |c, vr, cp| {
        const specs = try vcheckSpecs(ar, st, wkey, c, vr);
        try verifyCheck(ar, &tr, plan, st, c, specs, vr.ahat, cp, &claims, &wclaims, wkey);
    }
    // exact einsums and linear equalities
    if (proof.xhats.len != plan.xchecks.len or proof.xchecks.len != plan.xchecks.len) return error.ProofShape;
    for (plan.xchecks, proof.xhats, proof.xchecks) |c, yhat, cp| {
        const e = st.ext.ops[c.idx].einsum;
        const rho_x = try ar.alloc(QM31, e.n_out);
        tr.drawN(rho_x);
        var t_a: [4]QM31 = undefined;
        tr.drawN(&t_a);
        tr.mixFelt(yhat);
        const vr = VRem{ .local = rho_x, .t_a = t_a, .ahat = yhat };
        try exactHatClaim(ar, e, c, vr, &claims);
        const specs = try vcheckSpecs(ar, st, wkey, c, vr);
        try verifyCheck(ar, &tr, plan, st, c, specs, yhat, cp, &claims, &wclaims, wkey);
    }
    try lineqClaims(ar, &tr, st, &claims);
    try publicClaims(ar, &tr, st, public, &claims);

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
    const ospec = try openingSpec(ar, plan, bv.point, proof.batch);
    const shapes = [2]zkp.Shape{ plan.shape(0, cfg.pcs.log_blowup), plan.shape(1, cfg.pcs.log_blowup) };
    const roots = [2]Hash{ proof.root1, proof.root2 orelse proof.root1 };
    try verifyAny(ar, &tr, cfg, cfg.pcs, shapes[0..n_tabs], roots[0..n_tabs], ospec.groups, .{ .table = 0, .row = plan.maskRow() }, proof.opening);
    {
        const aop = proof.aux_opening orelse return error.ProofShape;
        const zeta = tr.draw();
        const xg = try auxGroup(ar, plan, bv.point, proof.batch, zeta);
        var auxtw = try pcs.Twiddles.init(a, AUX_LC + AUX_LB);
        defer auxtw.deinit(a);
        const xshapes = [_]zkp.Shape{auxShape()};
        const xroots = [_]Hash{proof.aux_root};
        try zkp.verifyOpening(ar, &tr, auxParams().params, &auxtw, &xshapes, &xroots, xg, .{ .table = 0, .row = 1 }, aop);
    }

    // weight opening
    if (proof.weight_opening) |wop| {
        const wk = wkey.?;
        const rec = (try zk2(cfg)) != null;
        const ng = weightGroupCount(plan, st, wk);
        const wmr = wmaskRows(plan, st, wk, rec);
        const wg = try weightGroup(ar, wk, wclaims.items, ng);
        const wshape = wk.shape(wpcs(cfg).log_blowup);
        const mshape = zkp.Shape{ .log_cols = wk.log_cols, .log_blowup = wpcs(cfg).log_blowup, .slots = wk.slots, .n_rows = wmr };
        const wshapes = [_]zkp.Shape{ wshape, mshape };
        const wroots = [_]Hash{ wk.root, proof.wmask_root.? };
        const wprox: ?zkp.MaskRef = if (rec) .{ .table = 1, .row = 4 * ng } else null;
        try verifyAny(ar, &tr, cfg, wpcs(cfg), &wshapes, &wroots, wg, wprox, wop);
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
        .ext_lookup => |id| return f.identityMle(local).add(beta.mul(try f.mleEvalI32(a, st.ext.tables[id].values, local))),
        .glu => |g| {
            // key(idx) = vg + beta vu + beta^2 glu(vg, vu), idx = (vg + 128) * 256 + (vu + 128)
            const fv = try a.alloc(i32, 1 << 16);
            defer a.free(fv);
            for (fv, 0..) |*o, idx| o.* = @intCast(proto.gluValue(st, g.table, g.shift, @as(i64, @intCast(idx >> 8)) - 128, @as(i64, @intCast(idx & 255)) - 128));
            const vg = f.identityMle(local[0..8]).sub(qi(128));
            const vu = f.identityMle(local[8..16]).sub(qi(128));
            return vg.add(beta.mul(vu)).add(beta.mul(beta).mul(try f.mleEvalI32(a, fv, local)));
        },
    }
}

/// Linear terms of an ext expression at a key point: appends coef * mult * scale * T~(pt) for
/// witness terms and returns mult * (constant + public terms) (both sides).
fn exprLeaf(a: std.mem.Allocator, st: Statement, e: xt.Expr, local: []const QM31, mult: QM31, coef: QM31, terms: *std.ArrayList(LTerm)) !QM31 {
    var pub_v = qi(e.constant);
    for (e.terms) |t| {
        const nb = try xt.refBits(st, t.t);
        const pt = try xt.termPoint(a, t, nb, local);
        const sc_ = xt.termScale(t, nb);
        if (t.t.public) {
            pub_v = pub_v.add(sc_.mul(try xt.publicMle(a, st.ext, t.t.id, pt)));
        } else try terms.append(a, .{ .table = 0, .id = t.t.id, .coeff = coef.mul(mult).mul(sc_), .form = .{ .eq = pt } });
    }
    return mult.mul(pub_v);
}

/// Claims on the committed tensors from the last layer's hats (both sides).
fn gkrLeafClaims(a: std.mem.Allocator, plan: Plan, st: Statement, g: GRel, alpha: QM31, beta: QM31, tau: QM31, p: []const QM31, gam: QM31, c: QM31, t: [4]QM31, pads: [4]u32, ahat: QM31, bhat: QM31, vrems: []const VRem, claims: *std.ArrayList(LClaim)) !void {
    var vi: usize = 0;
    const n = g.n;
    const omg = QM31.one().sub(gam);
    var nterms: std.ArrayList(LTerm) = .empty;
    var dterms: std.ArrayList(LTerm) = .empty;
    var num_pub = QM31.zero();
    var den_pub = QM31.zero();
    var sum_blk = QM31.zero();
    for (g.seg_log, g.seg_off, g.segs) |l, o, sg| {
        const bits = try a.alloc(QM31, n - l);
        bitsPoint(bits, o >> @intCast(l));
        const blk = f.eqEval(p[0 .. n - l], bits);
        const local = p[n - l ..];
        sum_blk = sum_blk.add(blk);
        const shift = relTag(g, tau, sg.rel);
        switch (sg.kind) {
            .key => if (isVirtualRem(plan, plan.keys[sg.idx])) {
                // virtual remainder r = acc + 2^(s-1) - 2^s Y with acc~(local) = A^ - P_A~(t_a):
                // leaf denominator alpha - tag - r = (alpha - tag - 2^(s-1) - A^) + 2^s Y~ + P_A~(t_a)
                const k = plan.keys[sg.idx];
                const vr = vrems[vi];
                vi += 1;
                const ys = remYShift(plan, st, k);
                const sh = ys.s;
                num_pub = num_pub.add(blk);
                den_pub = den_pub.add(blk.mul(alpha.sub(shift).sub(qi(shiftHalf(sh))).sub(vr.ahat)));
                try dterms.append(a, .{ .table = 0, .id = ys.y, .coeff = omg.mul(blk).mul(qi(@as(i64, 1) << sh)), .form = .{ .eq = local } });
                try dterms.append(a, .{ .table = 0, .id = vcheckOf(plan, sg.idx).apad, .coeff = omg.mul(blk), .form = .{ .eq = try a.dupe(QM31, &vr.t_a) } });
            } else if (plan.keys[sg.idx].kind == .ext) {
                // ext keys: alpha - tag - (in~(local) + beta out~(local)); einsum output range:
                // alpha - tag - (Y~(local) + 2^(ob-1))
                const xk = plan.xkeys[plan.keys[sg.idx].op];
                num_pub = num_pub.add(blk);
                var konst = alpha.sub(shift);
                switch (xk.kind) {
                    .y_range => {
                        const e = st.ext.ops[xk.op].einsum;
                        konst = konst.sub(qi(@as(i64, 1) << (e.out_bits - 1)));
                        try dterms.append(a, .{ .table = 0, .id = e.y.?, .coeff = omg.mul(blk).neg(), .form = .{ .eq = local } });
                    },
                    .key => {
                        const ko = st.ext.ops[xk.op].key;
                        konst = konst.sub(try exprLeaf(a, st, ko.input, local, QM31.one(), omg.mul(blk).neg(), &dterms));
                        if (ko.output) |oe| konst = konst.sub(try exprLeaf(a, st, oe, local, beta, omg.mul(blk).neg(), &dterms));
                    },
                    .remainder => unreachable,
                }
                den_pub = den_pub.add(blk.mul(konst));
            } else {
                const k = plan.keys[sg.idx];
                const d = try keyFactorD(a, plan, st, k, alpha, beta, k.log_size);
                num_pub = num_pub.add(blk);
                den_pub = den_pub.add(blk.mul(d.konst.sub(shift)));
                for (d.parts) |pt| try dterms.append(a, .{ .table = 0, .id = pt.id, .coeff = omg.mul(blk).mul(pt.coeff), .form = .{ .eq = local } });
            },
            .table => {
                const rel = plan.rels[sg.idx];
                try nterms.append(a, .{ .table = 0, .id = rel.mult, .coeff = omg.mul(blk).neg(), .form = .{ .eq = local } });
                den_pub = den_pub.add(blk.mul(alpha.sub(try relKeyMle(a, st, rel, local, beta)).sub(shift)));
            },
            .blinder => try dterms.append(a, .{ .table = 0, .id = g.blinder, .coeff = omg.mul(blk), .form = .{ .eq = local } }),
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
    rvals: []const []const i32,
    xps: ?*const xt.ProverState,
    alpha: QM31,
    beta: QM31,
    tau: QM31,
    g: GRel,
    claims: *std.ArrayList(LClaim),
    roots: *std.ArrayList(QM31),
    layers_out: *std.ArrayList(zks.MaskedProof),
    vrems: *std.ArrayList(VRem),
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
    for (g.segs, g.seg_off) |sg, o| switch (sg.kind) {
        .key => {
            const kk_ = plan.keys[sg.idx];
            const d = if (kk_.kind == .ext)
                try xt.keyDen(a, pool, xps.?, kk_.op, alpha.sub(relTag(g, tau, sg.rel)), beta)
            else
                try keyDenomsShift(a, pool, plan, st, witness, rvals, kk_, alpha.sub(relTag(g, tau, sg.rel)), beta);
            defer a.free(d);
            @memcpy(lden[n][o..][0..d.len], d);
            @memset(lnum[n][o..][0..d.len], QM31.one());
        },
        .table => {
            const rel = plan.rels[sg.idx];
            const shift = relTag(g, tau, sg.rel);
            for (vecs1[rel.mult], 0..) |m, t| {
                lnum[n][o + t] = qi(-@as(i64, m));
                lden[n][o + t] = alpha.sub(relKey(st, rel.kind, t, beta)).sub(shift);
            }
        },
        .blinder => lden[n][o] = QM31.fromBase(f.fromI32(vecs1[g.blinder][0])),
    };
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
    // (test builds with xt.test_unchecked_prover: a cheating prover continues, so that
    // adversarial tests reach the verifier)
    if (!lnum[0][0].isZero() and !(@import("builtin").is_test and xt.test_unchecked_prover)) return error.LogUpMismatch;
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
        // layer kk is consumed exactly once: fold its halves in place
        const A0 = lnum[kk][0..half];
        const A1 = lnum[kk][half..];
        const D0 = lden[kk][0..half];
        const D1 = lden[kk][half..];
        {
            const SC = struct { x: []QM31, lam: QM31 };
            const sc0 = SC{ .x = lnum[kk], .lam = lam };
            pool.parallelFor(lnum[kk].len, 8192, &sc0, struct {
                fn run(c: *const SC, s0: usize, e0: usize) void {
                    for (c.x[s0..e0]) |*v| v.* = c.lam.mul(v.*);
                }
            }.run);
        }
        // et and Q are supported on the first 2^min(m,4) entries
        const small = @min(half, 16);
        const et = try a.alloc(QM31, small);
        defer a.free(et);
        @memset(et, QM31.zero());
        const Q = try a.alloc(QM31, small);
        defer a.free(Q);
        @memset(Q, QM31.zero());
        var qs: QShape = undefined;
        var coef_q = QM31.zero();
        var w: [4]QM31 = undefined;
        if (kk == 1) {
            et[0] = QM31.one();
        } else {
            qs = qShape(m, &t_prev);
            const ett = try f.eqTable(a, qs.t_tail, QM31.one());
            defer a.free(ett);
            @memcpy(et[0..ett.len], ett);
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
        var out = try zks.proveGkrLayer(&T_GKR, a, pool, tr, claim, r_prev, .{ A0, A1, D0, D1 }, et, Q, small, hp, pctx);
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
    // virtual remainders of this tree: A^ = acc~(local) + P_A~(t_a), with
    // acc~ = r~ - 2^(s-1) + 2^s Y~ at the remainder leaf point
    const v0 = vrems.items.len;
    for (g.segs) |sg| {
        if (sg.kind != .key or !isVirtualRem(plan, plan.keys[sg.idx])) continue;
        const rk = plan.keys[sg.idx];
        const vc = vcheckOf(plan, sg.idx);
        const local = r_prev[g.n - rk.log_size ..];
        var t_a: [4]QM31 = undefined;
        tr.drawN(&t_a);
        var accv: QM31 = undefined;
        if (rk.kind == .ext) {
            accv = try mleI64(a, pool, xps.?.acc[plan.xkeys[rk.op].op].?, local);
        } else {
            const sh = opShift(st.ops[rk.op]);
            accv = (try f.mleEvalI32(a, rvals[rk.op], local)).sub(qi(shiftHalf(sh))).add(qi(@as(i64, 1) << sh).mul(try f.mleEvalI32(a, witness[opY(st.ops[rk.op])], local)));
        }
        const ahat = accv.add(try f.mleEvalI32(a, vecs1[vc.apad], &t_a));
        tr.mixFelt(ahat);
        try vrems.append(ar, .{ .local = try ar.dupe(QM31, local), .t_a = t_a, .ahat = ahat });
    }
    try gkrLeafClaims(ar, plan, st, g, alpha, beta, tau, r_prev, gam, c_prev, t_prev, pads_prev, ca, cb, vrems.items[v0..], claims);
}

/// et = eq((0, t_tail), .) and Q = [head = 0] P(t_lead, tail), supported on the first 2^mp entries.
fn qVectors(a: std.mem.Allocator, n: u32, t_a: [4]QM31, pad_cells: []const i32) !struct { et: []QM31, q: []QM31 } {
    const len = @as(usize, 1) << @intCast(n);
    const qs = qShape(n, &t_a);
    const et = try a.alloc(QM31, len);
    errdefer a.free(et);
    @memset(et, QM31.zero());
    const ett = try f.eqTable(a, qs.t_tail, QM31.one());
    defer a.free(ett);
    @memcpy(et[0..ett.len], ett);
    const q = try a.alloc(QM31, len);
    @memset(q, QM31.zero());
    const part = try padPartial(a, pad_cells, qs.t_lead);
    defer a.free(part.ptr[0..16]);
    @memcpy(q[0..part.len], part);
    return .{ .et = et, .q = q };
}

/// Masked einsum sumcheck  sum_{b,k} eq(rho_B, b) A'(b,k) B'(b,k) + sum et Q = claim
/// at rho = vr.local (prover).
fn proveEinsumMasked(a: std.mem.Allocator, pool: *f.Pool, tr: *Transcript, st: Statement, witness: []const []const i32, c: Check, vr: VRem, et: []QM31, Q: []QM31, specs: []const FSpec, hp: zks.Hp, pc: *const ProverCtx) !zks.ProveOut {
    const e = st.ext.ops[c.idx].einsum;
    const lay = xt.Layout.init(e);
    const fa = try xt.foldOperand(a, pool, lay, xt.refValues(st, witness, e.a), e.a_labels, vr.local);
    defer a.free(fa);
    const fb = try xt.foldOperand(a, pool, lay, xt.refValues(st, witness, e.b), e.b_labels, vr.local);
    defer a.free(fb);
    var bpt: [xt.MAXB]QM31 = undefined;
    for (0..lay.n_batch) |i| bpt[i] = vr.local[lay.batch[i]];
    const eqb = try f.eqTablePar(a, pool, bpt[0..lay.n_batch], QM31.one());
    defer a.free(eqb);
    const eqf = try a.alloc(QM31, fa.len);
    defer a.free(eqf);
    for (eqf, 0..) |*o, i| o.* = eqb[i >> @intCast(e.n_k)];
    std.debug.assert(fa.len == (@as(usize, 1) << @intCast(c.n)) and et.len == fa.len);
    return runMasked(5, &T_HADV, a, pool, tr, vr.ahat, .{ eqf, fa, fb, et, Q }, fa.len, specs, hp, pc);
}

/// Linear claim binding an exact einsum's output hat: Y~(rho) + P(t) = Y^ (Y absent: P(t) = Y^).
fn exactHatClaim(a: std.mem.Allocator, e: xt.Einsum, c: Check, vr: VRem, claims: *std.ArrayList(LClaim)) !void {
    var terms: std.ArrayList(LTerm) = .empty;
    if (e.y) |y| try terms.append(a, .{ .table = 0, .id = y, .coeff = QM31.one(), .form = .{ .eq = vr.local } });
    try terms.append(a, .{ .table = 0, .id = c.apad, .coeff = QM31.one(), .form = .{ .eq = try a.dupe(QM31, &vr.t_a) } });
    try claims.append(a, .{ .terms = try terms.toOwnedSlice(a), .value = vr.ahat });
}

/// Ext linear equalities expr == 0: one public-valued (0) linear claim each at a fresh point.
fn lineqClaims(a: std.mem.Allocator, tr: *Transcript, st: Statement, claims: *std.ArrayList(LClaim)) !void {
    for (st.ext.ops) |op| switch (op) {
        .lineq => |l| {
            const rho = try a.alloc(QM31, l.n);
            tr.drawN(rho);
            var terms: std.ArrayList(LTerm) = .empty;
            const pub_v = try exprLeaf(a, st, l.expr, rho, QM31.one(), QM31.one(), &terms);
            try claims.append(a, .{ .terms = try terms.toOwnedSlice(a), .value = pub_v.neg() });
        },
        else => {},
    };
}

/// Virtual remainder keys: core requant remainders (virtual mode) and every ext
/// requant-einsum remainder.
fn isVirtualRem(plan: Plan, k: Key) bool {
    return (plan.virt and k.kind == .remainder) or (k.kind == .ext and plan.xkeys[k.op].kind == .remainder);
}

/// (Y tensor, shift) of a virtual remainder key.
fn remYShift(plan: Plan, st: Statement, k: Key) struct { y: u32, s: u5 } {
    if (k.kind == .ext) {
        const e = st.ext.ops[plan.xkeys[k.op].op].einsum;
        return .{ .y = e.y.?, .s = e.shift };
    }
    return .{ .y = opY(st.ops[k.op]), .s = opShift(st.ops[k.op]) };
}

/// MLE of an integer vector at a point.
fn mleI64(a: std.mem.Allocator, pool: *f.Pool, vals: []const i64, pt: []const QM31) !QM31 {
    const eq = try f.eqTablePar(a, pool, pt, QM31.one());
    defer a.free(eq);
    var acc = QM31.zero();
    for (vals, eq) |v, w| acc = acc.add(w.mul(qi(v)));
    return acc;
}

/// The post-GKR check of remainder key `key` (virtual mode).
fn vcheckOf(plan: Plan, key: u32) Check {
    for (plan.vchecks) |c| if (c.key == key) return c;
    unreachable;
}

fn gkrVerifyRel(ar: std.mem.Allocator, tr: *Transcript, plan: Plan, st: Statement, alpha: QM31, beta: QM31, tau: QM31, g: GRel, d_root: QM31, layers: []const zks.MaskedProof, vhats: []const QM31, vrems: *std.ArrayList(VRem), claims: *std.ArrayList(LClaim)) !void {
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
    const v0 = vrems.items.len;
    for (g.segs) |sg| {
        if (sg.kind != .key or !isVirtualRem(plan, plan.keys[sg.idx])) continue;
        const k = plan.keys[sg.idx];
        var t_a: [4]QM31 = undefined;
        tr.drawN(&t_a);
        if (vrems.items.len >= vhats.len) return error.ProofShape;
        const ahat = vhats[vrems.items.len];
        tr.mixFelt(ahat);
        try vrems.append(ar, .{ .local = r_prev[g.n - k.log_size ..], .t_a = t_a, .ahat = ahat });
    }
    try gkrLeafClaims(ar, plan, st, g, alpha, beta, tau, r_prev, gam, c_prev, t_prev, pads_prev, ca, cb, vrems.items[v0..], claims);
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
    // the non-hiding prover refuses a hiding config
    {
        const dummy_info = [_]TensorInfo{TensorInfo.mat(2, 2)};
        var dummy: [16]i8 = [_]i8{0} ** 16;
        const dv = [_][]const i8{&dummy};
        var ws = try proto.commitWeights(a, &pool, cfg, &dummy_info, &dv);
        defer ws.deinit(a);
        var st0 = st;
        st0.weights = &dummy_info;
        try std.testing.expectError(error.HidingRequiresZkProve, proto.prove(a, &pool, cfg, st0, &ws, wv, &tm));
    }
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
    inline for (.{ "hat", "sigma", "u_val", "round", "bhat", "bsigma", "row", "mu", "auxrow", "auxmu" }) |what| {
        const ptr: *QM31 = if (comptime std.mem.eql(u8, what, "hat")) &proof.checks[0].hats[1] else if (comptime std.mem.eql(u8, what, "sigma")) &proof.checks[0].sigma else if (comptime std.mem.eql(u8, what, "u_val")) &proof.checks[0].u_val else if (comptime std.mem.eql(u8, what, "round")) &proof.checks[0].rounds[2][1] else if (comptime std.mem.eql(u8, what, "bhat")) &proof.batch.hats[0] else if (comptime std.mem.eql(u8, what, "bsigma")) &proof.batch.sigma else if (comptime std.mem.eql(u8, what, "row")) &proof.opening.flat.rows[1][3] else if (comptime std.mem.eql(u8, what, "auxrow")) &proof.aux_opening.?.rows[1][2] else if (comptime std.mem.eql(u8, what, "auxmu")) &proof.aux_opening.?.mus[0] else &proof.opening.flat.mus[0];
        ptr.* = ptr.*.add(one);
        try H.expectReject(a, cfg, st, &proof);
        ptr.* = ptr.*.sub(one);
    }
    proof.opening.flat.tables[0].values[5] = proof.opening.flat.tables[0].values[5].add(M31.one());
    try H.expectReject(a, cfg, st, &proof);
    proof.opening.flat.tables[0].values[5] = proof.opening.flat.tables[0].values[5].sub(M31.one());
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
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7 , .fused = false };
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
    prox.flat.rows[0][2] = prox.flat.rows[0][2].add(QM31.one());
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
    proof.weight_opening.?.flat.rows[0][1] = proof.weight_opening.?.flat.rows[0][1].add(QM31.one());
    try std.testing.expect(std.meta.isError(verify(a, cfg, st, key, &proof)));
    proof.weight_opening.?.flat.rows[0][1] = proof.weight_opening.?.flat.rows[0][1].sub(QM31.one());
    // statement change (shift) and wrong weight root are rejected
    const ops2 = try a.dupe(proto.Op, st.ops);
    defer a.free(ops2);
    ops2[1].matmul.shift += 1;
    var st2 = st;
    st2.ops = ops2;
    try std.testing.expect(std.meta.isError(verify(a, cfg, st2, key, &proof)));
    // public input and output: bound to the proof, everything else hidden
    {
        var zwp = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zwp.deinit(a);
        const keyp = zwp.key();
        const pubs = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = 5, .values = wv[5] } };
        var pp = try provePublic(a, &pool, cfg, st, &zwp, wv, &pubs, &tm);
        defer pp.deinit(a);
        try verifyPublic(a, cfg, st, keyp, &pubs, &pp);
        // a different claimed output is rejected
        const out2 = try a.dupe(i32, wv[5]);
        defer a.free(out2);
        out2[7] +%= 1;
        const pubs2 = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = 5, .values = out2 } };
        try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, keyp, &pubs2, &pp)));
        // the proof is bound to its public tensors: no public tensors -> different transcript
        try std.testing.expect(std.meta.isError(verify(a, cfg, st, keyp, &pp)));
        // the prover refuses public values that are not the witness
        try std.testing.expectError(error.PublicMismatch, provePublic(a, &pool, cfg, st, &zwp, wv, &pubs2, &tm));
    }
    // statement weight shapes must match the key
    var winfos_bad = winfos;
    winfos_bad[2].log_dims[1] -= 1;
    var st3 = st;
    st3.weights = &winfos_bad;
    try std.testing.expectError(error.StatementShape, verify(a, cfg, st3, key, &proof));
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
        rr.link.opening.flat.rows[0][0] = rr.link.opening.flat.rows[0][0].add(QM31.one());
        try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link)));
        rr.link.opening.flat.rows[0][0] = rr.link.opening.flat.rows[0][0].sub(QM31.one());
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
    // weight table wider than the matmul output dims: one opening group per matmul
    {
        var cfgw = cfg;
        cfgw.weight_log_cols = 8;
        var zww = try commitWeights(a, &pool, cfgw, &winfos, &wvv);
        defer zww.deinit(a);
        var pw = try prove(a, &pool, cfgw, st, &zww, wv, &tm);
        defer pw.deinit(a);
        try verify(a, cfgw, st, zww.key(), &pw);
        try std.testing.expectEqual(@as(usize, 3), pw.weight_opening.?.flat.rows.len);
        pw.weight_opening.?.flat.rows[2][5] = pw.weight_opening.?.flat.rows[2][5].add(QM31.one());
        try std.testing.expect(std.meta.isError(verify(a, cfgw, st, zww.key(), &pw)));
        pw.weight_opening.?.flat.rows[2][5] = pw.weight_opening.?.flat.rows[2][5].sub(QM31.one());
        pw.checks[0].hats[1] = pw.checks[0].hats[1].add(QM31.one());
        try std.testing.expect(std.meta.isError(verify(a, cfgw, st, zww.key(), &pw)));
    }
    try std.testing.expectEqual(@as(usize, 6), proof3.weight_opening.?.flat.tables[0].salts.len);
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
            for (proof.opening.flat.tables[0].values) |v| Acc.add(&n_vals, &top, &zeros, &mean, v.v);
            for (proof.opening.flat.rows) |r| for (r) |q| for (f.limbs(q)) |l| Acc.add(&n_vals, &top, &zeros, &mean, l);
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
    // both graphs: unfused (silu lookup + hadamard) and fused (one glu triple lookup)
    try mlpStatSanity(false);
    try mlpStatSanity(true);
}

fn mlpStatSanity(fused: bool) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var cfg = testCfg();
    cfg.weight_mask_slots = 64;
    cfg.weight_pcs = .{ .log_blowup = 3, .n_queries = 4, .pow_bits = 1 };
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = fused };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 300 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var stats: [2][2]f64 = undefined;
    for (0..2) |case| {
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(mc.log_t + mc.log_d), 77);
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

test "zk plan: relations share one tagged GKR tree when that pads less" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = testCfg();
    var saw_tagged = false;
    for ([_]u32{ 3, 4, 5, 6 }) |log_t| {
        var arena_state = std.heap.ArenaAllocator.init(a);
        defer arena_state.deinit();
        const ar = arena_state.allocator();
        const mc = model.Mlp{ .log_t = log_t, .log_d = 6, .log_f = 7 , .fused = false };
        const winfos = model.mlpWeightInfos(mc);
        var wdata: [3][]i8 = undefined;
        for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
        defer for (wdata) |w| a.free(w);
        const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
        var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zw.deinit(a);
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(mc.log_t + mc.log_d), 9);
        defer a.free(x);
        const pv = zw.plainView();
        var built = try model.buildMlp(a, &pool, &pv, mc, x);
        defer built.deinit(a);
        const st = built.statement();
        const plan = try makePlan(ar, st, zw.key(), cfg);
        // the chosen layout pads no more than the alternative
        var total: usize = 0;
        for (plan.grels) |g| total += @as(usize, 1) << @intCast(g.n);
        var sep: usize = 0;
        var all: usize = 1;
        for (plan.rels, 0..) |rel, ri| {
            var cnt: usize = 1 + (@as(usize, 1) << @intCast(rel.log_size));
            for (plan.keys) |k| if (k.rel == ri) {
                cnt += @as(usize, 1) << @intCast(k.log_size);
            };
            sep += try std.math.ceilPowerOfTwo(usize, cnt);
            all += @as(usize, 1) << @intCast(rel.log_size);
        }
        for (plan.keys) |k| all += @as(usize, 1) << @intCast(k.log_size);
        try std.testing.expectEqual(@min(sep, try std.math.ceilPowerOfTwo(usize, all)), total);
        if (plan.grels.len == 1 and plan.grels[0].tagged) {
            saw_tagged = true;
            var n_tables: usize = 0;
            for (plan.grels[0].segs) |sg| n_tables += @intFromBool(sg.kind == .table);
            try std.testing.expectEqual(plan.rels.len, n_tables);
            var tm: proto.Timings = .{};
            const wv = try wview(a, built.witness);
            defer a.free(wv);
            var proof = try prove(a, &pool, cfg, st, &zw, wv, &tm);
            defer proof.deinit(a);
            try verify(a, cfg, st, zw.key(), &proof);
            try std.testing.expectEqual(@as(usize, 1), proof.gkr_roots.len);
            const L = proof.gkr_layers.len;
            proof.gkr_layers[L - 1].hats[2] = proof.gkr_layers[L - 1].hats[2].add(QM31.one());
            try std.testing.expect(std.meta.isError(verify(a, cfg, st, zw.key(), &proof)));
        }
    }
    try std.testing.expect(saw_tagged);
}

// ---------------------------------------------------------------------------
// Recursive hiding PCS mode (Config.two_level).

fn testCfgRec(depth: u32) proto.Config {
    var c = testCfg();
    c.two_level = .{ .inner = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .depth = depth, .inner_work_shift = 0 };
    return c;
}

fn tamperRec(op: *zkp2.Opening, comptime what: []const u8, undo: bool) void {
    const one = QM31.one();
    const d = if (undo) one.neg() else one;
    if (comptime std.mem.eql(u8, what, "col")) {
        op.tables[0].values[5] = if (undo) op.tables[0].values[5].sub(M31.one()) else op.tables[0].values[5].add(M31.one());
    } else if (comptime std.mem.eql(u8, what, "salt")) {
        op.tables[0].salts[0][3] ^= 1;
    } else if (comptime std.mem.eql(u8, what, "mu")) {
        op.mus[0] = op.mus[0].add(d);
    } else if (comptime std.mem.eql(u8, what, "root")) {
        op.inner_root[7] ^= 1;
    } else if (comptime std.mem.eql(u8, what, "round")) {
        op.sumcheck.rounds[1].evals[1] = op.sumcheck.rounds[1].evals[1].add(d);
    } else if (comptime std.mem.eql(u8, what, "limb")) {
        op.limb_vals[3] = op.limb_vals[3].add(d);
    } else if (comptime std.mem.eql(u8, what, "inner_col")) {
        const lp = &op.inner.levels[1];
        lp.col_values[2] = if (undo) lp.col_values[2].sub(M31.one()) else lp.col_values[2].add(M31.one());
    } else if (comptime std.mem.eql(u8, what, "final_row")) {
        const lp = &op.inner.levels[op.inner.levels.len - 1];
        lp.rows[0][1] = lp.rows[0][1].add(d);
    } else @compileError("unknown");
}

const REC_FIELDS = .{ "col", "salt", "root", "round", "limb", "inner_col", "final_row" };

test "zk recursive PCS refuses the non-hiding pcs2 OOD / deep extensions" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var built = try model.buildProduct(a, 9, 3);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try wview(a, built.witness);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try prove(a, &pool, testCfgRec(1), st, null, wv, &tm);
    defer proof.deinit(a);
    var c_ood = testCfgRec(1);
    c_ood.two_level.?.ood = true;
    try std.testing.expectError(error.ZkOodUnsupported, prove(a, &pool, c_ood, st, null, wv, &tm));
    try std.testing.expectError(error.ZkOodUnsupported, verify(a, c_ood, st, null, &proof));
    var c_deep = testCfgRec(2);
    c_deep.two_level.?.deep = .{ .log_blowup = 3, .n_queries = 8, .pow_bits = 1 };
    try std.testing.expectError(error.ZkDeepUnsupported, prove(a, &pool, c_deep, st, null, wv, &tm));
}

test "zk recursive PCS: product proves, verifies, rejects tampering and mode mismatch" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var built = try model.buildProduct(a, 9, 3);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try wview(a, built.witness);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    for ([_]u32{ 1, 2 }) |depth| {
        const cfg = testCfgRec(depth);
        var proof = try prove(a, &pool, cfg, st, null, wv, &tm);
        defer proof.deinit(a);
        try verify(a, cfg, st, null, &proof);
        try std.testing.expect(proof.opening == .rec);
        try std.testing.expectEqual(@as(usize, depth + 1), proof.opening.rec.inner.levels.len);
        inline for (REC_FIELDS ++ .{"mu"}) |what| {
            tamperRec(&proof.opening.rec, what, false);
            try std.testing.expect(std.meta.isError(verify(a, cfg, st, null, &proof)));
            tamperRec(&proof.opening.rec, what, true);
        }
        // the batch hat and an op hat still bind through the recursive opening
        proof.batch.hats[0] = proof.batch.hats[0].add(QM31.one());
        try std.testing.expect(std.meta.isError(verify(a, cfg, st, null, &proof)));
        proof.batch.hats[0] = proof.batch.hats[0].sub(QM31.one());
        proof.root1[0] ^= 1;
        try std.testing.expect(std.meta.isError(verify(a, cfg, st, null, &proof)));
        proof.root1[0] ^= 1;
        try verify(a, cfg, st, null, &proof);
        // a flat-mode verifier and a verifier with another depth reject it
        try std.testing.expect(std.meta.isError(verify(a, testCfg(), st, null, &proof)));
        try std.testing.expect(std.meta.isError(verify(a, testCfgRec(depth + 1), st, null, &proof)));
    }
    // depth 0 is not a recursive mode
    try std.testing.expectError(error.ZkTwoLevelDepth, prove(a, &pool, testCfgRec(0), st, null, wv, &tm));
}

test "zk recursive PCS: mlp weights, proximity, link, budget, tampering" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = testCfgRec(1);
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = false };
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
    try std.testing.expect(prox == .rec);
    inline for (REC_FIELDS) |what| {
        tamperRec(&prox.rec, what, false);
        try std.testing.expect(std.meta.isError(verifyWeightProximity(a, cfg, key, prox)));
        tamperRec(&prox.rec, what, true);
    }
    try verifyWeightProximity(a, cfg, key, prox);
    try std.testing.expect(std.meta.isError(verifyWeightProximity(a, testCfg(), key, prox)));

    const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
    defer a.free(x);
    const pv = zw.plainView();
    var built = try model.buildMlp(a, &pool, &pv, mc, x);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try wview(a, built.witness);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    const pubs = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = @intCast(wv.len - 1), .values = wv[wv.len - 1] } };
    var proof = try provePublic(a, &pool, cfg, st, &zw, wv, &pubs, &tm);
    defer proof.deinit(a);
    try verifyPublic(a, cfg, st, key, &pubs, &proof);
    try std.testing.expect(proof.weight_opening.? == .rec);
    inline for (REC_FIELDS ++ .{"mu"}) |what| {
        tamperRec(&proof.weight_opening.?.rec, what, false);
        try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
        tamperRec(&proof.weight_opening.?.rec, what, true);
        tamperRec(&proof.opening.rec, what, false);
        try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
        tamperRec(&proof.opening.rec, what, true);
    }
    // the weight table (2nd outer table: the per-proof mask table) is opened too
    proof.weight_opening.?.rec.tables[1].values[0] = proof.weight_opening.?.rec.tables[1].values[0].add(M31.one());
    try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
    proof.weight_opening.?.rec.tables[1].values[0] = proof.weight_opening.?.rec.tables[1].values[0].sub(M31.one());
    // W hat and a GKR hat still bind
    proof.checks[0].hats[1] = proof.checks[0].hats[1].add(QM31.one());
    try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
    proof.checks[0].hats[1] = proof.checks[0].hats[1].sub(QM31.one());
    proof.gkr_layers[2].hats[0] = proof.gkr_layers[2].hats[0].add(QM31.one());
    try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
    proof.gkr_layers[2].hats[0] = proof.gkr_layers[2].hats[0].sub(QM31.one());
    try verifyPublic(a, cfg, st, key, &pubs, &proof);
    var key2 = key;
    key2.root[1] ^= 1;
    try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key2, &pubs, &proof)));

    // re-randomization link (recursive): verifies, tampering / swapped roots / other weights rejected
    {
        var zw0 = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zw0.deinit(a);
        var rr = try rerandomizeWeights(a, &pool, cfg, &zw0);
        defer rr.new.deinit(a);
        defer rr.link.deinit(a);
        try verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link);
        try std.testing.expect(rr.link.opening == .rec);
        inline for (REC_FIELDS ++ .{"mu"}) |what| {
            tamperRec(&rr.link.opening.rec, what, false);
            try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link)));
            tamperRec(&rr.link.opening.rec, what, true);
        }
        try verifyWeightLink(a, cfg, zw0.key(), rr.new.key(), rr.link);
        try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, rr.new.key(), zw0.key(), rr.link)));
        var pn = try prove(a, &pool, cfg, st, &rr.new, wv, &tm);
        defer pn.deinit(a);
        try verify(a, cfg, st, rr.new.key(), &pn);
        const other = try model.randomWeights(a, winfos[1].size(), 999, -8, 7);
        defer a.free(other);
        const wvo = [_][]const i8{ wdata[0], other, wdata[2] };
        var zo = try commitWeights(a, &pool, cfg, &winfos, &wvo);
        defer zo.deinit(a);
        var bad = try proveWeightLink(a, &pool, cfg, &zw0, &zo);
        defer bad.deinit(a);
        try std.testing.expect(std.meta.isError(verifyWeightLink(a, cfg, zw0.key(), zo.key(), bad)));
    }

    // the outer weight budget (slots/2 = 32 columns) is enforced in the recursive mode too
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
}

test "zk recursive PCS statistical sanity: zero vs random witness, every level" {
    // Everything the recursive opening reveals (outer columns, committed-row
    // sumcheck, limb values, inner columns, final rows) must look uniform for an
    // all-zero witness, and alike for zero and random witnesses.
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var cfg = testCfgRec(2);
    cfg.pcs.n_queries = 16;
    var stats: [2][3]f64 = undefined;
    for (0..2) |case| {
        var built = try model.buildProduct(a, 10, 21);
        defer built.deinit(a);
        if (case == 0) for (built.witness) |w| @memset(w, 0);
        const st = built.statement();
        const wv = try wview(a, built.witness);
        defer a.free(wv);
        const ws = try witnessShape(a, cfg, st, null);
        const ish = zkp2.innerShapeFor(cfg.pcs, cfg.two_level.?, 2, ws.log_cols);
        const C = @as(usize, 1) << @intCast(ws.log_cols);
        const C1 = @as(usize, 1) << @intCast(ish.log_cols);
        var tm: proto.Timings = .{};
        var acc = [_]f64{0} ** 4; // n, top, zeros, mean
        const Acc = struct {
            fn add(x: *[4]f64, v: u32) void {
                x[0] += 1;
                if (v >= f.P / 2) x[1] += 1;
                if (v == 0) x[2] += 1;
                x[3] += @as(f64, @floatFromInt(v)) / @as(f64, @floatFromInt(f.P));
            }
            fn addQ(x: *[4]f64, q: QM31) void {
                for (f.limbs(q)) |l| add(x, l);
            }
        };
        for (0..4) |_| {
            var proof = try prove(a, &pool, cfg, st, null, wv, &tm);
            defer proof.deinit(a);
            try verify(a, cfg, st, null, &proof);
            const op = proof.opening.rec;
            for (op.tables[0].values) |v| Acc.add(&acc, v.v);
            for (op.sumcheck.rounds) |r| for (r.evals[0..2]) |e| Acc.addQ(&acc, e);
            for (op.limb_vals) |l| Acc.addQ(&acc, l);
            const nl = op.inner.levels.len;
            for (op.inner.levels[1..], 1..) |lp, li| {
                if (li == 1) {
                    // level-1 rows lying in the public zero tail [C + S, 2C) of a U row are skipped
                    const R1 = ish.rows_used;
                    for (0..lp.col_values.len / R1) |q| for (0..R1) |row| {
                        if ((row * C1) % (2 * C) < C + ws.slots) Acc.add(&acc, lp.col_values[q * R1 + row].v);
                    };
                } else for (lp.col_values) |v| Acc.add(&acc, v.v);
                for (lp.rows) |row| for (row) |q| Acc.addQ(&acc, q);
                for (lp.sumcheck.rounds) |r| for (r.evals[0..2]) |e| Acc.addQ(&acc, e);
                if (li + 1 < nl) for (lp.limb_vals) |l| Acc.addQ(&acc, l);
            }
            for (proof.batch.hats) |q| Acc.addQ(&acc, q);
        }
        stats[case] = .{ acc[1] / acc[0], acc[2] / acc[0], acc[3] / acc[0] };
    }
    for (stats) |s| {
        try std.testing.expect(@abs(s[0] - 0.5) < 0.02);
        try std.testing.expect(s[1] < 0.001);
        try std.testing.expect(@abs(s[2] - 0.5) < 0.02);
    }
    try std.testing.expect(@abs(stats[0][0] - stats[1][0]) < 0.03);
    try std.testing.expect(@abs(stats[0][2] - stats[1][2]) < 0.03);
}

// ---------------------------------------------------------------------------
// Fused SwiGLU (glu triple lookup) in hiding mode.

test "zk fused glu MLP (flat and recursive PCS): verifies, binds the glu statement, refuses wrong outputs" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = true };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    for ([_]proto.Config{ testCfg(), testCfgRec(1) }) |cfg| {
        var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zw.deinit(a);
        const key = zw.key();
        const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
        defer a.free(x);
        const pv = zw.plainView();
        var built = try model.buildMlp(a, &pool, &pv, mc, x);
        defer built.deinit(a);
        const st = built.statement();
        var n_glu: usize = 0;
        for (st.ops) |op| n_glu += @intFromBool(op == .glu);
        try std.testing.expectEqual(@as(usize, 1), n_glu);
        const wv = try wview(a, built.witness);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        const pubs = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = @intCast(wv.len - 1), .values = wv[wv.len - 1] } };
        var proof = try provePublic(a, &pool, cfg, st, &zw, wv, &pubs, &tm);
        defer proof.deinit(a);
        try verifyPublic(a, cfg, st, key, &pubs, &proof);
        // the fused graph needs no y-range keys for gate/up (implied by the glu table)
        // and no hadamard remainder: only the 3 matmul checks remain
        try std.testing.expectEqual(@as(usize, 3), proof.checks.len);
        // a GKR leaf-layer hat and root bind the triple
        {
            const L = proof.gkr_layers.len;
            const targets = [_]*QM31{ &proof.gkr_roots[0], &proof.gkr_layers[L - 1].hats[1], &proof.gkr_layers[L - 1].hats[3] };
            for (targets) |ptr| {
                ptr.* = ptr.*.add(QM31.one());
                try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
                ptr.* = ptr.*.sub(QM31.one());
            }
        }
        // the glu statement (shift, table values) is bound
        {
            const ops2 = try a.dupe(proto.Op, st.ops);
            defer a.free(ops2);
            for (ops2) |*op| if (op.* == .glu) {
                op.glu.shift += 1;
            };
            var st2 = st;
            st2.ops = ops2;
            try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st2, key, &pubs, &proof)));
            var tv = st.tables[0].values;
            tv[200] +%= 1;
            const tabs2 = [_]proto.Table{.{ .values = tv }};
            var st3 = st;
            st3.tables = &tabs2;
            try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st3, key, &pubs, &proof)));
        }
        try verifyPublic(a, cfg, st, key, &pubs, &proof);
        // a wrong glu output, and gate values outside int8, are refused by the prover
        {
            var hid: u32 = 0;
            var gid: u32 = 0;
            for (st.ops) |op| if (op == .glu) {
                hid = op.glu.h;
                gid = op.glu.g;
            };
            // (the down matmul's remainder check or the glu table check refuses it)
            built.witness[hid][5] +%= 1;
            try std.testing.expect(std.meta.isError(prove(a, &pool, cfg, st, &zw, wv, &tm)));
            built.witness[hid][5] -%= 1;
            // gate value pushed outside the glu table domain
            built.witness[gid][3] = 300;
            try std.testing.expect(std.meta.isError(prove(a, &pool, cfg, st, &zw, wv, &tm)));
        }
    }
    // a malformed glu statement (shift 0) is rejected by the plan
    {
        const cfg = testCfg();
        var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
        defer zw.deinit(a);
        const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
        defer a.free(x);
        const pv = zw.plainView();
        var built = try model.buildMlp(a, &pool, &pv, mc, x);
        defer built.deinit(a);
        const st = built.statement();
        const ops2 = try a.dupe(proto.Op, st.ops);
        defer a.free(ops2);
        for (ops2) |*op| if (op.* == .glu) {
            op.glu.shift = 0;
        };
        var st2 = st;
        st2.ops = ops2;
        const wv = try wview(a, built.witness);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        try std.testing.expectError(error.StatementShape, prove(a, &pool, cfg, st2, &zw, wv, &tm));
    }
}

// ---------------------------------------------------------------------------
// Virtual remainders (Config.zk_virtual_remainders).

test "zk virtual remainders: MLPs verify under both PCS modes, smaller table, tampering rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    for ([_]bool{ false, true }) |fused| {
        const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = fused };
        const winfos = model.mlpWeightInfos(mc);
        var wdata: [3][]i8 = undefined;
        for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 500 + i, -8, 7);
        defer for (wdata) |w| a.free(w);
        const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
        for ([_]proto.Config{ testCfg(), testCfgRec(1) }) |base| {
            var cfg = base;
            cfg.zk_virtual_remainders = true;
            var zw = try commitWeights(a, &pool, cfg, &winfos, &wvv);
            defer zw.deinit(a);
            const key = zw.key();
            const x = try model.randomInput(a, @as(usize, 1) << @intCast(mc.log_t + mc.log_d), 19);
            defer a.free(x);
            const pv = zw.plainView();
            var built = try model.buildMlp(a, &pool, &pv, mc, x);
            defer built.deinit(a);
            const st = built.statement();
            const wv = try wview(a, built.witness);
            defer a.free(wv);
            const pubs = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = @intCast(wv.len - 1), .values = wv[wv.len - 1] } };
            var tm: proto.Timings = .{};
            var proof = try provePublic(a, &pool, cfg, st, &zw, wv, &pubs, &tm);
            defer proof.deinit(a);
            try verifyPublic(a, cfg, st, key, &pubs, &proof);
            // one post-GKR check per remainder (3 matmuls, + the hadamard when unfused)
            const n_rem: usize = if (fused) 3 else 4;
            try std.testing.expectEqual(n_rem, proof.vchecks.len);
            try std.testing.expectEqual(n_rem, proof.vrem_hats.len);
            // the remainders are no longer committed
            {
                var cfg_c = base;
                cfg_c.zk_virtual_remainders = false;
                var zwc = try commitWeights(a, &pool, cfg_c, &winfos, &wvv);
                defer zwc.deinit(a);
                var tmc: proto.Timings = .{};
                var pc = try provePublic(a, &pool, cfg_c, st, &zwc, wv, &pubs, &tmc);
                defer pc.deinit(a);
                try std.testing.expect(tm.witness_table_elems < tmc.witness_table_elems);
                // a virtual-mode verifier rejects a committed-remainder proof and vice versa
                try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, zwc.key(), &pubs, &pc)));
                try std.testing.expect(std.meta.isError(verifyPublic(a, cfg_c, st, key, &pubs, &proof)));
            }
            // tampering: accumulator hat, check hats (X, W, Q), round message, u, sigma
            {
                const vc = &proof.vchecks[0];
                const targets = [_]*QM31{ &proof.vrem_hats[0], &proof.vrem_hats[n_rem - 1], &vc.hats[0], &vc.hats[1], &vc.hats[2], &vc.rounds[1][0], &vc.u_val, &vc.sigma, &proof.vchecks[n_rem - 1].hats[1] };
                for (targets) |ptr| {
                    ptr.* = ptr.*.add(QM31.one());
                    try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
                    ptr.* = ptr.*.sub(QM31.one());
                }
                try verifyPublic(a, cfg, st, key, &pubs, &proof);
            }
            // a changed requant shift (the remainder relation) is rejected
            {
                const ops2 = try a.dupe(proto.Op, st.ops);
                defer a.free(ops2);
                for (ops2) |*op| if (op.* == .matmul) {
                    op.matmul.shift += 1;
                    break;
                };
                var st2 = st;
                st2.ops = ops2;
                try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st2, key, &pubs, &proof)));
            }
            // a wrong requant output is refused by the prover
            built.witness[1][2] +%= 1;
            try std.testing.expect(std.meta.isError(provePublic(a, &pool, cfg, st, &zw, wv, &.{}, &tm)));
            built.witness[1][2] -%= 1;
        }
    }
    // virtual remainders need the masked GKR
    {
        var cfg = testCfg();
        cfg.zk_virtual_remainders = true;
        cfg.zk_logup_gkr = false;
        var built = try model.buildProduct(a, 6, 3);
        defer built.deinit(a);
        const wv = try wview(a, built.witness);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        try std.testing.expectError(error.ZkVirtualNeedsGkr, prove(a, &pool, cfg, built.statement(), null, wv, &tm));
    }
}

test "zk virtual remainders statistical sanity: accumulator hats and check hats, zero vs random input" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var cfg = testCfg();
    cfg.zk_virtual_remainders = true;
    cfg.weight_mask_slots = 64;
    cfg.weight_pcs = .{ .log_blowup = 3, .n_queries = 4, .pow_bits = 1 };
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = false };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 700 + i, -8, 7);
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
        for (0..6) |_| {
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
            try vals.appendSlice(a, proof.vrem_hats);
            for (proof.vchecks) |c| {
                try vals.appendSlice(a, c.hats);
                try vals.append(a, c.sigma);
            }
            for (vals.items) |q| for (f.limbs(q)) |l| {
                n_vals += 1;
                if (l >= f.P / 2) top += 1;
                mean += @as(f64, @floatFromInt(l)) / @as(f64, @floatFromInt(f.P));
            };
        }
        stats[case] = .{ top / n_vals, mean / n_vals };
    }
    for (stats) |s| {
        try std.testing.expect(@abs(s[0] - 0.5) < 0.06);
        try std.testing.expect(@abs(s[1] - 0.5) < 0.06);
    }
}

// ---------------------------------------------------------------------------
// Ext ops (attention, softmax, RMSNorm, RoPE, residual, MoE) in hiding mode.

const tfm = @import("transformer.zig");

const LayerFixture = struct {
    zw: ZkWeights,
    wdata: [][]i8,
    winfos: []TensorInfo,
    b: tfm.Builder,
    out: tfm.LayerOut = undefined,

    fn init(self: *LayerFixture, a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, lc: tfm.LayerCfg, seed: u64) !void {
        self.winfos = try tfm.layerWeightInfos(a, lc);
        self.wdata = try a.alloc([]i8, self.winfos.len);
        const wv = try a.alloc([]const i8, self.winfos.len);
        defer a.free(wv);
        for (self.wdata, 0..) |*w, i| {
            w.* = try model.randomWeights(a, self.winfos[i].size(), seed + i, -8, 7);
            wv[i] = w.*;
        }
        self.zw = try commitWeights(a, pool, cfg, self.winfos, wv);
        self.b = tfm.Builder.init(a, pool);
        const pv = self.zw.plainView();
        const c = try tfm.initCtx(&self.b, lc, &pv, 1);
        const x = try model.randomInput(a, @as(usize, 1) << @intCast(lc.log_t + lc.log_d), 17);
        defer a.free(x);
        self.out = try tfm.buildStack(&self.b, c, x);
    }

    fn deinit(self: *LayerFixture, a: std.mem.Allocator) void {
        self.b.deinit();
        self.zw.deinit(a);
        for (self.wdata) |w| a.free(w);
        a.free(self.wdata);
        a.free(self.winfos);
    }
};

fn layerCfgZk() proto.Config {
    var c = testCfg();
    c.weight_log_cols = 6;
    c.zk_virtual_remainders = true;
    return c;
}

test "zk decoder layer (GQA attention, RoPE, softmax, RMSNorm, SwiGLU): verifies, tampering rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const lc = tfm.LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    for ([_]bool{ false, true }) |rec| {
        var cfg = layerCfgZk();
        if (rec) cfg.two_level = .{ .inner = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .depth = 1, .inner_work_shift = 0 };
        var fx: LayerFixture = undefined;
        try fx.init(a, &pool, cfg, lc, 300);
        defer fx.deinit(a);
        const st = fx.b.statement();
        try std.testing.expect(st.ext.ops.len > 0);
        const wv = try fx.b.witnessView(a);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        const key = fx.zw.key();
        const pubs = [_]PublicTensor{ .{ .id = 0, .values = wv[0] }, .{ .id = @intCast(wv.len - 1), .values = wv[wv.len - 1] } };
        var proof = try provePublic(a, &pool, cfg, st, &fx.zw, wv, &pubs, &tm);
        defer proof.deinit(a);
        try verifyPublic(a, cfg, st, key, &pubs, &proof);
        try std.testing.expect(proof.xchecks.len > 0 and proof.vchecks.len > 0);
        // tamper: ext output hats, einsum check hats / rounds, accumulator hats, GKR
        {
            var targets: std.ArrayList(*QM31) = .empty;
            defer targets.deinit(a);
            try targets.append(a, &proof.xhats[0]);
            try targets.append(a, &proof.xhats[proof.xhats.len - 1]);
            try targets.append(a, &proof.vrem_hats[proof.vrem_hats.len - 1]);
            for (proof.xchecks, 0..) |*c, i| if (i % 2 == 0) {
                try targets.append(a, &c.hats[0]);
                try targets.append(a, &c.hats[c.hats.len - 1]);
                try targets.append(a, &c.rounds[0][0]);
            };
            for (proof.vchecks, 0..) |*c, i| if (i % 3 == 0) {
                try targets.append(a, &c.hats[0]);
                try targets.append(a, &c.u_val);
            };
            try targets.append(a, &proof.gkr_layers[proof.gkr_layers.len - 1].hats[2]);
            for (targets.items) |ptr| {
                ptr.* = ptr.*.add(QM31.one());
                try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st, key, &pubs, &proof)));
                ptr.* = ptr.*.sub(QM31.one());
            }
        }
        try verifyPublic(a, cfg, st, key, &pubs, &proof);
        // public operands are bound: a changed causal mask / RoPE table is rejected
        {
            const pubv = try a.alloc(xt.Public, st.ext.publics.len);
            defer a.free(pubv);
            @memcpy(pubv, st.ext.publics);
            const vals = try a.dupe(i32, pubv[0].values);
            defer a.free(vals);
            vals[1] +%= 1;
            pubv[0].values = vals;
            var st2 = st;
            st2.ext.publics = pubv;
            try std.testing.expect(std.meta.isError(verifyPublic(a, cfg, st2, key, &pubs, &proof)));
        }
        // a witness that violates an attention / softmax relation is refused by the prover
        {
            const wid = st.witness.len / 2;
            fx.b.wit.items[wid][0] +%= 1;
            const wv2 = try fx.b.witnessView(a);
            defer a.free(wv2);
            try std.testing.expect(std.meta.isError(prove(a, &pool, cfg, st, &fx.zw, wv2, &tm)));
            fx.b.wit.items[wid][0] -%= 1;
        }
    }
}

const ZkCheat = enum { prob_plus_one, rden_plus_one, rt_plus_one, residual, exp_value, masked_exp, score, ss_value, sel_nonbinary };

fn zkCheatCase(a: std.mem.Allocator, pool: *f.Pool, cheat: ZkCheat) !void {
    const lc = tfm.LayerCfg{ .log_t = 2, .log_d = 4, .log_f = 5, .log_heads = 2, .log_kv_heads = 1 };
    const cfg = layerCfgZk();
    var fx: LayerFixture = undefined;
    try fx.init(a, pool, cfg, lc, 77);
    defer fx.deinit(a);
    const b = &fx.b;
    const at = fx.out.attn;
    const T = @as(usize, 1) << @intCast(lc.log_t);
    const row = T - 1; // head 0, last token: no masked positions
    const sel = b.wit.items[at.sel];
    var jstar: usize = 0;
    for (0..T) |j| if (sel[row * T + j] == 1) {
        jstar = j;
    };
    switch (cheat) {
        .prob_plus_one => b.wit.items[at.od][0] += 1, // division-inequality output (softmax restructure, EXT-1)
        .rden_plus_one => b.wit.items[at.den][row] += 1, // row denominator (replaces rden)
        .rt_plus_one => b.wit.items[fx.out.rms1.rt][0] += 1,
        .residual => b.wit.items[fx.out.h][0] += 1,
        .exp_value => b.wit.items[at.e][row * T + jstar] -= 1,
        .masked_exp => b.wit.items[at.e][1] = 3, // (t = 0, j = 1) is masked
        .score => b.wit.items[at.scores][row * T] += 1,
        .ss_value => b.wit.items[fx.out.rms2.ss][0] += 1,
        .sel_nonbinary => {
            const jo = (jstar + 1) % T;
            sel[row * T + jstar] = 2;
            sel[row * T + jo] = -1;
        },
    }
    xt.test_unchecked_prover = true;
    defer xt.test_unchecked_prover = false;
    zks.test_cheating_prover = true;
    defer zks.test_cheating_prover = false;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = prove(a, pool, cfg, st, &fx.zw, wv, &tm) catch |e| {
        // some cheats break a core relation the hiding prover always checks (not a verifier test)
        if (e == error.RemainderOutOfRange or e == error.ValueOutOfRange or e == error.LookupMismatch) return error.SkipZkCheat;
        return e;
    };
    defer proof.deinit(a);
    if (verify(a, cfg, st, fx.zw.key(), &proof)) |_| return error.TamperAccepted else |_| {}
}

test "zk decoder layer: verifier rejects invalid attention / softmax / RMSNorm / residual witnesses (cheating prover)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var n_run: usize = 0;
    inline for (@typeInfo(ZkCheat).@"enum".fields) |fld| {
        if (zkCheatCase(a, &pool, @enumFromInt(fld.value))) |_| {
            n_run += 1;
        } else |err| {
            if (err != error.SkipZkCheat) {
                std.debug.print("zk cheat case {s} failed: {}\n", .{ fld.name, err });
                return err;
            }
        }
    }
    try std.testing.expect(n_run >= 6);
}

test "zk MoE top-1 layer (routing, dispatch, combine): verifies under both PCS modes, tampering rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // MoE config of transformer.zig's tests; router columns = weight table columns
    const lc = tfm.LayerCfg{ .log_t = 3, .log_d = 4, .log_f = 5, .log_heads = 1, .log_kv_heads = 1, .log_experts = 2, .log_capacity = 3, .router_log_cols = 6 };
    for ([_]bool{ false, true }) |rec| {
        var cfg = layerCfgZk();
        if (rec) cfg.two_level = .{ .inner = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .depth = 1, .inner_work_shift = 0 };
        var fx: LayerFixture = undefined;
        try fx.init(a, &pool, cfg, lc, 600);
        defer fx.deinit(a);
        try std.testing.expect(fx.out.moe != null);
        const st = fx.b.statement();
        const wv = try fx.b.witnessView(a);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        var proof = try prove(a, &pool, cfg, st, &fx.zw, wv, &tm);
        defer proof.deinit(a);
        try verify(a, cfg, st, fx.zw.key(), &proof);
        const targets = [_]*QM31{ &proof.xhats[proof.xhats.len / 2], &proof.vrem_hats[0], &proof.vchecks[proof.vchecks.len - 1].hats[1], &proof.batch.hats[0] };
        for (targets) |ptr| {
            ptr.* = ptr.*.add(QM31.one());
            try std.testing.expect(std.meta.isError(verify(a, cfg, st, fx.zw.key(), &proof)));
            ptr.* = ptr.*.sub(QM31.one());
        }
        try verify(a, cfg, st, fx.zw.key(), &proof);
    }
}
