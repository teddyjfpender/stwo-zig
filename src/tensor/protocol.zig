//! Tensor proof protocol (v1, non-hiding).
//!
//! Statement: a list of integer tensor ops over committed weights (int8,
//! committed once) and a per-batch witness (activations, multiplicities).
//!
//!   matmul    Y = requant_s(X . W)        X witness [T,K], W weight [K,N] (or witness [N,K]^T)
//!   hadamard  Y = requant_s(A (.) B)      A, B, Y witness, same shape
//!   lookup    Out = table(In)             elementwise int8 -> int8 public table
//!   range8    In in [-128, 128)
//!
//! requant_s(acc) = floor((acc + 2^(s-1)) / 2^s), defined only when the result
//! is in [-128, 128) (the model is undefined otherwise, as in FlashProve).
//! The remainder r = acc + 2^(s-1) - 2^s Y is a *virtual* column: never
//! committed. Range checks r in [0, 2^s) and Y + 128 in [0, 256) are LogUp
//! relations proved by one batched LogUp-GKR (stwo's fast prover). GKR's
//! terminal claims on r are turned into claims on acc, which matmul/hadamard
//! sumchecks reduce to claims on committed X and W. All witness claims are
//! batched by one sumcheck into a single opening of the witness table; all
//! weight claims share their column point (GKR's common ood suffix) and are
//! opened with one combined row.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const f = @import("field.zig");
const sc = @import("sumcheck.zig");
const pcs = @import("pcs.zig");
const linalg = @import("linalg.zig");
const batch = @import("batch.zig");
const eqsum = @import("eqsum.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const lookups = engine.lookups;
const Fast = lookups.gkr_prover_fast.ForField(QM31);
const GkrVerifier = lookups.gkr_verifier;

// ---------------------------------------------------------------------------
// Statement.

pub const MAX_DIMS = 3;

pub const TensorInfo = struct {
    /// log2 of each dimension, MSB-first (outermost first)
    log_dims: [MAX_DIMS]u32 = .{ 0, 0, 0 },
    n_dims: u8,

    pub fn logSize(self: TensorInfo) u32 {
        var s: u32 = 0;
        for (self.log_dims[0..self.n_dims]) |d| s += d;
        return s;
    }
    pub fn size(self: TensorInfo) usize {
        return @as(usize, 1) << @intCast(self.logSize());
    }
    pub fn mat(lt: u32, ln: u32) TensorInfo {
        return .{ .log_dims = .{ lt, ln, 0 }, .n_dims = 2 };
    }
    pub fn vec(l: u32) TensorInfo {
        return .{ .log_dims = .{ l, 0, 0 }, .n_dims = 1 };
    }
};

pub const Table = struct {
    /// out[v + 128] for v in [-128, 128)
    values: [256]i8,
};

pub const Op = union(enum) {
    matmul: struct { x: u32, w: u32, y: u32, shift: u5 },
    hadamard: struct { a: u32, b: u32, y: u32, shift: u5 },
    lookup: struct { in: u32, out: u32, table: u32 },
    range8: struct { in: u32 },
    /// c = a (.) b over the field (arbitrary M31 values, canonical in [0, p))
    product: struct { a: u32, b: u32, c: u32 },
    /// fused gated activation: h = clamp8(requant_s(table[g] * u)); one lookup
    /// of the triple (g, u, h) into a public 2^16-entry table. Proves g, u in
    /// int8 (table domain) and h, without committing table[g] or a remainder.
    glu: struct { g: u32, u: u32, h: u32, table: u32, shift: u5 },
};

pub const Statement = struct {
    witness: []const TensorInfo,
    weights: []const TensorInfo, // matrices [K, N]
    tables: []const Table,
    ops: []const Op,
};

/// Committed weights (prover side): concatenated int8 table + commitment.
pub const WeightStore = struct {
    infos: []const TensorInfo,
    offsets: []usize,
    table: []i8,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
    com: pcs.Committed,

    pub fn deinit(self: *WeightStore, a: std.mem.Allocator) void {
        a.free(self.offsets);
        a.free(self.table);
        self.com.deinit(a);
    }

    pub fn matrix(self: *const WeightStore, id: usize) pcs.Matrix(i8) {
        const info = self.infos[id];
        return .{ .data = self.table[self.offsets[id]..][0..info.size()], .log_rows = info.log_dims[0], .log_cols = info.log_dims[1] };
    }

    pub fn tableMatrix(self: *const WeightStore) pcs.Matrix(i8) {
        return .{ .data = self.table, .log_rows = self.log_rows, .log_cols = self.log_cols, .rows_used = self.rows_used };
    }
};

/// Aligned layout: tensors sorted by size (desc), each at an offset that is a
/// multiple of its size. Returns offsets and total log size.
pub fn layout(a: std.mem.Allocator, infos: []const TensorInfo, extra_sizes: []const usize) !struct { offsets: []usize, log_total: u32, used: usize } {
    const n = infos.len + extra_sizes.len;
    const sizes = try a.alloc(usize, n);
    defer a.free(sizes);
    for (infos, 0..) |t, i| sizes[i] = t.size();
    for (extra_sizes, 0..) |s, i| sizes[infos.len + i] = s;
    const order = try a.alloc(usize, n);
    defer a.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.mem.sort(usize, order, sizes, struct {
        fn lt(s: []usize, x: usize, y: usize) bool {
            return s[x] > s[y] or (s[x] == s[y] and x < y);
        }
    }.lt);
    const offsets = try a.alloc(usize, n);
    var cur: usize = 0;
    for (order) |i| {
        offsets[i] = cur;
        cur += sizes[i];
    }
    var total: usize = 1;
    while (total < cur) total *= 2;
    return .{ .offsets = offsets, .log_total = f.log2Exact(total), .used = cur };
}

fn splitTable(log_total: u32, log_cols_max: u32) struct { lr: u32, lc: u32 } {
    // balance: columns ~ sqrt(total) * 4, capped
    var lc: u32 = (log_total + 3) / 2;
    if (lc > log_cols_max) lc = log_cols_max;
    if (lc > log_total) lc = log_total;
    return .{ .lr = log_total - lc, .lc = lc };
}

pub const Config = struct {
    pcs: pcs.Params = .{},
    /// max log columns of the weight table (must be <= min log N over matmuls)
    weight_log_cols: u32 = 10,
    witness_log_cols_max: u32 = 14,
    gkr_threads: usize = 8,
};

pub fn commitWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: Config, infos: []const TensorInfo, data: []const []const i8) !WeightStore {
    const lay = try layout(a, infos, &.{});
    const total = @as(usize, 1) << @intCast(lay.log_total);
    const table = try a.alloc(i8, total);
    @memset(table, 0);
    for (infos, 0..) |t, i| @memcpy(table[lay.offsets[i]..][0..t.size()], data[i]);
    var lc = cfg.weight_log_cols;
    if (lc > lay.log_total) lc = lay.log_total;
    const lr = lay.log_total - lc;
    var tw = try pcs.Twiddles.init(a, lc + cfg.pcs.log_blowup);
    defer tw.deinit(a);
    const ru = (lay.used + (@as(usize, 1) << @intCast(lc)) - 1) >> @intCast(lc);
    const m = pcs.Matrix(i8){ .data = table, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    const com = try pcs.commit(i8, a, pool, &tw, m, cfg.pcs.log_blowup);
    return .{ .infos = infos, .offsets = lay.offsets, .table = table, .log_rows = lr, .log_cols = lc, .rows_used = ru, .com = com };
}

// ---------------------------------------------------------------------------
// Relations derived from the statement (shared by prover and verifier).

const KeyKind = enum { remainder, y_range, lookup_pair, plain_range, glu_triple };

const KeyInst = struct {
    kind: KeyKind,
    op: usize,
    log_size: u32,
    table: usize, // index into `tables` list below
};

const TableKind = union(enum) { range: u5, act: u32, glu: struct { table: u32, shift: u5 } };

const RelTable = struct {
    kind: TableKind,
    log_size: u32,
    mult_tensor: usize, // index of multiplicity tensor in the extended witness list
};

const Relations = struct {
    keys: []KeyInst,
    tables: []RelTable,

    fn deinit(self: *Relations, a: std.mem.Allocator) void {
        a.free(self.keys);
        a.free(self.tables);
    }
};

fn tableIndex(list: *std.ArrayList(RelTable), a: std.mem.Allocator, kind: TableKind, n_witness: usize) !usize {
    for (list.items, 0..) |t, i| {
        if (std.meta.eql(t.kind, kind)) return i;
    }
    const log_size: u32 = switch (kind) {
        .range => |s| @max(@as(u32, s), 1),
        .act => 8,
        .glu => 16,
    };
    try list.append(a, .{ .kind = kind, .log_size = log_size, .mult_tensor = n_witness + list.items.len });
    return list.items.len - 1;
}

/// Tensors whose int8 range is implied by a lookup (inputs of lookup/glu).
fn rangeImplied(st: Statement, id: u32) bool {
    for (st.ops) |op| switch (op) {
        .lookup => |l| if (l.in == id) return true,
        .glu => |g| if (g.g == id or g.u == id) return true,
        else => {},
    };
    return false;
}

pub fn gluValue(st: Statement, table: u32, shift: u5, vg: i64, vu: i64) i64 {
    const act: i64 = st.tables[table].values[@intCast(vg + 128)];
    const q = @divFloor(act * vu + shiftHalf(shift), @as(i64, 1) << shift);
    return std.math.clamp(q, -128, 127);
}

fn deriveRelations(a: std.mem.Allocator, st: Statement) !Relations {
    var keys: std.ArrayList(KeyInst) = .empty;
    var tabs: std.ArrayList(RelTable) = .empty;
    const nw = st.witness.len;
    for (st.ops, 0..) |op, i| {
        switch (op) {
            .matmul => |m| {
                const ls = st.witness[m.y].logSize();
                try keys.append(a, .{ .kind = .remainder, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = m.shift }, nw) });
                if (!rangeImplied(st, m.y)) try keys.append(a, .{ .kind = .y_range, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .hadamard => |h| {
                const ls = st.witness[h.y].logSize();
                try keys.append(a, .{ .kind = .remainder, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = h.shift }, nw) });
                if (!rangeImplied(st, h.y)) try keys.append(a, .{ .kind = .y_range, .op = i, .log_size = ls, .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .lookup => |l| {
                try keys.append(a, .{ .kind = .lookup_pair, .op = i, .log_size = st.witness[l.in].logSize(), .table = try tableIndex(&tabs, a, .{ .act = l.table }, nw) });
            },
            .range8 => |r| {
                try keys.append(a, .{ .kind = .plain_range, .op = i, .log_size = st.witness[r.in].logSize(), .table = try tableIndex(&tabs, a, .{ .range = 8 }, nw) });
            },
            .product => {},
            .glu => |g| {
                try keys.append(a, .{ .kind = .glu_triple, .op = i, .log_size = st.witness[g.h].logSize(), .table = try tableIndex(&tabs, a, .{ .glu = .{ .table = g.table, .shift = g.shift } }, nw) });
            },
        }
    }
    return .{ .keys = try keys.toOwnedSlice(a), .tables = try tabs.toOwnedSlice(a) };
}

fn extendedInfos(a: std.mem.Allocator, st: Statement, rel: Relations) ![]TensorInfo {
    const out = try a.alloc(TensorInfo, st.witness.len + rel.tables.len);
    @memcpy(out[0..st.witness.len], st.witness);
    for (rel.tables, 0..) |t, i| out[st.witness.len + i] = TensorInfo.vec(t.log_size);
    return out;
}

fn shiftHalf(s: u5) i64 {
    return @as(i64, 1) << (s - 1);
}

fn tableValue(st: Statement, kind: TableKind, idx: usize) struct { key: i64, out: i64, out2: i64 = 0 } {
    return switch (kind) {
        .range => .{ .key = @intCast(idx), .out = 0 },
        .act => |t| .{ .key = @as(i64, @intCast(idx)) - 128, .out = st.tables[t].values[idx] },
        .glu => |g| blk: {
            const vg = @as(i64, @intCast(idx >> 8)) - 128;
            const vu = @as(i64, @intCast(idx & 255)) - 128;
            break :blk .{ .key = vg, .out = vu, .out2 = gluValue(st, g.table, g.shift, vg, vu) };
        },
    };
}

/// MLE of a public table's key at point (n = log_size vars).
fn tableKeyMle(st: Statement, a: std.mem.Allocator, t: RelTable, point: []const QM31, beta: QM31) !QM31 {
    switch (t.kind) {
        .range => return f.identityMle(point),
        .act => |ti| {
            var outv: [256]i32 = undefined;
            for (0..256) |i| outv[i] = st.tables[ti].values[i];
            const out_mle = try f.mleEvalI32(a, &outv, point);
            return f.identityMle(point).sub(f.qFromI64(128)).add(beta.mul(out_mle));
        },
        .glu => |g| {
            const fv = try a.alloc(i32, 1 << 16);
            defer a.free(fv);
            for (0..1 << 16) |idx| fv[idx] = @intCast(tableValue(st, .{ .glu = g }, idx).out2);
            const f_mle = try f.mleEvalI32(a, fv, point);
            const vg = f.identityMle(point[0..8]).sub(f.qFromI64(128));
            const vu = f.identityMle(point[8..16]).sub(f.qFromI64(128));
            return vg.add(beta.mul(vu)).add(beta.mul(beta).mul(f_mle));
        },
    }
}

// ---------------------------------------------------------------------------
// Proof.

pub const WitnessClaim = struct { tensor: usize, point: []QM31, value: QM31 };

pub const Proof = struct {
    witness_root: [32]u8,
    gkr: ?GkrVerifier.GkrBatchProof,
    /// per lookup key instance: claimed In(rho)
    lookup_in_values: []QM31,
    /// per matmul/hadamard op (in op order): sumcheck proof and final factor values
    op_sumchecks: []sc.Proof,
    op_finals: [][]QM31,
    batch_sumcheck: sc.Proof,
    witness_value: QM31,
    witness_opening: pcs.OpeningProof,
    weight_values: []QM31,
    weight_opening: ?pcs.OpeningProof,

    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        if (self.gkr) |*g| g.deinit(a);
        a.free(self.lookup_in_values);
        for (self.op_sumchecks) |*p| p.deinit(a);
        a.free(self.op_sumchecks);
        for (self.op_finals) |x| a.free(x);
        a.free(self.op_finals);
        self.batch_sumcheck.deinit(a);
        self.witness_opening.deinit(a);
        a.free(self.weight_values);
        if (self.weight_opening) |*w| w.deinit(a);
    }

    pub const Sizes = struct { gkr: usize, sumchecks: usize, witness_opening: usize, weight_opening: usize, total: usize };

    pub fn sizes(self: Proof) Sizes {
        var gk: usize = 0;
        if (self.gkr) |g| {
            for (g.sumcheck_proofs) |p| for (p.round_polys) |rp| {
                gk += rp.coeffsSlice().len * 16;
            };
            for (g.layer_masks_by_instance) |ms| for (ms) |m| {
                gk += m.columnsSlice().len * 32;
            };
            for (g.output_claims_by_instance) |c| gk += c.len * 16;
        }
        var s: usize = self.lookup_in_values.len * 16 + self.batch_sumcheck.byteSize() + 16 + self.weight_values.len * 16;
        for (self.op_sumchecks) |p| s += p.byteSize();
        for (self.op_finals) |x| s += x.len * 16;
        const wo = self.witness_opening.byteSize();
        const wto = if (self.weight_opening) |w| w.byteSize() else 0;
        return .{ .gkr = gk, .sumchecks = s, .witness_opening = wo, .weight_opening = wto, .total = 32 + gk + s + wo + wto };
    }
};

pub const Timings = struct {
    witness_commit_ns: u64 = 0,
    gkr_ns: u64 = 0,
    op_sumcheck_ns: u64 = 0,
    weight_fold_ns: u64 = 0,
    batch_ns: u64 = 0,
    witness_open_ns: u64 = 0,
    weight_open_ns: u64 = 0,
    witness_elems: usize = 0,
    witness_table_elems: usize = 0,
};

fn mixStatement(tr: *Transcript, st: Statement, weight_root: [32]u8) void {
    tr.mixDigest(weight_root);
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
            w[i] = 0;
            for (0..4) |j| w[i] |= @as(u32, @as(u8, @bitCast(t.values[i * 4 + j]))) << @intCast(8 * j);
        }
        tr.mixU32s(&w);
    }
    for (st.ops) |op| switch (op) {
        .matmul => |m| tr.mixU32s(&.{ 1, m.x, m.w, m.y, m.shift }),
        .hadamard => |h| tr.mixU32s(&.{ 2, h.a, h.b, h.y, h.shift }),
        .lookup => |l| tr.mixU32s(&.{ 3, l.in, l.out, l.table }),
        .range8 => |r| tr.mixU32s(&.{ 4, r.in }),
        .product => |q| tr.mixU32s(&.{ 5, q.a, q.b, q.c }),
        .glu => |g| tr.mixU32s(&.{ 6, g.g, g.u, g.h, g.table, g.shift }),
    };
}

fn fullPoint(a: std.mem.Allocator, log_total: u32, offset: usize, log_size: u32, local: []const QM31) ![]QM31 {
    const out = try a.alloc(QM31, log_total);
    const nb = log_total - log_size;
    const block = offset >> @intCast(log_size);
    for (0..nb) |k| {
        const bit = (block >> @intCast(nb - 1 - k)) & 1;
        out[k] = if (bit == 1) QM31.one() else QM31.zero();
    }
    @memcpy(out[nb..], local);
    return out;
}

/// Key value at index for a key instance (prover side), as field element.
fn keyValues(a: std.mem.Allocator, pool: *f.Pool, st: Statement, w: []const []const i32, acc: []const ?[]i64, k: KeyInst, alpha: QM31, beta: QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(k.log_size);
    const out = try a.alloc(QM31, n);
    const Ctx = struct { out: []QM31, st: Statement, w: []const []const i32, acc: []const ?[]i64, k: KeyInst, alpha: QM31, beta: QM31 };
    const ctx = Ctx{ .out = out, .st = st, .w = w, .acc = acc, .k = k, .alpha = alpha, .beta = beta };
    pool.parallelFor(n, 4096, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| {
                const key: QM31 = switch (c.k.kind) {
                    .remainder => blk: {
                        const op = c.st.ops[c.k.op];
                        const y_id: u32, const sh: u5 = switch (op) {
                            .matmul => |m| .{ m.y, m.shift },
                            .hadamard => |h| .{ h.y, h.shift },
                            else => unreachable,
                        };
                        const r = c.acc[c.k.op].?[i] + shiftHalf(sh) - (@as(i64, c.w[y_id][i]) << sh);
                        break :blk f.qFromI64(r);
                    },
                    .y_range => blk: {
                        const y_id: u32 = switch (c.st.ops[c.k.op]) {
                            .matmul => |m| m.y,
                            .hadamard => |h| h.y,
                            else => unreachable,
                        };
                        break :blk f.qFromI64(@as(i64, c.w[y_id][i]) + 128);
                    },
                    .plain_range => f.qFromI64(@as(i64, c.w[c.st.ops[c.k.op].range8.in][i]) + 128),
                    .lookup_pair => blk: {
                        const l = c.st.ops[c.k.op].lookup;
                        break :blk f.qFromI64(c.w[l.in][i]).add(c.beta.mul(f.qFromI64(c.w[l.out][i])));
                    },
                    .glu_triple => blk: {
                        const g = c.st.ops[c.k.op].glu;
                        break :blk f.qFromI64(c.w[g.g][i]).add(c.beta.mul(f.qFromI64(c.w[g.u][i]))).add(c.beta.mul(c.beta).mul(f.qFromI64(c.w[g.h][i])));
                    },
                };
                c.out[i] = c.alpha.sub(key);
            }
        }
    }.run);
    return out;
}

fn tableDen(a: std.mem.Allocator, st: Statement, t: RelTable, alpha: QM31, beta: QM31) ![]QM31 {
    const n = @as(usize, 1) << @intCast(t.log_size);
    const out = try a.alloc(QM31, n);
    for (0..n) |i| {
        const v = tableValue(st, t.kind, i);
        out[i] = alpha.sub(f.qFromI64(v.key).add(beta.mul(f.qFromI64(v.out))).add(beta.mul(beta).mul(f.qFromI64(v.out2))));
    }
    return out;
}

/// Compute multiplicities for all tables from witness values.
fn multiplicities(a: std.mem.Allocator, st: Statement, rel: Relations, w: []const []const i32, acc: []const ?[]i64) ![][]i32 {
    const out = try a.alloc([]i32, rel.tables.len);
    var n_alloc: usize = 0;
    errdefer {
        for (out[0..n_alloc]) |m| a.free(m);
        a.free(out);
    }
    for (rel.tables, 0..) |t, i| {
        out[i] = try a.alloc(i32, @as(usize, 1) << @intCast(t.log_size));
        @memset(out[i], 0);
        n_alloc += 1;
    }
    for (rel.keys) |k| {
        const n = @as(usize, 1) << @intCast(k.log_size);
        const mult = out[k.table];
        switch (k.kind) {
            .remainder => {
                const op = st.ops[k.op];
                const y_id: u32, const sh: u5 = switch (op) {
                    .matmul => |m| .{ m.y, m.shift },
                    .hadamard => |h| .{ h.y, h.shift },
                    else => unreachable,
                };
                for (0..n) |i| {
                    const r = acc[k.op].?[i] + shiftHalf(sh) - (@as(i64, w[y_id][i]) << sh);
                    if (r < 0 or r >= mult.len) return error.RemainderOutOfRange;
                    mult[@intCast(r)] += 1;
                }
            },
            .y_range, .plain_range => {
                const y_id: u32 = switch (st.ops[k.op]) {
                    .matmul => |m| m.y,
                    .hadamard => |h| h.y,
                    .range8 => |r| r.in,
                    else => unreachable,
                };
                for (0..n) |i| {
                    const v = @as(i64, w[y_id][i]) + 128;
                    if (v < 0 or v >= 256) return error.ValueOutOfRange;
                    mult[@intCast(v)] += 1;
                }
            },
            .glu_triple => {
                const g = st.ops[k.op].glu;
                for (0..n) |i| {
                    const vg = @as(i64, w[g.g][i]);
                    const vu = @as(i64, w[g.u][i]);
                    if (vg < -128 or vg > 127 or vu < -128 or vu > 127) return error.ValueOutOfRange;
                    if (gluValue(st, g.table, g.shift, vg, vu) != w[g.h][i]) return error.LookupMismatch;
                    mult[@intCast((vg + 128) * 256 + (vu + 128))] += 1;
                }
            },
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                for (0..n) |i| {
                    const v = @as(i64, w[l.in][i]) + 128;
                    if (v < 0 or v >= 256) return error.ValueOutOfRange;
                    if (st.tables[l.table].values[@intCast(v)] != w[l.out][i]) return error.LookupMismatch;
                    mult[@intCast(v)] += 1;
                }
            },
        }
    }
    return out;
}

/// Integer accumulators for matmul/hadamard ops (prover side).
pub fn computeAccumulators(a: std.mem.Allocator, pool: *f.Pool, st: Statement, ws: *const WeightStore, w: []const []const i32) ![]?[]i64 {
    const out = try a.alloc(?[]i64, st.ops.len);
    for (st.ops, 0..) |op, i| {
        out[i] = null;
        switch (op) {
            .matmul => |m| out[i] = try matmulAcc(a, pool, st.witness[m.x], w[m.x], ws.matrix(m.w)),
            .hadamard => |h| {
                const n = st.witness[h.y].size();
                const acc = try a.alloc(i64, n);
                for (0..n) |j| acc[j] = @as(i64, w[h.a][j]) * @as(i64, w[h.b][j]);
                out[i] = acc;
            },
            else => {},
        }
    }
    return out;
}

pub fn matmulAcc(a: std.mem.Allocator, pool: *f.Pool, xi: TensorInfo, x: []const i32, wm: pcs.Matrix(i8)) ![]i64 {
    const T = @as(usize, 1) << @intCast(xi.log_dims[0]);
    const K = wm.nRows();
    const N = wm.nCols();
    const acc = try a.alloc(i64, T * N);
    const Ctx = struct { x: []const i32, wm: pcs.Matrix(i8), acc: []i64, K: usize, N: usize };
    const ctx = Ctx{ .x = x, .wm = wm, .acc = acc, .K = K, .N = N };
    pool.parallelFor(T, 1, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            const tmp = std.heap.page_allocator.alloc(i32, c.N) catch @panic("oom");
            defer std.heap.page_allocator.free(tmp);
            for (s..e) |t| {
                @memset(tmp, 0);
                for (0..c.K) |k| {
                    const xv = c.x[t * c.K + k];
                    if (xv == 0) continue;
                    const row = c.wm.row(k);
                    for (tmp, row) |*o, wv| o.* += xv * @as(i32, wv);
                }
                for (0..c.N) |n| c.acc[t * c.N + n] = tmp[n];
            }
        }
    }.run);
    return acc;
}

/// requant (prover helper)
pub fn requant(acc: i64, s: u5) i32 {
    return @intCast(@divFloor(acc + shiftHalf(s), @as(i64, 1) << s));
}

fn toQM31Vec(a: std.mem.Allocator, pool: *f.Pool, v: []const i32) ![]QM31 {
    const out = try a.alloc(QM31, v.len);
    const Ctx = struct { v: []const i32, out: []QM31 };
    const ctx = Ctx{ .v = v, .out = out };
    pool.parallelFor(v.len, 8192, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| c.out[i] = QM31.fromBase(f.fromI32(c.v[i]));
        }
    }.run);
    return out;
}

const ClaimList = std.ArrayList(WitnessClaim);

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_PRODUCT = [_]sc.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

fn nowNs(t0: std.time.Instant) u64 {
    const t1 = std.time.Instant.now() catch return 0;
    return t1.since(t0);
}

// ---------------------------------------------------------------------------
// Prover.

pub fn prove(
    a: std.mem.Allocator,
    pool: *f.Pool,
    cfg: Config,
    st: Statement,
    ws: *const WeightStore,
    witness: []const []const i32,
    timings: *Timings,
) !Proof {
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    const acc = try computeAccumulators(a, pool, st, ws, witness);
    defer {
        for (acc) |x| if (x) |v| a.free(v);
        a.free(acc);
    }
    const mults = try multiplicities(a, st, rel, witness, acc);
    defer {
        for (mults) |m| a.free(m);
        a.free(mults);
    }
    const ext = try extendedInfos(a, st, rel);
    defer a.free(ext);
    const all = try a.alloc([]const i32, ext.len);
    defer a.free(all);
    for (witness, 0..) |w, i| all[i] = w;
    for (mults, 0..) |m, i| all[witness.len + i] = m;

    // --- witness table + commitment
    var t0 = try std.time.Instant.now();
    const lay = try layout(a, ext, &.{});
    defer a.free(lay.offsets);
    const total = @as(usize, 1) << @intCast(lay.log_total);
    const wtab = try a.alloc(i32, total);
    defer a.free(wtab);
    @memset(wtab, 0);
    for (all, 0..) |v, i| @memcpy(wtab[lay.offsets[i]..][0..v.len], v);
    const split = splitTable(lay.log_total, cfg.witness_log_cols_max);
    var wtw = try pcs.Twiddles.init(a, split.lc + cfg.pcs.log_blowup);
    defer wtw.deinit(a);
    const w_ru = (lay.used + (@as(usize, 1) << @intCast(split.lc)) - 1) >> @intCast(split.lc);
    const wm = pcs.Matrix(i32){ .data = wtab, .log_rows = split.lr, .log_cols = split.lc, .rows_used = w_ru };
    var wcom = try pcs.commit(i32, a, pool, &wtw, wm, cfg.pcs.log_blowup);
    defer wcom.deinit(a);
    timings.witness_commit_ns = nowNs(t0);
    timings.witness_table_elems = w_ru << @intCast(split.lc);
    for (all) |v| timings.witness_elems += v.len;

    var tr = Transcript.initDomain("stwo-tensor-v1");
    mixStatement(&tr, st, ws.com.root());
    tr.mixDigest(wcom.root());
    const alpha = tr.draw();
    const beta = tr.draw();

    // --- LogUp-GKR over all key and table instances
    t0 = try std.time.Instant.now();
    const n_inst = rel.keys.len + rel.tables.len;
    const inputs = try a.alloc(Fast.Input, n_inst);
    defer a.free(inputs);
    for (rel.keys, 0..) |k, i| inputs[i] = .{ .num = .ones, .den = try keyValues(a, pool, st, all, acc, k, alpha, beta), .owned = true };
    const mult_m31 = try a.alloc([]M31, rel.tables.len);
    defer {
        for (mult_m31) |m| a.free(m);
        a.free(mult_m31);
    }
    for (rel.tables, 0..) |t, i| {
        mult_m31[i] = try a.alloc(M31, mults[i].len);
        for (mults[i], mult_m31[i]) |m, *o| o.* = f.fromI32(m);
        inputs[rel.keys.len + i] = .{ .num = .{ .base = mult_m31[i] }, .den = try tableDen(a, st, t, alpha, beta), .owned = false };
    }
    var gkr_proof: ?GkrVerifier.GkrBatchProof = null;
    var art: lookups.verifier_kernel.Artifact(QM31) = .{ .ood_point = &.{}, .claims_to_verify_by_instance = &.{}, .n_variables_by_instance = &.{} };
    if (n_inst > 0) {
        const gkr_res = try Fast.proveBatch(a, &tr.ch, inputs, .{ .threads = cfg.gkr_threads }, null);
        gkr_proof = gkr_res.proof;
        art = gkr_res.artifact;
    }
    // table dens were borrowed (owned=false): free them now
    for (rel.tables, 0..) |_, i| a.free(inputs[rel.keys.len + i].den);
    defer if (n_inst > 0) art.deinit(a);
    timings.gkr_ns = nowNs(t0);
    const L = art.ood_point.len;

    var claims: ClaimList = .empty;
    defer {
        for (claims.items) |c| a.free(c.point);
        claims.deinit(a);
    }
    var weight_claims: std.ArrayList(struct { w: usize, point: []QM31, value: QM31 }) = .empty;
    defer {
        for (weight_claims.items) |c| a.free(c.point);
        weight_claims.deinit(a);
    }

    // terminal claims -> witness claims
    var lookup_vals: std.ArrayList(QM31) = .empty;
    const y_vals = try a.alloc(QM31, rel.keys.len);
    defer a.free(y_vals);
    for (rel.keys, 0..) |k, i| {
        const pt = art.ood_point[L - k.log_size ..];
        switch (k.kind) {
            .glu_triple => {
                const g = st.ops[k.op].glu;
                const vg = try f.mleEvalI32(a, all[g.g], pt);
                const vu = try f.mleEvalI32(a, all[g.u], pt);
                try lookup_vals.append(a, vg);
                try lookup_vals.append(a, vu);
                tr.mixFelts(&.{ vg, vu });
                const den = art.claims_to_verify_by_instance[i][1];
                const b2 = beta.mul(beta);
                const vh = alpha.sub(den).sub(vg).sub(beta.mul(vu)).mul(b2.inv() catch unreachable);
                try claims.append(a, .{ .tensor = g.g, .point = try a.dupe(QM31, pt), .value = vg });
                try claims.append(a, .{ .tensor = g.u, .point = try a.dupe(QM31, pt), .value = vu });
                try claims.append(a, .{ .tensor = g.h, .point = try a.dupe(QM31, pt), .value = vh });
            },
            .remainder, .y_range => {
                if (k.kind == .remainder) {
                    const has_range = i + 1 < rel.keys.len and rel.keys[i + 1].kind == .y_range and rel.keys[i + 1].op == k.op;
                    if (has_range) {
                        y_vals[i] = alpha.sub(art.claims_to_verify_by_instance[i + 1][1]).sub(f.qFromI64(128));
                    } else {
                        const y_id: u32 = switch (st.ops[k.op]) {
                            .matmul => |m| m.y,
                            .hadamard => |h| h.y,
                            else => unreachable,
                        };
                        const yv = try f.mleEvalI32(a, all[y_id], pt);
                        try lookup_vals.append(a, yv);
                        tr.mixFelt(yv);
                        y_vals[i] = yv;
                        try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = yv });
                    }
                }
                if (k.kind == .y_range) {
                    const y_id: u32 = switch (st.ops[k.op]) {
                        .matmul => |m| m.y,
                        .hadamard => |h| h.y,
                        else => unreachable,
                    };
                    const den = art.claims_to_verify_by_instance[i][1];
                    try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = alpha.sub(den).sub(f.qFromI64(128)) });
                }
            },
            .plain_range => {
                const den = art.claims_to_verify_by_instance[i][1];
                try claims.append(a, .{ .tensor = st.ops[k.op].range8.in, .point = try a.dupe(QM31, pt), .value = alpha.sub(den).sub(f.qFromI64(128)) });
            },
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                const vin = try f.mleEvalI32(a, all[l.in], pt);
                try lookup_vals.append(a, vin);
                tr.mixFelt(vin);
                const den = art.claims_to_verify_by_instance[i][1];
                const vout = alpha.sub(den).sub(vin).mul(beta.inv() catch unreachable);
                try claims.append(a, .{ .tensor = l.in, .point = try a.dupe(QM31, pt), .value = vin });
                try claims.append(a, .{ .tensor = l.out, .point = try a.dupe(QM31, pt), .value = vout });
            },
        }
    }
    for (rel.tables, 0..) |t, ti| {
        const pt = art.ood_point[L - t.log_size ..];
        const num = art.claims_to_verify_by_instance[rel.keys.len + ti][0];
        try claims.append(a, .{ .tensor = t.mult_tensor, .point = try a.dupe(QM31, pt), .value = num });
    }

    // --- op sumchecks (matmul / hadamard), in key order (one per remainder key)
    t0 = try std.time.Instant.now();
    var op_proofs: std.ArrayList(sc.Proof) = .empty;
    var op_finals: std.ArrayList([]QM31) = .empty;
    for (rel.keys, 0..) |k, i| {
        if (k.kind != .remainder) continue;
        const pt = art.ood_point[L - k.log_size ..];
        // acc(rho) = r(rho) - 2^(s-1) + 2^s y(rho), with r = alpha - den_r, y = alpha - den_y - 128
        const r_val = alpha.sub(art.claims_to_verify_by_instance[i][1]);
        const y_val = y_vals[i];
        switch (st.ops[k.op]) {
            .matmul => |m| {
                const sh = m.shift;
                const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const lk = xi.log_dims[1];
                const rho_t = pt[0..lt];
                const rho_n = pt[lt..];
                // f(k) = X(rho_t, k)
                const eq_t = try f.eqTablePar(a, pool, rho_t, QM31.one());
                defer a.free(eq_t);
                const xm = pcs.Matrix(i32){ .data = all[m.x], .log_rows = lt, .log_cols = lk };
                const fx = try linalg.colCombine(i32, a, pool, xm, eq_t, 8);
                defer a.free(fx);
                // g(k) = W(k, rho_n): the weight pass
                const tw0 = try std.time.Instant.now();
                const eq_n = try f.eqTablePar(a, pool, rho_n, QM31.one());
                defer a.free(eq_n);
                const gw = try linalg.rowDots(i8, a, pool, ws.matrix(m.w), eq_n, 7);
                defer a.free(gw);
                timings.weight_fold_ns += nowNs(tw0);
                const res = try sc.proveActive(2, &T_PROD2, a, pool, &tr, acc_val, .{ fx, gw }, fx.len);
                defer a.free(res.point);
                try op_proofs.append(a, res.proof);
                tr.mixFelts(res.finals);
                try op_finals.append(a, res.finals);
                const px = try a.alloc(QM31, lt + lk);
                @memcpy(px[0..lt], rho_t);
                @memcpy(px[lt..], res.point);
                try claims.append(a, .{ .tensor = m.x, .point = px, .value = res.finals[0] });
                const pw = try a.alloc(QM31, lk + rho_n.len);
                @memcpy(pw[0..lk], res.point);
                @memcpy(pw[lk..], rho_n);
                try weight_claims.append(a, .{ .w = m.w, .point = pw, .value = res.finals[1] });
            },
            .hadamard => |h| {
                const sh = h.shift;
                const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
                // same transcript as proveActive(3, T_EQ3, {eq(pt), A, B}) (split-eq prover)
                var res = try eqsum.prove(.hadamard, a, pool, &tr, acc_val, pt, .{ all[h.a], all[h.b] });
                defer a.free(res.point);
                try op_proofs.append(a, res.proof);
                tr.mixFelts(res.finals[1..]);
                const fin = try a.dupe(QM31, res.finals[1..]);
                a.free(res.finals);
                try op_finals.append(a, fin);
                try claims.append(a, .{ .tensor = h.a, .point = try a.dupe(QM31, res.point), .value = fin[0] });
                try claims.append(a, .{ .tensor = h.b, .point = try a.dupe(QM31, res.point), .value = fin[1] });
            },
            else => unreachable,
        }
    }
    for (st.ops) |op| switch (op) {
        .product => |q| {
            const ls = st.witness[q.c].logSize();
            const rho = try a.alloc(QM31, ls);
            defer a.free(rho);
            tr.drawN(rho);
            // same transcript as proveActive(4, T_PRODUCT, {eq(rho), A, B, C}) (split-eq prover)
            var res = try eqsum.prove(.product, a, pool, &tr, QM31.zero(), rho, .{ all[q.a], all[q.b], all[q.c] });
            defer a.free(res.point);
            try op_proofs.append(a, res.proof);
            const fin = try a.dupe(QM31, res.finals[1..]);
            a.free(res.finals);
            res.finals = &.{};
            tr.mixFelts(fin);
            try op_finals.append(a, fin);
            try claims.append(a, .{ .tensor = q.a, .point = try a.dupe(QM31, res.point), .value = fin[0] });
            try claims.append(a, .{ .tensor = q.b, .point = try a.dupe(QM31, res.point), .value = fin[1] });
            try claims.append(a, .{ .tensor = q.c, .point = try a.dupe(QM31, res.point), .value = fin[2] });
        },
        else => {},
    };
    timings.op_sumcheck_ns = nowNs(t0);

    // --- batch witness claims into one point
    t0 = try std.time.Instant.now();
    for (claims.items) |c| tr.mixFelt(c.value);
    const gammas = try a.alloc(QM31, claims.items.len);
    defer a.free(gammas);
    tr.drawN(gammas);
    // E = sum_c gamma_c eq(z_c, .) on tensor c's block; entries >= lay.used are never read.
    const E = try a.alloc(QM31, total);
    @memset(E[0..lay.used], QM31.zero());
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |c, g| {
        const off = lay.offsets[c.tensor];
        try batch.addEqScaled(a, pool, E[off..][0 .. @as(usize, 1) << @intCast(c.point.len)], c.point, g);
        batch_claim = batch_claim.add(g.mul(c.value));
    }
    const bres = try batch.proveBaseTimesExt(a, pool, &tr, batch_claim, wtab, E, lay.used);
    a.free(E);
    defer a.free(bres.point);
    const wval = bres.finals[0];
    a.free(bres.finals);
    timings.batch_ns = nowNs(t0);

    // --- witness opening (with proximity)
    t0 = try std.time.Instant.now();
    const wclaim = [_]pcs.Claim{.{ .point = bres.point, .value = wval }};
    const wgroups = [_]pcs.Group{.{ .claims = &wclaim }};
    const wopen = try pcs.open(i32, a, pool, &tr, cfg.pcs, &wcom, wm, &wgroups, true);
    timings.witness_open_ns = nowNs(t0);

    // --- weight opening (single combined row; proximity proven at commit time)
    t0 = try std.time.Instant.now();
    const wcl = try a.alloc(pcs.Claim, weight_claims.items.len);
    defer a.free(wcl);
    const wvals = try a.alloc(QM31, weight_claims.items.len);
    const full_pts = try a.alloc([]QM31, weight_claims.items.len);
    defer {
        for (full_pts) |p| a.free(p);
        a.free(full_pts);
    }
    const wlog_total = ws.log_rows + ws.log_cols;
    for (weight_claims.items, 0..) |c, i| {
        full_pts[i] = try fullPoint(a, wlog_total, ws.offsets[c.w], ws.infos[c.w].logSize(), c.point);
        wcl[i] = .{ .point = full_pts[i], .value = c.value };
        wvals[i] = c.value;
    }
    const wtgroups = [_]pcs.Group{.{ .claims = wcl }};
    const wtopen: ?pcs.OpeningProof = if (wcl.len == 0) null else try pcs.open(i8, a, pool, &tr, cfg.pcs, &ws.com, ws.tableMatrix(), &wtgroups, false);
    timings.weight_open_ns = nowNs(t0);

    return .{
        .witness_root = wcom.root(),
        .gkr = gkr_proof,
        .lookup_in_values = try lookup_vals.toOwnedSlice(a),
        .op_sumchecks = try op_proofs.toOwnedSlice(a),
        .op_finals = try op_finals.toOwnedSlice(a),
        .batch_sumcheck = bres.proof,
        .witness_value = wval,
        .witness_opening = wopen,
        .weight_values = wvals,
        .weight_opening = wtopen,
    };
}

// ---------------------------------------------------------------------------
// Verifier.

pub const WeightKey = struct {
    root: [32]u8,
    infos: []const TensorInfo,
    offsets: []const usize,
    log_rows: u32,
    log_cols: u32,
    rows_used: usize,
};

pub fn weightKey(ws: *const WeightStore) WeightKey {
    return .{ .root = ws.com.root(), .infos = ws.infos, .offsets = ws.offsets, .log_rows = ws.log_rows, .log_cols = ws.log_cols, .rows_used = ws.rows_used };
}

/// Public well-formedness checks the soundness argument relies on:
/// - every matmul/hadamard operand is int8-bounded by a proved relation
///   (output of matmul/hadamard requant, lookup output, or range8 input);
/// - K <= 2^15 so |acc| <= 2^14 K < 2^30 never wraps mod p;
/// - 1 <= shift <= 22 so 2^s * 129 < 2^30 and the requant identity mod p is an
///   integer identity;
/// - shapes are consistent.
pub fn validateStatement(st: Statement) !void {
    const n = st.witness.len;
    var is_bounded: [4096]bool = undefined;
    if (n > is_bounded.len) return error.StatementTooLarge;
    @memset(is_bounded[0..n], false);
    for (st.ops) |op| switch (op) {
        .matmul => |m| is_bounded[m.y] = true,
        .hadamard => |h| is_bounded[h.y] = true,
        .lookup => |l| {
            is_bounded[l.out] = true;
            is_bounded[l.in] = true; // table domain is int8
        },
        .range8 => |r| is_bounded[r.in] = true,
        .product => {},
        .glu => |g| {
            is_bounded[g.h] = true;
            is_bounded[g.g] = true;
            is_bounded[g.u] = true;
        },
    };
    for (st.ops) |op| switch (op) {
        .matmul => |m| {
            if (m.x >= n or m.y >= n or m.w >= st.weights.len) return error.StatementShape;
            if (!is_bounded[m.x]) return error.StatementUnboundedOperand;
            if (m.shift < 1 or m.shift > 22) return error.StatementShift;
            const xi = st.witness[m.x];
            const wi = st.weights[m.w];
            if (xi.n_dims != 2 or wi.n_dims != 2) return error.StatementShape;
            if (xi.log_dims[1] != wi.log_dims[0] or xi.log_dims[1] > 15) return error.StatementShape;
            if (st.witness[m.y].logSize() != xi.log_dims[0] + wi.log_dims[1]) return error.StatementShape;
        },
        .hadamard => |h| {
            if (h.a >= n or h.b >= n or h.y >= n) return error.StatementShape;
            if (!is_bounded[h.a] or !is_bounded[h.b]) return error.StatementUnboundedOperand;
            if (h.shift < 1 or h.shift > 22) return error.StatementShift;
            const ls = st.witness[h.y].logSize();
            if (st.witness[h.a].logSize() != ls or st.witness[h.b].logSize() != ls) return error.StatementShape;
        },
        .lookup => |l| {
            if (l.in >= n or l.out >= n or l.table >= st.tables.len) return error.StatementShape;
            if (st.witness[l.in].logSize() != st.witness[l.out].logSize()) return error.StatementShape;
        },
        .range8 => |r| if (r.in >= n) return error.StatementShape,
        .product => |q| if (q.a >= n or q.b >= n or q.c >= n) return error.StatementShape,
        .glu => |g| {
            if (g.g >= n or g.u >= n or g.h >= n or g.table >= st.tables.len) return error.StatementShape;
            if (g.shift < 1 or g.shift > 22) return error.StatementShift;
            const ls = st.witness[g.h].logSize();
            if (st.witness[g.g].logSize() != ls or st.witness[g.u].logSize() != ls) return error.StatementShape;
        },
    };
}

pub fn verify(a: std.mem.Allocator, cfg: Config, st: Statement, key: WeightKey, proof: *const Proof) !void {
    try validateStatement(st);
    var rel = try deriveRelations(a, st);
    defer rel.deinit(a);
    const ext = try extendedInfos(a, st, rel);
    defer a.free(ext);
    const lay = try layout(a, ext, &.{});
    defer a.free(lay.offsets);
    const split = splitTable(lay.log_total, cfg.witness_log_cols_max);

    var tr = Transcript.initDomain("stwo-tensor-v1");
    mixStatement(&tr, st, key.root);
    tr.mixDigest(proof.witness_root);
    const alpha = tr.draw();
    const beta = tr.draw();

    const n_inst = rel.keys.len + rel.tables.len;
    if ((n_inst > 0) != (proof.gkr != null)) return error.GkrShape;
    var art: lookups.verifier_kernel.Artifact(QM31) = .{ .ood_point = &.{}, .claims_to_verify_by_instance = &.{}, .n_variables_by_instance = &.{} };
    if (proof.gkr) |*gp| {
        if (gp.output_claims_by_instance.len != n_inst) return error.GkrShape;
        const gates = try a.alloc(GkrVerifier.Gate, n_inst);
        defer a.free(gates);
        @memset(gates, .LogUp);
        art = try GkrVerifier.partiallyVerifyBatch(a, gates, gp, &tr.ch);
    }
    defer if (n_inst > 0) art.deinit(a);
    const L = art.ood_point.len;
    for (rel.keys, 0..) |k, i| if (art.n_variables_by_instance[i] != k.log_size) return error.GkrShape;
    for (rel.tables, 0..) |t, i| if (art.n_variables_by_instance[rel.keys.len + i] != t.log_size) return error.GkrShape;

    // LogUp sums per table relation must vanish.
    for (rel.tables, 0..) |_, ti| {
        var num = QM31.zero();
        var den = QM31.one();
        const add = struct {
            fn f(n: *QM31, d: *QM31, n2: QM31, d2: QM31) void {
                n.* = n.*.mul(d2).add(n2.mul(d.*));
                d.* = d.*.mul(d2);
            }
        }.f;
        for (rel.keys, 0..) |k, i| if (k.table == ti) {
            const oc = proof.gkr.?.output_claims_by_instance[i];
            if (oc.len != 2 or oc[1].isZero()) return error.GkrShape;
            add(&num, &den, oc[0], oc[1]);
        };
        const oc = proof.gkr.?.output_claims_by_instance[rel.keys.len + ti];
        if (oc.len != 2 or oc[1].isZero()) return error.GkrShape;
        // table side is subtracted
        add(&num, &den, oc[0].neg(), oc[1]);
        if (!num.isZero()) return error.LogUpSumNonZero;
    }

    var claims: ClaimList = .empty;
    defer {
        for (claims.items) |c| a.free(c.point);
        claims.deinit(a);
    }
    var lk_i: usize = 0;
    const y_vals = try a.alloc(QM31, rel.keys.len);
    defer a.free(y_vals);
    for (rel.keys, 0..) |k, i| {
        const pt = art.ood_point[L - k.log_size ..];
        const cv = art.claims_to_verify_by_instance[i];
        if (cv.len != 2) return error.GkrShape;
        if (!cv[0].eql(QM31.one())) return error.GkrTerminal; // singles: numerator MLE is 1
        switch (k.kind) {
            .remainder => {
                const has_range = i + 1 < rel.keys.len and rel.keys[i + 1].kind == .y_range and rel.keys[i + 1].op == k.op;
                if (has_range) {
                    y_vals[i] = alpha.sub(art.claims_to_verify_by_instance[i + 1][1]).sub(f.qFromI64(128));
                } else {
                    const y_id: u32 = switch (st.ops[k.op]) {
                        .matmul => |m| m.y,
                        .hadamard => |h| h.y,
                        else => unreachable,
                    };
                    if (lk_i >= proof.lookup_in_values.len) return error.ProofShape;
                    const yv = proof.lookup_in_values[lk_i];
                    lk_i += 1;
                    tr.mixFelt(yv);
                    y_vals[i] = yv;
                    try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = yv });
                }
            },
            .glu_triple => {
                const g = st.ops[k.op].glu;
                if (lk_i + 2 > proof.lookup_in_values.len) return error.ProofShape;
                const vg = proof.lookup_in_values[lk_i];
                const vu = proof.lookup_in_values[lk_i + 1];
                lk_i += 2;
                tr.mixFelts(&.{ vg, vu });
                const b2 = beta.mul(beta);
                const vh = alpha.sub(cv[1]).sub(vg).sub(beta.mul(vu)).mul(b2.inv() catch return error.ProofShape);
                try claims.append(a, .{ .tensor = g.g, .point = try a.dupe(QM31, pt), .value = vg });
                try claims.append(a, .{ .tensor = g.u, .point = try a.dupe(QM31, pt), .value = vu });
                try claims.append(a, .{ .tensor = g.h, .point = try a.dupe(QM31, pt), .value = vh });
            },
            .y_range => {
                const y_id: u32 = switch (st.ops[k.op]) {
                    .matmul => |m| m.y,
                    .hadamard => |h| h.y,
                    else => unreachable,
                };
                try claims.append(a, .{ .tensor = y_id, .point = try a.dupe(QM31, pt), .value = alpha.sub(cv[1]).sub(f.qFromI64(128)) });
            },
            .plain_range => try claims.append(a, .{ .tensor = st.ops[k.op].range8.in, .point = try a.dupe(QM31, pt), .value = alpha.sub(cv[1]).sub(f.qFromI64(128)) }),
            .lookup_pair => {
                const l = st.ops[k.op].lookup;
                if (lk_i >= proof.lookup_in_values.len) return error.ProofShape;
                const vin = proof.lookup_in_values[lk_i];
                lk_i += 1;
                tr.mixFelt(vin);
                const vout = alpha.sub(cv[1]).sub(vin).mul(beta.inv() catch return error.ProofShape);
                try claims.append(a, .{ .tensor = l.in, .point = try a.dupe(QM31, pt), .value = vin });
                try claims.append(a, .{ .tensor = l.out, .point = try a.dupe(QM31, pt), .value = vout });
            },
        }
    }
    if (lk_i != proof.lookup_in_values.len) return error.ProofShape;
    for (rel.tables, 0..) |t, ti| {
        const pt = art.ood_point[L - t.log_size ..];
        const cv = art.claims_to_verify_by_instance[rel.keys.len + ti];
        if (cv.len != 2) return error.GkrShape;
        const expect_den = alpha.sub(try tableKeyMle(st, a, t, pt, beta));
        if (!cv[1].eql(expect_den)) return error.GkrTerminal;
        try claims.append(a, .{ .tensor = t.mult_tensor, .point = try a.dupe(QM31, pt), .value = cv[0] });
    }

    var weight_pts: std.ArrayList([]QM31) = .empty;
    defer {
        for (weight_pts.items) |p| a.free(p);
        weight_pts.deinit(a);
    }
    var op_i: usize = 0;
    for (rel.keys, 0..) |k, i| {
        if (k.kind != .remainder) continue;
        if (op_i >= proof.op_sumchecks.len) return error.ProofShape;
        const pt = art.ood_point[L - k.log_size ..];
        const r_val = alpha.sub(art.claims_to_verify_by_instance[i][1]);
        const y_val = y_vals[i];
        const sh: u5 = switch (st.ops[k.op]) {
            .matmul => |m| m.shift,
            .hadamard => |h| h.shift,
            else => unreachable,
        };
        const acc_val = r_val.sub(f.qFromI64(shiftHalf(sh))).add(y_val.mulM31(M31.fromCanonical(@as(u32, 1) << sh)));
        const fin = proof.op_finals[op_i];
        switch (st.ops[k.op]) {
            .matmul => |m| {
                const xi = st.witness[m.x];
                const lt = xi.log_dims[0];
                const lkk = xi.log_dims[1];
                if (st.weights[m.w].log_dims[0] != lkk or st.weights[m.w].log_dims[1] != k.log_size - lt) return error.StatementShape;
                const vr = try sc.verify(a, &tr, acc_val, lkk, 2, proof.op_sumchecks[op_i]);
                defer a.free(vr.point);
                if (fin.len != 2) return error.ProofShape;
                if (!vr.final_claim.eql(fin[0].mul(fin[1]))) return error.OpSumcheck;
                tr.mixFelts(fin);
                const px = try a.alloc(QM31, lt + lkk);
                @memcpy(px[0..lt], pt[0..lt]);
                @memcpy(px[lt..], vr.point);
                try claims.append(a, .{ .tensor = m.x, .point = px, .value = fin[0] });
                const pw = try a.alloc(QM31, lkk + (k.log_size - lt));
                @memcpy(pw[0..lkk], vr.point);
                @memcpy(pw[lkk..], pt[lt..]);
                try weight_pts.append(a, try fullPoint(a, key.log_rows + key.log_cols, key.offsets[m.w], key.infos[m.w].logSize(), pw));
                a.free(pw);
            },
            .hadamard => |h| {
                const vr = try sc.verify(a, &tr, acc_val, k.log_size, 3, proof.op_sumchecks[op_i]);
                defer a.free(vr.point);
                if (fin.len != 2) return error.ProofShape;
                if (!vr.final_claim.eql(f.eqEval(pt, vr.point).mul(fin[0]).mul(fin[1]))) return error.OpSumcheck;
                tr.mixFelts(fin);
                try claims.append(a, .{ .tensor = h.a, .point = try a.dupe(QM31, vr.point), .value = fin[0] });
                try claims.append(a, .{ .tensor = h.b, .point = try a.dupe(QM31, vr.point), .value = fin[1] });
            },
            else => unreachable,
        }
        op_i += 1;
    }
    for (st.ops) |op| switch (op) {
        .product => |q| {
            if (op_i >= proof.op_sumchecks.len) return error.ProofShape;
            const ls = st.witness[q.c].logSize();
            if (st.witness[q.a].logSize() != ls or st.witness[q.b].logSize() != ls) return error.StatementShape;
            const rho = try a.alloc(QM31, ls);
            defer a.free(rho);
            tr.drawN(rho);
            const vr = try sc.verify(a, &tr, QM31.zero(), ls, 3, proof.op_sumchecks[op_i]);
            defer a.free(vr.point);
            const fin = proof.op_finals[op_i];
            if (fin.len != 3) return error.ProofShape;
            const e = f.eqEval(rho, vr.point);
            if (!vr.final_claim.eql(e.mul(fin[0].mul(fin[1]).sub(fin[2])))) return error.OpSumcheck;
            tr.mixFelts(fin);
            try claims.append(a, .{ .tensor = q.a, .point = try a.dupe(QM31, vr.point), .value = fin[0] });
            try claims.append(a, .{ .tensor = q.b, .point = try a.dupe(QM31, vr.point), .value = fin[1] });
            try claims.append(a, .{ .tensor = q.c, .point = try a.dupe(QM31, vr.point), .value = fin[2] });
            op_i += 1;
        },
        else => {},
    };
    if (op_i != proof.op_sumchecks.len) return error.ProofShape;

    // batch reduction
    for (claims.items) |c| tr.mixFelt(c.value);
    const gammas = try a.alloc(QM31, claims.items.len);
    defer a.free(gammas);
    tr.drawN(gammas);
    var batch_claim = QM31.zero();
    for (claims.items, gammas) |c, g| batch_claim = batch_claim.add(g.mul(c.value));
    const bv = try sc.verify(a, &tr, batch_claim, lay.log_total, 2, proof.batch_sumcheck);
    defer a.free(bv.point);
    var e_at = QM31.zero();
    for (claims.items, gammas) |c, g| {
        const fp = try fullPoint(a, lay.log_total, lay.offsets[c.tensor], ext[c.tensor].logSize(), c.point);
        defer a.free(fp);
        e_at = e_at.add(g.mul(f.eqEval(fp, bv.point)));
    }
    if (!bv.final_claim.eql(proof.witness_value.mul(e_at))) return error.BatchSumcheck;

    var wtw = try pcs.Twiddles.init(a, split.lc + cfg.pcs.log_blowup);
    defer wtw.deinit(a);
    const wclaim = [_]pcs.Claim{.{ .point = bv.point, .value = proof.witness_value }};
    const wgroups = [_]pcs.Group{.{ .claims = &wclaim }};
    const w_ru = (lay.used + (@as(usize, 1) << @intCast(split.lc)) - 1) >> @intCast(split.lc);
    try pcs.verifyOpening(a, &tr, cfg.pcs, &wtw, .{ .log_rows = split.lr, .log_cols = split.lc, .log_blowup = cfg.pcs.log_blowup, .rows_used = w_ru }, proof.witness_root, &wgroups, true, proof.witness_opening);

    if (proof.weight_values.len != weight_pts.items.len) return error.ProofShape;
    const wcl = try a.alloc(pcs.Claim, weight_pts.items.len);
    defer a.free(wcl);
    for (weight_pts.items, proof.weight_values, 0..) |p, v, i| wcl[i] = .{ .point = p, .value = v };
    var ktw = try pcs.Twiddles.init(a, key.log_cols + cfg.pcs.log_blowup);
    defer ktw.deinit(a);
    const kgroups = [_]pcs.Group{.{ .claims = wcl }};
    // matmul finals for W must equal the opened weight values
    {
        var oi: usize = 0;
        var j: usize = 0;
        for (rel.keys) |k| {
            if (k.kind != .remainder) continue;
            switch (st.ops[k.op]) {
                .matmul => {
                    if (!proof.op_finals[oi][1].eql(proof.weight_values[j])) return error.WeightValueMismatch;
                    j += 1;
                },
                else => {},
            }
            oi += 1;
        }
    }
    if ((wcl.len == 0) != (proof.weight_opening == null)) return error.ProofShape;
    if (proof.weight_opening) |wop| try pcs.verifyOpening(a, &tr, cfg.pcs, &ktw, .{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = cfg.pcs.log_blowup, .rows_used = key.rows_used }, key.root, &kgroups, false, wop);
}

/// Offline: proximity test of the committed weight table (run once per commitment).
pub fn proveWeightProximity(a: std.mem.Allocator, pool: *f.Pool, cfg: Config, ws: *const WeightStore) !pcs.OpeningProof {
    var tr = Transcript.initDomain("stwo-tensor-weights-v1");
    tr.mixDigest(ws.com.root());
    return pcs.open(i8, a, pool, &tr, cfg.pcs, &ws.com, ws.tableMatrix(), &.{}, true);
}

pub fn verifyWeightProximity(a: std.mem.Allocator, cfg: Config, key: WeightKey, proof: pcs.OpeningProof) !void {
    var tr = Transcript.initDomain("stwo-tensor-weights-v1");
    tr.mixDigest(key.root);
    var ktw = try pcs.Twiddles.init(a, key.log_cols + cfg.pcs.log_blowup);
    defer ktw.deinit(a);
    try pcs.verifyOpening(a, &tr, cfg.pcs, &ktw, .{ .log_rows = key.log_rows, .log_cols = key.log_cols, .log_blowup = cfg.pcs.log_blowup, .rows_used = key.rows_used }, key.root, &.{}, true, proof);
}
