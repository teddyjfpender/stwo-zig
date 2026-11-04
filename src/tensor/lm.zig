//! Model-scale statements: an N-layer stack with dense and MoE layers
//! interleaved (as in Llama 4 Maverick), the prompt's embeddings as public
//! input, an LM head and the greedy-token output check.
//!
//! Statement for a request (prompt x of T - P + 1 tokens, output y of P
//! tokens, P = 2^log_out, the window is x || y[0..P-1]):
//!
//!   X = Emb[window]                       public input [T, D], bound by a lineq
//!   H = Layer_{L-1}(... Layer_0(X))       dense / MoE decoder layers (transformer.zig)
//!   Hs = H[T-P .. T)                      last P positions (fixed-bit slice, lineq)
//!   logits = rq(RMSNorm(Hs, g) . W_lm)    core matmul, W_lm [D, V] committed, int8
//!   y[t] = greedy(logits[t]) = min{v : logits[t, v] = max_v' logits[t, v']}
//!
//! Greedy check (y public): Sel[t, v] = [v = y_t] and Lt[t, v] = [v < y_t] are
//! public tensors the verifier builds from y. Committed m [P] and
//! Dr [P, V] with
//!   (1) Dr - m + logits = 0                        (lineq)
//!   (2) Dr - Lt in [0, 256)                        (range key)
//!   (3) sum_v Sel[t, v] Dr[t, v] = 0 for every t   (exact einsum, zero)
//! (3) gives Dr[t, y_t] = 0, so m_t = logits[t, y_t]; then
//! Dr[t, v] = logits[t, y_t] - logits[t, v], an integer in (-256, 256), and
//! (2) forces logits[t, v] <= logits[t, y_t] for every v and strict inequality
//! for v < y_t: y_t is the least maximiser. This reuses the rowmax pattern of
//! attention / MoE routing (transformer.md) with the selector public, so no
//! binary-selector check and no V x V tie-break triangle are needed.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");
const model = @import("model.zig");

const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;
const ids = tf.ids;
const term = tf.term;

pub const ModelCfg = struct {
    log_t: u32,
    log_d: u32,
    log_heads: u32,
    log_kv_heads: u32,
    /// dense SwiGLU width
    log_f: u32,
    n_layers: u32,
    /// MoE layers: 2^log_experts experts of width 2^log_f_expert, top-1,
    /// 2^log_capacity slots each; 0 = all layers dense
    log_experts: u32 = 0,
    log_f_expert: u32 = 0,
    log_capacity: u32 = 0,
    /// layer l is MoE iff log_experts > 0 and l % moe_every == moe_every - 1
    /// (Maverick interleaves dense and MoE layers: moe_every = 2)
    moe_every: u32 = 2,
    log_vocab: u32,
    /// greedy-checked positions: the last 2^log_out of the window
    log_out: u32 = 0,
    fused_qkv: bool = true,
    /// weight-table column count (router columns are padded to it)
    weight_log_cols: u32 = 0,
    /// MoE experts as stacked [E, K, N] weights proved by batched matmuls (one
    /// weight claim per stack instead of one per expert matrix); false: the
    /// per-expert transformer.moe layout
    stacked_experts: bool = true,

    pub fn isMoeLayer(self: ModelCfg, l: u32) bool {
        return self.log_experts > 0 and l % self.moe_every == self.moe_every - 1;
    }

    pub fn layerCfg(self: ModelCfg, l: u32) tf.LayerCfg {
        const moe = self.isMoeLayer(l);
        return .{
            .log_t = self.log_t,
            .log_d = self.log_d,
            .log_f = if (moe) self.log_f_expert else self.log_f,
            .log_heads = self.log_heads,
            .log_kv_heads = self.log_kv_heads,
            .n_layers = 1,
            .log_experts = if (moe) self.log_experts else 0,
            .log_capacity = if (moe) self.log_capacity else 0,
            .router_log_cols = self.weight_log_cols,
            .fused_qkv = self.fused_qkv,
        };
    }

    pub fn isStackedLayer(self: ModelCfg, l: u32) bool {
        return self.stacked_experts and self.isMoeLayer(l);
    }

    /// weights of layer l: attention, then MLP (dense), or router + experts
    /// (per expert: gate, up, down; stacked: three [E, ., .] tensors)
    pub fn weightsOfLayer(self: ModelCfg, l: u32) u32 {
        const lc = self.layerCfg(l);
        return if (self.isStackedLayer(l)) lc.wRouter() + 4 else lc.weightsPerLayer();
    }

    pub fn layerBase(self: ModelCfg, l: u32) u32 {
        var s: u32 = 0;
        for (0..l) |i| s += self.weightsOfLayer(@intCast(i));
        return s;
    }

    pub fn lmHead(self: ModelCfg) u32 {
        return self.layerBase(self.n_layers);
    }

    pub fn nMoeLayers(self: ModelCfg) u32 {
        var n: u32 = 0;
        for (0..self.n_layers) |l| n += @intFromBool(self.isMoeLayer(@intCast(l)));
        return n;
    }

    pub fn validate(self: ModelCfg) !void {
        if (self.n_layers == 0 or self.moe_every == 0) return error.BadConfig;
        if (self.log_out > self.log_t or self.log_vocab < 1 or self.log_vocab > 20) return error.BadConfig;
        // logits [P, V] index space and the greedy einsum (t, v) fit the ext label space
        if (self.log_out + self.log_vocab > xt.MAXB - 2) return error.BadConfig;
        for (0..self.n_layers) |l| try self.layerCfg(@intCast(l)).validate();
    }
};

pub fn weightInfos(a: std.mem.Allocator, cfg: ModelCfg) ![]TensorInfo {
    var out: std.ArrayList(TensorInfo) = .empty;
    errdefer out.deinit(a);
    for (0..cfg.n_layers) |l| {
        const lc = cfg.layerCfg(@intCast(l));
        const wi = try tf.layerWeightInfos(a, lc);
        defer a.free(wi);
        if (cfg.isStackedLayer(@intCast(l))) {
            // attention + router as in the per-expert layout, then the stacks
            try out.appendSlice(a, wi[0 .. lc.wRouter() + 1]);
            const le = lc.log_experts;
            try out.append(a, .{ .log_dims = .{ le, lc.log_d, lc.log_f }, .n_dims = 3 });
            try out.append(a, .{ .log_dims = .{ le, lc.log_d, lc.log_f }, .n_dims = 3 });
            try out.append(a, .{ .log_dims = .{ le, lc.log_f, lc.log_d }, .n_dims = 3 });
        } else try out.appendSlice(a, wi);
    }
    try out.append(a, TensorInfo.mat(cfg.log_d, cfg.log_vocab));
    return out.toOwnedSlice(a);
}

/// Weights one token touches: attention and dense MLPs, each MoE layer's
/// router and one expert, and the LM head.
pub fn activeWeightsPerToken(cfg: ModelCfg, infos: []const TensorInfo) usize {
    var n: usize = 0;
    for (0..cfg.n_layers) |l| {
        const lc = cfg.layerCfg(@intCast(l));
        const wb = cfg.layerBase(@intCast(l));
        const E = @as(usize, 1) << @intCast(lc.log_experts);
        for (0..cfg.weightsOfLayer(@intCast(l))) |i| {
            const sz = infos[wb + i].size();
            if (!lc.isMoe() or i <= lc.wRouter()) {
                n += sz;
            } else if (cfg.isStackedLayer(@intCast(l))) {
                n += sz / E;
            } else if (i < lc.wExpert(1)) n += sz; // per-expert layout: one expert's three matrices
        }
    }
    return n + infos[cfg.lmHead()].size();
}

pub fn nWeights(a: std.mem.Allocator, cfg: ModelCfg) !usize {
    const wi = try weightInfos(a, cfg);
    defer a.free(wi);
    var n: usize = 0;
    for (wi) |w| n += w.size();
    return n;
}

pub fn setupWeights(a: std.mem.Allocator, pool: *f.Pool, cfg: ModelCfg, pc: proto.Config, seed: u64) !tf.WeightSetup {
    const winfos = try weightInfos(a, cfg);
    errdefer a.free(winfos);
    const wdata = try a.alloc([]i8, winfos.len);
    const wv = try a.alloc([]const i8, winfos.len);
    defer a.free(wv);
    for (wdata, 0..) |*w, i| {
        w.* = try model.randomWeights(a, winfos[i].size(), seed + i, -8, 7);
        wv[i] = w.*;
    }
    // router padding columns (>= E) are zero, as in a padded real router: they
    // must not inflate the router's requant shift (coarse logits -> ties ->
    // everything routed to expert 0)
    for (0..cfg.n_layers) |l| {
        const lc = cfg.layerCfg(@intCast(l));
        if (!lc.isMoe()) continue;
        const r = wdata[cfg.layerBase(@intCast(l)) + lc.wRouter()];
        const ncol = @as(usize, 1) << @intCast(lc.routerLogCols());
        const E = @as(usize, 1) << @intCast(lc.log_experts);
        for (0..r.len / ncol) |row| @memset(r[row * ncol + E .. (row + 1) * ncol], 0);
    }
    const ws = try proto.commitWeights(a, pool, pc, winfos, wv);
    return .{ .ws = ws, .wdata = wdata, .winfos = winfos };
}

const MoeLayer = struct { y: u32, logits: u32, expert_of: []const usize };

/// Y[e] = requant(X[e] . W[e]) for X [E, T, K] and a stacked weight W [E, K, N]
/// (a core matmul with 3-dim operands; protocol.zig proves it as a batched
/// matmul with one weight claim).
pub fn matmul3(b: *tf.Builder, ws: *const proto.WeightStore, x: u32, w: u32) !u32 {
    const xi = b.infos.items[x];
    const wi = ws.infos[w];
    std.debug.assert(xi.n_dims == 3 and wi.n_dims == 3);
    const acc = try proto.batchedMatmulAcc(b.a, b.pool, xi, b.wit.items[x], ws.matrix(w), null);
    defer b.a.free(acc);
    const s = model.chooseShift(acc);
    const y = try b.a.alloc(i32, acc.len);
    for (acc, y) |v, *o| o.* = proto.requant(v, s);
    const id = try b.add(.{ .log_dims = .{ xi.log_dims[0], xi.log_dims[1], wi.log_dims[2] }, .n_dims = 3 }, y);
    try b.ops.append(b.a, .{ .matmul = .{ .x = x, .w = w, .y = id, .shift = s } });
    return id;
}

/// Top-1 MoE with stacked experts: the routing of transformer.moe, then
/// Xe[x, c, d] = sum_t Disp[x, c, t] y[t, d] (one exact einsum), the SwiGLU of
/// every expert as batched matmuls over the [E, C, .] stacks (g, u, down),
/// and out[t, d] = sum_{x, c} Disp[x, c, t] MO[x, c, d]. Same semantics as
/// transformer.moe (each token's output is its expert's SwiGLU).
pub fn moeStacked(b: *tf.Builder, c: tf.Ctx, wb: u32, y: u32) !struct { out: u32, route: tf.MoeRoute, xe: u32, mo: u32 } {
    const cfg = c.cfg;
    const lt = cfg.log_t;
    const ld = cfg.log_d;
    const le = cfg.log_experts;
    const lc = cfg.log_capacity;
    const r = try tf.moeRoute(b, c, wb, y);
    const ns = le + lc + ld;
    const xe = (try b.einsumExact(.{ .log_dims = .{ le, lc, ld }, .n_dims = 3 }, ns, Ref.w(r.disp), Ref.w(y), lt, &.{ ids(0, le + lc), ids(ns, lt) }, &.{ ids(ns, lt), ids(le + lc, ld) })).?;
    const w0 = wb + cfg.wRouter() + 1;
    const g = try matmul3(b, c.ws, xe, w0);
    const u = try matmul3(b, c.ws, xe, w0 + 1);
    const act = try b.lookup(g, c.silu);
    const hm = try b.hadamard(act, u);
    const mo = try matmul3(b, c.ws, hm, w0 + 2);
    const n_out = lt + ld;
    const out = (try b.einsumExact(TensorInfo.mat(lt, ld), n_out, Ref.w(r.disp), Ref.w(mo), le + lc, &.{ ids(n_out, le + lc), ids(0, lt) }, &.{ ids(n_out, le + lc), ids(lt, ld) })).?;
    return .{ .out = out, .route = r, .xe = xe, .mo = mo };
}

pub const GreedyOut = struct { m: u32, dr: u32, sel: u32, lt: u32 };

/// The greedy-token check on int8 logits [2^lp, 2^lv] for public tokens.
/// `tokens[t]` must be the least maximiser of row t (else the honest prover
/// refuses at proving time: the range key fails).
/// `logits` may have 2^lr >= 2^lp rows; the check covers its last 2^lp rows.
pub fn greedyCheck(b: *tf.Builder, logits: u32, lp: u32, lv: u32, tokens: []const u32) !GreedyOut {
    const P = @as(usize, 1) << @intCast(lp);
    const V = @as(usize, 1) << @intCast(lv);
    const lr = b.infos.items[logits].logSize() - lv;
    std.debug.assert(tokens.len == P and lr >= lp);
    const rows = @as(usize, 1) << @intCast(lr);
    const L = b.wit.items[logits][(rows - P) * V ..];
    const rowfix = tf.fixesOf(rows - 1, lr - lp); // top row bits = 1: the last 2^lp rows
    const sel = try b.a.alloc(i32, P * V);
    defer b.a.free(sel);
    const ltv = try b.a.alloc(i32, P * V);
    defer b.a.free(ltv);
    const m = try b.a.alloc(i32, P);
    const dr = b.a.alloc(i32, P * V) catch |e| {
        b.a.free(m);
        return e;
    };
    for (0..P) |t| {
        if (tokens[t] >= V) {
            b.a.free(m);
            b.a.free(dr);
            return error.BadToken;
        }
        m[t] = L[t * V + tokens[t]];
        for (0..V) |v| {
            sel[t * V + v] = @intFromBool(v == tokens[t]);
            ltv[t * V + v] = @intFromBool(v < tokens[t]);
            dr[t * V + v] = m[t] - L[t * V + v];
        }
    }
    const n = lp + lv;
    const sel_id = try b.public(n, sel);
    const lt_id = try b.public(n, ltv);
    const m_id = try b.addVec(lp, m);
    const dr_id = try b.addVec(n, dr);
    const all = ids(0, n);
    // (1) Dr - m + logits = 0
    try b.lineq(n, try b.expr(&.{ term(1, Ref.w(dr_id), &.{all}), term(-1, Ref.w(m_id), &.{ids(0, lp)}), term(1, Ref.w(logits), &.{ rowfix, all }) }, 0));
    // (2) Dr - Lt in [0, 256)
    try b.key(n, try b.expr(&.{ term(1, Ref.w(dr_id), &.{all}), term(-1, Ref.p(lt_id), &.{all}) }, 0), null, .{ .range = 8 });
    // (3) sum_v Sel Dr = 0 per row
    _ = try b.einsumExact(null, lp, Ref.w(dr_id), Ref.p(sel_id), lv, &.{all}, &.{all});
    return .{ .m = m_id, .dr = dr_id, .sel = sel_id, .lt = lt_id };
}

/// Least maximiser of each row of int8 logits [P, V] (the honest output).
pub fn greedyTokens(a: std.mem.Allocator, L: []const i32, P: usize, V: usize) ![]u32 {
    const out = try a.alloc(u32, P);
    for (0..P) |t| {
        var best: i32 = std.math.minInt(i32);
        var arg: usize = 0;
        for (0..V) |v| if (L[t * V + v] > best) {
            best = L[t * V + v];
            arg = v;
        };
        out[t] = @intCast(arg);
    }
    return out;
}

pub const ModelOut = struct {
    x: u32,
    hidden: u32,
    logits: u32,
    greedy: GreedyOut,
    /// greedy tokens of the last 2^log_out positions (owned by the builder arena)
    tokens: []u32,
    /// largest number of tokens routed to one expert (any MoE layer)
    max_expert_load: usize = 0,
    /// router input (RMSNorm output) of each MoE layer, in layer order
    router_in: []const u32 = &.{},
    router_logits: []const u32 = &.{},
};

/// Synthetic-weight calibration (offline, before the commitment): with random
/// weights the router inputs of all tokens share one dominant direction (with
/// a per-token sign and scale), so a random router sends most tokens to one
/// expert, unlike a trained, load-balanced router. For each MoE layer and
/// pass, remove from every used router column its projection on the 2E
/// dominant directions of a calibration window's router inputs
/// (w_x -= sum_k mu_k (mu_k . w_x), |mu_k| = 1, then rounded); routing then
/// follows the rest of the token's features. Edits `ws.table` in place; the caller re-commits.
pub fn calibrateRouters(a: std.mem.Allocator, pool: *f.Pool, cfg: ModelCfg, ws: *proto.WeightStore, x: []const i32, passes: usize) !void {
    if (cfg.log_experts == 0) return;
    var full = cfg;
    full.log_capacity = cfg.log_t;
    const T = @as(usize, 1) << @intCast(cfg.log_t);
    const D = @as(usize, 1) << @intCast(cfg.log_d);
    const E = @as(usize, 1) << @intCast(cfg.log_experts);
    for (0..passes) |_| {
        var moe_i: usize = 0;
        for (0..cfg.n_layers) |l| {
            if (!cfg.isMoeLayer(@intCast(l))) continue;
            var b = tf.Builder.init(a, pool);
            defer b.deinit();
            const mo = try buildModel(&b, full, ws, 7, x, null);
            const y = b.wit.items[mo.router_in[moe_i]];
            moe_i += 1;
            // the K dominant directions of the router inputs (top right
            // singular vectors of Y [T, D], uncentered): power iteration with
            // Gram-Schmidt against the earlier ones
            const K = @min(2 * E, D);
            const mus = try a.alloc(f64, K * D);
            defer a.free(mus);
            const tmp = try a.alloc(f64, T);
            defer a.free(tmp);
            for (0..K) |k| {
                const mu = mus[k * D ..][0..D];
                for (mu, 0..) |*v, d| v.* = 1.0 + @as(f64, @floatFromInt((d * (k + 3)) % 11)) * 0.1;
                for (0..40) |_| {
                    for (0..T) |t| {
                        var acc: f64 = 0;
                        for (0..D) |d| acc += @as(f64, @floatFromInt(y[t * D + d])) * mu[d];
                        tmp[t] = acc;
                    }
                    @memset(mu, 0);
                    for (0..T) |t| for (0..D) |d| {
                        mu[d] += tmp[t] * @as(f64, @floatFromInt(y[t * D + d]));
                    };
                    for (0..k) |q| {
                        const u = mus[q * D ..][0..D];
                        var dot: f64 = 0;
                        for (u, mu) |p, v| dot += p * v;
                        for (u, mu) |p, *v| v.* -= dot * p;
                    }
                    var nrm: f64 = 0;
                    for (mu) |v| nrm += v * v;
                    if (nrm == 0) break;
                    nrm = @sqrt(nrm);
                    for (mu) |*v| v.* /= nrm;
                }
            }
            const lc = cfg.layerCfg(@intCast(l));
            const wr = ws.matrix(cfg.layerBase(@intCast(l)) + lc.wRouter());
            const ncol = wr.nCols();
            const data = @constCast(wr.data);
            const col_f = try a.alloc(f64, D);
            defer a.free(col_f);
            for (0..E) |col| {
                for (0..D) |d| col_f[d] = @floatFromInt(data[d * ncol + col]);
                for (0..K) |k| {
                    const mu = mus[k * D ..][0..D];
                    var sx: f64 = 0;
                    for (0..D) |d| sx += mu[d] * col_f[d];
                    for (0..D) |d| col_f[d] -= mu[d] * sx;
                }
                for (0..D) |d| data[d * ncol + col] = @intFromFloat(std.math.clamp(@round(col_f[d]), -128, 127));
            }
        }
    }
}

/// Re-commits a weight store after its table was edited in place.
pub fn recommit(a: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, ws: *proto.WeightStore) !void {
    const n = ws.infos.len;
    const views = try a.alloc([]const i8, n);
    defer a.free(views);
    const copies = try a.alloc([]i8, n);
    defer a.free(copies);
    for (0..n) |i| {
        copies[i] = try a.dupe(i8, ws.matrix(i).data);
        views[i] = copies[i];
    }
    defer for (copies) |c| a.free(c);
    const infos = ws.infos;
    ws.deinit(a);
    ws.* = try proto.commitWeights(a, pool, pc, infos, views);
}

/// Smallest log capacity that holds every expert's tokens of a forward pass
/// with full capacity (statement parameter chosen per request by the prover).
pub fn fitCapacity(max_load: usize) u32 {
    return std.math.log2_int_ceil(usize, @max(max_load, 1));
}

/// Builds a request: public input embeddings x_in [T, D] (int8), the layer
/// stack, the LM head and the greedy check. `claim` overrides the output
/// tokens (tests: a non-greedy claim must not verify).
pub fn buildModel(b: *tf.Builder, cfg: ModelCfg, ws: *const proto.WeightStore, seed: u64, x_in: []const i32, claim: ?[]const u32) !ModelOut {
    try cfg.validate();
    const lt = cfg.log_t;
    const ld = cfg.log_d;
    // shared publics (RoPE, mask, exp table, SiLU, gammas, MoE triangle)
    var ctx_cfg = cfg.layerCfg(if (cfg.log_experts > 0) cfg.moe_every - 1 else 0);
    ctx_cfg.n_layers = cfg.n_layers;
    const c0 = try tf.initCtxPublics(b, ctx_cfg, ws, seed);
    {
        const wi = try weightInfos(b.a, cfg);
        defer b.a.free(wi);
        try b.weight_infos.appendSlice(b.a, wi);
    }
    // public input bound to the committed layer-0 input
    const n_x = lt + ld;
    const x_pub = try b.public(n_x, x_in);
    var x = try b.add(TensorInfo.mat(lt, ld), try b.a.dupe(i32, x_in));
    const x_id = x;
    try b.lineq(n_x, try b.expr(&.{ term(1, Ref.w(x), &.{ids(0, n_x)}), term(-1, Ref.p(x_pub), &.{ids(0, n_x)}) }, 0));
    var max_load: usize = 0;
    var router_in: std.ArrayList(u32) = .empty;
    var router_logits: std.ArrayList(u32) = .empty;
    for (0..cfg.n_layers) |l| {
        var c = c0;
        c.cfg = cfg.layerCfg(@intCast(l));
        const wb = cfg.layerBase(@intCast(l));
        var route: ?MoeLayer = null;
        if (cfg.isStackedLayer(@intCast(l))) {
            const ab = try tf.attnBlock(b, c, @intCast(l), wb, x, l == 0);
            const ms = try moeStacked(b, c, wb, ab.rms2.y);
            x = try tf.residual(b, ab.h, ms.out);
            route = .{ .y = ab.rms2.y, .logits = ms.route.logits, .expert_of = ms.route.expert_of };
        } else {
            const o = try tf.decoderLayerAt(b, c, @intCast(l), wb, x, l == 0);
            x = o.out;
            if (o.moe) |m| route = .{ .y = o.rms2.y, .logits = m.logits, .expert_of = m.expert_of };
        }
        if (route) |m| {
            try router_in.append(b.arena.allocator(), m.y);
            try router_logits.append(b.arena.allocator(), m.logits);
            var load: [64]usize = [_]usize{0} ** 64;
            for (m.expert_of) |e| load[e] += 1;
            for (load) |n| max_load = @max(max_load, n);
        }
    }
    // last 2^lh positions go through the head (lh >= 1: GKR instances need >= 2
    // entries); the greedy check covers the last 2^lp of them
    const lp = cfg.log_out;
    const lh = @max(lp, @min(lt, 1));
    var hs = x;
    if (lh < lt) {
        const D = @as(usize, 1) << @intCast(ld);
        const Ph = @as(usize, 1) << @intCast(lh);
        const T = @as(usize, 1) << @intCast(lt);
        const sl = try b.a.dupe(i32, b.wit.items[x][(T - Ph) * D ..][0 .. Ph * D]);
        hs = try b.add(TensorInfo.mat(lh, ld), sl);
        const ones = tf.fixesOf((@as(usize, 1) << @intCast(lt - lh)) - 1, lt - lh);
        try b.lineq(lh + ld, try b.expr(&.{ term(1, Ref.w(hs), &.{ids(0, lh + ld)}), term(-1, Ref.w(x), &.{ ones, ids(0, lh + ld) }) }, 0));
    }
    // final RMSNorm (public gamma) and LM head
    var ch = c0;
    ch.cfg = cfg.layerCfg(0);
    ch.cfg.log_t = lh;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5eed);
    const g = try b.a.alloc(i32, @as(usize, 1) << @intCast(ld));
    defer b.a.free(g);
    for (g) |*v| v.* = prng.random().intRangeAtMost(i32, 48, 80);
    const gamma = try b.public(ld, g);
    const r = try tf.rmsnorm(b, ch, hs, gamma, false);
    const logits = try b.matmul(ws, r.y, cfg.lmHead());
    const P = @as(usize, 1) << @intCast(lp);
    const V = @as(usize, 1) << @intCast(cfg.log_vocab);
    const Ph = @as(usize, 1) << @intCast(lh);
    const greedy = try greedyTokens(b.a, b.wit.items[logits][(Ph - P) * V ..], P, V);
    defer b.a.free(greedy);
    const toks = try b.arena.allocator().dupe(u32, claim orelse greedy);
    const gc = try greedyCheck(b, logits, lp, cfg.log_vocab, toks);
    return .{ .x = x_id, .hidden = x, .logits = logits, .greedy = gc, .tokens = toks, .max_expert_load = max_load, .router_in = router_in.items, .router_logits = router_logits.items };
}

// ---------------------------------------------------------------------------
// Tests.

const testing = std.testing;
const serve = @import("serve.zig");

fn testPc() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 },
            .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
    };
}

test "model with one checked output token (log_out = 0) proves and verifies" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    var cfg = SmallModel;
    cfg.log_out = 0;
    var pc = testPc();
    pc.weight_log_cols = cfg.weight_log_cols;
    var sw = try setupWeights(a, &pool, cfg, pc, 900);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 77);
    defer a.free(x);
    const mo = try buildModel(&b, cfg, &sw.ws, 3, x, null);
    try testing.expectEqual(@as(usize, 1), mo.tokens.len);
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv, .salt = serve.testSalt(5) }};
    var batch = try serve.proveRequests(a, &pool, pc, &sw.ws, &reqs, null);
    defer batch.deinit(a);
    try serve.verifyRequest(a, pc, reqs[0].st, proto.weightKey(&sw.ws), &batch.requests[0], &batch.shared, 0);
}

const SmallModel = ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 2, .log_experts = 1, .log_f_expert = 4, .log_capacity = 3, .log_vocab = 6, .log_out = 1, .weight_log_cols = 3 };

test "model stack (dense + MoE interleaved), LM head and greedy output: per-request proofs verify; wrong claims rejected" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = SmallModel;
    try testing.expect(!cfg.isMoeLayer(0) and cfg.isMoeLayer(1));
    var pc = testPc();
    pc.weight_log_cols = cfg.weight_log_cols;
    var sw = try setupWeights(a, &pool, cfg, pc, 700);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    const key = proto.weightKey(&sw.ws);
    const R = 2;
    var bs: [R]tf.Builder = undefined;
    var outs: [R]ModelOut = undefined;
    var views: [R][]const []const i32 = undefined;
    var reqs: [R]serve.Request = undefined;
    for (0..R) |j| {
        bs[j] = tf.Builder.init(a, &pool);
        const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 40 + j);
        defer a.free(x);
        outs[j] = try buildModel(&bs[j], cfg, &sw.ws, 3, x, null);
        // the claimed tokens are the least maximisers (direct reference)
        const V = @as(usize, 1) << cfg.log_vocab;
        const Lall = bs[j].wit.items[outs[j].logits];
        const L = Lall[Lall.len - (outs[j].tokens.len * V) ..];
        for (outs[j].tokens, 0..) |tok, t| {
            for (0..V) |v| {
                try testing.expect(L[t * V + v] <= L[t * V + tok]);
                if (v < tok) try testing.expect(L[t * V + v] < L[t * V + tok]);
            }
        }
        views[j] = try bs[j].witnessView(a);
        reqs[j] = .{ .st = bs[j].statement(), .witness = views[j], .salt = serve.testSalt(j) };
    }
    defer for (0..R) |j| {
        a.free(views[j]);
        bs[j].deinit();
    };
    var batch = try serve.proveRequests(a, &pool, pc, &sw.ws, &reqs, null);
    defer batch.deinit(a);
    for (0..R) |j| try serve.verifyRequest(a, pc, reqs[j].st, key, &batch.requests[j], &batch.shared, j);
    // single-proof protocol on the same statement as well
    {
        var tm: proto.Timings = .{};
        var p = try proto.prove(a, &pool, pc, reqs[0].st, &sw.ws, views[0], &tm);
        defer p.deinit(a);
        try proto.verify(a, pc, reqs[0].st, key, &p);
    }
    // the verifier's statement claims a different output token -> reject
    {
        const st = reqs[0].st;
        const pubs = try a.dupe(xt.Public, st.ext.publics);
        defer a.free(pubs);
        const V = @as(usize, 1) << cfg.log_vocab;
        const nsel = try a.dupe(i32, pubs[outs[0].greedy.sel].values);
        defer a.free(nsel);
        const nlt = try a.dupe(i32, pubs[outs[0].greedy.lt].values);
        defer a.free(nlt);
        const tok = outs[0].tokens[0];
        const other: u32 = if (tok == 0) 1 else tok - 1;
        nsel[tok] = 0;
        nsel[other] = 1;
        for (0..V) |v| nlt[v] = @intFromBool(v < other);
        pubs[outs[0].greedy.sel].values = nsel;
        pubs[outs[0].greedy.lt].values = nlt;
        var st2 = st;
        st2.ext.publics = pubs;
        try testing.expect(std.meta.isError(serve.verifyRequest(a, pc, st2, key, &batch.requests[0], &batch.shared, 0)));
    }
    // a different public prompt -> reject
    {
        const st = reqs[1].st;
        const pubs = try a.dupe(xt.Public, st.ext.publics);
        defer a.free(pubs);
        var found = false;
        for (pubs, 0..) |p, i| if (p.log_size == cfg.log_t + cfg.log_d and std.mem.eql(i32, p.values, bs[1].wit.items[outs[1].x])) {
            const nx = try a.dupe(i32, p.values);
            nx[5] +%= 1;
            pubs[i].values = nx;
            found = true;
            break;
        };
        try testing.expect(found);
        defer for (pubs, st.ext.publics) |p, q| if (p.values.ptr != q.values.ptr) a.free(p.values);
        var st2 = st;
        st2.ext.publics = pubs;
        try testing.expect(std.meta.isError(serve.verifyRequest(a, pc, st2, key, &batch.requests[1], &batch.shared, 1)));
    }
}

const Outcome = enum { verified, prover_refused, verifier_rejected };

fn gadgetCase(a: std.mem.Allocator, row: []const i32, claim: u32, unchecked: bool) !Outcome {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = testPc();
    pc.weight_log_cols = 2;
    const dummy_info = [_]TensorInfo{TensorInfo.mat(2, 2)};
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    defer ws.deinit(a);
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    try b.weight_infos.appendSlice(a, &dummy_info);
    const lv: u32 = std.math.log2_int(usize, row.len);
    const L = try b.addVec(lv, try a.dupe(i32, row));
    try b.rangeSigned(L, 8);
    _ = greedyCheck(&b, L, 0, lv, &.{claim}) catch return .prover_refused;
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    xt.test_unchecked_prover = unchecked;
    defer xt.test_unchecked_prover = false;
    var proof = proto.prove(a, &pool, pc, st, &ws, wv, &tm) catch return .prover_refused;
    defer proof.deinit(a);
    proto.verify(a, pc, st, proto.weightKey(&ws), &proof) catch return .verifier_rejected;
    return .verified;
}

test "greedy check: least maximiser accepted; later tie, non-maximum and out-of-vocab claims rejected" {
    const a = testing.allocator;
    // max 9 at v = 2 and v = 5 (tie): greedy token is 2
    const row = [_]i32{ -3, 7, 9, 1, -128, 9, 7, 0 };
    try testing.expectEqual(Outcome.verified, try gadgetCase(a, &row, 2, false));
    try testing.expectEqual(Outcome.verified, try gadgetCase(a, &[_]i32{ 127, -128, 127, 0 }, 0, false));
    try testing.expectEqual(Outcome.verified, try gadgetCase(a, &[_]i32{ -128, -128, -128, -128 }, 0, false));
    try testing.expectEqual(Outcome.verified, try gadgetCase(a, &[_]i32{ -128, -128, -128, 127 }, 3, false));
    // the honest prover refuses false claims (later tie, non-maximum)
    try testing.expectEqual(Outcome.prover_refused, try gadgetCase(a, &row, 5, false));
    try testing.expectEqual(Outcome.prover_refused, try gadgetCase(a, &row, 1, false));
    // an unchecked prover gets a proof out; the verifier rejects it
    try testing.expectEqual(Outcome.verifier_rejected, try gadgetCase(a, &row, 5, true));
    try testing.expectEqual(Outcome.verifier_rejected, try gadgetCase(a, &row, 1, true));
    try testing.expectEqual(Outcome.verifier_rejected, try gadgetCase(a, &row, 4, true));
    try testing.expectEqual(Outcome.verifier_rejected, try gadgetCase(a, &[_]i32{ -128, -128, -128, 127 }, 0, true));
    // out-of-vocabulary token
    try testing.expectEqual(Outcome.prover_refused, try gadgetCase(a, &row, 8, false));
}

test "stacked-expert MoE (batched matmuls): matches a direct integer reference; proves, verifies; cheats rejected" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 1, .moe_every = 1, .log_experts = 2, .log_f_expert = 4, .log_capacity = 3, .log_vocab = 4, .weight_log_cols = 3 };
    var pc = testPc();
    pc.weight_log_cols = cfg.weight_log_cols;
    var sw = try setupWeights(a, &pool, cfg, pc, 1300);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    const lc = cfg.layerCfg(0);
    const T = @as(usize, 1) << cfg.log_t;
    const D = @as(usize, 1) << cfg.log_d;
    const Fe = @as(usize, 1) << cfg.log_f_expert;
    const E = @as(usize, 1) << cfg.log_experts;
    for (0..2) |cheat| {
        var b = tf.Builder.init(a, &pool);
        defer b.deinit();
        var ccfg = lc;
        ccfg.n_layers = 1;
        const c = try tf.initCtxPublics(&b, ccfg, &sw.ws, 5);
        try b.weight_infos.appendSlice(a, sw.winfos);
        const yv = try model.randomInput(a, T * D, 77);
        const y = try b.add(TensorInfo.mat(cfg.log_t, cfg.log_d), yv);
        try b.rangeSigned(y, 8);
        const ms = try moeStacked(&b, c, 0, y);
        // shifts of the three batched matmuls
        var shifts: [3]u5 = undefined;
        var n_sh: usize = 0;
        for (b.ops.items) |op| if (op == .matmul and sw.winfos[op.matmul.w].n_dims == 3) {
            shifts[n_sh] = op.matmul.shift;
            n_sh += 1;
        };
        try testing.expectEqual(@as(usize, 3), n_sh);
        // direct reference: out[t] = SwiGLU_{x(t)}(y[t]) with the statement's shifts
        const out = b.wit.items[ms.out];
        const silu = model.siluTable();
        const wg = sw.ws.matrix(1 + 2 + 0).data; // layer: qkv, wo, router, Wg, Wu, Wd
        const wu = sw.ws.matrix(1 + 2 + 1).data;
        const wd = sw.ws.matrix(1 + 2 + 2).data;
        for (0..T) |t| {
            const x = ms.route.expert_of[t];
            var hrow: [16]i64 = undefined;
            for (0..Fe) |j| {
                var ag: i64 = 0;
                var au: i64 = 0;
                for (0..D) |d| {
                    ag += @as(i64, yv[t * D + d]) * wg[(x * D + d) * Fe + j];
                    au += @as(i64, yv[t * D + d]) * wu[(x * D + d) * Fe + j];
                }
                const g = proto.requant(ag, shifts[0]);
                const u = proto.requant(au, shifts[1]);
                const act: i64 = silu.values[@intCast(g + 128)];
                // hadamard shift: from the op list
                var hs: u5 = 0;
                for (b.ops.items) |op| if (op == .hadamard) {
                    hs = op.hadamard.shift;
                };
                hrow[j] = proto.requant(act * u, hs);
            }
            for (0..D) |d| {
                var ad: i64 = 0;
                for (0..Fe) |j| ad += hrow[j] * wd[(x * Fe + j) * D + d];
                try testing.expectEqual(@as(i32, proto.requant(ad, shifts[2])), out[t * D + d]);
            }
        }
        _ = E;
        const st = b.statement();
        const wv = try b.witnessView(a);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        if (cheat == 1) {
            // token 2's MoE output differs from its expert's slot output (the
            // combine einsum); core requant keys would already stop the
            // prover itself on a changed matmul output
            b.wit.items[ms.out][2 * D + 1] += 1;
            xt.test_unchecked_prover = true;
        }
        defer xt.test_unchecked_prover = false;
        var proof = try proto.prove(a, &pool, pc, st, &sw.ws, wv, &tm);
        defer proof.deinit(a);
        const key = proto.weightKey(&sw.ws);
        if (cheat == 1) {
            try testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            continue;
        }
        try proto.verify(a, pc, st, key, &proof);
        // one weight claim per stack (3) + router; tamper the batched sumcheck and finals
        {
            // weight claims (values = the op finals for W; not resent in the proof)
            var tr = @import("transcript.zig").Transcript.initDomain("stwo-tensor-v1");
            var wc = proto.VerifierWeightClaims{};
            defer wc.deinit(a);
            try proto.verifyCore(a, pc, st, key, &proof, &tr, &wc, null);
            try testing.expect(wc.values.items.len <= 6);
        }
        for (proof.op_sumchecks, proof.op_finals) |*p, fin| {
            if (p.rounds.len == 0) continue;
            const sv = p.rounds[0].evals[0];
            p.rounds[0].evals[0] = sv.add(f.QM31.one());
            try testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            p.rounds[0].evals[0] = sv;
            const s0 = fin[0];
            fin[0] = s0.add(f.QM31.one());
            try testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            fin[0] = s0;
        }
        // the weight claim values are the last op finals (W~ at the claim
        // point); tampering one must break the sumcheck or the weight opening
        for (proof.op_finals) |fin| {
            if (fin.len < 2) continue;
            const v = &fin[fin.len - 1];
            const sv = v.*;
            v.* = sv.add(f.QM31.one());
            try testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            v.* = sv;
        }
        // statement / key shape mismatches are errors, not crashes
        {
            const wi2 = try a.dupe(TensorInfo, st.weights);
            defer a.free(wi2);
            for (wi2) |*w| if (w.n_dims == 3) {
                w.n_dims = 2;
                break;
            };
            var st2 = st;
            st2.weights = wi2;
            try testing.expect(std.meta.isError(proto.verify(a, pc, st2, key, &proof)));
        }
        {
            const wi2 = try a.dupe(TensorInfo, st.weights);
            defer a.free(wi2);
            for (wi2) |*w| if (w.n_dims == 3) {
                w.log_dims[0] += 1;
                break;
            };
            var st2 = st;
            st2.weights = wi2;
            try testing.expect(std.meta.isError(proto.verify(a, pc, st2, key, &proof)));
        }
        try proto.verify(a, pc, st, key, &proof);
    }
}

test "model with per-expert MoE layout (stacked_experts = false) still proves per request" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    var cfg = SmallModel;
    cfg.stacked_experts = false;
    var pc = testPc();
    pc.weight_log_cols = cfg.weight_log_cols;
    var sw = try setupWeights(a, &pool, cfg, pc, 1700);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 78);
    defer a.free(x);
    _ = try buildModel(&b, cfg, &sw.ws, 3, x, null);
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv, .salt = serve.testSalt(6) }};
    var batch = try serve.proveRequests(a, &pool, pc, &sw.ws, &reqs, null);
    defer batch.deinit(a);
    try serve.verifyRequest(a, pc, reqs[0].st, proto.weightKey(&sw.ws), &batch.requests[0], &batch.shared, 0);
}
