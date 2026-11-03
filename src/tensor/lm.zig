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

    pub fn layerBase(self: ModelCfg, l: u32) u32 {
        var s: u32 = 0;
        for (0..l) |i| s += self.layerCfg(@intCast(i)).weightsPerLayer();
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
        const wi = try tf.layerWeightInfos(a, cfg.layerCfg(@intCast(l)));
        defer a.free(wi);
        try out.appendSlice(a, wi);
    }
    try out.append(a, TensorInfo.mat(cfg.log_d, cfg.log_vocab));
    return out.toOwnedSlice(a);
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
    const ws = try proto.commitWeights(a, pool, pc, winfos, wv);
    return .{ .ws = ws, .wdata = wdata, .winfos = winfos };
}

pub const GreedyOut = struct { m: u32, dr: u32, sel: u32, lt: u32 };

/// The greedy-token check on int8 logits [2^lp, 2^lv] for public tokens.
/// `tokens[t]` must be the least maximiser of row t (else the honest prover
/// refuses at proving time: the range key fails).
pub fn greedyCheck(b: *tf.Builder, logits: u32, lp: u32, lv: u32, tokens: []const u32) !GreedyOut {
    const P = @as(usize, 1) << @intCast(lp);
    const V = @as(usize, 1) << @intCast(lv);
    std.debug.assert(tokens.len == P and b.infos.items[logits].logSize() == lp + lv);
    const L = b.wit.items[logits];
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
    try b.lineq(n, try b.expr(&.{ term(1, Ref.w(dr_id), &.{all}), term(-1, Ref.w(m_id), &.{ids(0, lp)}), term(1, Ref.w(logits), &.{all}) }, 0));
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
};

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
    for (0..cfg.n_layers) |l| {
        var c = c0;
        c.cfg = cfg.layerCfg(@intCast(l));
        const o = try tf.decoderLayerAt(b, c, @intCast(l), cfg.layerBase(@intCast(l)), x, l == 0);
        x = o.out;
    }
    // last 2^lp positions
    const lp = cfg.log_out;
    var hs = x;
    if (lp < lt) {
        const D = @as(usize, 1) << @intCast(ld);
        const P = @as(usize, 1) << @intCast(lp);
        const T = @as(usize, 1) << @intCast(lt);
        const sl = try b.a.dupe(i32, b.wit.items[x][(T - P) * D ..][0 .. P * D]);
        hs = try b.add(TensorInfo.mat(lp, ld), sl);
        const ones = tf.fixesOf((@as(usize, 1) << @intCast(lt - lp)) - 1, lt - lp);
        try b.lineq(lp + ld, try b.expr(&.{ term(1, Ref.w(hs), &.{ids(0, lp + ld)}), term(-1, Ref.w(x), &.{ ones, ids(0, lp + ld) }) }, 0));
    }
    // final RMSNorm (public gamma) and LM head
    var ch = c0;
    ch.cfg = cfg.layerCfg(0);
    ch.cfg.log_t = lp;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x5eed);
    const g = try b.a.alloc(i32, @as(usize, 1) << @intCast(ld));
    defer b.a.free(g);
    for (g) |*v| v.* = prng.random().intRangeAtMost(i32, 48, 80);
    const gamma = try b.public(ld, g);
    const r = try tf.rmsnorm(b, ch, hs, gamma, false);
    const logits = try b.matmul(ws, r.y, cfg.lmHead());
    const P = @as(usize, 1) << @intCast(lp);
    const V = @as(usize, 1) << @intCast(cfg.log_vocab);
    const greedy = try greedyTokens(b.a, b.wit.items[logits], P, V);
    defer b.a.free(greedy);
    const toks = try b.arena.allocator().dupe(u32, claim orelse greedy);
    const gc = try greedyCheck(b, logits, lp, cfg.log_vocab, toks);
    return .{ .x = x_id, .hidden = x, .logits = logits, .greedy = gc, .tokens = toks };
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
        const L = bs[j].wit.items[outs[j].logits];
        const V = @as(usize, 1) << cfg.log_vocab;
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
