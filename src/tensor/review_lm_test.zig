//! Regression tests for adversarial review phase B, LM findings LM-1..3
//! (lm.zig). Copied from revb-serve/src/tensor/review_lm_test.zig.
//!
//! The first two tests are the reviewers' gadget-level tests, kept as they
//! were: the greedy gadget alone accepts any Sel/Lt it is handed (that is
//! why the verifier must build them). They pass before and after the fix.
//! The regression tests below them (prefixed "regression") assert the fix
//! at the verifier entry point `lm.verifyRequest(key, desc, prompt, y, ...)`
//! and do not compile / fail on the parent commit (no verifier-side builder,
//! no descriptor, no committed Emb).
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");

const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;
const ids = tf.ids;
const term = tf.term;
const testing = std.testing;

fn testPc() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 },
            .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
        .weight_log_cols = 2,
    };
}

/// The three relations of lm.greedyCheck with caller-supplied Sel, Lt and m
/// (one row, log_out = 0). Proved by the HONEST prover (no unchecked flag).
fn customGreedy(a: std.mem.Allocator, row: []const i32, sel: []const i32, ltv: []const i32, m: i32) !bool {
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc = testPc();
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
    const mv = try a.alloc(i32, 1);
    mv[0] = m;
    const dr = try a.alloc(i32, row.len);
    for (dr, row) |*d, l| d.* = m - l;
    const sel_id = try b.public(lv, sel);
    const lt_id = try b.public(lv, ltv);
    const m_id = try b.addVec(0, mv);
    const dr_id = try b.addVec(lv, dr);
    const all = ids(0, lv);
    try b.lineq(lv, try b.expr(&.{ term(1, Ref.w(dr_id), &.{all}), term(-1, Ref.w(m_id), &.{ids(0, 0)}), term(1, Ref.w(L), &.{all}) }, 0));
    try b.key(lv, try b.expr(&.{ term(1, Ref.w(dr_id), &.{all}), term(-1, Ref.p(lt_id), &.{all}) }, 0), null, .{ .range = 8 });
    _ = try b.einsumExact(null, 0, Ref.w(dr_id), Ref.p(sel_id), lv, &.{all}, &.{all});
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = proto.prove(a, &pool, pc, st, &ws, wv, &tm) catch return false;
    defer proof.deinit(a);
    proto.verify(a, pc, st, proto.weightKey(&ws), &proof) catch return false;
    return true;
}

const ROW = [_]i32{ -3, 7, 9, 1, -128, 9, 7, 0 }; // max 9 at v = 2 and v = 5

// REVIEW-LM-1: an out-of-vocabulary token y >= V. A verifier that builds
// Sel[v] = [v = y] and Lt[v] = [v < y] from y gets Sel = 0, Lt = 1: relation
// (3) is vacuous and m = max + 1 satisfies (1) and (2). Proof verifies.
test "review lm: verifier-built Sel/Lt for an out-of-vocab token y = V is accepted" {
    const a = testing.allocator;
    const V = ROW.len;
    var sel: [V]i32 = undefined;
    var ltv: [V]i32 = undefined;
    const y: usize = V; // out of vocabulary (any y >= V gives the same tensors)
    for (0..V) |v| {
        sel[v] = @intFromBool(v == y);
        ltv[v] = @intFromBool(v < y);
    }
    try testing.expect(try customGreedy(a, &ROW, &sel, &ltv, 10));
}

// REVIEW-LM-2: Sel and Lt are both statement data, absorbed but never
// cross-checked. With Lt inconsistent with Sel, a LATER maximiser (5) passes;
// with a two-hot Sel, the output token is ambiguous.
test "review lm: Sel/Lt not cross-checked: later tie and two-hot selector accepted" {
    const a = testing.allocator;
    const V = ROW.len;
    var sel: [V]i32 = [_]i32{0} ** V;
    var ltv: [V]i32 = [_]i32{0} ** V;
    sel[5] = 1; // claims token 5 (the honest least maximiser is 2)
    try testing.expect(try customGreedy(a, &ROW, &sel, &ltv, 9));
    sel[2] = 1; // two-hot: tokens 2 and 5
    try testing.expect(try customGreedy(a, &ROW, &sel, &ltv, 9));
    // sanity: the consistent Lt for y = 5 is rejected by the honest prover/verifier
    var lt5: [V]i32 = undefined;
    for (0..V) |v| lt5[v] = @intFromBool(v < 5);
    var sel5: [V]i32 = [_]i32{0} ** V;
    sel5[5] = 1;
    try testing.expect(!(try customGreedy(a, &ROW, &sel5, &lt5, 9)));
}

// ---------------------------------------------------------------------------
// Regression tests (verifier side).

const lm = @import("lm.zig");
const serve = @import("serve.zig");

const CFG = lm.ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 1, .log_vocab = 4, .log_out = 1, .weight_log_cols = 3 };

const Fx = struct {
    pool: f.Pool,
    sw: tf.WeightSetup,
    desc: lm.ModelDesc,
    pc: proto.Config,

    fn init(fx: *Fx, a: std.mem.Allocator) !void {
        try fx.pool.init(a, 2);
        fx.pc = testPc();
        fx.pc.weight_log_cols = CFG.weight_log_cols;
        fx.sw = try lm.setupWeights(a, &fx.pool, CFG, fx.pc, 700);
        fx.desc = try lm.ModelDesc.synthetic(a, CFG, 3);
    }

    fn deinit(fx: *Fx, a: std.mem.Allocator) void {
        fx.desc.deinit(a);
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
        fx.pool.deinit();
    }

    fn key(fx: *const Fx) proto.WeightKey {
        return proto.weightKey(&fx.sw.ws);
    }
};

/// Proves one request's statement in a batch of one and verifies it with
/// the LM verifier for (prompt, y).
fn proveVerify(a: std.mem.Allocator, fx: *Fx, b: *tf.Builder, prompt: []const u32, y: []const u32) !void {
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv }};
    var batch = try serve.proveRequests(a, &fx.pool, fx.pc, &fx.sw.ws, &reqs, null);
    defer batch.deinit(a);
    try lm.verifyRequest(a, fx.pc, fx.key(), &fx.desc, prompt, y, reqs[0].st, &batch.requests[0], &batch.shared, 0);
}

// LM-1 regression: Emb is committed (in the key), the window's tokens are
// the public input, and the verifier rebuilds OH = 2 onehot(prompt ||
// y[0..P-1)) itself. A statement over embeddings unrelated to y (the
// reviewer's case: a window whose tail is not y[0..P-1)) is rejected.
test "regression LM-1: X = Emb[prompt || y[0..P-1)] from the committed Emb; an unrelated window is rejected" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    // the key covers Emb [V, D]
    const k = fx.key();
    try testing.expect(std.meta.eql(k.infos[CFG.embIndex()], TensorInfo.mat(CFG.log_vocab, CFG.log_d)));
    // honest decoded request verifies
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 41);
    defer rq.deinit(a);
    try proveVerify(a, &fx, &rq.b, rq.prompt, rq.y);
    // a statement whose window tail is not y[0..P-1): built over prompt || z
    // with z != y[0], claiming the window's own greedy output
    const T = @as(usize, 1) << CFG.log_t;
    const V = @as(u32, 1) << CFG.log_vocab;
    const w = try a.alloc(u32, T);
    defer a.free(w);
    @memcpy(w[0 .. T - 1], rq.prompt);
    w[T - 1] = (rq.y[0] + 1) % V;
    var b = tf.Builder.init(a, &fx.pool);
    defer b.deinit();
    const mo = try lm.buildModel(&b, &fx.desc, &fx.sw.ws, w, null);
    // the proof itself is fine; the verifier for (prompt, mo.tokens) rejects
    // unless mo.tokens[0] happens to equal w[T-1] (then the request is true)
    try testing.expect(mo.tokens[0] != w[T - 1]); // (holds for this seed)
    try testing.expectError(error.StatementMismatch, proveVerify(a, &fx, &b, rq.prompt, mo.tokens));
    // a key without Emb (the pre-fix weight list) is rejected
    var k2 = k;
    k2.infos = k.infos[0..CFG.embIndex()];
    try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, k2, &fx.desc, rq.prompt, rq.y, rq.b.statement()));
}

// LM-2 regression (a): an out-of-vocab y is refused by the VERIFIER (the
// reviewer's REVIEW-LM-1 tensors Sel = 0, Lt = 1 are never built).
// (b): Sel/Lt are the verifier's own: a later tie or a two-hot selector in the
// prover's statement (REVIEW-LM-2) is rejected.
test "regression LM-2: verifier refuses out-of-vocab tokens and builds Sel/Lt itself" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 42);
    defer rq.deinit(a);
    const st = rq.b.statement();
    const V = @as(u32, 1) << CFG.log_vocab;
    try lm.checkRequestStatement(a, fx.key(), &fx.desc, rq.prompt, rq.y, st);
    {
        const yy = try a.dupe(u32, rq.y);
        defer a.free(yy);
        yy[yy.len - 1] = V; // the checked output token is out of vocabulary
        try testing.expectError(error.BadToken, lm.checkRequestStatement(a, fx.key(), &fx.desc, rq.prompt, yy, st));
        yy[yy.len - 1] = V + 1000;
        try testing.expectError(error.BadToken, lm.checkRequestStatement(a, fx.key(), &fx.desc, rq.prompt, yy, st));
        const pp = try a.dupe(u32, rq.prompt);
        defer a.free(pp);
        pp[0] = V;
        try testing.expectError(error.BadToken, lm.checkRequestStatement(a, fx.key(), &fx.desc, pp, rq.y, st));
    }
    // prover's statement with a two-hot Sel / an inconsistent Lt
    for (0..2) |which| {
        const pubs = try a.dupe(xt.Public, st.ext.publics);
        defer a.free(pubs);
        const id = if (which == 0) rq.mo.greedy.sel else rq.mo.greedy.lt;
        const nv = try a.dupe(i32, pubs[id].values);
        defer a.free(nv);
        const last_row = nv[nv.len - V ..];
        const tok = rq.y[rq.y.len - 1];
        last_row[(tok + 1) % V] = 1 - last_row[(tok + 1) % V];
        pubs[id].values = nv;
        var st2 = st;
        st2.ext.publics = pubs;
        try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, fx.key(), &fx.desc, rq.prompt, rq.y, st2));
    }
}

// LM-3 regression (the reviewer's skeptic test, inverted): the RMSNorm gains
// come from the verifier-held descriptor. A prover building with other gains
// (seed 4) on the same key differs in exactly the 3 gain publics and is
// rejected by the verifier holding the descriptor (seed 3).
test "regression LM-3: one weight key, two different norm-gain sets: only the descriptor's verifies" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var other = try lm.ModelDesc.synthetic(a, CFG, 4);
    defer other.deinit(a);
    try testing.expect(!std.mem.eql(u8, &other.digest(), &fx.desc.digest()));
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 43);
    defer rq.deinit(a);
    const w = try lm.requestWindow(a, CFG, rq.prompt, rq.y);
    defer a.free(w);
    var b1 = tf.Builder.init(a, &fx.pool);
    defer b1.deinit();
    const mo1 = try lm.buildModel(&b1, &other, &fx.sw.ws, w, null);
    const s0 = rq.b.statement();
    const s1 = b1.statement();
    try testing.expectEqual(s0.ext.publics.len, s1.ext.publics.len);
    var n_gamma_diff: usize = 0;
    for (s0.ext.publics, s1.ext.publics) |p, q| {
        if (p.log_size == CFG.log_d and !std.mem.eql(i32, p.values, q.values)) n_gamma_diff += 1;
    }
    try testing.expectEqual(@as(usize, 3), n_gamma_diff); // 2 per layer + the final norm
    try proveVerify(a, &fx, &rq.b, rq.prompt, rq.y);
    // the other gains: the proof is valid for its own statement, but not for
    // the descriptor this verifier holds
    try testing.expectError(error.StatementMismatch, proveVerify(a, &fx, &b1, rq.prompt, mo1.tokens));
    {
        // isolate the gains: the honest statement with only its 3 gain
        // publics replaced by the other descriptor's -> rejected
        const pubs = try a.dupe(xt.Public, s0.ext.publics);
        defer a.free(pubs);
        for (pubs, s1.ext.publics) |*p, q| {
            if (p.log_size == CFG.log_d and !std.mem.eql(i32, p.values, q.values)) p.values = q.values;
        }
        var st2 = s0;
        st2.ext.publics = pubs;
        try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, fx.key(), &fx.desc, rq.prompt, rq.y, st2));
        try lm.checkRequestStatement(a, fx.key(), &other, rq.prompt, rq.y, st2);
    }
    // a descriptor with a gain out of [1, 127] is refused
    const g = try a.dupe(i32, fx.desc.gains);
    defer a.free(g);
    g[0] = 0;
    const bad = lm.ModelDesc{ .cfg = CFG, .gains = g };
    try testing.expectError(error.BadConfig, lm.checkRequestStatement(a, fx.key(), &bad, rq.prompt, rq.y, s0));
}
