//! Regression tests for adversarial review phase B, LM findings LM-1..3
//! (lm.zig). Copied from revb-serve/src/tensor/review_lm_test.zig.
//!
//! The first two tests are the reviewers' gadget-level tests, kept as they
//! were: the greedy gadget alone accepts any Sel/Lt it is handed (that is
//! why the verifier must build them). They pass before and after the fix.
//! The regression tests below them (prefixed "regression") assert the fix
//! at the verifier entry point `lm.verifyRequest(key, desc, request, ...)`,
//! which builds the whole request statement itself (no prover statement).
//! The "variant" tests are the adversarial re-checks of review-B-lm-open
//! (LM-1 OH-pin lineq deleted, LM-2 Sel/Lt redirected to witness copies,
//! LM-3 gains redirected to range-checked witness vectors): each was ACCEPTED by the
//! publics-only verifier (the proof is valid for the prover's statement,
//! asserted below) and is rejected now.
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

/// The relations of lm.greedyCheck ((0) m int8, (1)-(3)) with caller-supplied Sel, Lt and m
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
    // (0) m int8 over one variable, as lm.greedyCheck: without it the
    // statement-level bound analysis refuses the gadget (Dr unbounded)
    try b.key(1, try b.expr(&.{term(1, Ref.w(m_id), &.{ids(0, 0)})}, 128), null, .{ .range = 8 });
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
        fx.desc = try lm.testDesc(a, &fx.pool, CFG, &fx.sw.ws, 3);
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

    fn check(fx: *Fx, a: std.mem.Allocator, prompt: []const u32, y: []const u32, st: proto.Statement) !void {
        return lm.checkRequestStatement(a, &fx.pool, fx.pc, fx.key(), &fx.desc, .{ .prompt = prompt, .y = y }, st);
    }
};

/// A batch of one request proved by the HONEST prover for the builder's
/// statement, checked by the LM verifier for (prompt, y) (and first, when
/// `raw_ok`, against the prover's own statement).
fn proveVerify(a: std.mem.Allocator, fx: *Fx, b: *tf.Builder, prompt: []const u32, y: []const u32, raw_ok: bool) !void {
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv }};
    var batch = try serve.proveRequests(a, &fx.pool, fx.pc, &fx.sw.ws, &reqs, null);
    defer batch.deinit(a);
    if (raw_ok) try serve.verifyRequest(a, fx.pc, reqs[0].st, fx.key(), &batch.requests[0], &batch.shared, 0);
    try lm.verifyRequest(a, &fx.pool, fx.pc, fx.key(), &fx.desc, .{ .prompt = prompt, .y = y }, &batch.requests[0], &batch.shared, 0);
}

/// An attack: the honest prover proves the (modified) statement, the proof
/// verifies against that statement (serve.verifyRequest: it is a real
/// proof), and the LM verifier for (prompt, y) rejects it.
fn expectAttackRejected(a: std.mem.Allocator, fx: *Fx, b: *tf.Builder, prompt: []const u32, y: []const u32) !void {
    const wv = try b.witnessView(a);
    defer a.free(wv);
    const reqs = [_]serve.Request{.{ .st = b.statement(), .witness = wv }};
    var batch = try serve.proveRequests(a, &fx.pool, fx.pc, &fx.sw.ws, &reqs, null);
    defer batch.deinit(a);
    try serve.verifyRequest(a, fx.pc, reqs[0].st, fx.key(), &batch.requests[0], &batch.shared, 0);
    try testing.expect(std.meta.isError(lm.verifyRequest(a, &fx.pool, fx.pc, fx.key(), &fx.desc, .{ .prompt = prompt, .y = y }, &batch.requests[0], &batch.shared, 0)));
}

fn removeXop(b: *tf.Builder, i: usize) void {
    _ = b.xops.orderedRemove(i);
    if (b.ext_accs.orderedRemove(i)) |acc| b.a.free(acc);
}

fn termOf(e: xt.Expr, r: Ref) ?usize {
    for (e.terms, 0..) |t, k| if (t.t.public == r.public and t.t.id == r.id) return k;
    return null;
}

/// Replaces every reference to public `from` in the ext ops (einsum
/// operands, expression terms) by witness `to`; returns the count.
fn redirect(b: *tf.Builder, from: u32, to: u32) !usize {
    const ar = b.arena.allocator();
    var n: usize = 0;
    const same = struct {
        fn f(r: Ref, id: u32) bool {
            return r.public and r.id == id;
        }
    }.f;
    for (b.xops.items) |*op| switch (op.*) {
        .einsum => |*e| {
            if (same(e.a, from)) {
                e.a = Ref.w(to);
                n += 1;
            }
            if (same(e.b, from)) {
                e.b = Ref.w(to);
                n += 1;
            }
        },
        .key => |*k| {
            if (termOf(k.input, Ref.p(from))) |ti| {
                const ts = try ar.dupe(xt.Term, k.input.terms);
                ts[ti].t = Ref.w(to);
                k.input.terms = ts;
                n += 1;
            }
        },
        .lineq => |*l| {
            if (termOf(l.expr, Ref.p(from))) |ti| {
                const ts = try ar.dupe(xt.Term, l.expr.terms);
                ts[ti].t = Ref.w(to);
                l.expr.terms = ts;
                n += 1;
            }
        },
    };
    return n;
}

fn onehot2(a: std.mem.Allocator, window: []const u32, V: usize) ![]i32 {
    const oh = try a.alloc(i32, window.len * V);
    @memset(oh, 0);
    for (window, 0..) |t, i| oh[i * V + t] = 2;
    return oh;
}

// LM-1 regression: Emb is committed (in the key), the window's tokens are
// the public input, and the verifier rebuilds the whole statement from
// (prompt, y). A statement over a window whose tail is not y[0..P-1) is
// rejected, and so is a key without Emb.
test "regression LM-1: X = Emb[prompt || y[0..P-1)] from the committed Emb; an unrelated window is rejected" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    // the key covers Emb [V, D]
    const k = fx.key();
    try testing.expect(std.meta.eql(k.infos[CFG.embIndex()], TensorInfo.mat(CFG.log_vocab, CFG.log_d)));
    // honest decoded request verifies; the prover's statement is the verifier's
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 41);
    defer rq.deinit(a);
    try proveVerify(a, &fx, &rq.b, rq.prompt, rq.y, true);
    try fx.check(a, rq.prompt, rq.y, rq.b.statement());
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
    try testing.expect(mo.tokens[0] != w[T - 1]); // (holds for this seed)
    try expectAttackRejected(a, &fx, &b, rq.prompt, mo.tokens);
    try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, mo.tokens, b.statement()));
    // a key without Emb (the pre-fix weight list) is rejected
    var k2 = k;
    k2.infos = k.infos[0..CFG.embIndex()];
    try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, &fx.pool, fx.pc, k2, &fx.desc, .{ .prompt = rq.prompt, .y = rq.y }, rq.b.statement()));
}

// LM-1 re-check variant (review-B-lm-open): a real request for prompt p2
// (output y2), its OH public replaced by 2 onehot(p1 || y2[0..P-1)) (so
// every public is the verifier's for (p1, y2)), and the ONE lineq pinning
// the committed OH witness to the OH public deleted. The honest prover
// proves it, the proof is valid for that statement, and a publics-only
// verifier accepted (p1, y2). The verifier-built statement keeps the
// lineq: rejected.
test "regression LM-1 variant: deleting the OH-pin lineq to reuse another prompt's proof is rejected" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    const V = @as(usize, 1) << CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 44);
    defer rq.deinit(a);
    // p1: p2 with one token changed, whose honest output differs from y2
    const p1 = try a.dupe(u32, rq.prompt);
    defer a.free(p1);
    var found = false;
    for (1..V) |dv| {
        p1[0] = @intCast((rq.prompt[0] + dv) % V);
        const y1 = lm.decodeGreedy(a, &fx.pool, &fx.desc, &fx.sw.ws, p1) catch continue;
        defer a.free(y1);
        if (!std.mem.eql(u32, y1, rq.y)) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
    const win1 = try lm.requestWindow(a, CFG, p1, rq.y);
    defer a.free(win1);
    const oh1 = try onehot2(a, win1, V);
    defer a.free(oh1);
    rq.b.publics.items[rq.mo.oh_pub].values = try rq.b.arena.allocator().dupe(i32, oh1);
    var pin: ?usize = null;
    for (rq.b.xops.items, 0..) |op, i| if (op == .lineq and termOf(op.lineq.expr, Ref.p(rq.mo.oh_pub)) != null) {
        try testing.expect(pin == null);
        pin = i;
    };
    removeXop(&rq.b, pin.?);
    try expectAttackRejected(a, &fx, &rq.b, p1, rq.y);
    try testing.expectError(error.StatementMismatch, fx.check(a, p1, rq.y, rq.b.statement()));
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
    try fx.check(a, rq.prompt, rq.y, st);
    {
        const yy = try a.dupe(u32, rq.y);
        defer a.free(yy);
        yy[yy.len - 1] = V; // the checked output token is out of vocabulary
        try testing.expectError(error.BadToken, fx.check(a, rq.prompt, yy, st));
        yy[yy.len - 1] = V + 1000;
        try testing.expectError(error.BadToken, fx.check(a, rq.prompt, yy, st));
        yy[yy.len - 1] = std.math.maxInt(u32);
        try testing.expectError(error.BadToken, fx.check(a, rq.prompt, yy, st));
        const pp = try a.dupe(u32, rq.prompt);
        defer a.free(pp);
        pp[0] = V;
        try testing.expectError(error.BadToken, fx.check(a, pp, rq.y, st));
        try testing.expectError(error.BadRequest, fx.check(a, pp[1..], rq.y, st));
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
        try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, rq.y, st2));
    }
}

// LM-2 re-check variant: for a false claim y' (last token changed; the
// window is unchanged), the Sel/Lt publics are the verifier's for y', but
// witness copies of the HONEST Sel/Lt are added and the zero einsum's Sel
// operand and the range key's Lt term are pointed at them (2 refs). The
// honest prover proves it; the verifier-built statement reads its own
// publics: rejected.
test "regression LM-2 variant: greedy Sel/Lt redirected to witness copies is rejected" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    const V = @as(u32, 1) << CFG.log_vocab;
    const n = CFG.log_out + CFG.log_vocab;
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 45);
    defer rq.deinit(a);
    const yf = try a.dupe(u32, rq.y);
    defer a.free(yf);
    yf[yf.len - 1] = (yf[yf.len - 1] + 1) % V;
    const ar = rq.b.arena.allocator();
    const g = rq.mo.greedy;
    // witness copies of the honest selector tensors
    const sel_w = try rq.b.addVec(n, try a.dupe(i32, rq.b.publics.items[g.sel].values));
    const lt_w = try rq.b.addVec(n, try a.dupe(i32, rq.b.publics.items[g.lt].values));
    // bounded copies (range keys), so the statement passes the verifier's
    // witness-free bound analysis
    for ([_]u32{ sel_w, lt_w }) |cw| try rq.b.key(n, try rq.b.expr(&.{term(1, Ref.w(cw), &.{ids(0, n)})}, 0), null, .{ .range = 1 });
    try testing.expectEqual(@as(usize, 1), try redirect(&rq.b, g.sel, sel_w));
    try testing.expectEqual(@as(usize, 1), try redirect(&rq.b, g.lt, lt_w));
    // the publics now say y'
    const sel = try ar.alloc(i32, yf.len * V);
    const ltv = try ar.alloc(i32, yf.len * V);
    for (yf, 0..) |tok, t| for (0..V) |v| {
        sel[t * V + v] = @intFromBool(v == tok);
        ltv[t * V + v] = @intFromBool(v < tok);
    };
    rq.b.publics.items[g.sel].values = sel;
    rq.b.publics.items[g.lt].values = ltv;
    try expectAttackRejected(a, &fx, &rq.b, rq.prompt, yf);
    try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, yf, rq.b.statement()));
    // the honest claim still verifies through the same path
    var rq2 = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 45);
    defer rq2.deinit(a);
    try proveVerify(a, &fx, &rq2.b, rq2.prompt, rq2.y, true);
}

/// `fx.desc` with other gains (seed 4) and the same shift plan (borrowed:
/// do not deinit the plan).
fn otherGains(a: std.mem.Allocator, fx: *const Fx) !lm.ModelDesc {
    var other = try lm.ModelDesc.synthetic(a, CFG, 4);
    other.shifts = fx.desc.shifts;
    return other;
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
    var other = try otherGains(a, &fx);
    defer a.free(other.gains);
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
    try proveVerify(a, &fx, &rq.b, rq.prompt, rq.y, true);
    // the other gains: the proof is valid for its own statement, but not for
    // the descriptor this verifier holds
    try expectAttackRejected(a, &fx, &b1, rq.prompt, mo1.tokens);
    {
        // the honest statement with only its 3 gain publics replaced -> rejected
        const pubs = try a.dupe(xt.Public, s0.ext.publics);
        defer a.free(pubs);
        for (pubs, s1.ext.publics) |*p, q| {
            if (p.log_size == CFG.log_d and !std.mem.eql(i32, p.values, q.values)) p.values = q.values;
        }
        var st2 = s0;
        st2.ext.publics = pubs;
        try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, rq.y, st2));
        // P2 model_digest: missing or naming another descriptor -> rejected
        var st3 = s0;
        try testing.expect(st3.model_digest != null);
        st3.model_digest = null;
        try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, rq.y, st3));
        st3.model_digest = other.digest();
        try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, rq.y, st3));
    }
    // a descriptor with a gain out of [1, 127] is refused
    const g = try a.dupe(i32, fx.desc.gains);
    defer a.free(g);
    g[0] = 0;
    const bad = lm.ModelDesc{ .cfg = CFG, .gains = g, .shifts = fx.desc.shifts };
    try testing.expectError(error.BadConfig, lm.checkRequestStatement(a, &fx.pool, fx.pc, fx.key(), &bad, .{ .prompt = rq.prompt, .y = rq.y }, s0));
    // another shift plan is another model (digest), and so is no plan
    try testing.expect(fx.desc.shifts.?.len > 0);
    const sh = try a.dupe(u5, fx.desc.shifts.?);
    defer a.free(sh);
    sh[0] += 1;
    const d2 = lm.ModelDesc{ .cfg = CFG, .gains = fx.desc.gains, .shifts = sh };
    try testing.expect(!std.mem.eql(u8, &d2.digest(), &fx.desc.digest()));
    try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, &fx.pool, fx.pc, fx.key(), &d2, .{ .prompt = rq.prompt, .y = rq.y }, s0));
    const d3 = lm.ModelDesc{ .cfg = CFG, .gains = fx.desc.gains };
    try testing.expectError(error.NotCalibrated, lm.checkRequestStatement(a, &fx.pool, fx.pc, fx.key(), &d3, .{ .prompt = rq.prompt, .y = rq.y }, s0));
}

// LM-3 re-check variant: decode with other gains (seed 4) on its own
// window, write the verifier descriptor's gains into the 3 gain publics and
// its digest into model_digest, and redirect the 3 RMSNorm gain einsums to
// witness vectors holding the other gains. The proof is valid for that
// statement; the verifier-built one reads its own gain publics: rejected.
test "regression LM-3 variant: RMSNorm gains redirected to witness vectors is rejected" {
    const a = testing.allocator;
    var fx: Fx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var other = try otherGains(a, &fx);
    defer a.free(other.gains);
    // a prompt whose decode under the other gains differs from the
    // descriptor's own decode (the false claim)
    var rq: lm.TestRequest = undefined;
    var found = false;
    for (46..110) |seed| {
        rq = lm.TestRequest.init(a, &fx.pool, &other, &fx.sw.ws, seed) catch continue;
        const yd = lm.decodeGreedy(a, &fx.pool, &fx.desc, &fx.sw.ws, rq.prompt) catch null;
        defer if (yd) |v| a.free(v);
        if (yd != null and !std.mem.eql(u32, yd.?, rq.y)) {
            found = true;
            break;
        }
        rq.deinit(a);
    }
    try testing.expect(found);
    defer rq.deinit(a);
    var n_redirected: usize = 0;
    var n_gains: usize = 0;
    for (0..CFG.nGainVecs()) |gi| {
        // the public holding other's gain vector gi
        var pid: ?u32 = null;
        for (rq.b.publics.items, 0..) |p, i| if (p.log_size == CFG.log_d and std.mem.eql(i32, p.values, other.gain(gi))) {
            pid = @intCast(i);
        };
        const id = pid.?;
        const wcopy = try rq.b.addVec(CFG.log_d, try a.dupe(i32, other.gain(gi)));
        try rq.b.key(CFG.log_d, try rq.b.expr(&.{term(1, Ref.w(wcopy), &.{ids(0, CFG.log_d)})}, 0), null, .{ .range = 8 });
        n_redirected += try redirect(&rq.b, id, wcopy);
        rq.b.publics.items[id].values = try rq.b.arena.allocator().dupe(i32, fx.desc.gain(gi));
        n_gains += 1;
    }
    try testing.expectEqual(@as(usize, 3), n_gains);
    try testing.expectEqual(@as(usize, 3), n_redirected);
    rq.b.model_digest = fx.desc.digest();
    try expectAttackRejected(a, &fx, &rq.b, rq.prompt, rq.y);
    try testing.expectError(error.StatementMismatch, fx.check(a, rq.prompt, rq.y, rq.b.statement()));
}
