//! Independent re-check (uncommitted): original reviewer attacks + variants
//! against codex/tensor-lmfix. Each test PRINTS its verdict and asserts what
//! was observed.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const xt = @import("ext.zig");
const tf = @import("transformer.zig");
const lm = @import("lm.zig");
const serve = @import("serve.zig");
const model = @import("model.zig");

const QM31 = f.QM31;
const TensorInfo = proto.TensorInfo;
const Ref = xt.Ref;
const testing = std.testing;

fn say(comptime fmt: []const u8, args: anytype) void {
    std.debug.print("[RECHECK] " ++ fmt ++ "\n", args);
}

// ---------------------------------------------------------------------------
// LM fixture

fn lmPc() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 },
            .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
        .weight_log_cols = 3,
    };
}

const CFG = lm.ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 1, .log_vocab = 4, .log_out = 1, .weight_log_cols = 3 };

const LFx = struct {
    pool: f.Pool,
    sw: tf.WeightSetup,
    desc: lm.ModelDesc,
    pc: proto.Config,

    fn init(fx: *LFx, a: std.mem.Allocator) !void {
        try fx.pool.init(a, 2);
        fx.pc = lmPc();
        fx.sw = try lm.setupWeights(a, &fx.pool, CFG, fx.pc, 700);
        fx.desc = try lm.ModelDesc.synthetic(a, CFG, 3);
    }
    fn deinit(fx: *LFx, a: std.mem.Allocator) void {
        fx.desc.deinit(a);
        fx.sw.ws.deinit(a);
        for (fx.sw.wdata) |w| a.free(w);
        a.free(fx.sw.wdata);
        a.free(fx.sw.winfos);
        fx.pool.deinit();
    }
};

fn proveVerifySt(a: std.mem.Allocator, fx: *LFx, st: proto.Statement, wv: []const []const i32, prompt: []const u32, y: []const u32) !void {
    const reqs = [_]serve.Request{.{ .st = st, .witness = wv }};
    var batch = try serve.proveRequests(a, &fx.pool, fx.pc, &fx.sw.ws, &reqs, null);
    defer batch.deinit(a);
    try lm.verifyRequest(a, fx.pc, proto.weightKey(&fx.sw.ws), &fx.desc, prompt, y, st, &batch.requests[0], &batch.shared, 0);
}

fn usesPublic(e: xt.Expr, pid: u32) bool {
    for (e.terms) |t| if (t.t.public and t.t.id == pid) return true;
    return false;
}

// LM-1 variant (op-structure / P1 class): keep the verifier's OH public, but
// delete the lineq that pins the committed OH witness to it. The witness OH is
// the one-hot of a DIFFERENT prompt. Claim: prompt p1 -> y2 (the output of p2).
test "recheck LM-1 variant: drop the OH lineq, prove another prompt's output" {
    const a = testing.allocator;
    var fx: LFx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var r1 = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 41);
    defer r1.deinit(a);
    var r2 = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 99);
    defer r2.deinit(a);
    const T = @as(usize, 1) << CFG.log_t;
    const V = @as(usize, 1) << CFG.log_vocab;
    const st0 = r2.b.statement();
    const oh_pub = r2.mo.greedy.sel - 2;
    try testing.expectEqual(@as(u32, CFG.log_t + CFG.log_vocab), st0.ext.publics[oh_pub].log_size);
    // the verifier's OH for window p1 || y2[0..P-1)
    const win = try lm.requestWindow(a, CFG, r1.prompt, r2.y);
    defer a.free(win);
    const oh = try a.alloc(i32, T * V);
    defer a.free(oh);
    @memset(oh, 0);
    for (win, 0..) |t, i| oh[i * V + t] = 2;
    const pubs = try a.dupe(xt.Public, st0.ext.publics);
    defer a.free(pubs);
    pubs[oh_pub].values = oh;
    var ops: std.ArrayList(xt.Op) = .empty;
    defer ops.deinit(a);
    var dropped: usize = 0;
    for (st0.ext.ops) |op| {
        if (op == .lineq and usesPublic(op.lineq.expr, oh_pub)) {
            dropped += 1;
            continue;
        }
        try ops.append(a, op);
    }
    try testing.expectEqual(@as(usize, 1), dropped);
    var st = st0;
    st.ext.publics = pubs;
    st.ext.ops = ops.items;
    const wv = try r2.b.witnessView(a);
    defer a.free(wv);
    // the claim is false: the honest output for p1 differs (for these seeds)
    const honest = try lm.decodeGreedy(a, &fx.pool, &fx.desc, &fx.sw.ws, r1.prompt);
    defer a.free(honest);
    const false_claim = !std.mem.eql(u32, honest, r2.y);
    const prompts_differ = !std.mem.eql(u32, r1.prompt, r2.prompt);
    try lm.checkRequestStatement(a, proto.weightKey(&fx.sw.ws), &fx.desc, r1.prompt, r2.y, st);
    const res = proveVerifySt(a, &fx, st, wv, r1.prompt, r2.y);
    say("LM-1 variant: prompts_differ={} claim_false={} honest={any} claimed={any} verify={any}", .{ prompts_differ, false_claim, honest, r2.y, res });
    try res; // observed: accepted
}

// LM-3 variant (same P1 class): verifier's gains in the publics, but the
// rmsnorm einsums read a witness copy of OTHER gains.
test "recheck LM-3 variant: gain publics match the descriptor, einsums read other gains" {
    const a = testing.allocator;
    var fx: LFx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var other = try lm.ModelDesc.synthetic(a, CFG, 4);
    defer other.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 43);
    defer rq.deinit(a);
    const yo = try lm.decodeGreedy(a, &fx.pool, &other, &fx.sw.ws, rq.prompt);
    defer a.free(yo);
    const w = try lm.requestWindow(a, CFG, rq.prompt, yo);
    defer a.free(w);
    var b1 = tf.Builder.init(a, &fx.pool);
    defer b1.deinit();
    const mo1 = try lm.buildModel(&b1, &other, &fx.sw.ws, w, null);
    try testing.expect(std.mem.eql(u32, mo1.tokens, yo));
    // s0: the descriptor's gains over the SAME window (to read its gain publics)
    var bd = tf.Builder.init(a, &fx.pool);
    defer bd.deinit();
    _ = try lm.buildModel(&bd, &fx.desc, &fx.sw.ws, w, null);
    const s0 = bd.statement();
    // gain ids in b1 and witness copies of their (other) values
    var map: [8]struct { pid: u32, wid: u32 } = undefined;
    var nm: usize = 0;
    {
        const s1 = b1.statement();
        for (s0.ext.publics, s1.ext.publics, 0..) |p, q, i| {
            if (p.log_size == CFG.log_d and !std.mem.eql(i32, p.values, q.values)) {
                const wid = try b1.addVec(CFG.log_d, try a.dupe(i32, q.values));
                map[nm] = .{ .pid = @intCast(i), .wid = wid };
                nm += 1;
            }
        }
    }
    try testing.expectEqual(@as(usize, 3), nm);
    const s1 = b1.statement();
    const pubs = try a.dupe(xt.Public, s1.ext.publics);
    defer a.free(pubs);
    for (map[0..nm]) |m| pubs[m.pid].values = s0.ext.publics[m.pid].values;
    const ops = try a.dupe(xt.Op, s1.ext.ops);
    defer a.free(ops);
    var redirected: usize = 0;
    for (ops) |*op| if (op.* == .einsum) {
        for (map[0..nm]) |m| {
            if (op.einsum.b.public and op.einsum.b.id == m.pid) {
                op.einsum.b = Ref.w(m.wid);
                redirected += 1;
            }
            if (op.einsum.a.public and op.einsum.a.id == m.pid) {
                op.einsum.a = Ref.w(m.wid);
                redirected += 1;
            }
        }
    };
    var st = s1;
    st.ext.publics = pubs;
    st.ext.ops = ops;
    const wv = try b1.witnessView(a);
    defer a.free(wv);
    for (st.ext.publics, 0..) |p, i| {
        var vb = tf.Builder.init(a, &fx.pool);
        defer vb.deinit();
        _ = p;
        _ = i;
    }
    {
        const key = proto.weightKey(&fx.sw.ws);
        const r0 = lm.checkRequestStatement(a, key, &fx.desc, rq.prompt, mo1.tokens, st);
        const r1 = lm.checkRequestStatement(a, key, &fx.desc, rq.prompt, rq.y, st);
        const sp = rq.b.statement().ext.publics;
        var ndiff: usize = 0;
        for (sp, st.ext.publics, 0..) |p, q, i| if (p.log_size != q.log_size or !std.mem.eql(i32, p.values, q.values)) {
            ndiff += 1;
            say("LM-3 diff public {} log={}", .{ i, p.log_size });
        };
        say("LM-3 check(y_other)={any} check(y_desc)={any} ndiff_vs_honest={} npub={} {}", .{ r0, r1, ndiff, sp.len, st.ext.publics.len });
    }
    const res = proveVerifySt(a, &fx, st, wv, rq.prompt, mo1.tokens);
    say("LM-3 variant: redirected={} tokens_other={any} tokens_desc={any} verify={any}", .{ redirected, mo1.tokens, rq.y, res });
    try res;
}

// LM-2 variants: y length mismatches, u32 max token, P1-class Sel redirect.
test "recheck LM-2 variants: bad lengths / huge token refused" {
    const a = testing.allocator;
    var fx: LFx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 42);
    defer rq.deinit(a);
    const st = rq.b.statement();
    const key = proto.weightKey(&fx.sw.ws);
    const yy = try a.dupe(u32, rq.y);
    defer a.free(yy);
    yy[0] = std.math.maxInt(u32);
    try testing.expectError(error.BadToken, lm.checkRequestStatement(a, key, &fx.desc, rq.prompt, yy, st));
    try testing.expectError(error.BadRequest, lm.checkRequestStatement(a, key, &fx.desc, rq.prompt, rq.y[0..1], st));
    try testing.expectError(error.BadRequest, lm.checkRequestStatement(a, key, &fx.desc, rq.prompt[1..], rq.y, st));
    // y[P-1] is not in the window; changing it must change Sel/Lt -> mismatch
    yy[0] = rq.y[0];
    yy[yy.len - 1] = (rq.y[yy.len - 1] + 1) % 16;
    try testing.expectError(error.StatementMismatch, lm.checkRequestStatement(a, key, &fx.desc, rq.prompt, yy, st));
    say("LM-2 variants: all refused", .{});
}

// LM-2 P1-class variant: Sel public is the verifier's, but the greedy einsum
// reads a witness Sel for a later tie / different token.
test "recheck LM-2 variant: greedy einsum redirected to a witness Sel" {
    const a = testing.allocator;
    var fx: LFx = undefined;
    try fx.init(a);
    defer fx.deinit(a);
    var rq = try lm.TestRequest.init(a, &fx.pool, &fx.desc, &fx.sw.ws, 42);
    defer rq.deinit(a);
    // claim a different last token z; build Sel/Lt publics for (y with y[P-1] = z)
    const V: u32 = 16;
    const z = (rq.y[rq.y.len - 1] + 1) % V;
    const yz = try a.dupe(u32, rq.y);
    defer a.free(yz);
    yz[yz.len - 1] = z;
    const st0 = rq.b.statement();
    const sel_id = rq.mo.greedy.sel;
    const lt_id = rq.mo.greedy.lt;
    const wsel = try rq.b.addVec(CFG.log_out + CFG.log_vocab, try a.dupe(i32, st0.ext.publics[sel_id].values));
    const wlt = try rq.b.addVec(CFG.log_out + CFG.log_vocab, try a.dupe(i32, st0.ext.publics[lt_id].values));
    const s1 = rq.b.statement();
    const pubs = try a.dupe(xt.Public, s1.ext.publics);
    defer a.free(pubs);
    const P = yz.len;
    const sel = try a.alloc(i32, P * V);
    defer a.free(sel);
    const ltv = try a.alloc(i32, P * V);
    defer a.free(ltv);
    for (yz, 0..) |tok, t| for (0..V) |v| {
        sel[t * V + v] = @intFromBool(v == tok);
        ltv[t * V + v] = @intFromBool(v < tok);
    };
    pubs[sel_id].values = sel;
    pubs[lt_id].values = ltv;
    const ops = try a.dupe(xt.Op, s1.ext.ops);
    defer a.free(ops);
    var redirected: usize = 0;
    for (ops) |*op| {
        switch (op.*) {
            .einsum => |*e| {
                if (e.b.public and e.b.id == sel_id) {
                    e.b = Ref.w(wsel);
                    redirected += 1;
                }
                if (e.a.public and e.a.id == sel_id) {
                    e.a = Ref.w(wsel);
                    redirected += 1;
                }
            },
            .key => |*k| {
                const terms = try rq.b.arena.allocator().dupe(xt.Term, k.input.terms);
                for (terms) |*t| if (t.t.public and t.t.id == lt_id) {
                    t.t = Ref.w(wlt);
                    redirected += 1;
                };
                k.input.terms = terms;
            },
            .lineq => {},
        }
    }
    var st = s1;
    st.ext.publics = pubs;
    st.ext.ops = ops;
    const wv = try rq.b.witnessView(a);
    defer a.free(wv);
    const res = proveVerifySt(a, &fx, st, wv, rq.prompt, yz);
    say("LM-2 P1 variant: redirected={} honest={any} claimed={any} verify={any}", .{ redirected, rq.y, yz, res });
    try res;
}

// ---------------------------------------------------------------------------
// Serve fixture (reviewer's)

fn tlConfig() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 },
            .inner = .{ .log_blowup = 3, .n_queries = 12, .pow_bits = 1 },
            .depth = 1,
        },
        .gkr_threads = 2,
        .batch_matmuls = true,
    };
}
const MCFG = model.Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };
const Fx = struct {
    pool: f.Pool,
    ws: proto.WeightStore,
    wdata: [3][]i8,
    winfos: [3]proto.TensorInfo,
    fn init(fx: *Fx, a: std.mem.Allocator, pc: *proto.Config) !void {
        try fx.pool.init(a, 2);
        fx.winfos = model.mlpWeightInfos(MCFG);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc.*, a, &fx.winfos, 2);
        for (&fx.wdata, 0..) |*w, i| w.* = try model.randomWeights(a, fx.winfos[i].size(), 100 + i, -8, 7);
        const wv = [_][]const i8{ fx.wdata[0], fx.wdata[1], fx.wdata[2] };
        fx.ws = try proto.commitWeights(a, &fx.pool, pc.*, &fx.winfos, &wv);
    }
    fn deinit(fx: *Fx, a: std.mem.Allocator) void {
        fx.ws.deinit(a);
        for (fx.wdata) |w| a.free(w);
        fx.pool.deinit();
    }
};
const Req = struct {
    built: model.Built,
    view: []const []const i32,
    fn init(a: std.mem.Allocator, fx: *Fx, seed: u64) !Req {
        const x = try model.randomInput(a, @as(usize, 1) << (MCFG.log_t + MCFG.log_d), seed);
        defer a.free(x);
        var b = try model.buildMlp(a, &fx.pool, &fx.ws, MCFG, x);
        errdefer b.deinit(a);
        const v = try a.alloc([]const i32, b.witness.len);
        for (b.witness, 0..) |w, i| v[i] = w;
        return .{ .built = b, .view = v };
    }
    fn deinit(r: *Req, a: std.mem.Allocator) void {
        r.built.deinit(a);
        a.free(r.view);
    }
    fn request(r: *const Req, salt: ?[32]u8) serve.Request {
        return .{ .st = r.built.statement(), .witness = r.view, .acc = r.built.accs, .salt = salt };
    }
};

fn appendJunkPoint(a: std.mem.Allocator, cs: *serve.ClaimSet, len: usize) !void {
    const np = try a.alloc([]QM31, cs.points.len + 1);
    @memcpy(np[0..cs.points.len], cs.points);
    const junk = try a.alloc(QM31, len);
    for (junk, 0..) |*v, i| v.* = QM31.fromBase(f.M31.fromCanonical(@intCast(1234 + i)));
    np[cs.points.len] = junk;
    a.free(cs.points);
    cs.points = np;
}

/// Appends a duplicate of claim k (same weight, same point index, same value).
fn dupClaim(a: std.mem.Allocator, cs: *serve.ClaimSet, k: usize) !void {
    const n = cs.w.len;
    const w = try a.alloc(u32, n + 1);
    const po = try a.alloc(u32, n + 1);
    const vs = try a.alloc(QM31, n + 1);
    @memcpy(w[0..n], cs.w);
    @memcpy(po[0..n], cs.point_of);
    @memcpy(vs[0..n], cs.values);
    w[n] = cs.w[k];
    po[n] = cs.point_of[k];
    vs[n] = cs.values[k];
    a.free(cs.w);
    a.free(cs.point_of);
    a.free(cs.values);
    cs.w = w;
    cs.point_of = po;
    cs.values = vs;
}

const Mut = enum { orig_junk, junk_right_len_other, dup_claim_own, dup_claim_other, swap_claims_own };

fn serveMut(a: std.mem.Allocator, m: Mut) ![2]anyerror!void {
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10);
    defer r1.deinit(a);
    const q0 = r0.request(serve.testSalt(0));
    const q1 = r1.request(serve.testSalt(1));
    var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
    defer bp.deinit();
    var tm: proto.Timings = .{};
    try bp.add(q0, &tm);
    try bp.add(q1, &tm);
    switch (m) {
        .orig_junk => {
            try appendJunkPoint(a, &bp.sets.items[0], 3);
            try appendJunkPoint(a, &bp.sets.items[1], 1);
        },
        .junk_right_len_other => try appendJunkPoint(a, &bp.sets.items[1], key.infos[0].logSize()),
        .dup_claim_own => try dupClaim(a, &bp.sets.items[0], 0),
        .dup_claim_other => try dupClaim(a, &bp.sets.items[1], 0),
        .swap_claims_own => {
            const s = &bp.sets.items[0];
            // swap claims 0 and last (values/weights/points), keeping point order canonical is not attempted
            const l = s.w.len - 1;
            std.mem.swap(u32, &s.w[0], &s.w[l]);
            std.mem.swap(u32, &s.point_of[0], &s.point_of[l]);
            std.mem.swap(QM31, &s.values[0], &s.values[l]);
        },
    }
    var batch = try bp.finish();
    defer batch.deinit(a);
    return .{
        serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &batch.shared, 0),
        serve.verifyRequest(a, pc, q1.st, key, &batch.requests[1], &batch.shared, 1),
    };
}

test "recheck SERVE-1: original + variants" {
    const a = testing.allocator;
    inline for (@typeInfo(Mut).@"enum".fields) |fld| {
        const r = try serveMut(a, @field(Mut, fld.name));
        say("SERVE-1 {s}: v0={any} v1={any}", .{ fld.name, r[0], r[1] });
    }
}

test "recheck SERVE-2: original (explicit testSalt) + default salt variant" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10);
    defer r1.deinit(a);
    // original: with known testSalt the guess confirms (by design, test-only API)
    {
        const reqs = [_]serve.Request{ r0.request(serve.testSalt(0)), r1.request(serve.testSalt(1)) };
        var batch = try serve.proveRequests(a, &fx.pool, pc, &fx.ws, &reqs, null);
        defer batch.deinit(a);
        var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
        defer bp.deinit();
        var tm: proto.Timings = .{};
        try bp.add(r1.request(serve.testSalt(1)), &tm);
        say("SERVE-2 original (explicit testSalt): guess confirms = {}", .{std.mem.eql(u8, &bp.sets.items[0].digest, &batch.shared.requests[1].digest)});
    }
    // default: the victim's request uses null salt; attacker tries every
    // salt it could know (testSalt(0..64), all-zero)
    {
        const reqs = [_]serve.Request{ r0.request(null), r1.request(null) };
        var batch = try serve.proveRequests(a, &fx.pool, pc, &fx.ws, &reqs, null);
        defer batch.deinit(a);
        const seen = batch.shared.requests[1].digest;
        var hit = false;
        for (0..65) |s| {
            var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
            defer bp.deinit();
            var tm: proto.Timings = .{};
            const salt: [32]u8 = if (s == 64) [_]u8{0} ** 32 else serve.testSalt(s);
            try bp.add(r1.request(salt), &tm);
            hit = hit or std.mem.eql(u8, &bp.sets.items[0].digest, &seen);
        }
        const s0 = batch.requests[0].salt;
        const s1 = batch.requests[1].salt;
        say("SERVE-2 default: hit={} salts distinct={} nonzero={}", .{ hit, !std.mem.eql(u8, &s0, &s1), !std.mem.allEqual(u8, &s1, 0) });
        try testing.expect(!hit);
        try testing.expect(!std.mem.eql(u8, &s0, &s1));
        // both still verify
        const key = proto.weightKey(&fx.ws);
        try serve.verifyRequest(a, pc, reqs[0].st, key, &batch.requests[0], &batch.shared, 0);
        try serve.verifyRequest(a, pc, reqs[1].st, key, &batch.requests[1], &batch.shared, 1);
    }
}

test "recheck SERVE-3: original + cap variants" {
    const a = testing.allocator;
    var pc = tlConfig();
    var fx: Fx = undefined;
    try fx.init(a, &pc);
    defer fx.deinit(a);
    const key = proto.weightKey(&fx.ws);
    var r0 = try Req.init(a, &fx, 9);
    defer r0.deinit(a);
    var r1 = try Req.init(a, &fx, 10);
    defer r1.deinit(a);
    const q0 = r0.request(serve.testSalt(0));
    var bp = serve.BatchProver.init(a, &fx.pool, pc, &fx.ws);
    defer bp.deinit();
    var tm: proto.Timings = .{};
    try bp.add(q0, &tm);
    try bp.add(r1.request(serve.testSalt(77)), &tm);
    bp.sets.items[1].digest = [_]u8{0xAB} ** 32;
    var batch = try bp.finish();
    defer batch.deinit(a);
    const orig = serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &batch.shared, 0);
    say("SERVE-3 original fabricated true slot: v0={any} (by design, documented)", .{orig});
    // variant 1: slot 1 with exactly cap+1 claims (all duplicate of claim 0)
    const cap = serve.max_claims_per_weight * key.infos.len;
    const n = cap + 1;
    const w = try a.alloc(u32, n);
    defer a.free(w);
    const po = try a.alloc(u32, n);
    defer a.free(po);
    const vs = try a.alloc(QM31, n);
    defer a.free(vs);
    const s1 = batch.shared.requests[1];
    for (0..n) |i| {
        w[i] = s1.w[0];
        po[i] = 0;
        vs[i] = s1.values[0];
    }
    var big = s1;
    big.w = w;
    big.point_of = po;
    big.values = vs;
    big.points = s1.points[0..1];
    var slots = [_]serve.ClaimSet{ batch.shared.requests[0], big };
    var sh = batch.shared;
    sh.requests = &slots;
    const v1 = serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &sh, 0);
    // exactly cap claims (all duplicates): passes the shape cap? (then fails reduction)
    var at = big;
    at.w = w[0..cap];
    at.point_of = po[0..cap];
    at.values = vs[0..cap];
    slots[1] = at;
    const v2 = serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &sh, 0);
    // variant 2: max_slots + 1 empty slots
    const many = try a.alloc(serve.ClaimSet, serve.max_slots + 1);
    defer a.free(many);
    for (many) |*s| s.* = .{ .digest = [_]u8{0} ** 32, .points = &.{}, .w = &.{}, .point_of = &.{}, .values = &.{} };
    many[0] = batch.shared.requests[0];
    var sh2 = batch.shared;
    sh2.requests = many;
    const v3 = serve.verifyRequest(a, pc, q0.st, key, &batch.requests[0], &sh2, 0);
    say("SERVE-3 variants: cap+1 claims={any}; cap dup claims={any}; max_slots+1={any}", .{ v1, v2, v3 });
    try testing.expectError(error.ProofShape, v1);
    try testing.expectError(error.ProofShape, v3);
}
