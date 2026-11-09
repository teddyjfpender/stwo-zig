//! Adversarial review tests: commitments (pcs.zig, pcs2.zig, weight_key.zig).
//! Copied from the review worktree (rev-pcs); the tests that demonstrated an
//! attack (5, 8, 9) now assert that it is rejected (PCS-1, PCS-2, PCS-3), and
//! regression tests for PCS-4, P7 and PROTO-6 are added at the end.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const pcs2 = @import("pcs2.zig");
const proto = @import("protocol.zig");
const wk = @import("weight_key.zig");
const model = @import("model.zig");
const Transcript = @import("transcript.zig").Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const Hash = [32]u8;

fn rq(prng: *std.Random.DefaultPrng) QM31 {
    const r = prng.random();
    return QM31.fromU32Unchecked(r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P));
}

// ---------------------------------------------------------------------------
// 1. Circle-basis tensor factorisation vs the real encoder, QM31 messages,
//    many (log_c, log_blowup) pairs including the tiny inner shapes.
test "review: circleFactors/evalCoeffs/tensorEvalAt match encodeSecure for all j" {
    const a = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(99);
    for ([_]u32{ 1, 2, 3, 4, 6 }) |log_c| for ([_]u32{ 1, 2, 3 }) |lb| {
        var tw = try pcs.Twiddles.init(a, log_c + lb);
        defer tw.deinit(a);
        const C = @as(usize, 1) << @intCast(log_c);
        const u = try a.alloc(QM31, C);
        defer a.free(u);
        for (u) |*x| x.* = rq(&prng);
        const enc = try pcs.encodeSecure(a, &tw, u);
        defer a.free(enc);
        const fac = try a.alloc(M31, log_c);
        defer a.free(fac);
        const r = try a.alloc(QM31, log_c);
        defer a.free(r);
        for (r) |*x| x.* = rq(&prng);
        for (0..enc.len) |j| {
            pcs2.circleFactors(log_c + lb, j, log_c, fac);
            try std.testing.expect((try pcs2.evalCoeffs(a, u, fac)).eql(enc[j]));
            const tt = try pcs2.tensorTable(a, fac);
            defer a.free(tt);
            const tq = try a.alloc(QM31, C);
            defer a.free(tq);
            for (tq, tt) |*o, t| o.* = QM31.fromBase(t);
            try std.testing.expect((try f.mleEval(a, tq, r)).eql(pcs2.tensorEvalAt(fac, r)));
        }
    };
}

// ---------------------------------------------------------------------------
// 2. Multiproof: malformed leaf sets and sibling lists.
test "review: multiproof rejects duplicate, unsorted, out-of-range, extra and missing siblings" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lc = 4;
    var tw = try pcs.Twiddles.init(a, lc + 1);
    defer tw.deinit(a);
    var data: [4 << lc]i8 = undefined;
    for (&data, 0..) |*d, i| d.* = @intCast(@as(i32, @intCast(i % 200)) - 100);
    var com = try pcs.commit(i8, a, &pool, &tw, .{ .data = &data, .log_rows = 2, .log_cols = lc }, 1);
    defer com.deinit(a);
    const L = lc + 1;
    const uq = [_]usize{ 1, 2, 3, 30 };
    const sibs = try pcs2.multiproof(a, com.tree, &uq);
    defer a.free(sibs);
    var hs: [4]Hash = undefined;
    for (uq, &hs) |j, *h| h.* = pcs.hashColumn(com.column(j));
    try std.testing.expect(try pcs2.verifyMultiproof(a, com.root(), L, &uq, &hs, sibs));
    // duplicate leaf
    {
        const d = [_]usize{ 1, 2, 2, 30 };
        var dh = hs;
        dh[2] = hs[1];
        try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &d, &dh, sibs));
    }
    // unsorted
    {
        const d = [_]usize{ 2, 1, 3, 30 };
        var dh = hs;
        dh[0] = hs[1];
        dh[1] = hs[0];
        try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &d, &dh, sibs));
    }
    // out of range (index aliasing mod 2^L)
    {
        const d = [_]usize{ 1, 2, 3, 30 + (1 << L) };
        try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &d, &hs, sibs));
    }
    // extra trailing sibling
    {
        const ex = try a.alloc(Hash, sibs.len + 1);
        defer a.free(ex);
        @memcpy(ex[0..sibs.len], sibs);
        ex[sibs.len] = sibs[0];
        try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &uq, &hs, ex));
    }
    // missing sibling
    try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &uq, &hs, sibs[1..]));
    // empty leaves with/without siblings
    try std.testing.expect(!try pcs2.verifyMultiproof(a, com.root(), L, &.{}, &.{}, sibs));
    // all leaves: zero siblings needed
    {
        var all: [1 << L]usize = undefined;
        var ah: [1 << L]Hash = undefined;
        for (&all, &ah, 0..) |*p, *h, j| {
            p.* = j;
            h.* = pcs.hashColumn(com.column(j));
        }
        const s2 = try pcs2.multiproof(a, com.tree, &all);
        defer a.free(s2);
        try std.testing.expectEqual(@as(usize, 0), s2.len);
        try std.testing.expect(try pcs2.verifyMultiproof(a, com.root(), L, &all, &ah, s2));
    }
}

// ---------------------------------------------------------------------------
// 3. rows_used: rows past rows_used are zero in the verifier's view, even if
//    the prover's matrix has data there.
test "review: rows_used truncation - garbage past rows_used is not committed, claims on it rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 5;
    const R = 1 << lr;
    const C = 1 << lc;
    const ru: usize = 5;
    var prng = std.Random.DefaultPrng.init(17);
    const data = try a.alloc(i8, R * C);
    defer a.free(data);
    for (data) |*d| d.* = prng.random().int(i8);
    for (data[ru * C ..]) |*d| if (d.* == 0) {
        d.* = 1;
    }; // nonzero garbage past rows_used
    const m = pcs.Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc, .rows_used = ru };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    const params = pcs.Params{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 };
    var pt: [lr + lc]QM31 = undefined;
    for (&pt) |*x| x.* = rq(&prng);
    const full = try a.alloc(i32, R * C);
    defer a.free(full);
    for (data, full) |d, *x| x.* = d;
    const v_garbage = try f.mleEvalI32(a, full, &pt);
    @memset(full[ru * C ..], 0);
    const v_trunc = try f.mleEvalI32(a, full, &pt);
    const shape = pcs.Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2, .rows_used = ru };
    for ([_]bool{ true, false }) |prox| {
        // honest (truncated) claim accepted
        {
            const cl = [_]pcs.Claim{.{ .point = &pt, .value = v_trunc }};
            const gs = [_]pcs.Group{.{ .claims = &cl }};
            var tp = Transcript.initDomain("r");
            var pr = try pcs.open(i8, a, &pool, &tp, params, &com, m, &gs, prox);
            defer pr.deinit(a);
            var tv = Transcript.initDomain("r");
            try pcs.verifyOpening(a, &tv, params, &tw, shape, com.root(), &gs, prox, pr);
            // verifier with the wrong rows_used (full) rejects on shape
            var tv2 = Transcript.initDomain("r");
            try std.testing.expectError(error.OpeningShape, pcs.verifyOpening(a, &tv2, params, &tw, .{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 }, com.root(), &gs, prox, pr));
        }
        // claim including the garbage rows rejected
        {
            const cl = [_]pcs.Claim{.{ .point = &pt, .value = v_garbage }};
            const gs = [_]pcs.Group{.{ .claims = &cl }};
            var tp = Transcript.initDomain("r");
            var pr = try pcs.open(i8, a, &pool, &tp, params, &com, m, &gs, prox);
            defer pr.deinit(a);
            var tv = Transcript.initDomain("r");
            try std.testing.expectError(error.OpeningEvalMismatch, pcs.verifyOpening(a, &tv, params, &tw, shape, com.root(), &gs, prox, pr));
        }
    }
    // pcs2 at depth 1: garbage claim rejected, truncated accepted
    const p2 = pcs2.Params{ .outer = params, .inner = .{ .log_blowup = 2, .n_queries = 10, .pow_bits = 1 }, .depth = 1 };
    for ([_]QM31{ v_trunc, v_garbage }, 0..) |v, which| {
        const cl = [_]pcs.Claim{.{ .point = &pt, .value = v }};
        const gs = [_]pcs.Group{.{ .claims = &cl }};
        var tp = Transcript.initDomain("r2");
        var pr = try pcs2.open(i8, a, &pool, &tp, p2, &com, m, &gs, false);
        defer pr.deinit(a);
        var tv = Transcript.initDomain("r2");
        const res = pcs2.verify(a, &tv, p2, shape, com.root(), &gs, false, pr);
        if (which == 0) try res else try std.testing.expect(std.meta.isError(res));
    }
}

// ---------------------------------------------------------------------------
// 4. Cheating prover on flat Ligero, consistency-only (as for per-batch weight
//    openings): sends a combined row that satisfies the evaluation check for a
//    FALSE value. Must fail column consistency.
test "review: flat pcs cheater with adjusted combined row is rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 5;
    const R = 1 << lr;
    const C = 1 << lc;
    var prng = std.Random.DefaultPrng.init(23);
    const data = try a.alloc(i8, R * C);
    defer a.free(data);
    for (data) |*d| d.* = prng.random().int(i8);
    const m = pcs.Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    const params = pcs.Params{ .log_blowup = 2, .n_queries = 16, .pow_bits = 1 };
    var pt: [lr + lc]QM31 = undefined;
    for (&pt) |*x| x.* = rq(&prng);
    const ints = try a.alloc(i32, R * C);
    defer a.free(ints);
    for (data, ints) |d, *x| x.* = d;
    const v_true = try f.mleEvalI32(a, ints, &pt);
    const v_false = v_true.add(QM31.one());
    const cl = [_]pcs.Claim{.{ .point = &pt, .value = v_false }};
    const gs = [_]pcs.Group{.{ .claims = &cl }};

    // cheating prover: replicate pcs.open (no proximity) with an adjusted row
    var tp = Transcript.initDomain("cheat");
    tp.mixFelt(v_false);
    var gamma: [1]QM31 = undefined;
    tp.drawN(&gamma);
    const coeff = try f.eqTable(a, pt[0..lr], gamma[0]);
    defer a.free(coeff);
    const cv = [_][]const QM31{coeff};
    const rows = try pcs.combineRows(i8, a, &pool, m, &cv, 7);
    const eqc = try f.eqTable(a, pt[lr..], QM31.one());
    defer a.free(eqc);
    // u'[0] += gamma (v' - v) / eqc[0]
    rows[0][0] = rows[0][0].add(gamma[0].mul(v_false.sub(v_true)).mul(try eqc[0].inv()));
    for (rows) |r| tp.mixFelts(r);
    const nonce = tp.grind(params.pow_bits);
    const idx = try a.alloc(usize, params.n_queries);
    defer a.free(idx);
    tp.drawIndices(com.logExt(), idx);
    const cols = try a.alloc(pcs.OpenedColumn, params.n_queries);
    for (idx, 0..) |j, q| {
        const path = try a.alloc(Hash, com.logExt());
        com.tree.path(path, j);
        cols[q] = .{ .index = j, .values = try a.dupe(M31, com.column(j)), .path = path };
    }
    var pr = pcs.OpeningProof{ .rows = rows, .pow_nonce = nonce, .columns = cols };
    defer pr.deinit(a);
    var tv = Transcript.initDomain("cheat");
    try std.testing.expectError(error.OpeningColumnMismatch, pcs.verifyOpening(a, &tv, params, &tw, .{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 }, com.root(), &gs, false, pr));
}

// ---------------------------------------------------------------------------
// 5. (PCS-2 / PROTO-5) Weight key layout binding: a key whose offsets are
//    swapped (same root, same shapes) is rejected by the key verifier and by
//    the batch verifier, and malformed keys give errors, not panics.
test "review: weight key binds tensor offsets - swapped layout rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 3, .log_d = 4, .log_f = 5, .fused = false };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 4, .witness_log_cols_max = 6, .gkr_threads = 1 };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 300 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    var kp = try wk.prove(a, &pool, pc, &ws);
    defer kp.deinit(a);
    try wk.verify(a, pc, proto.weightKey(&ws), &kp);

    // same commitment, layout with W0 and W1 (same shape) swapped
    const sw_off = try a.dupe(usize, ws.offsets);
    defer a.free(sw_off);
    std.mem.swap(usize, &sw_off[0], &sw_off[1]);
    try std.testing.expect(sw_off[0] != sw_off[1]);
    var ws2 = ws; // shallow: same table, same commitment
    ws2.offsets = sw_off;
    const key2 = proto.weightKey(&ws2);
    try std.testing.expect(std.mem.eql(u8, &key2.root, &proto.weightKey(&ws).root));
    try std.testing.expectError(error.WeightKeyShape, wk.verify(a, pc, key2, &kp));

    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 5);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws2, cfg, x);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    // the prover refuses the non-canonical layout as well
    try std.testing.expectError(error.WeightKeyShape, proto.prove(a, &pool, pc, built.statement(), &ws2, wview, &tm));
    var built_h = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built_h.deinit(a);
    const hview = try a.alloc([]const i32, built_h.witness.len);
    defer a.free(hview);
    for (built_h.witness, 0..) |w, i| hview[i] = w;
    var proof = try proto.prove(a, &pool, pc, built_h.statement(), &ws, hview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, built_h.statement(), proto.weightKey(&ws), &proof);
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, built_h.statement(), key2, &proof));

    // malformed keys: errors, never panics
    const st = built_h.statement();
    var k = proto.weightKey(&ws);
    k.offsets = ws.offsets[0..2];
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    k = proto.weightKey(&ws);
    k.infos = winfos[0..2];
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    k = proto.weightKey(&ws);
    k.log_rows += 1;
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    k = proto.weightKey(&ws);
    k.log_cols = k.log_rows + k.log_cols + 1;
    k.log_rows = 0;
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    k = proto.weightKey(&ws);
    k.rows_used += 1;
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    const odd = try a.dupe(usize, ws.offsets);
    defer a.free(odd);
    odd[2] += 1; // misaligned
    k = proto.weightKey(&ws);
    k.offsets = odd;
    try std.testing.expectError(error.WeightKeyShape, proto.verify(a, pc, st, k, &proof));
    // a key with another OOD answer is a different key: the batch rejects it
    k = proto.weightKey(&ws);
    k.ood_value = k.ood_value.add(QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, k, &proof)));
    try std.testing.expect(std.meta.isError(wk.verify(a, pc, k, &kp)));
}

// ---------------------------------------------------------------------------
// 6. Binding beyond unique decoding (no OOD sample). A committer builds a
//    hybrid table whose encoded columns equal Enc(M1) on a set A (half the
//    positions) and Enc(M2) elsewhere. With proximity, an M1-opening passes
//    when all t queries land in A; a later consistency-only opening of the
//    SAME root as M2 (M2 holds an out-of-range weight) passes when all land
//    outside A. Per-opening acceptance is ~(1/2)^t (up to ((1+rho)/2)^t with
//    a vanishing difference), far above the rho^t that
//    `Params.conjecturedBits` (= t*log_blowup + pow) assumes. This is a
//    property of bare consistency openings and stays true; the protocol-level
//    fix (key OOD + per-batch proximity) is tested end to end in 9.
fn buildTree(a: std.mem.Allocator, enc: []const M31, R: usize, E: usize) !pcs.Merkle {
    const nodes = try a.alloc(Hash, 2 * E);
    for (0..E) |j| nodes[E + j] = pcs.hashColumn(enc[j * R .. (j + 1) * R]);
    var i = E - 1;
    while (i >= 1) : (i -= 1) nodes[i] = pcs.hashNode(nodes[2 * i], nodes[2 * i + 1]);
    return .{ .nodes = nodes, .n_leaves = E };
}

test "review: pcs level - without an OOD claim a hybrid table opens as two matrices (why weights carry the key OOD)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 2;
    const lc = 4;
    const lb = 2;
    const R = 1 << lr;
    const C = 1 << lc;
    const E = C << lb;
    const t = 4;
    const params = pcs.Params{ .log_blowup = lb, .n_queries = t, .pow_bits = 0 };
    var prng = std.Random.DefaultPrng.init(41);
    const m1 = try a.alloc(i32, R * C);
    defer a.free(m1);
    for (m1) |*x| x.* = prng.random().intRangeAtMost(i32, -128, 127);
    const m2 = try a.dupe(i32, m1);
    defer a.free(m2);
    m2[5] = 1000; // out of int8 range
    const M1 = pcs.Matrix(i32){ .data = m1, .log_rows = lr, .log_cols = lc };
    const M2 = pcs.Matrix(i32){ .data = m2, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    var c1 = try pcs.commit(i32, a, &pool, &tw, M1, lb);
    defer c1.deinit(a);
    var c2 = try pcs.commit(i32, a, &pool, &tw, M2, lb);
    defer c2.deinit(a);
    const shape = pcs.Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = lb };
    var z1: [lr + lc]QM31 = undefined;
    var z2: [lr + lc]QM31 = undefined;
    for (&z1) |*x| x.* = rq(&prng);
    for (&z2) |*x| x.* = rq(&prng);
    const v1 = try f.mleEvalI32(a, m1, &z1);
    const v2 = try f.mleEvalI32(a, m2, &z2);
    try std.testing.expect(!v2.eql(try f.mleEvalI32(a, m1, &z2))); // a false claim about M1

    const n_trials = 512;
    var acc_m2: usize = 0;
    var both: usize = 0;
    const enc = try a.alloc(M31, R * E);
    defer a.free(enc);
    for (0..n_trials) |trial| {
        // random half A
        var inA: [E]bool = undefined;
        for (&inA) |*b| b.* = prng.random().boolean();
        for (0..E) |j| @memcpy(enc[j * R ..][0..R], if (inA[j]) c1.column(j) else c2.column(j));
        var tree = try buildTree(a, enc, R, E);
        defer tree.deinit(a);
        const hy = pcs.Committed{ .log_rows = lr, .log_cols = lc, .log_blowup = lb, .rows_used = R, .enc = enc, .tree = tree };
        var d: [8]u8 = undefined;
        std.mem.writeInt(u64, &d, trial, .little);
        // "key proof": M1 opening with proximity
        const cl1 = [_]pcs.Claim{.{ .point = &z1, .value = v1 }};
        const g1 = [_]pcs.Group{.{ .claims = &cl1 }};
        var tp1 = Transcript.initDomain("key");
        tp1.mixDigest(hy.root());
        var p1 = try pcs.open(i32, a, &pool, &tp1, params, &hy, M1, &g1, true);
        defer p1.deinit(a);
        var tv1 = Transcript.initDomain("key");
        tv1.mixDigest(hy.root());
        const ok1 = !std.meta.isError(pcs.verifyOpening(a, &tv1, params, &tw, shape, hy.root(), &g1, true, p1));
        // "batch": M2 opening, consistency only, fresh transcript per trial
        const cl2 = [_]pcs.Claim{.{ .point = &z2, .value = v2 }};
        const g2 = [_]pcs.Group{.{ .claims = &cl2 }};
        var tp2 = Transcript.initDomain("batch");
        tp2.mixDigest(hy.root());
        var p2 = try pcs.open(i32, a, &pool, &tp2, params, &hy, M2, &g2, false);
        defer p2.deinit(a);
        var tv2 = Transcript.initDomain("batch");
        tv2.mixDigest(hy.root());
        const ok2 = !std.meta.isError(pcs.verifyOpening(a, &tv2, params, &tw, shape, hy.root(), &g2, false, p2));
        acc_m2 += @intFromBool(ok2);
        both += @intFromBool(ok1 and ok2);
    }
    std.debug.print("\n[review hybrid] t={d} rho=1/{d}: M2 (false) opening accepted {d}/{d}; key(M1)+batch(M2) both accepted {d}/{d}; conjectured per-opening bound rho^t*n = {d:.1}\n", .{ t, 1 << lb, acc_m2, n_trials, both, n_trials, @as(f64, n_trials) / 256.0 });
    // expected ~ n/16 = 32 vs conjectured n/256 = 2
    try std.testing.expect(acc_m2 > 10);
    try std.testing.expect(both > 0);
}

// ---------------------------------------------------------------------------
// 7. pcs2: limb values tampered by a vector in the kernel of
//    (v_0..v_3) -> sum_c e_c v_c pass the level's sumcheck final check; the
//    next level must still reject them.
test "review: pcs2 limb_vals kernel tamper passes sumcheck final but is rejected by the next level" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 6;
    const R = 1 << lr;
    const C = 1 << lc;
    var prng = std.Random.DefaultPrng.init(5);
    const data = try a.alloc(i8, R * C);
    defer a.free(data);
    for (data) |*d| d.* = prng.random().int(i8);
    const m = pcs.Matrix(i8){ .data = data, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    var pt: [lr + lc]QM31 = undefined;
    for (&pt) |*x| x.* = rq(&prng);
    const ints = try a.alloc(i32, R * C);
    defer a.free(ints);
    for (data, ints) |d, *x| x.* = d;
    const v = try f.mleEvalI32(a, ints, &pt);
    const cl = [_]pcs.Claim{.{ .point = &pt, .value = v }};
    const gs = [_]pcs.Group{.{ .claims = &cl }};
    const p2 = pcs2.Params{ .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 0 }, .inner = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 0 }, .depth = 2 };
    const shape = pcs.Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 };
    for ([_]bool{ true, false }) |prox| {
        var tp = Transcript.initDomain("k");
        var pr = try pcs2.open(i8, a, &pool, &tp, p2, &com, m, &gs, prox);
        defer pr.deinit(a);
        var tv = Transcript.initDomain("k");
        try pcs2.verify(a, &tv, p2, shape, com.root(), &gs, prox, pr);
        const e0 = f.fromLimbs(.{ 1, 0, 0, 0 });
        const e1 = f.fromLimbs(.{ 0, 1, 0, 0 });
        const s = rq(&prng);
        for (0..2) |li| {
            const lv = &pr.levels[li].limb_vals;
            const before = lv.*;
            lv[0] = lv[0].add(e1.mul(s));
            lv[1] = lv[1].sub(e0.mul(s));
            var ua = QM31.zero();
            var ub = QM31.zero();
            for (before, lv.*, 0..) |b, x, c| {
                var l = [_]u32{ 0, 0, 0, 0 };
                l[c] = 1;
                ua = ua.add(f.fromLimbs(l).mul(b));
                ub = ub.add(f.fromLimbs(l).mul(x));
            }
            try std.testing.expect(ua.eql(ub)); // invisible to the final check
            var t2 = Transcript.initDomain("k");
            try std.testing.expect(std.meta.isError(pcs2.verify(a, &t2, p2, shape, com.root(), &gs, prox, pr)));
            lv.* = before;
        }
    }
}

// ---------------------------------------------------------------------------
// 8. (PCS-3) Flat PCS with Config.weight_log_cols larger than some matmul's
//    log N: claims are grouped by column point, so the honest proof verifies.
test "review: flat weight opening with weight_log_cols > min log N verifies" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 3, .log_d = 4, .log_f = 5, .fused = false };
    // log N of the down projection is log_d = 4 < 5
    for ([_]bool{ true, false }) |wprox| {
        var pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 5, .witness_log_cols_max = 6, .gkr_threads = 1 };
        pc.weight_proximity = wprox;
        const winfos = model.mlpWeightInfos(cfg);
        var wdata: [3][]i8 = undefined;
        for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 400 + i, -8, 7);
        defer for (wdata) |w| a.free(w);
        const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
        var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
        defer ws.deinit(a);
        const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 6);
        defer a.free(x);
        var built = try model.buildMlp(a, &pool, &ws, cfg, x);
        defer built.deinit(a);
        const wview = try a.alloc([]const i32, built.witness.len);
        defer a.free(wview);
        for (built.witness, 0..) |w, i| wview[i] = w;
        var tm: proto.Timings = .{};
        var proof = try proto.prove(a, &pool, pc, built.statement(), &ws, wview, &tm);
        defer proof.deinit(a);
        try proto.verify(a, pc, built.statement(), proto.weightKey(&ws), &proof);
    }
}

// ---------------------------------------------------------------------------
// 9. (PCS-1) End-to-end version of 6: the review found a weight key proof for
//    M1 and a batch proof for M2 (down projection negated), both accepted
//    under one root, after 8 hybrid seeds at t = 2 (flat PCS, no OOD). Now the
//    key fixes an OOD answer v_ood = M1~(z_ood), which every batch's weight
//    opening must also satisfy; a batch prover holding M2 cannot (the OOD
//    group's row is checked both against v_ood and against the committed
//    columns, together with the M2 matmul claims). Flat and pcs2, with and
//    without per-batch proximity: no seed is accepted.
fn hybridAttack(pc: proto.Config, seeds: usize) !usize {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 3, .log_d = 4, .log_f = 5, .fused = false };
    const winfos = model.mlpWeightInfos(cfg);
    var w1: [3][]i8 = undefined;
    for (&w1, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 500 + i, -8, 7);
    defer for (w1) |w| a.free(w);
    var w2: [3][]i8 = undefined;
    for (&w2, 0..) |*w, i| w.* = try a.dupe(i8, w1[i]);
    defer for (w2) |w| a.free(w);
    for (w2[2]) |*x| x.* = -x.*; // M2: down projection negated
    var ws1 = try proto.commitWeights(a, &pool, pc, &winfos, &.{ w1[0], w1[1], w1[2] });
    defer ws1.deinit(a);
    var ws2 = try proto.commitWeights(a, &pool, pc, &winfos, &.{ w2[0], w2[1], w2[2] });
    defer ws2.deinit(a);
    const RU = ws1.com.rows_used;
    const E = ws1.com.nCols() << @intCast(ws1.com.log_blowup);
    const enc = try a.alloc(M31, RU * E);
    defer a.free(enc);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 8);
    defer a.free(x);
    var prng = std.Random.DefaultPrng.init(77);
    var key_ok: usize = 0;
    var accepted: usize = 0;
    for (0..seeds) |_| {
        for (0..E) |j| @memcpy(enc[j * RU ..][0..RU], if (prng.random().boolean()) ws1.com.column(j) else ws2.com.column(j));
        var tree = try buildTree(a, enc, RU, E);
        defer tree.deinit(a);
        const hy = pcs.Committed{ .log_rows = ws1.com.log_rows, .log_cols = ws1.com.log_cols, .log_blowup = ws1.com.log_blowup, .rows_used = RU, .enc = enc, .tree = tree };
        var wsA = ws1;
        wsA.com = hy;
        // the OOD point depends on the root: recompute M1's answer for it
        const z = try proto.weightOodPoint(a, proto.weightKey(&wsA));
        defer a.free(z);
        wsA.ood_value = try proto.tableMleI8(a, &pool, wsA.tableMatrix(), z);
        var kp = try wk.prove(a, &pool, pc, &wsA);
        defer kp.deinit(a);
        const keyA = proto.weightKey(&wsA);
        if (std.meta.isError(wk.verify(a, pc, keyA, &kp))) continue;
        key_ok += 1;
        // the batch prover holds M2 but must present the certified key
        var wsB = ws2;
        wsB.com = hy;
        wsB.ood_value = keyA.ood_value;
        var built = try model.buildMlp(a, &pool, &wsB, cfg, x);
        defer built.deinit(a);
        const wview = try a.alloc([]const i32, built.witness.len);
        defer a.free(wview);
        for (built.witness, 0..) |w, i| wview[i] = w;
        var tm: proto.Timings = .{};
        var proof = try proto.prove(a, &pool, pc, built.statement(), &wsB, wview, &tm);
        defer proof.deinit(a);
        if (std.meta.isError(proto.verify(a, pc, built.statement(), keyA, &proof))) continue;
        accepted += 1;
    }
    std.debug.print("\n[review e2e hybrid] two_level={} weight_proximity={}: key(M1) accepted {d}/{d}, key(M1)+batch(M2) accepted {d}\n", .{ pc.two_level != null, pc.weight_proximity, key_ok, seeds, accepted });
    try std.testing.expect(key_ok > 0); // the key half of the attack still works at t = 2
    return accepted;
}

test "review: end-to-end - key proof certifies M1, batch proof with M2 under the same root is rejected" {
    const flat = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 2, .pow_bits = 0 }, .weight_log_cols = 4, .witness_log_cols_max = 6, .gkr_threads = 1 };
    var two = flat;
    two.two_level = .{ .outer = flat.pcs, .inner = .{ .log_blowup = 2, .n_queries = 2, .pow_bits = 0 }, .depth = 1 };
    for ([_]proto.Config{ flat, two }) |base| for ([_]bool{ true, false }) |wprox| {
        var pc = base;
        pc.weight_proximity = wprox;
        try std.testing.expectEqual(@as(usize, 0), try hybridAttack(pc, 40));
    };
}

// ---------------------------------------------------------------------------
// 10. (PCS-4) pcs.verifyOpening rejects a claim point of the wrong arity
//     with an error before slicing it (it used to panic in groupCoeffs).
test "review: flat verifyOpening rejects short and long claim points" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 4;
    var data: [1 << (lr + lc)]i8 = undefined;
    for (&data, 0..) |*d, i| d.* = @intCast(@as(i32, @intCast(i % 100)) - 50);
    const m = pcs.Matrix(i8){ .data = &data, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    const params = pcs.Params{ .log_blowup = 2, .n_queries = 8, .pow_bits = 0 };
    var prng = std.Random.DefaultPrng.init(3);
    var pt: [lr + lc]QM31 = undefined;
    for (&pt) |*x| x.* = rq(&prng);
    const ints = try a.alloc(i32, data.len);
    defer a.free(ints);
    for (&data, ints) |d, *x| x.* = d;
    const cl = [_]pcs.Claim{.{ .point = &pt, .value = try f.mleEvalI32(a, ints, &pt) }};
    const gs = [_]pcs.Group{.{ .claims = &cl }};
    var tp = Transcript.initDomain("p4");
    var pr = try pcs.open(i8, a, &pool, &tp, params, &com, m, &gs, true);
    defer pr.deinit(a);
    const shape = pcs.Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 };
    var tv = Transcript.initDomain("p4");
    try pcs.verifyOpening(a, &tv, params, &tw, shape, com.root(), &gs, true, pr);
    for ([_]usize{ 0, 1, lr - 1, lr + lc - 1 }) |len| {
        const bad = [_]pcs.Claim{.{ .point = pt[0..len], .value = cl[0].value }};
        // a second, well-formed group first: the check covers every group
        const bgs = [_]pcs.Group{ .{ .claims = &cl }, .{ .claims = &bad } };
        var t2 = Transcript.initDomain("p4");
        try std.testing.expectError(error.OpeningShape, pcs.verifyOpening(a, &t2, params, &tw, shape, com.root(), &bgs, true, pr));
    }
    var long: [lr + lc + 1]QM31 = undefined;
    @memcpy(long[0 .. lr + lc], &pt);
    long[lr + lc] = QM31.one();
    const lcl = [_]pcs.Claim{.{ .point = &long, .value = cl[0].value }};
    const lgs = [_]pcs.Group{.{ .claims = &lcl }};
    var t3 = Transcript.initDomain("p4");
    try std.testing.expectError(error.OpeningShape, pcs.verifyOpening(a, &t3, params, &tw, shape, com.root(), &lgs, true, pr));
}

// ---------------------------------------------------------------------------
// 11. (P7) Weight-key LogUp needs 2^n + 256 < p: a key of 2^31 weights is
//     refused before the histogram check (which, with >= p keys, could be met
//     by adding p to an in-range bucket).
test "review: weight key with >= p LogUp fractions is rejected" {
    try wk.checkCount(30);
    try std.testing.expectError(error.LogUpCountAboveP, wk.checkCount(31));
    try std.testing.expectError(error.LogUpCountAboveP, wk.checkCount(40));
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 0 }, .weight_log_cols = 4, .gkr_threads = 1 };
    // a key that claims a 2^31-entry table: one tensor of 2^31 weights
    const big = [_]proto.TensorInfo{proto.TensorInfo.mat(15, 16)};
    var key = proto.WeightKey{ .root = [_]u8{0} ** 32, .infos = &big, .offsets = &.{0}, .log_rows = 21, .log_cols = 10, .rows_used = 1 << 21, .ood_value = QM31.zero() };
    var hist = [_]u32{0} ** 256;
    hist[128] = 1 << 31; // integer total 2^31 = 2^n_vars
    // a well-formed small key proof to borrow the other fields from
    const infos = [_]proto.TensorInfo{proto.TensorInfo.mat(3, 4)};
    var w0: [1 << 7]i8 = [_]i8{1} ** (1 << 7);
    const wv = [_][]const i8{&w0};
    var ws = try proto.commitWeights(a, &pool, pc, &infos, &wv);
    defer ws.deinit(a);
    var kp = try wk.prove(a, &pool, pc, &ws);
    defer kp.deinit(a);
    kp.histogram = hist;
    try std.testing.expectError(error.LogUpCountAboveP, wk.verify(a, pc, key, &kp));
    key.log_rows = 20; // 2^30 + 256 < p is allowed (fails later on the layout)
    try std.testing.expect(wk.verify(a, pc, key, &kp) != error.LogUpCountAboveP);
}

// ---------------------------------------------------------------------------
// 12. (PROTO-6) Request LogUp: a relation with >= p fractions (here a range8
//     key on a 2^31-entry tensor) is refused by the statement check that
//     prove and verify both run.
test "review: request LogUp relation with >= p fractions is rejected" {
    const a = std.testing.allocator;
    const ok = [_]proto.TensorInfo{proto.TensorInfo.vec(30)};
    const big = [_]proto.TensorInfo{proto.TensorInfo.vec(31)};
    const two = [_]proto.TensorInfo{ proto.TensorInfo.vec(30), proto.TensorInfo.vec(30) };
    const ops1 = [_]proto.Op{.{ .range8 = .{ .in = 0 } }};
    const ops2 = [_]proto.Op{ .{ .range8 = .{ .in = 0 } }, .{ .range8 = .{ .in = 1 } } };
    try proto.checkStatementLogUp(a, .{ .witness = &ok, .weights = &.{}, .tables = &.{}, .ops = &ops1 });
    try std.testing.expectError(error.LogUpCountAboveP, proto.checkStatementLogUp(a, .{ .witness = &big, .weights = &.{}, .tables = &.{}, .ops = &ops1 }));
    // two keys of 2^30 on one range table: 2^31 + 256 >= p
    try std.testing.expectError(error.LogUpCountAboveP, proto.checkStatementLogUp(a, .{ .witness = &two, .weights = &.{}, .tables = &.{}, .ops = &ops2 }));
}
