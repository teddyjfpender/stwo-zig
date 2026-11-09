//! Regression tests for the review-B zero-knowledge findings ZK-1..ZK-3 (copied
//! from the reviewers' attack tests, review_zk_test.zig of review stream B).
//!
//! Each test plays an honest-but-curious verifier: it replays the public
//! Fiat-Shamir transcript of a hiding proof (zk.zig) and runs the reviewer's
//! extraction. Before the fixes the extraction succeeded (the reviewer's
//! assertions held); the assertions here are inverted: the extracted value must
//! no longer match the private one (zk.md 4.5, rank argument).
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const zk = @import("zk.zig");
const zks = @import("zk_sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const M31 = f.M31;
const TensorInfo = proto.TensorInfo;
const Statement = proto.Statement;

fn qi(v: i64) QM31 {
    return f.qFromI64(v);
}

/// Copy of zk.mixStatement for core-op statements (no ext ops, flat PCS, committed remainders).
fn mixStatement(tr: *Transcript, st: Statement, weight_root: [32]u8, cfg: proto.Config) void {
    tr.mixDigest(weight_root);
    tr.mixU64(cfg.pcs.n_queries);
    tr.mixU64(cfg.pcs.log_blowup);
    tr.mixU64(zk.wpcs(cfg).n_queries);
    tr.mixU64(zk.wpcs(cfg).log_blowup);
    tr.mixU64(st.witness.len);
    for (st.witness) |t| {
        tr.mixU64(t.n_dims);
        for (t.log_dims) |d| tr.mixU64(d);
    }
    tr.mixU64(st.weights.len);
    for (st.weights) |t| for (t.log_dims) |d| tr.mixU64(d);
    for (st.ops) |op| switch (op) {
        .matmul => |m| tr.mixU32s(&.{ 1, m.x, m.w, m.y, m.shift }),
        .range8 => |r| tr.mixU32s(&.{ 4, r.in }),
        .product => |q| tr.mixU32s(&.{ 5, q.a, q.b, q.c }),
        else => unreachable,
    };
}

/// Verifier transcript up to (and including) alpha, beta, tau and rho.
fn replayHead(st: Statement, cfg: proto.Config, wroot: [32]u8, p: *const zk.Proof, rho: []QM31) struct { tr: Transcript, alpha: QM31 } {
    var tr = Transcript.initDomain("stwo-tensor-zk-v1");
    mixStatement(&tr, st, wroot, cfg);
    tr.mixU64(0); // no public tensors
    tr.mixDigest(p.root1);
    tr.mixDigest(p.aux_root);
    if (p.wmask_root) |r| tr.mixDigest(r);
    const alpha = tr.draw();
    _ = tr.draw(); // beta
    _ = tr.draw(); // tau
    tr.drawN(rho);
    return .{ .tr = tr, .alpha = alpha };
}

fn cfgZk() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 4, .witness_log_cols_max = 7, .gkr_threads = 1, .hiding = true, .weight_mask_slots = 16 };
}

fn isBase(x: QM31) bool {
    const l = f.limbs(x);
    return l[1] == 0 and l[2] == 0 and l[3] == 0;
}

// ---------------------------------------------------------------------------
// ZK-1: a tensor with fewer pad cells than hats. Pads are min(16, size) cells,
// so a scalar witness used by two masked zero-checks gets two hats on ONE pad cell:
//   h_i = (1 - g_i) a + g_i P   =>   a = (h1 g2 - h2 g1) / (g2 - g1).
test "zk regress zk-1: scalar witness used by two products is recovered from the hats" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const s0 = TensorInfo.vec(0);
    const infos = [_]TensorInfo{ s0, s0, s0, s0, s0 };
    const ops = [_]proto.Op{ .{ .product = .{ .a = 0, .b = 1, .c = 2 } }, .{ .product = .{ .a = 0, .b = 3, .c = 4 } } };
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    const secret: i32 = 1234567;
    const w0 = [_]i32{secret};
    const w1 = [_]i32{7};
    const w2 = [_]i32{secret * 7};
    const w3 = [_]i32{3};
    const w4 = [_]i32{secret * 3};
    const wv = [_][]const i32{ &w0, &w1, &w2, &w3, &w4 };
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, cfg, st, null, &proof);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var rho: [1]QM31 = undefined;
    var h = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
    var g: [2]QM31 = undefined;
    for (0..2) |i| {
        const vo = try zks.verify(arena.allocator(), &h.tr, QM31.zero(), 0, 3, 3, proof.checks[i]);
        g[i] = vo.point[0];
    }
    const h1 = proof.checks[0].hats[0];
    const h2 = proof.checks[1].hats[0];
    const rec = h1.mul(g[1]).sub(h2.mul(g[0])).mul(try g[1].sub(g[0]).inv());
    // each hat now has its own QM31 pad: the two pad terms no longer cancel
    try std.testing.expect(!rec.eql(qi(secret)));
}

// Same mechanism at log size 1 (2-cell pad, 3 hats): the verifier learns the
// witness functional  sum_i l_i (1 - g_i) a~(r_i)  with l = null vector of the pad
// functionals g_i eq(r_i, .).
test "zk regress zk-1b: size-2 witness in three products leaks a linear functional" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const v1 = TensorInfo.vec(1);
    const infos = [_]TensorInfo{ v1, v1, v1, v1, v1, v1, v1 };
    const ops = [_]proto.Op{
        .{ .product = .{ .a = 0, .b = 1, .c = 2 } },
        .{ .product = .{ .a = 0, .b = 3, .c = 4 } },
        .{ .product = .{ .a = 0, .b = 5, .c = 6 } },
    };
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    const x = [_]i32{ 4242, -77 };
    const b1 = [_]i32{ 3, 5 };
    const b2 = [_]i32{ 2, 9 };
    const b3 = [_]i32{ 11, 1 };
    var c1: [2]i32 = undefined;
    var c2: [2]i32 = undefined;
    var c3: [2]i32 = undefined;
    for (0..2) |i| {
        c1[i] = x[i] * b1[i];
        c2[i] = x[i] * b2[i];
        c3[i] = x[i] * b3[i];
    }
    // product values are canonical M31 in the witness
    const P: i64 = 0x7fff_ffff;
    var xc = x;
    var c1c = c1;
    var c2c = c2;
    var c3c = c3;
    for (&xc) |*v| v.* = @intCast(@mod(@as(i64, v.*), P));
    for (&c1c) |*v| v.* = @intCast(@mod(@as(i64, v.*), P));
    for (&c2c) |*v| v.* = @intCast(@mod(@as(i64, v.*), P));
    for (&c3c) |*v| v.* = @intCast(@mod(@as(i64, v.*), P));
    const wv = [_][]const i32{ &xc, &b1, &c1c, &b2, &c2c, &b3, &c3c };
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, cfg, st, null, &proof);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var rho: [1]QM31 = undefined;
    var h = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
    var M: [2][3]QM31 = undefined; // pad functionals g_i * eq(r_i, k)
    var g: [3]QM31 = undefined;
    var r: [3]QM31 = undefined;
    for (0..3) |i| {
        const vo = try zks.verify(arena.allocator(), &h.tr, QM31.zero(), 1, 3, 3, proof.checks[i]);
        r[i] = vo.point[0];
        g[i] = vo.point[1];
        M[0][i] = g[i].mul(QM31.one().sub(r[i]));
        M[1][i] = g[i].mul(r[i]);
    }
    // null vector by the cross product
    const l = [3]QM31{
        M[0][1].mul(M[1][2]).sub(M[0][2].mul(M[1][1])),
        M[0][2].mul(M[1][0]).sub(M[0][0].mul(M[1][2])),
        M[0][0].mul(M[1][1]).sub(M[0][1].mul(M[1][0])),
    };
    var lhs = QM31.zero(); // from the proof only
    var rhs = QM31.zero(); // from the private witness only
    for (0..3) |i| {
        lhs = lhs.add(l[i].mul(proof.checks[i].hats[0]));
        const ax = try f.mleEvalI32(a, &xc, r[i .. i + 1]);
        rhs = rhs.add(l[i].mul(QM31.one().sub(g[i])).mul(ax));
    }
    try std.testing.expect(!rhs.isZero());
    // the null vector of the old shared-pad functionals no longer cancels the pads
    try std.testing.expect(!lhs.eql(rhs));
}

// ---------------------------------------------------------------------------
// ZK-2: the GKR blinder is ONE M31 cell, so the root denominator
// d_0 = rho * prod(alpha - key) * prod(alpha - t) is known up to an M31 factor:
// the verifier tests a candidate key multiset by checking d_0 / D(candidate) in M31.
test "zk regress zk-2: GKR root denominator identifies the key multiset (blinder in M31)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const infos = [_]TensorInfo{TensorInfo.vec(4)};
    const ops = [_]proto.Op{.{ .range8 = .{ .in = 0 } }};
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    var x: [16]i32 = undefined;
    for (&x, 0..) |*v, i| v.* = @as(i32, @intCast(i * 13 % 200)) - 100;
    const wv = [_][]const i32{&x};
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, cfg, st, null, &proof);
    try std.testing.expectEqual(@as(usize, 1), proof.gkr_roots.len);

    var rho: [1]QM31 = undefined;
    const h = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
    const alpha = h.alpha;
    const H = struct {
        fn denom(al: QM31, keys: []const i32) QM31 {
            var d = QM31.one();
            for (keys) |v| d = d.mul(al.sub(qi(@as(i64, v) + 128)));
            for (0..256) |t| d = d.mul(al.sub(qi(@intCast(t))));
            return d;
        }
    };
    const d0 = proof.gkr_roots[0];
    // the true witness: the ratio is the (now QM31-uniform) blinder, not in M31
    try std.testing.expect(!isBase(d0.mul(try H.denom(alpha, &x).inv())));
    // any other multiset (one value changed): not in M31
    var y = x;
    y[3] += 1;
    try std.testing.expect(!isBase(d0.mul(try H.denom(alpha, &y).inv())));
    // an all-zero witness hypothesis is also rejected
    const z = [_]i32{0} ** 16;
    try std.testing.expect(!isBase(d0.mul(try H.denom(alpha, &z).inv())));
}

// ---------------------------------------------------------------------------
// ZK-3: the weight pad R_W is 4 rows; every weight hat at the shared column point
// cp uses the functional  sum_k eq(s, k) R_W[k]~(cp)  (4-dimensional). Five matmuls
// sharing cp in one proof give five hats on a 4-dim pad span: a linear functional of
// the private weights is revealed.
test "zk regress zk-3: five matmuls sharing the weight column point leak a weight functional" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    var cfg = cfgZk();
    cfg.weight_pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 0 };
    const NW = 5;
    const lt = 1;
    const lk = 2;
    const ln = 4;
    var winfos: [NW]TensorInfo = undefined;
    for (&winfos) |*w| w.* = TensorInfo.mat(lk, ln);
    var wdata: [NW][64]i8 = undefined;
    var prng = std.Random.DefaultPrng.init(5);
    for (&wdata) |*w| for (w) |*v| {
        v.* = prng.random().intRangeAtMost(i8, -3, 3);
    };
    var wslices: [NW][]const i8 = undefined;
    for (&wslices, 0..) |*s, i| s.* = &wdata[i];
    var zw = try zk.commitWeights(a, &pool, cfg, &winfos, &wslices);
    defer zw.deinit(a);

    var infos: [1 + NW]TensorInfo = undefined;
    infos[0] = TensorInfo.mat(lt, lk);
    for (1..1 + NW) |i| infos[i] = TensorInfo.mat(lt, ln);
    var ops: [NW]proto.Op = undefined;
    for (&ops, 0..) |*o, i| o.* = .{ .matmul = .{ .x = 0, .w = @intCast(i), .y = @intCast(1 + i), .shift = 1 } };
    const st = Statement{ .witness = &infos, .weights = &winfos, .tables = &.{}, .ops = &ops };
    var x: [8]i32 = undefined;
    for (&x) |*v| v.* = prng.random().intRangeAtMost(i32, -3, 3);
    var ys: [NW][32]i32 = undefined;
    for (0..NW) |wi| for (0..2) |t| for (0..16) |n| {
        var acc: i64 = 0;
        for (0..4) |k| acc += @as(i64, x[t * 4 + k]) * wdata[wi][k * 16 + n];
        ys[wi][t * 16 + n] = @intCast((acc + 1) >> 1);
    };
    var wv: [1 + NW][]const i32 = undefined;
    wv[0] = &x;
    for (0..NW) |i| wv[1 + i] = &ys[i];
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, &zw, &wv, &tm);
    defer proof.deinit(a);
    const key = zw.key();
    try zk.verify(a, cfg, st, key, &proof);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    var rho: [lt + ln]QM31 = undefined;
    var h = replayHead(st, cfg, key.root, &proof, &rho);
    const n = lt + ln; // max(lk, lt + ln)
    var M: [4][NW]QM31 = undefined;
    var cdata_w: [NW]QM31 = undefined;
    for (0..NW) |i| {
        const vo = try zks.verify(ar, &h.tr, qi(-1), n, 2, 4, proof.checks[i]);
        const r = vo.point[0..n];
        const g = vo.point[n];
        var scale = QM31.one();
        for (r[0 .. n - lk]) |c| scale = scale.mul(QM31.one().sub(c));
        var local: [lk + ln]QM31 = undefined;
        @memcpy(local[0..lk], r[n - lk ..]);
        @memcpy(local[lk..], rho[lt..]);
        var wi32: [64]i32 = undefined;
        for (&wi32, wdata[i]) |*o, v| o.* = v;
        const wval = try f.mleEvalI32(a, &wi32, &local);
        cdata_w[i] = QM31.one().sub(g).mul(scale).mul(wval);
        const eqs = try f.eqTable(ar, &.{ r[n - 2], r[n - 1] }, g);
        for (0..4) |k| M[k][i] = eqs[k];
    }
    // null vector l of the 4 x 5 pad-functional matrix (Gaussian elimination)
    var A = M;
    var piv_col: [4]usize = undefined;
    var row: usize = 0;
    for (0..NW) |c| {
        if (row == 4) break;
        var p: ?usize = null;
        for (row..4) |rr| if (!A[rr][c].isZero()) {
            p = rr;
            break;
        };
        const pr = p orelse continue;
        std.mem.swap([NW]QM31, &A[pr], &A[row]);
        const inv = try A[row][c].inv();
        for (&A[row]) |*v| v.* = v.*.mul(inv);
        for (0..4) |rr| if (rr != row and !A[rr][c].isZero()) {
            const fac = A[rr][c];
            for (0..NW) |cc| A[rr][cc] = A[rr][cc].sub(fac.mul(A[row][cc]));
        };
        piv_col[row] = c;
        row += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), row);
    // free column: the one not among the pivots
    var free: usize = 0;
    outer: for (0..NW) |c| {
        for (piv_col) |pc| if (pc == c) continue :outer;
        free = c;
        break;
    }
    var l: [NW]QM31 = [_]QM31{QM31.zero()} ** NW;
    l[free] = QM31.one();
    for (0..4) |rr| l[piv_col[rr]] = A[rr][free].neg();
    var lhs = QM31.zero(); // public: from the proof
    var rhs = QM31.zero(); // private: from the weights only
    for (0..NW) |i| {
        lhs = lhs.add(l[i].mul(proof.checks[i].hats[1]));
        rhs = rhs.add(l[i].mul(cdata_w[i]));
    }
    try std.testing.expect(!rhs.isZero());
    // each W hat has its own fresh pad row in the per-proof mask table
    try std.testing.expect(!lhs.eql(rhs));
}
