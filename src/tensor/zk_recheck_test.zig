//! Independent re-check variants of the review-B ZK attacks (not committed).
//! Each test recovers the pad term of the revealed hats from the witness and
//! checks that it no longer has the old (leaking) linear structure.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const zk = @import("zk.zig");
const zks = @import("zk_sumcheck.zig");
const Transcript = @import("transcript.zig").Transcript;

const QM31 = f.QM31;
const TensorInfo = proto.TensorInfo;
const Statement = proto.Statement;

fn qi(v: i64) QM31 {
    return f.qFromI64(v);
}

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

fn replayHead(st: Statement, cfg: proto.Config, wroot: [32]u8, p: *const zk.Proof, rho: []QM31) struct { tr: Transcript, alpha: QM31 } {
    var tr = Transcript.initDomain("stwo-tensor-zk-v1");
    mixStatement(&tr, st, wroot, cfg);
    tr.mixU64(0);
    tr.mixDigest(p.root1);
    tr.mixDigest(p.aux_root);
    if (p.wmask_root) |r| tr.mixDigest(r);
    const alpha = tr.draw();
    _ = tr.draw();
    _ = tr.draw();
    tr.drawN(rho);
    return .{ .tr = tr, .alpha = alpha };
}

fn cfgZk() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 4, .witness_log_cols_max = 7, .gkr_threads = 1, .hiding = true, .weight_mask_slots = 16 };
}

/// Rank of a matrix over QM31 (equals the rank over M31 for M31 entries).
fn rank(a: std.mem.Allocator, rows_in: []const []const QM31) !usize {
    const m = rows_in.len;
    if (m == 0) return 0;
    const n = rows_in[0].len;
    const A = try a.alloc([]QM31, m);
    defer {
        for (A) |r| a.free(r);
        a.free(A);
    }
    for (A, rows_in) |*r, s| r.* = try a.dupe(QM31, s);
    var row: usize = 0;
    for (0..n) |c| {
        if (row == m) break;
        var p: ?usize = null;
        for (row..m) |rr| if (!A[rr][c].isZero()) {
            p = rr;
            break;
        };
        const pr = p orelse continue;
        std.mem.swap([]QM31, &A[pr], &A[row]);
        const inv = try A[row][c].inv();
        for (A[row]) |*v| v.* = v.*.mul(inv);
        for (0..m) |rr| if (rr != row and !A[rr][c].isZero()) {
            const fac = A[rr][c];
            for (0..n) |cc| A[rr][cc] = A[rr][cc].sub(fac.mul(A[row][cc]));
        };
        row += 1;
    }
    return row;
}

/// True iff the system  A x = b  (A: rows, b: rhs) is consistent.
fn consistent(a: std.mem.Allocator, A: []const []const QM31, b: []const QM31) !bool {
    const aug = try a.alloc([]QM31, A.len);
    defer {
        for (aug) |r| a.free(r);
        a.free(aug);
    }
    for (aug, A, b) |*r, s, v| {
        r.* = try a.alloc(QM31, s.len + 1);
        @memcpy(r.*[0..s.len], s);
        r.*[s.len] = v;
    }
    const ra = try rank(a, A);
    const constAug: []const []const QM31 = @ptrCast(aug);
    return ra == try rank(a, constAug);
}

fn allLimbsNonzero(x: QM31) bool {
    const l = f.limbs(x);
    return l[0] != 0 and l[1] != 0 and l[2] != 0 and l[3] != 0;
}

// ---------------------------------------------------------------------------
// ZK-1 variant A: one scalar in SIX products. The pad term of hat i is
// q_i = (h_i - (1 - g_i) a) / g_i. Old code: q_i = P (the same M31 cell) for all i.
// Fixed: each q_i is a distinct, full QM31 value; every pairwise two-hat
// extraction fails.
test "recheck zk-1 A: scalar in six products, pad terms are distinct full QM31" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const K = 6;
    const s0 = TensorInfo.vec(0);
    const infos = [_]TensorInfo{s0} ** (1 + 2 * K);
    var ops: [K]proto.Op = undefined;
    for (&ops, 0..) |*o, i| o.* = .{ .product = .{ .a = 0, .b = @intCast(1 + 2 * i), .c = @intCast(2 + 2 * i) } };
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    const secret: i32 = 98765;
    var cells: [1 + 2 * K][1]i32 = undefined;
    cells[0] = .{secret};
    for (0..K) |i| {
        const b: i32 = @intCast(3 + i);
        cells[1 + 2 * i] = .{b};
        cells[2 + 2 * i] = .{secret * b};
    }
    var wv: [1 + 2 * K][]const i32 = undefined;
    for (&wv, 0..) |*w, i| w.* = &cells[i];
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, cfg, st, null, &proof);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    var rho: [1]QM31 = undefined;
    var h = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
    var g: [K]QM31 = undefined;
    var q: [K]QM31 = undefined;
    for (0..K) |i| {
        const vo = try zks.verify(arena.allocator(), &h.tr, QM31.zero(), 0, 3, 3, proof.checks[i]);
        g[i] = vo.point[0];
        const hat = proof.checks[i].hats[0];
        q[i] = hat.sub(QM31.one().sub(g[i]).mul(qi(secret))).mul(try g[i].inv());
        try std.testing.expect(allLimbsNonzero(q[i]));
    }
    for (0..K) |i| for (i + 1..K) |j| {
        try std.testing.expect(!q[i].eql(q[j]));
        const hi_ = proof.checks[i].hats[0];
        const hj = proof.checks[j].hats[0];
        const rec = hi_.mul(g[j]).sub(hj.mul(g[i])).mul(try g[j].sub(g[i]).inv());
        try std.testing.expect(!rec.eql(qi(secret)));
    };
    // also the b / c hats of each check (parts 1, 2): residual not in M31
    // (a 1-cell M31 pad would put each hat on an M31 line)
}

// ---------------------------------------------------------------------------
// ZK-1 variant B: a log-size-2 witness (4 cells, old pad = 4 M31 cells) in three
// products: 3 QM31 functionals = 12 M31 equations on 4 pad unknowns. Old code:
// q_i = P~(r_i) with P in M31^4 -> the 12x4 system is consistent. Fixed: inconsistent.
test "recheck zk-1 B: log-2 witness in three products, pad terms are not one 4-cell M31 pad" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const v2 = TensorInfo.vec(2);
    const infos = [_]TensorInfo{v2} ** 7;
    const ops = [_]proto.Op{
        .{ .product = .{ .a = 0, .b = 1, .c = 2 } },
        .{ .product = .{ .a = 0, .b = 3, .c = 4 } },
        .{ .product = .{ .a = 0, .b = 5, .c = 6 } },
    };
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    const x = [_]i32{ 4242, 77, 1000, 31337 };
    const bs = [3][4]i32{ .{ 3, 5, 7, 9 }, .{ 2, 9, 4, 6 }, .{ 11, 1, 13, 8 } };
    var cs: [3][4]i32 = undefined;
    for (0..3) |k| for (0..4) |i| {
        cs[k][i] = x[i] * bs[k][i];
    };
    const wv = [_][]const i32{ &x, &bs[0], &cs[0], &bs[1], &cs[1], &bs[2], &cs[2] };
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, cfg, st, null, &proof);

    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    var rho: [1]QM31 = undefined;
    var h = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
    var A: [12][]QM31 = undefined;
    var b: [12]QM31 = undefined;
    for (0..3) |i| {
        const vo = try zks.verify(ar, &h.tr, QM31.zero(), 2, 3, 3, proof.checks[i]);
        const r = vo.point[0..2];
        const g = vo.point[2];
        const ax = try f.mleEvalI32(a, &x, r);
        const q = proof.checks[i].hats[0].sub(QM31.one().sub(g).mul(ax)).mul(try g.inv());
        try std.testing.expect(allLimbsNonzero(q));
        const eq = try f.eqTable(ar, r, QM31.one());
        const ql = f.limbs(q);
        for (0..4) |l| {
            const row = try ar.alloc(QM31, 4);
            for (0..4) |j| row[j] = qi(f.limbs(eq[j])[l]);
            A[4 * i + l] = row;
            b[4 * i + l] = qi(ql[l]);
        }
    }
    const Ac: []const []const QM31 = @ptrCast(&A);
    try std.testing.expectEqual(@as(usize, 4), try rank(ar, Ac));
    try std.testing.expect(!try consistent(ar, Ac, &b));
}

// ---------------------------------------------------------------------------
// ZK-2 variant: four different witnesses; the ratio d_0 / D(true keys) is the
// blinder rho. Old: rho in M31. Fixed: rho must not lie in M31, CM31, or any
// coordinate subspace (all four limbs non-zero), and differs across proofs.
test "recheck zk-2: blinder ratio is a full QM31 value (not in M31 / CM31) across witnesses" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const cfg = cfgZk();
    const infos = [_]TensorInfo{TensorInfo.vec(4)};
    const ops = [_]proto.Op{.{ .range8 = .{ .in = 0 } }};
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    var seen: [4]QM31 = undefined;
    for (0..4) |trial| {
        var x: [16]i32 = undefined;
        for (&x, 0..) |*v, i| v.* = @as(i32, @intCast((i * (7 + 2 * trial) + trial) % 256)) - 128;
        const wv = [_][]const i32{&x};
        var tm: proto.Timings = .{};
        var proof = try zk.prove(a, &pool, cfg, st, null, &wv, &tm);
        defer proof.deinit(a);
        try zk.verify(a, cfg, st, null, &proof);
        var rho: [1]QM31 = undefined;
        const hd = replayHead(st, cfg, [_]u8{0} ** 32, &proof, &rho);
        var d = QM31.one();
        for (x) |v| d = d.mul(hd.alpha.sub(qi(@as(i64, v) + 128)));
        for (0..256) |t| d = d.mul(hd.alpha.sub(qi(@intCast(t))));
        const ratio = proof.gkr_roots[0].mul(try d.inv());
        const l = f.limbs(ratio);
        try std.testing.expect(!(l[2] == 0 and l[3] == 0)); // not in CM31 (incl. M31)
        try std.testing.expect(allLimbsNonzero(ratio));
        for (seen[0..trial]) |s| try std.testing.expect(!s.eql(ratio));
        seen[trial] = ratio;
    }
}

// ---------------------------------------------------------------------------
// ZK-3 variant: EIGHT matmuls at the shared column point. Pad term of W hat i:
// q_i = (hatW_i - c_data_i) / g_i. Old: q_i = sum_k eq(s_i,k) R_k(cp), a 4-dim span
// (QM31 system q = E^T R with 8 eqs / 4 unknowns consistent). Fixed: inconsistent,
// and the q_i are pairwise distinct with full limbs.
test "recheck zk-3: eight matmuls at a shared column point, W pad terms independent" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    var cfg = cfgZk();
    cfg.weight_pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 0 };
    const NW = 8;
    const lt = 1;
    const lk = 2;
    const ln = 4;
    var winfos: [NW]TensorInfo = undefined;
    for (&winfos) |*w| w.* = TensorInfo.mat(lk, ln);
    var wdata: [NW][64]i8 = undefined;
    var prng = std.Random.DefaultPrng.init(17);
    for (&wdata) |*w| for (w) |*v| {
        v.* = prng.random().intRangeAtMost(i8, -5, 5);
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
    const n = lt + ln;
    var E: [NW][]QM31 = undefined;
    var q: [NW]QM31 = undefined;
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
        const cdata = QM31.one().sub(g).mul(scale).mul(wval);
        q[i] = proof.checks[i].hats[1].sub(cdata).mul(try g.inv());
        try std.testing.expect(allLimbsNonzero(q[i]));
        E[i] = try f.eqTable(ar, &.{ r[n - 2], r[n - 1] }, QM31.one());
    }
    for (0..NW) |i| for (i + 1..NW) |j| try std.testing.expect(!q[i].eql(q[j]));
    const Ec: []const []const QM31 = @ptrCast(&E);
    try std.testing.expectEqual(@as(usize, 4), try rank(ar, Ec));
    try std.testing.expect(!try consistent(ar, Ec, &q));
}

// ---------------------------------------------------------------------------
// ZK-4 variant: real concurrent zk.prove calls (8 threads x 3 proofs) on ONE
// ZkWeights through *const. Distinct weight columns opened must never exceed the
// budget, every failure must be OpeningBudgetExceeded, and count == popcount.
const ConcCtx = struct {
    zw: *const zk.ZkWeights,
    cfg: proto.Config,
    st: Statement,
    wv: []const []const i32,
    ok: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    refused: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    other: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    fn run(self: *ConcCtx) void {
        const a = std.heap.page_allocator;
        var pool: f.Pool = undefined;
        pool.init(a, 1) catch return;
        defer pool.deinit();
        for (0..3) |_| {
            var tm: proto.Timings = .{};
            if (zk.prove(a, &pool, self.cfg, self.st, self.zw, self.wv, &tm)) |p| {
                var pp = p;
                if (zk.verify(a, self.cfg, self.st, self.zw.key(), &pp)) |_| {
                    _ = self.ok.fetchAdd(1, .monotonic);
                } else |_| _ = self.other.fetchAdd(1, .monotonic);
                pp.deinit(a);
            } else |e| {
                if (e == error.OpeningBudgetExceeded) _ = self.refused.fetchAdd(1, .monotonic) else _ = self.other.fetchAdd(1, .monotonic);
            }
        }
    }
};

test "recheck zk-4: concurrent zk.prove on one ZkWeights never exceeds the opening budget" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    var cfg = cfgZk();
    cfg.weight_log_cols = 6;
    cfg.weight_mask_slots = 64;
    cfg.weight_pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 0 };
    const winfos = [_]TensorInfo{TensorInfo.mat(2, 6)};
    var wdata: [256]i8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    for (&wdata) |*v| v.* = prng.random().intRangeAtMost(i8, -5, 5);
    const ws = [_][]const i8{&wdata};
    var zw = try zk.commitWeights(a, &pool, cfg, &winfos, &ws);
    defer zw.deinit(a);
    const infos = [_]TensorInfo{ TensorInfo.mat(1, 2), TensorInfo.mat(1, 6) };
    const ops = [_]proto.Op{.{ .matmul = .{ .x = 0, .w = 0, .y = 1, .shift = 1 } }};
    const st = Statement{ .witness = &infos, .weights = &winfos, .tables = &.{}, .ops = &ops };
    var x: [8]i32 = undefined;
    for (&x) |*v| v.* = prng.random().intRangeAtMost(i32, -3, 3);
    var y: [128]i32 = undefined;
    for (0..2) |t| for (0..64) |n| {
        var acc: i64 = 0;
        for (0..4) |k| acc += @as(i64, x[t * 4 + k]) * wdata[k * 64 + n];
        y[t * 64 + n] = @intCast((acc + 1) >> 1);
    };
    const wv = [_][]const i32{ &x, &y };
    var ctx = ConcCtx{ .zw = &zw, .cfg = cfg, .st = st, .wv = &wv };
    var th: [8]std.Thread = undefined;
    for (&th) |*h| h.* = try std.Thread.spawn(.{}, ConcCtx.run, .{&ctx});
    for (th) |h| h.join();
    const u = zw.budgetUsed();
    std.debug.print("\n[zk-4 recheck] ok={d} refused={d} other={d} used={d}/{d}\n", .{ ctx.ok.load(.monotonic), ctx.refused.load(.monotonic), ctx.other.load(.monotonic), u[0], u[1] });
    try std.testing.expect(u[0] <= u[1]);
    try std.testing.expectEqual(@as(usize, 0), ctx.other.load(.monotonic));
    try std.testing.expect(ctx.ok.load(.monotonic) >= 1);
    try std.testing.expect(ctx.refused.load(.monotonic) >= 1); // the budget actually binds
    try std.testing.expectEqual(zw.com.budget.?.opened.count(), u[0]);
}

// ---------------------------------------------------------------------------
// ZK-5 variants: log_blowup 1 refused as an error (no panic in ReleaseSafe) on the
// verifier side for a real proof, in the recursive (two-level) mode, and for the
// weight table.
test "recheck zk-5: log_blowup 1 is an error on verify, recursive prove and weight commit" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 1);
    defer pool.deinit();
    const good = cfgZk();
    const v = TensorInfo.vec(3);
    const infos = [_]TensorInfo{ v, v, v };
    const ops = [_]proto.Op{.{ .product = .{ .a = 0, .b = 1, .c = 2 } }};
    const st = Statement{ .witness = &infos, .weights = &.{}, .tables = &.{}, .ops = &ops };
    const w = [_]i32{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const wv = [_][]const i32{ &w, &w, &[_]i32{ 1, 4, 9, 16, 25, 36, 49, 64 } };
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, good, st, null, &wv, &tm);
    defer proof.deinit(a);
    try zk.verify(a, good, st, null, &proof);
    var bad = good;
    bad.pcs.log_blowup = 1;
    try std.testing.expectError(error.ZkRate, zk.verify(a, bad, st, null, &proof));
    // recursive mode
    var rec = bad;
    rec.two_level = .{ .inner = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .depth = 1, .inner_work_shift = 0 };
    try std.testing.expectError(error.ZkRate, zk.prove(a, &pool, rec, st, null, &wv, &tm));
    var recg = good;
    recg.two_level = rec.two_level;
    var p2 = try zk.prove(a, &pool, recg, st, null, &wv, &tm);
    defer p2.deinit(a);
    try zk.verify(a, recg, st, null, &p2);
    try std.testing.expectError(error.ZkRate, zk.verify(a, rec, st, null, &p2));
    // weight table at log_blowup 1
    var wc = good;
    wc.weight_pcs = .{ .log_blowup = 1, .n_queries = 8, .pow_bits = 0 };
    const winfos = [_]TensorInfo{TensorInfo.mat(2, 4)};
    const wd = [_]i8{1} ** 64;
    const ws = [_][]const i8{&wd};
    try std.testing.expectError(error.WeightMaskSlots, zk.commitWeights(a, &pool, wc, &winfos, &ws));
}
