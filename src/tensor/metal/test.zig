//! CPU vs Metal bit-identity tests for the tensor prover's GPU path.
const std = @import("std");
const t = @import("stwo_tensor");
const metal = @import("stwo_tensor_metal");
const f = t.field;
const pcs = t.pcs;
const sc = t.sumcheck;
const proto = t.protocol;
const model = t.model;
const Transcript = t.transcript.Transcript;

const M31 = f.M31;
const QM31 = f.QM31;
const proofDigest = t.digest.proofDigest;

var gpu_singleton: ?*metal.Gpu = null;
fn gpu() !*metal.Gpu {
    if (gpu_singleton) |g| return g;
    gpu_singleton = try metal.Gpu.init(std.heap.c_allocator);
    return gpu_singleton.?;
}

fn checkCommit(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, g: *metal.Gpu, lr: u32, lc: u32, lb: u32, rows_used: ?usize, seed: u64) !void {
    const R = @as(usize, 1) << @intCast(lr);
    const C = @as(usize, 1) << @intCast(lc);
    const data = try a.alloc(T, R * C);
    defer a.free(data);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (data) |*d| d.* = if (T == i8) rnd.int(i8) else @intCast(rnd.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
    const m = pcs.Matrix(T){ .data = data, .log_rows = lr, .log_cols = lc, .rows_used = rows_used };
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    var cpu = try pcs.commit(T, a, pool, &tw, m, lb);
    defer cpu.deinit(a);
    var dev = (try g.commit(T, a, &tw, m, lb)).?;
    defer dev.deinit(a);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(cpu.enc), std.mem.sliceAsBytes(dev.enc));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(cpu.tree.nodes[1..]), std.mem.sliceAsBytes(dev.tree.nodes[1..]));
    try std.testing.expectEqual(cpu.root(), dev.root());
}

test "metal commit matches CPU (encoding, leaves, Merkle tree)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    // small shapes, odd rows_used, multiple blowups; tail-only and global layers
    try checkCommit(i32, a, &pool, g, 4, 1, 2, null, 1);
    try checkCommit(i32, a, &pool, g, 3, 2, 1, null, 2);
    try checkCommit(i8, a, &pool, g, 5, 6, 2, 19, 3);
    try checkCommit(i32, a, &pool, g, 6, 10, 2, 37, 4);
    try checkCommit(i32, a, &pool, g, 5, 12, 1, null, 5);
    try checkCommit(i32, a, &pool, g, 4, 14, 2, 13, 6);
    try checkCommit(i8, a, &pool, g, 7, 13, 3, 100, 7);
    // force several streamed chunks (rows not a multiple of 16 in the last)
    const saved = g.chunk_bytes;
    defer g.chunk_bytes = saved;
    g.chunk_bytes = 16 * (1 << 12) * 4;
    try checkCommit(i32, a, &pool, g, 7, 10, 2, 83, 8);
    try checkCommit(i8, a, &pool, g, 8, 9, 3, null, 9);
}

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_PRODUCT = [_]sc.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

fn randQ(r: std.Random) QM31 {
    return QM31.fromU32Unchecked(r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P));
}

fn checkSumcheck(comptime NF: usize, comptime terms: []const sc.Term, a: std.mem.Allocator, pool: *f.Pool, g: *metal.Gpu, n: u32, active: usize, seed: u64) !void {
    const len = @as(usize, 1) << @intCast(n);
    var prng = std.Random.DefaultPrng.init(seed);
    var cpu_f: [NF][]QM31 = undefined;
    var dev_f: [NF][]QM31 = undefined;
    for (0..NF) |j| {
        cpu_f[j] = try a.alloc(QM31, len);
        for (cpu_f[j], 0..) |*x, i| x.* = if (i < active) randQ(prng.random()) else QM31.zero();
        dev_f[j] = try a.dupe(QM31, cpu_f[j]);
    }
    defer for (0..NF) |j| {
        a.free(cpu_f[j]);
        a.free(dev_f[j]);
    };
    // claim = sum of the summand
    var claim = QM31.zero();
    for (0..len) |i| {
        var cur: [NF]QM31 = undefined;
        for (0..NF) |j| cur[j] = cpu_f[j][i];
        claim = claim.add(sc.evalTerms(terms, &cur));
    }
    var tc = Transcript.initDomain("sc");
    var rc = try sc.proveActive(NF, terms, a, pool, &tc, claim, cpu_f, active);
    defer rc.deinit(a);
    var acc = g.accel().*;
    acc.sc_min_work = 16;
    var td = Transcript.initDomain("sc");
    var rd = try t.accel.proveActive(&acc, NF, terms, a, pool, &td, claim, dev_f, active);
    defer rd.deinit(a);
    try std.testing.expectEqual(rc.proof.deg, rd.proof.deg);
    for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
    for (rc.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
    for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
    try std.testing.expect(tc.draw().eql(td.draw()));
}

test "metal sumcheck matches CPU (deg 2/3, partial active)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    try checkSumcheck(2, &T_PROD2, a, &pool, g, 12, 1 << 12, 1);
    try checkSumcheck(2, &T_PROD2, a, &pool, g, 13, 5000, 2);
    try checkSumcheck(3, &T_EQ3, a, &pool, g, 11, 1500, 3);
    try checkSumcheck(4, &T_PRODUCT, a, &pool, g, 12, 4096, 4);
    try checkSumcheck(4, &T_PRODUCT, a, &pool, g, 14, 9999, 5);
    try checkSumcheck(2, &T_PROD2, a, &pool, g, 18, 200_001, 6);
}

fn proveBoth(a: std.mem.Allocator, pool: *f.Pool, pc_cpu: proto.Config, st: proto.Statement, ws_cpu: *const proto.WeightStore, ws_gpu: *const proto.WeightStore, wview: []const []const i32) !void {
    const g = try gpu();
    var acc = g.accel().*;
    acc.sc_min_work = 16; // exercise device rounds on small tests
    acc.mle_min_len = 1;
    acc.gkr_min_log = 0;
    var pc_gpu = pc_cpu;
    pc_gpu.accel = &acc;
    var tm: proto.Timings = .{};
    var p_cpu = try proto.prove(a, pool, pc_cpu, st, ws_cpu, wview, &tm);
    defer p_cpu.deinit(a);
    const before = g.stats;
    var p_gpu = try proto.prove(a, pool, pc_gpu, st, ws_gpu, wview, &tm);
    defer p_gpu.deinit(a);
    // the device path actually ran
    try std.testing.expect(g.stats.commit_calls > before.commit_calls);
    try std.testing.expect(g.stats.sc_rounds > before.sc_rounds);
    if (p_cpu.gkr != null) try std.testing.expect(g.stats.gkr_calls > before.gkr_calls);
    try std.testing.expectEqual(proofDigest(p_cpu), proofDigest(p_gpu));
    try proto.verify(a, pc_cpu, st, proto.weightKey(ws_cpu), &p_gpu);
}

test "metal proof digest equals CPU: product toy" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 6, .gkr_threads = 2 };
    const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    defer ws.deinit(a);
    var built = try model.buildProduct(a, 12, 5);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var st = built.statement();
    st.weights = &dummy_info;
    try proveBoth(a, &pool, pc, st, &ws, &ws, wview);
}

test "metal proof digest equals CPU: small MLP (GPU weight commitment too)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 4, .log_d = 6, .log_f = 7 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 }, .weight_log_cols = 5, .witness_log_cols_max = 7, .gkr_threads = 2 };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    const g = try gpu();
    var pcg = pc;
    pcg.accel = g.accel();
    var ws_gpu = try proto.commitWeights(a, &pool, pcg, &winfos, &wv);
    defer ws_gpu.deinit(a);
    try std.testing.expectEqual(ws.com.root(), ws_gpu.com.root());
    // offline weight-key proof (GKR over the whole weight table) on the device
    {
        var kacc = g.accel().*;
        kacc.gkr_min_log = 0;
        var pck = pc;
        pck.accel = &kacc;
        const before = g.stats.gkr_calls;
        var kc = try t.weight_key.prove(a, &pool, pc, &ws);
        defer kc.deinit(a);
        var kd = try t.weight_key.prove(a, &pool, pck, &ws_gpu);
        defer kd.deinit(a);
        try std.testing.expect(g.stats.gkr_calls > before);
        try std.testing.expectEqual(t.digest.keyProofDigest(kc), t.digest.keyProofDigest(kd));
        try t.weight_key.verify(a, pc, proto.weightKey(&ws), &kd);
    }

    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    // forward pass with device matmuls: identical witness
    {
        var cfg_d = cfg;
        cfg_d.accel = g.accel();
        const before = g.stats.matmul_calls;
        var built_d = try model.buildMlp(a, &pool, &ws, cfg_d, x);
        defer built_d.deinit(a);
        try std.testing.expect(g.stats.matmul_calls >= before + 3);
        try std.testing.expectEqual(built.witness.len, built_d.witness.len);
        for (built.witness, built_d.witness) |u, v| try std.testing.expectEqualSlices(i32, u, v);
    }
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    try proveBoth(a, &pool, pc, built.statement(), &ws, &ws_gpu, wview);
}

test "metal batch sumcheck (device-built factors) matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    const n = 15;
    const total = @as(usize, 1) << n;
    const used = total - 777;
    var prng = std.Random.DefaultPrng.init(42);
    const r = prng.random();
    const wtab = try a.alloc(i32, total);
    defer a.free(wtab);
    for (wtab, 0..) |*x, i| x.* = if (i < used) @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P)) else 0;
    // overlapping claims of several sizes (incl. a 0-variable one)
    const sizes = [_]u32{ 13, 13, 10, 0, 14, 7 };
    const offs = [_]usize{ 0, 0, 1 << 13, 5, 1 << 14, (1 << 14) + 128 };
    var pts: [sizes.len][]QM31 = undefined;
    var claims: [sizes.len]t.accel.BatchClaim = undefined;
    for (sizes, offs, 0..) |sz, off, i| {
        pts[i] = try a.alloc(QM31, sz);
        for (pts[i]) |*p| p.* = randQ(r);
        claims[i] = .{ .offset = off, .point = pts[i], .gamma = randQ(r) };
    }
    defer for (pts) |p| a.free(p);
    const claim = randQ(r); // value is irrelevant to prover determinism
    // many device rounds, and exactly one (the lazy round-0 fold then finishes)
    defer g.lazy_rounds = 1;
    for ([_]u32{ 1, 2, 3, 5 }) |lr| for ([_]usize{ 64, 1 << 12, 1 << 14 }) |mw| {
        g.lazy_rounds = lr;
        var acc = g.accel().*;
        acc.sc_min_work = mw;
        const before = g.stats.sc_rounds;
        var tc2 = Transcript.initDomain("b");
        var rc2 = try t.accel.batchProve(null, a, &pool, &tc2, wtab, used, &claims, claim);
        defer rc2.deinit(a);
        var td = Transcript.initDomain("b");
        var rd = try t.accel.batchProve(&acc, a, &pool, &td, wtab, used, &claims, claim);
        defer rd.deinit(a);
        try std.testing.expect(g.stats.sc_rounds > before);
        if (mw == 1 << 14) try std.testing.expectEqual(before + 1, g.stats.sc_rounds);
        for (rc2.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
        for (rc2.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
        for (rc2.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
        try std.testing.expect(tc2.draw().eql(td.draw()));
    };
}

test "metal matmul accumulators match CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    const shapes = [_][3]u32{ .{ 0, 5, 3 }, .{ 4, 6, 7 }, .{ 7, 9, 6 }, .{ 6, 12, 8 }, .{ 7, 11, 7 } };
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    // int8-range activations take the fp32 matrix units; wider ones the int32
    // kernel. For int8, row 0 x column 0 is the worst case (every partial sum
    // at its bound 2^14 k).
    for (shapes) |sh| for ([_]bool{ false, true }) |int8| {
        const T = @as(usize, 1) << @intCast(sh[0]);
        const K = @as(usize, 1) << @intCast(sh[1]);
        const N = @as(usize, 1) << @intCast(sh[2]);
        const x = try a.alloc(i32, T * K);
        defer a.free(x);
        for (x) |*v| v.* = if (int8 or r.boolean()) r.intRangeAtMost(i32, -128, 127) else r.intRangeAtMost(i32, -(1 << 15) + 1, (1 << 15) - 1);
        // (the CPU kernel's i32 accumulator bounds the wide case to random rows)
        if (int8) for (0..K) |k| {
            x[k] = -127; // odd products: fp32 sums past 2^24 would round
        };
        const w = try a.alloc(i8, K * N + 3);
        defer a.free(w);
        for (w) |*v| v.* = r.int(i8);
        for (0..K) |k| w[3 + k * N] = -127;
        // unaligned weight view (offset 3), like a tensor inside the weight table
        const wm = pcs.Matrix(i8){ .data = w[3..], .log_rows = sh[1], .log_cols = sh[2] };
        const xi = proto.TensorInfo.mat(sh[0], sh[1]);
        const cpu = try proto.matmulAcc(a, &pool, xi, x, wm);
        defer a.free(cpu);
        const dev = (try t.accel.matmulAcc(g.accel(), a, sh[0], x, wm)).?;
        defer a.free(dev);
        try std.testing.expectEqualSlices(i64, cpu, dev);
    };
    // out-of-bound activations are declined (CPU fallback)
    var big = [_]i32{1 << 15} ** 4;
    var wsmall = [_]i8{1} ** 4;
    try std.testing.expect((try t.accel.matmulAcc(g.accel(), a, 1, &big, .{ .data = &wsmall, .log_rows = 1, .log_cols = 1 })) == null);
}

test "metal MLE evaluation of integer vectors matches CPU" {
    const a = std.testing.allocator;
    const g = try gpu();
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    for ([_]u32{ 0, 1, 5, 12, 17 }) |n| {
        const len = @as(usize, 1) << @intCast(n);
        const v = try a.alloc(i32, len);
        defer a.free(v);
        for (v) |*x| x.* = switch (r.uintLessThan(u8, 3)) {
            0 => 0,
            1 => r.intRangeAtMost(i32, -128, 127),
            else => @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P)),
        };
        const pt = try a.alloc(QM31, n);
        defer a.free(pt);
        for (pt) |*p| p.* = randQ(r);
        const want = try f.mleEvalI32(a, v, pt);
        var acc = g.accel().*;
        acc.mle_min_len = 1;
        const before = g.stats.mle_calls;
        const got = try t.accel.mleEvalI32(&acc, a, v, pt);
        try std.testing.expect(g.stats.mle_calls == before + 1);
        try std.testing.expect(want.eql(got));
    }
}

const engine = @import("stwo_prover_engine");
const Fast = engine.lookups.gkr_prover_fast.ForField(QM31);

fn makeInputs(a: std.mem.Allocator, seed: u64, logs: []const u32, kinds: []const u8, owned: bool, keep: *std.ArrayList([]u8)) ![]Fast.Input {
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const ins = try a.alloc(Fast.Input, logs.len);
    for (logs, kinds, 0..) |lg, kd, i| {
        const n = @as(usize, 1) << @intCast(lg);
        const den = try a.alloc(QM31, n);
        for (den) |*d| d.* = randQ(r);
        const num: Fast.Numerators = switch (kd) {
            0 => .ones,
            1 => blk: {
                const b = try a.alloc(M31, n);
                for (b) |*x| x.* = M31.fromCanonical(r.intRangeLessThan(u32, 0, f.P));
                if (!owned) try keep.append(a, std.mem.sliceAsBytes(b));
                break :blk .{ .base = b };
            },
            else => blk: {
                const sv = try a.alloc(QM31, n);
                for (sv) |*x| x.* = randQ(r);
                if (!owned) try keep.append(a, std.mem.sliceAsBytes(sv));
                break :blk .{ .secure = sv };
            },
        };
        if (!owned) try keep.append(a, std.mem.sliceAsBytes(den));
        ins[i] = .{ .num = num, .den = den, .owned = owned };
    }
    return ins;
}

test "metal LogUp-GKR batch proof matches the CPU fast prover" {
    const a = std.heap.c_allocator;
    const g = try gpu();
    const logs = [_]u32{ 10, 3, 15, 1, 7, 12, 14 };
    const kinds = [_]u8{ 0, 1, 2, 0, 1, 0, 1 };
    const saved = .{ g.gkr_cpu_sum_max, g.gkr_cpu_fold_max };
    defer {
        g.gkr_cpu_sum_max = saved[0];
        g.gkr_cpu_fold_max = saved[1];
    }
    // default split (CPU for small layers), all-device, and a mixed split
    defer g.gkr_fused_fold_sum = false;
    for ([_][2]usize{ .{ 1 << 9, 1 << 10 }, .{ 0, 0 }, .{ 1 << 12, 1 << 13 } }) |th| for ([_]bool{ true, false }) |owned| for ([_]bool{ true, false }) |fused| {
        g.gkr_cpu_sum_max = th[0];
        g.gkr_cpu_fold_max = th[1];
        g.gkr_fused_fold_sum = fused;
        var keep: std.ArrayList([]u8) = .empty;
        defer {
            for (keep.items) |b| a.free(b);
            keep.deinit(a);
        }
        const in_cpu = try makeInputs(a, 77, &logs, &kinds, owned, &keep);
        defer a.free(in_cpu);
        const in_gpu = try makeInputs(a, 77, &logs, &kinds, owned, &keep);
        defer a.free(in_gpu);
        var tc = Transcript.initDomain("gkr");
        var rc = try Fast.proveBatch(a, &tc.ch, in_cpu, .{ .threads = 2 }, null);
        defer rc.deinit(a);
        var acc = g.accel().*;
        acc.gkr_min_log = 0;
        var td = Transcript.initDomain("gkr");
        var rd = try t.accel.gkrProveBatch(&acc, a, &td.ch, in_gpu, 2);
        defer rd.deinit(a);
        try std.testing.expect(tc.draw().eql(td.draw()));
        try std.testing.expectEqual(rc.proof.sumcheck_proofs.len, rd.proof.sumcheck_proofs.len);
        for (rc.proof.sumcheck_proofs, rd.proof.sumcheck_proofs) |x, y| {
            try std.testing.expectEqual(x.round_polys.len, y.round_polys.len);
            for (x.round_polys, y.round_polys) |px, py| {
                try std.testing.expectEqual(px.coeffsSlice().len, py.coeffsSlice().len);
                for (px.coeffsSlice(), py.coeffsSlice()) |cx, cy| try std.testing.expect(cx.eql(cy));
            }
        }
        for (rc.proof.layer_masks_by_instance, rd.proof.layer_masks_by_instance) |mx, my| for (mx, my) |x, y| for (x.columnsSlice(), y.columnsSlice()) |cx, cy| {
            try std.testing.expect(cx[0].eql(cy[0]) and cx[1].eql(cy[1]));
        };
        for (rc.proof.output_claims_by_instance, rd.proof.output_claims_by_instance) |x, y| for (x, y) |u, v| try std.testing.expect(u.eql(v));
        for (rc.artifact.ood_point, rd.artifact.ood_point) |x, y| try std.testing.expect(x.eql(y));
        for (rc.artifact.claims_to_verify_by_instance, rd.artifact.claims_to_verify_by_instance) |x, y| for (x, y) |u, v| try std.testing.expect(u.eql(v));
        // borrowed inputs must be left untouched by the device path
        if (!owned) {
            var k: usize = 0;
            while (k < keep.items.len / 2) : (k += 1) try std.testing.expectEqualSlices(u8, keep.items[k], keep.items[k + keep.items.len / 2]);
        }
    };
}

test "metal lazy-factor sumcheck (eq sums and int vectors, degree 3) matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    const n = 14;
    const len = @as(usize, 1) << n;
    var prng = std.Random.DefaultPrng.init(99);
    const r = prng.random();
    var ints: [3][]i32 = undefined;
    for (&ints) |*v| {
        v.* = try a.alloc(i32, len);
        for (v.*) |*x| x.* = @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
    }
    defer for (ints) |v| a.free(v);
    var p0: [n]QM31 = undefined;
    var p1: [12]QM31 = undefined;
    for (&p0) |*p| p.* = randQ(r);
    for (&p1) |*p| p.* = randQ(r);
    const claims = [_]t.accel.BatchClaim{ .{ .offset = 0, .point = &p0, .gamma = randQ(r) }, .{ .offset = 1 << 13, .point = &p1, .gamma = randQ(r) } };
    const specs = [4]t.accel.FactorSpec{ .{ .eq = &claims }, .{ .int = ints[0] }, .{ .int = ints[1] }, .{ .int = ints[2] } };
    defer g.lazy_rounds = 1;
    for ([_]u32{ 1, 2, 3, 5 }) |lr| for ([_]usize{ len, len - 3001 }) |active| for ([_]usize{ 32, 1 << 11, 1 << 13 }) |mw| {
        g.lazy_rounds = lr;
        const claim = randQ(r);
        var tc = Transcript.initDomain("lz");
        var rc = try t.accel.proveFactors(null, 4, &T_PRODUCT, a, &pool, &tc, claim, specs, len, active);
        defer rc.deinit(a);
        var acc = g.accel().*;
        acc.sc_min_work = mw;
        const before = g.stats.sc_rounds;
        var td = Transcript.initDomain("lz");
        var rd = try t.accel.proveFactors(&acc, 4, &T_PRODUCT, a, &pool, &td, claim, specs, len, active);
        defer rd.deinit(a);
        try std.testing.expect(g.stats.sc_rounds > before);
        for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
        for (rc.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
        for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
        try std.testing.expect(tc.draw().eql(td.draw()));
    };
}

test "metal weight passes (combine rows, row dots) match CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    var prng = std.Random.DefaultPrng.init(21);
    const r = prng.random();
    for ([_][3]u32{ .{ 8, 9, 0 }, .{ 11, 7, 1 }, .{ 6, 12, 2 } }) |sh| {
        const R = @as(usize, 1) << @intCast(sh[0]);
        const C = @as(usize, 1) << @intCast(sh[1]);
        const d8 = try a.alloc(i8, R * C + 1);
        defer a.free(d8);
        for (d8) |*x| x.* = r.int(i8);
        const d32 = try a.alloc(i32, R * C);
        defer a.free(d32);
        for (d32) |*x| x.* = @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
        const used = R - sh[2] * 3; // partial rows_used
        const m8 = pcs.Matrix(i8){ .data = d8[1..], .log_rows = sh[0], .log_cols = sh[1], .rows_used = used };
        const m32 = pcs.Matrix(i32){ .data = d32, .log_rows = sh[0], .log_cols = sh[1], .rows_used = used };
        var cf: [3][]QM31 = undefined;
        for (&cf) |*c| {
            c.* = try a.alloc(QM31, R);
            for (c.*) |*x| x.* = randQ(r);
        }
        defer for (cf) |c| a.free(c);
        const cv = [_][]const QM31{ cf[0], cf[1], cf[2] };
        inline for (.{ i8, i32 }) |T| {
            const m = if (T == i8) m8 else m32;
            const want = try pcs.combineRows(T, a, &pool, m, &cv, if (T == i8) 7 else 30);
            defer {
                for (want) |w| a.free(w);
                a.free(want);
            }
            const got = (try g.combine(T, a, m, &cv)).?;
            defer {
                for (got) |w| a.free(w);
                a.free(got);
            }
            for (want, got) |x, y| for (x, y) |u, v| try std.testing.expect(u.eql(v));
        }
        const vec = try a.alloc(QM31, C);
        defer a.free(vec);
        for (vec) |*x| x.* = randQ(r);
        const mfull = pcs.Matrix(i8){ .data = d8[1..], .log_rows = sh[0], .log_cols = sh[1] };
        const want = try @import("stwo_tensor").linalg.rowDots(i8, a, &pool, mfull, vec, 7);
        defer a.free(want);
        const got = try t.accel.rowDots(g.accel(), a, &pool, mfull, vec, 7);
        defer a.free(got);
        for (want, got) |x, y| try std.testing.expect(x.eql(y));
    }
}

test "metal lazy eq-prefix factor (eq over leading vars, broadcast over trailing) matches CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    const n = 14;
    const len = @as(usize, 1) << n;
    var prng = std.Random.DefaultPrng.init(1234);
    const r = prng.random();
    var ints: [2][]i32 = undefined;
    for (&ints) |*v| {
        v.* = try a.alloc(i32, len);
        for (v.*) |*x| x.* = @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
    }
    defer for (ints) |v| a.free(v);
    const T3 = T_EQ3;
    var pt: [n]QM31 = undefined;
    for (&pt) |*p| p.* = randQ(r);
    for ([_]u32{ 0, 1, 4, 8, 11 }) |free| {
        const specs = [3]t.accel.FactorSpec{ .{ .eq_prefix = .{ .point = pt[0 .. n - free], .free_bits = free } }, .{ .int = ints[0] }, .{ .int = ints[1] } };
        defer g.lazy_rounds = 1;
        for ([_]u32{ 1, 3 }) |lr| for ([_]usize{ len, len - 777 }) |active| for ([_]usize{ 32, 1 << 13 }) |mw| {
            g.lazy_rounds = lr;
            const claim = randQ(r);
            var tc = Transcript.initDomain("ep");
            var rc = try t.accel.proveFactors(null, 3, &T3, a, &pool, &tc, claim, specs, len, active);
            defer rc.deinit(a);
            var acc = g.accel().*;
            acc.sc_min_work = mw;
            const before = g.stats.sc_rounds;
            var td = Transcript.initDomain("ep");
            var rd = try t.accel.proveFactors(&acc, 3, &T3, a, &pool, &td, claim, specs, len, active);
            defer rd.deinit(a);
            try std.testing.expect(g.stats.sc_rounds > before);
            for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
            for (rc.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
            for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
            try std.testing.expect(tc.draw().eql(td.draw()));
        };
    }
}

test "metal decoder layer proof equals the CPU golden digest (ext einsums on the device)" {
    const a = std.testing.allocator;
    const tf = t.transformer;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const g = try gpu();
    var acc = g.accel().*;
    acc.sc_min_work = 32; // push the small layer's sumchecks onto the device
    const cfg = tf.LayerCfg{ .log_t = 4, .log_d = 6, .log_f = 7, .log_heads = 2, .log_kv_heads = 1, .fused_qkv = true };
    var pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 6, .witness_log_cols_max = 8, .gkr_threads = 4 };
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 4242);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    b.keep_accs = true;
    b.accel = &acc;
    const c = try tf.initCtx(&b, cfg, &sw.ws, 4243);
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(cfg.log_t + cfg.log_d), 4244);
    defer a.free(x);
    _ = try tf.buildStack(&b, c, x);
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    pc.accel = &acc;
    var tm: proto.Timings = .{};
    const sc_before = g.stats.sc_calls;
    var proof = try proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), b.extAccs(), &tm);
    defer proof.deinit(a);
    try std.testing.expect(g.stats.sc_calls > sc_before + 3);
    pc.accel = null;
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
    const hx = std.fmt.bytesToHex(t.digest.fullDigest(proof), .lower);
    try std.testing.expectEqualStrings("837b19acbf642dbe2707dd2bf04a0dba665c9b3785e650e6adf057ae4f77811f", &hx);
}

test "metal per-request serving batch (dense + MoE stack, LM head, greedy check) equals CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const tf = t.transformer;
    const cfg = t.lm.ModelCfg{ .log_t = 3, .log_d = 4, .log_heads = 1, .log_kv_heads = 0, .log_f = 5, .n_layers = 2, .log_experts = 1, .log_f_expert = 4, .log_capacity = 3, .log_vocab = 6, .log_out = 1, .weight_log_cols = 3 };
    var pc = proto.Config{
        .two_level = .{ .outer = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .inner = .{ .log_blowup = 3, .n_queries = 10, .pow_bits = 1 }, .depth = 1 },
        .gkr_threads = 2,
        .batch_matmuls = true,
    };
    pc.weight_log_cols = cfg.weight_log_cols;
    var sw = try t.lm.setupWeights(a, &pool, cfg, pc, 700);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    const g = try gpu();
    var acc = g.accel().*;
    acc.sc_min_work = 16;
    acc.mle_min_len = 1;
    acc.gkr_min_log = 0;
    var pcg = pc;
    pcg.accel = &acc;
    const R = 2;
    var bs: [R]tf.Builder = undefined;
    var views: [R][]const []const i32 = undefined;
    var reqs: [R]t.serve.Request = undefined;
    var desc = try t.lm.ModelDesc.synthetic(a, cfg, 3);
    defer desc.deinit(a);
    for (0..R) |j| {
        bs[j] = tf.Builder.init(a, &pool);
        const w = try t.lm.randomTokens(a, @as(usize, 1) << cfg.log_t, @as(usize, 1) << cfg.log_vocab, 40 + j);
        defer a.free(w);
        _ = try t.lm.buildModel(&bs[j], &desc, &sw.ws, w, null);
        views[j] = try bs[j].witnessView(a);
        reqs[j] = .{ .st = bs[j].statement(), .witness = views[j], .salt = t.serve.testSalt(j) };
    }
    defer for (0..R) |j| {
        a.free(views[j]);
        bs[j].deinit();
    };
    var b_cpu = try t.serve.proveRequests(a, &pool, pc, &sw.ws, &reqs, null);
    defer b_cpu.deinit(a);
    const before = g.stats;
    var b_gpu = try t.serve.proveRequests(a, &pool, pcg, &sw.ws, &reqs, null);
    defer b_gpu.deinit(a);
    try std.testing.expect(g.stats.sc_rounds > before.sc_rounds);
    try std.testing.expect(g.stats.gkr_calls > before.gkr_calls);
    try std.testing.expectEqual(t.digest.batchDigest(b_cpu), t.digest.batchDigest(b_gpu));
    for (0..R) |j| try t.serve.verifyRequest(a, pc, reqs[j].st, proto.weightKey(&sw.ws), &b_gpu.requests[j], &b_gpu.shared, j);
}

// ---------------------------------------------------------------------------
// Hiding mode (zk.zig): device hooks give byte-identical proofs for a fixed
// (test-only) prover seed.

const zk = t.zk;

fn zkBoth(a: std.mem.Allocator, pool: *f.Pool, cfg: proto.Config, st: proto.Statement, winfos: []const t.protocol.TensorInfo, wdata: []const []const i8, wview: []const []const i32, expect_commit: bool, expect_matmul: bool) !void {
    const g = try gpu();
    var acc = g.accel().*;
    acc.sc_min_work = 16; // exercise device rounds on small tests
    acc.mle_min_len = 1;
    var cfg_gpu = cfg;
    cfg_gpu.accel = &acc;
    const seed = [_]u8{0x5a} ** 32;
    var digests: [2][32]u8 = undefined;
    const before = g.stats;
    for ([_]proto.Config{ cfg, cfg_gpu }, 0..) |c, i| {
        zk.setTestSeed(seed);
        defer zk.setTestSeed(null);
        var zw: ?zk.ZkWeights = null;
        defer if (zw) |*w| w.deinit(a);
        if (winfos.len > 0) zw = try zk.commitWeights(a, pool, c, winfos, wdata);
        var tm: proto.Timings = .{};
        var p = try zk.prove(a, pool, c, st, if (zw) |*w| w else null, wview, &tm);
        defer p.deinit(a);
        try zk.verify(a, c, st, if (zw) |*w| w.key() else null, &p);
        digests[i] = zk.proofDigest(&p);
    }
    try std.testing.expectEqualSlices(u8, &digests[0], &digests[1]);
    // the device path actually ran
    try std.testing.expect(g.stats.sc_rounds > before.sc_rounds);
    if (expect_commit) try std.testing.expect(g.stats.commit_calls > before.commit_calls);
    if (expect_matmul) try std.testing.expect(g.stats.matmul_calls > before.matmul_calls or g.stats.weight_pass_calls > before.weight_pass_calls);
}

test "metal hiding proofs equal CPU hiding proofs (seeded): product, MLP; flat and recursive PCS" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const base = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 6, .witness_log_cols_max = 7, .gkr_threads = 1, .hiding = true, .weight_mask_slots = 64 };
    var rec = base;
    rec.two_level = .{ .inner = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .depth = 1, .inner_work_shift = 0 };
    // product toy (masked op check + batch sumcheck on the device)
    {
        var built = try model.buildProduct(a, 12, 3);
        defer built.deinit(a);
        const wv = try a.alloc([]const i32, built.witness.len);
        defer a.free(wv);
        for (built.witness, 0..) |w, i| wv[i] = w;
        try zkBoth(a, &pool, base, built.statement(), &.{}, &.{}, wv, false, false);
        try zkBoth(a, &pool, rec, built.statement(), &.{}, &.{}, wv, true, false);
    }
    // fused MLP with virtual remainders (matmul accumulators, weight folds, virtual checks)
    {
        const mc = model.Mlp{ .log_t = 4, .log_d = 6, .log_f = 7, .fused = true };
        const winfos = model.mlpWeightInfos(mc);
        var wdata: [3][]i8 = undefined;
        for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
        defer for (wdata) |w| a.free(w);
        const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
        var zw0 = try zk.commitWeights(a, &pool, base, &winfos, &wvv);
        defer zw0.deinit(a);
        const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
        defer a.free(x);
        const pv = zw0.plainView();
        var built = try model.buildMlp(a, &pool, &pv, mc, x);
        defer built.deinit(a);
        const wv = try a.alloc([]const i32, built.witness.len);
        defer a.free(wv);
        for (built.witness, 0..) |w, i| wv[i] = w;
        for ([_]proto.Config{ base, rec }) |c0| {
            var c = c0;
            c.zk_virtual_remainders = true;
            try zkBoth(a, &pool, c, built.statement(), &winfos, &wvv, wv, c.two_level != null, true);
        }
    }
}
test {
    _ = @import("review_kern_metal_test.zig");
}
