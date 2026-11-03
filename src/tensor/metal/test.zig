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

    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    try proveBoth(a, &pool, pc, built.statement(), &ws, &ws_gpu, wview);
}
