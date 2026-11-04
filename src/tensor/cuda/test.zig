//! CPU vs CUDA bit-identity tests for the tensor prover's CUDA backend.
//!
//! The same file runs in two builds:
//!   zig build test-cuda-emu      kernels + host layer compiled as C++ and run
//!                                on the CPU (any machine; no GPU)
//!   zig build test-cuda -Dcuda   the nvcc build on an NVIDIA device
//! so a pass here is evidence about the exact kernel indexing/arithmetic and
//! the host layer, and the GPU host re-runs the identical assertions.
const std = @import("std");
const t = @import("stwo_tensor");
const cuda = @import("stwo_tensor_cuda");
const f = t.field;
const pcs = t.pcs;
const sc = t.sumcheck;
const proto = t.protocol;
const model = t.model;
const Transcript = t.transcript.Transcript;
const M31 = f.M31;
const QM31 = f.QM31;
const proofDigest = t.digest.proofDigest;

var dev_singleton: ?*cuda.Cuda = null;
fn dev() !*cuda.Cuda {
    if (dev_singleton) |d| return d;
    dev_singleton = try cuda.Cuda.init(std.heap.c_allocator, 0);
    return dev_singleton.?;
}

fn randQ(r: std.Random) QM31 {
    return QM31.fromU32Unchecked(r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P));
}

fn edgeLimb(r: std.Random) u32 {
    return switch (r.uintLessThan(u8, 6)) {
        0 => 0,
        1 => 1,
        2 => f.P - 1,
        3 => f.P - 2,
        4 => 1 << 30,
        else => r.intRangeLessThan(u32, 0, f.P),
    };
}

test "cuda QM31 mul (lazy reduction) matches the Zig field, incl. edge limbs" {
    const a = std.testing.allocator;
    const d = try dev();
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    const n = 20000;
    const x = try a.alloc(QM31, n);
    defer a.free(x);
    const y = try a.alloc(QM31, n);
    defer a.free(y);
    for (x, y) |*u, *v| {
        u.* = QM31.fromU32Unchecked(edgeLimb(r), edgeLimb(r), edgeLimb(r), edgeLimb(r));
        v.* = QM31.fromU32Unchecked(edgeLimb(r), edgeLimb(r), edgeLimb(r), edgeLimb(r));
    }
    const out = try a.alloc(QM31, n);
    defer a.free(out);
    try std.testing.expectEqual(@as(c_int, 0), cuda.tc_qm_mul_batch(d.ctx, cuda.limbsPtr(x), cuda.limbsPtr(y), n, @ptrCast(out.ptr)));
    for (x, y, out) |u, v, w| try std.testing.expect(u.mul(v).eql(w));
}

test "cuda eq tables (two-launch split build) match f.eqTable" {
    const a = std.testing.allocator;
    const d = try dev();
    var prng = std.Random.DefaultPrng.init(4);
    const r = prng.random();
    for ([_]u32{ 0, 1, 2, 5, 9, 14 }) |n| {
        const pt = try a.alloc(QM31, n);
        defer a.free(pt);
        for (pt) |*p| p.* = randQ(r);
        const gamma = randQ(r);
        const want = try f.eqTable(a, pt, gamma);
        defer a.free(want);
        const got = try a.alloc(QM31, want.len);
        defer a.free(got);
        const gl = f.limbs(gamma);
        try std.testing.expectEqual(@as(c_int, 0), cuda.tc_eq_table(d.ctx, cuda.limbsPtr(pt), n, &gl, @ptrCast(got.ptr)));
        for (want, got) |u, v| try std.testing.expect(u.eql(v));
    }
}

fn checkCommit(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, d: *cuda.Cuda, lr: u32, lc: u32, lb: u32, rows_used: ?usize, seed: u64) !void {
    const R = @as(usize, 1) << @intCast(lr);
    const C = @as(usize, 1) << @intCast(lc);
    const data = try a.alloc(T, R * C);
    defer a.free(data);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    for (data) |*x| x.* = if (T == i8) rnd.int(i8) else @intCast(rnd.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
    if (T == i32 and data.len > 2) {
        data[0] = std.math.minInt(i32);
        data[1] = std.math.maxInt(i32);
    }
    const m = pcs.Matrix(T){ .data = data, .log_rows = lr, .log_cols = lc, .rows_used = rows_used };
    var tw = try pcs.Twiddles.init(a, lc + lb);
    defer tw.deinit(a);
    var cpu = try pcs.commit(T, a, pool, &tw, m, lb);
    defer cpu.deinit(a);
    var got = (try d.commit(T, a, &tw, m, lb)).?;
    defer got.deinit(a);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(cpu.enc), std.mem.sliceAsBytes(got.enc));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(cpu.tree.nodes[1..]), std.mem.sliceAsBytes(got.tree.nodes[1..]));
    try std.testing.expectEqual(cpu.root(), got.root());
}

test "cuda commit matches CPU (circle-FFT encoding, column-major codeword, Blake2s leaves, Merkle tree)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
    // tail-only shapes, global layers (log_c > 11), odd rows_used, blowups 1..3,
    // a single coefficient (all layers are copies)
    try checkCommit(i32, a, &pool, d, 4, 1, 2, null, 1);
    try checkCommit(i32, a, &pool, d, 3, 2, 1, null, 2);
    try checkCommit(i8, a, &pool, d, 5, 6, 2, 19, 3);
    try checkCommit(i32, a, &pool, d, 6, 10, 2, 37, 4);
    try checkCommit(i32, a, &pool, d, 3, 13, 1, null, 5);
    try checkCommit(i8, a, &pool, d, 4, 12, 2, 13, 6);
    try checkCommit(i8, a, &pool, d, 2, 0, 3, null, 7);
    // several row chunks (Blake2s leaf states carried across launches)
    tc_chunk(d, 16);
    defer tc_chunk(d, 0);
    try checkCommit(i32, a, &pool, d, 7, 8, 2, 83, 8);
    try checkCommit(i8, a, &pool, d, 6, 9, 1, null, 9);
}

fn tc_chunk(d: *cuda.Cuda, rows: u64) void {
    cuda.tc_set_commit_chunk_rows(d.ctx, rows);
}

const T_PROD2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const T_EQ3 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }};
const T_PRODUCT = [_]sc.Term{ .{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1, 2 } }, .{ .coeff = QM31.fromU32Unchecked(f.P - 1, 0, 0, 0), .factors = &[_]u8{ 0, 3 } } };

fn checkSumcheck(comptime NF: usize, comptime terms: []const sc.Term, a: std.mem.Allocator, pool: *f.Pool, d: *cuda.Cuda, n: u32, active: usize, seed: u64) !void {
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
    var claim = QM31.zero();
    for (0..len) |i| {
        var cur: [NF]QM31 = undefined;
        for (0..NF) |j| cur[j] = cpu_f[j][i];
        claim = claim.add(sc.evalTerms(terms, &cur));
    }
    var tcp = Transcript.initDomain("sc");
    var rc = try sc.proveActive(NF, terms, a, pool, &tcp, claim, cpu_f, active);
    defer rc.deinit(a);
    var acc = d.accel().*;
    acc.sc_min_work = 16;
    const before = d.stats();
    var td = Transcript.initDomain("sc");
    var rd = try t.accel.proveActive(&acc, NF, terms, a, pool, &td, claim, dev_f, active);
    defer rd.deinit(a);
    const after = d.stats();
    try std.testing.expect(after.sc_rounds > before.sc_rounds);
    // transfer budget: factors in once, 48 bytes per round, the folded tail out
    const rounds = after.sc_rounds - before.sc_rounds;
    try std.testing.expectEqual(@as(u64, NF * len * 16), after.h2d_bytes - before.h2d_bytes);
    try std.testing.expect(after.d2h_bytes - before.d2h_bytes <= rounds * 48 + NF * 16 * (len >> @intCast(rounds)));
    try std.testing.expectEqual(rounds + 1, after.launches - before.launches);
    try std.testing.expectEqual(rc.proof.deg, rd.proof.deg);
    for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
    for (rc.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
    for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
    try std.testing.expect(tcp.draw().eql(td.draw()));
}

test "cuda sumcheck (fused fold + round, last-block reduction) matches CPU (deg 2/3, partial active)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
    try checkSumcheck(2, &T_PROD2, a, &pool, d, 12, 1 << 12, 1);
    try checkSumcheck(2, &T_PROD2, a, &pool, d, 13, 5000, 2);
    try checkSumcheck(3, &T_EQ3, a, &pool, d, 11, 1500, 3);
    try checkSumcheck(4, &T_PRODUCT, a, &pool, d, 12, 4096, 4);
    try checkSumcheck(4, &T_PRODUCT, a, &pool, d, 14, 9999, 5);
    // 2^17 work items: a 128-block grid, 4 grid-stride iterations per thread, and
    // 128 last-block partials. The SC_MAX_GROUPS = 1024 cap (work >= 2^20) is
    // not reached by any test.
    try checkSumcheck(2, &T_PROD2, a, &pool, d, 18, 200_001, 6);
}

test "cuda lazy factors (int vectors, eq sums at offsets, eq prefix) match CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
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
    var p2: [0]QM31 = undefined;
    for (&p0) |*p| p.* = randQ(r);
    for (&p1) |*p| p.* = randQ(r);
    const claims = [_]t.accel.BatchClaim{ .{ .offset = 0, .point = &p0, .gamma = randQ(r) }, .{ .offset = 1 << 13, .point = &p1, .gamma = randQ(r) }, .{ .offset = 77, .point = &p2, .gamma = randQ(r) } };
    const specs = [4]t.accel.FactorSpec{ .{ .eq = &claims }, .{ .int = ints[0] }, .{ .int = ints[1] }, .{ .int = ints[2] } };
    for ([_]usize{ len, len - 3001 }) |active| for ([_]usize{ 32, 1 << 11, 1 << 13 }) |mw| {
        const claim = randQ(r);
        var tcp = Transcript.initDomain("lz");
        var rc = try t.accel.proveFactors(null, 4, &T_PRODUCT, a, &pool, &tcp, claim, specs, len, active);
        defer rc.deinit(a);
        var acc = d.accel().*;
        acc.sc_min_work = mw;
        const before = d.stats();
        var td = Transcript.initDomain("lz");
        var rd = try t.accel.proveFactors(&acc, 4, &T_PRODUCT, a, &pool, &td, claim, specs, len, active);
        defer rd.deinit(a);
        const after = d.stats();
        try std.testing.expect(after.sc_rounds > before.sc_rounds);
        // the eq factor never crosses: only int32 vectors and points go up
        try std.testing.expect(after.h2d_bytes - before.h2d_bytes < 3 * len * 4 + 4096);
        for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
        for (rc.point, rd.point) |x, y| try std.testing.expect(x.eql(y));
        for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
        try std.testing.expect(tcp.draw().eql(td.draw()));
    };
    var pt: [n]QM31 = undefined;
    for (&pt) |*p| p.* = randQ(r);
    for ([_]u32{ 0, 1, 4, 11 }) |free| {
        const sp = [3]t.accel.FactorSpec{ .{ .eq_prefix = .{ .point = pt[0 .. n - free], .free_bits = free } }, .{ .int = ints[0] }, .{ .int = ints[1] } };
        for ([_]usize{ len, len - 777 }) |active| {
            const claim = randQ(r);
            var tcp = Transcript.initDomain("ep");
            var rc = try t.accel.proveFactors(null, 3, &T_EQ3, a, &pool, &tcp, claim, sp, len, active);
            defer rc.deinit(a);
            var acc = d.accel().*;
            acc.sc_min_work = 32;
            var td = Transcript.initDomain("ep");
            var rd = try t.accel.proveFactors(&acc, 3, &T_EQ3, a, &pool, &td, claim, sp, len, active);
            defer rd.deinit(a);
            for (rc.proof.rounds, rd.proof.rounds) |x, y| for (0..sc.MAX_DEG) |k| try std.testing.expect(x.evals[k].eql(y.evals[k]));
            for (rc.finals, rd.finals) |x, y| try std.testing.expect(x.eql(y));
            try std.testing.expect(tcp.draw().eql(td.draw()));
        }
    }
}

test "cuda weight passes (combine rows, row dots; i8 lazy int64 limbs) match CPU; pinned weights skip the upload" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
    const saved = d.min_pass_elems;
    d.min_pass_elems = 0;
    defer d.min_pass_elems = saved;
    var prng = std.Random.DefaultPrng.init(21);
    const r = prng.random();
    for ([_][3]u32{ .{ 8, 9, 0 }, .{ 11, 7, 1 }, .{ 6, 12, 2 }, .{ 10, 2, 3 } }) |sh| {
        const R = @as(usize, 1) << @intCast(sh[0]);
        const C = @as(usize, 1) << @intCast(sh[1]);
        const d8 = try a.alloc(i8, R * C + 1);
        defer a.free(d8);
        for (d8) |*x| x.* = r.int(i8);
        d8[1] = -128;
        const d32 = try a.alloc(i32, R * C);
        defer a.free(d32);
        for (d32) |*x| x.* = @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P));
        d32[0] = std.math.minInt(i32);
        const used = R - sh[2] * 3;
        const m8 = pcs.Matrix(i8){ .data = d8[1..], .log_rows = sh[0], .log_cols = sh[1], .rows_used = used };
        const m32 = pcs.Matrix(i32){ .data = d32, .log_rows = sh[0], .log_cols = sh[1], .rows_used = used };
        var cf: [3][]QM31 = undefined;
        for (&cf) |*c| {
            c.* = try a.alloc(QM31, R);
            for (c.*) |*x| x.* = QM31.fromU32Unchecked(edgeLimb(r), edgeLimb(r), edgeLimb(r), edgeLimb(r));
        }
        defer for (cf) |c| a.free(c);
        const cv = [_][]const QM31{ cf[0], cf[1], cf[2] };
        inline for (.{ i8, i32 }) |T| {
            const m = if (T == i8) m8 else m32;
            const want = try pcs.combineRows(T, a, &pool, m, &cv, if (T == i8) 7 else 31);
            defer {
                for (want) |w| a.free(w);
                a.free(want);
            }
            const got = (try d.combine(T, a, m, &cv)).?;
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
        const want = try t.linalg.rowDots(i8, a, &pool, mfull, vec, 7);
        defer a.free(want);
        const got = try t.accel.rowDots(d.accel(), a, &pool, mfull, vec, 7);
        defer a.free(got);
        for (want, got) |x, y| try std.testing.expect(x.eql(y));
        // pinned: the matrix stays on the device, a second pass uploads only the vector
        try d.pin(std.mem.sliceAsBytes(mfull.data[0 .. R * C]));
        defer d.unpinAll();
        const before = d.stats();
        const got2 = try t.accel.rowDots(d.accel(), a, &pool, mfull, vec, 7);
        defer a.free(got2);
        const after = d.stats();
        try std.testing.expectEqual(@as(u64, C * 16), after.h2d_bytes - before.h2d_bytes);
        try std.testing.expectEqual(before.resident_hits + 1, after.resident_hits);
        for (want, got2) |x, y| try std.testing.expect(x.eql(y));
    }
}

test "cuda matmul accumulators match CPU" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
    const shapes = [_][3]u32{ .{ 0, 5, 3 }, .{ 4, 6, 7 }, .{ 7, 9, 6 }, .{ 6, 10, 8 }, .{ 2, 3, 1 } };
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    for (shapes) |sh| {
        const T = @as(usize, 1) << @intCast(sh[0]);
        const K = @as(usize, 1) << @intCast(sh[1]);
        const N = @as(usize, 1) << @intCast(sh[2]);
        const x = try a.alloc(i32, T * K);
        defer a.free(x);
        for (x) |*v| v.* = if (r.boolean()) r.intRangeAtMost(i32, -128, 127) else r.intRangeAtMost(i32, -(1 << 15) + 1, (1 << 15) - 1);
        const w = try a.alloc(i8, K * N + 3);
        defer a.free(w);
        for (w) |*v| v.* = r.int(i8);
        const wm = pcs.Matrix(i8){ .data = w[3..], .log_rows = sh[1], .log_cols = sh[2] };
        const xi = proto.TensorInfo.mat(sh[0], sh[1]);
        const cpu = try proto.matmulAcc(a, &pool, xi, x, wm);
        defer a.free(cpu);
        const got = (try t.accel.matmulAcc(d.accel(), a, sh[0], x, wm)).?;
        defer a.free(got);
        try std.testing.expectEqualSlices(i64, cpu, got);
    }
}

test "cuda MLE evaluation of integer vectors matches CPU" {
    const a = std.testing.allocator;
    const d = try dev();
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    for ([_]u32{ 0, 1, 5, 12, 17 }) |n| {
        const len = @as(usize, 1) << @intCast(n);
        const v = try a.alloc(i32, len);
        defer a.free(v);
        for (v) |*x| x.* = switch (r.uintLessThan(u8, 4)) {
            0 => 0,
            1 => r.intRangeAtMost(i32, -128, 127),
            2 => if (r.boolean()) std.math.minInt(i32) else std.math.maxInt(i32),
            else => @intCast(r.intRangeLessThan(i64, -(@as(i64, 1) << 30), f.P)),
        };
        const pt = try a.alloc(QM31, n);
        defer a.free(pt);
        for (pt) |*p| p.* = randQ(r);
        const want = try f.mleEvalI32(a, v, pt);
        var acc = d.accel().*;
        acc.mle_min_len = 1;
        const before = d.stats().mles;
        const got = try t.accel.mleEvalI32(&acc, a, v, pt);
        try std.testing.expectEqual(before + 1, d.stats().mles);
        try std.testing.expect(want.eql(got));
    }
}

test "cuda batched LogUp-GKR fraction layer (one launch, mixed heights) matches the fraction sum" {
    const a = std.testing.allocator;
    const d = try dev();
    var prng = std.Random.DefaultPrng.init(8);
    const r = prng.random();
    const logs = [_]u32{ 10, 1, 7, 3, 12, 1 };
    var in_off: [logs.len]u64 = undefined;
    var out_off: [logs.len + 1]u64 = undefined;
    var n_in: u64 = 0;
    for (logs, 0..) |lg, k| {
        in_off[k] = n_in;
        out_off[k] = n_in / 2;
        n_in += @as(u64, 1) << @intCast(lg);
    }
    out_off[logs.len] = n_in / 2;
    const num = try a.alloc(QM31, n_in);
    defer a.free(num);
    const den = try a.alloc(QM31, n_in);
    defer a.free(den);
    for (num, den) |*x, *y| {
        x.* = randQ(r);
        y.* = randQ(r);
    }
    const on = try a.alloc(QM31, n_in / 2);
    defer a.free(on);
    const od = try a.alloc(QM31, n_in / 2);
    defer a.free(od);
    const before = d.stats().launches;
    try std.testing.expectEqual(@as(c_int, 0), cuda.tc_gkr_layer(d.ctx, &in_off, &out_off, logs.len, cuda.limbsPtr(num), cuda.limbsPtr(den), n_in, @ptrCast(on.ptr), @ptrCast(od.ptr)));
    try std.testing.expectEqual(before + 1, d.stats().launches);
    for (0..n_in / 2) |j| {
        const n0 = num[2 * j];
        const n1 = num[2 * j + 1];
        const d0 = den[2 * j];
        const d1 = den[2 * j + 1];
        try std.testing.expect(on[j].eql(n0.mul(d1).add(n1.mul(d0))));
        try std.testing.expect(od[j].eql(d0.mul(d1)));
    }
}

// ---------------------------------------------------------------------------
// Whole proofs: identical digests with the CUDA accelerator.

fn proveBoth(a: std.mem.Allocator, pool: *f.Pool, pc_cpu: proto.Config, st: proto.Statement, ws_cpu: *const proto.WeightStore, ws_dev: *const proto.WeightStore, wview: []const []const i32) !void {
    const d = try dev();
    var acc = d.accel().*;
    acc.sc_min_work = 16;
    acc.mle_min_len = 1;
    var pc_dev = pc_cpu;
    pc_dev.accel = &acc;
    var tm: proto.Timings = .{};
    var p_cpu = try proto.prove(a, pool, pc_cpu, st, ws_cpu, wview, &tm);
    defer p_cpu.deinit(a);
    const before = d.stats();
    var p_dev = try proto.prove(a, pool, pc_dev, st, ws_dev, wview, &tm);
    defer p_dev.deinit(a);
    const after = d.stats();
    try std.testing.expect(after.commits > before.commits);
    try std.testing.expect(after.sc_rounds > before.sc_rounds);
    try std.testing.expectEqual(proofDigest(p_cpu), proofDigest(p_dev));
    try proto.verify(a, pc_cpu, st, proto.weightKey(ws_cpu), &p_dev);
}

test "cuda proof digest equals CPU: product toy" {
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

test "cuda proof digest equals CPU: small MLP (device weight commitment and matmuls too)" {
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
    const d = try dev();
    const saved = d.min_pass_elems;
    d.min_pass_elems = 0;
    defer d.min_pass_elems = saved;
    var pcg = pc;
    pcg.accel = d.accel();
    var ws_dev = try proto.commitWeights(a, &pool, pcg, &winfos, &wv);
    defer ws_dev.deinit(a);
    try std.testing.expectEqual(ws.com.root(), ws_dev.com.root());
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    {
        var cfg_d = cfg;
        cfg_d.accel = d.accel();
        const before = d.stats().matmuls;
        var built_d = try model.buildMlp(a, &pool, &ws, cfg_d, x);
        defer built_d.deinit(a);
        try std.testing.expect(d.stats().matmuls >= before + 3);
        for (built.witness, built_d.witness) |u, v| try std.testing.expectEqualSlices(i32, u, v);
    }
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    const wp_before = d.stats().weight_passes;
    try proveBoth(a, &pool, pc, built.statement(), &ws, &ws_dev, wview);
    try std.testing.expect(d.stats().weight_passes > wp_before);
}

test "cuda decoder layer proof equals the CPU golden digest" {
    const a = std.testing.allocator;
    const tf = t.transformer;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const d = try dev();
    var acc = d.accel().*;
    acc.sc_min_work = 32;
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
    const before = d.stats().sc_sessions;
    var proof = try proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wv, b.coreAccs(), b.extAccs(), &tm);
    defer proof.deinit(a);
    try std.testing.expect(d.stats().sc_sessions > before + 3);
    pc.accel = null;
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
    const hx = std.fmt.bytesToHex(t.digest.fullDigest(proof), .lower);
    try std.testing.expectEqualStrings("837b19acbf642dbe2707dd2bf04a0dba665c9b3785e650e6adf057ae4f77811f", &hx);
}

test "cuda per-request serving batch (dense + MoE stack, LM head, greedy check) equals CPU" {
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
    const d = try dev();
    var acc = d.accel().*;
    acc.sc_min_work = 16;
    acc.mle_min_len = 1;
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
    const before = d.stats();
    var b_dev = try t.serve.proveRequests(a, &pool, pcg, &sw.ws, &reqs, null);
    defer b_dev.deinit(a);
    try std.testing.expect(d.stats().sc_rounds > before.sc_rounds);
    try std.testing.expectEqual(t.digest.batchDigest(b_cpu), t.digest.batchDigest(b_dev));
    for (0..R) |j| try t.serve.verifyRequest(a, pc, reqs[j].st, proto.weightKey(&sw.ws), &b_dev.requests[j], &b_dev.shared, j);
}

test "cuda backend reports its build" {
    const d = try dev();
    std.debug.print("\ntensor cuda backend: {s} (emulation={})\n", .{ d.deviceName(), d.isEmulation() });
}
