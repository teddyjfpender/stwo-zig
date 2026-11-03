//! Primitive microbenchmarks mirroring the FlashProve CPU baseline harness
//! (same shapes: L1-resident arrays of 4096, register-accumulator mul-adds,
//! column leaf hashing, Merkle tree of 2^20 leaves, RS encode at rates 1/2
//! and 1/8, sumcheck fold/round per entry). Median of >=5 reps after warm-up.
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const pcs = t.pcs;
const sc = t.sumcheck;
const M31 = f.M31;
const QM31 = f.QM31;

var sink: u32 = 0;

fn now() std.time.Instant {
    return std.time.Instant.now() catch unreachable;
}

fn median(xs: []f64) f64 {
    std.mem.sort(f64, xs, {}, std.sort.asc(f64));
    return xs[xs.len / 2];
}

fn timeIt(reps: usize, ctx: anytype, comptime func: anytype) f64 {
    var buf: [16]f64 = undefined;
    func(ctx); // warm-up
    for (0..reps) |r| {
        const t0 = now();
        func(ctx);
        buf[r] = @as(f64, @floatFromInt(now().since(t0))) / 1e9;
    }
    return median(buf[0..reps]);
}

const N = 4096;
const ITER = 2000;

const ArrCtx = struct { x: []M31, y: []M31, z: []M31, qx: []QM31, qy: []QM31, qz: []QM31 };

fn m31Mul(c: *const ArrCtx) void {
    for (0..ITER) |_| {
        for (c.x, c.y, c.z) |a, b, *o| o.* = a.mul(b);
        std.mem.doNotOptimizeAway(c.z[7]);
    }
}
fn m31MulAdd(c: *const ArrCtx) void {
    var acc = [_]M31{M31.zero()} ** 4;
    for (0..ITER) |_| {
        var i: usize = 0;
        while (i < N) : (i += 4) {
            inline for (0..4) |j| acc[j] = acc[j].add(c.x[i + j].mul(c.y[i + j]));
        }
    }
    sink +%= acc[0].v ^ acc[1].v ^ acc[2].v ^ acc[3].v;
}
fn m31MulVec(c: *const ArrCtx) void {
    // stwo packed SIMD multiply (4-lane NEON)
    for (0..ITER) |_| {
        var i: usize = 0;
        while (i < N) : (i += 4) {
            const a = core_m31.loadVec4(c.x[i..].ptr);
            const b = core_m31.loadVec4(c.y[i..].ptr);
            core_m31.storeVec4(c.z[i..].ptr, core_m31.mulVec4(a, b));
        }
        std.mem.doNotOptimizeAway(c.z[11]);
    }
}
fn qMul(c: *const ArrCtx) void {
    for (0..ITER / 4) |_| {
        for (c.qx, c.qy, c.qz) |a, b, *o| o.* = a.mul(b);
        std.mem.doNotOptimizeAway(c.qz[3]);
    }
}
fn qMulAdd(c: *const ArrCtx) void {
    var acc = [_]QM31{QM31.zero()} ** 4;
    for (0..ITER / 4) |_| {
        var i: usize = 0;
        while (i < N) : (i += 4) {
            inline for (0..4) |j| acc[j] = acc[j].add(c.qx[i + j].mul(c.qy[i + j]));
        }
    }
    sink +%= acc[0].c0.a.v ^ acc[3].c1.b.v;
}
fn qMulBaseAdd(c: *const ArrCtx) void {
    var acc = [_]QM31{QM31.zero()} ** 4;
    for (0..ITER / 4) |_| {
        var i: usize = 0;
        while (i < N) : (i += 4) {
            inline for (0..4) |j| acc[j] = acc[j].add(c.qx[i + j].mulM31(c.y[i + j]));
        }
    }
    sink +%= acc[0].c0.a.v ^ acc[3].c1.b.v;
}

const core_m31 = @import("stwo_core").fields.m31;

const HashCtx = struct { col: []M31, n: usize };
fn hashCols(c: *const HashCtx) void {
    for (0..c.n) |_| {
        const h = pcs.hashColumn(c.col);
        sink +%= h[0];
    }
}

const TreeCtx = struct { a: std.mem.Allocator, pool: *f.Pool, data: []i32, lr: u32, lc: u32, tw: *const pcs.Twiddles, lb: u32 };
fn commitRun(c: *const TreeCtx) void {
    const m = pcs.Matrix(i32){ .data = c.data, .log_rows = c.lr, .log_cols = c.lc };
    var com = pcs.commit(i32, c.a, c.pool, c.tw, m, c.lb) catch unreachable;
    sink +%= com.root()[0];
    com.deinit(c.a);
}

const EncCtx = struct { tw: *const pcs.Twiddles, buf: []M31, msg: usize, src: []const M31 };
fn encRun(c: *const EncCtx) void {
    @memcpy(c.buf[0..c.msg], c.src);
    c.tw.encode(c.buf, c.msg);
    sink +%= c.buf[5].v;
}

const T2 = [_]sc.Term{.{ .coeff = QM31.one(), .factors = &[_]u8{ 0, 1 } }};
const ScCtx = struct { a: std.mem.Allocator, pool: *f.Pool, x: []QM31, y: []QM31, wx: []QM31, wy: []QM31 };
fn scRun(c: *const ScCtx) void {
    @memcpy(c.wx, c.x);
    @memcpy(c.wy, c.y);
    var tr = t.transcript.Transcript.initDomain("prims");
    var res = sc.proveActive(2, &T2, c.a, c.pool, &tr, QM31.zero(), .{ c.wx, c.wy }, c.wx.len) catch unreachable;
    sink +%= res.finals[0].c0.a.v;
    res.deinit(c.a);
}

pub fn run(a: std.mem.Allocator, threads: usize) !void {
    const out = std.fs.File.stdout().deprecatedWriter();
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    const x = try a.alloc(M31, N);
    const y = try a.alloc(M31, N);
    const z = try a.alloc(M31, N);
    const qx = try a.alloc(QM31, N);
    const qy = try a.alloc(QM31, N);
    const qz = try a.alloc(QM31, N);
    for (0..N) |i| {
        x[i] = M31.fromCanonical(r.intRangeLessThan(u32, 0, f.P));
        y[i] = M31.fromCanonical(r.intRangeLessThan(u32, 0, f.P));
        qx[i] = QM31.fromU32Unchecked(r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P));
        qy[i] = QM31.fromU32Unchecked(r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P), r.intRangeLessThan(u32, 0, f.P));
    }
    const ac = ArrCtx{ .x = x, .y = y, .z = z, .qx = qx, .qy = qy, .qz = qz };
    const ops_m = @as(f64, @floatFromInt(N * ITER));
    const ops_q = @as(f64, @floatFromInt(N * (ITER / 4)));
    try out.print("{{\"bench\":\"prims\",\"threads_note\":\"single thread unless stated\",", .{});
    try out.print("\"m31_mul_per_s\":{e:.4},", .{ops_m / timeIt(5, &ac, m31Mul)});
    try out.print("\"m31_muladd_per_s\":{e:.4},", .{ops_m / timeIt(5, &ac, m31MulAdd)});
    try out.print("\"m31_mul_simd4_per_s\":{e:.4},", .{ops_m / timeIt(5, &ac, m31MulVec)});
    try out.print("\"qm31_mul_per_s\":{e:.4},", .{ops_q / timeIt(5, &ac, qMul)});
    try out.print("\"qm31_muladd_per_s\":{e:.4},", .{ops_q / timeIt(5, &ac, qMulAdd)});
    try out.print("\"qm31_x_m31_muladd_per_s\":{e:.4},", .{ops_q / timeIt(5, &ac, qMulBaseAdd)});

    // column leaf hashing: 2048-row column (FlashProve weight-table width) and 3-row column
    const col = try a.alloc(M31, 2048);
    for (col, 0..) |*v, i| v.* = M31.fromCanonical(@intCast(i * 7919 % f.P));
    const hc = HashCtx{ .col = col, .n = 2000 };
    const th = timeIt(5, &hc, hashCols);
    try out.print("\"blake2s_leaf_2048x4B_MBps\":{d:.1},", .{@as(f64, 2000.0 * 2048.0 * 4.0) / th / 1e6});
    const hc3 = HashCtx{ .col = col[0..3], .n = 200000 };
    const th3 = timeIt(5, &hc3, hashCols);
    try out.print("\"blake2s_leaf_3sym_per_s\":{e:.4},", .{200000.0 / th3});

    // RS encode throughput (one row) at rate 1/2 and 1/8
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    try out.print("\"rs_encode\":[", .{});
    var first = true;
    for ([_]u32{ 16, 20, 22 }) |lm| {
        for ([_]u32{ 1, 3 }) |lb| {
            var tw = try pcs.Twiddles.init(a, lm + lb);
            defer tw.deinit(a);
            const msg = @as(usize, 1) << @intCast(lm);
            const buf = try a.alloc(M31, msg << @intCast(lb));
            defer a.free(buf);
            const src = try a.alloc(M31, msg);
            defer a.free(src);
            for (src, 0..) |*v, i| v.* = M31.fromCanonical(@intCast(i % 1000));
            const ec = EncCtx{ .tw = &tw, .buf = buf, .msg = msg, .src = src };
            const te = timeIt(5, &ec, encRun);
            if (!first) try out.print(",", .{});
            first = false;
            try out.print("{{\"log_msg\":{d},\"rate\":\"1/{d}\",\"msg_elems_per_s\":{e:.4},\"codeword_symbols_per_s\":{e:.4}}}", .{ lm, @as(u32, 1) << @intCast(lb), @as(f64, @floatFromInt(msg)) / te, @as(f64, @floatFromInt(buf.len)) / te });
        }
    }
    try out.print("],", .{});

    // commit (encode + Merkle) of a 2^20-element table at rate 1/8, 3 rows-ish shape (2^4 rows x 2^16)
    {
        const data = try a.alloc(i32, 1 << 20);
        defer a.free(data);
        for (data, 0..) |*v, i| v.* = @intCast(i % 251);
        var tw = try pcs.Twiddles.init(a, 16 + 3);
        defer tw.deinit(a);
        const tc = TreeCtx{ .a = a, .pool = &pool, .data = data, .lr = 4, .lc = 16, .tw = &tw, .lb = 3 };
        try out.print("\"commit_2p20_rate1_8_s\":{d:.4},", .{timeIt(5, &tc, commitRun)});
    }

    // sumcheck product (deg 2) over 2^20 QM31: ns per entry (rounds + folds)
    {
        const n = 1 << 20;
        const sx = try a.alloc(QM31, n);
        const sy = try a.alloc(QM31, n);
        const wx = try a.alloc(QM31, n);
        const wy = try a.alloc(QM31, n);
        defer a.free(sx);
        defer a.free(sy);
        defer a.free(wx);
        defer a.free(wy);
        for (0..n) |i| {
            sx[i] = QM31.fromU32Unchecked(@intCast(i), 1, 2, 3);
            sy[i] = QM31.fromU32Unchecked(@intCast(i * 3), 5, 6, 7);
        }
        const scc = ScCtx{ .a = a, .pool = &pool, .x = sx, .y = sy, .wx = wx, .wy = wy };
        const ts = timeIt(5, &scc, scRun);
        try out.print("\"sumcheck_deg2_2p20_ns_per_entry\":{d:.3},\"threads\":{d}}}\n", .{ ts * 1e9 / @as(f64, n), threads });
    }
    std.mem.doNotOptimizeAway(sink);
}
