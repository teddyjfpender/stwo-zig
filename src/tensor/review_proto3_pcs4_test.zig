//! Regression tests copied from the adversarial review (review_proto_test.zig
//! R1 = PROTO-3; PCS-4 shape precheck). The other review_proto tests belong
//! to other fix streams.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const pcs = @import("pcs.zig");
const Transcript = @import("transcript.zig").Transcript;

const TI = proto.TensorInfo;
const P: i64 = f.P;

fn cfg(batch: bool) proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 4, .gkr_threads = 1, .batch_matmuls = batch };
}

/// integer matmul X[T,K] . W[K,N] (i64)
fn matmulI64(a: std.mem.Allocator, x: []const i32, w: []const i8, T: usize, K: usize, N: usize) ![]i64 {
    const out = try a.alloc(i64, T * N);
    for (0..T) |t| for (0..N) |n| {
        var s: i64 = 0;
        for (0..K) |k| s += @as(i64, x[t * K + k]) * w[k * N + n];
        out[t * N + n] = s;
    };
    return out;
}

/// signed representative of v mod p in (-p/2, p/2]
fn modP(v: i64) i64 {
    var r = @mod(v, P);
    if (r > @divFloor(P, 2)) r -= P;
    return r;
}

// ---------------------------------------------------------------------------
// R1: batch_matmuls completeness when the last remainder key is a non-first
// member of a shape class.

test "R1 batch_matmuls: two same-shape matmuls (class is last) verify" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // x [2 x 4] int8, y1 = requant_1(x W0), y2 = requant_1(x W1)
    const infos = [_]TI{ TI.mat(1, 2), TI.mat(1, 2), TI.mat(1, 2) };
    const winfos = [_]TI{ TI.mat(2, 2), TI.mat(2, 2) };
    var w0: [16]i8 = undefined;
    var w1: [16]i8 = undefined;
    for (&w0, &w1, 0..) |*u, *v, i| {
        u.* = @as(i8, @intCast(i % 5)) - 2;
        v.* = @as(i8, @intCast(i % 3)) - 1;
    }
    const ops = [_]proto.Op{
        .{ .range8 = .{ .in = 0 } },
        .{ .matmul = .{ .x = 0, .w = 0, .y = 1, .shift = 1 } },
        .{ .matmul = .{ .x = 0, .w = 1, .y = 2, .shift = 1 } },
    };
    const st = proto.Statement{ .witness = &infos, .weights = &winfos, .tables = &.{}, .ops = &ops };
    var x: [8]i32 = .{ 1, -2, 3, 4, -5, 6, 7, -8 };
    const acc0 = try matmulI64(a, &x, &w0, 2, 4, 4);
    defer a.free(acc0);
    const acc1 = try matmulI64(a, &x, &w1, 2, 4, 4);
    defer a.free(acc1);
    var y1: [8]i32 = undefined;
    var y2: [8]i32 = undefined;
    for (0..8) |i| {
        y1[i] = proto.requant(acc0[i], 1);
        y2[i] = proto.requant(acc1[i], 1);
    }
    for ([_]bool{ false, true }) |bb| {
        const b = &bb;
        const pc = cfg(b.*);
        const wv = [_][]const i8{ &w0, &w1 };
        var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
        defer ws.deinit(a);
        const wit = [_][]const i32{ &x, &y1, &y2 };
        var tm: proto.Timings = .{};
        var proof = try proto.prove(a, &pool, pc, st, &ws, &wit, &tm);
        defer proof.deinit(a);
        proto.verify(a, pc, st, proto.weightKey(&ws), &proof) catch |e| {
            std.debug.print("R1: honest proof rejected with batch_matmuls={}: {s}\n", .{ b.*, @errorName(e) });
            return e;
        };
    }
}

// ---------------------------------------------------------------------------
// PCS-4: a claim point of the wrong length is rejected with OpeningShape
// before groupCoeffs slices it (was an out-of-bounds panic in safe builds).

test "PCS-4 verifyOpening rejects a short claim point before slicing it" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lr = 3;
    const lc = 4;
    var data: [1 << (lr + lc)]i8 = undefined;
    for (&data, 0..) |*d, i| d.* = @as(i8, @intCast(i % 7)) - 3;
    const m = pcs.Matrix(i8){ .data = &data, .log_rows = lr, .log_cols = lc };
    var tw = try pcs.Twiddles.init(a, lc + 2);
    defer tw.deinit(a);
    var com = try pcs.commit(i8, a, &pool, &tw, m, 2);
    defer com.deinit(a);
    const params = pcs.Params{ .log_blowup = 2, .n_queries = 6, .pow_bits = 1 };
    var pt: [lr + lc]f.QM31 = undefined;
    for (&pt, 0..) |*x, i| x.* = f.QM31.fromU32Unchecked(@intCast(3 * i + 1), 2, @intCast(i), 5);
    var ints: [data.len]i32 = undefined;
    for (data, &ints) |d, *x| x.* = d;
    const v = try f.mleEvalI32(a, &ints, &pt);
    const good = [_]pcs.Claim{.{ .point = &pt, .value = v }};
    const groups = [_]pcs.Group{.{ .claims = &good }};
    var tp = Transcript.initDomain("pcs4");
    var proof = try pcs.open(i8, a, &pool, &tp, params, &com, m, &groups, true);
    defer proof.deinit(a);
    const shape = pcs.Shape{ .log_rows = lr, .log_cols = lc, .log_blowup = 2 };
    var tv = Transcript.initDomain("pcs4");
    try pcs.verifyOpening(a, &tv, params, &tw, shape, com.root(), &groups, true, proof);
    for ([_]usize{ 0, lr - 1, lr + lc - 1, lr + lc + 1 }) |len| {
        const bad = [_]pcs.Claim{ good[0], .{ .point = pt[0..@min(len, pt.len)], .value = v } };
        var long: [lr + lc + 1]f.QM31 = undefined;
        @memcpy(long[0..pt.len], &pt);
        long[pt.len] = f.QM31.one();
        const bad_long = [_]pcs.Claim{ good[0], .{ .point = &long, .value = v } };
        const gb = [_]pcs.Group{.{ .claims = if (len > pt.len) &bad_long else &bad }};
        var tb = Transcript.initDomain("pcs4");
        try std.testing.expectError(error.OpeningShape, pcs.verifyOpening(a, &tb, params, &tw, shape, com.root(), &gb, true, proof));
    }
}
