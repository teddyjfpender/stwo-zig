//! Independent re-check variants (not committed).
const std = @import("std");
const builtin = @import("builtin");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const canonical = @import("canonical.zig");
const tfm = @import("transformer.zig");
const xt = @import("ext.zig");

const TI = proto.TensorInfo;

fn matmulI64(a: std.mem.Allocator, x: []const i32, w: []const i8, T: usize, K: usize, N: usize) ![]i64 {
    const out = try a.alloc(i64, T * N);
    for (0..T) |t| for (0..N) |n| {
        var s: i64 = 0;
        for (0..K) |k| s += @as(i64, x[t * K + k]) * w[k * N + n];
        out[t * N + n] = s;
    };
    return out;
}

fn pcfg(batch: bool) proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 4, .gkr_threads = 1, .batch_matmuls = batch };
}

// PROTO-3 variant: two interleaved shape classes; last two remainder keys are
// non-first members of different classes. Also: trailing extra sumcheck rejected,
// and every limb set to 0xFFFFFFFF -> NonCanonical (KERN-1 variant).
test "recheck PROTO-3 variant: interleaved classes + trailing sumcheck + all-limb 0xFFFFFFFF" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    // x0 [2 x 4], x1 [4 x 4]; all W [4 x 4]; classes (x0-shape) and (x1-shape) interleave
    const infos = [_]TI{ TI.mat(1, 2), TI.mat(2, 2), TI.mat(1, 2), TI.mat(2, 2), TI.mat(1, 2), TI.mat(2, 2) };
    const winfos = [_]TI{ TI.mat(2, 2), TI.mat(2, 2), TI.mat(2, 2), TI.mat(2, 2) };
    var wb: [4][16]i8 = undefined;
    for (&wb, 0..) |*w, j| for (w, 0..) |*u, i| {
        u.* = @as(i8, @intCast((i * (j + 2)) % 7)) - 3;
    };
    const ops = [_]proto.Op{
        .{ .range8 = .{ .in = 0 } },
        .{ .range8 = .{ .in = 1 } },
        .{ .matmul = .{ .x = 0, .w = 0, .y = 2, .shift = 1 } },
        .{ .matmul = .{ .x = 1, .w = 1, .y = 3, .shift = 1 } },
        .{ .matmul = .{ .x = 0, .w = 2, .y = 4, .shift = 1 } },
        .{ .matmul = .{ .x = 1, .w = 3, .y = 5, .shift = 1 } },
    };
    const st = proto.Statement{ .witness = &infos, .weights = &winfos, .tables = &.{}, .ops = &ops };
    var x0: [8]i32 = .{ 1, -2, 3, 4, -5, 6, 7, -8 };
    var x1: [16]i32 = .{ 9, -1, 0, 4, -7, 3, 2, -8, 5, 5, -6, 1, 12, -11, 3, 0 };
    const ws_raw = [_][]const i8{ &wb[0], &wb[1], &wb[2], &wb[3] };
    const xs = [_][]const i32{ &x0, &x1, &x0, &x1 };
    const Ts = [_]usize{ 2, 4, 2, 4 };
    var ys: [4][]i32 = undefined;
    for (0..4) |j| {
        const acc = try matmulI64(a, xs[j], ws_raw[j], Ts[j], 4, 4);
        defer a.free(acc);
        ys[j] = try a.alloc(i32, acc.len);
        for (acc, ys[j]) |v, *y| y.* = proto.requant(v, 1);
    }
    defer for (ys) |y| a.free(y);
    for ([_]bool{ false, true }) |batch| {
        const pc = pcfg(batch);
        var ws = try proto.commitWeights(a, &pool, pc, &winfos, &ws_raw);
        defer ws.deinit(a);
        const wit = [_][]const i32{ &x0, &x1, ys[0], ys[1], ys[2], ys[3] };
        var tm: proto.Timings = .{};
        var proof = try proto.prove(a, &pool, pc, st, &ws, &wit, &tm);
        defer proof.deinit(a);
        const key = proto.weightKey(&ws);
        proto.verify(a, pc, st, key, &proof) catch |e| {
            std.debug.print("\n[recheck] honest interleaved proof rejected batch={}: {s}\n", .{ batch, @errorName(e) });
            return e;
        };
        std.debug.print("\n[recheck] batch={} op_sumchecks={d}\n", .{ batch, proof.op_sumchecks.len });
        // trailing extra sumcheck
        {
            const sv = proof.op_sumchecks;
            const fv = proof.op_finals;
            const sx = try a.alloc(@TypeOf(sv[0]), sv.len + 1);
            defer a.free(sx);
            const fx = try a.alloc([]f.QM31, fv.len + 1);
            defer a.free(fx);
            @memcpy(sx[0..sv.len], sv);
            sx[sv.len] = sv[0];
            @memcpy(fx[0..fv.len], fv);
            fx[fv.len] = fv[0];
            proof.op_sumchecks = sx;
            proof.op_finals = fx;
            const r = proto.verify(a, pc, st, key, &proof);
            proof.op_sumchecks = sv;
            proof.op_finals = fv;
            if (r) |_| return error.TrailingSumcheckAccepted else |e| std.debug.print("[recheck] trailing sumcheck -> {s}\n", .{@errorName(e)});
        }
        // every limb -> 0xFFFFFFFF
        const n = canonical.countLimbs(&proof);
        for (0..n) |i| {
            const p = canonical.nthLimb(&proof, i).?;
            const old = p.*;
            p.* = 0xFFFF_FFFF;
            const r = proto.verify(a, pc, st, key, &proof);
            p.* = old;
            if (r) |_| return error.Accepted else |e| if (e != error.NonCanonical) {
                std.debug.print("[recheck] limb {d}: {s}\n", .{ i, @errorName(e) });
                return e;
            }
        }
        std.debug.print("[recheck] {d} limbs all NonCanonical\n", .{n});
        try proto.verify(a, pc, st, key, &proof);
    }
}

// KERN-3 variant: a range key that covers only HALF of the operand (MSB label
// fixed to 0) still sets bound[x] = 20 for the whole tensor; the other half is
// unconstrained and holds 2^30. Weights zero -> acc = 0, y = 0 (honest witness).
fn halfKeyed(batch: bool, label: u8) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const lt = 13;
    const lk = 1;
    const ln = 2;
    const winfos = [_]proto.TensorInfo{ proto.TensorInfo.mat(lk, ln), proto.TensorInfo.mat(lk, ln) };
    var w0 = [_]i8{0} ** (1 << (lk + ln));
    var w1 = [_]i8{0} ** (1 << (lk + ln));
    const wv = [_][]const i8{ &w0, &w1 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = ln, .witness_log_cols_max = 8, .gkr_threads = 1, .batch_matmuls = batch };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    var b = tfm.Builder.init(a, &pool);
    defer b.deinit();
    try b.weight_infos.appendSlice(a, &winfos);
    const n: usize = 1 << (lt + lk);
    const xd = try a.alloc(i32, n);
    // MSB (first label) = 0 half: < 2^20 ; MSB = 1 half: 2^30
    for (xd, 0..) |*v, i| v.* = if (i < n / 2) (1 << 20) - 1 else (1 << 30);
    const x = try b.add(proto.TensorInfo.mat(lt, lk), xd);
    var labs: [xt.MAXB]u8 = undefined;
    labs[0] = label;
    for (1..lt + lk) |i| labs[i] = @intCast(i - 1);
    try b.key(lt + lk - 1, try b.expr(&.{tfm.term(1, xt.Ref.w(x), &.{labs[0 .. lt + lk]})}, 0), null, .{ .range = 20 });
    _ = try b.matmul(&ws, x, 0);
    _ = try b.matmul(&ws, x, 1);
    const st = b.statement();
    try proto.validateStatement(st);
    std.debug.print("\n[recheck] operandBoundLog2 = {d} (true max |x| = 2^30)\n", .{proto.operandBoundLog2(st, x)});
    const wit = try b.witnessView(a);
    defer a.free(wit);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &ws, wit, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
}

test "recheck KERN-3 variant: half-covering (FIX0 label) range key, per-matmul" {
    if (builtin.mode == .ReleaseSafe and std.posix.getenv("RECHECK_SAFE") == null) return error.SkipZigTest;
    try halfKeyed(false, xt.FIX0);
}
