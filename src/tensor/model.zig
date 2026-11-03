//! Integer transformer blocks expressed as tensor-protocol statements.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const proto = @import("protocol.zig");
const accel = @import("accel.zig");

const TensorInfo = proto.TensorInfo;

pub fn siluTable() proto.Table {
    var t: proto.Table = undefined;
    for (0..256) |i| {
        const v: f64 = @as(f64, @floatFromInt(@as(i32, @intCast(i)) - 128)) / 16.0;
        const s = v / (1.0 + @exp(-v));
        var q: i32 = @intFromFloat(@round(s * 16.0));
        q = std.math.clamp(q, -128, 127);
        t.values[i] = @intCast(q);
    }
    return t;
}

/// Smallest shift s >= 1 with requant(acc, s) in [-128, 128) for all entries.
pub fn chooseShift(acc: []const i64) u5 {
    var mx: i64 = 0;
    for (acc) |v| mx = @max(mx, @as(i64, @intCast(@abs(v))));
    var s: u5 = 1;
    while (s < 30) : (s += 1) {
        const lim = (@as(i64, 127) << s) - (@as(i64, 1) << (s - 1));
        if (mx <= lim) break;
    }
    return s;
}

pub const Mlp = struct {
    log_t: u32,
    log_d: u32,
    log_f: u32,
    /// fused SwiGLU gate: one glu lookup instead of silu lookup + hadamard
    fused: bool = true,
    /// optional device accelerator for the forward matmuls (same witness)
    accel: ?*const accel.Accel = null,
};

fn fwdMatmul(cfg: Mlp, a: std.mem.Allocator, pool: *f.Pool, xi: TensorInfo, x: []const i32, wm: pcs.Matrix(i8)) ![]i64 {
    return (try accel.matmulAcc(cfg.accel, a, xi.log_dims[0], x, wm)) orelse proto.matmulAcc(a, pool, xi, x, wm);
}

pub const Built = struct {
    witness_infos: []TensorInfo,
    weight_infos: []TensorInfo,
    tables: []proto.Table,
    ops: []proto.Op,
    witness: [][]i32,
    /// per op: integer accumulator kept from the forward pass (matmul/hadamard), for
    /// protocol.proveWithAccumulators; empty when the builder does not keep them
    accs: []?[]i64 = &.{},

    pub fn statement(self: *const Built) proto.Statement {
        return .{ .witness = self.witness_infos, .weights = self.weight_infos, .tables = self.tables, .ops = self.ops };
    }

    pub fn deinit(self: *Built, a: std.mem.Allocator) void {
        a.free(self.witness_infos);
        a.free(self.weight_infos);
        a.free(self.tables);
        a.free(self.ops);
        for (self.witness) |w| a.free(w);
        a.free(self.witness);
        for (self.accs) |x| if (x) |v| a.free(v);
        if (self.accs.len > 0) a.free(self.accs);
    }
};

pub fn randomWeights(a: std.mem.Allocator, n: usize, seed: u64, lo: i8, hi: i8) ![]i8 {
    const w = try a.alloc(i8, n);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    for (w) |*x| x.* = r.intRangeAtMost(i8, lo, hi);
    return w;
}

pub fn randomInput(a: std.mem.Allocator, n: usize, seed: u64) ![]i32 {
    const x = try a.alloc(i32, n);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    for (x) |*v| v.* = r.intRangeAtMost(i32, -64, 63);
    return x;
}

fn requantAll(a: std.mem.Allocator, acc: []const i64, s: u5) ![]i32 {
    const y = try a.alloc(i32, acc.len);
    for (acc, y) |v, *o| o.* = proto.requant(v, s);
    return y;
}

/// SwiGLU MLP: out = requant(requant(silu(xWg) * xWu) Wd). Weights ids: 0=Wg,1=Wu,2=Wd.
pub fn buildMlp(a: std.mem.Allocator, pool: *f.Pool, ws: *const proto.WeightStore, cfg: Mlp, x_in: []const i32) !Built {
    const T = @as(usize, 1) << @intCast(cfg.log_t);
    _ = T;
    var infos: std.ArrayList(TensorInfo) = .empty;
    var wit: std.ArrayList([]i32) = .empty;
    var ops: std.ArrayList(proto.Op) = .empty;
    const tables = try a.alloc(proto.Table, 1);
    tables[0] = siluTable();

    // 0: x
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_d));
    try wit.append(a, try a.dupe(i32, x_in));
    try ops.append(a, .{ .range8 = .{ .in = 0 } });
    // gate (1), up (2)
    const xi = infos.items[0];
    const acc_g = try fwdMatmul(cfg, a, pool, xi, wit.items[0], ws.matrix(0));
    const sg = chooseShift(acc_g);
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_f));
    try wit.append(a, try requantAll(a, acc_g, sg));
    try ops.append(a, .{ .matmul = .{ .x = 0, .w = 0, .y = 1, .shift = sg } });
    const acc_u = try fwdMatmul(cfg, a, pool, xi, wit.items[0], ws.matrix(1));
    const su = chooseShift(acc_u);
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_f));
    try wit.append(a, try requantAll(a, acc_u, su));
    try ops.append(a, .{ .matmul = .{ .x = 0, .w = 1, .y = 2, .shift = su } });
    const n_tf = wit.items[1].len;
    if (cfg.fused) {
        // h = clamp8(requant(silu(gate) * up)) (3), one glu lookup
        const acc_h = try a.alloc(i64, n_tf);
        defer a.free(acc_h);
        for (wit.items[1], wit.items[2], acc_h) |g, q, *o| o.* = @as(i64, tables[0].values[@intCast(g + 128)]) * q;
        const sh = chooseShift(acc_h);
        const tmp_st = proto.Statement{ .witness = &.{}, .weights = &.{}, .tables = tables, .ops = &.{} };
        const hv = try a.alloc(i32, n_tf);
        for (wit.items[1], wit.items[2], hv) |g, q, *o| o.* = @intCast(proto.gluValue(tmp_st, 0, sh, g, q));
        try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_f));
        try wit.append(a, hv);
        try ops.append(a, .{ .glu = .{ .g = 1, .u = 2, .h = 3, .table = 0, .shift = sh } });
        const acc_o = try fwdMatmul(cfg, a, pool, infos.items[3], wit.items[3], ws.matrix(2));
        const so = chooseShift(acc_o);
        try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_d));
        try wit.append(a, try requantAll(a, acc_o, so));
        try ops.append(a, .{ .matmul = .{ .x = 3, .w = 2, .y = 4, .shift = so } });
        const winfos_f = try a.alloc(TensorInfo, 3);
        winfos_f[0] = TensorInfo.mat(cfg.log_d, cfg.log_f);
        winfos_f[1] = TensorInfo.mat(cfg.log_d, cfg.log_f);
        winfos_f[2] = TensorInfo.mat(cfg.log_f, cfg.log_d);
        return .{
            .witness_infos = try infos.toOwnedSlice(a),
            .weight_infos = winfos_f,
            .tables = tables,
            .ops = try ops.toOwnedSlice(a),
            .witness = try wit.toOwnedSlice(a),
            .accs = blk: {
                const accs_f = try a.alloc(?[]i64, 5);
                @memset(accs_f, null);
                accs_f[1] = acc_g;
                accs_f[2] = acc_u;
                accs_f[4] = acc_o;
                break :blk accs_f;
            },
        };
    }
    // act = silu(gate) (3)
    const act = try a.alloc(i32, n_tf);
    for (wit.items[1], act) |g, *o| o.* = tables[0].values[@intCast(g + 128)];
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_f));
    try wit.append(a, act);
    try ops.append(a, .{ .lookup = .{ .in = 1, .out = 3, .table = 0 } });
    // h = requant(act * up) (4)
    const acc_h = try a.alloc(i64, n_tf);
    for (act, wit.items[2], acc_h) |p, q, *o| o.* = @as(i64, p) * q;
    const sh = chooseShift(acc_h);
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_f));
    try wit.append(a, try requantAll(a, acc_h, sh));
    try ops.append(a, .{ .hadamard = .{ .a = 3, .b = 2, .y = 4, .shift = sh } });
    // out = requant(h Wd) (5)
    const acc_o = try fwdMatmul(cfg, a, pool, infos.items[4], wit.items[4], ws.matrix(2));
    const so = chooseShift(acc_o);
    try infos.append(a, TensorInfo.mat(cfg.log_t, cfg.log_d));
    try wit.append(a, try requantAll(a, acc_o, so));
    try ops.append(a, .{ .matmul = .{ .x = 4, .w = 2, .y = 5, .shift = so } });

    const accs = try a.alloc(?[]i64, ops.items.len);
    @memset(accs, null);
    accs[1] = acc_g;
    accs[2] = acc_u;
    accs[4] = acc_h;
    accs[5] = acc_o;
    const winfos = try a.alloc(TensorInfo, 3);
    winfos[0] = TensorInfo.mat(cfg.log_d, cfg.log_f);
    winfos[1] = TensorInfo.mat(cfg.log_d, cfg.log_f);
    winfos[2] = TensorInfo.mat(cfg.log_f, cfg.log_d);
    return .{
        .witness_infos = try infos.toOwnedSlice(a),
        .weight_infos = winfos,
        .tables = tables,
        .ops = try ops.toOwnedSlice(a),
        .witness = try wit.toOwnedSlice(a),
        .accs = accs,
    };
}

pub fn mlpWeightInfos(cfg: Mlp) [3]TensorInfo {
    return .{ TensorInfo.mat(cfg.log_d, cfg.log_f), TensorInfo.mat(cfg.log_d, cfg.log_f), TensorInfo.mat(cfg.log_f, cfg.log_d) };
}

test "unfused mlp block proves and verifies" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = Mlp{ .log_t = 4, .log_d = 6, .log_f = 7, .fused = false };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 }, .weight_log_cols = 5, .witness_log_cols_max = 6, .gkr_threads = 2 };
    const winfos = mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try randomWeights(a, winfos[i].size(), 200 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    const x = try randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 4);
    defer a.free(x);
    var built = try buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, built.statement(), &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, built.statement(), proto.weightKey(&ws), &proof);
    proof.lookup_in_values[0] = proof.lookup_in_values[0].add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, built.statement(), proto.weightKey(&ws), &proof)));
}

test "mlp block proves and verifies; tampering rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = Mlp{ .log_t = 4, .log_d = 6, .log_f = 7 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 }, .weight_log_cols = 5, .witness_log_cols_max = 6, .gkr_threads = 2 };
    const winfos = mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    var prox = try proto.proveWeightProximity(a, &pool, pc, &ws);
    defer prox.deinit(a);
    try proto.verifyWeightProximity(a, pc, proto.weightKey(&ws), prox);

    const x = try randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
    defer a.free(x);
    var built = try buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const st = built.statement();
    var tm: proto.Timings = .{};
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
    defer proof.deinit(a);
    const key = proto.weightKey(&ws);
    try proto.verify(a, pc, st, key, &proof);
    // reusing the forward-pass accumulators yields the identical proof
    {
        var proof2 = try proto.proveWithAccumulators(a, &pool, pc, st, &ws, wview, built.accs, &tm);
        defer proof2.deinit(a);
        try std.testing.expectEqualSlices(u8, &@import("proof_digest.zig").digest(&proof), &@import("proof_digest.zig").digest(&proof2));
        // wrong accumulator shape is refused
        try std.testing.expectError(error.AccumulatorShape, proto.proveWithAccumulators(a, &pool, pc, st, &ws, wview, built.accs[0..2], &tm));
    }

    // tamper: final witness value
    const saved = proof.witness_value;
    proof.witness_value = saved.add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
    proof.witness_value = saved;
    // tamper: a prover-sent terminal value (glu / implied-range y)
    {
        const sv = proof.lookup_in_values[0];
        proof.lookup_in_values[0] = sv.add(f.QM31.one());
        try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
        proof.lookup_in_values[0] = sv;
    }
    // tamper: every op final (the weight claims' values are op finals)
    for (proof.op_finals) |fin| for (fin) |*fv| {
        const sv = fv.*;
        fv.* = sv.add(f.QM31.one());
        try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
        fv.* = sv;
    };
    // tamper: statement (different shift) must be rejected
    const ops2 = try a.dupe(proto.Op, st.ops);
    defer a.free(ops2);
    ops2[1].matmul.shift += 1;
    var st2 = st;
    st2.ops = ops2;
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st2, key, &proof)));
    // statement validation: unbounded matmul operand rejected
    {
        const ops3 = try a.dupe(proto.Op, st.ops);
        defer a.free(ops3);
        ops3[0] = .{ .range8 = .{ .in = 1 } }; // x (0) no longer range-checked
        var st3 = st;
        st3.ops = ops3;
        try std.testing.expectError(error.StatementUnboundedOperand, proto.validateStatement(st3));
    }
    // tamper: different weights root
    var key2 = key;
    key2.root[0] ^= 1;
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key2, &proof)));
    // still verifies after restoring
    try proto.verify(a, pc, st, key, &proof);
}

test "prover refuses a wrong witness (requant mismatch)" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = Mlp{ .log_t = 3, .log_d = 5, .log_f = 6 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 1 }, .weight_log_cols = 5, .witness_log_cols_max = 6, .gkr_threads = 1 };
    const winfos = mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try randomWeights(a, winfos[i].size(), 7 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    const x = try randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 1);
    defer a.free(x);
    var built = try buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    built.witness[built.witness.len - 1][3] += 1; // wrong output
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    try std.testing.expectError(error.RemainderOutOfRange, proto.prove(a, &pool, pc, built.statement(), &ws, wview, &tm));
}

/// FlashProve toy-equivalent statement: prover knows a, b, c in F^(2^L) with
/// a[i] * b[i] = c[i]. Witness ids 0=a, 1=b, 2=c.
pub fn buildProduct(a: std.mem.Allocator, log_n: u32, seed: u64) !Built {
    const n = @as(usize, 1) << @intCast(log_n);
    var prng = std.Random.DefaultPrng.init(seed);
    const r = prng.random();
    const wa = try a.alloc(i32, n);
    const wb = try a.alloc(i32, n);
    const wc = try a.alloc(i32, n);
    for (0..n) |i| {
        const x = r.intRangeLessThan(u32, 0, f.P);
        const y = r.intRangeLessThan(u32, 0, f.P);
        wa[i] = @intCast(x);
        wb[i] = @intCast(y);
        wc[i] = @intCast(f.M31.fromCanonical(x).mul(f.M31.fromCanonical(y)).v);
    }
    const infos = try a.alloc(TensorInfo, 3);
    for (infos) |*x| x.* = TensorInfo.vec(log_n);
    const ops = try a.alloc(proto.Op, 1);
    ops[0] = .{ .product = .{ .a = 0, .b = 1, .c = 2 } };
    const wit = try a.alloc([]i32, 3);
    wit[0] = wa;
    wit[1] = wb;
    wit[2] = wc;
    return .{ .witness_infos = infos, .weight_infos = try a.alloc(TensorInfo, 0), .tables = try a.alloc(proto.Table, 0), .ops = ops, .witness = wit };
}

test "product statement proves and verifies; wrong c rejected by prover-side check" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 2, .witness_log_cols_max = 6, .gkr_threads = 1 };
    const dummy_info = [_]TensorInfo{TensorInfo.mat(2, 2)};
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    defer ws.deinit(a);
    var built = try buildProduct(a, 10, 5);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    var st = built.statement();
    st.weights = &dummy_info;
    var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
    proof.op_finals[0][2] = proof.op_finals[0][2].add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, proto.weightKey(&ws), &proof)));
}
