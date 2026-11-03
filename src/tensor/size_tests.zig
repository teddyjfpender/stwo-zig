//! End-to-end tests of the tensor protocol under the recursive PCS (pcs2).
const std = @import("std");
const f = @import("field.zig");
const pcs2 = @import("pcs2.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");

fn tlConfig(depth: u32) proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 },
            .inner = .{ .log_blowup = 3, .n_queries = 12, .pow_bits = 1 },
            .depth = depth,
        },
        .gkr_threads = 2,
    };
}

fn mlpCase(depth: u32) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 4, .log_d = 6, .log_f = 7 };
    var pc = tlConfig(depth);
    const winfos = model.mlpWeightInfos(cfg);
    pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, &winfos, 3);
    // the size model must be allowed to go past the shared-column limit (log_d)
    try std.testing.expect(pc.weight_log_cols > 0);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
    var prox = try proto.proveWeightProximity(a, &pool, pc, &ws);
    defer prox.deinit(a);
    const key = proto.weightKey(&ws);
    try proto.verifyWeightProximity(a, pc, key, prox);
    // the flat verifier must not accept a pcs2 proximity proof
    var flat = pc;
    flat.two_level = null;
    try std.testing.expect(std.meta.isError(proto.verifyWeightProximity(a, flat, key, prox)));

    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, key, &proof);
    try std.testing.expect(proof.witness_opening == .two);
    try std.testing.expectEqual(@as(usize, depth + 1), proof.witness_opening.two.levels.len);
    // weight claims have distinct column points: 3 groups, not 1
    try std.testing.expect(proof.weight_opening.? == .two);

    // tampering
    const saved = proof.witness_value;
    proof.witness_value = saved.add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
    proof.witness_value = saved;
    const wsaved = proof.weight_values[2];
    proof.weight_values[2] = wsaved.add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
    proof.weight_values[2] = wsaved;
    for ([_]*proto.Opening{ &proof.witness_opening, &proof.weight_opening.? }) |op| {
        for (op.two.levels) |*lp| {
            lp.col_values[0] = lp.col_values[0].add(f.M31.one());
            try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            lp.col_values[0] = lp.col_values[0].sub(f.M31.one());
            lp.limb_vals[0] = lp.limb_vals[0].add(f.QM31.one());
            if (lp.rows.len == 0) try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key, &proof)));
            lp.limb_vals[0] = lp.limb_vals[0].sub(f.QM31.one());
        }
    }
    var key2 = key;
    key2.root[1] ^= 1;
    try std.testing.expect(std.meta.isError(proto.verify(a, pc, st, key2, &proof)));
    // different depth configuration must reject
    try std.testing.expect(std.meta.isError(proto.verify(a, tlConfig(depth + 1), st, key, &proof)));
    try proto.verify(a, pc, st, key, &proof);
}

test "mlp under pcs2 depth 1" {
    try mlpCase(1);
}

test "mlp under pcs2 depth 2" {
    try mlpCase(2);
}

test "product under pcs2; wrong c rejected" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var pc = tlConfig(1);
    const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};
    pc.weight_log_cols = 2;
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    defer ws.deinit(a);
    var built = try model.buildProduct(a, 10, 5);
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

fn batchedCase(pc: proto.Config) !void {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 4);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 4, .log_d = 6, .log_f = 7 };
    var pcb = pc;
    pcb.batch_matmuls = true;
    const winfos = model.mlpWeightInfos(cfg);
    pcb.weight_log_cols = try proto.chooseWeightLogCols(pcb, a, &winfos, 2);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 300 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pcb, &winfos, &wv);
    defer ws.deinit(a);
    const key = proto.weightKey(&ws);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 4);
    defer a.free(x);
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    defer built.deinit(a);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pcb, st, &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pcb, st, key, &proof);
    // gate/up form one class (one sumcheck with 4 finals), down its own; the
    // fused SwiGLU (glu lookup) has no hadamard sumcheck
    try std.testing.expectEqual(@as(usize, 2), proof.op_sumchecks.len);
    try std.testing.expectEqual(@as(usize, 4), proof.op_finals[0].len);
    // the unbatched verifier must reject a batched proof
    var pcu = pcb;
    pcu.batch_matmuls = false;
    try std.testing.expect(std.meta.isError(proto.verify(a, pcu, st, key, &proof)));
    // tamper each final of the batched class (x and w values of both members)
    for (0..4) |j| {
        const sv = proof.op_finals[0][j];
        proof.op_finals[0][j] = sv.add(f.QM31.one());
        try std.testing.expect(std.meta.isError(proto.verify(a, pcb, st, key, &proof)));
        proof.op_finals[0][j] = sv;
    }
    // weight value of the second class member
    const wsv = proof.weight_values[1];
    proof.weight_values[1] = wsv.add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pcb, st, key, &proof)));
    proof.weight_values[1] = wsv;
    // sumcheck round of the batched class
    proof.op_sumchecks[0].rounds[1].evals[1] = proof.op_sumchecks[0].rounds[1].evals[1].add(f.QM31.one());
    try std.testing.expect(std.meta.isError(proto.verify(a, pcb, st, key, &proof)));
    proof.op_sumchecks[0].rounds[1].evals[1] = proof.op_sumchecks[0].rounds[1].evals[1].sub(f.QM31.one());
    // statement: shift of the second member (up projection)
    const ops2 = try a.dupe(proto.Op, st.ops);
    defer a.free(ops2);
    ops2[2].matmul.shift += 1;
    var st2 = st;
    st2.ops = ops2;
    try std.testing.expect(std.meta.isError(proto.verify(a, pcb, st2, key, &proof)));
    // statement: swap which weight the up projection uses
    const ops3 = try a.dupe(proto.Op, st.ops);
    defer a.free(ops3);
    ops3[2].matmul.w = 0;
    var st3 = st;
    st3.ops = ops3;
    try std.testing.expect(std.meta.isError(proto.verify(a, pcb, st3, key, &proof)));
    try proto.verify(a, pcb, st, key, &proof);
}

test "batched matmul classes: flat PCS" {
    try batchedCase(.{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 }, .weight_log_cols = 6, .witness_log_cols_max = 6, .gkr_threads = 2 });
}

test "batched matmul classes: pcs2 depth 1 (gate/up share one weight group)" {
    try batchedCase(tlConfig(1));
}
