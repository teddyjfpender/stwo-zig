//! Canonical digest of a tensor proof (all transmitted values, in a fixed
//! order). Used to pin prover output byte-for-byte across performance work:
//! a prover optimization that does not change the protocol must not change
//! this digest for a fixed statement/witness/seed.
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");

const QM31 = f.QM31;
const B2 = std.crypto.hash.blake2.Blake2s256;

fn felt(h: *B2, x: QM31) void {
    const l = f.limbs(x);
    for (l) |v| h.update(std.mem.asBytes(&v));
}

fn u64v(h: *B2, x: u64) void {
    h.update(std.mem.asBytes(&x));
}

fn opening(h: *B2, o: pcs.OpeningProof) void {
    u64v(h, o.rows.len);
    for (o.rows) |r| {
        u64v(h, r.len);
        for (r) |x| felt(h, x);
    }
    u64v(h, o.pow_nonce);
    u64v(h, o.columns.len);
    for (o.columns) |c| {
        u64v(h, c.index);
        h.update(std.mem.sliceAsBytes(c.values));
        for (c.path) |p| h.update(&p);
    }
}

pub fn digest(p: *const proto.Proof) [32]u8 {
    var h = B2.init(.{});
    h.update(&p.witness_root);
    if (p.gkr) |g| {
        u64v(&h, 1);
        for (g.sumcheck_proofs) |sp| {
            u64v(&h, sp.round_polys.len);
            for (sp.round_polys) |rp| {
                const cs = rp.coeffsSlice();
                u64v(&h, cs.len);
                for (cs) |x| felt(&h, x);
            }
        }
        for (g.layer_masks_by_instance) |ms| for (ms) |m| {
            for (m.columnsSlice()) |c| {
                felt(&h, c[0]);
                felt(&h, c[1]);
            }
        };
        for (g.output_claims_by_instance) |cl| for (cl) |x| felt(&h, x);
    } else u64v(&h, 0);
    for (p.lookup_in_values) |x| felt(&h, x);
    for (p.op_sumchecks) |sp| for (sp.rounds) |rp| for (rp.evals[0..sp.deg]) |x| felt(&h, x);
    for (p.op_finals) |fs| for (fs) |x| felt(&h, x);
    for (p.batch_sumcheck.rounds) |rp| for (rp.evals[0..p.batch_sumcheck.deg]) |x| felt(&h, x);
    felt(&h, p.witness_value);
    opening(&h, p.witness_opening);
    for (p.weight_values) |x| felt(&h, x);
    if (p.weight_opening) |o| opening(&h, o);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hex(d: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(d, .lower);
}

/// Golden digests recorded on the pre-optimization prover (cc5ac62c9).
const GOLDEN_MLP = "fee693b4404f39f21414bbf5f5cdb4ddd3cac9bd54bc435711b29c928e0cbe35";
const GOLDEN_PRODUCT = "ef898ebc41f69dc02891d663b412d409f8b0e999d1672af46d7c2ffca1021446";

fn mlpProofDigest(threads: usize) ![32]u8 {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = 5, .log_d = 7, .log_f = 8 };
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 4 }, .weight_log_cols = 6, .witness_log_cols_max = 8, .gkr_threads = threads };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    defer ws.deinit(a);
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
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
    return digest(&proof);
}

fn productProofDigest(threads: usize) ![32]u8 {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 4 }, .weight_log_cols = 2, .witness_log_cols_max = 8, .gkr_threads = threads };
    const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    defer ws.deinit(a);
    var built = try model.buildProduct(a, 16, 5);
    defer built.deinit(a);
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var st = built.statement();
    st.weights = &dummy_info;
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
    defer proof.deinit(a);
    try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
    return digest(&proof);
}

test "proof digest is pinned (mlp, product) and thread-count independent" {
    const m1 = try mlpProofDigest(1);
    const m5 = try mlpProofDigest(5);
    const p1 = try productProofDigest(1);
    const p5 = try productProofDigest(5);
    if (!std.mem.eql(u8, GOLDEN_MLP, &hex(m1)) or !std.mem.eql(u8, GOLDEN_PRODUCT, &hex(p1)))
        std.debug.print("mlp digest {s}\nproduct digest {s}\n", .{ hex(m1), hex(p1) });
    try std.testing.expectEqualSlices(u8, &m1, &m5);
    try std.testing.expectEqualSlices(u8, &p1, &p5);
    try std.testing.expectEqualStrings(GOLDEN_MLP, &hex(m1));
    try std.testing.expectEqualStrings(GOLDEN_PRODUCT, &hex(p1));
}
