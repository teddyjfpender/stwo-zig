//! Regression tests for review phase B findings on the soundness calculator
//! (security.zig): SEC-2 (key proof verified before it is accounted), SEC-3
//! (no key proof: the total is conditional), SEC-4 (claim-dimension terms of
//! op sumchecks). Copied from the reviewer's tests (revb-sec
//! review_security_test.zig) with the assertions inverted: each test now
//! passes when the defect is fixed.
const std = @import("std");
const f = @import("field.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const security = @import("security.zig");
const weight_key = @import("weight_key.zig");

fn secureConfig() proto.Config {
    return .{
        .two_level = .{
            .outer = .{ .log_blowup = 2, .n_queries = 16, .pow_bits = 2 },
            .inner = .{ .log_blowup = 3, .n_queries = 12, .pow_bits = 1 },
            .depth = 1,
            .ood = true,
            .prox_rows = 2,
        },
        .weight_outer = .{ .log_blowup = 2, .n_queries = 9, .pow_bits = 2 },
        .key_outer = .{ .log_blowup = 2, .n_queries = 40, .pow_bits = 2 },
        .gkr_threads = 2,
    };
}

const Mlp = struct {
    ws: proto.WeightStore,
    wdata: [3][]i8,
    x: []i32,
    built: model.Built,
    wview: [][]const i32,
    proof: proto.Proof,
    pc: proto.Config,
    winfos: [3]proto.TensorInfo,

    fn init(self: *Mlp, a: std.mem.Allocator, pool: *f.Pool) !void {
        const cfg = model.Mlp{ .log_t = 4, .log_d = 6, .log_f = 7 };
        self.pc = secureConfig();
        self.winfos = model.mlpWeightInfos(cfg);
        self.pc.weight_log_cols = try proto.chooseWeightLogCols(self.pc, a, &self.winfos, 3);
        for (&self.wdata, 0..) |*w, i| w.* = try model.randomWeights(a, self.winfos[i].size(), 100 + i, -8, 7);
        const wv = [_][]const i8{ self.wdata[0], self.wdata[1], self.wdata[2] };
        self.ws = try proto.commitWeights(a, pool, self.pc, &self.winfos, &wv);
        self.x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 9);
        self.built = try model.buildMlp(a, pool, &self.ws, cfg, self.x);
        self.wview = try a.alloc([]const i32, self.built.witness.len);
        for (self.built.witness, 0..) |w, i| self.wview[i] = w;
        var tm: proto.Timings = .{};
        self.proof = try proto.prove(a, pool, self.pc, self.built.statement(), &self.ws, self.wview, &tm);
    }

    fn deinit(self: *Mlp, a: std.mem.Allocator) void {
        self.proof.deinit(a);
        a.free(self.wview);
        self.built.deinit(a);
        a.free(self.x);
        self.ws.deinit(a);
        for (self.wdata) |w| a.free(w);
    }
};

fn hasTerm(acc: security.Account, needle: []const u8) bool {
    for (acc.terms.items) |t| if (std.mem.indexOf(u8, t.name, needle) != null) return true;
    return false;
}

// SEC-2 (review SEC-R1): accountProof must refuse a weight-key proof that the
// key verifier rejects.
test "SEC-2: a rejected weight-key proof is not accounted" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var m: Mlp = undefined;
    try m.init(a, &pool);
    defer m.deinit(a);
    const key = proto.weightKey(&m.ws);
    var kp = weight_key.prove(a, &pool, m.pc, &m.ws) catch |e| {
        std.debug.print("\n[SEC-R1] key prove error {s}\n", .{@errorName(e)});
        return e;
    };
    defer kp.deinit(a);
    try weight_key.verify(a, m.pc, key, &kp);
    // tamper: the key's claimed W(rho) and its histogram
    kp.value = kp.value.add(f.QM31.one());
    kp.histogram[0] +%= 1;
    kp.histogram[255] -%= 1;
    try std.testing.expect(std.meta.isError(weight_key.verify(a, m.pc, key, &kp)));
    try std.testing.expect(std.meta.isError(security.accountProof(a, m.pc, m.built.statement(), key, &m.proof, &kp)));
    // the untampered key proof is accounted
    kp.value = kp.value.sub(f.QM31.one());
    kp.histogram[0] -%= 1;
    kp.histogram[255] +%= 1;
    var rep = try security.accountProof(a, m.pc, m.built.statement(), key, &m.proof, &kp);
    defer rep.deinit();
    try std.testing.expect(rep.key != null);
}

// SEC-3 (review SEC-R2): without a key proof nothing proves the weight
// table's proximity at delta_key, so the report must not print an
// unconditional total.
test "SEC-3: no key proof, the total is reported as conditional on the key" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var m: Mlp = undefined;
    try m.init(a, &pool);
    defer m.deinit(a);
    const key = proto.weightKey(&m.ws);
    var rep = try security.accountProof(a, m.pc, m.built.statement(), key, &m.proof, null);
    defer rep.deinit();
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    try security.writeReport(rep, buf.writer(a));
    const js = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, js, "\"conditional_on_key\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "\"total\":") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "\"total_conditional_on_key\":") != null);
}

// SEC-4 (review SEC-R3): the matmul acc identity acc~(rho) = sum_k X~ W~ is a
// Schwartz-Zippel test at the GKR point rho over lt + ln variables; the
// calculator must charge at least that many, not only (rounds + 1) = lk + 1.
test "SEC-4: matmul acc identity charged for its lt + ln claim variables" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    var m: Mlp = undefined;
    try m.init(a, &pool);
    defer m.deinit(a);
    var rep = try security.accountProof(a, m.pc, m.built.statement(), proto.weightKey(&m.ws), &m.proof, null);
    defer rep.deinit();
    var max_num: f64 = 0;
    for (rep.request.terms.items) |t| {
        if (!std.mem.eql(u8, t.name, "op sumcheck") or t.count != 1) continue;
        max_num = @max(max_num, std.math.exp2(t.log2_err + security.LOG2_F));
    }
    // MLP log_t 4, log_d 6, log_f 7: up/gate acc has lt + ln = 11 variables
    try std.testing.expect(max_num >= 11 - 1e-6);
}
