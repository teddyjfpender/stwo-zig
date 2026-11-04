//! KERN-1 regression (fuzz-style): every class of transmitted field element,
//! in every verifier entry point, is rejected with error.NonCanonical when one
//! limb is replaced by a non-canonical encoding (v + P, or exactly P) of the
//! same residue. Field classes are enumerated by reflection (canonical.zig), so
//! a new proof field is covered without editing this test; the expected-class
//! lists below pin that the fixtures actually exercise each class.
const std = @import("std");
const f = @import("field.zig");
const canonical = @import("canonical.zig");
const proto = @import("protocol.zig");
const model = @import("model.zig");
const tf = @import("transformer.zig");
const zk = @import("zk.zig");
const wk = @import("weight_key.zig");

const testing = std.testing;

/// path -> limb indices (walk order) of that class
const Classes = std.StringArrayHashMapUnmanaged(std.ArrayListUnmanaged(usize));

fn collect(a: std.mem.Allocator, proof: anytype) !Classes {
    const V = struct {
        a: std.mem.Allocator,
        map: Classes = .{},
        n: usize = 0,
        err: ?anyerror = null,
        pub fn limb(self: *@This(), comptime path: []const u8, _: *u32) void {
            defer self.n += 1;
            if (self.err != null) return;
            const gop = self.map.getOrPut(self.a, path) catch |e| {
                self.err = e;
                return;
            };
            if (!gop.found_existing) gop.value_ptr.* = .{};
            gop.value_ptr.append(self.a, self.n) catch |e| {
                self.err = e;
            };
        }
    };
    var v = V{ .a = a };
    canonical.forEachLimb(proof, &v);
    if (v.err) |e| return e;
    return v.map;
}

fn freeClasses(a: std.mem.Allocator, m: *Classes) void {
    for (m.values()) |*l| l.deinit(a);
    m.deinit(a);
}

/// For every field class, corrupt its first, middle and last limb (v + P and
/// v = P alternately) and expect `ctx.run()` to fail with NonCanonical; the
/// honest proof must still verify afterwards. Returns the class count.
fn fuzzEveryClass(a: std.mem.Allocator, proof: anytype, ctx: anytype, expect_prefixes: []const []const u8) !usize {
    try ctx.run();
    var classes = try collect(a, proof);
    defer freeClasses(a, &classes);
    for (expect_prefixes) |pre| {
        var hit = false;
        for (classes.keys()) |k| hit = hit or std.mem.startsWith(u8, k, pre);
        if (!hit) {
            std.debug.print("\n[canonical] fixture does not exercise field class {s}; classes:\n", .{pre});
            for (classes.keys()) |k| std.debug.print("  {s}\n", .{k});
            return error.ClassNotCovered;
        }
    }
    var flips: usize = 0;
    for (classes.keys(), classes.values()) |path, idx| {
        const l = idx.items;
        const picks = [_]usize{ l[0], l[l.len / 2], l[l.len - 1] };
        for (picks, 0..) |n, j| {
            const p = canonical.nthLimb(proof, n).?;
            const old = p.*;
            try testing.expect(old < f.P);
            p.* = if (j == 1) f.P else old + f.P;
            const r = ctx.run();
            p.* = old;
            r catch |e| {
                if (e == error.NonCanonical) {
                    flips += 1;
                    continue;
                }
                std.debug.print("\n[canonical] {s} limb {d}: expected NonCanonical, got {s}\n", .{ path, n, @errorName(e) });
                return e;
            };
            std.debug.print("\n[canonical] {s} limb {d}: non-canonical limb ACCEPTED\n", .{ path, n });
            return error.NonCanonicalAccepted;
        }
    }
    try testing.expectEqual(3 * classes.count(), flips);
    try ctx.run();
    return classes.count();
}

const PROTO_COMMON = [_][]const u8{
    ".gkr?.sumcheck_proofs[].round_polys[].coeffs[]",
    ".gkr?.layer_masks_by_instance[][].columns[][]",
    ".gkr?.output_claims_by_instance[][]",
    ".lookup_in_values[]",
    ".op_sumchecks[].rounds[].evals[]",
    ".op_finals[][]",
    ".batch_sumcheck.rounds[].evals[]",
    ".witness_value",
    ".ext.values[]",
    ".ext.sumchecks[].rounds[].evals[]",
    ".ext.finals[][]",
};

fn layerFuzz(pc: proto.Config, extra: []const []const u8) !void {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = tf.LayerCfg{ .log_t = 3, .log_d = 5, .log_f = 6, .log_heads = 2, .log_kv_heads = 1 };
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 300);
    defer {
        sw.ws.deinit(a);
        for (sw.wdata) |w| a.free(w);
        a.free(sw.wdata);
        a.free(sw.winfos);
    }
    var b = tf.Builder.init(a, &pool);
    defer b.deinit();
    const c = try tf.initCtx(&b, cfg, &sw.ws, 1);
    const x = try model.randomInput(a, @as(usize, 1) << (cfg.log_t + cfg.log_d), 17);
    defer a.free(x);
    _ = try tf.buildStack(&b, c, x);
    const st = b.statement();
    const wv = try b.witnessView(a);
    defer a.free(wv);
    var tm: proto.Timings = .{};
    var proof = try proto.prove(a, &pool, pc, st, &sw.ws, wv, &tm);
    defer proof.deinit(a);
    const Ctx = struct {
        a: std.mem.Allocator,
        pc: proto.Config,
        st: proto.Statement,
        key: proto.WeightKey,
        proof: *const proto.Proof,
        fn run(s: @This()) !void {
            return proto.verify(s.a, s.pc, s.st, s.key, s.proof);
        }
    };
    var want: [PROTO_COMMON.len + 4][]const u8 = undefined;
    @memcpy(want[0..PROTO_COMMON.len], &PROTO_COMMON);
    @memcpy(want[PROTO_COMMON.len..][0..extra.len], extra);
    _ = try fuzzEveryClass(a, &proof, Ctx{ .a = a, .pc = pc, .st = st, .key = proto.weightKey(&sw.ws), .proof = &proof }, want[0 .. PROTO_COMMON.len + extra.len]);

    // weight-key range proof (separate entry point; same walker)
    var kp = try wk.prove(a, &pool, pc, &sw.ws);
    defer kp.deinit(a);
    const KCtx = struct {
        a: std.mem.Allocator,
        pc: proto.Config,
        key: proto.WeightKey,
        kp: *const wk.KeyProof,
        fn run(s: @This()) !void {
            return wk.verify(s.a, s.pc, s.key, s.kp);
        }
    };
    _ = try fuzzEveryClass(a, &kp, KCtx{ .a = a, .pc = pc, .key = proto.weightKey(&sw.ws), .kp = &kp }, &.{ ".gkr.sumcheck_proofs", ".gkr.layer_masks_by_instance", ".gkr.output_claims_by_instance", ".value", ".opening<" });
}

fn layerCfg() proto.Config {
    return .{ .pcs = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .weight_log_cols = 4, .witness_log_cols_max = 8, .gkr_threads = 2 };
}

test "KERN-1 canonicity: flat-PCS decoder layer, every transmitted field class rejects a limb >= P" {
    try layerFuzz(layerCfg(), &.{ ".witness_opening<flat>.rows[][]", ".witness_opening<flat>.columns[].values[]", ".weight_opening?<flat>.rows[][]", ".weight_opening?<flat>.columns[].values[]" });
}

test "KERN-1 canonicity: pcs2 (OOD, batched matmuls) decoder layer, every transmitted field class rejects a limb >= P" {
    var pc = layerCfg();
    pc.batch_matmuls = true;
    pc.two_level = .{ .outer = pc.pcs, .depth = 2, .inner = .{ .log_blowup = 2, .n_queries = 12, .pow_bits = 1 }, .ood = true };
    try layerFuzz(pc, &.{ ".witness_ood?", ".witness_opening<two>.levels[].col_values[]", ".witness_opening<two>.levels[].limb_vals[]", ".witness_opening<two>.levels[].sumcheck.rounds[].evals[]" });
}

test "KERN-1 canonicity: zk MLP proof, weight proximity and weight link reject a limb >= P" {
    const a = testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 2);
    defer pool.deinit();
    const cfg = proto.Config{ .pcs = .{ .log_blowup = 2, .n_queries = 8, .pow_bits = 2 }, .weight_log_cols = 6, .witness_log_cols_max = 7, .gkr_threads = 1, .hiding = true, .weight_mask_slots = 64 };
    const mc = model.Mlp{ .log_t = 3, .log_d = 6, .log_f = 7, .fused = false };
    const winfos = model.mlpWeightInfos(mc);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wvv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var zw = try zk.commitWeights(a, &pool, cfg, &winfos, &wvv);
    defer zw.deinit(a);
    const key = zw.key();

    var prox = try zk.proveWeightProximity(a, &pool, cfg, &zw);
    defer prox.deinit(a);
    const PCtx = struct {
        a: std.mem.Allocator,
        cfg: proto.Config,
        key: zk.WeightKey,
        prox: *const @TypeOf(prox),
        fn run(s: @This()) !void {
            return zk.verifyWeightProximity(s.a, s.cfg, s.key, s.prox.*);
        }
    };
    _ = try fuzzEveryClass(a, &prox, PCtx{ .a = a, .cfg = cfg, .key = key, .prox = &prox }, &.{ "<flat>.rows[][]", "<flat>.tables[].values[]" });

    const x = try model.randomInput(a, @as(usize, 1) << (mc.log_t + mc.log_d), 9);
    defer a.free(x);
    const pv = zw.plainView();
    var built = try model.buildMlp(a, &pool, &pv, mc, x);
    defer built.deinit(a);
    const st = built.statement();
    const wv = try a.alloc([]const i32, built.witness.len);
    defer a.free(wv);
    for (built.witness, 0..) |w, i| wv[i] = w;
    var tm: proto.Timings = .{};
    var proof = try zk.prove(a, &pool, cfg, st, &zw, wv, &tm);
    defer proof.deinit(a);
    const Ctx = struct {
        a: std.mem.Allocator,
        cfg: proto.Config,
        st: proto.Statement,
        key: zk.WeightKey,
        proof: *const zk.Proof,
        fn run(s: @This()) !void {
            return zk.verify(s.a, s.cfg, s.st, s.key, s.proof);
        }
    };
    _ = try fuzzEveryClass(a, &proof, Ctx{ .a = a, .cfg = cfg, .st = st, .key = key, .proof = &proof }, &.{
        ".checks[].sigma",
        ".checks[].rounds[][]",
        ".checks[].hats[]",
        ".checks[].u_val",
        ".batch.rounds[][]",
        ".opening<flat>.mus[]",
        ".opening<flat>.rows[][]",
        ".opening<flat>.tables[].values[]",
        ".weight_opening?",
        ".gkr_roots[]",
        ".gkr_layers[]",
    });

    // weight link (re-keying the hiding weight commitment)
    var zw2 = try zk.commitWeights(a, &pool, cfg, &winfos, &wvv);
    defer zw2.deinit(a);
    var link = try zk.proveWeightLink(a, &pool, cfg, &zw, &zw2);
    defer link.deinit(a);
    const LCtx = struct {
        a: std.mem.Allocator,
        cfg: proto.Config,
        old: zk.WeightKey,
        new: zk.WeightKey,
        link: *const zk.WeightLink,
        fn run(s: @This()) !void {
            return zk.verifyWeightLink(s.a, s.cfg, s.old, s.new, s.link.*);
        }
    };
    _ = try fuzzEveryClass(a, &link, LCtx{ .a = a, .cfg = cfg, .old = key, .new = zw2.key(), .link = &link }, &.{".opening<flat>.rows[][]"});
}
