//! Hiding-mode benchmarks: `tensor-bench <product|mlp> ... zk`
//! (same positional arguments as the non-hiding benchmarks; prints one JSON line).
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const proto = t.protocol;
const model = t.model;
const zk = t.zk;

fn now() std.time.Instant {
    return std.time.Instant.now() catch unreachable;
}
fn secs(t0: std.time.Instant) f64 {
    return @as(f64, @floatFromInt(now().since(t0))) / 1e9;
}
fn nsToS(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / 1e9;
}
fn peakRssBytes() u64 {
    const ru = std.posix.getrusage(std.posix.rusage.SELF);
    return @intCast(ru.maxrss);
}

/// True (and `args` compacted) if a trailing "zk" argument is present.
pub fn takeFlag(args: [][:0]u8) ?[][:0]u8 {
    for (args, 0..) |x, i| if (std.mem.eql(u8, x, "zk")) {
        for (i..args.len - 1) |j| args[j] = args[j + 1];
        return args[0 .. args.len - 1];
    };
    return null;
}

/// Conjectured bits of a hiding opening: queries * log2(E / (C + slots)) + pow.
fn conjBits(queries: usize, msg_len: usize, log_ext: u32, pow: u32) f64 {
    const e: f64 = @floatFromInt(@as(u64, 1) << @intCast(log_ext));
    return @as(f64, @floatFromInt(queries)) * std.math.log2(e / @as(f64, @floatFromInt(msg_len))) + @as(f64, @floatFromInt(pow));
}

/// Proven (unique decoding, delta = (1 - rate)/2) bits of a hiding opening.
fn provenBits(queries: usize, msg_len: usize, log_ext: u32, pow: u32) f64 {
    const rate = @as(f64, @floatFromInt(msg_len)) / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(log_ext)));
    const delta = (1.0 - rate) / 2.0;
    return -@as(f64, @floatFromInt(queries)) * std.math.log2(1.0 - delta) + @as(f64, @floatFromInt(pow));
}

fn envU(name: []const u8, default: u64) !u64 {
    return if (std.posix.getenv(name)) |v| try std.fmt.parseInt(u64, v, 10) else default;
}

/// Recursive hiding PCS (zk_pcs2) from ZK_DEPTH [ZK_INNER_Q ZK_INNER_LB ZK_INNER_POW ZK_WORK_SHIFT];
/// unset or 0 = flat hiding PCS.
fn twoLevelFromEnv() !?t.pcs2.Params {
    const depth = try envU("ZK_DEPTH", 0);
    if (depth == 0) return null;
    return .{
        .inner = .{ .n_queries = @intCast(try envU("ZK_INNER_Q", 54)), .log_blowup = @intCast(try envU("ZK_INNER_LB", 2)), .pow_bits = @intCast(try envU("ZK_INNER_POW", 20)) },
        .depth = @intCast(depth),
        .inner_work_shift = @intCast(try envU("ZK_WORK_SHIFT", 3)),
    };
}

fn pcsJson(out: anytype, tl: ?t.pcs2.Params) !void {
    if (tl) |p| {
        try out.print("\"pcs\":\"zk_pcs2\",\"depth\":{d},\"inner_queries\":{d},\"inner_log_blowup\":{d},\"inner_pow\":{d},\"inner_conjectured_bits\":{d:.1},\"inner_proven_bits\":{d:.1},", .{ p.depth, p.inner.n_queries, p.inner.log_blowup, p.inner.pow_bits, p.inner.conjecturedBits(), p.inner.provenBits() });
    } else try out.print("\"pcs\":\"zk_pcs\",", .{});
}

fn levelsJson(out: anytype, name: []const u8, op: zk.Opening) !void {
    if (op != .rec) return;
    var buf: [16]usize = undefined;
    const ls = op.rec.levelSizes(&buf);
    try out.print("\"{s}\":[", .{name});
    for (ls, 0..) |x, i| try out.print("{s}{d}", .{ if (i == 0) "" else ",", x });
    try out.print("],", .{});
}

fn stagesJson(out: anytype, tm: proto.Timings) !void {
    try out.print("\"stage_s\":{{\"commit\":{d:.4},\"logup_checks\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4}}},", .{ nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns) });
}

pub fn main(a: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len >= 3 and std.mem.eql(u8, args[1], "product")) return runProduct(a, args);
    if (args.len >= 5 and std.mem.eql(u8, args[1], "mlp")) return runMlp(a, args);
    std.debug.print("usage: tensor-bench mlp <log_t> <log_d> <log_f> [threads] [queries] [log_blowup] [pow] zk\n       tensor-bench product <log_n> [threads] [queries] [log_blowup] [pow] zk\n", .{});
}

fn runProduct(a: std.mem.Allocator, args: [][:0]u8) !void {
    const ln = try std.fmt.parseInt(u32, args[2], 10);
    const threads: usize = if (args.len > 3) try std.fmt.parseInt(usize, args[3], 10) else 1;
    const queries: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 54;
    const lb: u32 = if (args.len > 5) try std.fmt.parseInt(u32, args[5], 10) else 2;
    const pow: u32 = if (args.len > 6) try std.fmt.parseInt(u32, args[6], 10) else 20;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow }, .weight_log_cols = 2, .witness_log_cols_max = 14, .gkr_threads = threads, .hiding = true, .two_level = try twoLevelFromEnv() };
    var built = try model.buildProduct(a, ln, 5);
    defer built.deinit(a);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var best_prove: f64 = 1e30;
    var best_verify: f64 = 1e30;
    var tm: proto.Timings = .{};
    var size: usize = 0;
    var sz: zk.Proof.Sizes = undefined;
    var msg_len: usize = 0;
    var lvbuf: [16]usize = undefined;
    var lvs: []usize = lvbuf[0..0];
    for (0..3) |_| {
        tm = .{};
        var t0 = now();
        var proof = try zk.prove(a, &pool, pc, st, null, wview, &tm);
        best_prove = @min(best_prove, secs(t0));
        t0 = now();
        try zk.verify(a, pc, st, null, &proof);
        best_verify = @min(best_verify, secs(t0));
        sz = proof.sizes();
        size = sz.total;
        if (proof.opening == .rec) lvs = proof.opening.rec.levelSizes(&lvbuf);
        proof.deinit(a);
    }
    const ws = try zk.witnessShape(a, pc, st, null);
    msg_len = (@as(usize, 1) << @intCast(ws.log_cols)) + ws.slots;
    const lc = ws.log_cols;
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"product\",\"hiding\":true,\"log_n\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},\"witness_log_cols\":{d},", .{ ln, threads, queries, lb, pow, lc });
    try pcsJson(out, pc.two_level);
    if (lvs.len > 0) {
        try out.print("\"witness_levels\":[", .{});
        for (lvs, 0..) |x, i| try out.print("{s}{d}", .{ if (i == 0) "" else ",", x });
        try out.print("],", .{});
    }
    try out.print("\"conjectured_bits\":{d:.1},\"proven_bits\":{d:.1},", .{ conjBits(queries, msg_len, @intCast(lc + lb), pow), provenBits(queries, msg_len, @intCast(lc + lb), pow) });
    try out.print("\"prove_s\":{d:.5},\"verify_s\":{d:.5},\"proof_bytes\":{d},\"proof_parts\":{{\"sumchecks\":{d},\"witness_opening\":{d}}},\"prove_ns_per_entry\":{d:.2},", .{ best_prove, best_verify, size, sz.sumchecks, sz.witness_opening, best_prove * 1e9 / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(ln))) });
    try stagesJson(out, tm);
    try out.print("\"witness_table_elems\":{d},\"peak_rss_bytes\":{d}}}\n", .{ tm.witness_table_elems, peakRssBytes() });
}

fn runMlp(a: std.mem.Allocator, args: [][:0]u8) !void {
    const lt = try std.fmt.parseInt(u32, args[2], 10);
    const ld = try std.fmt.parseInt(u32, args[3], 10);
    const lf = try std.fmt.parseInt(u32, args[4], 10);
    const threads: usize = if (args.len > 5) try std.fmt.parseInt(usize, args[5], 10) else 12;
    const queries: usize = if (args.len > 6) try std.fmt.parseInt(usize, args[6], 10) else 64;
    const lb: u32 = if (args.len > 7) try std.fmt.parseInt(u32, args[7], 10) else 2;
    const pow: u32 = if (args.len > 8) try std.fmt.parseInt(u32, args[8], 10) else 20;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const cfg = model.Mlp{ .log_t = lt, .log_d = ld, .log_f = lf , .fused = false };
    // Weight table (committed once): higher blowup, slots = C_w, queries for 128 conjectured bits.
    // hiding weight table may be wider than the smallest output dim (one opening group per such matmul)
    const wlc: u32 = if (std.posix.getenv("ZK_WEIGHT_LC")) |v| try std.fmt.parseInt(u32, v, 10) else @min(ld + 2, 14);
    const wlb: u32 = if (std.posix.getenv("ZK_WEIGHT_LB")) |v| try std.fmt.parseInt(u32, v, 10) else 4;
    const wslots: u32 = if (std.posix.getenv("ZK_WEIGHT_SLOTS")) |v| try std.fmt.parseInt(u32, v, 10) else @as(u32, 1) << @intCast(wlc - 2);
    const wbits = std.math.log2(@as(f64, @floatFromInt(@as(u64, 1) << @intCast(wlc + wlb))) / @as(f64, @floatFromInt((@as(u64, 1) << @intCast(wlc)) + wslots)));
    const wq_auto: usize = @intFromFloat(@ceil((128.0 - @as(f64, @floatFromInt(pow))) / wbits));
    const wq: usize = if (std.posix.getenv("ZK_WEIGHT_Q")) |v| try std.fmt.parseInt(usize, v, 10) else wq_auto;
    const pc = proto.Config{
        .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow },
        .weight_log_cols = wlc,
        .witness_log_cols_max = 14,
        .gkr_threads = threads,
        .hiding = true,
        .weight_mask_slots = wslots,
        .weight_pcs = .{ .log_blowup = wlb, .n_queries = wq, .pow_bits = pow },
        .two_level = try twoLevelFromEnv(),
    };
    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    defer for (wdata) |w| a.free(w);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var t0 = now();
    var zw = try zk.commitWeights(a, &pool, pc, &winfos, &wv);
    defer zw.deinit(a);
    const commit_s = secs(t0);
    t0 = now();
    var prox = try zk.proveWeightProximity(a, &pool, pc, &zw);
    defer prox.deinit(a);
    const prox_s = secs(t0);
    const key = zw.key();
    t0 = now();
    try zk.verifyWeightProximity(a, pc, key, prox);
    const prox_verify_s = secs(t0);

    const x = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 9);
    defer a.free(x);
    const pv = zw.plainView();
    t0 = now();
    var built = try model.buildMlp(a, &pool, &pv, cfg, x);
    defer built.deinit(a);
    const forward_s = secs(t0);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    defer a.free(wview);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    // realistic inference statement: input (witness 0) and output (last witness) public
    const public_io = if (std.posix.getenv("ZK_PUBLIC_IO")) |v| !std.mem.eql(u8, v, "0") else true;
    const pubs_all = [_]zk.PublicTensor{ .{ .id = 0, .values = wview[0] }, .{ .id = @intCast(wview.len - 1), .values = wview[wview.len - 1] } };
    const pubs: []const zk.PublicTensor = if (public_io) &pubs_all else &.{};
    t0 = now();
    var proof = try zk.provePublic(a, &pool, pc, st, &zw, wview, pubs, &tm);
    defer proof.deinit(a);
    const prove_s = secs(t0);
    t0 = now();
    try zk.verifyPublic(a, pc, st, key, pubs, &proof);
    const verify_s = secs(t0);
    const sz = proof.sizes();
    const budget = zw.budgetUsed();
    // re-randomized copy + link proof (the new copy also needs its own proximity proof)
    t0 = now();
    var rr = try zk.rerandomizeWeights(a, &pool, pc, &zw);
    defer rr.new.deinit(a);
    defer rr.link.deinit(a);
    const rerand_s = secs(t0);
    t0 = now();
    try zk.verifyWeightLink(a, pc, key, rr.new.key(), rr.link);
    const link_verify_s = secs(t0);
    const ws = try zk.witnessShape(a, pc, st, key);
    const wml = (@as(usize, 1) << @intCast(ws.log_cols)) + ws.slots;
    const wtlc = ws.log_cols;
    const kml = (@as(usize, 1) << @intCast(key.log_cols)) + key.slots;
    const cw = conjBits(queries, wml, @intCast(wtlc + lb), pow);
    const ck = conjBits(wq, kml, key.log_cols + wlb, pow);
    const pw = provenBits(queries, wml, @intCast(wtlc + lb), pow);
    const pk = provenBits(wq, kml, key.log_cols + wlb, pow);
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"mlp\",\"hiding\":true,\"log_t\":{d},\"log_d\":{d},\"log_f\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},\"weight_mask_slots\":{d},\"weight_log_blowup\":{d},\"weight_queries\":{d},\"weight_log_cols\":{d},\"witness_log_cols\":{d},\"public_io\":{},", .{ lt, ld, lf, threads, queries, lb, pow, pc.weight_mask_slots, wlb, wq, wlc, wtlc, public_io });
    try pcsJson(out, pc.two_level);
    try out.print("\"commit_weights_s\":{d:.4},\"weight_proximity_s\":{d:.4},\"weight_proximity_verify_s\":{d:.4},\"weight_proximity_bytes\":{d},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"verify_s\":{d:.5},", .{ commit_s, prox_s, prox_verify_s, prox.byteSize(), forward_s, prove_s, verify_s });
    try out.print("\"conjectured_bits\":{{\"witness\":{d:.1},\"weights\":{d:.1}}},\"proven_bits\":{{\"witness\":{d:.1},\"weights\":{d:.1}}},", .{ cw, ck, pw, pk });
    try levelsJson(out, "witness_levels", proof.opening);
    if (proof.weight_opening) |wo| try levelsJson(out, "weight_levels", wo);
    try stagesJson(out, tm);
    try out.print("\"proof_bytes\":{{\"sumchecks\":{d},\"witness_opening\":{d},\"weight_opening\":{d},\"total\":{d}}},\"rerandomize_link_s\":{d:.4},\"link_verify_s\":{d:.5},\"link_bytes\":{d},\"gkr_trees\":{d},\"gkr_layers\":{d},\"logup_bytes\":{d},\"weight_budget_used\":{d},\"weight_budget\":{d},\"witness_table_elems\":{d},\"peak_rss_bytes\":{d}}}\n", .{ sz.sumchecks, sz.witness_opening, sz.weight_opening, sz.total, rerand_s, link_verify_s, rr.link.byteSize(), proof.gkr_roots.len, proof.gkr_layers.len, sz.logup, budget[0], budget[1], tm.witness_table_elems, peakRssBytes() });
}
