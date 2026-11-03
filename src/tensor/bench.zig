//! tensor-bench: end-to-end benchmarks of the tensor frontend.
//!
//!   tensor-bench mlp <log_t> <log_d> <log_f> [threads] [queries] [log_blowup] [pow]
//!
//! Prints one JSON object with timings, sizes and derived metrics.
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const proto = t.protocol;
const model = t.model;
const build_options = @import("build_options");
const metal = if (build_options.metal) @import("stwo_tensor_metal") else struct {};

/// `--metal` anywhere on the command line selects the Metal GPU path.
var use_metal = false;
var gpu_ctx: if (build_options.metal) ?*metal.Gpu else ?*anyopaque = null;

fn accelFor() ?*const t.accel.Accel {
    if (!build_options.metal or !use_metal) return null;
    if (gpu_ctx == null) {
        gpu_ctx = metal.Gpu.init(std.heap.c_allocator) catch |e| std.debug.panic("metal init: {s}", .{@errorName(e)});
        // tuning knob: TENSOR_GKR_CPU_LOG=k runs GKR layers of <= 2^k terms on the CPU
        if (std.posix.getenv("TENSOR_GKR_CPU_LOG")) |v| {
            const k = std.fmt.parseInt(u6, v, 10) catch 12;
            gpu_ctx.?.gkr_cpu_sum_max = @as(usize, 1) << k;
            gpu_ctx.?.gkr_cpu_fold_max = @as(usize, 1) << (k + 1);
        }
    }
    return gpu_ctx.?.accel();
}

fn printGpuStats(out: anytype) !void {
    if (!build_options.metal) return;
    if (gpu_ctx) |g| try out.print("\"metal\":{{\"commit_gpu_ms\":{d:.2},\"commit_calls\":{d},\"sc_gpu_ms\":{d:.2},\"matmul_gpu_ms\":{d:.2},\"mle_gpu_ms\":{d:.2},\"gkr_gpu_ms\":{d:.2},\"gkr_rounds\":{d},\"sc_rounds\":{d},\"sc_calls\":{d},\"wrapped_mb\":{d:.1},\"copied_mb\":{d:.1}}},", .{ g.stats.commit_gpu_ms, g.stats.commit_calls, g.stats.sc_gpu_ms, g.stats.matmul_gpu_ms, g.stats.mle_gpu_ms, g.stats.gkr_gpu_ms, g.stats.gkr_rounds, g.stats.sc_rounds, g.stats.sc_calls, @as(f64, @floatFromInt(g.stats.wrapped_bytes)) / 1048576.0, @as(f64, @floatFromInt(g.stats.copied_bytes)) / 1048576.0 });
}

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
    var ru: std.posix.rusage = undefined;
    ru = std.posix.getrusage(std.posix.rusage.SELF);
    // macOS reports bytes
    return @intCast(ru.maxrss);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    const a = std.heap.c_allocator;
    _ = &gpa;
    const all_args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, all_args);
    var kept: std.ArrayList([:0]u8) = .empty;
    defer kept.deinit(a);
    for (all_args) |arg| {
        if (std.mem.eql(u8, arg, "--metal")) use_metal = true else try kept.append(a, arg);
    }
    if (use_metal and !build_options.metal) return error.MetalNotBuilt;
    const args = kept.items;
    if (args.len >= 3 and std.mem.eql(u8, args[1], "product")) return runProduct(a, args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "prims")) return @import("bench_prims.zig").run(a, if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 1);
    if (args.len < 5 or !std.mem.eql(u8, args[1], "mlp")) {
        std.debug.print("usage: tensor-bench mlp <log_t> <log_d> <log_f> [threads] [queries] [log_blowup] [pow]\n", .{});
        return;
    }
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
    const fused: bool = if (args.len > 9) !std.mem.eql(u8, args[9], "0") else true;
    const cfg = model.Mlp{ .log_t = lt, .log_d = ld, .log_f = lf, .fused = fused };
    const pc = proto.Config{
        .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow },
        .weight_log_cols = @min(ld, 13),
        .witness_log_cols_max = 14,
        .gkr_threads = threads,
        .accel = accelFor(),
    };
    if (pc.accel != null) {
        // warm the device (pipeline state, first-dispatch costs) off the clock
        var wt = try t.pcs.Twiddles.init(a, 4);
        defer wt.deinit(a);
        var zero = [_]i32{0} ** 64;
        var wc = try t.accel.commit(pc.accel, i32, a, &pool, &wt, .{ .data = &zero, .log_rows = 2, .log_cols = 4 }, 0);
        wc.deinit(a);
    }

    const winfos = model.mlpWeightInfos(cfg);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var t0 = now();
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    const commit_s = secs(t0);
    t0 = now();
    var prox = try t.weight_key.prove(a, &pool, pc, &ws);
    const prox_s = secs(t0);
    const key = proto.weightKey(&ws);
    t0 = now();
    try t.weight_key.verify(a, pc, key, &prox);
    const prox_verify_s = secs(t0);

    const x = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 9);
    t0 = now();
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    const forward_s = secs(t0);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    t0 = now();
    var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
    const prove_s = secs(t0);
    t0 = now();
    try proto.verify(a, pc, st, key, &proof);
    const verify_s = secs(t0);
    const sz = proof.sizes();
    const pd = t.digest.proofDigest(proof);

    const T: f64 = @floatFromInt(@as(u64, 1) << @intCast(lt));
    const D: f64 = @floatFromInt(@as(u64, 1) << @intCast(ld));
    const F: f64 = @floatFromInt(@as(u64, 1) << @intCast(lf));
    const n_weights = 3.0 * D * F;
    const macs = T * n_weights;
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"mlp\",\"fused\":{},\"log_t\":{d},\"log_d\":{d},\"log_f\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},", .{ fused, lt, ld, lf, threads, queries, lb, pow });
    try out.print("\"conjectured_bits\":{d:.1},\"proven_bits\":{d:.1},\"weights\":{d:.0},\"tokens\":{d:.0},\"macs\":{d:.0},\"witness_elems\":{d},\"witness_table_elems\":{d},", .{ pc.pcs.conjecturedBits(), pc.pcs.provenBits(), n_weights, T, macs, tm.witness_elems, tm.witness_table_elems });
    try out.print("\"commit_weights_s\":{d:.4},\"weight_key_proof_s\":{d:.4},\"weight_key_verify_s\":{d:.4},\"weight_key_bytes\":{d},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"verify_s\":{d:.5},", .{ commit_s, prox_s, prox_verify_s, prox.byteSize(), forward_s, prove_s, verify_s });
    try out.print("\"stage_s\":{{\"prep\":{d:.4},\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"terminal\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4}}},", .{ nsToS(tm.prep_ns), nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.terminal_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns) });
    try out.print("\"proof_bytes\":{{\"gkr\":{d},\"sumchecks\":{d},\"witness_opening\":{d},\"weight_opening\":{d},\"total\":{d}}},", .{ sz.gkr, sz.sumchecks, sz.witness_opening, sz.weight_opening, sz.total });
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",", .{std.fmt.bytesToHex(pd, .lower)});
    try out.print("\"proved_macs_per_s\":{d:.4},\"prove_ns_per_weight\":{d:.4},\"prove_ns_per_token\":{d:.1},\"committed_bits_per_token\":{d:.1},\"peak_rss_bytes\":{d}}}\n", .{ macs / prove_s, prove_s * 1e9 / n_weights, prove_s * 1e9 / T, @as(f64, @floatFromInt(tm.witness_table_elems)) * 32.0 / T, peakRssBytes() });
    proof.deinit(a);
    built.deinit(a);
    prox.deinit(a);
    ws.deinit(a);
}

/// tensor-bench product <log_n> [threads] [queries] [log_blowup] [pow]
fn runProduct(a: std.mem.Allocator, args: []const [:0]u8) !void {
    const ln = try std.fmt.parseInt(u32, args[2], 10);
    const threads: usize = if (args.len > 3) try std.fmt.parseInt(usize, args[3], 10) else 1;
    const queries: usize = if (args.len > 4) try std.fmt.parseInt(usize, args[4], 10) else 54;
    const lb: u32 = if (args.len > 5) try std.fmt.parseInt(u32, args[5], 10) else 2;
    const pow: u32 = if (args.len > 6) try std.fmt.parseInt(u32, args[6], 10) else 20;
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    const pc = proto.Config{ .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow }, .weight_log_cols = 2, .witness_log_cols_max = 14, .gkr_threads = threads, .accel = accelFor() };
    const dummy_info = [_]proto.TensorInfo{proto.TensorInfo.mat(2, 2)};
    var dummy: [16]i8 = [_]i8{0} ** 16;
    const dv = [_][]const i8{&dummy};
    var ws = try proto.commitWeights(a, &pool, pc, &dummy_info, &dv);
    var built = try model.buildProduct(a, ln, 5);
    var st = built.statement();
    st.weights = &dummy_info;
    const wview = try a.alloc([]const i32, built.witness.len);
    for (built.witness, 0..) |w, i| wview[i] = w;
    // warm-up (page faults, thread pool), then timed run
    var best_prove: f64 = 1e30;
    var best_verify: f64 = 1e30;
    var tm: proto.Timings = .{};
    var size: usize = 0;
    var digest: [32]u8 = undefined;
    var rep: usize = 0;
    while (rep < 3) : (rep += 1) {
        tm = .{};
        var t0 = now();
        var proof = try proto.prove(a, &pool, pc, st, &ws, wview, &tm);
        best_prove = @min(best_prove, secs(t0));
        t0 = now();
        try proto.verify(a, pc, st, proto.weightKey(&ws), &proof);
        best_verify = @min(best_verify, secs(t0));
        size = proof.sizes().total;
        digest = t.digest.proofDigest(proof);
        proof.deinit(a);
    }
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"product\",\"log_n\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},\"conjectured_bits\":{d:.1},\"proven_bits\":{d:.1},", .{ ln, threads, queries, lb, pow, pc.pcs.conjecturedBits(), pc.pcs.provenBits() });
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",", .{std.fmt.bytesToHex(digest, .lower)});
    try out.print("\"prove_s\":{d:.5},\"verify_s\":{d:.5},\"proof_bytes\":{d},\"prove_ns_per_entry\":{d:.2},\"stage_s\":{{\"witness_commit\":{d:.4},\"op_sumchecks\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4}}},\"peak_rss_bytes\":{d}}}\n", .{ best_prove, best_verify, size, best_prove * 1e9 / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(ln))), nsToS(tm.witness_commit_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), peakRssBytes() });
    built.deinit(a);
    ws.deinit(a);
    a.free(wview);
}
