//! tensor-bench: end-to-end benchmarks of the tensor frontend.
//!
//!   tensor-bench mlp <log_t> <log_d> <log_f> [threads] [queries] [log_blowup] [pow]
//!   tensor-bench layer <log_t> <log_d> <log_f> <log_heads> [threads] [queries] [log_blowup] [pow] [log_kv_heads] [n_layers] [log_experts] [log_capacity] [fused_qkv=1]
//!
//! Prints one JSON object with timings, sizes and derived metrics.
const std = @import("std");
const t = @import("stwo_tensor");
const f = t.field;
const proto = t.protocol;
const model = t.model;
const tf = t.transformer;
const build_options = @import("build_options");
const metal = if (build_options.metal) @import("stwo_tensor_metal") else struct {};

/// `--metal` anywhere on the command line selects the Metal GPU path.
var use_metal = false;
var gpu_ctx: if (build_options.metal) ?*metal.Gpu else ?*anyopaque = null;

fn accelFor() ?*const t.accel.Accel {
    if (!build_options.metal or !use_metal) return null;
    if (gpu_ctx == null) {
        gpu_ctx = metal.Gpu.init(std.heap.c_allocator) catch |e| std.debug.panic("metal init: {s}", .{@errorName(e)});
        if (std.posix.getenv("TENSOR_GKR_FUSED")) |v| gpu_ctx.?.gkr_fused_fold_sum = !std.mem.eql(u8, v, "0");
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
    if (gpu_ctx) |g| try out.print("\"metal\":{{\"commit_gpu_ms\":{d:.2},\"commit_calls\":{d},\"sc_gpu_ms\":{d:.2},\"matmul_gpu_ms\":{d:.2},\"mle_gpu_ms\":{d:.2},\"gkr_gpu_ms\":{d:.2},\"gkr_rounds\":{d},\"sc_rounds\":{d},\"sc_calls\":{d},\"wrapped_mb\":{d:.1},\"copied_mb\":{d:.1},\"pool_hits\":{d}}},", .{ g.stats.commit_gpu_ms, g.stats.commit_calls, g.stats.sc_gpu_ms, g.stats.matmul_gpu_ms, g.stats.mle_gpu_ms, g.stats.gkr_gpu_ms, g.stats.gkr_rounds, g.stats.sc_rounds, g.stats.sc_calls, @as(f64, @floatFromInt(g.stats.wrapped_bytes)) / 1048576.0, @as(f64, @floatFromInt(g.stats.copied_bytes)) / 1048576.0, g.stats.pool_hits });
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

/// Optional trailing args `<depth> [inner_queries] [inner_log_blowup] [inner_pow]`
/// select the recursive PCS (pcs2); absent = legacy flat Ligero.
fn twoLevel(args: []const [:0]u8, first: usize, outer: t.pcs.Params) !?t.pcs2.Params {
    if (args.len <= first) return null;
    var p = t.pcs2.Params{ .outer = outer, .depth = try std.fmt.parseInt(u32, args[first], 10) };
    p.inner.pow_bits = outer.pow_bits;
    if (args.len > first + 1) p.inner.n_queries = try std.fmt.parseInt(usize, args[first + 1], 10);
    if (args.len > first + 2) p.inner.log_blowup = try std.fmt.parseInt(u32, args[first + 2], 10);
    if (args.len > first + 3) p.inner.pow_bits = try std.fmt.parseInt(u32, args[first + 3], 10);
    if (args.len > first + 4) p.inner_work_shift = try std.fmt.parseInt(u32, args[first + 4], 10);
    if (args.len > first + 5) p.prox_rows = try std.fmt.parseInt(u32, args[first + 5], 10);
    return p;
}

fn printTl(out: anytype, pc: proto.Config) !void {
    if (pc.two_level) |tl| {
        try out.print("\"prox_rows\":{d},", .{tl.prox_rows});
        try out.print("\"pcs\":\"pcs2\",\"depth\":{d},\"inner_queries\":{d},\"inner_log_blowup\":{d},\"inner_pow\":{d},\"conjectured_bits\":{d:.1},\"proven_bits\":{d:.1},", .{ tl.depth, tl.inner.n_queries, tl.inner.log_blowup, tl.inner.pow_bits, tl.conjecturedBits(), tl.provenBits() });
    } else {
        try out.print("\"pcs\":\"flat\",\"conjectured_bits\":{d:.1},\"proven_bits\":{d:.1},", .{ pc.pcs.conjecturedBits(), pc.pcs.provenBits() });
    }
}

/// Per-level byte breakdown of a pcs2 opening: [cols, siblings, rows/inner].
fn printLevels(out: anytype, name: []const u8, op: proto.Opening) !void {
    if (op != .two) return;
    try out.print("\"{s}\":[", .{name});
    for (op.two.levels, 0..) |l, i| {
        const fin = i + 1 == op.two.levels.len;
        try out.print("{s}[{d},{d},{d}]", .{ if (i == 0) "" else ",", l.col_values.len * 4, l.decommit.len * 32, l.byteSize(fin) - l.col_values.len * 4 - l.decommit.len * 32 });
    }
    try out.print("],", .{});
}

fn peakRssBytes() u64 {
    var ru: std.posix.rusage = undefined;
    ru = std.posix.getrusage(std.posix.rusage.SELF);
    // macOS reports bytes
    return @intCast(ru.maxrss);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    _ = &gpa;
    // TENSOR_RECYCLE=1: keep freed large buffers for reuse (steady-state prover).
    var recycler = t.recycle.Recycler.init(std.heap.c_allocator);
    defer recycler.deinit();
    const a = if (std.posix.getenv("TENSOR_RECYCLE") != null) recycler.allocator() else std.heap.c_allocator;
    const all_args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, all_args);
    var kept: std.ArrayList([:0]u8) = .empty;
    defer kept.deinit(a);
    for (all_args) |arg| {
        if (std.mem.eql(u8, arg, "--metal")) use_metal = true else try kept.append(a, arg);
    }
    if (use_metal and !build_options.metal) return error.MetalNotBuilt;
    const args = kept.items;
    if (@import("zk_bench.zig").takeFlag(args)) |zargs| return @import("zk_bench.zig").main(a, zargs);
    if (args.len >= 3 and std.mem.eql(u8, args[1], "product")) return runProduct(a, args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "prims")) return @import("bench_prims.zig").run(a, if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 1);
    if (args.len >= 9 and std.mem.eql(u8, args[1], "model")) return runModel(args);
    if (args.len >= 6 and std.mem.eql(u8, args[1], "layer")) return runLayer(a, args);
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
    const fused: bool = if (std.posix.getenv("TENSOR_FUSED")) |v| !std.mem.eql(u8, v, "0") else true;
    var cfg = model.Mlp{ .log_t = lt, .log_d = ld, .log_f = lf, .fused = fused };
    var pc = proto.Config{
        .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow },
        .weight_log_cols = @min(ld, 13),
        .witness_log_cols_max = 14,
        .gkr_threads = threads,
        .gkr_min_parallel = if (std.posix.getenv("TENSOR_GKR_MINPAR")) |v| try std.fmt.parseInt(usize, v, 10) else (proto.Config{}).gkr_min_parallel,
        .accel = accelFor(),
    };
    pc.two_level = try twoLevel(args, 9, pc.pcs);
    // TENSOR_BATCH_MATMULS=1: shape-class batched matmul sumchecks (gate/up share)
    pc.batch_matmuls = if (std.posix.getenv("TENSOR_BATCH_MATMULS")) |v| std.mem.eql(u8, v, "1") else false;
    if (pc.accel != null) {
        // warm the device (pipeline state, first-dispatch costs) off the clock
        var wt = try t.pcs.Twiddles.init(a, 4);
        defer wt.deinit(a);
        var zero = [_]i32{0} ** 64;
        var wc = try t.accel.commit(pc.accel, i32, a, &pool, &wt, .{ .data = &zero, .log_rows = 2, .log_cols = 4 }, 0);
        wc.deinit(a);
    }

    const winfos = model.mlpWeightInfos(cfg);
    pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, &winfos, if (pc.batch_matmuls) 2 else 3);
    var wdata: [3][]i8 = undefined;
    for (&wdata, 0..) |*w, i| w.* = try model.randomWeights(a, winfos[i].size(), 100 + i, -8, 7);
    const wv = [_][]const i8{ wdata[0], wdata[1], wdata[2] };
    var t0 = now();
    var ws = try proto.commitWeights(a, &pool, pc, &winfos, &wv);
    const commit_s = secs(t0);
    t0 = now();
    // TENSOR_KEY_CPU=1 keeps the offline weight-key proof on the CPU
    var pc_key = pc;
    if (std.posix.getenv("TENSOR_KEY_CPU") != null) pc_key.accel = null;
    var prox = try t.weight_key.prove(a, &pool, pc_key, &ws);
    const prox_s = secs(t0);
    const kd = t.digest.keyProofDigest(prox);
    const key = proto.weightKey(&ws);
    t0 = now();
    try t.weight_key.verify(a, pc, key, &prox);
    const prox_verify_s = secs(t0);

    cfg.accel = pc.accel;
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 9);
    t0 = now();
    var built = try model.buildMlp(a, &pool, &ws, cfg, x);
    const forward_s = secs(t0);
    const st = built.statement();
    const wview = try a.alloc([]const i32, built.witness.len);
    for (built.witness, 0..) |w, i| wview[i] = w;
    var tm: proto.Timings = .{};
    t0 = now();
    // Default: reuse the forward pass's accumulators (TENSOR_RECOMPUTE_ACC=1 recomputes them inside prove).
    const recompute = std.posix.getenv("TENSOR_RECOMPUTE_ACC") != null;
    // TENSOR_PROVE_REPS=n: prove n times, report the fastest (first one separately).
    const reps: usize = if (std.posix.getenv("TENSOR_PROVE_REPS")) |v| try std.fmt.parseInt(usize, v, 10) else 1;
    var proof = if (recompute) try proto.prove(a, &pool, pc, st, &ws, wview, &tm) else try proto.proveWithAccumulators(a, &pool, pc, st, &ws, wview, built.accs, &tm);
    var prove_s = secs(t0);
    const prove_first_s = prove_s;
    for (1..@max(reps, 1)) |_| {
        proof.deinit(a);
        var tm2: proto.Timings = .{};
        t0 = now();
        proof = if (recompute) try proto.prove(a, &pool, pc, st, &ws, wview, &tm2) else try proto.proveWithAccumulators(a, &pool, pc, st, &ws, wview, built.accs, &tm2);
        const sec = secs(t0);
        if (sec < prove_s) {
            prove_s = sec;
            tm = tm2;
        }
    }
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
    try printTl(out, pc);
    try out.print("\"batch_matmuls\":{},", .{pc.batch_matmuls});
    try out.print("\"weight_log_cols\":{d},\"weights\":{d:.0},\"tokens\":{d:.0},\"macs\":{d:.0},\"witness_elems\":{d},\"witness_table_elems\":{d},", .{ pc.weight_log_cols, n_weights, T, macs, tm.witness_elems, tm.witness_table_elems });
    try out.print("\"commit_weights_s\":{d:.4},\"weight_key_proof_s\":{d:.4},\"weight_key_verify_s\":{d:.4},\"weight_key_bytes\":{d},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"verify_s\":{d:.5},", .{ commit_s, prox_s, prox_verify_s, prox.byteSize(), forward_s, prove_s, verify_s });
    try out.print("\"prove_reps\":{d},\"prove_first_s\":{d:.4},", .{ reps, prove_first_s });
    try out.print("\"recompute_acc\":{},\"prep_s\":{{\"accumulators\":{d:.4},\"multiplicities\":{d:.4}}},\"gkr_parts_s\":{{\"input\":{d:.4},\"build\":{d:.4},\"sumcheck\":{d:.4}}},", .{ recompute, nsToS(tm.accumulators_ns), nsToS(tm.multiplicities_ns), nsToS(tm.gkr_input_ns), nsToS(tm.gkr_build_ns), nsToS(tm.gkr_sumcheck_ns) });
    try out.print("\"stage_s\":{{\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4}}},", .{ nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns) });
    try out.print("\"proof_bytes\":{{\"gkr\":{d},\"sumchecks\":{d},\"witness_opening\":{d},\"weight_opening\":{d},\"total\":{d}}},", .{ sz.gkr, sz.sumchecks, sz.witness_opening, sz.weight_opening, sz.total });
    try printLevels(out, "witness_levels", proof.witness_opening);
    if (proof.weight_opening) |wo| try printLevels(out, "weight_levels", wo);
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",\"key_proof_digest\":\"{s}\",", .{ std.fmt.bytesToHex(pd, .lower), std.fmt.bytesToHex(kd, .lower) });
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
    var pc = proto.Config{ .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow }, .weight_log_cols = 2, .witness_log_cols_max = 14, .gkr_threads = threads };
    pc.two_level = try twoLevel(args, 7, pc.pcs);
    pc.accel = accelFor();
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
    try out.print("{{\"bench\":\"product\",\"log_n\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},", .{ ln, threads, queries, lb, pow });
    try printTl(out, pc);
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",", .{std.fmt.bytesToHex(digest, .lower)});
    try out.print("\"prove_s\":{d:.5},\"verify_s\":{d:.5},\"proof_bytes\":{d},\"prove_ns_per_entry\":{d:.2},\"stage_s\":{{\"witness_commit\":{d:.4},\"op_sumchecks\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4}}},\"peak_rss_bytes\":{d}}}\n", .{ best_prove, best_verify, size, best_prove * 1e9 / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(ln))), nsToS(tm.witness_commit_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), peakRssBytes() });
    built.deinit(a);
    ws.deinit(a);
    a.free(wview);
}

/// tensor-bench model <log_total> <used> <n_rows> <queries> <log_blowup> <depth> <inner_queries> <inner_log_blowup> [inner_work_shift]
/// Prints the pcs2 size model's chosen outer split and predicted opening bytes
/// (no proving; used for extrapolation).
fn runModel(args: []const [:0]u8) !void {
    const lt = try std.fmt.parseInt(u32, args[2], 10);
    const used = try std.fmt.parseInt(usize, args[3], 10);
    const nr = try std.fmt.parseInt(usize, args[4], 10);
    var p = t.pcs2.Params{
        .outer = .{ .n_queries = try std.fmt.parseInt(usize, args[5], 10), .log_blowup = try std.fmt.parseInt(u32, args[6], 10) },
        .depth = try std.fmt.parseInt(u32, args[7], 10),
    };
    p.inner.n_queries = if (args.len > 8) try std.fmt.parseInt(usize, args[8], 10) else p.inner.n_queries;
    p.inner.log_blowup = if (args.len > 9) try std.fmt.parseInt(u32, args[9], 10) else p.inner.log_blowup;
    if (args.len > 10) p.inner_work_shift = try std.fmt.parseInt(u32, args[10], 10);
    const b = t.pcs2.bestOuter(p, lt, used, nr, false, @min(lt, 30));
    const flat = t.pcs2.bestOuter(.{ .outer = p.outer, .depth = 0 }, lt, used, nr, false, @min(lt, 30));
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"log_total\":{d},\"used\":{d},\"n_rows\":{d},\"depth\":{d},\"log_cols\":{d},\"bytes\":{d:.0},\"flat_log_cols\":{d},\"flat_bytes\":{d:.0}}}\n", .{ lt, used, nr, p.depth, b.log_cols, b.bytes, flat.log_cols, flat.bytes });
}

/// tensor-bench layer <log_t> <log_d> <log_f> <log_heads> [threads] [queries] [log_blowup] [pow] [log_kv_heads] [n_layers] [log_experts] [log_capacity] [fused_qkv=1] [pcs2 depth inner_queries ...]
fn runLayer(a: std.mem.Allocator, args: []const [:0]u8) !void {
    const lt = try std.fmt.parseInt(u32, args[2], 10);
    const ld = try std.fmt.parseInt(u32, args[3], 10);
    const lf = try std.fmt.parseInt(u32, args[4], 10);
    const lh = try std.fmt.parseInt(u32, args[5], 10);
    const threads: usize = if (args.len > 6) try std.fmt.parseInt(usize, args[6], 10) else 12;
    const queries: usize = if (args.len > 7) try std.fmt.parseInt(usize, args[7], 10) else 64;
    const lb: u32 = if (args.len > 8) try std.fmt.parseInt(u32, args[8], 10) else 2;
    const pow: u32 = if (args.len > 9) try std.fmt.parseInt(u32, args[9], 10) else 20;
    const lkv: u32 = if (args.len > 10) try std.fmt.parseInt(u32, args[10], 10) else lh;
    const nl: u32 = if (args.len > 11) try std.fmt.parseInt(u32, args[11], 10) else 1;
    const le: u32 = if (args.len > 12) try std.fmt.parseInt(u32, args[12], 10) else 0;
    const lcap: u32 = if (args.len > 13) try std.fmt.parseInt(u32, args[13], 10) else lt;
    const fused = if (args.len > 14) (try std.fmt.parseInt(u32, args[14], 10)) != 0 else true;
    // fused QKV: every matmul output is >= D wide, so the weight table can
    // use 2^min(ld, lf) columns; unfused GQA caps it at 2^logDkv
    const wlc = @min(if (fused) @min(ld, lf) else cfg0Dkv(lh, lkv, ld), 13);
    const cfg = tf.LayerCfg{ .log_t = lt, .log_d = ld, .log_f = lf, .log_heads = lh, .log_kv_heads = lkv, .n_layers = nl, .log_experts = le, .log_capacity = lcap, .router_log_cols = wlc, .fused_qkv = fused };
    try cfg.validate();
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    var pc = proto.Config{
        .pcs = .{ .log_blowup = lb, .n_queries = queries, .pow_bits = pow },
        .weight_log_cols = wlc,
        .witness_log_cols_max = 14,
        .gkr_threads = threads,
    };
    pc.two_level = try twoLevel(args, 15, pc.pcs);
    pc.accel = accelFor();
    pc.batch_matmuls = if (std.posix.getenv("TENSOR_BATCH_MATMULS")) |v| std.mem.eql(u8, v, "1") else false;
    if (pc.two_level != null) {
        const wi = try tf.layerWeightInfos(a, cfg);
        defer a.free(wi);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, wi, wi.len);
    }
    var t0 = now();
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 100);
    const commit_s = secs(t0);
    var b = tf.Builder.init(a, &pool);
    const c = try tf.initCtx(&b, cfg, &sw.ws, 7);
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 9);
    t0 = now();
    _ = try tf.buildStack(&b, c, x);
    const forward_s = secs(t0);
    const st = b.statement();
    const wview = try b.witnessView(a);
    var tm: proto.Timings = .{};
    t0 = now();
    var proof = try proto.prove(a, &pool, pc, st, &sw.ws, wview, &tm);
    const prove_s = secs(t0);
    t0 = now();
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
    const verify_s = secs(t0);
    const sz = proof.sizes();
    var n_weights: usize = 0;
    for (sw.winfos) |wi| n_weights += wi.size();
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"layer\",\"log_t\":{d},\"log_d\":{d},\"log_f\":{d},\"log_heads\":{d},\"log_kv_heads\":{d},\"log_experts\":{d},\"log_capacity\":{d},\"fused_qkv\":{},\"weight_log_cols\":{d},\"n_layers\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},", .{ lt, ld, lf, lh, lkv, le, lcap, fused, wlc, nl, threads, queries, lb, pow });
    try printTl(out, pc);
    try out.print("\"weights\":{d},\"core_ops\":{d},\"ext_ops\":{d},\"witness_tensors\":{d},\"witness_elems\":{d},\"witness_table_elems\":{d},", .{ n_weights, st.ops.len, st.ext.ops.len, st.witness.len, tm.witness_elems, tm.witness_table_elems });
    try out.print("\"commit_weights_s\":{d:.4},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"verify_s\":{d:.5},", .{ commit_s, forward_s, prove_s, verify_s });
    try out.print("\"stage_s\":{{\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4},\"ext_init\":{d:.4},\"ext_terminal\":{d:.4}}},", .{ nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns), nsToS(tm.ext_init_ns), nsToS(tm.ext_terminal_ns) });
    try out.print("\"proof_bytes\":{{\"gkr\":{d},\"sumchecks\":{d},\"ext\":{d},\"witness_opening\":{d},\"weight_opening\":{d},\"total\":{d}}},\"peak_rss_bytes\":{d}}}\n", .{ sz.gkr, sz.sumchecks, proof.ext.byteSize(), sz.witness_opening, sz.weight_opening, sz.total, peakRssBytes() });
    proof.deinit(a);
    a.free(wview);
    b.deinit();
    sw.ws.deinit(a);
    for (sw.wdata) |w| a.free(w);
    a.free(sw.wdata);
    a.free(sw.winfos);
    a.free(x);
}

fn cfg0Dkv(lh: u32, lkv: u32, ld: u32) u32 {
    return lkv + (ld - lh);
}
