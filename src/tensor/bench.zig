//! tensor-bench: end-to-end benchmarks of the tensor frontend.
//!
//!   tensor-bench mlp <log_t> <log_d> <log_f> [threads] [queries] [log_blowup] [pow]
//!   tensor-bench layer <log_t> <log_d> <log_f> <log_heads> [threads] [queries] [log_blowup] [pow] [log_kv_heads] [n_layers] [log_experts] [log_capacity] [fused_qkv=1]
//!   tensor-bench model key=value ...   (model-scale serving bench; see runServe)
//!   tensor-bench size-model ...        (pcs2 size model, no proving)
//!
//! Default configuration: pcs2 (depth 2, inner 54 queries) + batched matmuls
//! (proto.recommendedConfig). TENSOR_PCS=flat / TENSOR_BATCH_MATMULS=0 select
//! the legacy flat Ligero / per-matmul sumchecks for comparison.
//!
//! Prints one JSON object with timings, sizes and derived metrics.
//! `--emit <dir>` also writes statement.bin / key.bin / proof.bin (wire.zig)
//! for `tensor-verify <dir>`; "encoded_bytes" reports the true wire sizes.
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
        // TENSOR_LAZY_ROUNDS=k: lazy (on-the-fly folded) rounds before the first materialised fold
        if (std.posix.getenv("TENSOR_LAZY_ROUNDS")) |v| gpu_ctx.?.lazy_rounds = std.fmt.parseInt(u32, v, 10) catch 1;
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

/// `--emit <dir>`: write statement.bin, key.bin and proof.bin (wire.zig) for tensor-verify.
var emit_dir: ?[]const u8 = null;

/// Prints the true encoded sizes ("encoded_bytes") next to the struct-sum
/// sizes and, with --emit, writes the files. The key proof is proven here
/// when the bench did not already prove one (only with --emit).
fn wireOut(out: anytype, a: std.mem.Allocator, pool: *f.Pool, pc: proto.Config, st: proto.Statement, ws: *const proto.WeightStore, kp_in: ?*const t.weight_key.KeyProof, proof: *const proto.Proof) !void {
    const pb = try t.wire.encodeProof(a, proof.*);
    defer a.free(pb);
    const sb = try t.wire.encodeStatement(a, pc, st);
    defer a.free(sb);
    var kp_own: ?t.weight_key.KeyProof = null;
    defer if (kp_own) |*k| k.deinit(a);
    if (kp_in == null and emit_dir != null) kp_own = try t.weight_key.prove(a, pool, pc, ws);
    const kp: ?*const t.weight_key.KeyProof = kp_in orelse if (kp_own) |*k| k else null;
    const kb: ?[]u8 = if (kp) |k| try t.wire.encodeKey(a, proto.weightKey(ws), k.*) else null;
    defer if (kb) |x| a.free(x);
    try out.print("\"encoded_bytes\":{{\"proof\":{d},\"struct_sum\":{d},\"statement\":{d}", .{ pb.len, proof.sizes().total, sb.len });
    if (kb) |x| try out.print(",\"key\":{d},\"key_struct_sum\":{d}", .{ x.len, kp.?.byteSize() });
    try out.print("}},", .{});
    const dir_path = emit_dir orelse return;
    try std.fs.cwd().makePath(dir_path);
    var dir = try std.fs.cwd().openDir(dir_path, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "statement.bin", .data = sb });
    try dir.writeFile(.{ .sub_path = "key.bin", .data = kb.? });
    try dir.writeFile(.{ .sub_path = "proof.bin", .data = pb });
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
/// select the recursive PCS (pcs2). Absent: the recommended configuration
/// (proto.recommendedConfig: depth 2, inner 54 queries, the outer blowup and
/// PoW), unless TENSOR_PCS=flat selects the legacy flat Ligero.
fn twoLevel(args: []const [:0]u8, first: usize, outer: t.pcs.Params) !?t.pcs2.Params {
    if (args.len <= first) {
        if (std.posix.getenv("TENSOR_PCS")) |v| if (std.mem.eql(u8, v, "flat")) return null;
        return proto.recommendedConfig(outer, .{ .n_queries = 54, .log_blowup = outer.log_blowup, .pow_bits = outer.pow_bits }).two_level;
    }
    var p = t.pcs2.Params{ .outer = outer, .depth = try std.fmt.parseInt(u32, args[first], 10) };
    p.inner.pow_bits = outer.pow_bits;
    if (args.len > first + 1) p.inner.n_queries = try std.fmt.parseInt(usize, args[first + 1], 10);
    if (args.len > first + 2) p.inner.log_blowup = try std.fmt.parseInt(u32, args[first + 2], 10);
    if (args.len > first + 3) p.inner.pow_bits = try std.fmt.parseInt(u32, args[first + 3], 10);
    if (args.len > first + 4) p.inner_work_shift = try std.fmt.parseInt(u32, args[first + 4], 10);
    if (args.len > first + 5) p.prox_rows = try std.fmt.parseInt(u32, args[first + 5], 10);
    // beyond unique decoding / level-specific parameters (security.md):
    //   TENSOR_OOD=1                      OOD samples on witness + committed rows
    //   TENSOR_DEEP=<q>,<lb>[,<pow>]      parameters of committed-row levels >= 2
    if (std.posix.getenv("TENSOR_OOD")) |v| p.ood = std.mem.eql(u8, v, "1");
    if (std.posix.getenv("TENSOR_DEEP")) |v| p.deep = try parseParams(v, p.inner.pow_bits, null);
    return p;
}

/// Batched matmul sumchecks: on by default (recommended config);
/// TENSOR_BATCH_MATMULS=0 turns them off.
fn batchMatmuls() bool {
    return if (std.posix.getenv("TENSOR_BATCH_MATMULS")) |v| !std.mem.eql(u8, v, "0") else true;
}

/// TENSOR_PREFAULT=0: allocate and fault the GKR key inputs at the GKR stage
/// (as before) instead of during the witness commitment.
fn prefault() bool {
    return if (std.posix.getenv("TENSOR_PREFAULT")) |v| !std.mem.eql(u8, v, "0") else true;
}

/// Warm the CPU GKR layer blocks during the witness commitment. It only pays
/// with the recycler, so it follows it (on unless TENSOR_RECYCLE=0);
/// TENSOR_WARM_GKR=0 turns it off.
fn warmLayers() bool {
    if (std.posix.getenv("TENSOR_RECYCLE")) |v| if (std.mem.eql(u8, v, "0")) return false;
    return if (std.posix.getenv("TENSOR_WARM_GKR")) |v| !std.mem.eql(u8, v, "0") else true;
}

/// "<q>,<lb>[,<pow>]" (or "<q>[,<pow>]" when the blowup is fixed)
fn parseParams(v: []const u8, pow_default: u32, fixed_lb: ?u32) !t.pcs.Params {
    var it = std.mem.splitScalar(u8, v, ',');
    var p = t.pcs.Params{ .pow_bits = pow_default };
    p.n_queries = try std.fmt.parseInt(usize, it.next() orelse return error.BadParams, 10);
    if (fixed_lb) |lb| p.log_blowup = lb else p.log_blowup = try std.fmt.parseInt(u32, it.next() orelse return error.BadParams, 10);
    if (it.next()) |x| p.pow_bits = try std.fmt.parseInt(u32, x, 10);
    return p;
}

/// TENSOR_WEIGHT_Q=<q>[,<pow>] (per-batch weight openings), TENSOR_KEY_Q=<q>[,<pow>]
/// (weight-key proximity): outer-level parameters at the outer blowup.
fn weightParams(pc: *proto.Config) !void {
    const o = proto.outerParams(pc.*);
    if (std.posix.getenv("TENSOR_WEIGHT_Q")) |v| pc.weight_outer = try parseParams(v, o.pow_bits, o.log_blowup);
    if (std.posix.getenv("TENSOR_KEY_Q")) |v| pc.key_outer = try parseParams(v, o.pow_bits, o.log_blowup);
    // TENSOR_KEY_ALPHAS=2: two independent LogUp alpha in the weight-key proof
    if (std.posix.getenv("TENSOR_KEY_ALPHAS")) |v| pc.key_alphas = try std.fmt.parseInt(u32, v, 10);
    // TENSOR_WEIGHT_PROX=0: per-batch weight openings without their own
    // proximity test (binding from the key's distance, security.md 4)
    if (std.posix.getenv("TENSOR_WEIGHT_PROX")) |v| pc.weight_proximity = !std.mem.eql(u8, v, "0");
}

fn printSecurity(out: anytype, a: std.mem.Allocator, pc: proto.Config, st: proto.Statement, key: proto.WeightKey, proof: *const proto.Proof, kp: ?*const t.weight_key.KeyProof) !void {
    var rep = try t.security.accountProof(a, pc, st, key, proof, kp);
    defer rep.deinit();
    try t.security.writeReport(rep, out);
    if (pc.weight_outer) |w| try out.print("\"weight_queries\":{d},", .{w.n_queries});
    if (pc.key_outer) |k| try out.print("\"key_queries\":{d},", .{k.n_queries});
    try out.print("\"key_alphas\":{d},", .{pc.key_alphas});
    if (pc.two_level) |tl| {
        try out.print("\"ood\":{},", .{tl.ood});
        if (tl.deep) |d| try out.print("\"deep\":[{d},{d},{d}],", .{ d.n_queries, d.log_blowup, d.pow_bits });
    }
}

/// `weight_openings`: the proof opens the weight table per batch. Without a
/// per-batch proximity test such openings are bound only at the key's proven
/// distance, so no conjectured figure is printed (null; see "security").
fn printTl(out: anytype, pc: proto.Config, weight_openings: bool) !void {
    const conj_ok = !weight_openings or pc.weight_proximity;
    try out.print("\"weight_proximity\":{},", .{pc.weight_proximity});
    if (pc.two_level) |tl| {
        try out.print("\"prox_rows\":{d},", .{tl.prox_rows});
        try out.print("\"pcs\":\"pcs2\",\"depth\":{d},\"inner_queries\":{d},\"inner_log_blowup\":{d},\"inner_pow\":{d},", .{ tl.depth, tl.inner.n_queries, tl.inner.log_blowup, tl.inner.pow_bits });
        try printConj(out, conj_ok, tl.conjecturedBits(), tl.provenBits());
    } else {
        try out.print("\"pcs\":\"flat\",", .{});
        try printConj(out, conj_ok, pc.pcs.conjecturedBits(), pc.pcs.provenBits());
    }
}

fn printConj(out: anytype, conj_ok: bool, conj: f64, proven: f64) !void {
    if (conj_ok) try out.print("\"conjectured_bits\":{d:.1},", .{conj}) else try out.print("\"conjectured_bits\":null,", .{});
    try out.print("\"proven_bits\":{d:.1},", .{proven});
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
    // Large buffers go through the recycling allocator by default: blocks freed
    // by the weight commitment, the forward pass and earlier prover stages are
    // reused instead of faulting in fresh pages (CPU single shot: layer 512
    // 1.09-1.16 -> 0.96 s, peak RSS +0.1 GB; see speed.md). TENSOR_RECYCLE=0
    // uses the system allocator directly. Allocation only; proofs are unchanged.
    var recycler = t.recycle.Recycler.init(std.heap.c_allocator);
    defer recycler.deinit();
    const no_recycle = if (std.posix.getenv("TENSOR_RECYCLE")) |v| std.mem.eql(u8, v, "0") else false;
    const a = if (no_recycle) std.heap.c_allocator else recycler.allocator();
    const all_args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, all_args);
    var kept: std.ArrayList([:0]u8) = .empty;
    defer kept.deinit(a);
    var ai: usize = 0;
    while (ai < all_args.len) : (ai += 1) {
        const arg = all_args[ai];
        if (std.mem.eql(u8, arg, "--metal")) {
            use_metal = true;
        } else if (std.mem.eql(u8, arg, "--emit") and ai + 1 < all_args.len) {
            ai += 1;
            emit_dir = all_args[ai];
        } else try kept.append(a, arg);
    }
    if (use_metal and !build_options.metal) return error.MetalNotBuilt;
    const args = kept.items;
    if (@import("zk_bench.zig").takeFlag(args)) |zargs| return @import("zk_bench.zig").mainAccel(a, zargs, accelFor());
    if (args.len >= 3 and std.mem.eql(u8, args[1], "product")) return runProduct(a, args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "prims")) return @import("bench_prims.zig").run(a, if (args.len > 2) try std.fmt.parseInt(usize, args[2], 10) else 1);
    if (args.len >= 9 and std.mem.eql(u8, args[1], "size-model")) return runModel(args);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "model")) return runServe(a, args);
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
    try weightParams(&pc);
    // TENSOR_BATCH_MATMULS=1: shape-class batched matmul sumchecks (gate/up share)
    pc.batch_matmuls = batchMatmuls();
    pc.prefault_gkr_inputs = prefault();
    pc.warm_gkr_layers = warmLayers();
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
    try printTl(out, pc, true);
    try out.print("\"batch_matmuls\":{},", .{pc.batch_matmuls});
    try out.print("\"weight_log_cols\":{d},\"weights\":{d:.0},\"tokens\":{d:.0},\"macs\":{d:.0},\"witness_elems\":{d},\"witness_table_elems\":{d},", .{ pc.weight_log_cols, n_weights, T, macs, tm.witness_elems, tm.witness_table_elems });
    try out.print("\"commit_weights_s\":{d:.4},\"weight_key_proof_s\":{d:.4},\"weight_key_verify_s\":{d:.4},\"weight_key_bytes\":{d},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"verify_s\":{d:.5},", .{ commit_s, prox_s, prox_verify_s, prox.byteSize(), forward_s, prove_s, verify_s });
    try out.print("\"prove_reps\":{d},\"prove_first_s\":{d:.4},", .{ reps, prove_first_s });
    try out.print("\"recompute_acc\":{},\"prep_s\":{{\"accumulators\":{d:.4},\"multiplicities\":{d:.4}}},\"gkr_parts_s\":{{\"input\":{d:.4},\"build\":{d:.4},\"sumcheck\":{d:.4}}},", .{ recompute, nsToS(tm.accumulators_ns), nsToS(tm.multiplicities_ns), nsToS(tm.gkr_input_ns), nsToS(tm.gkr_build_ns), nsToS(tm.gkr_sumcheck_ns) });
    try out.print("\"stage_s\":{{\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4}}},", .{ nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns) });
    try out.print("\"proof_bytes\":{{\"gkr\":{d},\"sumchecks\":{d},\"witness_opening\":{d},\"weight_opening\":{d},\"total\":{d}}},", .{ sz.gkr, sz.sumchecks, sz.witness_opening, sz.weight_opening, sz.total });
    try printLevels(out, "witness_levels", proof.witness_opening);
    if (proof.weight_opening) |wo| try printLevels(out, "weight_levels", wo);
    try printSecurity(out, a, pc, st, key, &proof, &prox);
    try wireOut(out, a, &pool, pc, st, &ws, &prox, &proof);
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
    try weightParams(&pc);
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
    var last: ?proto.Proof = null;
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
        if (rep + 1 < 3) proof.deinit(a) else last = proof;
    }
    defer last.?.deinit(a);
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"product\",\"log_n\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},", .{ ln, threads, queries, lb, pow });
    try printTl(out, pc, false);
    try printSecurity(out, a, pc, st, proto.weightKey(&ws), &last.?, null);
    try printLevels(out, "witness_levels", last.?.witness_opening);
    try wireOut(out, a, &pool, pc, st, &ws, null, &last.?);
    if (last.?.witness_opening == .two) {
        var inf: proto.VerifyInfo = .{};
        try proto.verifyInfo(a, pc, st, proto.weightKey(&ws), &last.?, &inf);
        const li = try t.security.openingInfos(a, pc, inf.witness_shape, inf.witness_groups, true);
        defer a.free(li);
        try out.print("\"witness_shapes\":[", .{});
        for (li, 0..) |l, i| try out.print("{s}[{d},{d},{d},{d}]", .{ if (i == 0) "" else ",", l.log_rows, l.log_cols, l.rows_used, l.n_rows });
        try out.print("],", .{});
    }
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",", .{std.fmt.bytesToHex(digest, .lower)});
    try out.print("\"prove_s\":{d:.5},\"verify_s\":{d:.5},\"proof_bytes\":{d},\"prove_ns_per_entry\":{d:.2},\"stage_s\":{{\"witness_commit\":{d:.4},\"op_sumchecks\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4}}},\"peak_rss_bytes\":{d}}}\n", .{ best_prove, best_verify, size, best_prove * 1e9 / @as(f64, @floatFromInt(@as(u64, 1) << @intCast(ln))), nsToS(tm.witness_commit_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), peakRssBytes() });
    built.deinit(a);
    ws.deinit(a);
    a.free(wview);
}

/// tensor-bench size-model <log_total> <used> <n_rows> <queries> <log_blowup> <depth> <inner_queries> <inner_log_blowup> [inner_work_shift]
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
        .gkr_min_parallel = if (std.posix.getenv("TENSOR_GKR_MINPAR")) |v| try std.fmt.parseInt(usize, v, 10) else (proto.Config{}).gkr_min_parallel,
    };
    pc.two_level = try twoLevel(args, 15, pc.pcs);
    try weightParams(&pc);
    pc.accel = accelFor();
    pc.batch_matmuls = batchMatmuls();
    pc.prefault_gkr_inputs = prefault();
    pc.warm_gkr_layers = warmLayers();
    if (pc.two_level != null) {
        const wi = try tf.layerWeightInfos(a, cfg);
        defer a.free(wi);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, wi, wi.len);
    }
    var t0 = now();
    var sw = try tf.setupWeights(a, &pool, cfg, pc, 100);
    const commit_s = secs(t0);
    var b = tf.Builder.init(a, &pool);
    // Default: keep the forward pass's accumulators for the prover
    // (TENSOR_RECOMPUTE_ACC=1 recomputes them inside prove, as for mlp).
    const recompute = std.posix.getenv("TENSOR_RECOMPUTE_ACC") != null;
    b.keep_accs = !recompute;
    b.accel = pc.accel;
    const c = try tf.initCtx(&b, cfg, &sw.ws, 7);
    const x = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 9);
    t0 = now();
    _ = try tf.buildStack(&b, c, x);
    const forward_s = secs(t0);
    const st = b.statement();
    const wview = try b.witnessView(a);
    var tm: proto.Timings = .{};
    t0 = now();
    var proof = if (recompute) try proto.prove(a, &pool, pc, st, &sw.ws, wview, &tm) else try proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wview, b.coreAccs(), b.extAccs(), &tm);
    var prove_s = secs(t0);
    const prove_first_s = prove_s;
    const pd_first = t.digest.proofDigest(proof);
    // TENSOR_PROVE_REPS=n: prove n times (steady state; the recycler is on unless TENSOR_RECYCLE=0), report the fastest
    const reps: usize = if (std.posix.getenv("TENSOR_PROVE_REPS")) |v| try std.fmt.parseInt(usize, v, 10) else 1;
    for (1..@max(reps, 1)) |_| {
        proof.deinit(a);
        var tm2: proto.Timings = .{};
        t0 = now();
        proof = if (recompute) try proto.prove(a, &pool, pc, st, &sw.ws, wview, &tm2) else try proto.proveWithAllAccumulators(a, &pool, pc, st, &sw.ws, wview, b.coreAccs(), b.extAccs(), &tm2);
        const sec = secs(t0);
        if (!std.mem.eql(u8, &t.digest.proofDigest(proof), &pd_first)) return error.NondeterministicProof;
        if (sec < prove_s) {
            prove_s = sec;
            tm = tm2;
        }
    }
    t0 = now();
    try proto.verify(a, pc, st, proto.weightKey(&sw.ws), &proof);
    const verify_s = secs(t0);
    const sz = proof.sizes();
    var n_weights: usize = 0;
    for (sw.winfos) |wi| n_weights += wi.size();
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"layer\",\"log_t\":{d},\"log_d\":{d},\"log_f\":{d},\"log_heads\":{d},\"log_kv_heads\":{d},\"log_experts\":{d},\"log_capacity\":{d},\"fused_qkv\":{},\"weight_log_cols\":{d},\"n_layers\":{d},\"threads\":{d},\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},", .{ lt, ld, lf, lh, lkv, le, lcap, fused, wlc, nl, threads, queries, lb, pow });
    try printTl(out, pc, true);
    try out.print("\"weights\":{d},\"core_ops\":{d},\"ext_ops\":{d},\"witness_tensors\":{d},\"witness_elems\":{d},\"witness_table_elems\":{d},", .{ n_weights, st.ops.len, st.ext.ops.len, st.witness.len, tm.witness_elems, tm.witness_table_elems });
    try out.print("\"recompute_acc\":{},\"batch_matmuls\":{},\"commit_weights_s\":{d:.4},\"forward_s\":{d:.4},\"prove_s\":{d:.4},\"prove_first_s\":{d:.4},\"prove_reps\":{d},\"verify_s\":{d:.5},", .{ recompute, pc.batch_matmuls, commit_s, forward_s, prove_s, prove_first_s, reps, verify_s });
    try out.print("\"prep_s\":{{\"accumulators\":{d:.4},\"multiplicities\":{d:.4}}},\"gkr_parts_s\":{{\"input\":{d:.4},\"build\":{d:.4},\"sumcheck\":{d:.4}}},\"terminal_s\":{d:.4},", .{ nsToS(tm.accumulators_ns), nsToS(tm.multiplicities_ns), nsToS(tm.gkr_input_ns), nsToS(tm.gkr_build_ns), nsToS(tm.gkr_sumcheck_ns), nsToS(tm.terminal_ns) });
    try printGpuStats(out);
    try out.print("\"proof_digest\":\"{s}\",\"full_digest\":\"{s}\",", .{ std.fmt.bytesToHex(pd_first, .lower), std.fmt.bytesToHex(t.digest.fullDigest(proof), .lower) });
    try out.print("\"stage_s\":{{\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"weight_open\":{d:.4},\"ext_init\":{d:.4},\"ext_terminal\":{d:.4},\"ext_ops\":{d:.4}}},", .{ nsToS(tm.witness_commit_ns), nsToS(tm.gkr_ns), nsToS(tm.op_sumcheck_ns), nsToS(tm.weight_fold_ns), nsToS(tm.batch_ns), nsToS(tm.witness_open_ns), nsToS(tm.weight_open_ns), nsToS(tm.ext_init_ns), nsToS(tm.ext_terminal_ns), nsToS(tm.ext_ops_ns) });
    try printSecurity(out, a, pc, st, proto.weightKey(&sw.ws), &proof, null);
    try wireOut(out, a, &pool, pc, st, &sw.ws, null, &proof);
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

// ---------------------------------------------------------------------------
// tensor-bench model: per-request serving at model scale (lm.zig + serve.zig).

const KV = struct {
    args: []const [:0]u8,
    fn get(self: KV, k: []const u8, default: u64) !u64 {
        for (self.args[2..]) |arg| {
            const eq = std.mem.indexOfScalar(u8, arg, '=') orelse continue;
            if (std.mem.eql(u8, arg[0..eq], k)) return std.fmt.parseInt(u64, arg[eq + 1 ..], 10);
        }
        return default;
    }
};

/// tensor-bench model [t=8] [d=10] [f=12] [h=3] [kv=1] [layers=4] [e=3] [fe=11] [cap=0] [v=15] [out=0]
///   [r=1] [threads=12] [q=54] [lb=2] [pow=20] [depth=2] [iq=54] [ilb=2] [ipow=20] [bm=1] [verify=r]
///   [seed=1] [calib=1] [key=1] [moe_every=2] [stacked=1] [--metal]
/// log2 sizes: t tokens/window, d model, f dense MLP, h query heads, kv KV heads,
/// e experts (0 = dense), fe expert width, cap slots per expert (0 = fitted per
/// request), v vocab, out checked output positions; r requests per batch;
/// depth=0 selects flat Ligero; calib = router calibration passes; key=0 skips
/// the offline weight-key proof.
fn runServe(a: std.mem.Allocator, args: []const [:0]u8) !void {
    const kv = KV{ .args = args };
    const lt: u32 = @intCast(try kv.get("t", 8));
    const ld: u32 = @intCast(try kv.get("d", 10));
    const lf: u32 = @intCast(try kv.get("f", 12));
    const le: u32 = @intCast(try kv.get("e", 3));
    const lfe: u32 = @intCast(try kv.get("fe", 11));
    const R: usize = @intCast(try kv.get("r", 1));
    const threads: usize = @intCast(try kv.get("threads", 12));
    const cap_arg = try kv.get("cap", 0);
    const n_verify: usize = @min(R, @as(usize, @intCast(try kv.get("verify", R))));
    var cfg = t.lm.ModelCfg{
        .log_t = lt,
        .log_d = ld,
        .log_f = lf,
        .log_heads = @intCast(try kv.get("h", 3)),
        .log_kv_heads = @intCast(try kv.get("kv", 1)),
        .n_layers = @intCast(try kv.get("layers", 4)),
        .log_experts = le,
        .log_f_expert = lfe,
        .log_capacity = if (cap_arg == 0) lt else @intCast(cap_arg),
        .log_vocab = @intCast(try kv.get("v", 15)),
        .log_out = @intCast(try kv.get("out", 0)),
        .moe_every = @intCast(try kv.get("moe_every", 2)),
        .stacked_experts = (try kv.get("stacked", 1)) != 0,
    };
    const outer = t.pcs.Params{ .n_queries = @intCast(try kv.get("q", 54)), .log_blowup = @intCast(try kv.get("lb", 2)), .pow_bits = @intCast(try kv.get("pow", 20)) };
    var pc = proto.Config{ .pcs = outer, .witness_log_cols_max = 14, .gkr_threads = threads, .batch_matmuls = (try kv.get("bm", 1)) != 0 };
    const depth: u32 = @intCast(try kv.get("depth", 2));
    if (depth > 0) {
        pc.two_level = .{ .outer = outer, .depth = depth, .inner = .{ .n_queries = @intCast(try kv.get("iq", 54)), .log_blowup = @intCast(try kv.get("ilb", 2)), .pow_bits = @intCast(try kv.get("ipow", 20)) } };
    }
    // every matmul output is >= min(D, F, F_e) wide (fused QKV); the router is padded to it
    var wlc = @min(@min(ld, lf), 13);
    if (le > 0) wlc = @min(wlc, lfe);
    cfg.weight_log_cols = wlc;
    pc.weight_log_cols = wlc;
    try cfg.validate();
    pc.accel = accelFor();
    var pool: f.Pool = undefined;
    try pool.init(a, threads);
    defer pool.deinit();
    if (pc.two_level != null) {
        const wi = try t.lm.weightInfos(a, cfg);
        defer a.free(wi);
        pc.weight_log_cols = try proto.chooseWeightLogCols(pc, a, wi, wi.len * R);
    }
    // wlc=n overrides the weight-table column count
    if (try kv.get("wlc", 0) != 0) pc.weight_log_cols = @intCast(try kv.get("wlc", 0));
    const seed = try kv.get("seed", 1);

    // --- offline: commit the weights, weight key proof
    var t0 = now();
    var sw = try t.lm.setupWeights(a, &pool, cfg, pc, 100 + seed);
    const commit_s = secs(t0);
    for (sw.wdata) |w| a.free(w); // the store keeps its own table
    a.free(sw.wdata);
    sw.wdata = &.{};
    // calib=n: n passes of router calibration (balanced routing, as a trained
    // MoE router), then re-commit (not timed as commit)
    const calib: usize = @intCast(try kv.get("calib", 1));
    t0 = now();
    if (le > 0 and calib > 0) {
        const xc = try model.randomInput(a, @as(usize, 1) << @intCast(lt + ld), 999_999);
        defer a.free(xc);
        try t.lm.calibrateRouters(a, &pool, cfg, &sw.ws, xc, calib);
        try t.lm.recommit(a, &pool, pc, &sw.ws);
    }
    const calib_s = secs(t0);
    const rss_after_commit = peakRssBytes();
    // key=0 skips the offline weight-key proof (its GKR over every weight sets
    // the offline memory peak; the online numbers do not depend on it)
    const with_key = (try kv.get("key", 1)) != 0;
    t0 = now();
    var pc_key = pc;
    if (std.posix.getenv("TENSOR_KEY_CPU") != null) pc_key.accel = null;
    var prox: ?t.weight_key.KeyProof = if (with_key) try t.weight_key.prove(a, &pool, pc_key, &sw.ws) else null;
    const key_s = secs(t0);
    const key = proto.weightKey(&sw.ws);
    t0 = now();
    if (prox) |*p| try t.weight_key.verify(a, pc, key, p);
    const key_verify_s = secs(t0);
    const rss_after_key = peakRssBytes();

    // --- online: R requests, each built (forward pass) and proved, witness dropped
    const builders = try a.alloc(tf.Builder, R);
    defer a.free(builders);
    const stmts = try a.alloc(proto.Statement, R);
    defer a.free(stmts);
    var n_built: usize = 0;
    defer for (builders[0..n_built]) |*b| b.deinit();
    var bp = t.serve.BatchProver.init(a, &pool, pc, &sw.ws);
    defer bp.deinit();
    var forward_ns: u64 = 0;
    var max_load: usize = 0;
    var cap_used: u32 = 0;
    var prove_ns: u64 = 0;
    var tm_sum: proto.Timings = .{};
    var tm_first: proto.Timings = .{};
    var witness_elems: usize = 0;
    var table_elems: usize = 0;
    var n_wit: usize = 0;
    var n_core: usize = 0;
    var n_ext: usize = 0;
    const tokens = try a.alloc(u32, R << @intCast(cfg.log_out));
    defer a.free(tokens);
    const D = @as(usize, 1) << @intCast(ld);
    const T = @as(usize, 1) << @intCast(lt);
    const t_all = now();
    for (0..R) |j| {
        builders[j] = tf.Builder.init(a, &pool);
        n_built += 1;
        const b = &builders[j];
        // the window's embedding rows (public input; int8)
        const x = try model.randomInput(a, T * D, 1000 * seed + j);
        defer a.free(x);
        // The expert capacity is a per-request statement parameter. cap=0
        // (default): the smallest power of two holding the request's largest
        // expert load, found by an untimed full-capacity forward pass (a
        // serving prover knows the routing after its forward pass anyway).
        // cap=c > 0: fixed, refit only on overflow.
        var rcfg = cfg;
        if (cap_arg == 0 and le > 0) {
            rcfg.log_capacity = lt;
            var probe = tf.Builder.init(a, &pool);
            defer probe.deinit();
            const full = try t.lm.buildModel(&probe, rcfg, &sw.ws, 7, x, null);
            rcfg.log_capacity = t.lm.fitCapacity(full.max_expert_load);
        }
        t0 = now();
        const mo = t.lm.buildModel(b, rcfg, &sw.ws, 7, x, null) catch |e| blk: {
            if (e != error.CapacityExceeded) return e;
            b.deinit();
            builders[j] = tf.Builder.init(a, &pool);
            rcfg.log_capacity = lt;
            const full = try t.lm.buildModel(b, rcfg, &sw.ws, 7, x, null);
            rcfg.log_capacity = t.lm.fitCapacity(full.max_expert_load);
            b.deinit();
            builders[j] = tf.Builder.init(a, &pool);
            t0 = now();
            break :blk try t.lm.buildModel(b, rcfg, &sw.ws, 7, x, null);
        };
        forward_ns += now().since(t0);
        max_load = @max(max_load, mo.max_expert_load);
        cap_used = @max(cap_used, rcfg.log_capacity);
        @memcpy(tokens[j << @intCast(cfg.log_out) ..][0..mo.tokens.len], mo.tokens);
        stmts[j] = b.statement();
        const wv = try b.witnessView(a);
        defer a.free(wv);
        var tm: proto.Timings = .{};
        t0 = now();
        try bp.add(.{ .st = stmts[j], .witness = wv, .salt = t.serve.testSalt(seed * 1000 + j) }, &tm);
        prove_ns += now().since(t0);
        if (j == 0) tm_first = tm;
        inline for (@typeInfo(proto.Timings).@"struct".fields) |fld| {
            if (fld.type == u64) @field(tm_sum, fld.name) += @field(tm, fld.name);
        }
        witness_elems = tm.witness_elems;
        table_elems = tm.witness_table_elems;
        n_wit = stmts[j].witness.len;
        n_core = stmts[j].ops.len;
        n_ext = stmts[j].ext.ops.len;
        // drop the witness (the statement stays for verification)
        for (b.wit.items) |*w| {
            a.free(w.*);
            w.* = w.*[0..0];
        }
    }
    t0 = now();
    var batch = try bp.finish();
    defer batch.deinit(a);
    const shared_s = secs(t0);
    const total_s = secs(t_all);
    const peak_rss = peakRssBytes();

    // --- verify (single thread): every request, or the first `verify`
    var v_min: f64 = 1e30;
    var v_max: f64 = 0;
    var v_sum: f64 = 0;
    for (0..n_verify) |j| {
        t0 = now();
        try t.serve.verifyRequest(a, pc, stmts[j], key, &batch.requests[j], &batch.shared, j);
        const s = secs(t0);
        v_min = @min(v_min, s);
        v_max = @max(v_max, s);
        v_sum += s;
    }

    // --- sizes
    var own_sum: usize = 0;
    var own_max: usize = 0;
    for (batch.requests) |rp| {
        own_sum += rp.byteSize();
        own_max = @max(own_max, rp.byteSize());
    }
    const sz0 = batch.requests[0].core.sizes();
    const shared_claims = batch.shared.claimBytes();
    const shared_open = batch.shared.openingBytes();
    var n_weights: usize = 0;
    for (sw.winfos) |wi| n_weights += wi.size();
    const active = t.lm.activeWeightsPerToken(cfg, sw.winfos);
    var n_claims: usize = 0;
    var n_points: usize = 0;
    for (batch.shared.requests) |cs| {
        n_claims += cs.w.len;
        n_points += cs.points.len;
    }

    const n_tok: f64 = @floatFromInt(R * T);
    const Rf: f64 = @floatFromInt(R);
    const out = std.fs.File.stdout().deprecatedWriter();
    try out.print("{{\"bench\":\"model\",\"log_t\":{d},\"log_d\":{d},\"log_f\":{d},\"log_heads\":{d},\"log_kv_heads\":{d},\"layers\":{d},\"moe_layers\":{d},\"log_experts\":{d},\"log_f_expert\":{d},\"log_capacity\":{d},\"log_capacity_used\":{d},\"max_expert_load\":{d},\"log_vocab\":{d},\"log_out\":{d},\"requests\":{d},\"threads\":{d},\"accel\":{},\"batch_matmuls\":{},", .{ lt, ld, lf, cfg.log_heads, cfg.log_kv_heads, cfg.n_layers, cfg.nMoeLayers(), le, lfe, cfg.log_capacity, cap_used, max_load, cfg.log_vocab, cfg.log_out, R, threads, pc.accel != null, pc.batch_matmuls });
    try printTl(out, pc);
    try out.print("\"queries\":{d},\"log_blowup\":{d},\"pow_bits\":{d},\"weight_log_cols\":{d},", .{ outer.n_queries, outer.log_blowup, outer.pow_bits, pc.weight_log_cols });
    try out.print("\"weights\":{d},\"active_weights_per_token\":{d},\"witness_tensors\":{d},\"core_ops\":{d},\"ext_ops\":{d},\"witness_elems_per_request\":{d},\"witness_table_elems\":{d},\"stacked_experts\":{},\"weight_claims_per_request\":{d},\"weight_points_per_request\":{d},", .{ n_weights, active, n_wit, n_core, n_ext, witness_elems, table_elems, cfg.stacked_experts, n_claims / R, n_points / R });
    try out.print("\"offline\":{{\"calib_passes\":{d},\"calib_s\":{d:.3},\"commit_s\":{d:.3},\"key_proof_s\":{d:.3},\"key_verify_s\":{d:.4},\"key_bytes\":{d},\"rss_after_commit\":{d},\"rss_after_key\":{d}}},", .{ calib, calib_s, commit_s, key_s, key_verify_s, if (prox) |p| p.byteSize() else 0, rss_after_commit, rss_after_key });
    try out.print("\"forward_s\":{d:.4},\"prove_requests_s\":{d:.4},\"shared_open_s\":{d:.4},\"wall_s\":{d:.4},", .{ nsToS(forward_ns), nsToS(prove_ns), shared_s, total_s });
    // serving cost = forward + per-request proving + shared opening (the
    // untimed capacity probe and witness dropping are excluded)
    const serve_s = nsToS(forward_ns) + nsToS(prove_ns) + shared_s;
    try out.print("\"s_per_request\":{d:.4},\"prove_s_per_request\":{d:.4},\"tokens_per_s\":{d:.2},\"tokens_per_s_prove_only\":{d:.2},", .{ serve_s / Rf, (nsToS(prove_ns) + shared_s) / Rf, n_tok / serve_s, n_tok / (nsToS(prove_ns) + shared_s) });
    try out.print("\"stage_s_sum\":{{\"ext_init\":{d:.4},\"multiplicities\":{d:.4},\"witness_commit\":{d:.4},\"gkr\":{d:.4},\"ext_terminal\":{d:.4},\"op_sumchecks\":{d:.4},\"weight_fold\":{d:.4},\"batch\":{d:.4},\"witness_open\":{d:.4},\"shared_weight_open\":{d:.4}}},", .{ nsToS(tm_sum.ext_init_ns), nsToS(tm_sum.multiplicities_ns), nsToS(tm_sum.witness_commit_ns), nsToS(tm_sum.gkr_ns), nsToS(tm_sum.ext_terminal_ns), nsToS(tm_sum.op_sumcheck_ns), nsToS(tm_sum.weight_fold_ns), nsToS(tm_sum.batch_ns), nsToS(tm_sum.witness_open_ns), shared_s });
    try out.print("\"request_bytes\":{{\"own\":{d},\"own_max\":{d},\"gkr\":{d},\"sumchecks\":{d},\"ext\":{d},\"witness_opening\":{d},\"shared_claims\":{d},\"shared_opening\":{d},\"per_request_total\":{d},\"amortized\":{d:.0}}},", .{ own_sum / R, own_max, sz0.gkr, sz0.sumchecks, batch.requests[0].core.ext.byteSize(), sz0.witness_opening, shared_claims, shared_open, own_max + shared_claims + shared_open, @as(f64, @floatFromInt(own_sum + shared_claims + shared_open)) / Rf });
    if (batch.shared.opening) |wo| try printLevels(out, "shared_levels", wo);
    try out.print("\"verify_s\":{{\"n\":{d},\"min\":{d:.4},\"mean\":{d:.4},\"max\":{d:.4}}},", .{ n_verify, v_min, v_sum / @as(f64, @floatFromInt(@max(n_verify, 1))), v_max });
    try out.print("\"first_tokens\":[", .{});
    for (tokens[0..@min(tokens.len, 8)], 0..) |tok, i| try out.print("{s}{d}", .{ if (i == 0) "" else ",", tok });
    try out.print("],", .{});
    try printGpuStats(out);
    try out.print("\"peak_rss_bytes\":{d}}}\n", .{peak_rss});
    if (prox) |*p| p.deinit(a);
    sw.ws.deinit(a);
    a.free(sw.winfos);
}
