//! rv64-logup-gkr-prototype: experimental WGKR-LS-RANGE-v0 driver.
//!
//!   capture <request.json> <jobs-dir> <out.witness>
//!       Real Word16 Ethereum batch 0: LS + LS_tail range-query columns,
//!       read from the production LS MAIN (load_store_v2 Source) in storage order.
//!   produce <classic|gkr> <witness> <out-dir> [fast|reference] [gkr-threads]
//!       Production suite (q70/PoW26/blowup 1). Writes proof.bin + producer.json.
//!   verify <classic|gkr> <proof.bin> <ls_log> <tail_log>
//!       Fresh-process receiver. Statement and variant come from argv only.
const std = @import("std");
const W = @import("witness.zig");
const P = @import("protocol.zig");
const Air = @import("air.zig");
const stage_profile = @import("stwo_prover_api").stage_profile;

pub fn main() !void {
    const a = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len < 2) return error.ExpectedMode;
    if (std.mem.eql(u8, args[1], "capture")) {
        if (args.len != 5) return error.ExpectedRequestJobsOutput;
        return capture(a, args[2], args[3], args[4]);
    }
    if (std.mem.eql(u8, args[1], "produce")) {
        if (args.len < 5 or args.len > 7) return error.ExpectedVariantWitnessOutput;
        const choice: P.GkrProverChoice = if (args.len < 6 or std.mem.eql(u8, args[5], "fast")) .fast else if (std.mem.eql(u8, args[5], "reference")) .reference else return error.InvalidGkrProver;
        // Standalone prototype owns a private pool: conservative default and
        // explicit bounded parallelism, independent of production workers.
        const threads = if (args.len == 7) try std.fmt.parseUnsigned(usize, args[6], 10) else 1;
        if (threads == 0 or threads > @import("fast_gkr.zig").MAX_THREADS) return error.InvalidGkrThreads;
        return produce(a, try parseVariant(args[2]), args[3], args[4], choice, threads);
    }
    if (std.mem.eql(u8, args[1], "verify")) {
        if (args.len != 6) return error.ExpectedVariantProofLogs;
        const statement = W.Statement.production(try std.fmt.parseUnsigned(u32, args[4], 10), try std.fmt.parseUnsigned(u32, args[5], 10));
        return verifyMain(a, try parseVariant(args[2]), args[3], statement);
    }
    return error.InvalidMode;
}

fn parseVariant(text: []const u8) !Air.Variant {
    if (std.mem.eql(u8, text, "classic")) return .classic;
    if (std.mem.eql(u8, text, "gkr")) return .gkr;
    return error.InvalidVariant;
}

fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

fn produce(a: std.mem.Allocator, variant: Air.Variant, witness_path: []const u8, out_dir: []const u8, choice: P.GkrProverChoice, threads: usize) !void {
    var timer = try std.time.Timer.start();
    var file = try std.fs.cwd().openFile(witness_path, .{});
    var witness = try W.read(a, file);
    file.close();
    defer witness.deinit();
    const load_ns = timer.read();
    var recorder = stage_profile.Recorder.init(a, "cpu", "wgkr-ls-range-v0");
    defer recorder.deinit();
    const start = timer.read();
    var result = try P.prove(a, P.productionConfig(), .{ .statement = witness.statement, .variant = variant, .witness = &witness, .gkr_prover = choice, .gkr_threads = threads }, &recorder);
    defer result.deinit(a);
    const prove_ns = timer.read() - start;
    try std.fs.cwd().makePath(out_dir);
    var dir = try std.fs.cwd().openDir(out_dir, .{});
    defer dir.close();
    try dir.writeFile(.{ .sub_path = "proof.bin", .data = result.bytes });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(result.bytes, &digest, .{});
    var profile = try recorder.snapshot(a);
    defer profile.deinit(a);
    const geometry = Air.Geometry{ .statement = witness.statement, .variant = variant };
    const report = .{
        .protocol = "WGKR-LS-RANGE-v0",
        .variant = @tagName(variant),
        .statement = witness.statement,
        .witness_load_ns = load_ns,
        .prove_ns = prove_ns,
        .gkr_prover = @tagName(choice),
        .gkr_threads = threads,
        .gkr_input_and_prove_ns = result.timings.gkr_ns,
        .gkr_input_ns = result.timings.gkr_input_ns,
        .gkr_binding_columns_ns = result.timings.binding_ns,
        .interaction_generation_ns = result.timings.interaction_ns,
        .gkr_input_layer_bytes = result.timings.gkr_input_bytes,
        .proof_bytes = result.bytes.len,
        .stark_bytes = result.stark_bytes,
        .gkr_bytes = result.gkr_bytes,
        .proof_sha256 = std.fmt.bytesToHex(digest, .lower),
        .inter_columns = geometry.interColumns(),
        .inter_cells = geometry.interCells(),
        .range_queries = witness.cells(),
        .stages = profile.stages,
    };
    const json = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try dir.writeFile(.{ .sub_path = "producer.json", .data = json });
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

fn verifyMain(a: std.mem.Allocator, variant: Air.Variant, proof_path: []const u8, statement: W.Statement) !void {
    var timer = try std.time.Timer.start();
    const bytes = try std.fs.cwd().readFileAlloc(a, proof_path, 64 * 1024 * 1024);
    defer a.free(bytes);
    const report = try P.verify(a, P.productionConfig(), statement, variant, bytes);
    try emit(a, .{ .accepted = true, .protocol = "WGKR-LS-RANGE-v0", .variant = @tagName(variant), .statement = statement, .proof_bytes = bytes.len, .verify_wall_ns = timer.read(), .report = report });
}

/// Historical experiment has exactly12U16+4U8 physical query lanes. A new
/// LS layout must get its own admitted capture mapping, never stale columns.
pub fn captureSupported(comptime Layout: type) bool {
    if (@hasDecl(Layout, "U8")) return Layout.U16.len == W.HI_LANES and Layout.U8.len == W.LO_LANES;
    return false;
}

fn capture(a: std.mem.Allocator, request_path: []const u8, jobs_path: []const u8, out_path: []const u8) !void {
    const engine = @import("stwo_prover_engine");
    const Request = @import("../rv64_ethereum_request.zig");
    const Image = @import("../word16_execution/expected_image.zig");
    const Program = @import("../word16_execution/program.zig").Program;
    const Capture = @import("../word16_global_execution/ethereum/capture.zig").Owner;
    const Plan = @import("../word16_global_execution/ethereum/plan.zig");
    const ProgramMetadata = @import("../word16_execution/program_metadata.zig");
    const X = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2;
    const Geometry = @import("../word16_execution/geometry.zig").Geometry;
    if (comptime captureSupported(X.layout)) {
        var timer = try std.time.Timer.start();
        const raw = try std.fs.cwd().readFileAlloc(a, request_path, 16384);
        defer a.free(raw);
        const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
        defer config.deinit();
        var pool: engine.work_pool.WorkPool = .{};
        try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
        defer pool.deinit();
        var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var image = try Image.Owner.init(a, config.value);
        defer image.deinit();
        var metadata_cache = try ProgramMetadata.Cache.init(a, 0);
        defer metadata_cache.deinit();
        var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &metadata_cache);
        defer program.deinit();
        var jobs = try std.fs.cwd().openDir(jobs_path, .{});
        defer jobs.close();
        var captured = try Capture.init(a, &image, &program, config.value, jobs, 1);
        defer captured.deinit();
        const decl = try Plan.cpus(a, &captured);
        defer a.free(decl);
        const g = decl[0].geometry;
        const events = captured.advice.events[0];
        const counts = try (Geometry{ .cpu_log = 5, .ls_log = g.ls_log, .ls_tail_log = g.ls_tail_log }).lsCounts(@intCast(events.len));
        const statement = W.Statement.production(g.ls_log, g.ls_tail_log orelse 0);
        var witness = try W.Witness.initZero(a, statement);
        defer witness.deinit();
        const spans = [_][]const X.native.Event{ events[0..counts.head], events[counts.head..] };
        for (witness.instances[0..witness.count], 0..) |*inst, i| {
            var source = try X.source.Source.init(a, spans[i], inst.log);
            defer source.deinit();
            const n = inst.rows();
            for (X.layout.U16, 0..) |column, j| for (0..n) |p| {
                inst.lanes[j][p] = source.main[column * n + p].v;
            };
            for (X.layout.U8, 0..) |column, j| for (0..n) |p| {
                inst.lanes[W.HI_LANES + j][p] = source.main[column * n + p].v;
            };
        }
        var mult = try witness.multiplicities(a);
        defer mult.deinit(a);
        if (mult.out_of_range != 0) return error.CapturedRangeValueOutOfRange;
        var file = try std.fs.cwd().createFile(out_path, .{});
        defer file.close();
        try W.write(&witness, file);
        try emit(a, .{ .batch = 0, .ls_events = events.len, .ls_head = counts.head, .ls_tail = counts.tail, .statement = statement, .range_queries = witness.cells(), .capture_ns = timer.read() });
    } else return error.CaptureRequiresHistoricalLsRangeLayout;
}
