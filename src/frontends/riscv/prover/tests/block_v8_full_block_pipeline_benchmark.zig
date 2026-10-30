//! Opt-in retained block proving. Every checkpoint is decoded once and shared
//! by adjacent jobs; the census/plan conveys no proof authority.
const std = @import("std");
const Engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Pipeline = @import("../block_v8_full_block_pipeline_v1.zig");
const Plan = struct {
    schema: []const u8,
    elf_sha256: []const u8,
    input_sha256: []const u8,
    output_sha256: []const u8,
    total_cycles: u64,
    security: struct { queries: u32, pow_bits: u32 },
    windows: []const Window,
};
const Window = struct {
    index: u32,
    kind: enum { native, mixed },
    skip_cycles: u64,
    cycles: u32,
    caller_calls: u32,
    initial: bool,
    terminal: bool,
};
const Checkpoint = struct {
    schema: []const u8,
    proof_verified: bool,
    completed_cycles: u64,
    file: []const u8,
    snapshot_id: []const u8,
    transport_sha256: []const u8,
    bytes: usize,
};
fn env(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingFullBlockBenchmarkInput;
}
fn digest(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidFullBlockBenchmarkPin;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
fn readPinned(a: std.mem.Allocator, path: []const u8, pin: [32]u8, max: usize) ![]u8 {
    const bytes = try std.fs.cwd().readFileAlloc(a, path, max);
    errdefer a.free(bytes);
    if (!std.meta.eql(Capture.sha(bytes), pin)) return error.UntrustedFullBlockBenchmarkBytes;
    return bytes;
}
test "retained complete block originals through one independently verified recursive root benchmark" {
    if (std.posix.getenv("STWO_B8_BLOCK_ENABLE") == null) return error.SkipZigTest;
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const native_cohort_cycles = try std.fmt.parseInt(u32, std.posix.getenv("STWO_B8_FULL_NATIVE_COHORT_CYCLES") orelse "8388608", 10);
    if (native_cohort_cycles == 0 or native_cohort_cycles > 1 << 23) return error.FullBlockBenchmarkResourceLimit;
    const budget_gib = try std.fmt.parseInt(u64, try env("STWO_B8_BLOCK_BUDGET_GIB"), 10);
    const workers = try std.fmt.parseInt(usize, try env("STWO_B8_BLOCK_WORKERS"), 10);
    if (budget_gib < 32 or budget_gib > 60 or workers == 0 or workers > 16) return error.FullBlockBenchmarkResourceLimit;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, budget_gib << 30);
    defer budget.destroy();
    const a = budget.allocator();
    const elf_pin = try digest(try env("STWO_B8_BLOCK_ELF_SHA256"));
    const input_pin = try digest(try env("STWO_B8_BLOCK_INPUT_SHA256"));
    const output_pin = try digest(try env("STWO_B8_BLOCK_EXPECTED_OUTPUT_SHA256"));
    const elf = try readPinned(a, try env("STWO_B8_BLOCK_ELF"), elf_pin, 32 << 20);
    defer a.free(elf);
    const private_input = try readPinned(a, try env("STWO_B8_BLOCK_INPUT"), input_pin, 4 << 20);
    defer a.free(private_input);
    const expected_output = try readPinned(a, try env("STWO_B8_BLOCK_EXPECTED_OUTPUT"), output_pin, 44);
    defer a.free(expected_output);
    if (expected_output.len != 43) return error.UntrustedFullBlockOutputLength;
    const plan_bytes = try readPinned(a, try env("STWO_B8_BLOCK_PLAN"), try digest(try env("STWO_B8_BLOCK_PLAN_SHA256")), 4 << 20);
    defer a.free(plan_bytes);
    const parsed = try std.json.parseFromSlice(Plan, a, plan_bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const plan = parsed.value;
    if (!std.mem.eql(u8, plan.schema, "stwo-b8-full-block-schedule-v1") or plan.total_cycles != 139214856 or plan.security.queries != 70 or plan.security.pow_bits != 26 or plan.windows.len == 0 or plan.windows.len > 2048 or !std.meta.eql(try digest(plan.elf_sha256), elf_pin) or !std.meta.eql(try digest(plan.input_sha256), input_pin) or !std.meta.eql(try digest(plan.output_sha256), output_pin)) return error.UntrustedFullBlockPlan;
    var completed: u64 = 0;
    for (plan.windows, 0..) |window, i| {
        if (window.index != i or window.skip_cycles != completed or window.cycles == 0 or window.cycles > (if (window.kind == .native) @as(u32, 1) << 23 else @as(u32, 1) << 20) or window.caller_calls > 4096 or (window.kind == .native and window.caller_calls != 0) or window.initial != (i == 0) or window.terminal != (i + 1 == plan.windows.len)) return error.UntrustedFullBlockCoverage;
        completed = try std.math.add(u64, completed, window.cycles);
    }
    if (completed != plan.total_cycles) return error.UntrustedFullBlockCoverage;
    const manifest_bytes = try readPinned(a, try env("STWO_B8_BLOCK_CHECKPOINT_MANIFEST"), try digest(try env("STWO_B8_BLOCK_CHECKPOINT_MANIFEST_SHA256")), 4 << 20);
    defer a.free(manifest_bytes);
    const snapshots = try a.alloc(Capture.Snapshot, plan.windows.len + 1);
    defer a.free(snapshots);
    var snapshot_count: usize = 0;
    defer for (snapshots[0..snapshot_count]) |*snapshot| snapshot.deinit(a);
    var directory = try std.fs.cwd().openDir(try env("STWO_B8_BLOCK_CHECKPOINT_DIR"), .{});
    defer directory.close();
    var lines = std.mem.tokenizeScalar(u8, manifest_bytes, '\n');
    while (lines.next()) |line| {
        if (snapshot_count >= snapshots.len) return error.ExtraFullBlockCheckpoint;
        const checkpoint_parsed = try std.json.parseFromSlice(Checkpoint, a, line, .{ .ignore_unknown_fields = true });
        defer checkpoint_parsed.deinit();
        const checkpoint = checkpoint_parsed.value;
        const cycle = if (snapshot_count == 0) 0 else try std.math.add(u64, plan.windows[snapshot_count - 1].skip_cycles, plan.windows[snapshot_count - 1].cycles);
        var file_buffer: [80]u8 = undefined;
        const filename = try std.fmt.bufPrint(&file_buffer, "state-{d}.b7win", .{cycle});
        if (!std.mem.eql(u8, checkpoint.schema, "stwo-b8-execution-checkpoint-input-v1") or checkpoint.proof_verified or checkpoint.completed_cycles != cycle or !std.mem.eql(u8, checkpoint.file, filename) or checkpoint.bytes > 256 << 20) return error.UntrustedFullBlockCheckpoint;
        const bytes = try directory.readFileAlloc(a, filename, 256 << 20);
        defer a.free(bytes);
        if (bytes.len != checkpoint.bytes or !std.meta.eql(Capture.sha(bytes), try digest(checkpoint.transport_sha256))) return error.UntrustedFullBlockCheckpoint;
        snapshots[snapshot_count] = try Capture.Snapshot.decode(a, bytes, try digest(checkpoint.snapshot_id), .{});
        snapshot_count += 1;
    }
    if (snapshot_count != snapshots.len) return error.MissingFullBlockCheckpoint;
    const jobs = try a.alloc(Pipeline.Job, plan.windows.len);
    defer a.free(jobs);
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    for (jobs, plan.windows, 0..) |*job, window, i| job.* = .{ .kind = if (window.kind == .native) .native else .mixed, .request = .{ .elf = elf, .elf_sha256 = elf_pin, .config = config, .incoming = snapshots[i], .outgoing = snapshots[i + 1], .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = snapshots[i].identity(), .outgoing_sha256 = snapshots[i + 1].identity(), .window = .{ .skip_cycles = window.skip_cycles, .cycles = window.cycles } } } };
    const loading_ns = phase.lap();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    // Core owns phase-specific bindings. Do not bind this pool around run().
    var output = try std.fs.cwd().openDir(try env("STWO_B8_BLOCK_OUTPUT"), .{ .iterate = true });
    defer output.close();
    var options: Pipeline.Options = .{};
    options.resume_saved = std.posix.getenv("STWO_B8_BLOCK_RESUME") != null;
    const cache_option = std.posix.getenv("STWO_B8_BLOCK_IMMUTABLE_ADMISSION_CACHE") orelse "0";
    if (!std.mem.eql(u8, cache_option, "0") and !std.mem.eql(u8, cache_option, "1")) return error.InvalidFullBlockAdmissionCacheOption;
    options.immutable_admission_cache = std.mem.eql(u8, cache_option, "1");
    options.native.proof_workers = workers;
    options.native.parallel_local_proofs = 1;
    options.native.cohort_cycles = native_cohort_cycles;
    options.native.max_cohort_cycles = native_cohort_cycles;
    options.native.bundle.max_cohort_cycles = native_cohort_cycles;
    const summary = try Pipeline.run(budget, &pool, output, .{ .elf = elf, .private_input = private_input, .trusted = .{ .elf_sha256 = elf_pin, .input_sha256 = input_pin, .total_cycles = plan.total_cycles, .expected_output = expected_output[0..43].*, .config = config }, .jobs = jobs }, options);
    const pipeline_ns = phase.lap();
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-full-block-one-root-benchmark-v1", .scope = "complete retained execution including initialization callers terminal output and recursive reduction", .queries = @as(u32, 70), .pow_bits = @as(u32, 26), .workers = workers, .budget_bytes = budget_gib << 30, .allocator = "std.heap.smp_allocator", .resume_saved = options.resume_saved, .immutable_admission_cache = options.immutable_admission_cache, .native_cohort_cycles = native_cohort_cycles, .checkpoint_count = snapshot_count, .unique_snapshot_decodes = snapshot_count, .loading_ns = loading_ns, .pipeline_ns = pipeline_ns, .whole_ns = whole.read(), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .independent_root_verified = true, .pipeline = summary }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "benchmark-report.json", .data = report });
}
