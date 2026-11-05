//! CPU-only producer capture diagnostic (M6 capture stream):
//! `rv64-capture-bench CONFIG JOBS PREFIX_COUNT RESOURCE_JSON`, the same
//! route, allocator, work pool and JSON fields as `rv64-word16-ethereum-gkr
//! capture` (whose CPU-only product no longer links since the M5 recursion
//! policy check pulled the circuit integration into its entry). No proof,
//! no acceptance; prints the capture timeline and `captured_values_sha256`.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Capture = @import("capture.zig").Owner;
const CaptureOptions = @import("capture_options.zig").Options;
const DirectCapture = @import("direct.zig");
const Plan = @import("plan.zig");
const MetadataCache = @import("../../word16_execution/program_metadata.zig");
const Recycler = @import("../../rv64_large_block_recycler.zig").LargeBlockRecycler;
const ReceiverBudget = @import("receiver_budget.zig");

const Resources = struct {
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    capture_options: CaptureOptions = .{},
    fixed_setup_bytes: usize = 12 << 30,
    keccak_uniform_throughput: bool = false,
    keccak_max_log: u32 = 18,
};
const CaptureInputs = struct {
    init_ns: u64,
    first_inputs_ns: ?u64,
    last_inputs_ns: ?u64,
    all_inputs_ns: u64,
    ledger_ns: u64,
    ledger_finish_ns: u64,
    fn of(timer: *const std.time.Timer, init_ns: u64, all_ns: u64, captured: *const Capture) CaptureInputs {
        return .{ .init_ns = init_ns, .first_inputs_ns = sinceTimer(timer, captured.first_inputs_at), .last_inputs_ns = sinceTimer(timer, captured.last_inputs_at), .all_inputs_ns = all_ns, .ledger_ns = captured.timing.ledger_ns, .ledger_finish_ns = captured.timing.finish_ns };
    }
    fn sinceTimer(timer: *const std.time.Timer, at: ?std.time.Instant) ?u64 {
        return if (at) |value| value.since(timer.started) else null;
    }
};

pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const a = recycler.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 5 and args.len != 6) return error.ExpectedCaptureConfigJobsPrefixAndResources;
    const setup_mode = if (args.len == 6) args[5] else "";
    if (args.len == 6 and !std.mem.eql(u8, setup_mode, "setup-serial") and !std.mem.eql(u8, setup_mode, "setup-eager") and !std.mem.eql(u8, setup_mode, "setup-classes")) return error.InvalidSetupDiagnosticMode;
    const raw = try std.fs.cwd().readFileAlloc(a, args[1], 16384);
    defer a.free(raw);
    const request = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer request.deinit();
    try @import("../services/gkr_local/service_scope.zig").profile(request.value.execution_profile);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(request.value), .stack_size = ReceiverBudget.WORKER_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    const limits_bytes = try std.fs.cwd().readFileAlloc(a, args[4], 16384);
    defer a.free(limits_bytes);
    const resources = try std.json.parseFromSlice(Resources, a, limits_bytes, .{ .ignore_unknown_fields = true });
    defer resources.deinit();
    _ = recycler.setCap(resources.value.recycler_cache_bytes);
    const count = try std.fmt.parseUnsigned(u32, args[3], 10);
    const direct_capture = std.mem.eql(u8, args[2], "-");
    const capture_options = resources.value.capture_options;
    if (!direct_capture and capture_options.execution_workers != 0) return error.ExecutionWorkersRequireDirectCapture;
    var timer = try std.time.Timer.start();
    var direct_stats: DirectCapture.Stats = .{};
    var direct_started: ?*DirectCapture.Started = if (direct_capture) try DirectCapture.Started.start(a, request.value, count, capture_options.execution_workers) else null;
    defer if (direct_started) |value| value.deinit(&direct_stats);
    var image = try Image.Owner.init(a, request.value);
    defer image.deinit();
    const image_load_ns = timer.read();
    var local_metadata = try MetadataCache.Cache.init(a, 64 << 20);
    defer local_metadata.deinit();
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &local_metadata);
    defer program.deinit();
    const program_ns = timer.read() - image_load_ns;
    const cpu_layout = Plan.CpuLayout.forGkrProfile(request.value.execution_profile);
    if (cpu_layout.compact_decode) try program.makeCompact();
    const import_start = timer.read();
    var captured = if (direct_started) |started| direct: {
        defer {
            started.deinit(&direct_stats);
            direct_started = null;
        }
        break :direct try started.capture(&image, &program, capture_options.max_inflight_packets, &direct_stats);
    } else capture: {
        var jobs = try std.fs.cwd().openDir(args[2], .{});
        defer jobs.close();
        break :capture try Capture.initWithOptions(a, &image, &program, request.value, jobs, count, capture_options.forPool(&pool));
    };
    defer captured.deinit();
    const packet_import_ns = timer.read() - import_start;
    const capture_ns = timer.read();
    const capture_inputs = CaptureInputs.of(&timer, import_start, capture_ns, &captured);
    if (args.len == 6) {
        // Explicit CPU-only setup diagnostic. Capture timing above stays exact;
        // no proof, native assignment, receiver or request speed claim follows.
        const Keys = @import("keys.zig").Owner;
        const Setup = @import("setup_cache.zig");
        const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
        const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
        const cpu = try Plan.cpus(a, &captured, cpu_layout);
        defer a.free(cpu);
        const truths = try Plan.truthsWithOptions(a, &captured, .{ .v3 = request.value.execution_profile == .ethereum_services_v3, .uniform_throughput = resources.value.keccak_uniform_throughput }, resources.value.keccak_max_log);
        defer a.free(truths);
        const config = coreConfig();
        var setup_cache = try Setup.Cache.init(a, .{ .log_blowup = config.fri_config.log_blowup_factor }, .{ .mode = .prover, .fixed_setup_bytes = resources.value.fixed_setup_bytes, .eager_fixed = std.mem.eql(u8, setup_mode, "setup-eager"), .unique_classes_first = !std.mem.eql(u8, setup_mode, "setup-serial") });
        defer setup_cache.deinit();
        try setup_cache.bindRequest(request.value);
        var clock = try std.time.Timer.start();
        var keys = try Keys.initResident(a, &image, cpu, truths, true, Suite.experimentalFold4(), .{ .program = &local_metadata }, &setup_cache);
        defer keys.deinit();
        const native_keys_ns = clock.read();
        var authority = try FixedSet.init(a, &setup_cache.fixed, keys.cpus, keys.truths, config);
        defer authority.deinit();
        const total_setup_ns = clock.read();
        try authority.require(keys.cpus, keys.truths, config);
        const Entry = struct { source: [32]u8, identity: [32]u8, root: [32]u8 };
        const entries = try a.alloc(Entry, authority.bindings.len);
        defer a.free(entries);
        for (authority.bindings, entries) |binding, *entry| entry.* = .{ .source = binding.source_root, .identity = binding.fixed_identity, .root = binding.fixed_root };
        const bytes = try std.json.Stringify.valueAlloc(a, .{ .scope = "CPU-only source class key + candidate fixed setup diagnostic; no proof or acceptance", .mode = setup_mode, .profile = "conjectured128_b2_q108_p20_fold4", .cpu = cpu, .truths = truths, .capture_ns = capture_ns, .native_keys_ns = native_keys_ns, .remaining_fixed_ns = total_setup_ns - native_keys_ns, .total_setup_ns = total_setup_ns, .setup_stats = setup_cache.stats, .fixed = setup_cache.fixed.snapshot(), .authorities = entries }, .{ .whitespace = .indent_2 });
        defer a.free(bytes);
        try std.fs.File.stdout().writeAll(bytes);
        try std.fs.File.stdout().writeAll("\n");
        return;
    }
    const digest_start = timer.read();
    const digest = @import("capture_digest.zig").digest(image.identity, &captured);
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "producer capture diagnostic only; no proof or acceptance (rv64-capture-bench)", .security_qualified = false, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .memory_words = captured.advice.initial.len, .capture_options = capture_options, .capture_selection = captured.capture_schedule, .packet_import_ns = if (direct_capture) @as(u64, 0) else packet_import_ns, .image_and_import_ns = capture_ns, .capture_breakdown = .{ .image_load_ns = image_load_ns, .program_ns = program_ns, .pre_import_ns = import_start - image_load_ns - program_ns, .import_ns = packet_import_ns }, .capture_inputs = capture_inputs, .captured_values_sha256 = std.fmt.bytesToHex(digest, .lower), .captured_values_v2_sha256 = std.fmt.bytesToHex(@import("capture_digest.zig").completeV2(digest, &captured), .lower), .capture_source = if (direct_capture) @as([]const u8, "in_process_execution") else "packet_directory", .direct_capture = if (direct_capture) direct_stats else null, .diagnostic_digest_ns = timer.read() - digest_start }, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

fn coreConfig() @import("stwo_core").pcs.PcsConfig {
    return .{ .pow_bits = 20, .fri_config = .{ .log_last_layer_degree_bound = 0, .log_blowup_factor = 1, .n_queries = 108, .fold_step = 4 } };
}
