//! Full block driver for the mixed-service Word16 global-memory protocol.
//! Verify modes consume only independently pinned config and durable proofs.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Driver = @import("../../word16_execution/driver.zig");
const Capture = @import("capture.zig").Owner;
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const Receiver = @import("receiver.zig");
const E = @import("../services/execution.zig");
const P = @import("../services/protocol.zig");
const W = @import("../services/wire.zig");
const ProgramMetadata = @import("../../word16_execution/program_metadata.zig");
const NativeCache = @import("../../word16_execution/fixed_native_cache.zig");
const Recycler = @import("../../rv64_large_block_recycler.zig").LargeBlockRecycler;
pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, 4 << 30);
    defer recycler.deinit();
    const a = recycler.allocator();
    const raw_args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, raw_args);
    const operational = try @import("options.zig").Options.parse(raw_args);
    const args = raw_args[0..operational.count];
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .core_claims = P.CORE_CLAIM_COUNT, .cpu_claims_with_services = P.CPU_CLAIM_COUNT, .pcs_config = @import("../protocol.zig").T.P.config() });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const fold4 = std.mem.endsWith(u8, args[1], "-fold4");
    const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
    const suite = if (fold4) Suite.experimentalFold4() else Suite.production();
    const verify = std.mem.eql(u8, args[1], "verify") or std.mem.eql(u8, args[1], "verify-fold4");
    const prefix = std.mem.eql(u8, args[1], "verify-prefix") or std.mem.eql(u8, args[1], "verify-prefix-fold4");
    // `-direct`: in-process handoff (execute + capture, no job packet files).
    const direct = std.mem.eql(u8, args[1], "produce-direct") or std.mem.eql(u8, args[1], "plan-direct");
    const produce = std.mem.eql(u8, args[1], "produce") or std.mem.eql(u8, args[1], "produce-fold4") or std.mem.eql(u8, args[1], "produce-direct");
    const plan = std.mem.eql(u8, args[1], "plan") or std.mem.eql(u8, args[1], "plan-direct");
    if (!verify and !prefix and !produce and !plan) return error.InvalidWord16EthereumMode;
    if ((verify or prefix) and args.len != 4) return error.VerifierNeedsNoExecutionPackets;
    if ((verify or prefix) and operational.producerOnly()) return error.ProvingOptionInReceiver;
    if ((produce or plan) and args.len != @as(usize, if (direct) 5 else 6)) return error.ExpectedModeConfigJobsOutputPrefixCount;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer config.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(config.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.init(a, config.value);
    defer image.deinit();
    var native_cache = try NativeCache.Cache.init(a, operational.fixed_native_cache_bytes);
    defer native_cache.deinit();
    var metadata_cache = try ProgramMetadata.Cache.init(a, operational.program_metadata_cache_bytes);
    defer metadata_cache.deinit();
    if (verify or prefix) {
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        var loaded = try W.read(a, dir, .{ .max_total_steps = config.value.max_steps });
        defer loaded.deinit(a);
        try admitProfile(config.value, loaded.cpu_declarations, loaded.truth_declarations);
        // Cheap schedule/genesis/completion admission precedes expensive keys.
        var trusted_program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &metadata_cache);
        defer trusted_program.deinit();
        _ = try Receiver.expected(&image, trusted_program.identity, &loaded.bundle, config.value.max_steps, config.value.batch_steps, verify);
        var keys = try Keys.initWithSuiteAndCaches(a, &image, loaded.cpu_declarations, loaded.truth_declarations, !operational.keep_fixed_witness, suite, .{ .native = &native_cache, .program = &metadata_cache });
        defer keys.deinit();
        const setup_ns = timer.read();
        const output = try Receiver.verify(a, &image, &keys, &loaded.bundle, config.value.max_steps, config.value.batch_steps, verify);
        return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns, .fixed_native_cache = native_cache.snapshot(), .program_metadata_cache = metadata_cache.snapshot() });
    }
    const out_path = args[if (direct) 3 else 4];
    const count = try std.fmt.parseUnsigned(u32, args[if (direct) 4 else 5], 10);
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &metadata_cache);
    defer program.deinit();
    // Range-checked by Options.parse; the windowed reader re-validates. (The
    // GKR driver's capture schema stays limited to its own 1-2 packets.)
    const capture_options = operational.captureOptions();
    var direct_stats: @import("direct.zig").Stats = .{};
    var captured = if (direct) try @import("direct.zig").capture(a, &image, &program, config.value, count, operational.capture_inflight, &direct_stats) else jobs: {
        var jobs = try std.fs.cwd().openDir(args[3], .{});
        defer jobs.close();
        break :jobs try Capture.initWithOptions(a, &image, &program, config.value, jobs, count, capture_options.forPool(&pool));
    };
    defer captured.deinit();
    const capture_ns = timer.read();
    const trim_start = timer.read();
    if (!operational.keep_fixed_witness) try program.releaseFixedWitness();
    const capture_cache_released = if (operational.keep_capture_cache) 0 else recycler.releaseCached();
    const trim_ns = timer.read() - trim_start;
    var cpu_layout = Plan.CpuLayout.forProfile(config.value.execution_profile);
    if (operational.no_ls_dword) cpu_layout.ls_dword = false;
    if (operational.layout.mul_u8_pairs) cpu_layout.mul_u8_pairs = true;
    if (operational.layout.ls_fused_pairs) cpu_layout.ls_fused_pairs = true;
    if (operational.layout.alu_fused_tail) cpu_layout.alu_fused_tail = true;
    if (operational.layout.ls_dword_fused_pairs) cpu_layout.ls_dword_fused_pairs = true;
    const cpu_declarations = try Plan.cpus(a, &captured, cpu_layout);
    defer a.free(cpu_declarations);
    const truth_declarations = try Plan.truthsForKeccakOptions(a, &captured, .{ .v3 = config.value.execution_profile == .ethereum_services_v3, .quartet = !operational.keccak_throughput_v1, .r27 = !operational.keccak_pair29 });
    defer a.free(truth_declarations);
    if (truth_declarations.len > (W.Limits{}).max_truths) return error.TooManyEthereumTruths;
    try admitProfile(config.value, cpu_declarations, truth_declarations);
    if (plan) return emit(a, .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .scope = "producer advice and bounded geometry only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu_declarations, .truth = truth_declarations, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns, .capture_schedule = captured.capture_schedule, .direct = direct_stats, .captured_values_sha256 = std.fmt.bytesToHex(@import("capture_digest.zig").digest(image.identity, &captured), .lower) });
    var keys = try Keys.initWithSuiteAndCaches(a, &image, cpu_declarations, truth_declarations, !operational.keep_fixed_witness, suite, .{ .native = &native_cache, .program = &metadata_cache });
    defer keys.deinit();
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = captured.total_steps, .max_total_steps = config.value.max_steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers };
    // Full completion is explicit. Prefix fixtures can never accidentally
    // publish a block-completed report merely because their proofs verify.
    const completed = count == 0;
    if (completed and expected.final_pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
    try std.fs.cwd().makeDir(out_path);
    var dir = try std.fs.cwd().openDir(out_path, .{});
    defer dir.close();
    const setup_ns = timer.read() - capture_ns - trim_ns;
    try @import("telemetry.zig").write(a, dir, &keys, &captured);
    var store = if (operational.park_retained_main) try @import("../retained_main_store.zig").Store.initParked(out_path, 128 << 30) else try @import("../retained_main_store.zig").Store.init(out_path, 128 << 30);
    defer store.deinit();
    var observations = try @import("observations.zig").Owner.init(a, keys.cpus.len + keys.truths.len);
    defer observations.deinit();
    const schedule = try operational.schedule(try Request.effectiveWorkers(config.value));
    const prove_start = timer.read();
    var bundle = try E.produceWithOptions(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, .{ .retained_main = &store, .schedule = schedule, .prefetch_main_bytes = operational.prefetch_main_bytes, .commit_batch_columns = operational.batch, .consume_memory_events = true, .recorders = if (config.value.profile_stages) observations.pointers else &.{}, .directory = if (config.value.profile_stages) dir else null });
    defer bundle.deinit(a);
    const prove_ns = timer.read() - prove_start;
    const verify_start = timer.read();
    const output = try Receiver.verify(a, &image, &keys, &bundle, config.value.max_steps, config.value.batch_steps, completed);
    const verify_ns = timer.read() - verify_start;
    const publish_start = timer.read();
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    try Driver.writeJson(a, dir, "report.json", .{ .core_schema = @import("../../word16_execution/protocol.zig").SCHEMA, .completed_ethereum_block = completed, .total_steps = expected.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .memory_words = captured.advice.initial.len, .output = output, .capture_ns = capture_ns, .capture_mode = @as([]const u8, if (direct) "in-process" else "packets"), .capture_schedule = captured.capture_schedule, .direct_capture = direct_stats, .capture_cache_trim_ns = trim_ns, .capture_cache_released_bytes = capture_cache_released, .cpu_fixed_witness_retired = !operational.keep_fixed_witness, .coordinator_schedule = schedule, .commit_batch_columns = operational.batch, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .publish_before_report_ns = timer.read() - publish_start, .total_before_report_ns = timer.read(), .retained_main = store.stats(), .fixed_native_cache = native_cache.snapshot(), .program_metadata_cache = metadata_cache.snapshot() });
    try std.posix.fsync(dir.fd);
}
/// Receiver policy: SHA-256, arith256_mod, curve/field and bulk-memory bridges/truths
/// exist only in the admitted v3 roster. A v2 request can never accept a
/// proof that relies on them.
pub fn admitProfile(config: Request.Config, cpus: []const W.CpuDeclaration, truths: []const W.TruthDeclaration) !void {
    if (config.execution_profile == .ethereum_services_v3) return;
    // The fused-tail CPU layout is admitted only on the v3 route. A v2
    // receiver keeps the historical CPU AIR and fails closed on any other.
    for (cpus) |d| if (d.geometry.cpu_fused_tail or d.geometry.cpu_u8_pairs or d.geometry.mul_u8_pairs or d.geometry.ls_fused_pairs or d.geometry.alu_fused_tail or d.geometry.ls_dword_fused_pairs) return error.UnadmittedFusedTailCpuLayout;
    // Throughput Keccak truth tables (wire logs[1] != 0) are v3-only.
    for (truths) |d| if (d.family == .keccak and d.logs[1] != 0) return error.UnadmittedKeccakThroughputProfile;
    // The secp row truth (wire logs[1] = 0) is v3-only.
    for (truths) |d| if (W.isSecpRow(d)) return error.UnadmittedSecpRowProfile;
    for (cpus) |d| if (d.bridges.sha256 != null) return error.UnadmittedSha256Service;
    for (truths) |d| if (d.family == .sha256) return error.UnadmittedSha256Service;
    for (cpus) |d| if (d.bridges.arith256_mod != null) return error.UnadmittedArith256Service;
    for (truths) |d| if (d.family == .arith256_mod) return error.UnadmittedArith256Service;
    for (cpus) |d| for (@import("../services/types.zig").V3[2..]) |family| if (d.bridges.at(family) != null) return error.UnadmittedCurveService;
    for (truths) |d| if (@import("../services/types.zig").curveOp(d.family) != null) return error.UnadmittedCurveService;
    for (cpus) |d| if (d.bridges.bulk.any()) return error.UnadmittedBulkMemoryService;
    for (cpus) |d| if (d.bridges.sponge.any()) return error.UnadmittedKeccakSpongeService;
    for (cpus) |d| if (d.bridges.ls_dword != null or d.bridges.ls_dword_tail != null) return error.UnadmittedLsDwordComponent;
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
