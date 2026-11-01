//! Experimental OM/GKR Ethereum driver. Receiver parameters are pinned here;
//! durable producer metadata cannot select configuration or security authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("../../word16_execution/program.zig").Program;
const Driver = @import("../../word16_execution/driver.zig");
const Capture = @import("capture.zig").Owner;
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const Admission = @import("receiver.zig");
const Receiver = @import("gkr_receiver.zig");
const C = @import("../services/gkr_local/coordinator.zig");
const W = @import("../services/gkr_local/bundle_wire.zig");
const Worker = @import("../services/gkr_local/worker_protocol.zig");
const P = @import("../services/protocol.zig");
const Store = @import("../retained_main_store.zig").Store;
const Schedule = @import("../services/schedule.zig");
const Suite = @import("../../word16_execution/pcs_suite.zig").Suite;
const NativeCache = @import("../../word16_execution/fixed_native_cache.zig");
const MetadataCache = @import("../../word16_execution/program_metadata.zig");
const Recycler = @import("../../rv64_large_block_recycler.zig").LargeBlockRecycler;
const PROFILE = "experimental-om31-local-gkr-q70-p26-fold4";
/// Operational admission only. These limits never enter statement authority.
/// The coordinator's accounting is not a complete bound on process RSS.
const Resources = struct {
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    /// Explicit operational choice: small inventories may retain MAIN in RAM.
    park_main: bool = true,
    schedule: Schedule.Policy,
    fn validate(self: Resources) !void {
        if (self.gkr_bytes == 0 or self.global_bytes == 0 or self.retained_frontend_bytes == 0 or (self.park_main and self.disk_bytes == 0) or self.schedule.memory_cap_bytes == 0) return error.MissingWideResourceAdmission;
        try self.schedule.validate();
    }
};
fn config() !Worker.PcsConfig {
    var value = Worker.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(Worker.O).FriConfig.init(0, 1, 70) };
    value.fri_config.fold_step = 4;
    return value;
}
pub fn main() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, 4 << 30);
    defer recycler.deinit();
    const a = recycler.allocator();
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .pcs = try config(), .usage = "produce-control CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON | verify-control CONFIG OUT | verify-prefix-control CONFIG OUT | plan CONFIG JOBS PREFIX_COUNT" });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const verify = std.mem.eql(u8, args[1], "verify-control");
    const prefix = std.mem.eql(u8, args[1], "verify-prefix-control");
    const produce = std.mem.eql(u8, args[1], "produce-control");
    const plan = std.mem.eql(u8, args[1], "plan");
    if (!verify and !prefix and !produce and !plan) return error.InvalidWideEthereumMode;
    if ((verify or prefix) and args.len != 4) return error.VerifierNeedsNoExecutionPackets;
    if (produce and args.len != 7) return error.ExpectedModeConfigJobsOutputPrefixAndResources;
    if (plan and args.len != 5) return error.ExpectedModeConfigJobsAndPrefix;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const request = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer request.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(request.value), .stack_size = 1024 * 1024, .backing_allocator = a });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    var timer = try std.time.Timer.start();
    var image = try Image.Owner.init(a, request.value);
    defer image.deinit();
    var native_cache = try NativeCache.Cache.init(a, 256 << 20);
    defer native_cache.deinit();
    var metadata_cache = try MetadataCache.Cache.init(a, 64 << 20);
    defer metadata_cache.deinit();
    const caches = @import("../../word16_execution/setup.zig").ImmutableCaches{ .native = &native_cache, .program = &metadata_cache };
    var program = try Program.initWithAuthorityAndMetadataCache(a, &image.authority, &metadata_cache);
    defer program.deinit();
    if (verify or prefix) {
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        var loaded = try W.read(a, dir, .{ .max_total_steps = request.value.max_steps });
        defer loaded.deinit(a);
        _ = try Admission.expectedFromRequests(&image, program.identity, loaded.bundle.requests, request.value.max_steps, request.value.batch_steps, verify);
        var keys = try Keys.initWithSuiteAndCaches(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches);
        defer keys.deinit();
        const setup_ns = timer.read();
        const output = try Receiver.verify(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, verify, try config());
        return emit(a, .{ .profile = PROFILE, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns });
    }
    var resources: ?Resources = null;
    if (produce) {
        const limits_bytes = try std.fs.cwd().readFileAlloc(a, args[6], 16384);
        defer a.free(limits_bytes);
        const limits = try std.json.parseFromSlice(Resources, a, limits_bytes, .{});
        defer limits.deinit();
        try limits.value.validate();
        resources = limits.value;
    }
    const count = try std.fmt.parseUnsigned(u32, args[if (plan) 4 else 5], 10);
    var jobs = try std.fs.cwd().openDir(args[3], .{});
    defer jobs.close();
    var captured = try Capture.init(a, &image, &program, request.value, jobs, count);
    defer captured.deinit();
    const capture_ns = timer.read();
    try program.releaseFixedWitness();
    const capture_cache_released = recycler.releaseCached();
    const cpu = try Plan.cpus(a, &captured);
    defer a.free(cpu);
    const truths = try Plan.truths(a, &captured);
    defer a.free(truths);
    if (plan) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .scope = "geometry advice only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns });
    const operational = resources.?;
    var keys = try Keys.initWithSuiteAndCaches(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = captured.total_steps, .max_total_steps = request.value.max_steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers };
    const completed = count == 0;
    if (completed and expected.final_pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
    try std.fs.cwd().makeDir(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var store: ?Store = if (operational.park_main) try Store.initFullyParked(args[4], operational.disk_bytes) else null;
    defer if (store) |*value| value.deinit();
    const setup_ns = timer.read() - capture_ns;
    var observations = try @import("observations.zig").Owner.init(a, keys.cpus.len + keys.truths.len);
    defer observations.deinit();
    const worker_timings = try a.alloc(C.WorkerTiming, keys.cpus.len + keys.truths.len);
    defer a.free(worker_timings);
    const prove_start = timer.read();
    var bundle = try C.produce(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, try config(), .{ .max_workers = if (operational.park_main) 32 else 8, .max_retained_frontend_bytes = operational.retained_frontend_bytes, .gkr_budget = operational.gkr_bytes, .global_budget = operational.global_bytes, .retained_store = if (store) |*value| value else null, .worker_timings = worker_timings, .native_profiles = if (request.value.profile_stages) observations.pointers else &.{}, .schedule = operational.schedule });
    defer bundle.deinit(a);
    const prove_ns = timer.read() - prove_start;
    if (request.value.profile_stages) {
        const profiling = @import("../services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
        for (0..observations.pointers.len) |i| try profiling.finish(a, i);
    }
    const verify_start = timer.read();
    const output = try Receiver.verify(a, &image, &keys, &bundle, request.value.max_steps, request.value.batch_steps, completed, try config());
    const verify_ns = timer.read() - verify_start;
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    try Driver.writeJson(a, dir, "report.json", .{ .profile = PROFILE, .security_qualified = false, .completed_ethereum_block = completed, .total_steps = captured.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .output = output, .resources = operational, .capture_ns = capture_ns, .capture_cache_released_bytes = capture_cache_released, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .workers = worker_timings, .total_before_report_ns = timer.read(), .retained_main = if (store) |*value| value.stats() else null });
    try std.posix.fsync(dir.fd);
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
