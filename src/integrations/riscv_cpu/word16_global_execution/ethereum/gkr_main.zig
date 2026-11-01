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
const CaptureOptions = @import("capture_options.zig").Options;
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
const FixedAuthority = @import("../services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const CANDIDATE_PROFILE = "experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering";
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
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    fn validate(self: Resources) !void {
        if (self.gkr_bytes == 0 or self.global_bytes == 0 or self.retained_frontend_bytes == 0 or (self.park_main and self.disk_bytes == 0) or self.schedule.memory_cap_bytes == 0) return error.MissingWideResourceAdmission;
        try self.capture_options.validate();
        try self.schedule.validate();
        try Schedule.validateOrder(self.stage2_order, self.stage2_order.len);
    }
    pub fn jsonStringify(self: Resources, writer: anytype) !void {
        try writer.beginObject();
        inline for (.{ "gkr_bytes", "global_bytes", "retained_frontend_bytes", "disk_bytes", "park_main", "schedule" }) |name| {
            try writer.objectField(name);
            try writer.write(@field(self, name));
        }
        // Preserve historical default report schema; only explicit opt-in emits order.
        if (self.stage2_order.len != 0) {
            try writer.objectField("stage2_order");
            try writer.write(self.stage2_order);
        }
        if (!self.capture_options.isDefault()) {
            try writer.objectField("capture_options");
            try writer.write(self.capture_options);
        }
        try writer.endObject();
    }
};
/// Separate operational schema keeps historical control resource/report bytes
/// unchanged. No field in either schema selects a security construction.
const CandidateResources = struct {
    gkr_bytes: usize,
    global_bytes: usize,
    retained_frontend_bytes: usize,
    disk_bytes: usize,
    fixed_setup_bytes: usize,
    park_main: bool = true,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    fn operational(self: CandidateResources) Resources {
        return .{ .gkr_bytes = self.gkr_bytes, .global_bytes = self.global_bytes, .retained_frontend_bytes = self.retained_frontend_bytes, .disk_bytes = self.disk_bytes, .park_main = self.park_main, .capture_options = self.capture_options, .stage2_order = self.stage2_order, .schedule = self.schedule };
    }
    fn validate(self: CandidateResources) !void {
        if (self.fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
        try self.operational().validate();
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
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .pcs = try config(), .usage = "produce-control CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON | verify-control CONFIG OUT | verify-prefix-control CONFIG OUT | plan CONFIG JOBS PREFIX_COUNT | capture CONFIG JOBS PREFIX_COUNT RESOURCE_JSON" });
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe-candidate")) return emit(a, .{ .profile = CANDIDATE_PROFILE, .security_qualified = false, .pcs = Candidate.config(), .scope = "beta2 engineering candidate; no reviewed whole-protocol128 certificate", .usage = "produce-candidate CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON (requires fixed_setup_bytes) | verify-candidate CONFIG OUT FIXED_SETUP_BYTES | verify-prefix-candidate CONFIG OUT FIXED_SETUP_BYTES" });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const candidate = std.mem.eql(u8, args[1], "produce-candidate") or std.mem.eql(u8, args[1], "verify-candidate") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    const verify = std.mem.eql(u8, args[1], "verify-control") or std.mem.eql(u8, args[1], "verify-candidate");
    const prefix = std.mem.eql(u8, args[1], "verify-prefix-control") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    const produce = std.mem.eql(u8, args[1], "produce-control") or std.mem.eql(u8, args[1], "produce-candidate");
    const plan = std.mem.eql(u8, args[1], "plan");
    const capture_only = std.mem.eql(u8, args[1], "capture");
    if (!verify and !prefix and !produce and !plan and !capture_only) return error.InvalidWideEthereumMode;
    if ((verify or prefix) and args.len != (if (candidate) @as(usize, 5) else 4)) return error.VerifierNeedsNoExecutionPackets;
    if (produce and args.len != 7) return error.ExpectedModeConfigJobsOutputPrefixAndResources;
    if (capture_only and args.len != 6) return error.ExpectedCaptureConfigJobsPrefixAndResources;
    if (plan and args.len != 5) return error.ExpectedModeConfigJobsAndPrefix;
    const pcs = if (candidate) Candidate.config() else try config();
    const selected_profile = if (candidate) CANDIDATE_PROFILE else PROFILE;
    var fixed_setup_bytes: usize = 0;
    if (candidate and (verify or prefix)) {
        fixed_setup_bytes = try std.fmt.parseUnsigned(usize, args[4], 10);
        if (fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
    }
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
        var fixed_cache: ?FixedAuthority.Fixed.Cache = if (candidate) try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes) else null;
        defer if (fixed_cache) |*owner| owner.deinit();
        var fixed_set: ?FixedSet = if (fixed_cache) |*owner| try FixedSet.init(a, owner, keys.cpus, keys.truths, pcs) else null;
        defer if (fixed_set) |*owner| owner.deinit();
        const setup_ns = timer.read();
        const output = try Receiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, verify, pcs, if (fixed_set) |*authority| authority else null);
        if (fixed_cache) |*owner| return emit(a, .{ .profile = selected_profile, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns, .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells });
        return emit(a, .{ .profile = PROFILE, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns });
    }
    var resources: ?Resources = null;
    var control_resource_owner: ?std.json.Parsed(Resources) = null;
    defer if (control_resource_owner) |*owner| owner.deinit();
    var candidate_resource_owner: ?std.json.Parsed(CandidateResources) = null;
    defer if (candidate_resource_owner) |*owner| owner.deinit();
    if (produce or capture_only) {
        const limits_bytes = try std.fs.cwd().readFileAlloc(a, args[if (capture_only) 5 else 6], 16384);
        defer a.free(limits_bytes);
        if (candidate) {
            candidate_resource_owner = try std.json.parseFromSlice(CandidateResources, a, limits_bytes, .{});
            try candidate_resource_owner.?.value.validate();
            resources = candidate_resource_owner.?.value.operational();
            fixed_setup_bytes = candidate_resource_owner.?.value.fixed_setup_bytes;
        } else {
            control_resource_owner = try std.json.parseFromSlice(Resources, a, limits_bytes, .{});
            try control_resource_owner.?.value.validate();
            resources = control_resource_owner.?.value;
        }
    }
    const count = try std.fmt.parseUnsigned(u32, args[if (plan or capture_only) 4 else 5], 10);
    var jobs = try std.fs.cwd().openDir(args[3], .{});
    defer jobs.close();
    const import_start = timer.read();
    var captured = try Capture.initWithOptions(a, &image, &program, request.value, jobs, count, (if (resources) |r| r.capture_options else CaptureOptions{}).forPool(&pool));
    defer captured.deinit();
    const packet_import_ns = timer.read() - import_start;
    const capture_ns = timer.read();
    try program.releaseFixedWitness();
    const capture_cache_released = recycler.releaseCached();
    const cpu = try Plan.cpus(a, &captured);
    defer a.free(cpu);
    const truths = try Plan.truths(a, &captured);
    defer a.free(truths);
    if (capture_only) {
        const digest_start = timer.read();
        const digest = @import("capture_digest.zig").digest(image.identity, &captured);
        return emit(a, .{ .scope = "producer capture diagnostic only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_options = resources.?.capture_options, .capture_selection = captured.capture_schedule, .packet_import_ns = packet_import_ns, .image_and_import_ns = capture_ns, .captured_values_sha256 = std.fmt.bytesToHex(digest, .lower), .diagnostic_digest_ns = timer.read() - digest_start });
    }
    if (plan) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .scope = "geometry advice only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns });
    const operational = resources.?;
    try Schedule.validateOrder(operational.stage2_order, try std.math.add(usize, cpu.len, truths.len));
    var keys = try Keys.initWithSuiteAndCaches(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    var fixed_cache: ?FixedAuthority.Fixed.Cache = if (candidate) try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes) else null;
    defer if (fixed_cache) |*owner| owner.deinit();
    var fixed_set: ?FixedSet = if (fixed_cache) |*owner| try FixedSet.init(a, owner, keys.cpus, keys.truths, pcs) else null;
    defer if (fixed_set) |*owner| owner.deinit();
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
    var bundle = try C.produceWithAuthority(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, .{ .max_workers = if (operational.park_main) 32 else 8, .max_retained_frontend_bytes = operational.retained_frontend_bytes, .gkr_budget = operational.gkr_bytes, .global_budget = operational.global_bytes, .retained_store = if (store) |*value| value else null, .worker_timings = worker_timings, .native_profiles = if (request.value.profile_stages) observations.pointers else &.{}, .schedule = operational.schedule, .stage2_order = operational.stage2_order }, if (fixed_set) |*authority| authority else null);
    defer bundle.deinit(a);
    const prove_ns = timer.read() - prove_start;
    if (request.value.profile_stages) {
        const profiling = @import("../services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
        for (0..observations.pointers.len) |i| try profiling.finish(a, i);
    }
    const verify_start = timer.read();
    const output = try Receiver.verifyWithAuthority(a, &image, &keys, &bundle, request.value.max_steps, request.value.batch_steps, completed, pcs, if (fixed_set) |*authority| authority else null);
    const verify_ns = timer.read() - verify_start;
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    try Driver.writeJson(a, dir, "report.json", .{ .profile = selected_profile, .security_qualified = false, .completed_ethereum_block = completed, .total_steps = captured.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .output = output, .resources = operational, .capture_ns = capture_ns, .packet_import_ns = packet_import_ns, .capture_selection = captured.capture_schedule, .capture_cache_released_bytes = capture_cache_released, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .workers = worker_timings, .total_before_report_ns = timer.read(), .retained_main = if (store) |*value| value.stats() else null });
    if (fixed_cache) |*owner| try Driver.writeJson(a, dir, "candidate-fixed-setup.json", .{ .profile = selected_profile, .security_qualified = false, .config = pcs, .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells });
    try std.posix.fsync(dir.fd);
}
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

test "candidate operational budget cannot select protocol and control resource schema stays exact" {
    const a = std.testing.allocator;
    const control_json = "{\"gkr_bytes\":1,\"global_bytes\":2,\"retained_frontend_bytes\":3,\"disk_bytes\":4,\"park_main\":true,\"schedule\":{\"memory_cap_bytes\":5}}";
    const parsed = try std.json.parseFromSlice(Resources, a, control_json, .{});
    defer parsed.deinit();
    try parsed.value.validate();
    const encoded = try std.json.Stringify.valueAlloc(a, parsed.value, .{});
    defer a.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "fixed_setup_bytes") == null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "stage2_order") == null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "capture_options") == null);
    try std.testing.expectEqual(@as(u8, 1), parsed.value.capture_options.max_inflight_packets);
    var capture_resources = parsed.value;
    capture_resources.capture_options.max_inflight_packets = 2;
    try capture_resources.validate();
    const capture_json = try std.json.Stringify.valueAlloc(a, capture_resources, .{});
    defer a.free(capture_json);
    try std.testing.expect(std.mem.indexOf(u8, capture_json, "capture_options") != null);
    // Schedule reports resolve lane_workers to an active-length numeric list;
    // they are deliberately not the input Policy schema. Round-trip only the
    // newly introduced numeric operational subobject.
    const options_json = try std.json.Stringify.valueAlloc(a, capture_resources.capture_options, .{});
    defer a.free(options_json);
    const capture_roundtrip = try std.json.parseFromSlice(CaptureOptions, a, options_json, .{});
    defer capture_roundtrip.deinit();
    try std.testing.expectEqualDeep(capture_resources.capture_options, capture_roundtrip.value);
    capture_resources.capture_options.max_inflight_packets = 3;
    try std.testing.expectError(error.InvalidEthereumCaptureOptions, capture_resources.validate());
    const forbidden_capture = "{\"max_inflight_packets\":2,\"security_qualified\":true}";
    try std.testing.expectError(error.UnknownField, std.json.parseFromSlice(CaptureOptions, a, forbidden_capture, .{}));
    try std.testing.expectError(error.MissingField, std.json.parseFromSlice(CandidateResources, a, control_json, .{}));
    var candidate = CandidateResources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .fixed_setup_bytes = 0, .schedule = .{ .memory_cap_bytes = 5 } };
    try std.testing.expectError(error.MissingCandidateFixedSetupAdmission, candidate.validate());
    candidate.fixed_setup_bytes = 6;
    try candidate.validate();
    try std.testing.expectEqualDeep(parsed.value, candidate.operational());
    candidate.capture_options.max_inflight_packets = 2;
    try candidate.validate();
    try std.testing.expectEqual(@as(u8, 2), candidate.operational().capture_options.max_inflight_packets);
    const bad = "{\"gkr_bytes\":1,\"global_bytes\":2,\"retained_frontend_bytes\":3,\"disk_bytes\":4,\"fixed_setup_bytes\":6,\"schedule\":{\"memory_cap_bytes\":5},\"security_qualified\":true}";
    try std.testing.expectError(error.UnknownField, std.json.parseFromSlice(CandidateResources, a, bad, .{}));
}

test "explicit stage2 resource order remains owner-backed and serializes only when selected" {
    const a = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(Resources, a, "{\"gkr_bytes\":1,\"global_bytes\":2,\"retained_frontend_bytes\":3,\"disk_bytes\":0,\"park_main\":false,\"stage2_order\":[2,0,1],\"schedule\":{\"memory_cap_bytes\":5}}", .{});
    defer parsed.deinit();
    const operational = parsed.value;
    try operational.validate();
    try Schedule.validateOrder(operational.stage2_order, 3);
    try std.testing.expectEqualSlices(usize, &.{ 2, 0, 1 }, operational.stage2_order);
    const encoded = try std.json.Stringify.valueAlloc(a, operational, .{});
    defer a.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"stage2_order\":[2,0,1]") != null);
    try std.testing.expectError(error.InvalidServiceOrder, Schedule.validateOrder(operational.stage2_order, 5));
}
