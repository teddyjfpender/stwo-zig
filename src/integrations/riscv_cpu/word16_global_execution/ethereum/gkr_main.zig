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
const DirectCapture = @import("direct.zig");
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
const ReceiverBudget = @import("receiver_budget.zig");
const FixedAuthority = @import("../services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const SourceBounds = @import("../services/gkr_local/source_bounds.zig");
const SetupCache = @import("setup_cache.zig");
/// Operator-owned setup cache directory (receiver policy; never bundle data).
const SETUP_CACHE_ENV = "STWO_ZIG_RV64_SETUP_CACHE";
/// A/B switch for the identity-only CPU source (default on).
const IDENTITY_ONLY_ENV = "STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU";
fn setupCacheOptions(a: std.mem.Allocator, mode: SetupCache.Mode, fixed_setup_bytes: usize) !struct { options: SetupCache.Options, owned: ?[]u8 } {
    const dir = std.process.getEnvVarOwned(a, SETUP_CACHE_ENV) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    errdefer if (dir) |d| a.free(d);
    const identity_only = blk: {
        const v = std.process.getEnvVarOwned(a, IDENTITY_ONLY_ENV) catch break :blk true;
        defer a.free(v);
        break :blk !std.mem.eql(u8, v, "0");
    };
    const threads = blk: {
        const v = std.process.getEnvVarOwned(a, "STWO_ZIG_RV64_SETUP_BUILD_THREADS") catch break :blk @as(usize, 8);
        defer a.free(v);
        break :blk std.fmt.parseUnsigned(usize, v, 10) catch return error.InvalidSetupBuildThreads;
    };
    const directory: ?[]const u8 = if (dir) |d| (if (d.len == 0) null else d) else null;
    return .{ .options = .{ .mode = mode, .directory = directory, .fixed_setup_bytes = fixed_setup_bytes, .identity_only_cpu = identity_only, .max_build_threads = threads }, .owned = dir };
}
/// block_to_inputs phase report (observation only; never proof authority).
/// Every *_at_ns is nanoseconds since gkr_main entry on the monotonic clock.
const BlockToInputs = struct {
    clock: []const u8 = "ns since gkr_main entry (monotonic)",
    scope: []const u8,
    init_done_at_ns: u64 = 0,
    capture_done_at_ns: u64 = 0,
    plan_done_at_ns: u64 = 0,
    keys_done_at_ns: u64 = 0,
    setup_done_at_ns: u64 = 0,
    coordinator_admitted_at_ns: u64 = 0,
    t_first_ns: u64 = 0,
    t_first_any_ns: u64 = 0,
    t_all_cpu_ns: u64 = 0,
    t_all_ns: u64 = 0,
    stages: struct { init_ns: u64 = 0, capture_import_ns: u64 = 0, plan_ns: u64 = 0, setup_ns: u64 = 0, setup_keys_ns: u64 = 0, setup_fixed_ns: u64 = 0, coordinator_admission_ns: u64 = 0 } = .{},
    segments: []const Segment = &.{},
    setup_cache: ?SetupCache.Stats = null,
    /// Capture-relative timeline (init, segment 0 / last / all inputs, ledger).
    capture: ?CaptureInputs = null,
    const Segment = struct { ordinal: usize, kind: []const u8, source_begin_at_ns: u64, source_ready_at_ns: u64, source_ns: u64 };
    fn finish(self: *BlockToInputs, a: std.mem.Allocator, timings: []const C.WorkerTiming, cpu_count: usize) !void {
        const segments = try a.alloc(Segment, timings.len);
        var first_any: u64 = std.math.maxInt(u64);
        for (segments, timings, 0..) |*out, t, i| {
            out.* = .{ .ordinal = i, .kind = if (i < cpu_count) "cpu" else "truth", .source_begin_at_ns = t.source_begin_ns, .source_ready_at_ns = t.source_ready_ns, .source_ns = t.source_ready_ns -| t.source_begin_ns };
            if (i < cpu_count) {
                self.t_all_cpu_ns = @max(self.t_all_cpu_ns, t.source_ready_ns);
                first_any = @min(first_any, t.source_ready_ns);
            }
            self.t_all_ns = @max(self.t_all_ns, t.source_ready_ns);
        }
        self.segments = segments;
        self.t_first_ns = if (timings.len != 0) timings[0].source_ready_ns else 0;
        self.t_first_any_ns = if (first_any == std.math.maxInt(u64)) 0 else first_any;
        self.stages = .{
            .init_ns = self.init_done_at_ns,
            .capture_import_ns = self.capture_done_at_ns -| self.init_done_at_ns,
            .plan_ns = self.plan_done_at_ns -| self.capture_done_at_ns,
            .setup_ns = self.setup_done_at_ns -| self.plan_done_at_ns,
            .setup_keys_ns = self.keys_done_at_ns -| self.plan_done_at_ns,
            .setup_fixed_ns = self.setup_done_at_ns -| self.keys_done_at_ns,
            .coordinator_admission_ns = self.coordinator_admitted_at_ns -| self.setup_done_at_ns,
        };
    }
};
fn since(origin: std.time.Instant) u64 {
    const now = std.time.Instant.now() catch return 0;
    return now.since(origin);
}
const CANDIDATE_PROFILE = "experimental-om31-local-gkr-beta2-q256-p0-fold4-engineering";
const CONJECTURED_PROFILE = "experimental-om31-local-gkr-conjectured128-b2-q108-p20-fold4-engineering";
/// Report label of a receiver-selected candidate profile (historical label for proven).
fn candidateLabel(profile: Candidate.Profile) []const u8 {
    return switch (profile) {
        .proven_beta2_q256_p0_fold4 => CANDIDATE_PROFILE,
        .conjectured128_b2_q108_p20_fold4 => CONJECTURED_PROFILE,
    };
}
/// The receiver's/producer's OWN policy: `--security-profile NAME` before the
/// mode, candidate modes only; default Candidate.DEFAULT_PROFILE. Proof bytes
/// and bundle metadata never select it.
const ProfileSelection = struct { profile: Candidate.Profile, explicit: bool, args: []const [:0]u8 };
fn selectProfile(all: []const [:0]u8) !ProfileSelection {
    if (all.len >= 3 and std.mem.eql(u8, all[1], "--security-profile"))
        return .{ .profile = try Candidate.Profile.parse(all[2]), .explicit = true, .args = all[2..] };
    return .{ .profile = Candidate.DEFAULT_PROFILE, .explicit = false, .args = all };
}
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
    /// Operational cache only; never changes live proof ownership or protocol.
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    fn validate(self: Resources) !void {
        if (self.gkr_bytes == 0 or self.global_bytes == 0 or self.retained_frontend_bytes == 0 or (self.park_main and self.disk_bytes == 0) or self.schedule.memory_cap_bytes == 0) return error.MissingWideResourceAdmission;
        try self.capture_options.validate();
        try self.schedule.validate();
        if (self.recycler_cache_bytes > ReceiverBudget.RECYCLER_CACHE_BYTES) return error.UnsupportedRecyclerCacheLimit;
        if (self.keccak_max_log < 16 or self.keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
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
        if (self.recycler_cache_bytes != ReceiverBudget.RECYCLER_CACHE_BYTES) {
            try writer.objectField("recycler_cache_bytes");
            try writer.write(self.recycler_cache_bytes);
        }
        if (self.keccak_max_log != 18) {
            try writer.objectField("keccak_max_log");
            try writer.write(self.keccak_max_log);
        }
        if (self.checkpoint_above_gkr_bytes != 0) {
            try writer.objectField("checkpoint_above_gkr_bytes");
            try writer.write(self.checkpoint_above_gkr_bytes);
        }
        if (self.defer_local_binding) {
            try writer.objectField("defer_local_binding");
            try writer.write(true);
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
    recycler_cache_bytes: usize = ReceiverBudget.RECYCLER_CACHE_BYTES,
    /// Producer geometry experiment. The default preserves the admitted roster.
    keccak_max_log: u32 = 18,
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    capture_options: CaptureOptions = .{},
    stage2_order: []const usize = &.{},
    schedule: Schedule.Policy,
    fn operational(self: CandidateResources) Resources {
        return .{ .gkr_bytes = self.gkr_bytes, .global_bytes = self.global_bytes, .retained_frontend_bytes = self.retained_frontend_bytes, .disk_bytes = self.disk_bytes, .park_main = self.park_main, .recycler_cache_bytes = self.recycler_cache_bytes, .keccak_max_log = self.keccak_max_log, .checkpoint_above_gkr_bytes = self.checkpoint_above_gkr_bytes, .defer_local_binding = self.defer_local_binding, .capture_options = self.capture_options, .stage2_order = self.stage2_order, .schedule = self.schedule };
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
    const process_start = try std.time.Instant.now();
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const base = recycler.allocator();
    const all_args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, all_args);
    const selection = try selectProfile(all_args);
    const security_profile = selection.profile;
    const args = selection.args;
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(base, .{ .profile = PROFILE, .security_qualified = false, .pcs = try config(), .usage = "produce-control CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON | verify-control CONFIG OUT [RECEIVER_BYTES] | verify-prefix-control CONFIG OUT [RECEIVER_BYTES] | plan CONFIG JOBS PREFIX_COUNT | capture CONFIG JOBS PREFIX_COUNT RESOURCE_JSON" });
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe-candidate")) return emit(base, .{ .profile = candidateLabel(security_profile), .security_profile = security_profile.name(), .security_qualified = false, .security_target = Candidate.assumptionTarget(security_profile), .pcs = Candidate.configFor(security_profile), .scope = if (security_profile.conjectured()) "native 128-bit CONJECTURED target (ethSTARK-style FRI accounting); no proven bound and no whole-protocol certificate" else "native 128-bit target under documented assumptions; no whole-protocol certificate", .usage = "[--security-profile proven_beta2_q256_p0_fold4|conjectured128_b2_q108_p20_fold4 (default)] produce-candidate CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON (requires fixed_setup_bytes; JOBS=- executes in process) | verify-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] | verify-prefix-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES]" });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const candidate = std.mem.eql(u8, args[1], "produce-candidate") or std.mem.eql(u8, args[1], "verify-candidate") or std.mem.eql(u8, args[1], "verify-prefix-candidate") or std.mem.eql(u8, args[1], "inputs-candidate");
    const verify = std.mem.eql(u8, args[1], "verify-control") or std.mem.eql(u8, args[1], "verify-candidate");
    const prefix = std.mem.eql(u8, args[1], "verify-prefix-control") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    const produce = std.mem.eql(u8, args[1], "produce-control") or std.mem.eql(u8, args[1], "produce-candidate");
    const plan = std.mem.eql(u8, args[1], "plan");
    const capture_only = std.mem.eql(u8, args[1], "capture");
    // Diagnostic: everything produce-candidate does up to every worker's
    // prover inputs (setup + per-segment source build), then stops. No proof.
    const inputs_only = std.mem.eql(u8, args[1], "inputs-candidate");
    if (!verify and !prefix and !produce and !plan and !capture_only and !inputs_only) return error.InvalidWideEthereumMode;
    if (inputs_only and args.len != 6) return error.ExpectedInputsConfigJobsPrefixAndResources;
    if (selection.explicit and !candidate) return error.SecurityProfileRequiresCandidateMode;
    const receiver_bytes: ?usize = if (verify or prefix) try ReceiverBudget.limit(args, candidate) else null;
    if (produce and args.len != 7) return error.ExpectedModeConfigJobsOutputPrefixAndResources;
    if (capture_only and args.len != 6) return error.ExpectedCaptureConfigJobsPrefixAndResources;
    if (plan and args.len != 5) return error.ExpectedModeConfigJobsAndPrefix;
    const pcs = if (candidate) Candidate.configFor(security_profile) else try config();
    const selected_profile = if (candidate) candidateLabel(security_profile) else PROFILE;
    const security_target = Candidate.assumptionTarget(security_profile);
    var fixed_setup_bytes: usize = 0;
    if (candidate and (verify or prefix)) {
        fixed_setup_bytes = try std.fmt.parseUnsigned(usize, args[4], 10);
        if (fixed_setup_bytes == 0) return error.MissingCandidateFixedSetupAdmission;
    }
    // Stable heap owner precedes every receiver image/key/bundle allocation.
    // Producer and plan allocations retain their historical path.
    const receiver_budget = if (receiver_bytes) |limit| try engine.host_budget_allocator.SharedHostBudget.create(base, limit) else null;
    defer if (receiver_budget) |owner| owner.destroy();
    const a = if (receiver_budget) |owner| owner.allocator() else base;
    const raw = try std.fs.cwd().readFileAlloc(a, args[2], 16384);
    defer a.free(raw);
    const request = try std.json.parseFromSlice(Request.Config, a, raw, .{});
    defer request.deinit();
    try @import("../services/gkr_local/service_scope.zig").profile(request.value.execution_profile);
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = try Request.effectiveWorkers(request.value), .stack_size = ReceiverBudget.WORKER_STACK_BYTES, .backing_allocator = a });
    defer pool.deinit();
    var pool_binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer pool_binding.deinit();
    // Producer modes: operational resources and the capture route are fixed
    // before any image work so the in-process walk can start first.
    var resources: ?Resources = null;
    var control_resource_owner: ?std.json.Parsed(Resources) = null;
    defer if (control_resource_owner) |*owner| owner.deinit();
    var candidate_resource_owner: ?std.json.Parsed(CandidateResources) = null;
    defer if (candidate_resource_owner) |*owner| owner.deinit();
    if (produce or capture_only or inputs_only) {
        const limits_bytes = try std.fs.cwd().readFileAlloc(a, args[if (capture_only or inputs_only) 5 else 6], 16384);
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
    if (resources) |limits| _ = recycler.setCap(limits.recycler_cache_bytes);
    const count: u32 = if (verify or prefix) 0 else try std.fmt.parseUnsigned(u32, args[if (plan or capture_only or inputs_only) 4 else 5], 10);
    const direct_capture = !(verify or prefix) and std.mem.eql(u8, args[3], "-");
    const capture_options = if (resources) |r| r.capture_options else CaptureOptions{};
    if (!direct_capture and capture_options.execution_workers != 0) return error.ExecutionWorkersRequireDirectCapture;
    var timer = try std.time.Timer.start();
    // JOBS="-": execution (and the first segment walks) overlaps the expected
    // image/program init below; admission still happens batch by batch in
    // `capture` against that independently loaded image.
    var direct_stats: DirectCapture.Stats = .{};
    var direct_started: ?*DirectCapture.Started = if (direct_capture) try DirectCapture.Started.start(a, request.value, count, capture_options.execution_workers) else null;
    defer if (direct_started) |value| value.deinit(&direct_stats);
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
        var source_bounds: ?SourceBounds.Report = if (candidate) try SourceBounds.derive(a, program.log_size, loaded.cpu_declarations, loaded.truth_declarations, loaded.bundle.requests) else null;
        defer if (source_bounds) |*value| value.deinit();
        var setup_cache: ?SetupCache.Cache = null;
        var setup_dir: ?[]u8 = null;
        defer if (setup_dir) |d| a.free(d);
        if (candidate) {
            const selected = try setupCacheOptions(a, .verifier, fixed_setup_bytes);
            setup_dir = selected.owned;
            setup_cache = try SetupCache.Cache.init(a, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, selected.options);
            try setup_cache.?.bindRequest(request.value);
        }
        defer if (setup_cache) |*owner| owner.deinit();
        var keys = if (setup_cache) |*owner| try Keys.initResident(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches, owner) else try Keys.initWithSuiteAndCaches(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches);
        defer keys.deinit();
        var fixed_set: ?FixedSet = if (setup_cache) |*owner| try FixedSet.init(a, &owner.fixed, keys.cpus, keys.truths, pcs) else null;
        defer if (fixed_set) |*owner| owner.deinit();
        const setup_ns = timer.read();
        const output = try Receiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, verify, pcs, if (fixed_set) |*authority| authority else null);
        const verify_end = timer.read();
        // Artifacts are written only after acceptance and outside the timings.
        if (setup_cache) |*owner| try owner.persist();
        if (setup_cache) |*cache_owner| {
            const owner = &cache_owner.fixed;
            return emit(a, .{ .profile = selected_profile, .security_qualified = false, .security_target = security_target, .security_profile = security_profile.name(), .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = verify_end - setup_ns, .setup_cache = cache_owner.stats, .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells, .source_accounting_profile = source_bounds.?.accounting_profile, .source_shape = source_bounds.?.shape, .source_lookup_only_conditional_degrees = source_bounds.?.conditional_degrees, .receiver_budget = receiver_budget.?.snapshot(), .receiver_recycler_cache_cap_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES, .receiver_worker_stack_upper_bound_bytes = try ReceiverBudget.stackBytes(try Request.effectiveWorkers(request.value)) });
        }
        return emit(a, .{ .profile = PROFILE, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .verify_ns = timer.read() - setup_ns });
    }
    var b2i = BlockToInputs{ .scope = if (inputs_only) "inputs-candidate diagnostic: sequential per-worker source build after setup; no proof" else "produce: per-worker source timestamps inside the scheduled prove" };
    b2i.init_done_at_ns = since(process_start);
    const cpu_layout = Plan.CpuLayout.forGkrProfile(request.value.execution_profile);
    // The capture's AUIPC/JAL FUNCTION facts depend on the decode layout.
    if (cpu_layout.compact_decode) try program.makeCompact();
    const import_start = timer.read();
    var captured = if (direct_started) |started| direct: {
        defer {
            started.deinit(&direct_stats);
            direct_started = null;
        }
        break :direct try started.capture(&image, &program, capture_options.max_inflight_packets, &direct_stats);
    } else capture: {
        var jobs = try std.fs.cwd().openDir(args[3], .{});
        defer jobs.close();
        break :capture try Capture.initWithOptions(a, &image, &program, request.value, jobs, count, capture_options.forPool(&pool));
    };
    defer captured.deinit();
    const packet_import_ns = timer.read() - import_start;
    const capture_ns = timer.read();
    b2i.capture_done_at_ns = since(process_start);
    const capture_inputs = CaptureInputs.of(&timer, import_start, capture_ns, &captured);
    b2i.capture = capture_inputs;
    try program.releaseFixedWitness();
    const capture_cache_released = recycler.releaseCached();
    // Explicit authenticated service scope; classic-only encodings stay closed.
    try @import("../services/gkr_local/service_scope.zig").advice(&captured.advice);
    const cpu = try Plan.cpus(a, &captured, cpu_layout);
    defer a.free(cpu);
    const truths = try Plan.truthsWithOptions(a, &captured, .{ .v3 = request.value.execution_profile == .ethereum_services_v3 }, if (resources) |limits| limits.keccak_max_log else 18);
    defer a.free(truths);
    if (capture_only) {
        const digest_start = timer.read();
        const digest = @import("capture_digest.zig").digest(image.identity, &captured);
        return emit(a, .{ .scope = "producer capture diagnostic only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_options = resources.?.capture_options, .capture_selection = captured.capture_schedule, .packet_import_ns = if (direct_capture) @as(u64, 0) else packet_import_ns, .image_and_import_ns = capture_ns, .captured_values_sha256 = std.fmt.bytesToHex(digest, .lower), .capture_inputs = capture_inputs, .capture_source = if (direct_capture) @as([]const u8, "in_process_execution") else "packet_directory", .direct_capture = if (direct_capture) direct_stats else null, .diagnostic_digest_ns = timer.read() - digest_start });
    }
    if (plan) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .scope = "geometry advice only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns });
    const operational = resources.?;
    const worker_limit = try producerWorkerLimit(operational.park_main, cpu.len + truths.len, operational.keccak_max_log);
    try Schedule.validateOrder(operational.stage2_order, try std.math.add(usize, cpu.len, truths.len));
    var source_bounds: ?SourceBounds.Report = null;
    defer if (source_bounds) |*value| value.deinit();
    if (candidate) {
        _ = try SourceBounds.validateInventory(cpu.len, truths.len);
        const requests = try a.alloc(P.Request, captured.native.items.len);
        defer a.free(requests);
        for (requests, 0..) |*value, i| {
            value.* = try C.requestView(captured.native.items, &captured.advice, i);
            try C.routeDword(value, cpu[i].bridges, captured.advice.events[i]);
        }
        try C.assignSpongeIds(requests);
        source_bounds = try SourceBounds.derive(a, program.log_size, cpu, truths, requests);
    }
    b2i.plan_done_at_ns = since(process_start);
    var setup_cache: ?SetupCache.Cache = null;
    var setup_dir: ?[]u8 = null;
    defer if (setup_dir) |d| a.free(d);
    if (candidate) {
        const selected = try setupCacheOptions(a, .prover, fixed_setup_bytes);
        setup_dir = selected.owned;
        setup_cache = try SetupCache.Cache.init(a, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, selected.options);
        try setup_cache.?.bindRequest(request.value);
    }
    defer if (setup_cache) |*owner| owner.deinit();
    var keys = if (setup_cache) |*owner| try Keys.initResident(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches, owner) else try Keys.initWithSuiteAndCaches(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    b2i.keys_done_at_ns = since(process_start);
    const fixed_cache: ?*FixedAuthority.Fixed.Cache = if (setup_cache) |*owner| &owner.fixed else null;
    var fixed_set: ?FixedSet = if (fixed_cache) |owner| try FixedSet.init(a, owner, keys.cpus, keys.truths, pcs) else null;
    defer if (fixed_set) |*owner| owner.deinit();
    b2i.setup_done_at_ns = since(process_start);
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = captured.total_steps, .max_total_steps = request.value.max_steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers };
    const completed = count == 0;
    if (completed and expected.final_pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
    if (inputs_only) {
        const timings = try a.alloc(C.WorkerTiming, keys.cpus.len + keys.truths.len);
        defer a.free(timings);
        try C.buildInputsOnly(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, if (fixed_set) |*authority| authority else null, process_start, timings, &b2i.coordinator_admitted_at_ns);
        b2i.setup_cache = if (setup_cache) |*owner| owner.stats else null;
        try b2i.finish(a, timings, keys.cpus.len);
        defer a.free(b2i.segments);
        // In-process residency: the setup of a next block with the same rungs
        // in this process (Keys + FixedSet again, all from the resident cache).
        var resident_setup_ns: ?u64 = null;
        var resident_stats: ?SetupCache.Stats = null;
        if (setup_cache) |*owner| {
            const before = owner.stats.resident_hits;
            var clock = try std.time.Timer.start();
            var again = try Keys.initResident(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches, owner);
            defer again.deinit();
            var again_set = try FixedSet.init(a, &owner.fixed, again.cpus, again.truths, pcs);
            defer again_set.deinit();
            resident_setup_ns = clock.read();
            try FixedSet.require(&again_set, again.cpus, again.truths, pcs);
            if (owner.stats.resident_hits - before != again.cpus.len + again.truths.len) return error.SetupCacheResidencyMiss;
            resident_stats = owner.stats;
        }
        if (setup_cache) |*owner| try owner.persist();
        return emit(a, .{ .scope = "producer block_to_inputs diagnostic only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .cpu_proofs = keys.cpus.len, .truth_proofs = keys.truths.len, .block_to_inputs = b2i, .resident_next_block_setup_ns = resident_setup_ns, .resident_stats = resident_stats, .setup_cache_after_persist = if (setup_cache) |*owner| owner.stats else null, .fixed_setup = if (fixed_cache) |owner| owner.snapshot() else null });
    }
    try std.fs.cwd().makeDir(args[4]);
    var dir = try std.fs.cwd().openDir(args[4], .{});
    defer dir.close();
    var store: ?Store = if (operational.park_main) try Store.initFullyParked(args[4], operational.disk_bytes) else null;
    defer if (store) |*value| value.deinit();
    const setup_ns = timer.read() - capture_ns;
    var observations = try @import("observations.zig").Owner.init(a, if (request.value.profile_stages) keys.cpus.len + keys.truths.len else 0);
    defer observations.deinit();
    if (request.value.profile_stages) try observations.enableScheduleTraces();
    const worker_timings = try a.alloc(C.WorkerTiming, keys.cpus.len + keys.truths.len);
    defer a.free(worker_timings);
    // This CLI owns capture; both snapshots occur outside worker activity.
    const capture_before_proving = captured.ownership();
    var gkr_tree_policy = @import("../services/gkr_local/child.zig").TreePolicy{};
    const prove_start = timer.read();
    var bundle = try C.produceWithAuthority(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, .{ .epoch = process_start, .admitted_at_ns = &b2i.coordinator_admitted_at_ns, .observed_tree_policy = &gkr_tree_policy, .checkpoint_above_gkr_bytes = operational.checkpoint_above_gkr_bytes, .defer_local_binding = operational.defer_local_binding, .consume_memory_events = true, .max_workers = worker_limit, .max_retained_frontend_bytes = operational.retained_frontend_bytes, .gkr_budget = operational.gkr_bytes, .global_budget = operational.global_bytes, .retained_store = if (store) |*value| value else null, .worker_timings = worker_timings, .native_profiles = if (request.value.profile_stages) observations.pointers else &.{}, .schedule = operational.schedule, .stage2_order = operational.stage2_order, .stage1_trace = observations.stage1_trace, .stage2_trace = observations.stage2_trace }, if (fixed_set) |*authority| authority else null);
    defer bundle.deinit(a);
    const prove_ns = timer.read() - prove_start;
    const capture_after_proving = captured.ownership();
    if (request.value.profile_stages) {
        const profiling = @import("../services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
        for (0..observations.pointers.len) |i| try profiling.finish(a, i);
        try Driver.writeJson(a, dir, "schedule.json", .{ .schema_version = 1, .indexing = "array index is original worker ordinal", .time_basis = "nanoseconds from each phase schedule start; stage1/stage2 origins distinct", .stage1 = observations.stage1_trace, .stage2 = observations.stage2_trace });
    }
    const verify_start = timer.read();
    const output = try Receiver.verifyWithAuthority(a, &image, &keys, &bundle, request.value.max_steps, request.value.batch_steps, completed, pcs, if (fixed_set) |*authority| authority else null);
    const verify_ns = timer.read() - verify_start;
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    b2i.setup_cache = if (setup_cache) |*owner| owner.stats else null;
    try b2i.finish(a, worker_timings, keys.cpus.len);
    defer a.free(b2i.segments);
    try Driver.writeJson(a, dir, "report.json", .{ .profile = selected_profile, .security_qualified = false, .security_target = if (candidate) security_target else null, .completed_ethereum_block = completed, .total_steps = captured.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .output = output, .resources = operational, .capture_ns = capture_ns, .packet_import_ns = if (direct_capture) @as(u64, 0) else packet_import_ns, .capture_source = if (direct_capture) @as([]const u8, "in_process_execution") else "packet_directory", .direct_capture = if (direct_capture) direct_stats else null, .capture_selection = captured.capture_schedule, .capture_cache_released_bytes = capture_cache_released, .capture_before_proving = capture_before_proving, .capture_after_proving = capture_after_proving, .gkr_tree_policy = gkr_tree_policy, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = verify_ns, .workers = worker_timings, .total_before_report_ns = timer.read(), .retained_main = if (store) |*value| value.stats() else null, .block_to_inputs = b2i });
    // Artifacts are written after the proof, outside every reported timing.
    if (setup_cache) |*owner| try owner.persist();
    if (fixed_cache) |owner| try Driver.writeJson(a, dir, "candidate-fixed-setup.json", .{ .profile = selected_profile, .security_qualified = false, .config = pcs, .fixed_setup = owner.snapshot(), .setup_cache = setup_cache.?.stats, .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells });
    if (source_bounds) |*value| try Driver.writeJson(a, dir, "candidate-source-bounds.json", .{ .profile = selected_profile, .security_qualified = false, .accounting_profile = value.accounting_profile, .shape = value.shape, .cpu_scopes = value.cpu_scopes, .truth_scopes = value.truth_scopes, .global_signed = value.global_signed, .global_denominator_slots = value.global_denominator_slots, .lookup_only_conditional_degrees = value.conditional_degrees, .transcript_round_bound_qualified = value.transcript_round_bound_qualified, .secp_polynomial_error_budget_qualified = value.secp_polynomial_error_budget_qualified });
    try std.posix.fsync(dir.fd);
}
/// Producer block-to-inputs timeline, nanoseconds on this CLI's clock (started
/// after request parse and pool start). Report-only; no protocol effect. On the
/// packet route it excludes the separate `nativeprepare` process.
const CaptureInputs = struct {
    /// Expected image + program init (and compact decode), before capture.
    init_ns: u64,
    /// Segment 0 inputs ready: captured, admitted and its ledger shard built.
    first_inputs_ns: ?u64,
    /// Last segment's ledger shard built.
    last_inputs_ns: ?u64,
    /// All segment inputs ready, including the global boundary cells.
    all_inputs_ns: u64,
    /// Serial ordered ledger, summed over segments; and its `finish`.
    ledger_ns: u64,
    ledger_finish_ns: u64,
    fn of(timer: *const std.time.Timer, init_ns: u64, all_ns: u64, captured: *const Capture) CaptureInputs {
        return .{ .init_ns = init_ns, .first_inputs_ns = sinceTimer(timer, captured.first_inputs_at), .last_inputs_ns = sinceTimer(timer, captured.last_inputs_at), .all_inputs_ns = all_ns, .ledger_ns = captured.timing.ledger_ns, .ledger_finish_ns = captured.timing.finish_ns };
    }
    fn sinceTimer(timer: *const std.time.Timer, at: ?std.time.Instant) ?u64 {
        return if (at) |value| value.since(timer.started) else null;
    }
};
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
    // The window is 1..MAX_INFLIGHT on both routes (no longer capped at 2).
    capture_resources.capture_options.max_inflight_packets = 3;
    try capture_resources.validate();
    capture_resources.capture_options.max_inflight_packets = @import("capture.zig").MAX_INFLIGHT;
    try capture_resources.validate();
    capture_resources.capture_options.max_inflight_packets = @import("capture.zig").MAX_INFLIGHT + 1;
    try std.testing.expectError(error.InvalidEthereumCaptureOptions, capture_resources.validate());
    capture_resources.capture_options.max_inflight_packets = 0;
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

test "explicit recycler cache ceiling remains an operational bounded option" {
    const a = std.testing.allocator;
    var limits = Resources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 0, .park_main = false, .schedule = .{ .memory_cap_bytes = 5 } };
    try limits.validate();
    const old = try std.json.Stringify.valueAlloc(a, limits, .{});
    defer a.free(old);
    try std.testing.expect(std.mem.indexOf(u8, old, "recycler_cache_bytes") == null);
    limits.recycler_cache_bytes = 0;
    try limits.validate();
    const encoded = try std.json.Stringify.valueAlloc(a, limits, .{});
    defer a.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"recycler_cache_bytes\":0") != null);
    const decoded = try std.json.parseFromSlice(Resources, a, encoded, .{});
    defer decoded.deinit();
    try decoded.value.validate();
    try std.testing.expectEqual(@as(usize, 0), decoded.value.recycler_cache_bytes);
    limits.recycler_cache_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES + 1;
    try std.testing.expectError(error.UnsupportedRecyclerCacheLimit, limits.validate());
    const candidate = CandidateResources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 0, .fixed_setup_bytes = 6, .park_main = false, .recycler_cache_bytes = 1024, .schedule = .{ .memory_cap_bytes = 5 } };
    try candidate.validate();
    try std.testing.expectEqual(@as(usize, 1024), candidate.operational().recycler_cache_bytes);
}

// Worker admission is an operational bound, independent of scheduler threads.
// The default geometry keeps the prior32 ceiling; only smaller parked shards
// may select a larger, still bounded roster. No-store retention stays at8.
fn producerWorkerLimit(park_main: bool, count: usize, keccak_max_log: u32) !usize {
    if (keccak_max_log < 16 or keccak_max_log > 18) return error.UnsupportedEthereumKeccakShardLog;
    const cap: usize = if (!park_main) 8 else if (keccak_max_log < 18) 64 else 32;
    if (count == 0 or count > cap or count > @import("../services/gkr_local/manifest.zig").MAX_WORKERS) return error.BoundedWideCoordinatorLimit;
    return if (park_main) @max(@as(usize, 32), count) else 8;
}
test "Keccak shard operational resource remains explicit bounded and default-schema preserving" {
    const a = std.testing.allocator;
    var limits = Resources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .schedule = .{ .memory_cap_bytes = 5 } };
    const old = try std.json.Stringify.valueAlloc(a, limits, .{});
    defer a.free(old);
    try std.testing.expect(std.mem.indexOf(u8, old, "keccak_max_log") == null);
    limits.keccak_max_log = 16;
    try limits.validate();
    const encoded = try std.json.Stringify.valueAlloc(a, limits, .{});
    defer a.free(encoded);
    const parsed = try std.json.parseFromSlice(Resources, a, encoded, .{});
    defer parsed.deinit();
    try parsed.value.validate();
    try std.testing.expectEqual(@as(u32, 16), parsed.value.keccak_max_log);
    limits.keccak_max_log = 15;
    try std.testing.expectError(error.UnsupportedEthereumKeccakShardLog, limits.validate());
    const candidate = CandidateResources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .fixed_setup_bytes = 5, .keccak_max_log = 17, .schedule = .{ .memory_cap_bytes = 6 } };
    try candidate.validate();
    try std.testing.expectEqual(@as(u32, 17), candidate.operational().keccak_max_log);
    try std.testing.expectEqual(@as(usize, 32), try producerWorkerLimit(true, 30, 18));
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, producerWorkerLimit(true, 36, 18));
    try std.testing.expectEqual(@as(usize, 36), try producerWorkerLimit(true, 36, 16));
    try std.testing.expectEqual(@as(usize, 64), try producerWorkerLimit(true, 64, 16));
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, producerWorkerLimit(true, 65, 16));
    try std.testing.expectEqual(@as(usize, 8), try producerWorkerLimit(false, 8, 16));
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, producerWorkerLimit(false, 9, 16));
}

test "hybrid checkpoint resource is optional operational metadata and candidate forwarded" {
    var limits = Resources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .schedule = .{ .memory_cap_bytes = 5 } };
    const before = try std.json.Stringify.valueAlloc(std.testing.allocator, limits, .{});
    defer std.testing.allocator.free(before);
    try std.testing.expect(std.mem.indexOf(u8, before, "checkpoint_above_gkr_bytes") == null);
    limits.checkpoint_above_gkr_bytes = 12 << 30;
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, limits, .{});
    defer std.testing.allocator.free(encoded);
    const decoded = try std.json.parseFromSlice(Resources, std.testing.allocator, encoded, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(limits.checkpoint_above_gkr_bytes, decoded.value.checkpoint_above_gkr_bytes);
    const candidate = CandidateResources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .fixed_setup_bytes = 6, .checkpoint_above_gkr_bytes = 7, .schedule = .{ .memory_cap_bytes = 5 } };
    try std.testing.expectEqual(@as(usize, 7), candidate.operational().checkpoint_above_gkr_bytes);
}

test "deferred local binding resource defaults off and candidate forwards operational flag" {
    var value = Resources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .schedule = .{ .memory_cap_bytes = 5 } };
    const old = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(old);
    try std.testing.expect(std.mem.indexOf(u8, old, "defer_local_binding") == null);
    value.defer_local_binding = true;
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(encoded);
    const decoded = try std.json.parseFromSlice(Resources, std.testing.allocator, encoded, .{});
    defer decoded.deinit();
    try std.testing.expect(decoded.value.defer_local_binding);
    const candidate = CandidateResources{ .gkr_bytes = 1, .global_bytes = 2, .retained_frontend_bytes = 3, .disk_bytes = 4, .fixed_setup_bytes = 6, .defer_local_binding = true, .schedule = .{ .memory_cap_bytes = 5 } };
    try std.testing.expect(candidate.operational().defer_local_binding);
}

test "direct execution worker count is explicit bounded operational metadata" {
    var options: CaptureOptions = .{};
    try std.testing.expectEqual(@as(u8, 0), options.execution_workers);
    options.execution_workers = 2;
    try options.validate();
    try std.testing.expect(!options.isDefault());
    options.execution_workers = 33;
    try std.testing.expectError(error.InvalidEthereumCaptureOptions, options.validate());
}
