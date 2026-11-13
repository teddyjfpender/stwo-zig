//! Single Ethereum request lifecycle: capture, proving, publication and optional recursion.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../../rv64_ethereum_request.zig");
const Image = @import("../../word16_execution/expected_image.zig");
const Program = @import("stwo_riscv_cpu_integration").rv64_program.Program;
const Driver = @import("../../word16_execution/driver.zig");
const Capture = @import("capture.zig").Owner;
const CaptureOptions = @import("capture_options.zig").Options;
const DirectCapture = @import("direct.zig");
const EarlyCPU = @import("early_cpu0.zig");
const EarlySegments = @import("early_segments.zig");
const Plan = @import("plan.zig");
const Keys = @import("keys.zig").Owner;
const Admission = @import("receiver.zig");
const Receiver = @import("gkr_receiver.zig");
const C = @import("coordinator.zig").Coordinator;
const W = @import("stwo_riscv_cpu_integration").rv64_gkr_bundle_wire;
const P = @import("stwo_riscv_cpu_integration").rv64_execution.services.protocol;
const Store = @import("stwo_riscv_cpu_integration").rv64_gkr_coordinator.Store;
const Schedule = @import("stwo_riscv_cpu_integration").rv64_execution.services.schedule;
const Suite = @import("stwo_riscv_cpu_integration").rv64_pcs_suite.Suite;
const NativeCache = @import("stwo_riscv_cpu_integration").rv64_execution.word16.setup.NativeCache;
const MetadataCache = @import("stwo_riscv_cpu_integration").rv64_program.Metadata;
const Recycler = @import("stwo_riscv_cpu_integration").rv64_large_block_recycler.LargeBlockRecycler;
const ReceiverBudget = @import("receiver_budget.zig");
const FixedAuthority = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority;
const FixedSet = @import("stwo_riscv_cpu_integration").rv64_gkr_fixed_authority_set.Set;
const Candidate = @import("stwo_riscv_cpu_integration").rv64_om31_security_candidate;
const SourceBounds = @import("stwo_riscv_cpu_integration").rv64_gkr_source_bounds;
const SetupCache = @import("setup_cache.zig");
const ResidentSession = @import("resident_session.zig").Session;
const SETUP_CACHE_ENV = @import("gkr_resources.zig").SETUP_CACHE_ENV;
const requireIndependentReceiverSetup = @import("gkr_resources.zig").requireIndependentReceiverSetup;
const residentSetupFixedSet = @import("gkr_resources.zig").residentSetupFixedSet;
const setupCacheOptions = @import("gkr_resources.zig").setupCacheOptions;
const candidateLabel = @import("gkr_resources.zig").candidateLabel;
const selectProfile = @import("gkr_resources.zig").selectProfile;
const PROFILE = @import("gkr_resources.zig").PROFILE;
const Resources = @import("gkr_resources.zig").Resources;
const CandidateResources = @import("gkr_resources.zig").CandidateResources;
const config = @import("gkr_resources.zig").config;
const residentWorkerLimit = @import("gkr_resources.zig").residentWorkerLimit;
const producerWorkerLimit = @import("gkr_resources.zig").producerWorkerLimit;
const CombinedRecursion = @import("gkr_main.zig").CombinedRecursion;
const ResidentStages = @import("gkr_main.zig").ResidentStages;

pub const CpuPrestage = struct {
    stage: @import("stwo_riscv_cpu_integration").rv64_cpu_source.ProjectionStage,
    image_identity: [32]u8 = undefined,
    first_pass: bool = false,
    pub fn firstPass(raw: *anyopaque, source: *const @import("stwo_riscv_cpu_integration").rv64_cpu_source.FirstPass) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        self.stage.prestage_first_pass.?(self.stage.context, source, self.image_identity);
    }
    pub fn ready(raw: *anyopaque, index: usize, native: *const @import("stwo_riscv_cpu_integration").rv64_execution.word16.prepared.Prepared, _: []const @import("ethereum_frontend_component").rv64_air.memory.load_store_v2.native.Event, at_ns: u64) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        if (index != 0 or self.first_pass) return;
        std.debug.print("GPU_CPU_PRESTAGE event=capture_ready ordinal=0 utc_ns={} ordered_ready_ns={}\n", .{ std.time.nanoTimestamp(), at_ns });
        if (native.cpu) |*source| self.stage.prestage.?(self.stage.context, source, self.image_identity);
    }
    pub fn cancel(raw: *anyopaque) void {
        const self: *CpuPrestage = @ptrCast(@alignCast(raw));
        self.stage.cancel_prestage.?(self.stage.context);
    }
};

pub const BlockToInputs = struct {
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
    pub fn finish(self: *BlockToInputs, a: std.mem.Allocator, timings: []const C.WorkerTiming, cpu_count: usize) !void {
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
pub fn since(origin: std.time.Instant) u64 {
    const now = std.time.Instant.now() catch return 0;
    return now.since(origin);
}

pub fn runArguments(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: ?*ResidentSession, comptime enable_recursion: bool, recursion_execution: if (enable_recursion) CombinedRecursion else void) !void {
    const process_start = try std.time.Instant.now();
    // canon-vk M5: outer profile / shape / fold arity env must parse, or the
    // process exits with a clean error before any work (never a panic, P03).
    try @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.checkPolicyEnv();
    const recursion_factory = if (enable_recursion) recursion_execution.factory else {};
    const base = recycler.allocator();
    const device_pcs_stage = stages.pcs;
    const om31_composition_stage = stages.composition;
    const numerical_gkr_stage = stages.numerical;
    const resident_composition_stage = stages.resident_composition;
    const selection = try selectProfile(all_args);
    const security_profile = selection.profile;
    const args = selection.args;
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe")) return emit(base, .{ .profile = PROFILE, .security_qualified = false, .pcs = try config(), .usage = "produce-control CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON | verify-control CONFIG OUT [RECEIVER_BYTES] | verify-prefix-control CONFIG OUT [RECEIVER_BYTES] | plan CONFIG JOBS PREFIX_COUNT | capture CONFIG JOBS PREFIX_COUNT RESOURCE_JSON" });
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe-candidate")) return emit(base, .{ .profile = candidateLabel(security_profile), .security_profile = security_profile.name(), .security_qualified = false, .security_target = Candidate.assumptionTarget(security_profile), .pcs = Candidate.configFor(security_profile), .scope = if (security_profile.conjectured()) "native 128-bit CONJECTURED target (ethSTARK-style FRI accounting); no proven bound and no whole-protocol certificate" else "native 128-bit target under documented assumptions; no whole-protocol certificate", .usage = "[--security-profile proven_beta2_q256_p0_fold4|conjectured128_b2_q108_p20_fold4 (default)|d2_native_b4_q54_p20_fold4] produce-candidate CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON (requires fixed_setup_bytes; JOBS=- executes in process) | inspect-recursion-schedule CONFIG OUT [ORDINAL] (CPU-only diagnostic; no acceptance,24GiB live/12GiB subset fixed cache) | verify-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] | verify-prefix-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] | verify-recursion-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] (CPU recursion receiver only; existing proofs, no proving fallback)" });
    if (args.len < 4) return error.ExpectedModeConfigAndDirectory;
    const inspect_schedule = std.mem.eql(u8, args[1], "inspect-recursion-schedule");
    const inspection_ordinal = if (inspect_schedule) try @import("schedule_inspection.zig").ordinal(args) else 0;
    if (inspect_schedule) {
        if (comptime enable_recursion) {
            if (recursion_factory != null or recursion_execution.ready != null) return error.ScheduleInspectionRequiresCpuProduct;
        } else return error.RecursionProductRequired;
    }
    const strict_recursion_verify = std.mem.eql(u8, args[1], "verify-recursion-candidate");
    const resume_recursion = std.mem.eql(u8, args[1], "resume-recursion-candidate");
    const recurse = strict_recursion_verify or resume_recursion or std.mem.eql(u8, args[1], "recurse-candidate");
    const combined = isCombinedProducer(args[1]);
    if (combined) {
        if (args.len != 7) return error.ExpectedModeConfigJobsOutputPrefixAndResources;
        if (try std.fmt.parseUnsigned(u32, args[5], 10) != 0) return error.CombinedRequiresCompleteExecution;
        if (comptime !enable_recursion) return error.RecursionProductRequired;
        if (recursion_factory == null and recursion_execution.ready == null) return error.CombinedRequiresDeviceRecursion;
        try stages.requireFullyResident();
    }
    // warm-setup-candidate: inputs-candidate stopped right after keys + FIXED
    // (resident-service pre-warm; no source build, no proof).
    const warm_setup = std.mem.eql(u8, args[1], "warm-setup-candidate");
    const candidate = std.mem.eql(u8, args[1], "inputs-candidate") or warm_setup or inspect_schedule or combined or recurse or std.mem.eql(u8, args[1], "produce-candidate") or std.mem.eql(u8, args[1], "verify-candidate") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    const verify = inspect_schedule or recurse or std.mem.eql(u8, args[1], "verify-control") or std.mem.eql(u8, args[1], "verify-candidate");
    // Persisted roots are operator-trusted acceleration, never independent
    // receiver authority. Fresh receivers always derive setup from source.
    if (verify) try requireIndependentReceiverSetup(std.process.hasEnvVarConstant(SETUP_CACHE_ENV));
    const prefix = std.mem.eql(u8, args[1], "verify-prefix-control") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    if (prefix) try requireIndependentReceiverSetup(std.process.hasEnvVarConstant(SETUP_CACHE_ENV));
    const produce = combined or std.mem.eql(u8, args[1], "produce-control") or std.mem.eql(u8, args[1], "produce-candidate");
    const plan = std.mem.eql(u8, args[1], "plan");
    // Session-scoped setup warm-up (inputs-candidate) is producer-side too.
    if (session != null and !produce and !std.mem.eql(u8, args[1], "inputs-candidate") and !warm_setup) return error.ResidentSessionRequiresProducer;
    const capture_only = std.mem.eql(u8, args[1], "capture");
    // Diagnostic: everything produce-candidate does up to every worker's
    // prover inputs (setup + per-segment source build), then stops. No proof.
    const inputs_only = std.mem.eql(u8, args[1], "inputs-candidate") or warm_setup;
    if (!verify and !prefix and !produce and !plan and !capture_only and !inputs_only) return error.InvalidWideEthereumMode;
    if (inputs_only and args.len != 6) return error.ExpectedInputsConfigJobsPrefixAndResources;
    if (selection.explicit and !candidate) return error.SecurityProfileRequiresCandidateMode;
    const receiver_bytes: ?usize = if (inspect_schedule) @import("schedule_inspection.zig").live_bytes else if (verify or prefix) try ReceiverBudget.limit(args, candidate) else null;
    if (produce and args.len != 7) return error.ExpectedModeConfigJobsOutputPrefixAndResources;
    if (capture_only and args.len != 6) return error.ExpectedCaptureConfigJobsPrefixAndResources;
    if (plan and args.len != 5) return error.ExpectedModeConfigJobsAndPrefix;
    const pcs = if (candidate) Candidate.configFor(security_profile) else try config();
    const selected_profile = if (candidate) candidateLabel(security_profile) else PROFILE;
    const security_target = Candidate.assumptionTarget(security_profile);
    var fixed_setup_bytes: usize = 0;
    if (candidate and (verify or prefix)) {
        fixed_setup_bytes = if (inspect_schedule) @import("schedule_inspection.zig").fixed_cache_bytes else try std.fmt.parseUnsigned(usize, args[4], 10);
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
    try @import("stwo_riscv_cpu_integration").rv64_execution.services.scope.profile(request.value.execution_profile);
    // Candidate lane pools already exist. This native pool stays idle but
    // alive during recursion, so charge its live helper stacks separately.
    const ready = if (enable_recursion) recursion_execution.ready else null;
    const native_workers = try Request.effectiveWorkers(request.value);
    if (ready) |options| if (options.pool_worker_budget > native_workers) return error.InvalidCombinedRecursionWorkerBudget;
    var native_stacks = engine.host_budget_allocator.SharedHostBudget.ExternalReservation.empty();
    defer native_stacks.deinit();
    if (ready != null) {
        const owner = try @import("stwo_riscv_cpu_integration").rv64_recursion_budget.require(engine.host_budget_allocator.SharedHostBudget, base);
        native_stacks = try owner.reserveExternal(try std.math.mul(usize, native_workers - 1, ReceiverBudget.WORKER_STACK_BYTES));
    }
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
    if (combined and resources.?.park_main) return error.CombinedRequiresResidentMain;
    const uniform_throughput = if (candidate_resource_owner) |owner| owner.value.keccak_uniform_throughput else false;
    if (uniform_throughput and request.value.execution_profile != .ethereum_services_v3) return error.UniformThroughputRequiresServicesV3;
    const coalesce_truth_families = if (resources) |r| r.coalesce_truth_families else false;
    if (coalesce_truth_families and (!candidate or request.value.execution_profile != .ethereum_services_v3)) return error.OneTruthPerFamilyRequiresV3Candidate;
    const one_truth_per_family = if (resources) |r| r.one_truth_per_family else false;
    if (one_truth_per_family and coalesce_truth_families) return error.ConflictingTruthFamilyPlans;
    if (one_truth_per_family and (!candidate or request.value.execution_profile != .ethereum_services_v3)) return error.OneTruthPerFamilyRequiresV3Candidate;

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
    const shared_walk_authority = false;
    const early_cpu = false;
    const early_main = false;
    const early_segments = false;
    // Refuse mixed speculative owners before starting boot/capture/callbacks.
    const old_first = false;
    if (early_main and (early_cpu or old_first)) return error.ConflictingEarlyCpuModes;
    if (early_segments and (early_cpu or old_first or early_main)) return error.ConflictingEarlyCpuModes;
    if (early_main and (!combined or !candidate or !direct_capture or count != 0 or session == null or stages.early_memory == null or capture_options.execution_workers == 0 or !@import("../../rv64_ethereum_segments.zig").ramFirstPassEnabled())) return error.EarlyMainRequiresAdmittedResidentFirstPass;
    if (early_segments and (!combined or !candidate or !direct_capture or count != 0 or session == null or stages.early_memory == null or stages.early_segments == null or capture_options.execution_workers == 0 or !@import("../../rv64_ethereum_segments.zig").ramFirstPassEnabled())) return error.EarlySegmentsRequireAdmittedResidentFirstPass;
    const early_host_budget = if (early_main or early_segments) try @import("stwo_riscv_cpu_integration").rv64_recursion_budget.require(engine.host_budget_allocator.SharedHostBudget, base) else null;

    if (early_cpu and (!direct_capture or !combined or stages.cpu_projection == null)) return error.CpuPrestageRequiresDirectResidentCombined;
    const early_first = false;
    if (early_first and (!early_cpu or !@import("../../rv64_ethereum_segments.zig").minimalFirstPassEnabled())) return error.FirstPassCpuPrestageRequiresRecords;
    var prestage: ?CpuPrestage = if (early_cpu) .{ .stage = stages.cpu_projection.?, .first_pass = early_first } else null;
    if (early_first and prestage.?.stage.prestage_first_pass == null) return error.FirstPassCpuPrestageUnavailable;
    if (prestage) |*p| if (p.stage.prestage == null or p.stage.join_prestage == null or p.stage.cancel_prestage == null) return error.CpuPrestageStageUnavailable;
    defer if (prestage) |*p| CpuPrestage.cancel(p);
    const walk_authority: ?Request.AuthorityProvider = if (shared_walk_authority and session != null) session.?.authorities.provider() else null;
    var direct_started: ?*DirectCapture.Started = if (direct_capture) try DirectCapture.Started.startWithAuthority(a, request.value, count, capture_options.execution_workers, walk_authority) else null;
    if (prestage) |*p| direct_started.?.ready = .{ .context = p, .call = CpuPrestage.ready, .cancel = CpuPrestage.cancel, .first_pass = if (early_first) CpuPrestage.firstPass else null };
    defer if (direct_started) |value| value.deinit(&direct_stats);
    // M5 platform: a resident session reuses the receiver-derived
    // ProgramAuthority of the same guest (keyed by its executable words).
    var image = if (session) |shared| try Image.Owner.initShared(a, request.value, &shared.authorities) else try Image.Owner.init(a, request.value);
    defer image.deinit();
    const image_load_ns = timer.read();
    if (prestage) |*p| p.image_identity = image.identity;
    var local_native: ?NativeCache.Cache = if (session == null) try NativeCache.Cache.init(a, 256 << 20) else null;
    defer if (local_native) |*cache| cache.deinit();
    var local_metadata: ?MetadataCache.Cache = if (session == null) try MetadataCache.Cache.init(a, 64 << 20) else null;
    defer if (local_metadata) |*cache| cache.deinit();
    const caches = if (session) |shared| shared.caches() else @import("stwo_riscv_cpu_integration").rv64_execution.word16.setup.ImmutableCaches{ .native = &local_native.?, .program = &local_metadata.? };
    const compact_capture_program = true;
    var program = if (compact_capture_program) try Program.initCaptureWithAuthorityAndMetadataCache(a, &image.authority, caches.program.?) else try Program.initWithAuthorityAndMetadataCache(a, &image.authority, caches.program.?);
    defer program.deinit();
    const program_ns = timer.read() - image_load_ns;
    if (verify or prefix) {
        var dir = try std.fs.cwd().openDir(args[3], .{});
        defer dir.close();
        var loaded = try W.read(a, dir, .{ .max_total_steps = request.value.max_steps });
        defer loaded.deinit(a);
        if (inspect_schedule and inspection_ordinal >= loaded.bundle.cpus.len + loaded.bundle.truths.len) return error.InvalidInspectionOrdinal;
        const expected = try Admission.expectedFromRequests(&image, program.identity, loaded.bundle.requests, request.value.max_steps, request.value.batch_steps, verify);
        var source_bounds: ?SourceBounds.Report = if (candidate) try SourceBounds.derive(a, program.log_size, loaded.cpu_declarations, loaded.truth_declarations, loaded.bundle.requests) else null;
        defer if (source_bounds) |*value| value.deinit();
        const native_keys_start_ns = timer.read();
        var keys = try Keys.initWithSuiteAndCaches(a, &image, loaded.cpu_declarations, loaded.truth_declarations, true, Suite.experimentalFold4(), caches);
        defer keys.deinit();
        const native_keys_ns = timer.read() - native_keys_start_ns;
        const fixed_setup_start_ns = timer.read();
        var fixed_cache: ?FixedAuthority.Fixed.Cache = if (candidate) try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes) else null;
        defer if (fixed_cache) |*owner| owner.deinit();
        var fixed_set: ?FixedSet = if (fixed_cache) |*owner| try FixedSet.init(a, owner, keys.cpus, keys.truths, pcs) else null;
        defer if (fixed_set) |*owner| owner.deinit();
        const setup_ns = timer.read();
        const setup_breakdown = .{ .image_ns = image_load_ns, .program_ns = program_ns, .native_keys_ns = native_keys_ns, .fixed_authority_ns = setup_ns - fixed_setup_start_ns, .other_ns = native_keys_start_ns - image_load_ns - program_ns };
        if (inspect_schedule) {
            if (comptime !enable_recursion) return error.RecursionProductRequired;
            const inspection = try @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.inspectLeafSchedule(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, if (fixed_set) |*authority| authority else null, inspection_ordinal);
            return emit(a, .{ .schema = "rv64-recursion-schedule-inspection/v1", .diagnostic = true, .accepted = false, .scope = "Selected native leaf capture and original graph schedule census only; no complete-block or recursive-root acceptance", .selected_native_leaf_verified = true, .recursion_proof_generated = false, .gpu_context_created = false, .profile = selected_profile, .security_qualified = false, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .inspection = inspection, .task_kind_order = .{ "add", "sub", "mul", "pointwise_mul", "triple_xor", "m31_to_u32", "blake_g", "permutation", "hint" }, .hint_kind_order = .{ "seed", "inverse", "divide", "pointwise_inverse_or_zero", "pointwise_lsb", "byte", "byte_complement", "is_nonzero", "zero" }, .width_bucket_upper_bounds = @import("stwo_riscv_cpu_integration").rv64_execution.recursion.om31_native.schedule_census.bucket_upper_bounds, .receiver_requested_live_cap_bytes = @import("schedule_inspection.zig").live_bytes, .receiver_budget = receiver_budget.?.snapshot(), .fixed_cache_cap_bytes = fixed_setup_bytes, .fixed_cache_is_subset_of_live_cap = true, .recycler_cache_cap_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES, .recycler_cached_bytes_outside_requested_live_cap = true, .requested_live_plus_recycler_cap_bytes = @import("schedule_inspection.zig").live_bytes + ReceiverBudget.RECYCLER_CACHE_BYTES, .budget_scope = "Requested live 24 GiB includes fixed cache 12 GiB and native/metadata caches; up to 4 GiB freed recycler blocks plus worker stacks outside live count; not an RSS cap", .worker_stack_upper_bound_bytes = try ReceiverBudget.stackBytes(native_workers), .operational_workers = native_workers, .device_capacity_values_are_estimates_only = true });
        }
        if (recurse) {
            std.log.info("RECURSION_SETUP image_ns={d} program_ns={d} native_keys_ns={d} fixed_authority_ns={d} other_ns={d}", .{ setup_breakdown.image_ns, setup_breakdown.program_ns, setup_breakdown.native_keys_ns, setup_breakdown.fixed_authority_ns, setup_breakdown.other_ns });
            if (comptime !enable_recursion) return error.RecursionProductRequired;
            if (strict_recursion_verify) {
                // One independent authority construction admits BOTH checks.
                // The existing-only recursion path cannot generate a proof or
                // materialize a host assignment even when a file is missing.
                const native_start_ns = timer.read();
                const output = try Receiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, true, pcs, if (fixed_set) |*authority| authority else null);
                const native_verify_ns = timer.read() - native_start_ns;
                const last = loaded.bundle.requests[loaded.bundle.requests.len - 1].base;
                _ = try @import("terminal.zig").require(&image, last.cpu, last.memory.terminal);
                var recursive_dir = try dir.openDir("recursion-om31", .{});
                defer recursive_dir.close();
                const recursion = try @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.verifyExisting(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, if (fixed_set) |*authority| authority else null, recursive_dir);
                return emit(a, .{ .accepted = true, .completed_ethereum_block = true, .output = output, .native_profile = selected_profile, .outer_profile = @import("stwo_circuit_cpu_integration").om31.protocol.domainName(), .security_qualified = false, .security_scope = "128-bit target under documented assumptions; no whole-protocol certificate", .shared_fresh_native_authority = true, .native_verified_before_recursion = true, .existing_recursive_proofs_only = true, .trace_only_recursive_graphs = true, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .native_verify_ns = native_verify_ns, .total_after_setup_ns = timer.read() - setup_ns, .native = .{ .accepted = true, .completed_ethereum_block = true, .security_profile = security_profile.name(), .profile = selected_profile, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .verify_ns = native_verify_ns }, .recursive = recursion });
            }
            dir.makeDir("recursion-om31") catch |err| {
                if (err != error.PathAlreadyExists or !resume_recursion) return err;
            };
            var recursive_dir = try dir.openDir("recursion-om31", .{});
            defer recursive_dir.close();
            const last = loaded.bundle.requests[loaded.bundle.requests.len - 1].base;
            const output = try @import("terminal.zig").require(&image, last.cpu, last.memory.terminal);
            // Reject an unexpected Ethereum endpoint before producing durable
            // recursive proofs or an accepted execution-root report.
            const recursion = try @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.run(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, if (fixed_set) |*authority| authority else null, recursive_dir, resume_recursion, recursion_factory);
            return emit(a, .{ .accepted = true, .completed_ethereum_block = true, .output = output, .native_profile = selected_profile, .outer_profile = @import("stwo_circuit_cpu_integration").om31.protocol.domainName(), .security_qualified = false, .security_scope = "128-bit target under documented assumptions; no whole-protocol certificate", .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .recursive = recursion });
        }
        const output = try Receiver.verifyWithAuthority(a, &image, &keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, verify, pcs, if (fixed_set) |*authority| authority else null);
        if (fixed_cache) |*owner| return emit(a, .{ .profile = selected_profile, .security_qualified = false, .security_target = security_target, .security_profile = security_profile.name(), .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .verify_ns = timer.read() - setup_ns, .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells, .source_accounting_profile = source_bounds.?.accounting_profile, .source_shape = source_bounds.?.shape, .source_lookup_only_conditional_degrees = source_bounds.?.conditional_degrees, .receiver_budget = receiver_budget.?.snapshot(), .receiver_recycler_cache_cap_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES, .receiver_worker_stack_upper_bound_bytes = try ReceiverBudget.stackBytes(try Request.effectiveWorkers(request.value)) });
        return emit(a, .{ .profile = PROFILE, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .verify_ns = timer.read() - setup_ns });
    }
    var b2i = BlockToInputs{ .scope = if (inputs_only) "inputs-candidate diagnostic: sequential per-worker source build after setup; no proof" else "produce: per-worker source timestamps inside the scheduled prove" };
    b2i.init_done_at_ns = since(process_start);
    const cpu_layout = Plan.CpuLayout.forGkrProfile(request.value.execution_profile);
    // The capture's AUIPC/JAL FUNCTION facts depend on the decode layout.
    if (cpu_layout.compact_decode) try program.makeCompact();
    var early_owner: ?*EarlyCPU.Owner = null;
    defer if (early_owner) |owner| owner.deinit();
    var early_segment_owner: ?*EarlySegments.Owner = null;
    defer if (early_segment_owner) |owner| owner.deinit();
    if (early_main or early_segments) {
        const shared = session.?;
        // Setup class lookup is receiver/image/suite owned and independent of
        // the final ordered roster. Cache lifetime remains the resident session.
        if (shared.setup == null) {
            const selected = try setupCacheOptions(shared.allocator, .prover, fixed_setup_bytes);
            defer if (selected.owned) |directory| shared.allocator.free(directory);
            shared.setup = try SetupCache.Cache.init(shared.allocator, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, selected.options);
            shared.setup_fixed_bytes = fixed_setup_bytes;
        } else if (shared.setup_fixed_bytes != fixed_setup_bytes) return error.ResidentFixedBudgetChanged;
        try shared.setup.?.bindRequest(request.value);
        var memory = stages.early_memory.?;
        if (memory.host_budget) |owner| if (owner != early_host_budget.?) return error.ForeignEarlyMainHostBudget;
        memory.host_budget = early_host_budget;
        if (early_segments) {
            var provider = stages.early_segments.?;
            provider.host_budget = early_host_budget;
            early_segment_owner = try EarlySegments.Owner.create(.{
                .allocator = a,
                .image = &image,
                .config = request.value,
                .pcs = pcs,
                .layout = cpu_layout,
                .strict_roster = (try @import("stwo_riscv_cpu_integration").rv64_native_policy.current()).strictRoster(),
                .canonical_rungs = false,
                .caches = caches,
                .setup_cache = &shared.setup.?,
                .fixed_cache = &shared.setup.?.fixed,
                .memory = memory,
                .provider = provider,
                .gkr_budget = resources.?.gkr_bytes,
            });
            direct_started.?.ready = early_segment_owner.?.hook();
        } else {
            early_owner = try EarlyCPU.Owner.create(.{
                .allocator = a,
                .image = &image,
                .config = request.value,
                .pcs = pcs,
                .layout = cpu_layout,
                .strict_roster = (try @import("stwo_riscv_cpu_integration").rv64_native_policy.current()).strictRoster(),
                .canonical_rungs = false,
                .caches = caches,
                .setup_cache = &shared.setup.?,
                .fixed_cache = &shared.setup.?.fixed,
                .memory = memory,
                .source = stages.source.?,
                .projection = stages.cpu_projection.?,
                .trace_commit = stages.trace_commit.?,
                .pcs_stage = stages.pcs.?,
                .numerical = stages.numerical.?,
                .composition = stages.resident_composition.?,
                .gkr_budget = resources.?.gkr_bytes,
            });
            direct_started.?.ready = early_owner.?.hook();
        }
    }
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
    // Capture callbacks may still have unpublished device work in flight.
    // Join and retire every speculative owner before its borrowed capture.
    defer if (early_segment_owner) |owner| {
        owner.deinit();
        early_segment_owner = null;
    };
    // Private early source overlays borrow this capture's normalized facts.
    // Destroy or finish transferred workers before that owner on every return.
    defer if (early_owner) |owner| {
        owner.deinit();
        early_owner = null;
    };
    if (early_owner) |owner| try owner.requireReady();
    // This later defer runs before captured.deinit on every downstream error.
    // Direct.run separately cancels before Ordered.deinit on capture failure.
    defer if (prestage) |*p| CpuPrestage.cancel(p);
    if (prestage) |*p| try p.stage.join_prestage.?(p.stage.context);
    const packet_import_ns = timer.read() - import_start;
    const capture_ns = timer.read();
    const capture_breakdown = .{ .image_load_ns = image_load_ns, .program_ns = program_ns, .pre_import_ns = import_start - image_load_ns - program_ns, .import_ns = packet_import_ns };
    b2i.capture_done_at_ns = since(process_start);
    const capture_inputs = CaptureInputs.of(&timer, import_start, capture_ns, &captured);
    const digest_capture = false;
    const captured_values_sha256: ?[64]u8 = if (digest_capture) std.fmt.bytesToHex(@import("capture_digest.zig").digest(image.identity, &captured), .lower) else null;
    b2i.capture = capture_inputs;
    // Early Source callbacks may still borrow immutable ROM columns. Keep this
    // owner until the early producer joins; Program.deinit follows that join.
    if (!early_segments and !program.fixed_retired) try program.releaseFixedWitness();
    const capture_cache_released = recycler.releaseCached();
    // Explicit authenticated service scope; classic-only encodings stay closed.
    try @import("stwo_riscv_cpu_integration").rv64_execution.services.scope.advice(&captured.advice);
    const cpu = try Plan.cpus(a, &captured, cpu_layout);
    defer a.free(cpu);
    const truths = try Plan.truthsWithOptions(a, &captured, Plan.KeccakTruthOptions.fromResources(request.value.execution_profile == .ethereum_services_v3, uniform_throughput, resources), if (resources) |limits| limits.keccak_max_log else 18);
    defer a.free(truths);
    // M5 canon-native (opt-in, producer geometry only): pad every declaration
    // to its canonical class rung. The padded declarations are ordinary
    // admitted geometries; the receiver policy is unchanged.
    // M6 native-format: rv64-m6-native/v2 (strict roster) ALWAYS pads every
    // declaration to exactly its class rung vector (fails closed otherwise).
    const strict_roster = (try @import("stwo_riscv_cpu_integration").rv64_native_policy.current()).strictRoster();
    const canon_flag = false;
    if (strict_roster or canon_flag) {
        const Rungs = @import("stwo_riscv_cpu_integration").rv64_native_rungs;
        const classes = try a.alloc(Plan.CanonClass, cpu.len + truths.len);
        defer a.free(classes);
        try Plan.canonicalCpusMode(&captured, cpu_layout, cpu, Rungs, classes[0..cpu.len], strict_roster);
        try Plan.canonicalTruths(truths, Rungs, classes[cpu.len..]);
        for (classes, 0..) |c, i| std.debug.print("RV64_CANON_CLASS ordinal={d} family={s} rung={d} rungs={d} strict={}\n", .{ i, @tagName(c.family), c.rung, Rungs.R, strict_roster });
    }
    if (capture_only) {
        const digest_start = timer.read();
        const digest = @import("capture_digest.zig").digest(image.identity, &captured);
        return emit(a, .{ .scope = "producer capture diagnostic only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .final_pc = captured.final_pc, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_options = resources.?.capture_options, .capture_selection = captured.capture_schedule, .packet_import_ns = if (direct_capture) @as(u64, 0) else packet_import_ns, .image_and_import_ns = capture_ns, .capture_breakdown = capture_breakdown, .capture_inputs = capture_inputs, .captured_values_sha256 = std.fmt.bytesToHex(digest, .lower), .capture_source = if (direct_capture) @as([]const u8, "in_process_execution") else "packet_directory", .direct_capture = if (direct_capture) direct_stats else null, .diagnostic_digest_ns = timer.read() - digest_start });
    }
    if (plan) return emit(a, .{ .profile = PROFILE, .security_qualified = false, .scope = "geometry advice only; no proof or acceptance", .total_steps = captured.total_steps, .cpu = cpu, .truths = truths, .memory_words = captured.advice.initial.len, .capture_ns = capture_ns });
    const operational = resources.?;
    const resident = blk: {
        stages.requireFullyResident() catch break :blk false;
        break :blk true;
    };
    const worker_limit = if (resident) try residentWorkerLimit(operational.park_main, cpu.len + truths.len, operational.keccak_max_log) else try producerWorkerLimit(operational.park_main, cpu.len + truths.len, operational.keccak_max_log);
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
    if (prestage != null) std.debug.print("GPU_CPU_PRESTAGE event=inventory_plan_ready utc_ns={} process_at_ns={}\n", .{ std.time.nanoTimestamp(), b2i.plan_done_at_ns });
    var setup_cache: ?SetupCache.Cache = null;
    var setup_dir: ?[]u8 = null;
    defer if (setup_dir) |d| a.free(d);
    // A resident session owns one SetupCache for its whole lifetime (warm,
    // persisted, seeded from disk); a one-shot process keeps a local one.
    var session_setup: ?*SetupCache.Cache = null;
    if (candidate and std.process.hasEnvVarConstant(SETUP_CACHE_ENV)) {
        if (session) |shared| {
            if (shared.setup == null) {
                const selected = try setupCacheOptions(shared.allocator, .prover, fixed_setup_bytes);
                defer if (selected.owned) |d| shared.allocator.free(d);
                shared.setup = try SetupCache.Cache.init(shared.allocator, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, selected.options);
                shared.setup_fixed_bytes = fixed_setup_bytes;
            } else if (shared.setup_fixed_bytes != fixed_setup_bytes) return error.ResidentFixedBudgetChanged;
            session_setup = &shared.setup.?;
            if (!early_main and !early_segments) try session_setup.?.bindRequest(request.value);
        } else {
            const selected = try setupCacheOptions(a, .prover, fixed_setup_bytes);
            setup_dir = selected.owned;
            setup_cache = try SetupCache.Cache.init(a, .{ .log_blowup = pcs.fri_config.log_blowup_factor }, selected.options);
            try setup_cache.?.bindRequest(request.value);
        }
    }
    defer if (setup_cache) |*owner| owner.deinit();
    const setup_owner: ?*SetupCache.Cache = if (setup_cache) |*owner| owner else session_setup;
    const producer_keys_start_ns = timer.read();
    var keys = if (setup_owner) |owner| try Keys.initResident(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches, owner) else if (session) |shared| try shared.acquireKeys(&image, program.identity, cpu, truths, Suite.experimentalFold4()) else try Keys.initWithSuiteAndCaches(a, &image, cpu, truths, true, Suite.experimentalFold4(), caches);
    defer keys.deinit();
    const producer_keys_ns = timer.read() - producer_keys_start_ns;
    b2i.keys_done_at_ns = since(process_start);
    const producer_fixed_start_ns = timer.read();
    var local_fixed: ?FixedAuthority.Fixed.Cache = if (candidate and session == null and setup_owner == null) try FixedAuthority.Fixed.Cache.init(a, fixed_setup_bytes) else null;
    defer if (local_fixed) |*owner| owner.deinit();
    const fixed_cache: ?*FixedAuthority.Fixed.Cache = if (!candidate) null else if (setup_owner) |owner| &owner.fixed else if (session) |shared| try shared.fixedAuthority(fixed_setup_bytes) else &local_fixed.?;
    var fixed_set: ?FixedSet = if (fixed_cache) |owner| if (session != null and setup_owner == null) try FixedSet.initWithValidatedCatalogue(a, owner, keys.cpus, keys.truths, pcs, &session.?.validated_fixed) else if (session_setup != null and setup_owner != null and setup_owner.? == session_setup.?) try residentSetupFixedSet(a, owner, &keys, pcs, &session.?.setup_validated) else try FixedSet.init(a, owner, keys.cpus, keys.truths, pcs) else null;
    defer if (fixed_set) |*owner| owner.deinit();
    const producer_fixed_ns = timer.read() - producer_fixed_start_ns;
    b2i.setup_done_at_ns = since(process_start);
    if (warm_setup) {
        if (fixed_set) |*authority| try FixedSet.require(authority, keys.cpus, keys.truths, pcs);
        return emit(a, .{ .scope = "warm-setup-candidate: resident setup pre-warm only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .cpu_proofs = keys.cpus.len, .truth_proofs = keys.truths.len, .keys_ns = producer_keys_ns, .fixed_ns = producer_fixed_ns, .setup_cache = if (setup_owner) |owner| owner.stats else null });
    }
    const expected = P.Expected{ .admission = Driver.admission(&image), .program_identity = program.identity, .total_steps = captured.total_steps, .max_total_steps = request.value.max_steps, .final_pc = captured.final_pc, .final_registers = captured.final_registers };
    const completed = count == 0;
    if (combined and !completed) return error.CombinedRequiresCompleteExecution;
    if (completed and expected.final_pc != image.terminal_pc) return error.MissingEthereumTerminalPacket;
    if (inputs_only) {
        const timings = try a.alloc(C.WorkerTiming, keys.cpus.len + keys.truths.len);
        defer a.free(timings);
        try C.buildInputsOnly(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, if (fixed_set) |*authority| authority else null, process_start, timings, &b2i.coordinator_admitted_at_ns);
        b2i.setup_cache = if (setup_owner) |owner| owner.stats else null;
        try b2i.finish(a, timings, keys.cpus.len);
        defer a.free(b2i.segments);
        // In-process residency: the setup of a next block with the same rungs
        // in this process (Keys + FixedSet again, all from the resident cache).
        var resident_setup_ns: ?u64 = null;
        var resident_stats: ?SetupCache.Stats = null;
        if (setup_owner) |owner| {
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
        if (setup_owner) |owner| try owner.persist();
        return emit(a, .{ .scope = "producer block_to_inputs diagnostic only; no proof or acceptance", .security_qualified = false, .total_steps = captured.total_steps, .cpu_proofs = keys.cpus.len, .truth_proofs = keys.truths.len, .block_to_inputs = b2i, .resident_next_block_setup_ns = resident_setup_ns, .resident_stats = resident_stats, .setup_cache_after_persist = if (setup_owner) |owner| owner.stats else null, .fixed_setup = if (fixed_cache) |owner| owner.snapshot() else null });
    }
    try std.fs.cwd().makeDir(args[4]);
    // Linux's path-only descriptor cannot be fsync'd. The producer publishes
    // durable bundle entries, so keep an ordinary readable directory handle.
    var dir = try std.fs.cwd().openDir(args[4], .{ .iterate = true });
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
    var gkr_tree_policy = @import("stwo_riscv_cpu_integration").rv64_gkr_child.TreePolicy{};
    // sched M6 streaming handoff (scheduling only; STWO_RV64_RECURSION_STREAM=0
    // restores the M5 sequential handoff): recursion leaves prep as soon as
    // their native proof is final; device recursion waits for nativeDone.
    const Streaming = if (enable_recursion) @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.Streaming else void;
    var early_recursive_dir: ?std.fs.Dir = null;
    defer if (early_recursive_dir) |*d| d.close();
    const streaming: if (enable_recursion) ?*Streaming else ?void = if (comptime enable_recursion) (if (combined and ready != null and Streaming.enabled()) blk: {
        try dir.makeDir("recursion-om31");
        early_recursive_dir = try dir.openDir("recursion-om31", .{});
        break :blk try Streaming.create(a, keys.cpus, keys.truths, expected, pcs, if (fixed_set) |*authority| authority else null, early_recursive_dir.?, ready.?);
    } else null) else null;
    defer if (comptime enable_recursion) if (streaming) |stream| stream.destroy();
    const prove_start = timer.read();
    var bundle = try C.produceWithAuthority(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, .{ .native_stage_two = stages.native_stage_two, .early_segments = early_segment_owner, .early_cpu0 = early_owner, .stream = if (comptime enable_recursion) (if (streaming) |stream| stream.hook() else null) else null, .epoch = process_start, .admitted_at_ns = &b2i.coordinator_admitted_at_ns, .cpu_replay_stage = stages.cpu_replay, .device_source_stage = stages.source, .device_global_stage = stages.global_interaction, .device_trace_commit_stage = stages.trace_commit, .device_cpu_projection = stages.cpu_projection, .device_pcs_stage = device_pcs_stage, .truth_device_pcs_stage = stages.truth_pcs, .truth_device_composition_stage = stages.truth_composition, .truth_device_source_stage = stages.truth_source, .om31_composition_stage = om31_composition_stage, .resident_composition_stage = resident_composition_stage, .numerical_gkr_stage = numerical_gkr_stage, .observed_tree_policy = &gkr_tree_policy, .checkpoint_above_gkr_bytes = operational.checkpoint_above_gkr_bytes, .defer_local_binding = operational.defer_local_binding, .consume_memory_events = true, .max_workers = worker_limit, .max_retained_frontend_bytes = operational.retained_frontend_bytes, .gkr_budget = operational.gkr_bytes, .global_budget = operational.global_bytes, .retained_store = if (store) |*value| value else null, .worker_timings = worker_timings, .native_profiles = if (request.value.profile_stages) observations.pointers else &.{}, .schedule = operational.schedule, .stage2_order = operational.stage2_order, .stage1_trace = observations.stage1_trace, .stage2_trace = observations.stage2_trace }, if (fixed_set) |*authority| authority else null);
    defer bundle.deinit(a);
    // The streaming recursion reads views of this bundle: join it first.
    defer if (comptime enable_recursion) if (streaming) |stream| stream.stop(error.StreamingRecursionCancelled);
    const prove_ns = timer.read() - prove_start;
    // Streaming: the terminal endpoint check (which must precede any accepted
    // root artifact) runs first, then device recursion starts while native
    // verification and publication proceed on the host.
    if (comptime enable_recursion) if (streaming) |stream| {
        const last = bundle.requests[bundle.requests.len - 1].base;
        _ = try @import("terminal.zig").require(&image, last.cpu, last.memory.terminal);
        stream.nativeDone();
    };
    const capture_after_proving = captured.ownership();
    if (request.value.profile_stages) {
        const profiling = @import("stwo_riscv_cpu_integration").rv64_execution.services.profiling.Options{ .recorders = observations.pointers, .directory = dir };
        for (0..observations.pointers.len) |i| try profiling.finish(a, i);
        try Driver.writeJson(a, dir, "schedule.json", .{ .schema_version = 1, .indexing = "array index is original worker ordinal", .time_basis = "nanoseconds from each phase schedule start; stage1/stage2 origins distinct", .stage1 = observations.stage1_trace, .stage2 = observations.stage2_trace });
    }
    // Combined requests overlap the same-process native verify with recursion
    // (scheduling only; joined before report.json/combined-report.json).
    const NativeVerify = @import("native_verify_overlap.zig");
    const overlap_verify = combined and NativeVerify.enabled();
    var side_verify = NativeVerify.Job(@TypeOf(image), @TypeOf(keys), @TypeOf(bundle), FixedSet, @TypeOf(pcs)){ .a = a, .image = &image, .keys = &keys, .bundle = &bundle, .max_steps = request.value.max_steps, .batch_steps = request.value.batch_steps, .completed = completed, .config = pcs, .fixed = if (fixed_set) |*authority| authority else null, .worker_count = NativeVerify.workers(a, pool.workerCount()) };
    // Never leave a running reader of keys/bundle behind on an error path.
    defer _ = side_verify.join() catch {};
    var output: ?[43]u8 = null;
    var verify_ns: u64 = 0;
    if (overlap_verify) {
        try side_verify.start();
    } else {
        const verify_start = timer.read();
        output = try Receiver.verifyWithAuthority(a, &image, &keys, &bundle, request.value.max_steps, request.value.batch_steps, completed, pcs, if (fixed_set) |*authority| authority else null);
        verify_ns = timer.read() - verify_start;
    }
    const publish_start_ns = timer.read();
    try W.write(a, dir, keys.cpus, keys.truths, &bundle);
    b2i.setup_cache = if (setup_owner) |owner| owner.stats else null;
    try b2i.finish(a, worker_timings, keys.cpus.len);
    defer a.free(b2i.segments);
    const native_publish_ns = timer.read() - publish_start_ns;
    const native_report = .{ .captured_values_sha256 = captured_values_sha256, .profile = selected_profile, .security_qualified = false, .security_target = if (candidate) security_target else null, .completed_ethereum_block = completed, .total_steps = captured.total_steps, .cpu_proofs = bundle.cpus.len, .truth_proofs = bundle.truths.len, .output = &output, .keccak_uniform_throughput = uniform_throughput, .one_truth_per_family = one_truth_per_family, .coalesce_truth_families = coalesce_truth_families, .resources = operational, .capture_ns = capture_ns, .capture_breakdown = capture_breakdown, .block_to_inputs = b2i, .packet_import_ns = if (direct_capture) @as(u64, 0) else packet_import_ns, .capture_source = if (direct_capture) @as([]const u8, "in_process_execution") else "packet_directory", .direct_capture = if (direct_capture) direct_stats else null, .capture_selection = captured.capture_schedule, .capture_cache_released_bytes = capture_cache_released, .capture_before_proving = capture_before_proving, .capture_after_proving = capture_after_proving, .gkr_tree_policy = gkr_tree_policy, .setup_ns = setup_ns, .prove_ns = prove_ns, .same_process_verify_ns = &verify_ns, .native_verify_overlapped_with_recursion = overlap_verify, .workers = worker_timings, .total_before_report_ns = timer.read(), .retained_main = if (store) |*value| value.stats() else null };
    if (!overlap_verify) try Driver.writeJson(a, dir, "report.json", native_report);
    if (fixed_cache) |owner| try Driver.writeJson(a, dir, "candidate-fixed-setup.json", .{ .profile = selected_profile, .security_qualified = false, .config = pcs, .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells });
    // A session persists new artifacts between requests, off the request wall.
    if (setup_cache) |*owner| try owner.persist();
    if (source_bounds) |*value| try Driver.writeJson(a, dir, "candidate-source-bounds.json", .{ .profile = selected_profile, .security_qualified = false, .accounting_profile = value.accounting_profile, .shape = value.shape, .cpu_scopes = value.cpu_scopes, .truth_scopes = value.truth_scopes, .global_signed = value.global_signed, .global_denominator_slots = value.global_denominator_slots, .lookup_only_conditional_degrees = value.conditional_degrees, .transcript_round_bound_qualified = value.transcript_round_bound_qualified, .secp_polynomial_error_budget_qualified = value.secp_polynomial_error_budget_qualified });
    try std.posix.fsync(dir.fd);
    if (combined) {
        if (comptime !enable_recursion) return error.RecursionProductRequired;
        // The terminal endpoint is checked before any accepted root artifact.
        const last = bundle.requests[bundle.requests.len - 1].base;
        _ = try @import("terminal.zig").require(&image, last.cpu, last.memory.terminal);
        if (streaming == null) try dir.makeDir("recursion-om31");
        var recursive_dir = try dir.openDir("recursion-om31", .{});
        defer recursive_dir.close();
        const recursion_start_ns = timer.read();
        const Recursive = @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap;
        var recursion = if (streaming) |stream| blk: {
            break :blk try stream.join();
        } else if (ready) |options|
            try Recursive.runWithFactories(a, keys.cpus, keys.truths, &bundle, expected, pcs, if (fixed_set) |*authority| authority else null, recursive_dir, false, options)
        else
            try Recursive.run(a, keys.cpus, keys.truths, &bundle, expected, pcs, if (fixed_set) |*authority| authority else null, recursive_dir, false, recursion_factory);
        var lane_workers: [4]usize = @splat(0);
        var lane_helper_bytes: usize = 0;
        if (ready) |options| {
            for (options.lanes, 0..) |lane, i| {
                lane_workers[i] = lane.pool.workerCount();
                lane_helper_bytes += (lane.pool.workerCount() - 1) * lane.pool.stackSize();
            }
        } else lane_workers[0] = pool.workerCount();
        const recursion_operational = .{
            .mode = if (ready != null) @as([]const u8, "ready_candidate") else "serial",
            .physical_device_ids = recursion_execution.physical_devices,
            .lane_workers = lane_workers[0..if (ready) |options| options.lanes.len else 1],
            .native_helper_stack_reserved_bytes = native_stacks.bytes,
            .lane_helper_stack_reserved_bytes = lane_helper_bytes,
            .coordinator_stack_reserved_bytes = if (ready) |options| options.lanes.len * (8 << 20) else @as(usize, 0),
            .producer_manifest_sha256 = recursion_execution.producer_manifest_sha256,
            .hardware_parallel_qualified = false,
        };
        recursion.native_prove_ns = prove_ns;
        const recursion_ns = timer.read() - recursion_start_ns;
        var native_verify_join_wait_ns: u64 = 0;
        if (overlap_verify) {
            const join_start = timer.read();
            output = try side_verify.join();
            native_verify_join_wait_ns = timer.read() - join_start;
            verify_ns = side_verify.ns;
            // Acceptance artifacts only after the complete native verify.
            try Driver.writeJson(a, dir, "report.json", native_report);
        }
        // execution_wrap already published its report exclusively. Native timing
        // belongs in this combined report; never republish the existing file.
        const fixed_setup_backend: []const u8 = if (try recursion_execution.usesDeviceFixed()) "device_candidate" else "cpu";
        const report = .{ .schema = 1, .accepted = true, .completed_ethereum_block = true, .fixed_setup_backend = fixed_setup_backend, .authority_handoff = "live independently derived keys and fixed authority; direct in-memory bundle", .native_bundle_reload = false, .recursion_execution = recursion_operational, .native_authority_session_used = session != null, .native_authority_classes = if (session) |shared| shared.keyCount() else @as(usize, 0), .restored_recursive_proofs = false, .security_qualified = false, .security_scope = "128-bit target under documented assumptions; no whole-protocol certificate", .profile = selected_profile, .capture_ns = capture_ns, .native_setup_ns = setup_ns, .setup_breakdown = .{ .image_ns = image_load_ns, .program_ns = program_ns, .native_keys_ns = producer_keys_ns, .fixed_authority_ns = producer_fixed_ns }, .native_prove_ns = prove_ns, .native_verify_ns = verify_ns, .native_verify_overlapped_with_recursion = overlap_verify, .native_verify_join_wait_ns = native_verify_join_wait_ns, .native_verify_workers = if (overlap_verify) side_verify.worker_count else pool.workerCount(), .native_publish_ns = native_publish_ns, .recursion_ns = recursion_ns, .recursion_streamed = streaming != null, .recursion_after_native_ns = timer.read() - (prove_start + prove_ns), .combined_ns = timer.read(), .recursive = recursion };
        try Driver.writeJson(a, dir, "combined-report.json", report);
        try std.posix.fsync(dir.fd);
        return emit(a, report);
    }
}
/// Producer block-to-inputs timeline, nanoseconds on this CLI's clock (started
/// after request parse and pool start). Report-only; no protocol effect. On the
/// packet route it excludes the separate `nativeprepare` process.
pub const CaptureInputs = struct {
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
    pub fn of(timer: *const std.time.Timer, init_ns: u64, all_ns: u64, captured: *const Capture) CaptureInputs {
        return .{ .init_ns = init_ns, .first_inputs_ns = sinceTimer(timer, captured.first_inputs_at), .last_inputs_ns = sinceTimer(timer, captured.last_inputs_at), .all_inputs_ns = all_ns, .ledger_ns = captured.timing.ledger_ns, .ledger_finish_ns = captured.timing.finish_ns };
    }
    pub fn sinceTimer(timer: *const std.time.Timer, at: ?std.time.Instant) ?u64 {
        return if (at) |value| value.since(timer.started) else null;
    }
};
pub fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

pub fn isCombinedProducer(mode: []const u8) bool {
    return std.mem.eql(u8, mode, "produce-and-recurse-candidate");
}
