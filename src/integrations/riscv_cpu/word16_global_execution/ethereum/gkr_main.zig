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
pub const EarlyCPU = @import("early_cpu0.zig");
pub const EarlySegments = @import("early_segments.zig");
const CpuPrestage = @import("cpu_prestage.zig").CpuPrestage;
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
pub const Recycler = @import("../../rv64_large_block_recycler.zig").LargeBlockRecycler;
const ReceiverBudget = @import("receiver_budget.zig");
const ReceiverSetup = @import("receiver_setup.zig");
const FixedAuthority = @import("../services/gkr_local/fixed_authority.zig");
const FixedSet = @import("../services/gkr_local/fixed_authority_set.zig").Set;
const Candidate = @import("../../word16_execution/om31_security_candidate.zig");
const SourceBounds = @import("../services/gkr_local/source_bounds.zig");
const CapturePlan = @import("capture_plan.zig");
const SetupCache = @import("setup_cache.zig");
/// Producer-owned trusted setup acceleration; forbidden to fresh receivers.
const SETUP_CACHE_ENV = "STWO_ZIG_RV64_SETUP_CACHE";
/// A/B switch for the identity-only CPU source (default on).
const IDENTITY_ONLY_ENV = "STWO_ZIG_RV64_SETUP_IDENTITY_ONLY_CPU";
fn requireIndependentReceiverSetup(persisted_selected: bool) !void {
    if (persisted_selected) return error.PersistedSetupCacheForbiddenForReceiver;
}
/// M4 resident: the session's SetupCache components are resident and frozen for
/// the session's life, so their fixed-authority bindings are validated once per
/// service and reused (pointer provenance, as for the key-owner catalogue). A
/// failure (for example the fixed cache's byte budget) clears the catalogue and
/// retries once from scratch: the result is the same pure function either way.
fn residentSetupFixedSet(a: std.mem.Allocator, owner: anytype, keys: anytype, pcs: anytype, catalogue: *@import("../services/gkr_local/fixed_authority_set.zig").ValidatedCatalogue) !FixedSet {
    return FixedSet.initWithValidatedCatalogue(a, owner, keys.cpus, keys.truths, pcs, catalogue) catch {
        catalogue.clear();
        return FixedSet.initWithValidatedCatalogue(a, owner, keys.cpus, keys.truths, pcs, catalogue);
    };
}

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
const BlockToInputs = @import("input_timeline.zig").BlockToInputs;
fn since(origin: std.time.Instant) u64 {
    const now = std.time.Instant.now() catch return 0;
    return now.since(origin);
}
const candidateLabel = @import("profile_selection.zig").candidateLabel;
const selectProfile = @import("profile_selection.zig").selectProfile;
const PROFILE = "experimental-om31-local-gkr-q70-p26-fold4";
const producerWorkerLimit = @import("resources.zig").producerWorkerLimit;
const residentWorkerLimit = @import("resources.zig").residentWorkerLimit;
const Resources = @import("resources.zig").Resources;
const CandidateResources = @import("resources.zig").CandidateResources;
fn config() !Worker.PcsConfig {
    var value = Worker.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.ForField(Worker.O).FriConfig.init(0, 1, 70) };
    value.fri_config.fold_step = 4;
    return value;
}
pub fn main() !void {
    return mainWithPcs(null);
}
pub fn mainWithPcs(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage) !void {
    return mainWithStages(device_pcs_stage, null);
}
pub fn mainWithStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("../services/gkr_local/cpu_worker.zig").CompositionStage) !void {
    return mainWithDeviceStages(device_pcs_stage, om31_composition_stage, null);
}
pub fn mainWithDeviceStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("../services/gkr_local/cpu_worker.zig").CompositionStage, numerical_gkr_stage: ?*const @import("../services/gkr_local/child.zig").NumericalStage) !void {
    return mainWithResidentStages(device_pcs_stage, om31_composition_stage, numerical_gkr_stage, null);
}
pub fn mainWithResidentStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("../services/gkr_local/cpu_worker.zig").CompositionStage, numerical_gkr_stage: ?*const @import("../services/gkr_local/child.zig").NumericalStage, resident_composition_stage: ?*const @import("../services/gkr_local/cpu_worker.zig").ResidentCompositionStage) !void {
    return mainWithResidentPipeline(.{ .pcs = device_pcs_stage, .composition = om31_composition_stage, .numerical = numerical_gkr_stage, .resident_composition = resident_composition_stage });
}
pub const ResidentStages = struct {
    early_memory: ?EarlyCPU.MemoryAdmission = null,
    early_segments: ?EarlySegments.StageProvider = null,
    cpu_replay: ?@import("../services/gkr_local/cpu_replay.zig").Stage = null,
    source: ?@import("../services/pipeline.zig").DeviceSourceStage = null,
    truth_source: ?@import("../services/gkr_local/truth_device_source.zig").Stage = null,
    truth_composition: ?@import("../services/gkr_local/truth_device_composition.zig").Stage = null,
    global_interaction: ?@import("../services/gkr_local/cpu_worker.zig").DeviceGlobal.Stage = null,
    pcs: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    truth_pcs: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    composition: ?*const @import("../services/gkr_local/cpu_worker.zig").CompositionStage = null,
    numerical: ?*const @import("../services/gkr_local/child.zig").NumericalStage = null,
    resident_composition: ?*const @import("../services/gkr_local/cpu_worker.zig").ResidentCompositionStage = null,
    trace_commit: ?*const @import("stwo_prover_api").device_pcs.TraceCommitStage = null,
    cpu_projection: ?@import("../../word16_execution/cpu_source.zig").ProjectionStage = null,
    pub fn requireFullyResident(self: ResidentStages) !void {
        if (self.source == null or self.truth_source == null or self.global_interaction == null or self.truth_composition == null or self.resident_composition == null or self.pcs == null or self.truth_pcs == null or self.trace_commit == null or self.cpu_projection == null or self.numerical == null or self.numerical.?.bind == null) return error.FullyResidentPipelineIncomplete;
        if (self.cpu_replay != null and self.numerical.?.replay_binding == null) return error.CpuReplayRequiresResidentProjection;
    }
};
pub const ResidentSession = @import("resident_session.zig").Session;
pub fn mainWithResidentPipeline(stages: ResidentStages) !void {
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const base = recycler.allocator();
    const all_args = try std.process.argsAlloc(base);
    defer std.process.argsFree(base, all_args);
    return runArguments(&recycler, all_args, stages, null, null, false, {}, true);
}
/// CPU native-only product: no recursive proving or policy dependency. Native
/// source admission, proof format and independent receiver remain the same.
pub fn mainNativeOnly() !void {
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const args = try std.process.argsAlloc(recycler.allocator());
    defer std.process.argsFree(recycler.allocator(), args);
    const selection = try selectProfile(args);
    if (selection.args.len >= 2 and std.mem.eql(u8, selection.args[1], "batch-candidate"))
        return @import("native_batch.zig").run(@This(), &recycler, selection.profile, selection.args);
    if (selection.args.len >= 2 and std.mem.eql(u8, selection.args[1], "verify-batch-candidate")) {
        try requireIndependentReceiverSetup(std.process.hasEnvVarConstant(SETUP_CACHE_ENV));
        return @import("receiver_batch.zig").run(@This(), &recycler, selection.profile, selection.args);
    }
    return runArguments(&recycler, args, .{}, null, null, false, {}, false);
}
/// Separate linked product: the resident native executable does not pull the
/// circuit stack into every GPU build merely to expose an unavailable mode.
pub fn mainWithRecursion() !void {
    return mainWithRecursionFactory(null);
}
/// Linked GPU-recursion product supplies one explicitly owned device factory.
pub fn mainWithRecursionFactory(factory: ?@import("stwo_circuit_cpu_integration").om31.device_prove.Factory) !void {
    var recycler = Recycler.init(std.heap.smp_allocator, ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const all_args = try std.process.argsAlloc(recycler.allocator());
    defer std.process.argsFree(recycler.allocator(), all_args);
    return runArguments(&recycler, all_args, .{}, null, null, true, .{ .factory = factory }, true);
}
/// Explicit linked product: production and recursion share independently derived
/// live authorities and the in-memory bundle. No receiver handoff is reloaded.
pub fn mainWithResidentPipelineAndRecursion(stages: ResidentStages, factory: @import("stwo_circuit_cpu_integration").om31.device_prove.Factory, host_bytes: usize) !void {
    try stages.requireFullyResident();
    if (host_bytes == 0) return error.InvalidCombinedHostBudget;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, host_bytes);
    defer budget.destroy();
    var recycler = Recycler.init(budget.allocator(), ReceiverBudget.RECYCLER_CACHE_BYTES);
    defer recycler.deinit();
    const all_args = try std.process.argsAlloc(recycler.allocator());
    defer std.process.argsFree(recycler.allocator(), all_args);
    const selection = try selectProfile(all_args);
    if (selection.args.len < 2 or !isCombinedProducer(selection.args[1])) return error.CombinedProductRequiresCombinedMode;
    // Reuse the existing bounded cache of independently derived native geometry
    // classes. Its 4 GiB allocation budget is a child of the same host budget.
    var session = try ResidentSession.init(recycler.allocator(), 4 << 30);
    defer session.deinit();
    return runCombinedResidentArgs(&recycler, all_args, stages, &session, factory);
}
/// Operational selection only; never enters AIR, proof profile or transcript.
pub const CombinedRecursion = struct {
    factory: ?@import("stwo_circuit_cpu_integration").om31.device_prove.Factory = null,
    ready: ?@import("../../rv64_recursion/om31_native/execution_wrap.zig").ParallelOptions = null,
    physical_devices: []const u32 = &.{},
    producer_manifest_sha256: ?[32]u8 = null,
    /// Derive telemetry from the installed callbacks, never the manifest flag.
    /// Mixed lane policies cannot be reported as one authenticated backend.
    pub fn usesDeviceFixed(self: CombinedRecursion) !bool {
        if (self.ready) |ready| {
            if (ready.lanes.len == 0) return error.InvalidCombinedRecursionSelection;
            const selected = ready.lanes[0].factory.precommit_fixed != null;
            for (ready.lanes) |lane| if ((lane.factory.precommit_fixed != null) != selected)
                return error.MixedCombinedFixedBackends;
            return selected;
        }
        return if (self.factory) |factory| factory.precommit_fixed != null else false;
    }
    pub fn validate(self: CombinedRecursion) !void {
        if (self.ready) |ready| {
            if (self.factory != null or ready.lanes.len != self.physical_devices.len) return error.InvalidCombinedRecursionSelection;
            try @import("../../rv64_recursion/om31_native/execution_wrap.zig").validateLanes(ready);
            for (ready.lanes, self.physical_devices) |lane, device| if (lane.physical_device != device) return error.InvalidCombinedRecursionSelection;
        } else if (self.factory == null or self.physical_devices.len > 1) return error.InvalidCombinedRecursionSelection;
        _ = try self.usesDeviceFixed();
    }
};
/// Persistent combined requests reuse only bounded independently derived setup.
/// Every call still captures, proves and freshly verifies the complete block.
pub fn runCombinedResidentArgs(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: *ResidentSession, factory: @import("stwo_circuit_cpu_integration").om31.device_prove.Factory) !void {
    return runCombinedResidentArgsWithExecution(recycler, all_args, stages, session, .{ .factory = factory });
}
pub fn runCombinedResidentArgsWithExecution(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: *ResidentSession, execution: CombinedRecursion) !void {
    try stages.requireFullyResident();
    const selection = try selectProfile(all_args);
    if (selection.args.len < 2 or !isCombinedProducer(selection.args[1])) return error.CombinedProductRequiresCombinedMode;
    try execution.validate();
    if (session.active) return error.ResidentRequestAlreadyActive;
    session.active = true;
    defer session.active = false;
    return runArguments(recycler, all_args, stages, session, null, true, execution, true);
}
fn isCombinedProducer(mode: []const u8) bool {
    return std.mem.eql(u8, mode, "produce-and-recurse-candidate");
}
/// Same producer authority and CLI contract, with caller-owned persistent caches.
/// The caller keeps one GPU pool/session alive and serializes complete requests.
pub fn runWithResidentArgs(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: *ResidentSession) !void {
    if (session.active) return error.ResidentRequestAlreadyActive;
    session.active = true;
    defer session.active = false;
    return runArguments(recycler, all_args, stages, session, null, false, {}, true);
}
/// CPU-only persistent producer. It has no recursion-policy/module dependency.
pub fn runNativeResidentArgs(recycler: *Recycler, args: []const [:0]u8, session: *ResidentSession) !void {
    if (session.active) return error.ResidentRequestAlreadyActive;
    session.active = true;
    defer session.active = false;
    return runArguments(recycler, args, .{}, session, null, false, {}, false);
}
pub fn runNativeReceiverArgs(recycler: *Recycler, args: []const [:0]u8, session: *ReceiverSetup.Session) !void {
    const selection = try selectProfile(args);
    if (selection.args.len < 2 or !std.mem.eql(u8, selection.args[1], "verify-candidate")) return error.ReceiverSessionRequiresVerifier;
    return runArguments(recycler, args, .{}, null, session, false, {}, false);
}
fn runArguments(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: ?*ResidentSession, receiver_session: ?*ReceiverSetup.Session, comptime enable_recursion: bool, recursion_execution: if (enable_recursion) CombinedRecursion else void, comptime check_recursion_policy: bool) !void {
    const process_start = try std.time.Instant.now();
    // canon-vk M5: outer profile / shape / fold arity env must parse, or the
    // process exits with a clean error before any work (never a panic, P03).
    if (comptime check_recursion_policy) try @import("../../rv64_recursion/om31_native/execution_wrap.zig").checkPolicyEnv();
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
    if (args.len == 2 and std.mem.eql(u8, args[1], "describe-candidate")) return emit(base, .{ .profile = candidateLabel(security_profile), .security_profile = security_profile.name(), .security_qualified = false, .security_target = Candidate.assumptionTarget(security_profile), .pcs = Candidate.configFor(security_profile), .scope = if (security_profile.conjectured()) "native 128-bit CONJECTURED target (ethSTARK-style FRI accounting); no proven bound and no whole-protocol certificate" else "native 128-bit target under documented assumptions; no whole-protocol certificate", .usage = "[--security-profile proven_beta2_q256_p0_fold4|conjectured128_b2_q108_p20_fold4 (default)|d2_native_b4_q54_p20_fold4] produce-candidate CONFIG JOBS OUT PREFIX_COUNT RESOURCE_JSON (requires fixed_setup_bytes; JOBS=- executes in process) | plan-candidate CONFIG JOBS PREFIX_COUNT RESOURCE_JSON (CPU-only source-derived native column cost; no proof or acceptance) | inspect-recursion-schedule CONFIG OUT [ORDINAL] (CPU-only diagnostic; no acceptance,24GiB live/12GiB subset fixed cache) | verify-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] | verify-prefix-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] | verify-recursion-candidate CONFIG OUT FIXED_SETUP_BYTES [RECEIVER_BYTES] (CPU recursion receiver only; existing proofs, no proving fallback)" });
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
    const plan_candidate = std.mem.eql(u8, args[1], "plan-candidate");
    const candidate = plan_candidate or std.mem.eql(u8, args[1], "inputs-candidate") or warm_setup or inspect_schedule or combined or recurse or std.mem.eql(u8, args[1], "produce-candidate") or std.mem.eql(u8, args[1], "verify-candidate") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    const verify = inspect_schedule or recurse or std.mem.eql(u8, args[1], "verify-control") or std.mem.eql(u8, args[1], "verify-candidate");
    // Persisted roots are operator-trusted acceleration, never independent
    // receiver authority. Fresh receivers always derive setup from source.
    if (verify) try requireIndependentReceiverSetup(std.process.hasEnvVarConstant(SETUP_CACHE_ENV));
    const prefix = std.mem.eql(u8, args[1], "verify-prefix-control") or std.mem.eql(u8, args[1], "verify-prefix-candidate");
    if (prefix) try requireIndependentReceiverSetup(std.process.hasEnvVarConstant(SETUP_CACHE_ENV));
    const produce = combined or std.mem.eql(u8, args[1], "produce-control") or std.mem.eql(u8, args[1], "produce-candidate");
    const plan = plan_candidate or std.mem.eql(u8, args[1], "plan");
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
    if (plan and args.len != (if (plan_candidate) @as(usize, 6) else 5)) return error.ExpectedModeConfigJobsPrefixAndOptionalResources;
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
    try @import("../services/gkr_local/service_scope.zig").profile(request.value.execution_profile);
    // Candidate lane pools already exist. This native pool stays idle but
    // alive during recursion, so charge its live helper stacks separately.
    const ready = if (enable_recursion) recursion_execution.ready else null;
    const native_workers = try Request.effectiveWorkers(request.value);
    if (ready) |options| if (options.pool_worker_budget > native_workers) return error.InvalidCombinedRecursionWorkerBudget;
    var native_stacks = engine.host_budget_allocator.SharedHostBudget.ExternalReservation.empty();
    defer native_stacks.deinit();
    if (ready != null) {
        const owner = try @import("../../rv64_recursion_budget.zig").require(engine.host_budget_allocator.SharedHostBudget, base);
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
    if (produce or capture_only or inputs_only or plan_candidate) {
        const limits_bytes = try std.fs.cwd().readFileAlloc(a, args[if (capture_only or inputs_only or plan_candidate) 5 else 6], 16384);
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
    const shared_walk_authority = if (std.posix.getenv("STWO_RV64_CAPTURE_SHARED_AUTHORITY")) |flag| std.mem.eql(u8, flag, "1") else false;
    const early_cpu = if (std.posix.getenv("STWO_RV64_CPU0_PRESTAGE")) |flag| std.mem.eql(u8, flag, "1") else false;
    const early_main = if (std.posix.getenv(EarlyCPU.FLAG)) |flag| std.mem.eql(u8, flag, "1") else false;
    const early_segments = if (std.posix.getenv(EarlySegments.FLAG)) |flag| std.mem.eql(u8, flag, "1") else false;
    // Refuse mixed speculative owners before starting boot/capture/callbacks.
    const old_first = if (std.posix.getenv("STWO_RV64_CPU0_FIRST_PASS_PRESTAGE")) |flag| std.mem.eql(u8, flag, "1") else false;
    if (early_main and (early_cpu or old_first)) return error.ConflictingEarlyCpuModes;
    if (early_segments and (early_cpu or old_first or early_main)) return error.ConflictingEarlyCpuModes;
    if (early_main and (!combined or !candidate or !direct_capture or count != 0 or session == null or stages.early_memory == null or capture_options.execution_workers == 0 or !@import("../../rv64_ethereum_segments.zig").ramFirstPassEnabled())) return error.EarlyMainRequiresAdmittedResidentFirstPass;
    if (early_segments and (!combined or !candidate or !direct_capture or count != 0 or session == null or stages.early_memory == null or stages.early_segments == null or capture_options.execution_workers == 0 or !@import("../../rv64_ethereum_segments.zig").ramFirstPassEnabled())) return error.EarlySegmentsRequireAdmittedResidentFirstPass;
    const early_host_budget = if (early_main or early_segments) try @import("../../rv64_recursion_budget.zig").require(engine.host_budget_allocator.SharedHostBudget, base) else null;

    if (early_cpu and (!direct_capture or !combined or stages.cpu_projection == null)) return error.CpuPrestageRequiresDirectResidentCombined;
    const early_first = if (std.posix.getenv("STWO_RV64_CPU0_FIRST_PASS_PRESTAGE")) |v| std.mem.eql(u8, v, "1") else false;
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
    var image = if (session) |shared| try Image.Owner.initShared(a, request.value, &shared.authorities) else if (receiver_session) |shared| try Image.Owner.initShared(a, request.value, &shared.images) else try Image.Owner.init(a, request.value);
    defer image.deinit();
    const image_load_ns = timer.read();
    if (prestage) |*p| p.image_identity = image.identity;
    var local_native: ?NativeCache.Cache = if (session == null and receiver_session == null) try NativeCache.Cache.init(a, 256 << 20) else null;
    defer if (local_native) |*cache| cache.deinit();
    var local_metadata: ?MetadataCache.Cache = if (session == null and receiver_session == null) try MetadataCache.Cache.init(a, 64 << 20) else null;
    defer if (local_metadata) |*cache| cache.deinit();
    const caches = if (session) |shared| shared.caches() else if (receiver_session) |shared| shared.caches() else @import("../../word16_execution/setup.zig").ImmutableCaches{ .native = &local_native.?, .program = &local_metadata.? };
    const compact_capture_program = if (std.posix.getenv("STWO_RV64_CAPTURE_PROGRAM_VIEW")) |v| !std.mem.eql(u8, v, "0") else true;
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
        const setup = try ReceiverSetup.Owner.create(a, &image, request.value, loaded.cpu_declarations, loaded.truth_declarations, pcs, caches, candidate, fixed_setup_bytes, receiver_session != null or try ReceiverSetup.identityOnly(), receiver_session);
        defer setup.destroy();
        const keys = &setup.keys;
        const fixed_cache = setup.fixedCache();
        const fixed_set = setup.fixedSet();
        const setup_ns = timer.read();
        const setup_breakdown = .{ .image_ns = image_load_ns, .program_ns = program_ns, .native_keys_ns = setup.keys_ns, .fixed_authority_ns = setup.fixed_ns, .other_ns = native_keys_start_ns - image_load_ns - program_ns };
        if (inspect_schedule) {
            if (comptime !enable_recursion) return error.RecursionProductRequired;
            const inspection = try @import("../../rv64_recursion/om31_native/execution_wrap.zig").inspectLeafSchedule(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, fixed_set, inspection_ordinal);
            return emit(a, .{ .schema = "rv64-recursion-schedule-inspection/v1", .diagnostic = true, .accepted = false, .scope = "Selected native leaf capture and original graph schedule census only; no complete-block or recursive-root acceptance", .selected_native_leaf_verified = true, .recursion_proof_generated = false, .gpu_context_created = false, .profile = selected_profile, .security_qualified = false, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .inspection = inspection, .task_kind_order = .{ "add", "sub", "mul", "pointwise_mul", "triple_xor", "m31_to_u32", "blake_g", "permutation", "hint" }, .hint_kind_order = .{ "seed", "inverse", "divide", "pointwise_inverse_or_zero", "pointwise_lsb", "byte", "byte_complement", "is_nonzero", "zero" }, .width_bucket_upper_bounds = @import("../../rv64_recursion/om31_native/schedule_census.zig").bucket_upper_bounds, .receiver_requested_live_cap_bytes = @import("schedule_inspection.zig").live_bytes, .receiver_budget = receiver_budget.?.snapshot(), .fixed_cache_cap_bytes = fixed_setup_bytes, .fixed_cache_is_subset_of_live_cap = true, .recycler_cache_cap_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES, .recycler_cached_bytes_outside_requested_live_cap = true, .requested_live_plus_recycler_cap_bytes = @import("schedule_inspection.zig").live_bytes + ReceiverBudget.RECYCLER_CACHE_BYTES, .budget_scope = "Requested live 24 GiB includes fixed cache 12 GiB and native/metadata caches; up to 4 GiB freed recycler blocks plus worker stacks outside live count; not an RSS cap", .worker_stack_upper_bound_bytes = try ReceiverBudget.stackBytes(native_workers), .operational_workers = native_workers, .device_capacity_values_are_estimates_only = true });
        }
        if (recurse) {
            std.log.info("RECURSION_SETUP image_ns={d} program_ns={d} native_keys_ns={d} fixed_authority_ns={d} other_ns={d}", .{ setup_breakdown.image_ns, setup_breakdown.program_ns, setup_breakdown.native_keys_ns, setup_breakdown.fixed_authority_ns, setup_breakdown.other_ns });
            if (comptime !enable_recursion) return error.RecursionProductRequired;
            if (strict_recursion_verify) {
                // One independent authority construction admits BOTH checks.
                // The existing-only recursion path cannot generate a proof or
                // materialize a host assignment even when a file is missing.
                const native_start_ns = timer.read();
                const output = try Receiver.verifyWithAuthorityAndProgram(a, &image, &program, keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, true, pcs, fixed_set);
                const native_verify_ns = timer.read() - native_start_ns;
                const last = loaded.bundle.requests[loaded.bundle.requests.len - 1].base;
                _ = try @import("terminal.zig").require(&image, last.cpu, last.memory.terminal);
                var recursive_dir = try dir.openDir("recursion-om31", .{});
                defer recursive_dir.close();
                const recursion = try @import("../../rv64_recursion/om31_native/execution_wrap.zig").verifyExisting(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, fixed_set, recursive_dir);
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
            const recursion = try @import("../../rv64_recursion/om31_native/execution_wrap.zig").run(a, keys.cpus, keys.truths, &loaded.bundle, expected, pcs, fixed_set, recursive_dir, resume_recursion, recursion_factory);
            return emit(a, .{ .accepted = true, .completed_ethereum_block = true, .output = output, .native_profile = selected_profile, .outer_profile = @import("stwo_circuit_cpu_integration").om31.protocol.domainName(), .security_qualified = false, .security_scope = "128-bit target under documented assumptions; no whole-protocol certificate", .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .recursive = recursion });
        }
        const output = try Receiver.verifyWithAuthorityAndProgram(a, &image, &program, keys, &loaded.bundle, request.value.max_steps, request.value.batch_steps, verify, pcs, fixed_set);
        if (fixed_cache) |owner| return emit(a, .{ .profile = selected_profile, .security_qualified = false, .security_target = security_target, .security_profile = security_profile.name(), .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .verify_ns = timer.read() - setup_ns, .receiver_session_setup = if (receiver_session) |shared| shared.cache.stats else null, .receiver_session_budget = if (receiver_session) |shared| shared.budget.snapshot() else null, .receiver_source_keys = if (setup.identity_only) @as([]const u8, "identity-only") else "committed", .fixed_setup = owner.snapshot(), .source_validations = fixed_set.?.source_validations, .source_coefficient_cells = fixed_set.?.source_coefficient_cells, .source_accounting_profile = source_bounds.?.accounting_profile, .source_shape = source_bounds.?.shape, .source_lookup_only_conditional_degrees = source_bounds.?.conditional_degrees, .receiver_budget = receiver_budget.?.snapshot(), .receiver_recycler_cache_cap_bytes = ReceiverBudget.RECYCLER_CACHE_BYTES, .receiver_worker_stack_upper_bound_bytes = try ReceiverBudget.stackBytes(try Request.effectiveWorkers(request.value)) });
        return emit(a, .{ .profile = PROFILE, .security_qualified = false, .accepted = true, .completed_ethereum_block = verify, .output = output, .cpu_proofs = loaded.bundle.cpus.len, .truth_proofs = loaded.bundle.truths.len, .load_and_setup_ns = setup_ns, .setup_breakdown = setup_breakdown, .verify_ns = timer.read() - setup_ns });
    }
    var b2i = BlockToInputs{ .scope = if (inputs_only) "inputs-candidate diagnostic: sequential per-worker source build after setup; no proof" else "produce: per-worker source timestamps inside the scheduled prove" };
    b2i.init_done_at_ns = since(process_start);
    var cpu_layout = Plan.CpuLayout.forGkrProfile(request.value.execution_profile);
    cpu_layout.reserve_arithmetic_row = candidate;
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
                .strict_roster = (try @import("../../word16_execution/native_policy.zig").current()).strictRoster(),
                .canonical_rungs = if (std.posix.getenv("STWO_RV64_CANON_RUNGS")) |flag| std.mem.eql(u8, flag, "1") else false,
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
                .strict_roster = (try @import("../../word16_execution/native_policy.zig").current()).strictRoster(),
                .canonical_rungs = if (std.posix.getenv("STWO_RV64_CANON_RUNGS")) |flag| std.mem.eql(u8, flag, "1") else false,
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
    const digest_capture = if (std.posix.getenv("STWO_RV64_CAPTURE_DIGEST")) |flag| std.mem.eql(u8, flag, "1") else false;
    const captured_values_sha256: ?[64]u8 = if (digest_capture) std.fmt.bytesToHex(@import("capture_digest.zig").digest(image.identity, &captured), .lower) else null;
    b2i.capture = capture_inputs;
    // Early Source callbacks may still borrow immutable ROM columns. Keep this
    // owner until the early producer joins; Program.deinit follows that join.
    if (!early_segments and !program.fixed_retired) try program.releaseFixedWitness();
    const capture_cache_released = recycler.releaseCached();
    // Explicit authenticated service scope; classic-only encodings stay closed.
    try @import("../services/gkr_local/service_scope.zig").advice(&captured.advice);
    const cpu = try Plan.cpus(a, &captured, cpu_layout);
    defer a.free(cpu);
    const truths = try Plan.truthsWithOptions(a, &captured, Plan.KeccakTruthOptions.fromResources(request.value.execution_profile == .ethereum_services_v3, uniform_throughput, resources), if (resources) |limits| limits.keccak_max_log else 18);
    defer a.free(truths);
    // M5 canon-native (opt-in, producer geometry only): pad every declaration
    // to its canonical class rung. The padded declarations are ordinary
    // admitted geometries; the receiver policy is unchanged.
    // M6 native-format: rv64-m6-native/v2 (strict roster) ALWAYS pads every
    // declaration to exactly its class rung vector (fails closed otherwise).
    const strict_roster = (try @import("../../word16_execution/native_policy.zig").current()).strictRoster();
    const canon_flag = if (std.posix.getenv("STWO_RV64_CANON_RUNGS")) |flag| std.mem.eql(u8, flag, "1") else false;
    if (strict_roster or canon_flag) {
        const Rungs = @import("canon_native_rungs.zig");
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
    if (plan_candidate) return emit(a, try CapturePlan.result(a, selected_profile, program.log_size, cpu, truths, &captured, count, capture_ns));
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
        source_bounds = try CapturePlan.sourceBounds(a, program.log_size, cpu, truths, &captured);
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
    var gkr_tree_policy = @import("../services/gkr_local/child.zig").TreePolicy{};
    // sched M6 streaming handoff (scheduling only; STWO_RV64_RECURSION_STREAM=0
    // restores the M5 sequential handoff): recursion leaves prep as soon as
    // their native proof is final; device recursion waits for nativeDone.
    const Streaming = if (enable_recursion) @import("../../rv64_recursion/om31_native/execution_wrap.zig").Streaming else void;
    var early_recursive_dir: ?std.fs.Dir = null;
    defer if (early_recursive_dir) |*d| d.close();
    const streaming: if (enable_recursion) ?*Streaming else ?void = if (comptime enable_recursion) (if (combined and ready != null and Streaming.enabled()) blk: {
        try dir.makeDir("recursion-om31");
        early_recursive_dir = try dir.openDir("recursion-om31", .{});
        break :blk try Streaming.create(a, keys.cpus, keys.truths, expected, pcs, if (fixed_set) |*authority| authority else null, early_recursive_dir.?, ready.?);
    } else null) else null;
    defer if (comptime enable_recursion) if (streaming) |stream| stream.destroy();
    const prove_start = timer.read();
    var bundle = try C.produceWithAuthority(a, keys.cpus, keys.truths, captured.native.items, &captured.advice, expected, pcs, .{ .early_segments = early_segment_owner, .early_cpu0 = early_owner, .stream = if (comptime enable_recursion) (if (streaming) |stream| stream.hook() else null) else null, .epoch = process_start, .admitted_at_ns = &b2i.coordinator_admitted_at_ns, .cpu_replay_stage = stages.cpu_replay, .device_source_stage = stages.source, .device_global_stage = stages.global_interaction, .device_trace_commit_stage = stages.trace_commit, .device_cpu_projection = stages.cpu_projection, .device_pcs_stage = device_pcs_stage, .truth_device_pcs_stage = stages.truth_pcs, .truth_device_composition_stage = stages.truth_composition, .truth_device_source_stage = stages.truth_source, .om31_composition_stage = om31_composition_stage, .resident_composition_stage = resident_composition_stage, .numerical_gkr_stage = numerical_gkr_stage, .observed_tree_policy = &gkr_tree_policy, .checkpoint_above_gkr_bytes = operational.checkpoint_above_gkr_bytes, .defer_local_binding = operational.defer_local_binding, .consume_memory_events = true, .max_workers = worker_limit, .max_retained_frontend_bytes = operational.retained_frontend_bytes, .gkr_budget = operational.gkr_bytes, .global_budget = operational.global_bytes, .retained_store = if (store) |*value| value else null, .worker_timings = worker_timings, .native_profiles = if (request.value.profile_stages) observations.pointers else &.{}, .schedule = operational.schedule, .stage2_order = operational.stage2_order, .stage1_trace = observations.stage1_trace, .stage2_trace = observations.stage2_trace }, if (fixed_set) |*authority| authority else null);
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
        const profiling = @import("../services/profiling.zig").Options{ .recorders = observations.pointers, .directory = dir };
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
        const Recursive = @import("../../rv64_recursion/om31_native/execution_wrap.zig");
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
const CaptureInputs = @import("input_timeline.zig").CaptureInputs;
fn emit(a: std.mem.Allocator, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(a, value, .{ .whitespace = .indent_2 });
    defer a.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}

test "combined mode is explicit and cannot be confused with native or cache modes" {
    try std.testing.expect(isCombinedProducer("produce-and-recurse-candidate"));
    for ([_][]const u8{ "produce-candidate", "produce-control", "recurse-candidate", "resume-recursion-candidate", "verify-candidate" }) |mode| try std.testing.expect(!isCombinedProducer(mode));
}

test "fresh receiver never admits persisted producer setup roots" {
    try requireIndependentReceiverSetup(false);
    try std.testing.expectError(error.PersistedSetupCacheForbiddenForReceiver, requireIndependentReceiverSetup(true));
}

test {
    _ = @import("resources.zig");
    _ = @import("native_batch.zig");
}

test {
    _ = @import("receiver_batch.zig");
}
