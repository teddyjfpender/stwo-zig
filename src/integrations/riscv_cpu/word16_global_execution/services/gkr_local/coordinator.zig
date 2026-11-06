//! Bounded two-stage producer for the explicitly selected OM services profile.
//! Large inventories require explicit parking and retained/disk/task admission.
//! Those partial bounds exclude setup/capture/PCS scratch; they are not total RSS.
//! Schedule policy is operational; the manifest barrier is not.
const std = @import("std");
const FixedSet = @import("fixed_authority_set.zig").Set;
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const P = @import("../protocol.zig");
const R = @import("../roster.zig");
const Pipeline = @import("../pipeline.zig");
const Advice = @import("../collector.zig").Advice;
const Schedule = @import("../schedule.zig");
const Native = @import("../../../word16_execution/prepared.zig").Prepared;
const CPU = @import("cpu_worker.zig");
const Truth = @import("truth_worker.zig");
const W = @import("worker_protocol.zig");
const Manifest = @import("manifest.zig");
const ManifestWire = @import("manifest_wire.zig");
const Execution = @import("execution.zig");
const Retention = @import("retention_plan.zig");
const TruthRetention = @import("truth_retention.zig");
pub const Store = @import("../../retained_main_store.zig").Store;
pub const WorkerTiming = struct {
    retained_local_binding_bytes: usize = 0,
    retained_local_projection_bytes: usize = 0,
    final_local_binding_bytes: usize = 0,
    deferred_binding_overlap_bytes: usize = 0,
    gkr_peak_including_final_binding_bytes: usize = 0,
    local_binding_completed: bool = false,
    resolved_tree_policy: ?@import("child.zig").TreePolicy = null,
    source_ns: u64 = 0,
    /// Observation only: nanoseconds since `Options.epoch` when this worker's
    /// witness source build began / its prover inputs were ready. Zero without
    /// an epoch. Never proof or schedule authority.
    source_begin_ns: u64 = 0,
    source_ready_ns: u64 = 0,
    seal_native_and_gkr_ns: u64 = 0,
    main_commit_ns: u64 = 0,
    early_source_and_main_ns: u64 = 0,
    early_main_commit_before_inventory: bool = false,
    gkr_ns: u64 = 0,
    inputs_ns: u64 = 0,
    numerical_ns: u64 = 0,
    binding_ns: u64 = 0,
    numerical_requested_peak_bytes: usize = 0,
    including_binding_requested_peak_bytes: usize = 0,
    admitted_gkr_peak_bytes: usize = 0,
    gkr_allocator_limit_bytes: usize = 0,
    metadata_retire_ns: u64 = 0,
    spill_ns: u64 = 0,
    restore_ns: u64 = 0,
    native_complete_ns: u64 = 0,
    stage1_ns: u64 = 0,
    stage2_ns: u64 = 0,
    actual_main_merkle_bytes: usize = 0,
    retired_memory_event_bytes: usize = 0,
    memory_event_retire_ns: u64 = 0,
    stage1_completed: bool = false,
    stage2_completed: bool = false,
    completed_worker_retired: bool = false,
};
/// Producer scheduling hook (sched M6 streaming handoff; default null = M5).
/// No proof, manifest or identity byte depends on it. `sealed` runs once on
/// the produce caller thread after the stage-one barrier; `cpu_done` /
/// `truth_done` run on the stage-two worker thread right after that
/// ordinal's encoded result is final (its address is valid only for the call;
/// the heap it references is moved into the returned Bundle). `abort` runs on
/// every error return after `sealed`, before requests or results are freed,
/// and returns only when the consumer no longer reads any of them.
pub const Stream = struct {
    context: *anyopaque,
    sealed: *const fn (context: *anyopaque, requests: []const P.Request, stage_one_bytes: []const u8) void,
    cpu_done: *const fn (context: *anyopaque, ordinal: usize, encoded: *const CPU.CpuEncoded) void,
    truth_done: *const fn (context: *anyopaque, ordinal: usize, encoded: *const Truth.TruthEncoded) void,
    abort: *const fn (context: *anyopaque) void,
};
pub const Options = struct {
    early_cpu0: ?*@import("../../ethereum/early_cpu0.zig").Owner = null,
    early_segments: ?*@import("../../ethereum/early_segments.zig").Owner = null,
    stream: ?Stream = null,
    cpu_replay_stage: ?@import("cpu_replay.zig").Stage = null,
    device_source_stage: ?Pipeline.DeviceSourceStage = null,
    device_global_stage: ?CPU.DeviceGlobal.Stage = null,
    device_cpu_projection: ?@import("../../../word16_execution/cpu_source.zig").ProjectionStage = null,
    device_trace_commit_stage: ?*const @import("stwo_prover_api").device_pcs.TraceCommitStage = null,
    numerical_gkr_stage: ?*const @import("child.zig").NumericalStage = null,
    device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    /// Explicit opt-in until each truth geometry has real memory qualification.
    truth_device_source_stage: ?@import("truth_device_source.zig").Stage = null,
    truth_device_composition_stage: ?@import("truth_device_composition.zig").Stage = null,
    truth_device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    om31_composition_stage: ?*const CPU.CompositionStage = null,
    resident_composition_stage: ?*const CPU.ResidentCompositionStage = null,
    /// Caller-owned BASE policy observation; per-CPU resolution is in worker timings.
    observed_tree_policy: ?*@import("child.zig").TreePolicy = null,
    max_workers: usize = 8,
    /// Strict source80 planned-peak threshold; zero disables hybrid selection.
    checkpoint_above_gkr_bytes: usize = 0,
    defer_local_binding: bool = false,
    /// Destructive opt-in for an exclusively owned Advice inventory. Successful
    /// CPU stage one has joined MAIN/local proofs and copied global LS caches;
    /// its original ordinary-memory events can then be retired. A later error
    /// leaves those slots empty. Failed/unstarted ordinals remain caller-owned.
    consume_memory_events: bool = false,
    /// Frontend MAIN/backing+binding admission, excluding independently owned setup
    /// and proof-engine scratch. This is not a total-RSS or device-memory claim.
    max_retained_frontend_bytes: usize = 512 << 20,
    gkr_budget: usize = 512 << 20,
    global_budget: usize = 1 << 30,
    retained_store: ?*Store = null,
    worker_timings: ?[]WorkerTiming = null,
    native_profiles: []const ?*@import("stwo_prover_api").stage_profile.Recorder = &.{},
    /// Operational execution order only; manifests and result slots keep original ordinals.
    stage2_order: []const usize = &.{},
    stage1_trace: []Schedule.Trace = &.{},
    stage2_trace: []Schedule.Trace = &.{},
    schedule: Schedule.Policy = .{ .lanes = 1, .workers_per_lane = 2 },
    /// Observation only (block_to_inputs report): a caller clock origin for
    /// per-worker source timestamps, and where to record the instant the
    /// coordinator finished admission (requests, inventory, estimates).
    epoch: ?std.time.Instant = null,
    admitted_at_ns: ?*u64 = null,
    pub fn validate(self: Options, count: usize) !void {
        if (self.cpu_replay_stage != null and (!self.defer_local_binding or self.device_source_stage == null or self.device_trace_commit_stage == null or self.numerical_gkr_stage == null or self.numerical_gkr_stage.?.replay_binding == null or self.retained_store != null)) return error.InvalidCpuReplayAdmission;
        if (self.truth_device_source_stage != null and (self.truth_device_pcs_stage == null or self.truth_device_composition_stage == null)) return error.DeviceTruthRequiresResidentStages;
        if (self.device_global_stage != null and self.device_trace_commit_stage == null) return error.ResidentGlobalRequiresDeviceTrace;
        if (self.device_source_stage != null and self.device_trace_commit_stage == null) return error.DeviceSourceRequiresDeviceTraceCommit;
        if (self.device_cpu_projection != null and self.device_trace_commit_stage == null) return error.DeviceProjectionRequiresDeviceTraceCommit;
        if (self.device_trace_commit_stage != null and (self.device_pcs_stage == null or self.numerical_gkr_stage == null or self.resident_composition_stage == null)) return error.DeviceTraceRequiresResidentStages;
        if (self.max_workers == 0 or self.max_workers > Manifest.MAX_WORKERS or count > self.max_workers or self.max_retained_frontend_bytes == 0 or self.gkr_budget == 0 or self.global_budget == 0) return error.BoundedWideCoordinatorLimit;
        if (self.worker_timings) |timings| if (timings.len != count) return error.InvalidWideCoordinatorTimings;
        if (self.native_profiles.len != 0 and self.native_profiles.len != count) return error.InvalidWideNativeProfiles;
        try self.schedule.validate();
        try Schedule.validateOrder(self.stage2_order, count);
        if ((self.stage1_trace.len != 0 and self.stage1_trace.len != count) or (self.stage2_trace.len != 0 and self.stage2_trace.len != count)) return error.InvalidWideScheduleTrace;
        if (self.retained_store) |store| {
            if (!store.stats().parking_enabled or self.schedule.memory_cap_bytes == 0) return error.WideCoordinatorRequiresParkingAdmission;
        } else if (self.max_workers > 8) {
            // The old bound protected retained host-wide witnesses. A complete
            // device route uses independently admitted device leases instead;
            // never lift it for partial offload or a producer-controlled flag.
            if (self.device_source_stage == null or self.device_global_stage == null or self.device_cpu_projection == null or self.device_trace_commit_stage == null or self.numerical_gkr_stage == null or self.numerical_gkr_stage.?.bind == null or self.device_pcs_stage == null or self.truth_device_source_stage == null or self.truth_device_composition_stage == null or self.truth_device_pcs_stage == null or self.resident_composition_stage == null) return error.BoundedWideCoordinatorLimit;
        }
    }
};
pub const Bundle = struct {
    requests: []P.Request,
    stage_one_bytes: []u8,
    cpus: []CPU.CpuEncoded,
    truths: []Truth.TruthEncoded,
    pub fn deinit(self: *Bundle, a: std.mem.Allocator) void {
        for (self.cpus) |*v| v.deinit(a);
        for (self.truths) |*v| v.deinit(a);
        a.free(self.cpus);
        a.free(self.truths);
        a.free(self.stage_one_bytes);
        freeRequests(a, self.requests);
        self.* = undefined;
    }
    pub fn verify(self: *const Bundle, a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig) !Execution.Verified {
        return Execution.verify(a, setups, truths, self.requests, expected, config, self.stage_one_bytes, self.cpus, self.truths);
    }
    pub fn verifyWithAuthority(self: *const Bundle, a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, expected: P.Expected, config: W.PcsConfig, fixed: *const FixedSet) !Execution.Verified {
        return Execution.verifyWithAuthority(a, setups, truths, self.requests, expected, config, self.stage_one_bytes, self.cpus, self.truths, fixed);
    }
};
fn freeRequests(a: std.mem.Allocator, requests: []P.Request) void {
    for (requests) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    }
    a.free(requests);
}
/// Borrowed request metadata for pre-key admission. Public cell arrays remain
/// owned by advice; callers must not pass these views to freeRequests.
pub fn requestView(native: []const *Native, advice: *const Advice, i: usize) !P.Request {
    if (i >= native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len or native.len != advice.sha256.len or native.len != advice.arith256_mod.len or native.len != advice.curves.len or native.len != advice.bulk.len or native.len != advice.sponge.len) return error.InvalidCombinedInventory;
    const n = native[i];
    const cpu = n.cpu orelse return error.PreparedExecutionConsumed;
    return .{ .calls = Pipeline.adviceCalls(advice, i), .bulk = advice.bulk[i].counts(), .sponge = advice.sponge[i].counts(), .base = .{ .cpu = cpu.public, .epoch = cpu.epoch, .division_requests = @intCast(n.division.len), .multiplication_requests = @intCast(n.multiplication.len), .memory = .{ .initial = if (i == 0) advice.initial else &.{}, .terminal = if (i + 1 == native.len) advice.terminal else &.{}, .epoch = cpu.epoch, .ls_count = @intCast(advice.events[i].len) } } };
}
fn requestsFrom(a: std.mem.Allocator, setups: []const *const R.CpuSetup, native: []const *Native, advice: *const Advice) ![]P.Request {
    const requests = try a.alloc(P.Request, native.len);
    errdefer a.free(requests);
    var done: usize = 0;
    errdefer for (requests[0..done]) |r| {
        a.free(r.base.memory.initial);
        a.free(r.base.memory.terminal);
    };
    for (requests, 0..) |*r, i| {
        var request = try requestView(native, advice, i);
        try routeDword(&request, setups[i].bridges, advice.events[i]);
        const initial = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.initial);
        errdefer a.free(initial);
        const terminal = try a.dupe(A.memory.closed_ram.types.Cell, request.base.memory.terminal);
        request.base.memory.initial = initial;
        request.base.memory.terminal = terminal;
        r.* = request;
        done += 1;
        // Faithful counts first (requestView), then fail closed on any v3 advice.
        try @import("service_scope.zig").request(r.*);
    }
    try assignSpongeIds(requests);
    return requests;
}

const Worker = union(enum) {
    cpu: CPU.CpuWorker,
    truth: Truth.TruthWorker,
    delegation: @import("truth_v3_worker.zig").NativeTruthWorker,
    fn deinit(self: *Worker, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};
const Result = union(enum) {
    cpu: CPU.CpuEncoded,
    truth: Truth.TruthEncoded,
    fn deinit(self: *Result, a: std.mem.Allocator) void {
        switch (self.*) {
            inline else => |*v| v.deinit(a),
        }
    }
};
const Run = struct {
    a: std.mem.Allocator,
    setups: []const *const R.CpuSetup,
    truths: []const R.Truth,
    native: []const *Native,
    advice: *const Advice,
    requests: []const P.Request,
    inventory: *const Execution.Inventory,
    inventory_admitted_utc_ns: u64,
    fixed: ?*const FixedSet,
    config: W.PcsConfig,
    options: Options,
    workers: []?Worker,
    stages: []Manifest.StageOne,
    results: []?Result,
    pending: ?*const Manifest.PendingManifest = null,
    cpu_tree_policies: []const @import("child.zig").TreePolicy,
    failure_logged: std.atomic.Value(bool) = .init(false),
    fn logFailure(self: *Run, phase: []const u8, index: usize, err: anyerror) void {
        // Preserve the first observed error before coordinator/budget teardown.
        // A poisoned peer can unwind before the failing owner does, so keep
        // later non-poison errors too; first-observed is not causal authority.
        const first = !self.failure_logged.swap(true, .monotonic);
        if (first or err != error.PhysicalAdmissionPoisoned) std.debug.print("NATIVE_COORDINATOR worker_error first_observed={} stage={s} ordinal={} kind={s} error={s} utc_ns={}\n", .{ first, phase, index, if (index < self.setups.len) "cpu" else "truth", @errorName(err), std.time.nanoTimestamp() });
    }
    fn stageOne(self: *Run, index: usize) !void {
        errdefer |err| self.logFailure("stage_one", index, err);
        const timing = if (self.options.worker_timings) |values| &values[index] else null;
        var timer: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        var total_timer = timer;
        defer if (total_timer) |*clock| {
            timing.?.stage1_ns = clock.read();
        };
        if (timing) |t| t.source_begin_ns = sinceEpoch(self.options.epoch);
        if (index < self.setups.len) {
            if (self.options.early_segments) |early| {
                self.workers[index] = .{ .cpu = try early.take(index, self.setups[index], self.requests[index], self.inventory.workers[index], self.config, self.inventory.first_ids[index]) };
                const slot = &early.slots[index];
                if (timing) |value| {
                    value.source_ns = slot.source_end_utc_ns - slot.source_begin_utc_ns;
                    value.early_source_and_main_ns = self.workers[index].?.cpu.main_commit_end_utc_ns - slot.source_begin_utc_ns;
                    value.early_main_commit_before_inventory = self.workers[index].?.cpu.main_commit_end_utc_ns <= self.inventory_admitted_utc_ns;
                }
                if (timer) |*clock| _ = clock.lap();
            } else if (index == 0 and self.options.early_cpu0 != null) {
                const early = self.options.early_cpu0.?;
                self.workers[index] = .{ .cpu = try early.take(self.setups[index], self.requests[index], self.inventory.workers[index], self.config, self.inventory.first_ids[index]) };
                if (timing) |value| {
                    value.source_ns = early.source_end_utc_ns - early.source_begin_utc_ns;
                    value.early_source_and_main_ns = self.workers[index].?.cpu.main_commit_end_utc_ns - early.source_begin_utc_ns;
                    value.early_main_commit_before_inventory = true;
                }
                if (timer) |*clock| _ = clock.lap();
            } else {
                var replay: ?@import("cpu_replay.zig").Owner = if (self.options.cpu_replay_stage) |stage| try stage.prepare(stage.context, self.a, .{ .setup = self.setups[index], .request = self.requests[index], .native = self.native[index], .advice = self.advice, .ordinal = index, .first_ids = self.inventory.first_ids[index], .scope = .{ .statement = self.inventory.workers[index].statement, .fixed = self.inventory.workers[index].fixed, .main = @splat(0), .ordinal = @intCast(index) } }) else null;
                errdefer if (replay) |*owner| owner.deinit();
                self.native[index].device_cpu_projection = self.options.device_cpu_projection;
                self.native[index].device_cpu_scope = if (self.options.device_cpu_projection != null) .{ .statement = self.inventory.workers[index].statement, .fixed = self.inventory.workers[index].fixed, .main = @splat(0), .ordinal = @intCast(self.inventory.workers[index].ordinal) } else null;
                var source = blk: {
                    // Observation only (lane rusage); never proof authority.
                    var scope = try @import("stwo_prover_api").stage_profile.StageScope.begin(if (self.options.native_profiles.len == 0) null else self.options.native_profiles[index], "source_construction", "CPU witness source from native capture");
                    defer scope.end();
                    if (self.options.device_source_stage) |stage| break :blk try stage.invoke(self.a, .{ .admission_replay_required = if (replay) |owner| owner.retained_host_bytes != 0 else false, .pcs_config = self.config, .setup = self.setups[index], .request = self.requests[index], .native = self.native[index], .advice = self.advice, .ordinal = index, .first_ids = self.inventory.first_ids[index], .scope = .{ .statement = self.inventory.workers[index].statement, .fixed = self.inventory.workers[index].fixed, .main = @splat(0), .ordinal = @intCast(index) } });
                    break :blk try Pipeline.buildCpuSource(self.a, self.setups[index], self.requests[index], self.native[index], self.advice, index, self.inventory.first_ids[index], false, null);
                };
                if (timer) |*clock| timing.?.source_ns = clock.lap();
                if (timing) |t| t.source_ready_ns = sinceEpoch(self.options.epoch);
                var owned = true;
                errdefer if (owned) source.deinit();
                const worker = try CPU.CpuWorker.initWithAuthority(self.a, self.setups[index], self.requests[index], source, self.inventory.workers[index], self.config, self.inventory.first_ids[index], self.options.gkr_budget, if (self.fixed) |authority| authority.at(index) else null);
                owned = false;
                self.workers[index] = .{ .cpu = worker };
                self.workers[index].?.cpu.replay = replay;
                replay = null;
            }
            self.workers[index].?.cpu.device_trace_commit_stage = if (self.options.device_trace_commit_stage) |stage| stage.* else null;
            self.workers[index].?.cpu.device_global_stage = self.options.device_global_stage;
            self.workers[index].?.cpu.tree_policy = self.cpu_tree_policies[index];
            self.workers[index].?.cpu.defer_local_binding = self.options.defer_local_binding;
            self.workers[index].?.cpu.scheme.device_om31_pcs_stage = self.options.device_pcs_stage;
            self.workers[index].?.cpu.numerical_gkr_stage = if (self.options.numerical_gkr_stage) |stage| stage.* else null;
            self.workers[index].?.cpu.om31_composition_stage = if (self.options.om31_composition_stage) |stage| stage.* else null;
            self.workers[index].?.cpu.resident_composition_stage = if (self.options.resident_composition_stage) |stage| stage.* else null;
            self.workers[index].?.cpu.native_recorder = if (self.options.native_profiles.len == 0) null else self.options.native_profiles[index];
            var cpu_timing = CPU.SealTiming{};
            self.workers[index].?.cpu.seal_timing = if (timing != null) &cpu_timing else null;
            defer self.workers[index].?.cpu.seal_timing = null;
            self.stages[index] = try self.workers[index].?.cpu.seal(self.a);
            if (timer) |*clock| {
                timing.?.seal_native_and_gkr_ns = clock.lap();
                timing.?.main_commit_ns = cpu_timing.main_commit_ns;
                timing.?.gkr_ns = cpu_timing.gkr_ns;
                timing.?.retained_local_binding_bytes = self.workers[index].?.cpu.child.?.binding_reserved_bytes;
                const child = self.workers[index].?.cpu.child.?;
                timing.?.retained_local_projection_bytes = if (child.projection_pending) child.binding_reserved_bytes else 0;
                timing.?.final_local_binding_bytes = try std.math.add(usize, child.plan.binding_bytes, try std.math.mul(usize, self.workers[index].?.cpu.instances.len, @sizeOf([]core.fields.m31.M31)));
                timing.?.deferred_binding_overlap_bytes = if (child.projection_pending) try std.math.add(usize, child.binding_reserved_bytes, timing.?.final_local_binding_bytes) else 0;
                timing.?.inputs_ns = cpu_timing.inputs_ns;
                timing.?.numerical_ns = cpu_timing.numerical_ns;
                timing.?.binding_ns = cpu_timing.binding_ns;
                timing.?.numerical_requested_peak_bytes = cpu_timing.numerical_requested_peak_bytes;
                timing.?.including_binding_requested_peak_bytes = cpu_timing.including_binding_requested_peak_bytes;
                timing.?.admitted_gkr_peak_bytes = cpu_timing.admitted_gkr_peak_bytes;
                timing.?.gkr_allocator_limit_bytes = cpu_timing.gkr_allocator_limit_bytes;

                timing.?.actual_main_merkle_bytes = try mainNodes(&self.workers[index].?.cpu.scheme);
            }
            try self.workers[index].?.cpu.retireLocalMetadata();
            if (self.workers[index].?.cpu.replay) |*owner| try owner.park(owner.context, &self.workers[index].?.cpu);
            if (timer) |*clock| timing.?.metadata_retire_ns = clock.lap();
            if (self.options.retained_store) |store| _ = try self.workers[index].?.cpu.spillMain(store);
        } else {
            const truth = self.truths[index - self.setups.len];
            if (self.options.truth_device_source_stage) |stage| {
                var owner = try stage.prepare(stage.context, self.a, .{ .truth = truth, .advice = self.advice, .expected = self.inventory.workers[index], .config = self.config, .budget = self.options.global_budget });
                var owned = true;
                errdefer if (owned) owner.deinit();
                if (timer) |*clock| timing.?.source_ns = clock.lap();
                if (timing) |t| t.source_ready_ns = sinceEpoch(self.options.epoch);
                if (Execution.extendedTruth(truth)) {
                    self.workers[index] = .{ .delegation = try @import("truth_v3_worker.zig").NativeTruthWorker.initDeviceWithAuthority(self.a, truth, owner, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                } else {
                    self.workers[index] = .{ .truth = try Truth.TruthWorker.initDeviceWithAuthority(self.a, truth, owner, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                }
                owned = false;
            } else {
                var source = try R.TruthSource.init(self.a, truth, self.advice);
                if (timer) |*clock| timing.?.source_ns = clock.lap();
                if (timing) |t| t.source_ready_ns = sinceEpoch(self.options.epoch);
                var owned = true;
                errdefer if (owned) source.deinit();
                if (Execution.extendedTruth(truth)) {
                    self.workers[index] = .{ .delegation = try @import("truth_v3_worker.zig").NativeTruthWorker.initWithAuthority(self.a, truth, source, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                } else {
                    self.workers[index] = .{ .truth = try Truth.TruthWorker.initWithAuthority(self.a, truth, source, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                }
                owned = false;
            }
            switch (self.workers[index].?) {
                inline .truth, .delegation => |*worker| {
                    worker.scheme.device_om31_pcs_stage = self.options.truth_device_pcs_stage;
                    worker.device_composition_stage = self.options.truth_device_composition_stage;
                    worker.native_recorder = if (self.options.native_profiles.len == 0) null else self.options.native_profiles[index];
                    self.stages[index] = try worker.seal(self.a);
                    if (timer) |*clock| {
                        timing.?.seal_native_and_gkr_ns = clock.lap();
                        timing.?.main_commit_ns = timing.?.seal_native_and_gkr_ns;
                        timing.?.actual_main_merkle_bytes = try mainNodes(&worker.scheme);
                    }
                    if (self.options.retained_store) |store| _ = try worker.spillMain(store);
                },
                else => unreachable,
            }
        }
        if (timer) |*clock| timing.?.spill_ns = clock.lap();
        if (index < self.setups.len and self.options.consume_memory_events and self.workers[index].?.cpu.replay == null) {
            const retired = try self.advice.retireEvents(index);
            if (timing) |value| value.retired_memory_event_bytes = retired;
            if (timer) |*clock| timing.?.memory_event_retire_ns = clock.lap();
        }
        if (timing) |value| value.stage1_completed = true;
    }
    fn stageTwo(self: *Run, index: usize) !void {
        errdefer |err| self.logFailure("stage_two", index, err);
        const timing = if (self.options.worker_timings) |values| &values[index] else null;
        var timer: ?std.time.Timer = if (timing != null) try std.time.Timer.start() else null;
        var total_timer = timer;
        defer if (total_timer) |*clock| {
            timing.?.stage2_ns = clock.read();
        };
        const worker = if (self.workers[index]) |*v| v else return error.MissingWideCoordinatorWorker;
        const pending = self.pending orelse return error.MissingWideCoordinatorManifest;
        if (self.options.retained_store) |store| switch (worker.*) {
            .cpu => |*v| {
                _ = try v.restoreMain(store);
            },
            inline .truth, .delegation => |*v| {
                _ = try v.restoreMain(store);
            },
        };
        if (timer) |*clock| timing.?.restore_ns = clock.lap();
        self.results[index] = switch (worker.*) {
            .cpu => |*v| blk: {
                if (v.replay) |*owner| {
                    try owner.restore(owner.context, v);
                    // Replay has joined every compact input reader; physical
                    // global obligations now live in regenerated device MAIN.
                    self.native[index].releaseFacts();
                    if (self.options.consume_memory_events) _ = try self.advice.retireEvents(index);
                }
                const encoded = try v.complete(self.a, pending, index, self.options.global_budget);
                if (timing) |value| {
                    value.gkr_peak_including_final_binding_bytes = v.child.?.peak_gkr_owned_bytes;
                    value.local_binding_completed = !v.child.?.projection_pending;
                }
                break :blk Result{ .cpu = encoded };
            },
            inline .truth, .delegation => |*v| .{ .truth = try v.complete(self.a, pending, index, self.options.global_budget) },
        };
        if (self.options.stream) |stream| switch (self.results[index].?) {
            .cpu => |*v| stream.cpu_done(stream.context, index, v),
            .truth => |*v| stream.truth_done(stream.context, index, v),
        };
        if (timer) |*clock| timing.?.native_complete_ns = clock.lap();
        // Encoded bytes/claims are detached owners. The joined manifest owns its
        // reconstructed local artifacts, and StageOne bytes were encoded before
        // this phase. No later worker needs this completed source/child owner.
        worker.deinit(self.a);
        self.workers[index] = null;
        if (timing) |value| {
            value.stage2_completed = true;
            value.completed_worker_retired = true;
        }
    }
};
fn mainNodes(scheme: *const W.Scheme) !usize {
    // Device MAIN occupies a logical trace slot, not a host PCS tree. Its
    // Merkle backing belongs to the device allocator, outside this host count.
    if (scheme.device_om31_trace_trees[1] != null) return 0;
    if (scheme.trees.items.len <= 1) return error.MissingPhysicalMainCommitment;
    var bytes: usize = 0;
    for (scheme.trees.items[1].commitment.layers) |layer| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, layer.len, @sizeOf(W.H.Hash)));
    return bytes;
}
test "MAIN host accounting accepts a device slot without a dummy host tree" {
    var scheme: W.Scheme = undefined;
    scheme.trees = .empty;
    scheme.device_om31_trace_trees = @splat(null);
    try std.testing.expectError(error.MissingPhysicalMainCommitment, mainNodes(&scheme));
    scheme.device_om31_trace_trees[1] = .{ .root = @splat(0), .columns = &.{} };
    try std.testing.expectEqual(@as(usize, 0), try mainNodes(&scheme));
}

/// Consume prepared CPU traces only through successful original source building;
/// advice and setup remain borrowed. Returned request cell lists are independent.
pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options) !Bundle {
    return produceWithAuthority(a, setups, truths, native, advice, expected, config, options, null);
}
/// The authority is independently derived from trusted setup, never parsed from
/// operational resource JSON or a producer bundle. It stays live through return.
/// Diagnostic only (block_to_inputs harness): runs exactly the stage-one
/// source construction of every worker, in ordinal order, with the same
/// requests/inventory as produce, records source timestamps and drops each
/// source. No proof, manifest or acceptance is produced.
pub fn buildInputsOnly(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, fixed: ?*const FixedSet, epoch: ?std.time.Instant, timings: []WorkerTiming, admitted_at_ns: *u64) !void {
    const count = try std.math.add(usize, setups.len, truths.len);
    if (timings.len != count) return error.InvalidWideCoordinatorTimings;
    if (setups.len == 0 or setups.len != native.len) return error.InvalidCombinedInventory;
    @memset(timings, .{});
    const requests = try requestsFrom(a, setups, native, advice);
    defer freeRequests(a, requests);
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
    defer inventory.deinit();
    admitted_at_ns.* = sinceEpoch(epoch);
    for (timings, 0..) |*t, index| {
        t.source_begin_ns = sinceEpoch(epoch);
        if (index < setups.len) {
            var source = try Pipeline.buildCpuSource(a, setups[index], requests[index], native[index], advice, index, inventory.first_ids[index], false, null);
            t.source_ready_ns = sinceEpoch(epoch);
            source.deinit();
        } else {
            var source = try R.TruthSource.init(a, truths[index - setups.len], advice);
            t.source_ready_ns = sinceEpoch(epoch);
            source.deinit();
        }
        t.source_ns = t.source_ready_ns - t.source_begin_ns;
    }
}
pub fn produceWithAuthority(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options, fixed: ?*const FixedSet) !Bundle {
    const policy = try @import("child.zig").readTreePolicyFor(a, options.checkpoint_above_gkr_bytes != 0);
    return produceFrozen(a, setups, truths, native, advice, expected, config, options, fixed, policy);
}
fn produceFrozen(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options, fixed: ?*const FixedSet, policy: @import("child.zig").TreePolicy) !Bundle {
    try @import("tree_selection.zig").validate(policy, options.checkpoint_above_gkr_bytes);
    if (options.observed_tree_policy) |out| out.* = policy;
    const count = try std.math.add(usize, setups.len, truths.len);
    try options.validate(count);
    if (options.worker_timings) |timings| @memset(timings, .{});
    @memset(options.stage1_trace, .{});
    @memset(options.stage2_trace, .{});
    if (setups.len == 0 or setups.len != native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len or native.len != advice.sha256.len or native.len != advice.arith256_mod.len or native.len != advice.curves.len or native.len != advice.bulk.len or native.len != advice.sponge.len) return error.InvalidCombinedInventory;
    const requests = try requestsFrom(a, setups, native, advice);
    errdefer freeRequests(a, requests);
    var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
    defer inventory.deinit();
    const estimates = try admit(a, setups, truths, requests, &inventory, config, options, policy, native, advice);
    defer estimates.deinit(a);
    if (options.admitted_at_ns) |out| out.* = sinceEpoch(options.epoch);
    const inventory_admitted_utc_ns: u64 = @intCast(std.time.nanoTimestamp());
    if (options.early_segments != null) std.debug.print("EARLY_NATIVE_SEGMENT event=inventory_ready utc_ns={}\n", .{inventory_admitted_utc_ns});
    if (std.posix.getenv("STWO_RV64_CPU0_PRESTAGE")) |flag| if (std.mem.eql(u8, flag, "1")) std.debug.print("GPU_CPU_PRESTAGE event=inventory_ready utc_ns={} process_at_ns={}\n", .{ std.time.nanoTimestamp(), sinceEpoch(options.epoch) });
    if (options.worker_timings) |timings| for (estimates.cpu_policies, 0..) |selected, i| {
        timings[i].resolved_tree_policy = selected;
    };
    const workers = try a.alloc(?Worker, count);
    defer a.free(workers);
    @memset(workers, null);
    defer for (workers) |*slot| if (slot.*) |*v| v.deinit(a);
    const stages = try a.alloc(Manifest.StageOne, count);
    defer a.free(stages);
    const results = try a.alloc(?Result, count);
    defer a.free(results);
    @memset(results, null);
    defer for (results) |*slot| if (slot.*) |*v| v.deinit(a);
    var run = Run{ .a = a, .setups = setups, .truths = truths, .native = native, .advice = advice, .requests = requests, .inventory = &inventory, .inventory_admitted_utc_ns = inventory_admitted_utc_ns, .fixed = fixed, .config = config, .options = options, .workers = workers, .stages = stages, .results = results, .cpu_tree_policies = estimates.cpu_policies };
    const stage1_options = Schedule.RunOptions{ .estimates = if (options.schedule.memory_cap_bytes != 0) estimates.stage1 else &.{}, .trace = options.stage1_trace };
    const stage2_options = Schedule.RunOptions{ .estimates = if (options.schedule.memory_cap_bytes != 0) estimates.stage2 else &.{}, .order = options.stage2_order, .trace = options.stage2_trace };
    const schedule = nativeSchedule(options.schedule);
    try Schedule.runWithOptions(Run, a, &run, count, schedule, stage1_options, Run.stageOne);
    // The complete ordered set of sealed MAINs and local children is joined once.
    var pending = try Manifest.verifyAndSeal(a, inventory.execution_identity, inventory.workers, stages);
    defer pending.deinit(a);
    const stage_bytes = try ManifestWire.encode(a, inventory.execution_identity, inventory.workers, stages);
    errdefer a.free(stage_bytes);
    if (options.stream) |stream| stream.sealed(stream.context, requests, stage_bytes);
    // Runs before stage_bytes, results and requests are freed (reverse order).
    errdefer if (options.stream) |stream| stream.abort(stream.context);
    run.pending = &pending;
    try Schedule.runWithOptions(Run, a, &run, count, schedule, stage2_options, Run.stageTwo);
    const cpus = try a.alloc(CPU.CpuEncoded, setups.len);
    errdefer a.free(cpus);
    const encoded_truths = try a.alloc(Truth.TruthEncoded, truths.len);
    errdefer a.free(encoded_truths);
    for (results) |result| if (result == null) return error.MissingWideCoordinatorResult;
    for (cpus, results[0..setups.len]) |*out, result| out.* = result.?.cpu;
    for (encoded_truths, results[setups.len..]) |*out, result| out.* = result.?.truth;
    @memset(results, null);
    return .{ .requests = requests, .stage_one_bytes = stage_bytes, .cpus = cpus, .truths = encoded_truths };
}
/// STWO_RV64_M8_NATIVE_DEVICE_ADMISSION=1 (default off) admits each device
/// queue against memory_cap_bytes separately (Schedule.Policy.device_admission).
/// Measured on 24628607 (vectors/reports/rv64-m8-20261106/native-enqueue/):
/// the shared cap held device-1 lane 3 for 1.47 s of stage 2 while device 0
/// had finished. Operational only; every ordinal runs once with the same inputs.
fn nativeSchedule(policy: Schedule.Policy) Schedule.Policy {
    var result = policy;
    if (std.posix.getenv("STWO_RV64_M8_NATIVE_DEVICE_ADMISSION")) |flag| {
        if (std.mem.eql(u8, flag, "1")) result.device_admission = true;
    }
    return result;
}
/// Observation clock only; zero when no epoch was supplied or the clock fails.
fn sinceEpoch(epoch: ?std.time.Instant) u64 {
    const origin = epoch orelse return 0;
    const now = std.time.Instant.now() catch return 0;
    return now.since(origin);
}
const Admission = struct {
    retained_bytes: usize = 0,
    stage1: []u64,
    stage2: []u64,
    cpu_policies: []@import("child.zig").TreePolicy,
    fn deinit(self: Admission, a: std.mem.Allocator) void {
        a.free(self.stage1);
        a.free(self.stage2);
        a.free(self.cpu_policies);
    }
};
fn admit(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, inventory: *const Execution.Inventory, config: W.PcsConfig, options: Options, policy: @import("child.zig").TreePolicy, native: []const *Native, advice: ?*const Advice) !Admission {
    const estimates = Admission{ .stage1 = try a.alloc(u64, inventory.workers.len), .stage2 = &.{}, .cpu_policies = &.{} };
    errdefer a.free(estimates.stage1);
    var result = estimates;
    result.stage2 = try a.alloc(u64, inventory.workers.len);
    errdefer a.free(result.stage2);
    result.cpu_policies = try a.alloc(@import("child.zig").TreePolicy, setups.len);
    errdefer a.free(result.cpu_policies);
    // Requests are coordinator-owned copies, separate from worker source lists.
    var retained: usize = ManifestWire.MAX_BYTES;
    retained = try std.math.add(usize, retained, try std.math.mul(usize, requests.len, @sizeOf(P.Request)));
    for (requests) |request| retained = try std.math.add(usize, retained, try std.math.mul(usize, request.base.memory.initial.len + request.base.memory.terminal.len, @sizeOf(A.memory.closed_ram.types.Cell)));
    const full_nodes = if (options.retained_store) |store| store.stats().merkle_parking_enabled else false;
    var disk: usize = 0;
    for (result.stage1, result.stage2, 0..) |*stage1, *stage2, i| {
        const plan = if (i < setups.len) blk: {
            const selected = try @import("tree_selection.zig").forCpuWithDeferredBinding(a, setups[i], requests[i], config, options.gkr_budget, options.global_budget, policy, options.checkpoint_above_gkr_bytes, options.defer_local_binding);
            result.cpu_policies[i] = selected.policy;
            break :blk selected.plan;
        } else try TruthRetention.forTruth(a, truths[i - setups.len], config, options.global_budget);
        const tasks = try Retention.taskEstimates(plan, options.global_budget);
        const truth_retained: ?usize = if (i >= setups.len and options.truth_device_source_stage != null) try options.truth_device_source_stage.?.retainedUpperBound(.{ .truth = truths[i - setups.len], .expected = inventory.workers[i], .config = config }, plan.coefficient_bytes) else null;
        stage1.* = tasks.stage1;
        stage2.* = tasks.stage2;
        // The full pending inventory remains charged once below, independently
        // of each task lease. Stage two has no numerical GKR working planes;
        // its child proof, binding and global advice remain in retained bytes.
        const retained_worker = if (i < setups.len and options.cpu_replay_stage != null) replay: {
            if (native.len != setups.len or advice == null or options.retained_store != null) return error.InvalidCpuReplayAdmission;
            const stage = options.cpu_replay_stage.?;
            const compact = try stage.estimate(stage.context, .{ .setup = setups[i], .request = requests[i], .native = native[i], .advice = advice.?, .ordinal = i, .first_ids = inventory.first_ids[i], .scope = .{ .statement = inventory.workers[i].statement, .fixed = inventory.workers[i].fixed, .main = @splat(0), .ordinal = @intCast(i) } });
            stage2.* = @max(stage2.*, plan.gkr_peak_bytes);
            // No MAIN/P8 planes survive this barrier. Account compact advice,
            // native proof/artifact and narrow authenticated binding metadata.
            break :replay try std.math.add(usize, compact, try std.math.add(usize, plan.local_proof_reserve_bytes + plan.owner_header_bytes + plan.binding_descriptor_bytes, 16 * 1024));
        } else if (truth_retained) |bytes| bytes else if (options.retained_store != null) plan.parked_retained_bytes - (if (full_nodes) plan.main_merkle_node_bytes else 0) else @max(plan.resident_retained_bytes, try std.math.add(usize, try std.math.mul(usize, plan.coefficient_bytes, 2), plan.binding_bytes));
        retained = try std.math.add(usize, retained, retained_worker);
        if (truth_retained == null) disk = try std.math.add(usize, disk, try @import("stwo_prover_engine").file_backed_allocator.ReservedFile.roundedLength(try std.math.add(usize, plan.coefficient_bytes, if (full_nodes) try std.math.add(usize, plan.main_merkle_node_bytes, Store.MERKLE_HEADER_BYTES) else 0)));
    }
    if (retained > options.max_retained_frontend_bytes) {
        std.debug.print("RV64_GKR_RETAINED_ADMISSION requested_bytes={} limit_bytes={} cpu_workers={} truth_workers={} cpu_replay={} truth_device_source={}\n", .{
            retained,
            options.max_retained_frontend_bytes,
            setups.len,
            truths.len,
            options.cpu_replay_stage != null,
            options.truth_device_source_stage != null,
        });
        return error.BoundedWideCoordinatorRetainedLimit;
    }
    result.retained_bytes = retained;
    if (options.retained_store) |store| {
        const stats = store.stats();
        if (disk > stats.limit_bytes - stats.live_bytes) return error.RetainedMainBudgetExceeded;
    }
    return result;
}
test "device truth barrier contract reduces retained admission without reducing transient tasks" {
    const a = std.testing.allocator;
    const F = @import("coordinator_fixture.zig");
    const Original = @import("../fixture.zig");
    const DS = @import("truth_device_source.zig");
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const pointers = [_]*Native{ &captured.native[0], &captured.native[1] };
    const requests = [_]P.Request{ try requestView(&pointers, &captured.advice, 0), try requestView(&pointers, &captured.advice, 1) };
    const config = try F.config();
    const all_truths = keys.truths();
    var inventory = try Execution.Inventory.initWithAuthority(a, &keys.pointers(), &all_truths, &requests, Original.expectedFor(captured.program.identity), config, null);
    defer inventory.deinit();
    // This admission-only view selects the first real Keccak provider; no
    // incomplete inventory is ever passed to execution or a receiver.
    var view = inventory;
    view.workers = inventory.workers[0..3];
    const truth = all_truths[0..1];
    const policy = @import("child.zig").TreePolicy{ .stream_bottom = true, .tight_admission = true };
    var options = Options{ .gkr_budget = 2 << 30, .global_budget = 1 << 30, .max_retained_frontend_bytes = 4 << 30 };
    var legacy = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    defer legacy.deinit(a);
    const Fake = struct {
        fn unused(_: *anyopaque, _: std.mem.Allocator, _: DS.Prepare) !DS.Owner {
            return error.UnusedTestPrepare;
        }
        fn retained(_: *anyopaque, request: DS.RetentionRequest) !DS.Retained {
            return .{ .compact_input_bytes = try DS.compactInputBytes(request.truth), .narrow_metadata_bytes = 4096, .kept_device_bytes = 0, .main_replayed = true };
        }
    };
    var marker: u8 = 0;
    options.truth_device_source_stage = .{ .context = &marker, .prepare = Fake.unused, .retained_upper_bound = Fake.retained };
    var replay = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    defer replay.deinit(a);
    try std.testing.expect(replay.retained_bytes < legacy.retained_bytes);
    try std.testing.expectEqualSlices(u64, legacy.stage1, replay.stage1);
    try std.testing.expectEqualSlices(u64, legacy.stage2, replay.stage2);
    options.max_retained_frontend_bytes = legacy.retained_bytes - 1;
    var bounded = try admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null);
    bounded.deinit(a);
    options.truth_device_source_stage = null;
    try std.testing.expectError(error.BoundedWideCoordinatorRetainedLimit, admit(a, &keys.pointers(), truth, &requests, &view, config, options, policy, &.{}, null));
}

test "hybrid per-CPU policies preserve complete physical proofs fresh verification and admission OOM ownership" {
    const a = std.testing.allocator;
    const F = @import("coordinator_fixture.zig");
    const Original = @import("../fixture.zig");
    const Child = @import("child.zig");
    var control = try F.Case.init(a);
    defer control.deinit();
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const pointers = [_]*Native{ &captured.native[0], &captured.native[1] };
    const requests = [_]P.Request{ try requestView(&pointers, &captured.advice, 0), try requestView(&pointers, &captured.advice, 1) };
    const config = try F.config();
    const base = Child.TreePolicy{ .stream_bottom = true, .tight_admission = true };
    const p0 = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, 2 << 30, 1 << 30, base, 0);
    const p1 = try @import("tree_selection.zig").forCpu(a, keys.cpus[1], requests[1], config, 2 << 30, 1 << 30, base, 0);
    try std.testing.expect(p0.plan.gkr_peak_bytes != p1.plan.gkr_peak_bytes);
    const threshold = @min(p0.plan.gkr_peak_bytes, p1.plan.gkr_peak_bytes);
    var timings: [5]WorkerTiming = undefined;
    var observed: Child.TreePolicy = undefined;
    const options = Options{ .gkr_budget = 2 << 30, .checkpoint_above_gkr_bytes = threshold, .worker_timings = &timings, .observed_tree_policy = &observed, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } };
    const expected = Original.expectedFor(captured.program.identity);
    var inventory = try Execution.Inventory.initWithAuthority(a, &keys.pointers(), &keys.truths(), &requests, expected, config, null);
    defer inventory.deinit();
    const AdmissionContext = struct {
        setups: []const *const R.CpuSetup,
        truths: []const R.Truth,
        requests: []const P.Request,
        inventory: *const Execution.Inventory,
        config: W.PcsConfig,
        options: Options,
        policy: Child.TreePolicy,
        fn run(allocator: std.mem.Allocator, context: @This()) !void {
            const value = try admit(allocator, context.setups, context.truths, context.requests, context.inventory, context.config, context.options, context.policy, &.{}, null);
            defer value.deinit(allocator);
        }
    };
    const setup_pointers = keys.pointers();
    const truths = keys.truths();
    try std.testing.checkAllAllocationFailures(a, AdmissionContext.run, .{AdmissionContext{ .setups = &setup_pointers, .truths = &truths, .requests = &requests, .inventory = &inventory, .config = config, .options = options, .policy = base }});
    // A selected non-checkpoint CPU may not silently switch after its budget
    // fails, even when checkpointing would have fit.
    try std.testing.expectError(error.LocalGkrBudgetExceeded, @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, p0.plan.gkr_peak_bytes - 1, 1 << 30, base, std.math.maxInt(usize)));
    const checkpoint_plan = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, 2 << 30, 1 << 30, base, 1);
    try std.testing.expect(checkpoint_plan.plan.gkr_peak_bytes < p0.plan.gkr_peak_bytes);
    const between = checkpoint_plan.plan.gkr_peak_bytes + (p0.plan.gkr_peak_bytes - checkpoint_plan.plan.gkr_peak_bytes) / 2;
    const admitted_below_dense = try @import("tree_selection.zig").forCpu(a, keys.cpus[0], requests[0], config, between, 1 << 30, base, 1);
    try std.testing.expect(admitted_below_dense.policy.checkpointed and admitted_below_dense.plan.gkr_peak_bytes <= between);
    var conflicting = base;
    conflicting.checkpointed = true;
    try std.testing.expectError(error.InvalidHybridGkrTreePolicy, produceFrozen(a, &setup_pointers, &truths, &pointers, &captured.advice, expected, config, options, null, conflicting));
    try std.testing.expect(captured.native[0].cpu != null and captured.native[1].cpu != null);
    var bundle = try produceFrozen(a, &setup_pointers, &truths, &pointers, &captured.advice, expected, config, options, null, base);
    defer bundle.deinit(a);
    try std.testing.expectEqualDeep(base, observed);
    for (timings, 0..) |timing, i| {
        if (i < 2) {
            const peak = if (i == 0) p0.plan.gkr_peak_bytes else p1.plan.gkr_peak_bytes;
            const selected = try @import("tree_selection.zig").resolve(base, threshold, peak);
            try std.testing.expectEqualDeep(selected, timing.resolved_tree_policy.?);
            const selected_plan = try @import("tree_selection.zig").forCpu(a, keys.cpus[i], requests[i], config, options.gkr_budget, options.global_budget, base, threshold);
            try std.testing.expectEqual(selected_plan.plan.gkr_peak_bytes, timing.admitted_gkr_peak_bytes);
            try std.testing.expect(timing.including_binding_requested_peak_bytes <= timing.admitted_gkr_peak_bytes);
            try std.testing.expect(timing.gkr_allocator_limit_bytes <= options.gkr_budget);
        } else try std.testing.expect(timing.resolved_tree_policy == null);
    }
    try std.testing.expect(timings[0].resolved_tree_policy.?.checkpointed != timings[1].resolved_tree_policy.?.checkpointed);
    try std.testing.expectEqualSlices(u8, control.bundle.stage_one_bytes, bundle.stage_one_bytes);
    for (control.bundle.cpus, bundle.cpus) |before, after| {
        try std.testing.expectEqualSlices(u8, before.bytes, after.bytes);
        try std.testing.expectEqualDeep(before.claims, after.claims);
    }
    for (control.bundle.truths, bundle.truths) |before, after| try std.testing.expectEqualSlices(u8, before.bytes, after.bytes);
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    const result = try bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, config);
    try std.testing.expect(result.completed);
    // Fail the next allocation only after CPU0 has a complete owned child and
    // physical MAIN. The serial outer lane then fails CPU1, exercising teardown
    // of live workers, frozen policy storage and every pending owner together.
    var failure_timings: [5]WorkerTiming = @splat(.{});
    var failing = HybridFailureAllocator{ .child = a, .first = &failure_timings[0] };
    var failed_capture = try Original.Captured.init(failing.allocator());
    defer failed_capture.deinit();
    var failure_options = options;
    failure_options.worker_timings = &failure_timings;
    failure_options.schedule = .{ .lanes = 1, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 };
    try std.testing.expectError(error.OutOfMemory, produceFrozen(failing.allocator(), &setup_pointers, &truths, &.{ &failed_capture.native[0], &failed_capture.native[1] }, &failed_capture.advice, expected, config, failure_options, null, base));
    try std.testing.expect(failure_timings[0].stage1_completed and !failure_timings[1].stage1_completed);
}

const HybridFailureAllocator = struct {
    child: std.mem.Allocator,
    first: *const WorkerTiming,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return if (self.first.stage1_completed) null else self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return !self.first.stage1_completed and self.child.rawResize(memory, alignment, len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return if (self.first.stage1_completed) null else self.child.rawRemap(memory, alignment, len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

/// Shared declaration routing for producer preflight and actual source building.
pub fn routeDword(request: *P.Request, logs: @import("../types.zig").Logs, events: []const A.memory.load_store_v2.native.Event) !void {
    if (logs.ls_dword != null) {
        request.ls_dword = Pipeline.dwordCount(events);
        if (request.ls_dword > request.base.memory.ls_count) return error.InvalidCombinedServiceCount;
        request.base.memory.ls_count -= request.ls_dword;
    }
}
pub fn assignSpongeIds(requests: []P.Request) !void {
    var next: u64 = 1;
    for (requests) |r| next = try std.math.add(u64, next, r.calls[0]);
    for (requests) |*r| if (r.sponge.any()) {
        r.sponge.first_id = std.math.cast(u32, next) orelse return error.CombinedLookupMassExceeded;
        next = try std.math.add(u64, next, r.sponge.perms);
    };
}
