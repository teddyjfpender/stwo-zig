//! Early-source producer operations, published by the coordinator facade.
//! The native facade selects no owners; products bind their actual owners.
//! Canonical proof records and destruction rules stay outside specialization.
//! Bounded two-stage producer for the explicitly selected OM services profile.
//! Large inventories require explicit parking and retained/disk/task admission.
//! Those partial bounds exclude setup/capture/PCS scratch; they are not total RSS.
//! Schedule policy is operational; the manifest barrier is not.
const std = @import("std");
const State = @import("coordinator_state.zig");
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

pub fn ForEarlySources(comptime EarlyCpu0: type, comptime EarlySegments: type) type {
    return struct {
        pub const EarlySourceOwners = struct {
            pub const Cpu0 = EarlyCpu0;
            pub const Segments = EarlySegments;
        };
        pub const Store = State.Store;
        pub const WorkerTiming = State.WorkerTiming;
        pub const Stream = State.Stream;
        pub const NativeStageTwo = State.NativeStageTwo;
        pub const Bundle = State.Bundle;
        pub const requestView = State.requestView;
        pub const buildInputsOnly = State.buildInputsOnly;
        pub const routeDword = State.routeDword;
        pub const assignSpongeIds = State.assignSpongeIds;
        const Worker = State.Worker;
        const Result = State.Result;

        pub const Options = struct {
            /// M8 native-hybrid stage-two seam (see NativeStageTwo); null = legacy.
            native_stage_two: ?NativeStageTwo = null,
            early_cpu0: if (EarlyCpu0 == void) @TypeOf(null) else ?*EarlyCpu0 = null,
            early_segments: if (EarlySegments == void) @TypeOf(null) else ?*EarlySegments = null,
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
                if (timing) |t| t.source_begin_ns = State.sinceEpoch(self.options.epoch);
                if (index < self.setups.len) {
                    if (EarlySegments != void and self.options.early_segments != null) {
                        const early = self.options.early_segments.?;
                        self.workers[index] = .{ .cpu = try early.take(index, self.setups[index], self.requests[index], self.inventory.workers[index], self.config, self.inventory.first_ids[index]) };
                        const slot = &early.slots[index];
                        if (timing) |value| {
                            value.source_ns = slot.source_end_utc_ns - slot.source_begin_utc_ns;
                            value.early_source_and_main_ns = self.workers[index].?.cpu.main_commit_end_utc_ns - slot.source_begin_utc_ns;
                            value.early_main_commit_before_inventory = self.workers[index].?.cpu.main_commit_end_utc_ns <= self.inventory_admitted_utc_ns;
                        }
                        if (timer) |*clock| _ = clock.lap();
                    } else if (EarlyCpu0 != void and index == 0 and self.options.early_cpu0 != null) {
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
                        if (timing) |t| t.source_ready_ns = State.sinceEpoch(self.options.epoch);
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

                        timing.?.actual_main_merkle_bytes = try State.mainNodes(&self.workers[index].?.cpu.scheme);
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
                        if (timing) |t| t.source_ready_ns = State.sinceEpoch(self.options.epoch);
                        if (Execution.extendedTruth(truth)) {
                            self.workers[index] = .{ .delegation = try @import("truth_v3_worker.zig").NativeTruthWorker.initDeviceWithAuthority(self.a, truth, owner, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                        } else {
                            self.workers[index] = .{ .truth = try Truth.TruthWorker.initDeviceWithAuthority(self.a, truth, owner, self.inventory.workers[index], self.config, self.options.global_budget, if (self.fixed) |authority| authority.at(index) else null) };
                        }
                        owned = false;
                    } else {
                        var source = try R.TruthSource.init(self.a, truth, self.advice);
                        if (timer) |*clock| timing.?.source_ns = clock.lap();
                        if (timing) |t| t.source_ready_ns = State.sinceEpoch(self.options.epoch);
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
                                timing.?.actual_main_merkle_bytes = try State.mainNodes(&worker.scheme);
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
                        if (self.options.native_stage_two) |hook| {
                            // The hook owns the replay restore (if it needs MAIN back);
                            // compact inputs are released after it, as below.
                            const encoded = try hook.stage_two(hook.context, self.a, v, pending, index, self.options.global_budget);
                            if (v.replay != null) {
                                self.native[index].releaseFacts();
                                if (self.options.consume_memory_events) _ = try self.advice.retireEvents(index);
                            }
                            break :blk Result{ .cpu = encoded };
                        }
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

        pub const Admission = struct {
            retained_bytes: usize = 0,
            stage1: []u64,
            stage2: []u64,
            cpu_policies: []@import("child.zig").TreePolicy,
            pub fn deinit(self: Admission, a: std.mem.Allocator) void {
                a.free(self.stage1);
                a.free(self.stage2);
                a.free(self.cpu_policies);
            }
        };

        pub fn produce(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options) !Bundle {
            return produceWithAuthority(a, setups, truths, native, advice, expected, config, options, null);
        }

        pub fn produceWithAuthority(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options, fixed: ?*const FixedSet) !Bundle {
            const policy = try @import("child.zig").readTreePolicyFor(a, options.checkpoint_above_gkr_bytes != 0);
            return produceWithPolicy(a, setups, truths, native, advice, expected, config, options, fixed, policy);
        }

        pub fn produceWithPolicy(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, native: []const *Native, advice: *const Advice, expected: P.Expected, config: W.PcsConfig, options: Options, fixed: ?*const FixedSet, policy: @import("child.zig").TreePolicy) !Bundle {
            try @import("tree_selection.zig").validate(policy, options.checkpoint_above_gkr_bytes);
            if (options.observed_tree_policy) |out| out.* = policy;
            const count = try std.math.add(usize, setups.len, truths.len);
            try options.validate(count);
            if (options.worker_timings) |timings| @memset(timings, .{});
            @memset(options.stage1_trace, .{});
            @memset(options.stage2_trace, .{});
            if (setups.len == 0 or setups.len != native.len or native.len != advice.events.len or native.len != advice.keccak.len or native.len != advice.secp.len or native.len != advice.sha256.len or native.len != advice.arith256_mod.len or native.len != advice.curves.len or native.len != advice.bulk.len or native.len != advice.sponge.len) return error.InvalidCombinedInventory;
            const requests = try State.requestsFrom(a, setups, native, advice);
            errdefer State.freeRequests(a, requests);
            var inventory = try Execution.Inventory.initWithAuthority(a, setups, truths, requests, expected, config, fixed);
            defer inventory.deinit();
            const estimates = try planAdmission(a, setups, truths, requests, &inventory, config, options, policy, native, advice);
            defer estimates.deinit(a);
            if (options.admitted_at_ns) |out| out.* = State.sinceEpoch(options.epoch);
            const inventory_admitted_utc_ns: u64 = @intCast(std.time.nanoTimestamp());
            if (options.early_segments != null) std.debug.print("EARLY_NATIVE_SEGMENT event=inventory_ready utc_ns={}\n", .{inventory_admitted_utc_ns});
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
            try Schedule.runWithOptions(Run, a, &run, count, options.schedule, stage1_options, Run.stageOne);
            // The complete ordered set of sealed MAINs and local children is joined once.
            var pending = try Manifest.verifyAndSeal(a, inventory.execution_identity, inventory.workers, stages);
            defer pending.deinit(a);
            const stage_bytes = try ManifestWire.encode(a, inventory.execution_identity, inventory.workers, stages);
            errdefer a.free(stage_bytes);
            if (options.stream) |stream| stream.sealed(stream.context, requests, stage_bytes);
            // Runs before stage_bytes, results and requests are freed (reverse order).
            errdefer if (options.stream) |stream| stream.abort(stream.context);
            run.pending = &pending;
            try Schedule.runWithOptions(Run, a, &run, count, options.schedule, stage2_options, Run.stageTwo);
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

        pub fn planAdmission(a: std.mem.Allocator, setups: []const *const R.CpuSetup, truths: []const R.Truth, requests: []const P.Request, inventory: *const Execution.Inventory, config: W.PcsConfig, options: Options, policy: @import("child.zig").TreePolicy, native: []const *Native, advice: ?*const Advice) !Admission {
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
    };
}
