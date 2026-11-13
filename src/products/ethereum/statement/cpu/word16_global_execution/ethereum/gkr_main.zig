//! Experimental OM/GKR Ethereum driver. Receiver parameters are pinned here;
//! durable producer metadata cannot select configuration or security authority.
const Receiver = @import("gkr_receiver.zig");
const Worker = @import("stwo_riscv_cpu_integration").rv64_gkr_worker_protocol;
const since = @import("gkr_request_execution.zig").since;
const std = @import("std");
const engine = @import("stwo_prover_engine");
pub const EarlyCPU = @import("early_cpu0.zig");
pub const EarlySegments = @import("early_segments.zig");
pub const Recycler = @import("stwo_riscv_cpu_integration").rv64_large_block_recycler.LargeBlockRecycler;
const ReceiverBudget = @import("receiver_budget.zig");
/// Producer-owned trusted setup acceleration; forbidden to fresh receivers.
/// block_to_inputs phase report (observation only; never proof authority).
/// Every *_at_ns is nanoseconds since gkr_main entry on the monotonic clock.
pub const candidateLabel = @import("gkr_resources.zig").candidateLabel;
const selectProfile = @import("gkr_resources.zig").selectProfile;
pub fn main() !void {
    return mainWithPcs(null);
}
pub fn mainWithPcs(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage) !void {
    return mainWithStages(device_pcs_stage, null);
}
pub fn mainWithStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.CompositionStage) !void {
    return mainWithDeviceStages(device_pcs_stage, om31_composition_stage, null);
}
pub fn mainWithDeviceStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.CompositionStage, numerical_gkr_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_child.NumericalStage) !void {
    return mainWithResidentStages(device_pcs_stage, om31_composition_stage, numerical_gkr_stage, null);
}
pub fn mainWithResidentStages(device_pcs_stage: ?*const @import("stwo_prover_api").device_pcs.Stage, om31_composition_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.CompositionStage, numerical_gkr_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_child.NumericalStage, resident_composition_stage: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.ResidentCompositionStage) !void {
    return mainWithResidentPipeline(.{ .pcs = device_pcs_stage, .composition = om31_composition_stage, .numerical = numerical_gkr_stage, .resident_composition = resident_composition_stage });
}
pub const ResidentStages = struct {
    early_memory: ?EarlyCPU.MemoryAdmission = null,
    early_segments: ?EarlySegments.StageProvider = null,
    cpu_replay: ?@import("stwo_riscv_cpu_integration").rv64_gkr_cpu_replay.Stage = null,
    source: ?@import("stwo_riscv_cpu_integration").rv64_device_source_stage = null,
    truth_source: ?@import("stwo_riscv_cpu_integration").rv64_gkr_truth_device_source.Stage = null,
    truth_composition: ?@import("stwo_riscv_cpu_integration").rv64_gkr_truth_device_composition.Stage = null,
    global_interaction: ?@import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.DeviceGlobal.Stage = null,
    pcs: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    truth_pcs: ?*const @import("stwo_prover_api").device_pcs.Stage = null,
    composition: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.CompositionStage = null,
    numerical: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_child.NumericalStage = null,
    resident_composition: ?*const @import("stwo_riscv_cpu_integration").rv64_gkr_cpu_worker.ResidentCompositionStage = null,
    trace_commit: ?*const @import("stwo_prover_api").device_pcs.TraceCommitStage = null,
    cpu_projection: ?@import("stwo_riscv_cpu_integration").rv64_cpu_source.ProjectionStage = null,
    /// M8 native-hybrid stage-two seam (coordinator.NativeStageTwo); null = legacy.
    native_stage_two: ?@import("stwo_riscv_cpu_integration").rv64_gkr_coordinator.NativeStageTwo = null,
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
    return runArguments(&recycler, all_args, stages, null, false, {});
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
    return runArguments(&recycler, all_args, .{}, null, true, .{ .factory = factory });
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
    ready: ?@import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.ParallelOptions = null,
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
            try @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap.validateLanes(ready);
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
    return runArguments(recycler, all_args, stages, session, true, execution);
}
const isCombinedProducer = @import("gkr_request_execution.zig").isCombinedProducer;

/// Same producer authority and CLI contract, with caller-owned persistent caches.
/// The caller keeps one GPU pool/session alive and serializes complete requests.
pub fn runWithResidentArgs(recycler: *Recycler, all_args: []const [:0]u8, stages: ResidentStages, session: *ResidentSession) !void {
    if (session.active) return error.ResidentRequestAlreadyActive;
    session.active = true;
    defer session.active = false;
    return runArguments(recycler, all_args, stages, session, false, {});
}
const runArguments = @import("gkr_request_execution.zig").runArguments;

// Worker admission is an operational bound, independent of scheduler threads.
// Parked coefficients and Merkle trees are bounded by explicit byte/disk
// admission. Their roster must fit the existing receiver security envelope.
// No-store retention keeps its smaller resident bound.

test {
    _ = @import("gkr_resources_test.zig");
}
