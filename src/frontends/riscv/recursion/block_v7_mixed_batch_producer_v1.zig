//! One bounded reduction of genuine direct mixed STARKs. This stage preserves
//! open typed frames; complete execution authority is only the final receiver.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Capture = @import("block_v7_mixed_batch_capture_v1.zig");
const Receive = @import("block_v7_mixed_batch_receiver_v1.zig");
const Bus = @import("block_v7_mixed_batch_public_v1.zig");
const Prepare = @import("block_v7_mixed_batch_prepare_v1.zig");
const Cold = @import("block_v7_mixed_batch_fixed_join_v1.zig");
const Protocol = @import("block_v7_mixed_batch_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Limits = struct {
    quotient_executor: ?*const @import("stwo_prover_engine").pcs.QuotientExecutor = null,
    composition_executor: ?*const @import("blake3_parent_composition_executor_v1.zig").Executor = null,
    interaction_executor: ?*const @import("blake3_parent_interaction_executor_v1.zig").Executor = null,
    resources: ?@import("block_v7_parent_resource_model_v1.zig").Limits = null,
    max_bytes: usize = 16 << 30,
    metadata: Receive.Limits = .{},
    prepare: Prepare.Limits = .{},
    fixed: Cold.Limits = .{},
};
pub const Artifact = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    key: Protocol.Key,
    wires: []Bus.Wire,
    planned_peak_bytes: ?usize,
    charged_peak_bytes: usize,
    pub fn deinit(self: *Artifact) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.wires);
        self.* = undefined;
    }
};
/// Inputs/keys are independently selected; proofs are always freshly verified.
/// Returns no success token and performs no global relation cancellation.
pub fn prove(backing: std.mem.Allocator, input: Inputs.Input, counts: []const u32, pins: []const Receive.DirectPin, proofs: []const []const u8, limits: Limits) !Artifact {
    if (proofs.len != pins.len or pins.len == 0 or pins.len > Bus.MAX_CHILDREN or limits.max_bytes == 0) return error.InvalidMixedBatchFanIn;
    const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    var metadata = try Receive.Metadata.init(a, input, counts, pins, limits.metadata);
    defer metadata.deinit();
    // Admit the independently compiled padded PCS geometry before collecting
    // live verifier rows. Legacy callers may omit this opt-in planning model.
    var cold = try Cold.Owned.derive(a, metadata.policies, metadata.expected, limits.prepare.circuit_capacity, limits.fixed);
    var cold_live = true;
    defer if (cold_live) cold.deinit();
    var planned_peak: ?usize = null;
    if (limits.resources) |resources| {
        const model = try @import("block_v7_parent_resource_model_v1.zig").estimate(cold.fixed, metadata.policies[0].key.config, resources);
        if (std.process.hasEnvVarConstant("STWO_V7_WINDOW_PROFILE")) std.debug.print("V7_REDUCTION_ESTIMATE batches={d} estimate={f} limits={f}\n", .{ pins.len, std.json.fmt(model, .{}), std.json.fmt(resources, .{}) });
        try model.require(resources);
        planned_peak = model.planned_peak_bytes;
    }
    var captures: [Bus.MAX_CHILDREN]Capture.Captured = undefined;
    var captured: usize = 0;
    defer for (captures[0..captured]) |*c| c.deinit();
    var pointers: [Bus.MAX_CHILDREN]*const Capture.Captured = undefined;
    for (proofs, metadata.policies, 0..) |bytes, policy, i| {
        captures[i] = try Capture.verifyAndCapture(a, bytes, policy, limits.metadata.capture);
        captured += 1;
        pointers[i] = &captures[i];
    }
    var ready = try Prepare.prepare(a, pointers[0..captured], metadata.expected, limits.prepare);
    defer ready.deinit();
    // Prepared public frames borrow these bounded captures through proving.
    // Keep that ownership contract; only emitted row builders are discarded.
    try cold.validateLive(&ready);
    const Fixed = @import("blake3_parent_fixed_key_v1.zig").ForBackend(Cpu);
    var committed = try Fixed.deriveCommitted(a, cold.fixed, cold.context, cold.profile);
    var commitment_live = true;
    defer if (commitment_live) committed.deinit();
    const key = try Protocol.Key.fromGeometry(committed.key, cold.wires, cold.expected);
    cold.deinit();
    cold_live = false;
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, ready.values(), ready.expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.initFromFixedCommitment(a, &ready.recursive.rows, admission, &committed);
    defer plan.deinit();
    plan.setQuotientExecutor(limits.quotient_executor);
    plan.setCompositionExecutor(limits.composition_executor);
    plan.setInteractionExecutor(limits.interaction_executor);
    committed.deinit();
    commitment_live = false;
    var proof = try plan.proveConsuming(a, &ready.recursive.rows);
    defer proof.deinit();
    const bytes = try Parent.codec.encode(backing, &proof, &admission);
    errdefer backing.free(bytes);
    const wires = try backing.dupe(Bus.Wire, ready.wires);
    return .{ .allocator = backing, .bytes = bytes, .key = key, .wires = wires, .planned_peak_bytes = planned_peak, .charged_peak_bytes = budget.snapshot().peak_live_bytes };
}
