//! Isolated warm producer: reuse original caller/access first-round recipe,
//! no arithmetic matrix regeneration or extra segment replay. Production
//! Caller pipeline remains unchanged until the canonical fused receiver gate.
const std = @import("std");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Batch = @import("block_v5_precompile_batch_v1.zig");
const Existing = @import("block_v5_caller_external_stage_v1.zig");
const Pipeline = @import("block_v5_caller_pipeline_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const Schedule = @import("block_v5_caller_fused_schedule_v1.zig").Schedule;
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Counter = @import("../air/lookups/tables/counter.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const Sink = struct { context: *anyopaque, put_fused: *const fn (*anyopaque, u32, *Fused.Proof) anyerror!void };
pub const Bound = struct {
    proposal: Pipeline.Proposal,
    record: Batch.Record,
    family11: Seal.Entry,
    family12: Seal.Entry,
    family13: Seal.Entry,
    pub fn require(self: *const Bound, a: std.mem.Allocator) !void {
        const expected = try lateBind(a, self.proposal, self.record.execution.instance_id);
        if (!std.meta.eql(self.*, expected)) return error.ChangedV5FusedBoundCaller;
    }
};
/// Existing first-pass collection remains authoritative for physical roots,
/// exact counters and RW witness. Only its late-bound family12 ID changes.
pub fn lateBind(a: std.mem.Allocator, proposal: Pipeline.Proposal, execution: [32]u8) !Bound {
    try Protocol.validate(&proposal.statement, proposal.total_steps, proposal.config);
    try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &proposal.statement);
    if (proposal.frame.cycle_count != proposal.total_steps or
        !std.meta.eql(proposal.key_id, try Protocol.keyId(&proposal.statement, proposal.total_steps, proposal.config, proposal.roots[0])) or
        !std.meta.eql(proposal.caller_max_requests, try @import("block_v5_precompile_table_demand_v1.zig").fromStatement(a, &proposal.statement, proposal.total_steps, proposal.config)))
        return error.ChangedV5PhysicalCallerProposal;
    var schedule = try Schedule.init(a, &proposal.statement, proposal.total_steps, proposal.frame, proposal.register_custody_mode);
    defer schedule.deinit();
    if (!std.meta.eql(proposal.byte_demand, try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(&proposal.statement, schedule.memory, proposal.register_custody_mode)))
        return error.ChangedV5PhysicalCallerProposal;
    const record = Batch.Record{ .execution = .{ .index = proposal.index, .instance_id = execution }, .total_steps = proposal.total_steps, .statement = proposal.statement, .key_id = proposal.key_id, .instance_id = Protocol.instanceId(proposal.key_id, execution, proposal.index, proposal.roots), .roots = proposal.roots };
    const binding = Protocol.CallerBinding{ .execution_index = proposal.index, .caller_entry_index = proposal.index, .execution_instance_id = execution, .caller_instance_id = record.instance_id, .caller_key_id = proposal.key_id, .first_roots = proposal.roots, .sealed_digest = @splat(0) };
    if (proposal.readonly_physical) |physical| {
        const authority = proposal.readonly_authority orelse return error.MissingV5CallerReadonlyAuthority;
        if (proposal.register_custody_mode != 1 or !std.meta.eql(physical.roots[0..2].*, proposal.roots) or !std.meta.eql(physical.roots[2], proposal.witness_root) or !std.meta.eql(physical.selection_digest, authority.selection.expected_digest) or physical.all_rw_events != schedule.rw_events or physical.readonly_events > physical.all_rw_events) return error.ChangedV5PhysicalCallerProposal;
        var admitted = try authority.admit(a);
        defer admitted.deinit();
        const readonly_proof = @import("block_v5_caller_readonly_proof_v1.zig");
        return .{ .proposal = proposal, .record = record, .family11 = record.entry(), .family12 = readonly_proof.entry(binding, proposal.witness_root, proposal.frame, 1, &schedule, authority), .family13 = readonly_proof.accessEntry(binding, proposal.witness_root, proposal.frame, &schedule, authority) };
    }
    if (proposal.readonly_authority != null) return error.ChangedV5PhysicalCallerProposal;
    return .{ .proposal = proposal, .record = record, .family11 = record.entry(), .family12 = Fused.entry(binding, proposal.witness_root, proposal.frame, proposal.register_custody_mode, &schedule), .family13 = @import("block_v5_external_memory_sidecar_proof_v1.zig").packedEntry(execution, record.instance_id, proposal.key_id, proposal.roots, proposal.witness_root, proposal.index, schedule.memory) };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const Prepared = Existing.ForBackend(Backend).Prepared;
        sink: Sink,
        frame: Frame,
        expected_witness_root: [32]u8,
        expected_byte_snapshot: [32]u8,
        pub fn proveWarm(self: *@This(), a: std.mem.Allocator, warm: Batch.ForBackend(Backend).WarmCaller) !void {
            try Protocol.admit(warm.first.binding(warm.sealed), warm.sealed, warm.pins, warm.entries);
            if (!std.meta.eql(warm.first.entry(), warm.record.entry()) or self.frame.cycle_count != warm.record.total_steps) return error.UntrustedV5FusedWarmCaller;
            var counter = try Counter.Counter.init(a, .range_check_8_8);
            defer counter.deinit(a);
            var prepared = try Prepared.initForMode(a, warm.first, &warm.record.statement, self.frame, warm.record.execution.index, &counter, warm.sealed.register_custody_mode);
            defer prepared.deinit(a);
            if (!std.meta.eql(prepared.first.roots[2], self.expected_witness_root) or !std.meta.eql(prepared.byte_snapshot, self.expected_byte_snapshot)) return error.ChangedV5FusedWarmCallerWitness;
            try self.provePreparedWarm(a, &prepared, warm);
        }
        /// Reuse the physical/access setup if the encompassing pipeline already
        /// made it. No retained source/witness ownership escapes this callback.
        pub fn provePreparedWarm(self: *@This(), a: std.mem.Allocator, prepared: *Prepared, warm: Batch.ForBackend(Backend).WarmCaller) !void {
            if (!std.meta.eql(prepared.first.roots[2], self.expected_witness_root) or !std.meta.eql(prepared.byte_snapshot, self.expected_byte_snapshot) or prepared.byte_demand.event_count != try @import("block_execution_external_trace_v2.zig").expectedEventCountForMode(&warm.record.statement, warm.sealed.register_custody_mode)) return error.ChangedV5FusedWarmCallerWitness;
            var proof = try Fused.ForBackend(Backend).proveForCallerFirstRound(a, &prepared.first, prepared.inputs, warm.first, self.frame, self.expected_witness_root, warm.sealed, warm.pins, warm.entries);
            var owns = true;
            defer if (owns) proof.deinit(a);
            try self.sink.put_fused(self.sink.context, warm.record.execution.index, &proof);
            owns = false;
        }
    };
}
