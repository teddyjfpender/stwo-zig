//! Pure typed accounting after a fresh partitioned proof or authenticated parent
//! public bus. This module never turns arithmetic metadata into proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Protocol = @import("block_v6_partitioned_native_proof_v1.zig");
const Admission = @import("block_v6_partitioned_recursive_admission_v1.zig");
const Windows = @import("block_v5_register_windows_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Contribution = struct {
    native_open_sum: Q,
    program_request: Q,
    table_requests: [Schema.KIND_COUNT]Q,
    /// Add caller state terms before closing this individual execution window.
    state_residual: Q,
    /// Add caller register terms before closing this individual window.
    register_residual: Q,
    register_compensation: Q,
    auxiliary_clock_memory: Q,
    ordinary_transition: Q,
    ordinary_memory_opposite: Q,
    ordinary_events: u64,
};

/// `open` must already be bound to a verified proof. `windows` is the complete
/// independently supplied register plan, pinned by the source seal.
pub fn extract(a: std.mem.Allocator, admitted: *const Admission.Prepared, open: *const Protocol.Open, windows: ?Windows.Plan) !Contribution {
    try admitted.validate(admitted.template_id);
    const native = open.native;
    const identity = admitted.binding;
    if (!std.meta.eql(native.template_id, identity.template_id) or !std.meta.eql(native.instance_id, identity.instance_id) or !std.meta.eql(native.first_roots, identity.first_roots) or !std.meta.eql(native.sealed_digest, identity.sealed_digest) or !std.meta.eql(native.layout_digest, admitted.layout_digest)) return error.UntrustedPartitionedAccountingIdentity;
    const p = open.companion.projections orelse return error.MissingPartitionedAccountingProjection;
    if (p.execution_index != admitted.native.index or !std.meta.eql(p.native_key_id, native.template_id) or !std.meta.eql(p.native_instance_id, native.instance_id) or !std.meta.eql(p.native_roots, native.first_roots) or !std.meta.eql(p.sealed_digest, native.sealed_digest)) return error.UntrustedPartitionedAccountingIdentity;
    var channel = admitted.native.sealed.sharedChannel();
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const public_state = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &admitted.native.shape.public_data, &relations.native);
    var compensation = Q.zero();
    if (admitted.native.sealed.register_custody_mode == 1) {
        const plan = windows orelse return error.MissingPartitionedRegisterPlan;
        try plan.validate();
        try plan.requireNative(admitted.native.shape);
        if (!std.meta.eql(try plan.digest(), admitted.native.sealed.register_endpoint_plan_digest) or admitted.native.index >= plan.windows.len) return error.UntrustedPartitionedRegisterPlan;
        try plan.windows[admitted.native.index].requirePublic(admitted.native.index, admitted.frame.global_first_cycle, admitted.native.shape.public_data);
        compensation = try plan.compensation(admitted.native.index, &relations.native);
    } else if (windows != null) return error.UnexpectedPartitionedRegisterPlan;
    var result = Contribution{ .native_open_sum = native.open_sum, .program_request = p.program_sum, .table_requests = p.claims, .state_residual = public_state.add(p.registers_state_sum), .register_residual = compensation.add(p.register_memory_sum).add(p.register_clock_memory_sum), .register_compensation = compensation, .auxiliary_clock_memory = p.auxiliary_clock_memory_sum, .ordinary_transition = Q.zero(), .ordinary_memory_opposite = Q.zero(), .ordinary_events = 0 };
    if (open.companion.memory) |m| {
        if (m.instance_index != admitted.native.index or !std.meta.eql(m.native_instance_id, native.instance_id) or !std.meta.eql(m.native_roots, native.first_roots) or !std.meta.eql(m.sealed_digest, native.sealed_digest) or !std.meta.eql(m.witness_root, admitted.witness_root) or !m.packed_transition) return error.UntrustedPartitionedAccountingMemory;
        result.ordinary_transition = m.transition_sum;
        result.ordinary_memory_opposite = m.universal_sum;
        result.ordinary_events = m.event_count;
    }
    if (result.ordinary_events != admitted.memory.expected_events) return error.UntrustedPartitionedAccountingCensus;
    return result;
}
