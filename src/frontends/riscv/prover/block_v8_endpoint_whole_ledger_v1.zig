//! Public algebra AFTER authentication of every B8 original physical claim.
//! A successful function call is not a proof. No aggregate may stand in for
//! native local closure, endpoint ranges or fresh original verification.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Scope = @import("block_v8_endpoint_whole_scope_v1.zig");
const Local = @import("block_v8_native_endpoint_local_source_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const Memory = @import("block_v7_window_memory_joint_protocol_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Claims = struct {
    native: []const Native.Claim,
    endpoint: [Endpoint.PLANES]Q,
    endpoint_range: [2]Q,
    program: Q,
    lookup: [Schema.KIND_COUNT]Q,
    memory: @import("block_v7_window_memory_joint_air_v1.zig").Claims,
};
pub const Summary = struct {
    cycles: u32,
    logical_ram_accesses: u64,
    global_endpoint_events: u32,
    program_fetches: u64,
    scope: enum { declared_nonterminal_window } = .declared_nonterminal_window,
};
pub fn close(a: std.mem.Allocator, admitted: *const Scope.Owned, input: Scope.Input, claims: Claims, drawn: *const @import("block_v7_execution_epoch_v1.zig").Drawn) !Summary {
    const local_owner = try Local.Owner.init(a, input.shape, admitted.descriptor.scope, claims.native, claims.endpoint, claims.endpoint_range, drawn);
    defer local_owner.deinit();
    const local = try Local.close(a, input.shape, local_owner, claims.native, drawn);
    const memory = try Memory.closeVerifiedClaims(admitted.policy, drawn.word.initial, claims.memory);
    if (memory.event_count != input.endpoint_count) return error.UnclosedEndpointGlobalCensus;
    if (!local.global_transition_sum.add(memory.transition).isZero()) return error.UnclosedEndpointGlobalRam;
    if (!local.program_sum.add(claims.program).isZero() or local.fetch_count != input.program_plan.expected_fetches)
        return error.UnclosedEndpointProgram;
    var tables = local.table_requests;
    tables[@intFromEnum(Schema.Kind.range_check_8_8)] = tables[@intFromEnum(Schema.Kind.range_check_8_8)].add(local.byte_pair_sum);
    for (tables, claims.lookup) |source, provider| {
        for (provider.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointProviderClaim;
        if (!source.add(provider).isZero()) return error.UnclosedEndpointLookup;
    }
    var accesses: u64 = 0;
    for (input.shape.component_descs[0..input.shape.n_components]) |desc| {
        if (desc.family == .load_store) accesses = try std.math.add(u64, accesses, desc.n_rows);
    }
    return .{ .cycles = input.shape.public_data.clock, .logical_ram_accesses = accesses, .global_endpoint_events = input.endpoint_count, .program_fetches = local.fetch_count };
}
