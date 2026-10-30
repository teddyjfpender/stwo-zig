//! Algebra only AFTER the source-local STARK authenticates all physical claims.
//! Native CPU/RAM-clock/endpoints, ranges, ROM and tables close here. Global
//! RAM does not: endpoint plane1 is OPEN and must be rebound to a later draw
//! by proving openings of this SAME authenticated endpoint-main commitment.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Scope = @import("block_v8_endpoint_local_scope_v1.zig");
const Local = @import("block_v8_native_endpoint_local_source_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Claims = struct {
    native: []const Native.Claim,
    endpoint: [Endpoint.PLANES]Q,
    endpoint_range: [2]Q,
    program: Q,
    lookup: [Schema.KIND_COUNT]Q,
};
pub const Summary = struct {
    source: Scope.Source,
    cycles: u32,
    logical_ram_accesses: u64,
    program_fetches: u64,
    scope: enum { local_execution_global_ram_open } = .local_execution_global_ram_open,
};
pub fn close(a: std.mem.Allocator, admitted: *const Scope.Owned, input: Scope.Input, claims: Claims, drawn: *const @import("block_v7_execution_epoch_v1.zig").Drawn) !Summary {
    const owner = try Local.Owner.init(a, input.shape, admitted.descriptor.scope, claims.native, claims.endpoint, claims.endpoint_range, drawn);
    defer owner.deinit();
    const local = try Local.close(a, input.shape, owner, claims.native, drawn);
    if (!local.program_sum.add(claims.program).isZero() or local.fetch_count != input.program_plan.expected_fetches) return error.UnclosedEndpointLocalProgram;
    var tables = local.table_requests;
    tables[@intFromEnum(Schema.Kind.range_check_8_8)] = tables[@intFromEnum(Schema.Kind.range_check_8_8)].add(local.byte_pair_sum);
    for (tables, claims.lookup) |source, provider| {
        for (provider.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointLocalProviderClaim;
        if (!source.add(provider).isZero()) return error.UnclosedEndpointLocalLookup;
    }
    var accesses: u64 = 0;
    for (input.shape.component_descs[0..input.shape.n_components]) |desc| if (desc.family == .load_store) {
        accesses = try std.math.add(u64, accesses, desc.n_rows);
    };
    // Deliberately do not expose the local-z global claim as a closed RAM
    // statement. The late bridge recomputes it using its global challenge.
    return .{ .source = admitted.source(), .cycles = input.shape.public_data.clock, .logical_ram_accesses = accesses, .program_fetches = local.fetch_count };
}
