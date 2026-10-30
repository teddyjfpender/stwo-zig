//! Closure after ONE mixed original STARK authenticates all physical claims.
//! No native-only close is called before adding caller state/register/RAM.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Scope = @import("block_v8_endpoint_mixed_scope_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Closure = @import("block_v8_native_endpoint_closure_v1.zig");
const Caller = @import("block_v8_caller_ram_owner_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const production_active = false;
pub const Claims = struct {
    native: []const Native.Claim,
    caller_arithmetic: P.ExtensionClaim,
    caller_basic: Fused.ClaimFrames,
    caller_ram: []const Q,
    endpoint: [@import("block_v8_ram_endpoint_component_v1.zig").PLANES]Q,
    endpoint_range: [2]Q,
    program: Q,
    lookup: [Schema.KIND_COUNT]Q,
};
pub const Summary = struct {
    source: @import("block_v8_endpoint_local_scope_v1.zig").Source,
    cycles: u32,
    external_retirements: u32,
    logical_ram_accesses: u64,
    program_fetches: u64,
    scope: enum { mixed_execution_global_ram_open } = .mixed_execution_global_ram_open,
};
fn canonical(value: Q) !void {
    for (value.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidEndpointMixedClaims;
}
/// The layout was independently derived in Scope from total and external
/// retirements; all partitions remain separate through transcript absorption.
pub fn extract(admitted: *const Scope.Owned, claims: []const Native.Claim) !Closure.Partitions {
    if (claims.len != admitted.layout.slots.len) return error.InvalidEndpointMixedNativeClaims;
    var out: Closure.Partitions = .{};
    for (admitted.layout.slots, claims) |slot, claim| {
        try canonical(claim.sum);
        if (claim.row_count != slot.n_rows) return error.InvalidEndpointMixedNativeClaims;
        switch (slot.kind) {
            .program => {
                out.program_sum = out.program_sum.add(claim.sum);
                out.fetch_count = try std.math.add(u64, out.fetch_count, claim.row_count);
            },
            .lookup => |lookup| switch (lookup.partition) {
                .registers_state => out.state_sum = out.state_sum.add(claim.sum),
                .register_memory_access => out.register_sum = out.register_sum.add(claim.sum),
                .register_clock_memory_access => out.register_clock_sum = out.register_clock_sum.add(claim.sum),
                .ordinary_memory_access => out.ordinary_ram_sum = out.ordinary_ram_sum.add(claim.sum),
                .clock_memory_access => out.ram_clock_sum = out.ram_clock_sum.add(claim.sum),
                else => {
                    const i = @intFromEnum(lookup.partition);
                    if (i >= Schema.KIND_COUNT) return error.InvalidEndpointMixedNativeClaims;
                    out.table_requests[i] = out.table_requests[i].add(claim.sum);
                },
            },
        }
    }
    return out;
}
pub fn close(a: std.mem.Allocator, admitted: *const Scope.Owned, input: Scope.Input, claims: Claims, drawn: *const @import("block_v7_execution_epoch_v1.zig").Drawn) !Summary {
    _ = a;
    for (claims.endpoint) |v| try canonical(v);
    for (claims.endpoint_range) |v| try canonical(v);
    try canonical(claims.program);
    for (claims.lookup) |v| try canonical(v);
    // Explicitly exclude the old integer/WORD memory partition. The complete
    // caller owner authenticates actual caller columns and their RAM projections.
    if (claims.caller_basic.memory_claims.len != 0) return error.UnexpectedMixedWordMemoryClaims;
    const caller = try Caller.closeComplete(&admitted.caller_plan.schedule, &claims.caller_arithmetic, &claims.caller_basic, claims.caller_ram);
    const native = try extract(admitted, claims.native);
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&drawn.word.universal_prefix);
    const Public = @import("../air/public_logup_arithmetic.zig");
    const state = (try Public.registersStateSumFor(Q, &input.shape.public_data, &shared.native)).add(native.state_sum).add(caller.state_sum);
    const registers = (try Public.registerMemoryAccessSumFor(Q, &input.shape.public_data, &shared.native)).add(native.register_sum).add(native.register_clock_sum).add(caller.register_sum);
    if (!state.isZero() or !registers.isZero()) return error.UnclosedEndpointMixedRegisters;
    if (!native.ordinary_ram_sum.add(native.ram_clock_sum).add(caller.ram_sum).add(claims.endpoint[0]).isZero()) return error.UnclosedEndpointMixedRam;
    try @import("block_v8_endpoint_range_provider_v1.zig").closeRangeClaims(input.endpoint_count, claims.endpoint, claims.endpoint_range);
    const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(admitted.descriptor.scope.execution_profile, &input.shape.public_data, &drawn.word.universal_prefix);
    const program = native.program_sum.add(caller.program_sum).add(boundary.sum);
    const fetches = try std.math.add(u64, try std.math.add(u64, native.fetch_count, caller.fetch_count), boundary.fetch_count);
    if (!program.add(claims.program).isZero() or fetches != input.program_plan.expected_fetches) return error.UnclosedEndpointMixedProgram;
    var tables = native.table_requests;
    for (&tables, caller.table_requests) |*sum, addend| sum.* = sum.add(addend);
    const b = @intFromEnum(Schema.Kind.range_check_8_8);
    tables[b] = tables[b].add(claims.endpoint[9]).add(claims.endpoint[10]);
    for (tables, claims.lookup) |source, provider| if (!source.add(provider).isZero()) return error.UnclosedEndpointMixedLookup;
    var accesses = caller.logical_ram_accesses;
    for (input.shape.component_descs[0..input.shape.n_components]) |desc| if (desc.family == .load_store) {
        accesses = try std.math.add(u64, accesses, desc.n_rows);
    };
    return .{ .source = admitted.source(), .cycles = input.shape.public_data.clock, .external_retirements = admitted.external, .logical_ram_accesses = accesses, .program_fetches = fetches };
}
