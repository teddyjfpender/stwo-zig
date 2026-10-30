//! Closure follows ONE authenticated group original. State/register/local RAM
//! MUST vanish member by member. Only bounded positive ROM/table/range buses
//! aggregate across members. These structs alone confer no proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("block_v8_endpoint_group_scope_v1.zig");
const Native = @import("block_v8_native_endpoint_components_v1.zig");
const Closure = @import("block_v8_native_endpoint_closure_v1.zig");
const Caller = @import("block_v8_caller_ram_owner_v1.zig");
const Fused = @import("block_v5_caller_fused_proof_v1.zig");
const P = @import("blake3_ethereum_sha_profile.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Q = core.fields.qm31.QM31;
pub const production_active = false;
pub const CallerClaims = struct { arithmetic: P.ExtensionClaim, basic: Fused.ClaimFrames, ram: []const Q };
pub const MemberClaims = struct { native: []const Native.Claim, endpoint: [Endpoint.PLANES]Q, caller: ?CallerClaims = null };
pub const Claims = struct { members: []const MemberClaims, endpoint_range: [2]Q, program: Q, lookup: [Schema.KIND_COUNT]Q };
pub const Summary = struct {
    /// Borrowed from Scope. A surviving proof/result MUST clone this slice.
    sources: []const @import("block_v8_endpoint_local_scope_v1.zig").Source,
    initial_pc: u32,
    final_pc: u32,
    initial_regs: [32]u32,
    final_regs: [32]u32,
    first_cohort_ordinal: u32,
    last_cohort_ordinal: u32,
    global_first_cycle: u64,
    cycles: u64,
    cohorts: u32,
    external_retirements: u64,
    logical_ram_accesses: u64,
    program_fetches: u64,
    scope: enum { group_execution_global_ram_open } = .group_execution_global_ram_open,
};
fn canonical(q: Q) !void {
    for (q.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidEndpointGroupClaims;
}
pub fn extract(member: *const Scope.OwnedMember, claims: []const Native.Claim) !Closure.Partitions {
    if (member.layout.slots.len != claims.len) return error.InvalidEndpointGroupNativeClaims;
    var out: Closure.Partitions = .{};
    for (member.layout.slots, claims) |slot, claim| {
        try canonical(claim.sum);
        if (slot.n_rows != claim.row_count) return error.InvalidEndpointGroupNativeClaims;
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
                    if (i >= Schema.KIND_COUNT) return error.InvalidEndpointGroupNativeClaims;
                    out.table_requests[i] = out.table_requests[i].add(claim.sum);
                },
            },
        }
    }
    return out;
}
/// Exposed algebraic check makes the no-cross-member-cancellation rule
/// independently testable. Its arguments must already be authenticated.
pub fn closeMember(state: Q, registers: Q, ram: Q) !void {
    try canonical(state);
    try canonical(registers);
    try canonical(ram);
    if (!state.isZero() or !registers.isZero()) return error.UnclosedEndpointGroupMemberRegisters;
    if (!ram.isZero()) return error.UnclosedEndpointGroupMemberRam;
}
pub fn close(a: std.mem.Allocator, admitted: *const Scope.Owned, input: Scope.Input, claims: Claims, drawn: *const @import("block_v7_execution_epoch_v1.zig").Drawn) !Summary {
    _ = a;
    if (claims.members.len != input.members.len or claims.members.len != admitted.member.len or admitted.sources.len != input.members.len) return error.InvalidEndpointGroupClaimInventory;
    for (claims.endpoint_range) |q| try canonical(q);
    try canonical(claims.program);
    for (claims.lookup) |q| try canonical(q);
    const prefix = &drawn.word.universal_prefix;
    const shared = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(prefix);
    const Public = @import("../air/public_logup_arithmetic.zig");
    var endpoint: [Endpoint.PLANES]Q = @splat(Q.zero());
    var tables: [Schema.KIND_COUNT]Q = @splat(Q.zero());
    var program = Q.zero();
    var fetches: u64 = 0;
    var logical: u64 = 0;
    for (input.members, admitted.member, claims.members) |m, *member, claimed| {
        const parts = try extract(member, claimed.native);
        for (claimed.endpoint) |q| try canonical(q);
        var caller_state = Q.zero();
        var caller_regs = Q.zero();
        var caller_ram = Q.zero();
        var caller_program = Q.zero();
        var caller_fetches: u64 = 0;
        var caller_logical: u64 = 0;
        var caller_tables: [Schema.KIND_COUNT]Q = @splat(Q.zero());
        if (member.caller_plan) |*plan| {
            const c = claimed.caller orelse return error.MissingEndpointGroupCallerClaims;
            if (c.basic.memory_claims.len != 0) return error.UnexpectedGroupWordMemoryClaims;
            const complete = try Caller.closeComplete(&plan.schedule, &c.arithmetic, &c.basic, c.ram);
            caller_state = complete.state_sum;
            caller_regs = complete.register_sum;
            caller_ram = complete.ram_sum;
            caller_program = complete.program_sum;
            caller_fetches = complete.fetch_count;
            caller_logical = complete.logical_ram_accesses;
            caller_tables = complete.table_requests;
        } else if (claimed.caller != null) return error.UnexpectedEndpointGroupCallerClaims;
        const state = (try Public.registersStateSumFor(Q, &m.shape.public_data, &shared.native)).add(parts.state_sum).add(caller_state);
        const regs = (try Public.registerMemoryAccessSumFor(Q, &m.shape.public_data, &shared.native)).add(parts.register_sum).add(parts.register_clock_sum).add(caller_regs);
        const ram = parts.ordinary_ram_sum.add(parts.ram_clock_sum).add(caller_ram).add(claimed.endpoint[0]);
        // Check NOW, before any sum with another member's claims is formed.
        try closeMember(state, regs, ram);
        for (&endpoint, claimed.endpoint) |*sum, q| sum.* = sum.add(q);
        const boundary = try @import("block_v5_program_boundary_v1.zig").deriveFromPinnedNativePublic(admitted.image.info.execution_profile, &m.shape.public_data, prefix);
        program = program.add(parts.program_sum).add(caller_program).add(boundary.sum);
        fetches = try std.math.add(u64, fetches, try std.math.add(u64, try std.math.add(u64, parts.fetch_count, caller_fetches), boundary.fetch_count));
        for (&tables, parts.table_requests, caller_tables) |*sum, n, c| sum.* = sum.add(n).add(c);
        logical = try std.math.add(u64, logical, caller_logical);
        for (m.shape.component_descs[0..m.shape.n_components]) |desc| if (desc.family == .load_store) {
            logical = try std.math.add(u64, logical, desc.n_rows);
        };
    }
    try Range.closeRangeClaims(admitted.endpoint_count_total, endpoint, claims.endpoint_range);
    if (!program.add(claims.program).isZero() or fetches != input.program_plan.expected_fetches) return error.UnclosedEndpointGroupProgram;
    const bytes = @intFromEnum(Schema.Kind.range_check_8_8);
    tables[bytes] = tables[bytes].add(endpoint[9]).add(endpoint[10]);
    for (tables, claims.lookup) |request, provider| if (!request.add(provider).isZero()) return error.UnclosedEndpointGroupLookup;
    const first = input.members[0];
    const last = input.members[input.members.len - 1];
    return .{ .initial_pc = first.shape.public_data.initial_pc, .final_pc = last.shape.public_data.final_pc, .initial_regs = first.shape.public_data.initial_regs, .final_regs = last.shape.public_data.final_regs, .first_cohort_ordinal = first.cohort_ordinal, .last_cohort_ordinal = last.cohort_ordinal, .global_first_cycle = first.frame.global_first_cycle, .sources = admitted.sources, .cycles = admitted.cycles, .cohorts = @intCast(input.members.len), .external_retirements = admitted.external, .logical_ram_accesses = logical, .program_fetches = fetches };
}
