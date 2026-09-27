//! Actual original child verification, pairing and global accounting equations
//! in ONE parent witness/supply schedule. This is an OPEN parent: authenticated
//! endpoint/source closure and semantic mapping completeness remain outstanding.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("air/block_v5_global_join_composition_v1.zig");
const Rows = @import("block_v5_heterogeneous_parent_preparation_v1.zig");
const Policy = @import("block_v5_heterogeneous_policy_v1.zig").Policy;
pub const Aggregate = struct { plan: G.Plan, pin: G.MappingPin, limits: G.Limits = .{} };
pub const Prepared = Rows.Prepared;
pub const aggregate_semantic_coverage_pending = true;
pub const endpoint_source_authority_pending = true;
/// Does not issue a complete-block result. The coordinate recipe must come
/// from independent job/policy assembly; it is never decoded from a proof.
pub fn admit(policy: Policy, aggregate: Aggregate) !void {
    try policy.validate();
    const C = @import("../prover/block_v5_recursive_coverage_plan_v1.zig");
    try requireScopes(aggregate.plan, policy.plan.meta.sources[@intFromEnum(C.SourceKind.native_catalog)].count, policy.plan.meta.sources[@intFromEnum(C.SourceKind.lookup_demand_roster)].count, policy.plan.meta.sources[@intFromEnum(C.SourceKind.register_windows)].count);
    if (!std.meta.eql(policy.plan.pinned_digest, aggregate.pin.coverage) or
        !std.meta.eql(policy.plan.meta.seal_digest, aggregate.pin.source_seal) or
        std.mem.allEqual(u8, &aggregate.pin.coverage, 0) or
        !std.meta.eql(try aggregate.plan.identity(), aggregate.pin.plan)) return error.InvalidGlobalJoinMapping;
}
/// Metadata/census admission only, never proof authority or semantic coverage.
/// Coverage v1 independently permits only canonical register custody mode1.
pub fn requireScopes(plan: G.Plan, executions: u64, lookup_groups: u64, windows: u64) !void {
    if (plan.register_custody_mode != 1 or executions == 0 or
        plan.states.len != executions or plan.byte_parts.len != executions or
        plan.lookup.len != lookup_groups or plan.registers.len != windows) return error.InvalidGlobalJoinScope;
    for (plan.states) |scope| if (scope.terms.len == 0) return error.InvalidGlobalJoinScope;
    for (plan.registers) |scope| if (scope.terms.len == 0) return error.InvalidGlobalJoinScope;
}
pub fn prepare(backing: std.mem.Allocator, policy: Policy, captures: []const *const @import("blake3_native_parent_verifier.zig").Verified, capacity: u32, row_limits: Rows.Limits, aggregate: Aggregate) !Prepared {
    try admit(policy, aggregate);
    var rows = try Rows.prepareVerifierRows(backing, policy, captures, capacity, row_limits);
    errdefer rows.deinit();
    // Both graph scratch and final cohorts charge the same parent allocator.
    // The graph's local cap is subordinate to this aggregate allocation cap.
    var recorded = try G.prepare(rows.allocator, policy.children, aggregate.plan, aggregate.pin, aggregate.limits);
    defer recorded.deinit();
    try rows.attachGraph(.{ .circuit = &recorded.circuit, .inputs = recorded.inputs, .values = recorded.values, .sources = recorded.sources });
    // Equation topology alone cannot authenticate which scoped recipe produced
    // it. Bind the full independent mapping/coverage/source identity as well.
    for (&rows.recursive.context.graph_ids, 0..) |*digest, ordinal| {
        var c = core.channel.blake3.Channel{};
        c.mixU32s(&.{ 0x42354750, G.VERSION, @intCast(ordinal) });
        c.mixRoot(digest.*);
        c.mixRoot(aggregate.pin.plan);
        c.mixRoot(aggregate.pin.coverage);
        c.mixRoot(aggregate.pin.source_seal);
        c.mixRoot(G.sourceIdentity());
        digest.* = c.digestBytes();
    }
    return rows;
}
