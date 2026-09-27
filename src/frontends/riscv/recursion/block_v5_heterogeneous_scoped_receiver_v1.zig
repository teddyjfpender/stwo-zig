//! Fresh original parent verifier, with independently chosen node admission.
//! Export frames become usable only together with this actual child equation.
const std = @import("std");
const Parent = @import("blake3_execution_parent_proof.zig");
const Protocol = @import("block_v5_reusable_heterogeneous_scoped_protocol_v1.zig");
const Frames = @import("block_v5_heterogeneous_scoped_source_v1.zig");
pub const Fresh = struct {
    source: Frames.Source,
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    pub const aggregate_joins_pending = true;
    pub const source_authorities_pending = @import("../prover/block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub fn deinit(self: *Fresh) void {
        self.equation.deinit();
        self.source.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, authority: Protocol.Admission) !Fresh {
    try authority.validate();
    var proof = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&proof, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, authority.expected_id);
    const source = try Frames.fromNode(a, authority);
    return .{ .source = source, .equation = equation };
}
pub fn verifyLeaf(a: std.mem.Allocator, bytes: []const u8, routes: *const @import("block_v5_heterogeneous_scoped_routes_v1.zig").Plan, ordinal: u32) !Fresh {
    try routes.validate();
    if (ordinal >= routes.scoped.full.expected.len or !@import("block_v5_heterogeneous_scoped_plan_v1.zig").includes(routes.scoped.recipe, routes.scoped.full.children[ordinal].physical)) return error.InvalidHeterogeneousHierarchyTopology;
    var leaf = try routes.scoped.full.expected[ordinal].verify(a, bytes, routes.scoped.full.plan, ordinal);
    errdefer leaf.deinit();
    const source = try Frames.fromLeaf(a, &leaf.child, ordinal, routes.digest);
    leaf.child.deinit();
    // Transfer the owned immutable original verifier capture, never a receipt.
    return .{ .source = source, .equation = leaf.equation };
}
