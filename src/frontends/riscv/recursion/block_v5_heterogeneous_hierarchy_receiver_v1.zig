//! Fresh original parent verifier, with independently chosen node admission.
//! Export frames become usable only together with this actual child equation.
const std = @import("std");
const Parent = @import("blake3_execution_parent_proof.zig");
const Protocol = @import("block_v5_reusable_heterogeneous_hierarchy_protocol_v1.zig");
const Frames = @import("block_v5_heterogeneous_hierarchy_frames_v1.zig");
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
pub fn verifyLeaf(a: std.mem.Allocator, bytes: []const u8, plan: *const @import("block_v5_heterogeneous_hierarchy_plan_v1.zig").Plan, ordinal: u32) !Fresh {
    try plan.validate();
    if (ordinal >= plan.full.expected.len) return error.InvalidHeterogeneousHierarchyTopology;
    var leaf = try plan.full.expected[ordinal].verify(a, bytes, plan.full.plan, ordinal);
    errdefer leaf.deinit();
    const source = try Frames.fromLeaf(a, &leaf.child, ordinal, plan.expected_coverage);
    leaf.child.deinit();
    // Transfer the owned immutable original verifier capture, never a receipt.
    return .{ .source = source, .equation = leaf.equation };
}
