//! Fresh original compact root, actual public-export root and final same-parent
//! compensation proof verification. This is scoped equation authority only.
const std = @import("std");
const Context = @import("block_v5_heterogeneous_scoped_public_context_v1.zig");
const Protocol = @import("block_v5_reusable_scoped_public_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Bus = @import("block_v5_heterogeneous_scoped_public_bus_v1.zig");
pub const Policy = struct {
    sources: Context.Policy,
    /// These are independently reconstructed actual setup outputs. Neither
    /// artifact metadata nor a received self-hash may populate this policy.
    key: Protocol.Key,
    expected_id: [32]u8,
    schedule: []const Bus.Wire,
    plan: [32]u8,
    max_proof_bytes: usize = 512 << 20,
};
pub const Fresh = struct {
    context: *Context.Context,
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    policy: Policy,
    pub const complete_block_authority = false;
    pub const complete_source_authority = false;
    pub fn validate(self: *const Fresh) !void {
        const admitted = try admission(self.context, self.policy);
        try self.equation.validate(&admitted, self.policy.expected_id);
    }
    pub fn deinit(self: *Fresh) void {
        self.equation.deinit();
        self.context.deinit();
        self.* = undefined;
    }
};
pub fn admission(context: *const Context.Context, policy: Policy) !Protocol.Admission {
    if (context.policy.owner != policy.sources.owner or !std.meta.eql(context.plan.pinned_digest, policy.plan) or policy.max_proof_bytes == 0) return error.UntrustedScopedPublicParentPolicy;
    const admitted = Protocol.Admission{ .key = policy.key, .expected_id = policy.expected_id, .wires = policy.schedule, .values = context.values() };
    try admitted.validate();
    return admitted;
}
/// Independently reload expected public input from disk, rederive source/plan
/// policy, verify both genuine lower children, then freshly verify final bytes.
pub fn verify(a: std.mem.Allocator, policy: Policy, compact_bytes: []const u8, public_bytes: []const u8, received: []const u8) !Fresh {
    if (received.len == 0 or policy.max_proof_bytes == 0 or received.len > policy.max_proof_bytes) return error.ScopedPublicBridgeResourceLimit;
    const context = try Context.open(a, policy.sources, compact_bytes, public_bytes);
    errdefer context.deinit();
    const admitted = try admission(context, policy);
    var proof = try Parent.codec.decode(a, received, &admitted);
    var equation = try Parent.verify(&proof, &admitted);
    errdefer equation.deinit();
    try equation.validate(&admitted, policy.expected_id);
    return .{ .context = context, .equation = equation, .policy = policy };
}
