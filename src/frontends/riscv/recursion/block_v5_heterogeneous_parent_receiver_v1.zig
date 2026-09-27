//! Genuine original parent STARK verification under independently admitted
//! heterogeneous public values. Deliberately OPEN: no complete-block token.
const std = @import("std");
const Protocol = @import("block_v5_reusable_heterogeneous_parent_protocol_v1.zig");
const Bus = @import("block_v5_heterogeneous_public_bus_v1.zig");
const Policy = @import("block_v5_heterogeneous_policy_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    /// These outstanding authorities are immutable scope, not caller claims.
    pub const aggregate_joins_pending = true;
    pub const source_authorities_pending = @import("../prover/block_v5_recursive_coverage_plan_v1.zig").SOURCE_COUNT;
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_id: [32]u8, wires: []const Bus.Wire, policy: Policy.Policy) !OpenEquation {
    const authority = try Protocol.Admission.init(key, expected_id, wires, .{ .policy = policy });
    var proof = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&proof, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_id);
    return .{ .equation = equation };
}
