//! Genuine full B5CF verifier equation under independent key/schedule policy.
//! Its open projections/access require block closure and a genuine B5CT base
//! companion. This result never says that the supplied native binding verified.
const std = @import("std");
const Bus = @import("block_v5_native_capacity_fused_recursive_public_bus_v1.zig");
const Protocol = @import("block_v5_reusable_native_capacity_fused_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Admission = @import("../prover/block_v5_native_capacity_fused_recursive_admission_v1.zig");
const Fused = @import("../prover/block_v5_native_capacity_fused_proof_v1.zig");
const Memory = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    public_values: Bus.Values,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.public_values.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_key_id: [32]u8, schedule: []const Bus.Wire, admitted: *const Admission.Prepared, expected_projection_claims: []const Fused.Claim, expected_memory_claims: []const Memory.Claim) !OpenEquation {
    if (!std.meta.eql(key.config, admitted.config) or !std.meta.eql(key.context.child_config, admitted.config)) return error.CapacityFusedRecursiveSecurityMismatch;
    var values = try Bus.Values.init(a, admitted, .{ .projection = expected_projection_claims, .memory = expected_memory_claims });
    errdefer values.deinit();
    const authority = try Protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&owned, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_key_id);
    return .{ .equation = equation, .public_values = values };
}
