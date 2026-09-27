//! Genuine original classifier recursive verification. Source/classification/
//! read-provider and transition/global equations remain explicitly open.
const std = @import("std");
const Bus = @import("block_v5_readonly_provider_recursive_public_bus_v2.zig");
const Protocol = @import("block_v5_reusable_readonly_provider_parent_protocol_v2.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Admission = @import("../prover/block_v5_readonly_provider_recursive_admission_v2.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    public_values: Bus.Values,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.public_values.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_key_id: [32]u8, schedule: []const Bus.Wire, admitted: *const Admission.Prepared, proposed: @import("../prover/block_v5_readonly_input_provider_component_v2.zig").Claim) !OpenEquation {
    if (!std.meta.eql(key.config, admitted.config) or !std.meta.eql(key.context.child_config, admitted.config)) return error.ProviderReadonlyV2RecursiveSecurityMismatch;
    var values = try Bus.Values.init(a, admitted, proposed);
    errdefer values.deinit();
    const authority = try Protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&owned, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_key_id);
    return .{ .equation = equation, .public_values = values };
}
