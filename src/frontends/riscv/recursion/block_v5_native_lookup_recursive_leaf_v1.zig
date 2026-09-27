//! Genuine provider verifier equation; its open lookup claim still requires
//! global requester closure and mandatory all-family detached verification.
const std = @import("std");
const Bus = @import("block_v5_native_lookup_recursive_public_bus_v1.zig");
const Protocol = @import("block_v5_reusable_native_lookup_parent_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Admission = @import("../prover/block_v5_native_lookup_recursive_admission_v1.zig");
const Native = @import("../prover/block_v5_native_lookup_proof_v1.zig");
pub const OpenEquation = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    public_values: Bus.Values,
    pub fn deinit(self: *OpenEquation) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_key_id: [32]u8, schedule: []const Bus.Wire, admitted: *const Admission.Prepared, expected_open: Native.OpenReceipt) !OpenEquation {
    if (!std.meta.eql(key.config, admitted.config) or !std.meta.eql(key.context.child_config, admitted.config)) return error.LookupRecursiveSecurityMismatch;
    const values = try Bus.Values.fromLookup(admitted, expected_open);
    const authority = try Protocol.Admission.init(key, expected_key_id, schedule, values);
    var owned = try Parent.codec.decode(a, bytes, &authority);
    var equation = try Parent.verify(&owned, &authority);
    errdefer equation.deinit();
    try equation.validate(&authority, expected_key_id);
    return .{ .equation = equation, .public_values = values };
}
