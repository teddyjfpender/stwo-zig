//! Fresh mixed original-verifier verification. The caller supplies independent
//! key, exact roster and public claims. No base files or wrapper proofs are
//! loaded here; this authenticates OPEN typed native/provider/source equations, not a block root.
const std = @import("std");
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub const OpenBatch = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    /// Borrowed independent public values must outlive this result.
    values: Bus.Values,
    pub fn deinit(self: *OpenBatch) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, key: Protocol.Key, expected_key: [32]u8, wires: []const Bus.Wire, roster: []const Bus.Expected, values: Bus.Values) !OpenBatch {
    const admission = try Protocol.Admission.init(key, expected_key, wires, values, roster);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, expected_key);
    return .{ .equation = equation, .values = values };
}
