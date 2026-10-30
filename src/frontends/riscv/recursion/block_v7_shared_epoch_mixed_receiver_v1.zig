//! Complete bounded v7 execution root receiver. The expected key and schedule
//! come from independent original-verifier compilation, never the candidate.
//! Original proof files, producer traces and purported success receipts are not
//! accepted. O(roster) public metadata remains explicit.
const std = @import("std");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Protocol = @import("block_v7_shared_epoch_mixed_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Global = @import("../prover/block_v7_global_public_closure_v1.zig");
pub const Verified = struct {
    equation: @import("blake3_native_parent_verifier.zig").Verified,
    summary: Global.Summary,
    pub fn deinit(self: *Verified) void {
        self.equation.deinit();
        self.* = undefined;
    }
};
pub fn verify(a: std.mem.Allocator, bytes: []const u8, trusted: Global.Trusted, input: Inputs.Input, expected_key: Protocol.Key, expected_wires: []const Bus.Wire, limits: Global.Limits) !Verified {
    try @import("block_v7_receiver_security_v1.zig").require(expected_key.config, trusted.config, input.epoch.config);
    var canonical = try Inputs.Owned.init(a, input);
    defer canonical.deinit();
    const admission = try Protocol.Admission.init(expected_key, try expected_key.identity(), expected_wires, canonical.values(), canonical.expected);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var equation = try Parent.verify(&decoded, &admission);
    errdefer equation.deinit();
    try equation.validate(&admission, try expected_key.identity());
    const summary = try Global.closePublic(a, trusted, input, canonical.values(), limits);
    return .{ .equation = equation, .summary = summary };
}
