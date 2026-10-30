//! Exact independent receiver security policy, before any proof decoding.
//! This check grants no proof or source authority.
const std = @import("std");
const Config = @import("stwo_core").pcs.PcsConfig;
pub fn require(root: Config, trusted: Config, epoch: Config) !void {
    if (!std.meta.eql(root, trusted) or !std.meta.eql(trusted, epoch)) return error.V7RootSecurityMismatch;
}
test "v7 receiver security rejects root downgrade and epoch mismatch before decoding" {
    const expected = @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    try require(expected, expected, expected);
    var changed = expected;
    changed.pow_bits += 1;
    try std.testing.expectError(error.V7RootSecurityMismatch, require(changed, expected, expected));
    try std.testing.expectError(error.V7RootSecurityMismatch, require(expected, changed, expected));
    try std.testing.expectError(error.V7RootSecurityMismatch, require(expected, expected, changed));
}
