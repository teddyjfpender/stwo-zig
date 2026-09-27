//! Canonical claims for the Ethereum prefix and five typed SHA components.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const ethereum = @import("ethereum_types.zig");
const sha = @import("../../air/guest_precompile/sha256_component_profile.zig");
const Statement = @import("../blake3_ethereum_sha_statement.zig").Statement;
pub const component_count = 14 + sha.Airs.len;
pub const ExtensionClaim = struct {
    ethereum: ethereum.ExtensionClaim,
    sha: [sha.Airs.len]Q,

    pub fn zeroForStatement(statement: *const Statement) !ExtensionClaim {
        try statement.sha.validateForRecipe(statement.sha.call_count, statement.ethereum.localZeroCustody());
        return .{ .ethereum = try ethereum.ExtensionClaim.zeroForStatement(&statement.ethereum), .sha = @splat(Q.zero()) };
    }
    pub fn validateCanonicalFields(self: *const ExtensionClaim) !void {
        try self.ethereum.validateCanonicalFields();
        for (self.sha) |claim| for (claim.toM31Array()) |word| {
            if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        };
    }
    pub fn validate(self: *const ExtensionClaim, statement: *const Statement) !void {
        try statement.sha.validateForRecipe(statement.sha.call_count, statement.ethereum.localZeroCustody());
        try self.ethereum.validate(&statement.ethereum);
        try self.validateCanonicalFields();
        // Zero calls still have padded lookup rows. Their claims need not vanish.
    }
    pub const ComponentClaimView = struct { detailed: []const Q, total: Q, has_batch_frame: bool };
    /// Borrowed in transcript order: Ethereum detailed/total frames, then SHA scalars.
    pub fn componentClaims(self: *const ExtensionClaim) [component_count]ComponentClaimView {
        var result: [component_count]ComponentClaimView = undefined;
        for (self.ethereum.componentClaims(), 0..) |view, i| result[i] = .{ .detailed = view.detailed, .total = view.total, .has_batch_frame = view.has_batch_frame };
        for (&self.sha, 14..) |*claim, i| result[i] = .{ .detailed = @as(*const [1]Q, @ptrCast(claim))[0..], .total = claim.*, .has_batch_frame = false };
        return result;
    }
    pub fn componentSum(self: *const ExtensionClaim) Q {
        var sum = self.ethereum.componentSum();
        for (self.sha) |claim| sum = sum.add(claim);
        return sum;
    }
    pub fn mixInto(self: *const ExtensionClaim, channel: anytype) void {
        channel.mixU32s(&.{ 0x42335343, 1, component_count }); // B3SC
        self.ethereum.mixInto(channel);
        channel.mixU32s(&.{ 0x5348434c, 1, sha.Airs.len }); // SHCL
        for (self.sha, 0..) |claim, i| {
            channel.mixU32s(&.{@intCast(i)});
            channel.mixFelts(&.{claim});
        }
    }
};
