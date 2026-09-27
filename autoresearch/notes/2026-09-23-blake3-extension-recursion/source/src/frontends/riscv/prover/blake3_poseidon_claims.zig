//! Detailed guest claims, independently checked against admitted AIR geometry.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const guest = @import("../air/guest_precompile/statement.zig");
const registry = @import("../air/guest_precompile/component_registry.zig");
const Caller = @import("../air/guest_precompile/caller_component.zig");
const Provider = @import("../air/guest_precompile/provider_component.zig");
const wire = @import("guest_precompile/proof_artifact_wire.zig");
pub const ExtensionClaim = struct {
    caller: Caller.Claim,
    provider: Provider.Claim,
    pub fn zeroForStatement(statement: *const guest.ExtensionStatement) !ExtensionClaim {
        return canonical(statement, @splat(Q.zero()), @splat(Q.zero()));
    }
    pub fn canonical(statement: *const guest.ExtensionStatement, caller: [Caller.batch_count]Q, provider: [Provider.batch_count]Q) !ExtensionClaim {
        try statement.validateGeometry();
        const authority = registry.Registry.forProfile(statement.profile);
        const result = ExtensionClaim{
            .caller = try Caller.Claim.canonical((try authority.verifierConstruction(statement.components[0])).caller, caller),
            .provider = try Provider.Claim.canonical((try authority.verifierConstruction(statement.components[1])).provider, provider),
        };
        try result.validate(statement);
        return result;
    }
    pub fn validate(self: *const ExtensionClaim, statement: *const guest.ExtensionStatement) !void {
        try statement.validateGeometry();
        const authority = registry.Registry.forProfile(statement.profile);
        try self.caller.validate((try authority.verifierConstruction(statement.components[0])).caller);
        try self.provider.validate((try authority.verifierConstruction(statement.components[1])).provider);
        if (!self.caller.batch_sums[Caller.batch_count - 1].add(self.provider.batch_sums[Provider.batch_count - 1]).isZero()) return error.UnbalancedGuestRelation;
    }
    pub fn validateCanonicalFields(self: *const ExtensionClaim) !void {
        inline for (.{ self.caller, self.provider }) |claim| {
            for (claim.batch_sums) |value| try canonicalField(value);
            try canonicalField(claim.component_sum);
        }
    }
    pub const ComponentClaimView = struct { detailed: []const Q, total: Q, has_batch_frame: bool = true };
    pub fn componentClaims(self: *const ExtensionClaim) [2]ComponentClaimView {
        return .{ .{ .detailed = &self.caller.batch_sums, .total = self.caller.component_sum }, .{ .detailed = &self.provider.batch_sums, .total = self.provider.component_sum } };
    }
    pub fn componentSum(self: *const ExtensionClaim) Q {
        return self.caller.component_sum.add(self.provider.component_sum);
    }
    pub fn mixInto(self: *const ExtensionClaim, channel: anytype) void {
        channel.mixU32s(&.{ 0x42335043, 1, 2 }); // B3PC
        inline for (.{ self.caller, self.provider }) |claim| {
            channel.mixU64(claim.batch_sums.len);
            channel.mixFelts(&claim.batch_sums);
            channel.mixFelts(&.{claim.component_sum});
        }
    }
};
fn canonicalField(value: Q) !void {
    for (value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
}
pub fn encodeExtensionClaim(writer: anytype, statement: *const guest.ExtensionStatement, claim: *const ExtensionClaim) !void {
    try claim.validateCanonicalFields();
    try claim.validate(statement);
    inline for (.{ claim.caller, claim.provider }) |component| {
        for (component.batch_sums) |value| try wire.writeQm31(writer, value);
        try wire.writeQm31(writer, component.component_sum);
    }
}
pub fn decodeExtensionClaim(cursor: *wire.Cursor, statement: *const guest.ExtensionStatement) !ExtensionClaim {
    var result = try ExtensionClaim.zeroForStatement(statement);
    inline for (.{ "caller", "provider" }) |name| {
        const claim = &@field(result, name);
        for (&claim.batch_sums) |*value| value.* = try cursor.readQm31();
        claim.component_sum = try cursor.readQm31();
    }
    try result.validate(statement);
    return result;
}
