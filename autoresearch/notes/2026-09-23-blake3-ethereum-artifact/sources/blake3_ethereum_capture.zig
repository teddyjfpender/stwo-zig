//! Successful verification receipt; its mutation seal does not replace a STARK.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const universal = @import("../recursion/air/universal_challenges.zig");
const statement = @import("../air/statement.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const Verified = struct {
    allocator: std.mem.Allocator,
    key_id: [32]u8,
    proof: core.verifier.ProofCapture(suite.Hasher),
    native_claims: *statement.RiscVInteractionClaim,
    hash_claims: [@import("blake3_commitment_components.zig").Airs.len]Q,
    extension_claims: @import("guest_precompile/ethereum_types.zig").ExtensionClaim,
    relations: universal.UniversalRelations,
    extension_draws: [26]Q,
    extension_placements: [14]@import("guest_precompile/ethereum_assembly.zig").PlacementDescriptor,
    final_channel: suite.Channel,
    seal: [32]u8,
    pub fn deinit(self: *Verified) void {
        self.proof.deinit(self.allocator);
        self.allocator.destroy(self.native_claims);
        self.* = undefined;
    }
    pub fn identity(self: *const Verified, shape: *const statement.Blake3ExecutionStatement) ![32]u8 {
        try self.relations.validate();
        if (self.native_claims.n_components != shape.n_components or self.native_claims.n_infra != shape.n_infra) return error.InvalidInteractionClaim;
        for (shape.component_descs[0..shape.n_components], 0..) |desc, i| for (try self.native_claims.opcodeClaims(desc.family, i)) |value| try canonical(value);
        for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| for (try self.native_claims.infraClaims(desc.kind, i)) |value| try canonical(value);
        for (self.hash_claims) |value| try canonical(value);
        try self.extension_claims.validateCanonicalFields();
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42334852, 1 }); // B3HR transport receipt
        protocol.mixDigest(&channel, self.key_id);
        protocol.mixDigest(&channel, @import("proof_capture_sha256.zig").compute(&self.proof));
        try protocol.mixClaims(&channel, shape, self.native_claims, &self.hash_claims);
        self.extension_claims.mixInto(&channel);
        for (self.relations.elements) |element| {
            try canonical(element.z);
            try canonical(element.alpha);
            if (!std.meta.eql(element, universal.Elements.init(element.arity, element.z, element.alpha))) return error.InvalidExecutionCapture;
            channel.mixFelts(&.{ element.z, element.alpha });
        }
        for (self.extension_draws) |value| try canonical(value);
        channel.mixFelts(&self.extension_draws);
        for (self.extension_placements) |placement| {
            channel.mixU64(placement.preprocessed_offset);
            channel.mixU64(placement.main_offset);
            channel.mixU64(placement.interaction_offset);
        }
        protocol.mixDigest(&channel, self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const Verified, prepared: anytype, expected: [32]u8) !void {
        try prepared.validate(expected);
        if (!std.mem.eql(u8, &self.key_id, &expected)) return error.UntrustedExecutionKey;
        if (self.proof.commitments.len != 4 or !std.mem.eql(u8, &self.proof.commitments[0], &prepared.root)) return error.InvalidExecutionCapture;
        if (!std.mem.eql(u8, &try self.identity(&prepared.native), &self.seal)) return error.InvalidExecutionCapture;
        try self.extension_claims.validate(&prepared.extension);
    }
};
fn canonical(value: Q) !void {
    for (value.toM31Array()) |word| if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
}
