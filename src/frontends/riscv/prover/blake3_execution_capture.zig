//! Successful execution verification receipt for recursive witness preparation.
//! The seal detects sidecar mutation; it is not a substitute for STARK verification.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const universal = @import("../recursion/air/universal_challenges.zig");
const statement = @import("../air/statement.zig");
const protocol = @import("blake3_execution_protocol.zig");
pub const Verified = struct {
    allocator: std.mem.Allocator,
    key_id: [32]u8,
    proof: core.verifier.ProofCapture(suite.Hasher),
    native_claims: *statement.RiscVInteractionClaim,
    hash_claims: [@import("blake3_commitment_components.zig").Airs.len]core.fields.qm31.QM31,
    ranges: ?@import("../recursion/air/compact_range_geometry.zig").Plan = null,
    compact_claims: [3]core.fields.qm31.QM31 = @splat(core.fields.qm31.QM31.zero()),
    relations: universal.UniversalRelations,
    final_channel: suite.Channel,
    seal: [32]u8,
    pub fn deinit(self: *Verified) void {
        self.proof.deinit(self.allocator);
        self.allocator.destroy(self.native_claims);
        self.* = undefined;
    }
    pub fn identity(self: *const Verified, shape: *const statement.Blake3ExecutionStatement) ![32]u8 {
        try self.relations.validate();
        if (self.ranges) |ranges| {
            try ranges.validate();
        } else {
            for (self.compact_claims) |claim| {
                if (!claim.isZero()) return error.InvalidExecutionCapture;
            }
        }
        for (self.compact_claims) |claim| for (claim.toM31Array()) |word| {
            if (word.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
        };
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42334552, 1 }); // B3ER transport receipt
        protocol.mixDigest(&channel, self.key_id);
        protocol.mixDigest(&channel, @import("proof_capture_sha256.zig").compute(&self.proof));
        try protocol.mixClaims(&channel, shape, self.native_claims, &self.hash_claims);
        if (self.ranges) |ranges| {
            try @import("compact_range_codec.zig").mixAdmitted(&channel, ranges, try ranges.identity());
            channel.mixFelts(&self.compact_claims);
        }
        for (self.relations.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        protocol.mixDigest(&channel, self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const Verified, prepared: anytype, expected: [32]u8) !void {
        try prepared.validate(expected);
        if (!std.meta.eql(self.ranges, prepared.ranges)) return error.InvalidExecutionCapture;
        if (!std.mem.eql(u8, &self.key_id, &expected)) return error.UntrustedExecutionKey;
        if (self.proof.commitments.len != 4 or !std.mem.eql(u8, &self.proof.commitments[0], &prepared.key.preprocessed_root)) return error.InvalidExecutionCapture;
        if (!std.mem.eql(u8, &try self.identity(&prepared.shape), &self.seal)) return error.InvalidExecutionCapture;
    }
};
