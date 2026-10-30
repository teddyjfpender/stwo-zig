//! Fresh original-STARK verification of an explicitly admitted nonterminal
//! machine window. Uses the original SHA-capable leaf equations and codec;
//! no terminal-v7 or whole-Ethereum verification receipt is synthesized.
const std = @import("std");
const core = @import("stwo_core");
const Scope = @import("block_v7_real_window_statement_v1.zig");
const Capture = @import("block_v7_real_window_capture_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
pub const Manifest = @import("blake3_extension_manifest.zig").ForProfile(Profile);
pub const Limits = struct {
    source: @import("block_v7_initial_intervals_v1.zig").Limits = .{},
    manifest: Manifest.Limits = .{},
    max_proof_bytes: usize = 128 << 20,
};
pub fn For(comptime Backend: type) type {
    const Original = @import("blake3_ethereum_sha_proof.zig");
    const Api = Original.ForBackend(Backend);
    return struct {
        pub fn verify(a: std.mem.Allocator, elf: []const u8, incoming: Capture.Snapshot, outgoing: Capture.Snapshot, trusted: Scope.Trusted, original_input_sha256: Capture.Digest, config: core.pcs.PcsConfig, metadata: []const u8, expected_metadata: Capture.Digest, proof_bytes: []const u8, limits: Limits) ![32]u8 {
            if (proof_bytes.len > limits.max_proof_bytes) return error.RealWindowProofResourceLimit;
            // The metadata identity is independently selected along with the
            // benchmark endpoints, never read from the received proof as its
            // own authority. Geometry is also validated by the original key.
            const scope = try Scope.Statement.derive(a, elf, incoming, outgoing, trusted, limits.source);
            var decoded = try Manifest.decode(a, metadata, expected_metadata, .{ .elf_sha256 = trusted.elf_sha256, .input_sha256 = original_input_sha256 }, config, limits.manifest);
            defer decoded.deinit();
            try scope.admit(decoded.base.statement.value.public_data);
            try scope.admitPlan(incoming, outgoing, &decoded.base.plan);
            const key = if (decoded.base.ranges) |ranges|
                try Api.PreparedVerifier.initCompact(a, &decoded.base.statement.value, decoded.extension, try decoded.base.admission(), config, ranges)
            else
                try Api.PreparedVerifier.init(a, &decoded.base.statement.value, decoded.extension, try decoded.base.admission(), config);
            defer key.deinit();
            try scope.admit(key.native.public_data);
            const proof = try Original.codec.decode(a, proof_bytes, key, key.id);
            return Api.verifyOwned(a, proof, key, key.id);
        }
    };
}
