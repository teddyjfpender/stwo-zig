//! Artifact/admission attacks exercised against the real runner proof.
const std = @import("std");
const core = @import("stwo_core");
const codec = @import("blake3_execution_codec.zig");
pub fn check(comptime Api: type, a: std.mem.Allocator, prepared: *Api.PreparedVerifier, expected: [32]u8, raw: []const u8, digest: [32]u8) !void {
    const changed = try a.dupe(u8, raw);
    defer a.free(changed);
    changed[12] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, codec.decode(a, changed, prepared, expected));
    changed[12] ^= 1;
    changed[8] ^= 1;
    try std.testing.expectError(error.InvalidExecutionArtifactVersion, codec.decode(a, changed, prepared, expected));
    changed[8] ^= 1;
    std.mem.writeInt(u32, changed[codec.HEADER_BYTES..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.InvalidInteractionClaim, codec.decode(a, changed, prepared, expected));
    @memcpy(changed, raw);
    std.mem.writeInt(u32, changed[44..48], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidInteractionClaim, codec.decode(a, changed, prepared, expected));
    try std.testing.expectError(error.InvalidExecutionArtifactLength, codec.decode(a, raw[0 .. raw.len - 1], prepared, expected));
    try std.testing.expectError(error.TruncatedExecutionArtifact, codec.decode(a, raw[0..8], prepared, expected));
    var wrong_pin = expected;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, codec.decode(a, raw, prepared, wrong_pin));
    prepared.key.preprocessed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, prepared.validate(expected));
    prepared.key.preprocessed_root[0] ^= 1;
    prepared.config.fri_config.n_queries += 1;
    try std.testing.expectError(error.UntrustedExecutionKey, prepared.validate(expected));
    prepared.config.fri_config.n_queries -= 1;
    prepared.shape.final_pc += 4;
    try std.testing.expectError(error.InvalidStatement, prepared.validate(expected));
    prepared.shape.final_pc -= 4;
    var bad_root = try codec.decode(a, raw, prepared, expected);
    bad_root.stark.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3Preprocessing, Api.verifyPreparedOwned(a, bad_root, prepared, expected));
    const bad_claim = try codec.decode(a, raw, prepared, expected);
    bad_claim.native_claims.opcode_claims[0][0] = bad_claim.native_claims.opcode_claims[0][0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UnclosedExecutionRelations, Api.verifyPreparedOwned(a, bad_claim, prepared, expected));
    const retained = prepared.hashes.?;
    // Two independent decoded proofs reuse the same prepared verifier. No
    // witness/fixed trace buffers are retained or reconstructed on this path.
    for (0..2) |iteration| {
        const proof = try codec.decode(a, raw, prepared, expected);
        if (iteration == 0) {
            const actual = try Api.verifyPreparedOwned(a, proof, prepared, expected);
            try std.testing.expectEqualSlices(u8, &digest, &actual);
        } else {
            var capture = try Api.verifyPreparedCaptureOwned(a, proof, prepared, expected);
            defer capture.deinit();
            try capture.validate(prepared, expected);
            try std.testing.expectEqualSlices(u8, &digest, &capture.final_channel.digestBytes());
            capture.proof.sampled_values[0] = capture.proof.sampled_values[0].add(core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidExecutionCapture, capture.validate(prepared, expected));
            capture.proof.sampled_values[0] = capture.proof.sampled_values[0].sub(core.fields.qm31.QM31.one());
            var replay = try @import("../recursion/air/blake3_execution_transcript.zig").planReplay(a, prepared, &capture, expected, 2);
            defer replay.deinit();
            try std.testing.expectEqualSlices(u8, &digest, &replay.end.digestBytes());
            const counts = try replay.hashCounts();
            try std.testing.expect(counts.g > 0 and counts.xor > 0);
        }
        try std.testing.expectEqual(retained, prepared.hashes.?);
        try std.testing.expectEqual(@as(usize, 0), retained.columns[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), retained.columns[1].items.len);
    }
}
