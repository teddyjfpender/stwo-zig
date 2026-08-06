const std = @import("std");
const reviewed = @import("typed_air_h009_artifacts");
const frontier = @import("materialization_frontier_manifest.zig");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");
const poseidon_fixed = @import("typed_poseidon2_fixed_direct.zig");
const vector = @import("poseidon_layout_benchmark_vector.zig");

test "H-010 protocol authenticates the exact reviewed H-009 artifact" {
    var decoded = try frontier.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();
    try protocol.authenticateArtifact(
        reviewed.h009_poseidon2_frontier,
        decoded.view(),
    );
}

test "H-010 protocol rejects raw artifact corruption before decoded authority" {
    var decoded = try frontier.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();
    const corrupted = try std.testing.allocator.dupe(
        u8,
        reviewed.h009_poseidon2_frontier,
    );
    defer std.testing.allocator.free(corrupted);
    corrupted[corrupted.len - 1] ^= 1;
    try std.testing.expectError(
        error.ArtifactDigestMismatch,
        protocol.authenticateArtifact(corrupted, decoded.view()),
    );
}

test "H-010 protocol rejects decoded identity corruption" {
    var decoded = try frontier.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();
    var manifest = decoded.view();
    manifest.identity.identity_digest[0] ^= 1;
    try std.testing.expectError(
        error.DigestMismatch,
        protocol.authenticateArtifact(
            reviewed.h009_poseidon2_frontier,
            manifest,
        ),
    );
}

test "H-010 protocol rejects copied geometry corruption" {
    var decoded = try frontier.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();
    var manifest = decoded.view();
    manifest.geometry.base_main_columns += 1;
    try std.testing.expectError(
        error.InconsistentCost,
        protocol.authenticateArtifact(
            reviewed.h009_poseidon2_frontier,
            manifest,
        ),
    );
}

test "H-010 vectors regenerate to every sealed measurement identity" {
    inline for (.{ @as(u8, 10), @as(u8, 14), @as(u8, 18) }) |log_size| {
        const identity = try vector.generatedIdentity(
            std.testing.allocator,
            log_size,
        );
        try protocol.authenticateVector(identity);
    }
}

test "H-010 vector and trace identity corruption fail closed" {
    var identity = try vector.generatedIdentity(std.testing.allocator, 10);
    identity.vector_seal[0] ^= 1;
    try std.testing.expectError(
        error.VectorIdentityMismatch,
        protocol.authenticateVector(identity),
    );
    identity.vector_seal[0] ^= 1;
    identity.vector_artifact_sha256[0] ^= 1;
    try std.testing.expectError(
        error.VectorIdentityMismatch,
        protocol.authenticateVector(identity),
    );
    identity.vector_artifact_sha256[0] ^= 1;
    identity.artifact_bytes += 1;
    try std.testing.expectError(
        error.VectorGeometryMismatch,
        protocol.authenticateVector(identity),
    );

    var trace: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &trace,
        protocol.vector_pins[0].trace_digest_hex[0],
    );
    try protocol.authenticateTrace(.compat_seed, 10, trace);
    trace[0] ^= 1;
    try std.testing.expectError(
        error.VectorIdentityMismatch,
        protocol.authenticateTrace(.compat_seed, 10, trace),
    );
}

test "H-010 executes the exact canonical and artifact fixed-program digest" {
    var decoded = try frontier.decodeAlloc(
        std.testing.allocator,
        reviewed.h009_poseidon2_frontier,
    );
    defer decoded.deinit();
    var actual = try poseidon_fixed.program.digestValue(std.testing.allocator);
    try protocol.authenticateFixedProgramDigest(
        actual,
        decoded.view().cost_model.fixed_program_digest,
    );
    actual[0] ^= 1;
    try std.testing.expectError(
        error.FixedProgramDigestMismatch,
        protocol.authenticateFixedProgramDigest(
            actual,
            decoded.view().cost_model.fixed_program_digest,
        ),
    );
}
