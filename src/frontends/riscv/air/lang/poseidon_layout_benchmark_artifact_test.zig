const std = @import("std");
const checked = @import("typed_air_h010_artifacts");
const artifact = @import("poseidon_layout_benchmark_artifact.zig");
const protocol = @import("poseidon_layout_benchmark_protocol.zig");
const vector = @import("poseidon_layout_benchmark_vector.zig");

test "H-010 checked vectors are byte-exact reproducible encodings" {
    inline for (.{
        .{ @as(u8, 10), checked.poseidon_layout_vector_log10 },
        .{ @as(u8, 14), checked.poseidon_layout_vector_log14 },
    }) |fixture| {
        const generated = try vector.encodeAlloc(std.testing.allocator, fixture[0]);
        defer std.testing.allocator.free(generated);
        try std.testing.expectEqualSlices(u8, fixture[1], generated);
        var decoded = try vector.Owned.decodeChecked(
            std.testing.allocator,
            fixture[1],
            fixture[0],
        );
        decoded.deinit();
    }
}

test "H-010 readable vector projection regenerates byte exactly" {
    const rendered = try artifact.renderIndexAlloc(std.testing.allocator);
    defer std.testing.allocator.free(rendered);
    try std.testing.expectEqualStrings(
        checked.poseidon_layout_vector_index,
        rendered,
    );
}

test "H-010 checked vector rejects raw and coherently resealed corruption" {
    const original = checked.poseidon_layout_vector_log10;
    const corrupted = try std.testing.allocator.dupe(u8, original);
    defer std.testing.allocator.free(corrupted);
    corrupted[98] ^= 1;
    try std.testing.expectError(
        error.CorruptVectorSeal,
        vector.Owned.decodeChecked(std.testing.allocator, corrupted, 10),
    );

    const preimage_len: usize = @intCast(protocol.vector_pins[0].preimage_bytes);
    std.crypto.hash.sha2.Sha256.hash(
        corrupted[0..preimage_len],
        corrupted[preimage_len..][0..32],
        .{},
    );
    try std.testing.expectError(
        error.SemanticOutputMismatch,
        vector.Owned.decodeChecked(std.testing.allocator, corrupted, 10),
    );
}

test "H-010 checked vector rejects truncation" {
    const original = checked.poseidon_layout_vector_log10;
    try std.testing.expectError(
        error.ArtifactLengthMismatch,
        vector.Owned.decodeChecked(
            std.testing.allocator,
            original[0 .. original.len - 1],
            10,
        ),
    );
}
