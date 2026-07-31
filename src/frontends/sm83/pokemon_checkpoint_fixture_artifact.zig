//! Fail-closed loading for the external Pokémon fixture artifacts.

const std = @import("std");

pub fn readPinned(
    allocator: std.mem.Allocator,
    directory: *std.fs.Dir,
    path: []const u8,
    exact_size: usize,
    expected_sha256: []const u8,
) ![]u8 {
    const maximum_size = std.math.add(
        usize,
        exact_size,
        1,
    ) catch return error.PinnedArtifactSizeMismatch;
    const bytes = directory.readFileAlloc(
        allocator,
        path,
        maximum_size,
    ) catch |err| return switch (err) {
        error.FileTooBig => error.PinnedArtifactSizeMismatch,
        else => error.MissingPinnedPokemonCorpus,
    };
    errdefer allocator.free(bytes);
    try validate(bytes, exact_size, expected_sha256);
    return bytes;
}

fn validate(
    bytes: []const u8,
    exact_size: usize,
    expected_sha256: []const u8,
) !void {
    if (bytes.len != exact_size) return error.PinnedArtifactSizeMismatch;
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    var expected: [32]u8 = undefined;
    if (expected_sha256.len != expected.len * 2)
        return error.InvalidPinnedDigest;
    _ = std.fmt.hexToBytes(&expected, expected_sha256) catch
        return error.InvalidPinnedDigest;
    if (!std.mem.eql(u8, &actual, &expected))
        return error.ContentDigestMismatch;
}

test "pinned artifacts fail closed on size and digest" {
    const empty_sha256 =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    try validate("", 0, empty_sha256);
    try std.testing.expectError(
        error.PinnedArtifactSizeMismatch,
        validate("x", 0, empty_sha256),
    );
    try std.testing.expectError(
        error.ContentDigestMismatch,
        validate(
            "",
            0,
            "03b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    );
}
