//! Device-free preflight for an authenticated core Metal AOT bundle.
//!
//! This is deliberately narrower than runtime admission. It authenticates the
//! manifest against the product's compiled trust anchor and requires the two
//! non-empty compiled artifacts before any code asks Metal for a device. The
//! backend subsequently re-opens and remeasures the complete manifest closure.

const std = @import("std");

pub const manifest_filename = "stwo_zig_core.manifest.json";
pub const manifest_digest_filename = "stwo_zig_core.manifest.sha256";
pub const air_filename = "stwo_zig_core.air";
pub const metallib_filename = "stwo_zig_core.metallib";

pub const Error = error{
    InvalidBundlePath,
    NonCanonicalTrustAnchor,
    ManifestTrustAnchorMismatch,
    EmptyCompiledArtifact,
    UnexpectedCompiledArtifactKind,
};

pub fn validate(
    allocator: std.mem.Allocator,
    absolute_path: []const u8,
    expected_manifest_sha256: [32]u8,
) !void {
    if (absolute_path.len == 0 or !std.fs.path.isAbsolute(absolute_path))
        return error.InvalidBundlePath;

    var directory = try std.fs.openDirAbsolute(absolute_path, .{});
    defer directory.close();
    const manifest = try directory.readFileAlloc(
        allocator,
        manifest_filename,
        1024 * 1024,
    );
    defer allocator.free(manifest);
    const encoded_anchor = try directory.readFileAlloc(
        allocator,
        manifest_digest_filename,
        256,
    );
    defer allocator.free(encoded_anchor);

    const anchor = try parseTrustAnchor(encoded_anchor);
    var measured: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(manifest, &measured, .{});
    if (!std.mem.eql(u8, &anchor, &measured) or
        !std.mem.eql(u8, &measured, &expected_manifest_sha256))
    {
        return error.ManifestTrustAnchorMismatch;
    }

    inline for (.{ air_filename, metallib_filename }) |filename| {
        const stat = try directory.statFile(filename);
        if (stat.kind != .file) return error.UnexpectedCompiledArtifactKind;
        if (stat.size == 0) return error.EmptyCompiledArtifact;
    }
}

fn parseTrustAnchor(encoded: []const u8) Error![32]u8 {
    const suffix = "  " ++ manifest_filename ++ "\n";
    if (encoded.len != 64 + suffix.len or
        !std.mem.eql(u8, encoded[64..], suffix))
    {
        return error.NonCanonicalTrustAnchor;
    }
    for (encoded[0..64]) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.NonCanonicalTrustAnchor;
    }
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded[0..64]) catch
        return error.NonCanonicalTrustAnchor;
    return digest;
}

test "authenticated AOT bundle preflight rejects invalid bundles without touching a device" {
    try std.testing.expectError(error.InvalidBundlePath, validate(
        std.testing.allocator,
        "relative/bundle",
        [_]u8{0} ** 32,
    ));

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);

    try temporary.dir.writeFile(.{
        .sub_path = manifest_filename,
        .data = "{}",
    });
    try temporary.dir.writeFile(.{
        .sub_path = manifest_digest_filename,
        .data = "not-a-canonical-anchor",
    });
    try std.testing.expectError(error.NonCanonicalTrustAnchor, validate(
        std.testing.allocator,
        root,
        [_]u8{0} ** 32,
    ));

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("{}", &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const anchor = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}  {s}\n",
        .{ &digest_hex, manifest_filename },
    );
    defer std.testing.allocator.free(anchor);
    try temporary.dir.writeFile(.{
        .sub_path = manifest_digest_filename,
        .data = anchor,
    });
    try std.testing.expectError(error.ManifestTrustAnchorMismatch, validate(
        std.testing.allocator,
        root,
        [_]u8{1} ** 32,
    ));
}

test "authenticated AOT bundle preflight admits the exact nonempty closure" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const manifest = "{\"schema\":\"test-only\"}";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(manifest, &digest, .{});
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const anchor = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}  {s}\n",
        .{ &digest_hex, manifest_filename },
    );
    defer std.testing.allocator.free(anchor);
    try temporary.dir.writeFile(.{ .sub_path = manifest_filename, .data = manifest });
    try temporary.dir.writeFile(.{ .sub_path = manifest_digest_filename, .data = anchor });
    try temporary.dir.writeFile(.{ .sub_path = air_filename, .data = "air" });
    try temporary.dir.writeFile(.{ .sub_path = metallib_filename, .data = "metallib" });
    try validate(std.testing.allocator, root, digest);
}
