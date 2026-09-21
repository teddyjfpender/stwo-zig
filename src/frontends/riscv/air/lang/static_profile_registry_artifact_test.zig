const std = @import("std");
const artifact_mod = @import("static_profile_registry_artifact.zig");
const checked = @import("typed_air_artifacts");
const registry = @import("static_profile_registry.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

test "P-002 reviewed native family profiles regenerate byte exactly" {
    var artifact = try artifact_mod.generate(std.testing.allocator);
    defer artifact.deinit();

    try std.testing.expectEqualStrings(
        checked.p002_native_family_static_profile_machine,
        artifact.machine,
    );
    try std.testing.expectEqualStrings(
        checked.p002_native_family_static_profile_readable,
        artifact.readable,
    );
    try expectDigest(
        "e61540ffbb0ebc35379fb1bc2d0c160e4c9f707b584687b53d4486b7f54f0f2a",
        artifact.machine,
    );
    try expectDigest(
        "d112808bd5676ab1955302910ee5bc450fc30eff44cf4e1f48bb5e230d98f87c",
        artifact.readable,
    );
}

test "P-002 reviewed projection comparison rejects corruption and truncation" {
    const expected = checked.p002_native_family_static_profile_machine;
    try artifact_mod.checkProjection(expected, expected);

    const corrupted = try std.testing.allocator.dupe(u8, expected);
    defer std.testing.allocator.free(corrupted);
    corrupted[corrupted.len / 2] ^= 1;
    try std.testing.expectError(
        error.ArtifactMismatch,
        artifact_mod.checkProjection(expected, corrupted),
    );
    try std.testing.expectError(
        error.ArtifactMismatch,
        artifact_mod.checkProjection(expected, expected[0 .. expected.len - 1]),
    );
}

test "P-002 reviewed projection cleans every introduced allocation failure" {
    const report = try registry.collect(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        renderFailureCase,
        .{&report},
    );
}

fn renderFailureCase(
    allocator: std.mem.Allocator,
    report: *const registry.Report,
) !void {
    var artifact = try artifact_mod.render(allocator, report);
    defer artifact.deinit();
}

fn expectDigest(expected: []const u8, bytes: []const u8) !void {
    var actual: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &actual, .{});
    try std.testing.expectEqualStrings(
        expected,
        &std.fmt.bytesToHex(actual, .lower),
    );
}
