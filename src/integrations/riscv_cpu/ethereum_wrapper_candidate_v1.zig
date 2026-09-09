//! Durable canonical artifact custody after core verification and before wrapper
//! admission. Metadata is not a verification receipt; replay must coldOpen.
const std = @import("std");
const resources = @import("ethereum_wrapper_resources_v1.zig");
const MAX_BYTES = 512 * 1024 * 1024;
const Metadata = struct {
    format_version: u32,
    core_verified: bool,
    wrapper_admitted: bool,
    artifact_sha256: []const u8,
    artifact_bytes: usize,
};

/// Call only with OwnedArtifact canonical bytes returned by the verified core.
/// This function records that stage; it cannot create wrapper admission.
pub fn retain(allocator: std.mem.Allocator, canonical_artifact_bytes: []const u8) !void {
    const corpus = std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_PROOF_CORPUS") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer allocator.free(corpus);
    if (corpus.len == 0) return;
    const path = try std.fs.path.join(allocator, &.{ corpus, "wrapper-candidates" });
    defer allocator.free(path);
    var directory = try std.fs.cwd().makeOpenPath(path, .{});
    defer directory.close();
    const hex = try retainInDirectory(allocator, directory, canonical_artifact_bytes);
    resources.progress("ETHEREUM_WRAPPER_CANDIDATE_RETAINED core_verified=true wrapper_admitted=false sha256={s} bytes={d} directory={s}\n", .{ hex, canonical_artifact_bytes.len, path });
}

fn retainInDirectory(allocator: std.mem.Allocator, directory: std.fs.Dir, bytes: []const u8) ![64]u8 {
    if (bytes.len == 0 or bytes.len > MAX_BYTES) return error.InvalidWrapperCandidate;
    const hex = digestHex(bytes);
    var bin_name: [68]u8 = undefined;
    _ = try std.fmt.bufPrint(&bin_name, "{s}.bin", .{hex});
    try writeDurable(directory, &bin_name, bytes);
    const metadata = try std.json.Stringify.valueAlloc(allocator, Metadata{
        .format_version = 1,
        .core_verified = true,
        .wrapper_admitted = false,
        .artifact_sha256 = &hex,
        .artifact_bytes = bytes.len,
    }, .{ .whitespace = .indent_2 });
    defer allocator.free(metadata);
    var metadata_name: [69]u8 = undefined;
    _ = try std.fmt.bufPrint(&metadata_name, "{s}.json", .{hex});
    try writeDurable(directory, &metadata_name, metadata);
    return hex;
}

fn writeDurable(directory: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    var file = try directory.createFile(name, .{});
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}

/// Returns custody-checked bytes, never a verified wrapper capability.
pub fn load(allocator: std.mem.Allocator, bin_path: []const u8) ![]u8 {
    const basename = std.fs.path.basename(bin_path);
    if (basename.len != 68 or !std.mem.endsWith(u8, basename, ".bin"))
        return error.InvalidWrapperCandidate;
    const expected_hex = basename[0..64];
    for (expected_hex) |char| if (!(char >= '0' and char <= '9') and !(char >= 'a' and char <= 'f'))
        return error.InvalidWrapperCandidate;
    const metadata_path = try std.fmt.allocPrint(allocator, "{s}.json", .{bin_path[0 .. bin_path.len - 4]});
    defer allocator.free(metadata_path);
    const metadata_bytes = try std.fs.cwd().readFileAlloc(allocator, metadata_path, 64 * 1024);
    defer allocator.free(metadata_bytes);
    const metadata = try std.json.parseFromSlice(Metadata, allocator, metadata_bytes, .{});
    defer metadata.deinit();
    const value = metadata.value;
    if (value.format_version != 1 or !value.core_verified or value.wrapper_admitted or
        value.artifact_bytes == 0 or value.artifact_bytes > MAX_BYTES or
        !std.mem.eql(u8, value.artifact_sha256, expected_hex))
        return error.InvalidWrapperCandidate;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, bin_path, MAX_BYTES);
    errdefer allocator.free(bytes);
    if (bytes.len != value.artifact_bytes or !std.mem.eql(u8, &digestHex(bytes), expected_hex))
        return error.InvalidWrapperCandidate;
    return bytes;
}

fn digestHex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

test "Ethereum wrapper candidate custody rejects altered metadata path and bytes" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    // A custody probe exercises no verifier and is never claimed as a proof.
    const payload = "canonical-artifact-custody-probe";
    const hex = try retainInDirectory(allocator, temporary.dir, payload);
    const directory = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(directory);
    const bin_path = try std.fmt.allocPrint(allocator, "{s}/{s}.bin", .{ directory, hex });
    defer allocator.free(bin_path);
    const loaded = try load(allocator, bin_path);
    defer allocator.free(loaded);
    try std.testing.expectEqualStrings(payload, loaded);
    const metadata_path = try std.fmt.allocPrint(allocator, "{s}/{s}.json", .{ directory, hex });
    defer allocator.free(metadata_path);
    const original = Metadata{ .format_version = 1, .core_verified = true, .wrapper_admitted = false, .artifact_sha256 = &hex, .artifact_bytes = payload.len };
    for (0..5) |index| {
        var changed = original;
        switch (index) {
            0 => changed.core_verified = false,
            1 => changed.wrapper_admitted = true,
            2 => changed.artifact_bytes += 1,
            3 => changed.artifact_sha256 = "00",
            4 => changed.format_version = 2,
            else => unreachable,
        }
        const json = try std.json.Stringify.valueAlloc(allocator, changed, .{});
        defer allocator.free(json);
        try std.fs.cwd().writeFile(.{ .sub_path = metadata_path, .data = json });
        try std.testing.expectError(error.InvalidWrapperCandidate, load(allocator, bin_path));
    }
    _ = try retainInDirectory(allocator, temporary.dir, payload);
    const corrupted = try allocator.dupe(u8, payload);
    defer allocator.free(corrupted);
    corrupted[0] ^= 1;
    try std.fs.cwd().writeFile(.{ .sub_path = bin_path, .data = corrupted });
    try std.testing.expectError(error.InvalidWrapperCandidate, load(allocator, bin_path));
    const malformed = try allocator.dupe(u8, bin_path);
    defer allocator.free(malformed);
    malformed[malformed.len - 68] = 'G';
    try std.testing.expectError(error.InvalidWrapperCandidate, load(allocator, malformed));
    // Even a well-formed different hash path cannot rename this candidate.
    _ = try retainInDirectory(allocator, temporary.dir, payload);
    malformed[malformed.len - 68] = if (bin_path[bin_path.len - 68] == '0') '1' else '0';
    const renamed_meta = try std.fmt.allocPrint(allocator, "{s}.json", .{malformed[0 .. malformed.len - 4]});
    defer allocator.free(renamed_meta);
    const json = try std.json.Stringify.valueAlloc(allocator, original, .{});
    defer allocator.free(json);
    try std.fs.cwd().writeFile(.{ .sub_path = renamed_meta, .data = json });
    try std.testing.expectError(error.InvalidWrapperCandidate, load(allocator, malformed));
}
