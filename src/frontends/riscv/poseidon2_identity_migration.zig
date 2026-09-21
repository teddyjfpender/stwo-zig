//! Offline migration of an independently pinned compact-Poseidon parent key.
//! Public inputs, PCS parameters, preprocessing and geometry remain unchanged.
//! Child pins must come from the independently reviewed admission tree.
const std = @import("std");
const protocol = @import("recursion/detached_parent_protocol_v1.zig");
const manifest_mod = @import("recursion/air/universal_adapter_manifest.zig");
const identity = @import("air/memory_commitment/poseidon2_universal_identity_v2.zig");

fn digest(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.ExpectedSha256;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 6) return error.ExpectedOldKeyOldHashLeftPinRightPinOutput;
    const bytes = try std.fs.cwd().readFileAlloc(allocator, args[1], 64 * 1024 * 1024);
    defer allocator.free(bytes);
    var actual: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &actual, .{});
    if (!std.mem.eql(u8, &actual, &try digest(args[2]))) return error.KeyHashMismatch;
    const parsed = try std.json.parseFromSlice(protocol.KeyV1, allocator, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    var key = parsed.value;
    try key.validate();
    const old = try key.manifest.placement(.poseidon2);
    if (!std.mem.eql(u8, &old.geometry.semantic_digest, &identity.LEGACY_SOURCE_DIGEST)) return error.ExpectedReviewedLegacyIdentity;
    try identity.validateAdmission(allocator, old.geometry.semantic_digest, .allow_reviewed_legacy);
    var builder = manifest_mod.Builder{};
    for (key.manifest.roster_rows[0..key.manifest.roster_count]) |row| {
        var geometry = key.manifest.placements[row].?.geometry;
        if (row == old.geometry.roster_row) geometry.semantic_digest = identity.CANONICAL_DIGEST;
        _ = try builder.append(geometry);
    }
    key.manifest = try builder.seal();
    key.child_key_sha256 = .{ try digest(args[3]), try digest(args[4]) };
    try key.validate();
    const output = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(output);
    var file = try std.fs.cwd().createFile(args[5], .{ .exclusive = true });
    defer file.close();
    try file.writeAll(output);
}
