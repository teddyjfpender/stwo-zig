//! Bounded file hashing/copying and JSONL frame output.

const std = @import("std");
const artifact_manifest = @import("stwo").metal_session.artifact_manifest;

pub fn hashFile(allocator: std.mem.Allocator, path: []const u8) ![32]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const buffer = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(buffer);
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    while (true) {
        const count = try file.read(buffer);
        if (count == 0) break;
        digest.update(buffer[0..count]);
    }
    return digest.finalResult();
}

pub fn copyFileExclusive(
    allocator: std.mem.Allocator,
    source_path: []const u8,
    destination_path: []const u8,
    mode: std.posix.mode_t,
) !artifact_manifest.Measurement {
    const source = try std.fs.openFileAbsolute(source_path, .{});
    defer source.close();
    const source_before = try source.stat();
    if (source_before.kind != .file) return error.InvalidCopySource;
    const destination = try std.fs.createFileAbsolute(destination_path, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    });
    var destination_open = true;
    defer if (destination_open) destination.close();
    errdefer std.fs.deleteFileAbsolute(destination_path) catch {};
    const buffer = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(buffer);
    var source_digest = std.crypto.hash.sha2.Sha256.init(.{});
    var copied: u64 = 0;
    while (true) {
        const count = try source.read(buffer);
        if (count == 0) break;
        try destination.writeAll(buffer[0..count]);
        source_digest.update(buffer[0..count]);
        copied = std.math.add(u64, copied, count) catch return error.InvalidCopySource;
    }
    if (copied != source_before.size or
        !artifact_manifest.FileIdentity.fromStat(source_before).eql(
            artifact_manifest.FileIdentity.fromStat(try source.stat()),
        ))
        return error.CopySourceChanged;
    try destination.chmod(mode);
    try destination.sync();
    destination.close();
    destination_open = false;
    const measurement = try artifact_manifest.measureFile(allocator, destination_path);
    if (measurement.bytes != copied or
        !std.mem.eql(u8, &measurement.sha256, &source_digest.finalResult()))
        return error.CopyDigestMismatch;
    return measurement;
}

pub fn writeFrame(writer: *std.Io.Writer, value: anytype) !void {
    try std.json.Stringify.value(value, .{}, writer);
    try writer.writeByte('\n');
    try writer.flush();
}
