//! Shared bounded transport I/O. Hash/length pins are not proof authority.
const std = @import("std");
pub fn hash(raw: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &result, .{});
    return result;
}
/// Publish a synced inode without replacing an existing artifact. The same
/// directory holds both names; a successful link is the atomic publication.
pub fn publish(dir: std.fs.Dir, path: []const u8, raw: []const u8) !void {
    return publishParts(dir, path, &.{raw});
}
/// Publish borrowed header/metadata/proof spans without building a second
/// complete envelope. The caller keeps all spans alive through this call.
pub fn publishParts(dir: std.fs.Dir, path: []const u8, parts: []const []const u8) !void {
    const Parts = struct {
        spans: []const []const u8,
        pub fn write(self: @This(), file: std.fs.File) !void {
            for (self.spans) |part| try file.writeAll(part);
        }
    };
    return publishStream(dir, path, Parts{ .spans = parts });
}
/// The emitter writes bounded chunks to a private inode. No destination is
/// published until the complete emitter succeeds and the inode is synced.
/// Publication never replaces an existing artifact; failed writes remove only
/// this call's private temporary file.
pub fn publishStream(dir: std.fs.Dir, path: []const u8, emitter: anytype) !void {
    var buffer: [160]u8 = undefined;
    const temporary = try std.fmt.bufPrint(&buffer, "{s}.part", .{path});
    var file = try dir.createFile(temporary, .{ .exclusive = true });
    var closed = false;
    defer if (!closed) file.close();
    defer dir.deleteFile(temporary) catch {};
    try emitter.write(file);
    try file.sync();
    file.close();
    closed = true;
    std.posix.linkat(dir.fd, temporary, dir.fd, path, 0) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ExistingV5BundleArtifact,
        else => return err,
    };
    errdefer dir.deleteFile(path) catch {};
    try std.posix.fsync(dir.fd);
}
pub fn hashParts(parts: []const []const u8) [32]u8 {
    var state = std.crypto.hash.sha2.Sha256.init(.{});
    for (parts) |part| state.update(part);
    return state.finalResult();
}
pub fn readPinned(a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, byte_len: u64, expected_hash: [32]u8, max_bytes: usize) ![]u8 {
    if (byte_len == 0 or byte_len > max_bytes) return error.V5BundleFileResourceLimit;
    var file = try dir.openFile(path, .{});
    defer file.close();
    if ((try file.stat()).size != byte_len) return error.TamperedV5BundleFileLength;
    const raw = try a.alloc(u8, std.math.cast(usize, byte_len) orelse return error.Overflow);
    errdefer a.free(raw);
    if (try file.readAll(raw) != raw.len) return error.TamperedV5BundleFileLength;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0 or !std.meta.eql(hash(raw), expected_hash)) return error.TamperedV5BundleFileHash;
    return raw;
}
