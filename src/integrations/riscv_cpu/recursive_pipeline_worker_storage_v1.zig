//! Direct-file custody helpers for the persistent recursive worker.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const io_buffer_bytes: usize = 1024 * 1024;

pub fn objectPathAlloc(
    allocator: std.mem.Allocator,
    store: *const artifact_store.Store,
    ref: artifact_store.BlobRefV1,
) ![]u8 {
    try ref.validate();
    const digest_hex = std.fmt.bytesToHex(ref.sha256, .lower);
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}.blob",
        .{ store.objects_path, digest_hex[0..2], digest_hex },
    );
}

pub fn refForDigest(
    allocator: std.mem.Allocator,
    store: *const artifact_store.Store,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    digest: artifact_store.Digest,
) !artifact_store.BlobRefV1 {
    const digest_hex = std.fmt.bytesToHex(digest, .lower);
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}/{s}.blob",
        .{ store.objects_path, digest_hex[0..2], digest_hex },
    );
    defer allocator.free(path);
    const parent_path = std.fs.path.dirname(path) orelse
        return error.InvalidWorkerArtifactPath;
    const basename = std.fs.path.basename(path);
    var parent = try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true });
    defer parent.close();
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFREG or
        entry.size < 0)
    {
        return error.WorkerArtifactNotRegular;
    }
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        @intCast(entry.size),
        digest,
    );
}

/// Reopens and hashes a CAS object without materializing its bytes.
pub fn exactOpenRef(
    allocator: std.mem.Allocator,
    store: *const artifact_store.Store,
    ref: artifact_store.BlobRefV1,
    diagnostic_path: ?[]const u8,
) !void {
    try ref.validate();
    const expected_path = try objectPathAlloc(allocator, store, ref);
    defer allocator.free(expected_path);
    if (diagnostic_path) |path| {
        // The controller may spell the same private workspace through an OS
        // path alias (for example `/var` versus `/private/var` on macOS).
        // Canonicalize only this diagnostic string, then ignore it: custody is
        // still reopened below from the digest-derived store path with
        // no-follow metadata and a complete content rehash.
        const canonical = std.fs.realpathAlloc(allocator, path) catch
            return error.WorkerInputObjectPathMismatch;
        defer allocator.free(canonical);
        if (!std.mem.eql(u8, canonical, expected_path))
            return error.WorkerInputObjectPathMismatch;
    }
    const parent_path = std.fs.path.dirname(expected_path) orelse
        return error.InvalidWorkerArtifactPath;
    const basename = std.fs.path.basename(expected_path);
    var parent = try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true });
    defer parent.close();
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFREG)
        return error.WorkerArtifactNotRegular;
    var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    const fd = try std.posix.openat(parent.fd, basename, flags, 0);
    const file: std.fs.File = .{ .handle = fd };
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size != ref.byte_count or
        before.mode & 0o222 != 0)
    {
        return error.WorkerArtifactMetadataMismatch;
    }
    const buffer = try allocator.alloc(u8, io_buffer_bytes);
    defer allocator.free(buffer);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var byte_count: u64 = 0;
    while (true) {
        const count = try file.read(buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        byte_count = std.math.add(u64, byte_count, count) catch
            return error.WorkerArtifactTooLarge;
    }
    const after = try file.stat();
    const observed = hash.finalResult();
    if (before.inode != after.inode or before.size != after.size or
        before.mtime != after.mtime or before.ctime != after.ctime or
        byte_count != ref.byte_count or
        !std.mem.eql(u8, &observed, &ref.sha256))
    {
        return error.WorkerArtifactIdentityMismatch;
    }
}

pub fn readSmallRefAlloc(
    _: std.mem.Allocator,
    store: *artifact_store.Store,
    ref: artifact_store.BlobRefV1,
    maximum_bytes: usize,
) ![]u8 {
    var reopened = try store.openBlob(
        ref,
        ref.kind,
        ref.schema_version,
        maximum_bytes,
    );
    const bytes = reopened.bytes;
    reopened = undefined;
    return bytes;
}

pub fn writeExclusive(
    allocator: std.mem.Allocator,
    output_path: []const u8,
    bytes: []const u8,
) !void {
    if (!std.fs.path.isAbsolute(output_path) or output_path.len == 0)
        return error.InvalidWorkerOutputPath;
    const temporary_path = try std.fmt.allocPrint(
        allocator,
        "{s}.worker-{x}.tmp",
        .{ output_path, std.crypto.random.int(u64) },
    );
    defer allocator.free(temporary_path);
    defer std.fs.deleteFileAbsolute(temporary_path) catch {};
    const output = try std.fs.createFileAbsolute(temporary_path, .{
        .exclusive = true,
        .mode = 0o600,
    });
    var open = true;
    defer if (open) output.close();
    try output.writeAll(bytes);
    try output.sync();
    output.close();
    open = false;
    try std.posix.link(temporary_path, output_path);
    std.fs.deleteFileAbsolute(temporary_path) catch {};
}

pub fn ingestTypedPath(
    store: *artifact_store.Store,
    output_path: []const u8,
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
) !artifact_store.BlobRefV1 {
    var snapshot = try store.ingestPath(output_path);
    defer snapshot.deinit(store.allocator);
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        snapshot.measurement.bytes,
        snapshot.measurement.sha256,
    );
}
