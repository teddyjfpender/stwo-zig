//! Fail-closed filesystem custody for Ethereum proof artifacts.

const std = @import("std");

const ExistingFileMode = enum { read_only, read_write };

pub const ethereum_leaf_source_basename = "leaf-sources";

/// Canonicalizes one CLI filesystem argument before it becomes retained
/// authority. Build runners commonly pass generated inputs as relative paths;
/// publications and embedded identities always use this absolute form.
pub fn resolveAbsolute(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]u8 {
    if (path.len == 0) return error.InvalidArtifactPath;
    const resolved = if (std.fs.path.isAbsolute(path))
        try std.fs.path.resolve(allocator, &.{path})
    else resolved: {
        const cwd = try std.process.getCwdAlloc(allocator);
        defer allocator.free(cwd);
        break :resolved try std.fs.path.resolve(allocator, &.{ cwd, path });
    };
    errdefer allocator.free(resolved);
    if (!std.fs.path.isAbsolute(resolved)) return error.AbsolutePathRequired;
    return resolved;
}

/// Resolves one pre-created controller directory to a fresh, single-component
/// publication child without allowing absolute or traversing basenames.
pub fn resolveCreateOnlyChild(
    allocator: std.mem.Allocator,
    parent: []const u8,
    basename: []const u8,
) ![]u8 {
    if (basename.len == 0 or std.fs.path.isAbsolute(basename) or
        !std.mem.eql(u8, basename, std.fs.path.basename(basename)) or
        std.mem.indexOfAny(u8, basename, "/\\") != null or
        std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, ".."))
    {
        return error.InvalidOutputPath;
    }
    const resolved_parent = try resolveAbsolute(allocator, parent);
    defer allocator.free(resolved_parent);
    return std.fs.path.join(allocator, &.{ resolved_parent, basename });
}

/// Creates one final directory entry exactly once after opening every parent
/// component without following symlinks. The newly created directory is then
/// reopened and inode-checked before a caller may publish beneath it.
pub fn createDirectoryCreateOnly(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) return error.AbsolutePathRequired;
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, "..")) return error.InvalidOutputPath;
    const parent_path = std.fs.path.dirname(path) orelse
        return error.InvalidOutputPath;
    var parent = try openDirectoryPathNoFollow(parent_path);
    defer parent.close();

    try std.posix.mkdirat(parent.fd, basename, 0o700);
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFDIR)
        return error.InvalidArtifactDirectory;
    var created = try parent.openDir(basename, .{ .no_follow = true });
    defer created.close();
    const opened = try created.stat();
    if (opened.kind != .directory or opened.inode != entry.ino)
        return error.ArtifactPathChanged;
    try std.posix.fsync(parent.fd);
}

fn openDirectoryPathNoFollow(path: []const u8) !std.fs.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.AbsolutePathRequired;
    var current = try std.fs.openDirAbsolute("/", .{ .no_follow = true });
    errdefer current.close();
    var components = std.mem.tokenizeScalar(u8, path, std.fs.path.sep);
    while (components.next()) |component| {
        if (std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidArtifactPath;
        }
        const next = try current.openDir(component, .{ .no_follow = true });
        current.close();
        current = next;
    }
    return current;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, "..")) return error.InvalidOutputPath;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try std.fs.openDirAbsolute(parent_path, .{})
    else
        try std.fs.cwd().openDir(parent_path, .{});
    defer parent.close();
    var file = try parent.createFile(basename, .{
        .read = false,
        .truncate = false,
        .exclusive = true,
    });
    var published = false;
    defer {
        file.close();
        if (!published) parent.deleteFile(basename) catch {};
    }
    try file.writeAll(bytes);
    try file.sync();
    published = true;
}

/// Create-only publication whose directory entry is durable before return.
pub fn publishCreateOnlyDurable(path: []const u8, bytes: []const u8) !void {
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, "..")) return error.InvalidOutputPath;
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true })
    else
        try std.fs.cwd().openDir(parent_path, .{ .no_follow = true });
    defer parent.close();
    var file = try parent.createFile(basename, .{
        .read = false,
        .truncate = false,
        .exclusive = true,
    });
    var file_open = true;
    var published = false;
    defer {
        if (file_open) file.close();
        if (!published) parent.deleteFile(basename) catch {};
    }
    try file.writeAll(bytes);
    try file.sync();
    file.close();
    file_open = false;
    try std.posix.fsync(parent.fd);
    published = true;
}

/// Appends one already-canonical journal record and durably publishes it.
pub fn appendDurable(path: []const u8, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n')
        return error.InvalidJournalRecord;
    const basename = std.fs.path.basename(path);
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true })
    else
        try std.fs.cwd().openDir(parent_path, .{ .no_follow = true });
    defer parent.close();
    var file = try openRegularNoFollow(parent, basename, .read_write);
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file) return error.InvalidJournalFile;
    try file.seekFromEnd(0);
    try file.writeAll(bytes);
    try file.sync();
    const after = try file.stat();
    if (after.size != before.size + bytes.len or before.inode != after.inode)
        return error.JournalPublicationMismatch;
    try std.posix.fsync(parent.fd);
}

pub fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    const basename = std.fs.path.basename(path);
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try std.fs.openDirAbsolute(parent_path, .{ .no_follow = true })
    else
        try std.fs.cwd().openDir(parent_path, .{ .no_follow = true });
    defer parent.close();
    var file = try openRegularNoFollow(parent, basename, .read_only);
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size > max_bytes)
        return error.ArtifactResourceLimitExceeded;
    const length = std.math.cast(usize, before.size) orelse
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.UnexpectedEndOfFile;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.ArtifactChangedDuringRead;
    const after = try file.stat();
    if (before.size != after.size or before.inode != after.inode or
        before.mtime != after.mtime)
    {
        return error.ArtifactChangedDuringRead;
    }
    return bytes;
}

/// Opens an existing regular file without following its final path component.
/// The `fstatat`/`fstat` identity comparison also closes a rename race between
/// inspecting the directory entry and acquiring the descriptor.
fn openRegularNoFollow(
    parent: std.fs.Dir,
    basename: []const u8,
    mode: ExistingFileMode,
) !std.fs.File {
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, "..")) return error.InvalidArtifactPath;
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFREG)
        return error.InvalidArtifactFile;

    var flags: std.posix.O = .{
        .ACCMODE = switch (mode) {
            .read_only => .RDONLY,
            .read_write => .RDWR,
        },
    };
    if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(std.posix.O, "NOFOLLOW")) flags.NOFOLLOW = true;
    const fd = try std.posix.openat(parent.fd, basename, flags, 0);
    errdefer std.posix.close(fd);
    const file = std.fs.File{ .handle = fd };
    const opened = try file.stat();
    if (opened.kind != .file or opened.inode != entry.ino)
        return error.ArtifactPathChanged;
    return file;
}

pub fn executableSha256(allocator: std.mem.Allocator) ![32]u8 {
    const path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(path);
    const bytes = try readFileBounded(allocator, path, 512 * 1024 * 1024);
    defer allocator.free(bytes);
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

pub fn transcriptReceiptDigest(
    channel_digest: [32]u8,
    draw_count: u32,
) [32]u8 {
    var draw_count_le: [4]u8 = undefined;
    std.mem.writeInt(u32, &draw_count_le, draw_count, .little);
    var hasher = @import("stwo_core").vcs.blake2_hash.Blake2sHasher.init();
    hasher.update("stwo-zig/riscv/transcript-state/v1");
    hasher.update(&channel_digest);
    hasher.update(&draw_count_le);
    return hasher.finalize();
}

test "Ethereum artifact publication is create-only" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "artifact.stw", .data = "" });
    const path = try temporary.dir.realpathAlloc(allocator, "artifact.stw");
    defer allocator.free(path);
    try temporary.dir.deleteFile("artifact.stw");
    try publishCreateOnly(path, "first");
    try std.testing.expectError(
        error.PathAlreadyExists,
        publishCreateOnly(path, "conflict"),
    );
    const retained = try readFileBounded(allocator, path, 16);
    defer allocator.free(retained);
    try std.testing.expectEqualStrings("first", retained);
}

test "Ethereum artifact bounded reader rejects a non-file" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const path = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(path);
    try std.testing.expectError(
        error.InvalidArtifactFile,
        readFileBounded(allocator, path, 16),
    );
}

test "Ethereum artifact CLI paths resolve to absolute retained authority" {
    const allocator = std.testing.allocator;
    const cwd = try std.process.getCwdAlloc(allocator);
    defer allocator.free(cwd);
    const expected_relative = try std.fs.path.resolve(
        allocator,
        &.{ cwd, "relative/path" },
    );
    defer allocator.free(expected_relative);
    const relative = try resolveAbsolute(
        allocator,
        "relative/./nested/../path",
    );
    defer allocator.free(relative);
    try std.testing.expect(std.fs.path.isAbsolute(relative));
    try std.testing.expectEqualStrings(expected_relative, relative);

    const absolute = try resolveAbsolute(
        allocator,
        "/tmp/./future/../retained",
    );
    defer allocator.free(absolute);
    try std.testing.expect(std.fs.path.isAbsolute(absolute));
    try std.testing.expectEqualStrings("/tmp/retained", absolute);

    const root_boundary = try resolveAbsolute(
        allocator,
        "/../../../../retained",
    );
    defer allocator.free(root_boundary);
    try std.testing.expect(std.fs.path.isAbsolute(root_boundary));
    try std.testing.expectEqualStrings("/retained", root_boundary);
}

test "Ethereum artifact directory publication is fresh and create-only" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const path = try resolveCreateOnlyChild(
        allocator,
        root,
        ethereum_leaf_source_basename,
    );
    defer allocator.free(path);

    try createDirectoryCreateOnly(path);
    var retained = try std.fs.openDirAbsolute(path, .{ .no_follow = true });
    defer retained.close();
    try std.testing.expectEqual(std.fs.File.Kind.directory, (try retained.stat()).kind);
    try std.testing.expectError(
        error.PathAlreadyExists,
        createDirectoryCreateOnly(path),
    );
    inline for (&.{ "", ".", "..", "nested/leaf", "nested\\leaf" }) |bad| {
        try std.testing.expectError(
            error.InvalidOutputPath,
            resolveCreateOnlyChild(allocator, root, bad),
        );
    }
    const file_path = try std.fs.path.join(allocator, &.{ root, "regular" });
    defer allocator.free(file_path);
    try temporary.dir.writeFile(.{ .sub_path = "regular", .data = "sealed" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        createDirectoryCreateOnly(file_path),
    );
}

test "Ethereum artifact directory publication rejects symlink custody" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.makeDir("real-parent");
    try temporary.dir.symLink("real-parent", "linked-parent", .{
        .is_directory = true,
    });
    try temporary.dir.symLink("real-parent", "final-link", .{
        .is_directory = true,
    });
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const linked_parent = try std.fs.path.join(
        allocator,
        &.{ root, "linked-parent", "forbidden" },
    );
    defer allocator.free(linked_parent);
    const final_link = try std.fs.path.join(
        allocator,
        &.{ root, "final-link" },
    );
    defer allocator.free(final_link);

    if (createDirectoryCreateOnly(linked_parent)) |_| {
        return error.SymlinkWasAccepted;
    } else |_| {}
    if (createDirectoryCreateOnly(final_link)) |_| {
        return error.SymlinkWasAccepted;
    } else |_| {}
    try std.testing.expectError(
        error.FileNotFound,
        temporary.dir.openDir("real-parent/forbidden", .{}),
    );
}

test "Ethereum artifact reader and appender reject final symlinks" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "target", .data = "sealed\n" });
    try temporary.dir.symLink("target", "link", .{});
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const link = try std.fs.path.join(allocator, &.{ root, "link" });
    defer allocator.free(link);

    if (readFileBounded(allocator, link, 32)) |accepted| {
        allocator.free(accepted);
        return error.SymlinkWasAccepted;
    } else |_| {}
    if (appendDurable(link, "forbidden\n")) |_| {
        return error.SymlinkWasAccepted;
    } else |_| {}

    const retained = try temporary.dir.readFileAlloc(allocator, "target", 32);
    defer allocator.free(retained);
    try std.testing.expectEqualStrings("sealed\n", retained);
}

test "Ethereum artifact reader and appender reject a symlinked parent" {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.makeDir("real");
    try temporary.dir.writeFile(.{ .sub_path = "real/target", .data = "sealed\n" });
    try temporary.dir.symLink("real", "linked-parent", .{ .is_directory = true });
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const path = try std.fs.path.join(
        allocator,
        &.{ root, "linked-parent", "target" },
    );
    defer allocator.free(path);

    if (readFileBounded(allocator, path, 32)) |accepted| {
        allocator.free(accepted);
        return error.SymlinkWasAccepted;
    } else |_| {}
    if (appendDurable(path, "forbidden\n")) |_| {
        return error.SymlinkWasAccepted;
    } else |_| {}

    const retained = try temporary.dir.readFileAlloc(allocator, "real/target", 32);
    defer allocator.free(retained);
    try std.testing.expectEqualStrings("sealed\n", retained);
}
