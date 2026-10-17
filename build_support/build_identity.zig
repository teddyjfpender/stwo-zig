//! Repository source identity resolved during build configuration.

const std = @import("std");

pub const IMPLEMENTATION_REPOSITORY = "https://github.com/teddyjfpender/stwo-zig";
pub const COMMIT_HEX_LEN = 40;
pub const SHA256_LEN = 32;

pub const Identity = struct {
    implementation_repository: []const u8 = IMPLEMENTATION_REPOSITORY,
    implementation_commit: [COMMIT_HEX_LEN]u8,
    implementation_tree: ?[COMMIT_HEX_LEN]u8,
    implementation_dirty: bool,
    dirty_content_sha256: ?[SHA256_LEN]u8,

    pub fn validate(self: Identity) !void {
        if (self.implementation_repository.len == 0) return error.MissingRepository;
        if (self.implementation_dirty != (self.dirty_content_sha256 != null))
            return error.InconsistentDirtyIdentity;
    }
};

pub const Override = struct {
    commit: []const u8,
    tree: ?[]const u8 = null,
    dirty: bool,
    dirty_content_sha256: ?[]const u8 = null,
};

const DirtyState = struct {
    dirty: bool,
    content_sha256: ?[SHA256_LEN]u8,
};

const git_output_limit = 64 * 1024 * 1024;

/// Compatibility entry point. A dirty explicit override must use
/// `resolveWithOverride` because commit plus `dirty=true` is not reproducible.
pub fn resolve(
    allocator: std.mem.Allocator,
    repository_root: []const u8,
    explicit_commit: ?[]const u8,
    explicit_dirty: ?bool,
) !Identity {
    if ((explicit_commit == null) != (explicit_dirty == null))
        return error.IncompleteImplementationIdentityOverride;
    return resolveWithOverride(
        allocator,
        repository_root,
        if (explicit_commit) |commit| .{
            .commit = commit,
            .dirty = explicit_dirty.?,
        } else null,
    );
}

pub fn resolveWithOverride(
    allocator: std.mem.Allocator,
    repository_root: []const u8,
    explicit: ?Override,
) !Identity {
    if (explicit) |override| {
        const commit = try parseCommit(override.commit);
        const dirty_digest = if (override.dirty)
            try parseRequiredSha256(override.dirty_content_sha256)
        else blk: {
            if (override.dirty_content_sha256 != null)
                return error.CleanOverrideHasDirtyDigest;
            break :blk null;
        };
        const identity = Identity{
            .implementation_commit = commit,
            .implementation_tree = if (override.tree) |tree|
                try parseCommit(tree)
            else
                readTree(allocator, repository_root, &commit) catch null,
            .implementation_dirty = override.dirty,
            .dirty_content_sha256 = dirty_digest,
        };
        try identity.validate();
        // A root build has a checkout: delegated identity must describe the
        // source actually present, rather than an arbitrary command-line claim.
        if (readCommit(allocator, repository_root)) |head| {
            if (!std.mem.eql(u8, &head, &identity.implementation_commit))
                return error.ImplementationIdentityMismatch;
            const tree = try readTree(allocator, repository_root, &head);
            if (identity.implementation_tree) |claimed_tree| {
                if (!std.mem.eql(u8, &tree, &claimed_tree)) return error.ImplementationIdentityMismatch;
            }
            const dirty = try readDirtyState(allocator, repository_root);
            if (dirty.dirty != identity.implementation_dirty)
                return error.ImplementationIdentityMismatch;
            if (dirty.content_sha256) |digest| {
                if (!std.mem.eql(u8, &digest, &identity.dirty_content_sha256.?))
                    return error.ImplementationIdentityMismatch;
            }
        } else |err| {
            // Source archives have no Git metadata, but a checkout whose Git
            // metadata is broken must not silently accept an asserted identity.
            const marker = try std.fs.path.join(allocator, &.{ repository_root, ".git" });
            defer allocator.free(marker);
            std.fs.cwd().access(marker, .{}) catch |access_err| switch (access_err) {
                error.FileNotFound => {
                    if (err == error.GitCommandFailed or err == error.FileNotFound) return identity;
                    return err;
                },
                else => return access_err,
            };
            return err;
        }
        return identity;
    }

    const commit = try readCommit(allocator, repository_root);
    const dirty = try readDirtyState(allocator, repository_root);
    const identity = Identity{
        .implementation_commit = commit,
        .implementation_tree = try readTree(allocator, repository_root, &commit),
        .implementation_dirty = dirty.dirty,
        .dirty_content_sha256 = dirty.content_sha256,
    };
    try identity.validate();
    return identity;
}

fn readCommit(allocator: std.mem.Allocator, repository_root: []const u8) ![COMMIT_HEX_LEN]u8 {
    const result = try runGit(allocator, repository_root, &.{ "rev-parse", "--verify", "HEAD" }, 256);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try requireSuccess(result.term);
    return parseCommit(std.mem.trim(u8, result.stdout, " \t\r\n"));
}

fn readTree(
    allocator: std.mem.Allocator,
    repository_root: []const u8,
    commit: []const u8,
) ![COMMIT_HEX_LEN]u8 {
    const revision = try std.fmt.allocPrint(allocator, "{s}^{{tree}}", .{commit});
    defer allocator.free(revision);
    const result = try runGit(allocator, repository_root, &.{
        "rev-parse", "--verify", revision,
    }, 256);
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try requireSuccess(result.term);
    return parseCommit(std.mem.trim(u8, result.stdout, " \t\r\n"));
}

fn readDirtyState(allocator: std.mem.Allocator, repository_root: []const u8) !DirtyState {
    const tracked = try runGit(allocator, repository_root, &.{
        "diff", "--name-only", "--no-renames", "-z", "HEAD", "--",
    }, git_output_limit);
    defer allocator.free(tracked.stdout);
    defer allocator.free(tracked.stderr);
    try requireSuccess(tracked.term);

    // This is the explicit exclusion policy: Git-ignored paths are build/cache
    // outputs and do not enter diagnostic source identity.
    const untracked = try runGit(allocator, repository_root, &.{
        "ls-files", "--others", "--exclude-standard", "-z",
    }, git_output_limit);
    defer allocator.free(untracked.stdout);
    defer allocator.free(untracked.stderr);
    try requireSuccess(untracked.term);

    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(allocator);
    try appendNulPaths(allocator, &paths, tracked.stdout);
    try appendNulPaths(allocator, &paths, untracked.stdout);
    if (paths.items.len == 0) return .{ .dirty = false, .content_sha256 = null };
    std.mem.sort([]const u8, paths.items, {}, lessThanPath);
    for (paths.items[1..], paths.items[0 .. paths.items.len - 1]) |path, previous| {
        if (std.mem.eql(u8, path, previous)) return error.DuplicateDirtyPath;
    }
    return .{
        .dirty = true,
        .content_sha256 = try hashDirtyPaths(repository_root, paths.items),
    };
}

fn appendNulPaths(
    allocator: std.mem.Allocator,
    paths: *std.ArrayList([]const u8),
    encoded: []const u8,
) !void {
    var remaining = encoded;
    while (remaining.len != 0) {
        const end = std.mem.indexOfScalar(u8, remaining, 0) orelse
            return error.InvalidGitPathList;
        const path = remaining[0..end];
        if (path.len == 0 or std.fs.path.isAbsolute(path)) return error.InvalidGitPath;
        var components = std.mem.splitScalar(u8, path, '/');
        while (components.next()) |component| {
            if (std.mem.eql(u8, component, "..")) return error.InvalidGitPath;
        }
        try paths.append(allocator, path);
        remaining = remaining[end + 1 ..];
    }
}

fn hashDirtyPaths(repository_root: []const u8, paths: []const []const u8) ![SHA256_LEN]u8 {
    var root = try std.fs.openDirAbsolute(repository_root, .{});
    defer root.close();
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hashField(&hasher, "stwo-dirty-content-v1");
    hashLength(&hasher, paths.len);
    for (paths) |path| {
        hashField(&hasher, path);
        try hashDirtyPath(&hasher, root, path);
    }
    return hasher.finalResult();
}

fn hashDirtyPath(hasher: *std.crypto.hash.sha2.Sha256, root: std.fs.Dir, path: []const u8) !void {
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (root.readLink(path, &link_buffer)) |target| {
        hashField(hasher, "120000");
        hashField(hasher, target);
        return;
    } else |err| switch (err) {
        error.NotLink => {},
        error.FileNotFound => {
            hashField(hasher, "000000");
            hashField(hasher, "");
            return;
        },
        else => return err,
    }

    var file = try root.openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file) return error.UnsupportedDirtyInput;
    hashField(hasher, if (stat.mode & 0o111 != 0) "100755" else "100644");
    hashLength(hasher, stat.size);
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
}

fn runGit(
    allocator: std.mem.Allocator,
    repository_root: []const u8,
    arguments: []const []const u8,
    max_output_bytes: usize,
) std.process.Child.RunError!std.process.Child.RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, "git");
    try argv.appendSlice(allocator, arguments);
    return std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv.items,
        .cwd = repository_root,
        .max_output_bytes = max_output_bytes,
    });
}

fn requireSuccess(term: std.process.Child.Term) error{GitCommandFailed}!void {
    switch (term) {
        .Exited => |status| if (status == 0) return,
        else => {},
    }
    return error.GitCommandFailed;
}

fn parseCommit(value: []const u8) error{InvalidImplementationCommit}![COMMIT_HEX_LEN]u8 {
    if (value.len != COMMIT_HEX_LEN) return error.InvalidImplementationCommit;
    var result: [COMMIT_HEX_LEN]u8 = undefined;
    for (value, 0..) |byte, index| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidImplementationCommit;
        result[index] = byte;
    }
    return result;
}

fn parseRequiredSha256(value: ?[]const u8) !?[SHA256_LEN]u8 {
    const encoded = value orelse return error.DirtyOverrideRequiresContentDigest;
    if (encoded.len != SHA256_LEN * 2) return error.InvalidDirtyContentDigest;
    var result: [SHA256_LEN]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch return error.InvalidDirtyContentDigest;
    const canonical = std.fmt.bytesToHex(result, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidDirtyContentDigest;
    return result;
}

fn lessThanPath(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}

fn hashField(hasher: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hashLength(hasher, value.len);
    hasher.update(value);
}

fn hashLength(hasher: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .big);
    hasher.update(&encoded);
}

test "explicit identity requires complete canonical dirty state" {
    const clean = try resolve(
        std.testing.allocator,
        "definitely-not-a-repository",
        "0123456789abcdef0123456789abcdef01234567",
        false,
    );
    try clean.validate();
    try std.testing.expect(clean.dirty_content_sha256 == null);
    try std.testing.expectError(
        error.DirtyOverrideRequiresContentDigest,
        resolveWithOverride(std.testing.allocator, ".", .{
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .dirty = true,
        }),
    );
    const dirty = try resolveWithOverride(std.testing.allocator, "definitely-not-a-repository", .{
        .commit = "0123456789abcdef0123456789abcdef01234567",
        .dirty = true,
        .dirty_content_sha256 = "11" ** SHA256_LEN,
    });
    try dirty.validate();
    try std.testing.expect(dirty.dirty_content_sha256 != null);
}

test "rejects partial or malformed explicit identity" {
    try std.testing.expectError(
        error.IncompleteImplementationIdentityOverride,
        resolve(std.testing.allocator, ".", "0123456789abcdef0123456789abcdef01234567", null),
    );
    try std.testing.expectError(
        error.InvalidImplementationCommit,
        resolve(std.testing.allocator, ".", "0123456789abcdef0123456789abcdef0123456A", false),
    );
    try std.testing.expectError(
        error.CleanOverrideHasDirtyDigest,
        resolveWithOverride(std.testing.allocator, ".", .{
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .dirty = false,
            .dirty_content_sha256 = "22" ** SHA256_LEN,
        }),
    );
}

test "an explicit root identity cannot impersonate another commit" {
    const allocator = std.testing.allocator;
    const head = readCommit(allocator, ".") catch return;
    var wrong = head;
    wrong[0] = if (head[0] == '0') '1' else '0';
    try std.testing.expectError(error.ImplementationIdentityMismatch, resolveWithOverride(
        allocator,
        ".",
        .{ .commit = &wrong, .dirty = false },
    ));
}

test "local dirty digest binds sorted source content and excludes ignored outputs" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    try runGitForTest(root, &.{ "init", "-q" });
    try temporary.dir.writeFile(.{ .sub_path = ".gitignore", .data = "zig-cache/\n" });
    try temporary.dir.writeFile(.{ .sub_path = "tracked.zig", .data = "const value = 1;\n" });
    try runGitForTest(root, &.{ "add", "." });
    try runGitForTest(root, &.{
        "-c",     "user.name=Identity Test", "-c",       "user.email=identity@example.invalid",
        "commit", "-qm",                     "baseline",
    });

    const clean = try resolve(std.testing.allocator, root, null, null);
    try std.testing.expect(!clean.implementation_dirty);
    try temporary.dir.makePath("zig-cache");
    try temporary.dir.writeFile(.{ .sub_path = "zig-cache/output.bin", .data = "ignored" });
    const ignored = try resolve(std.testing.allocator, root, null, null);
    try std.testing.expect(!ignored.implementation_dirty);

    try temporary.dir.writeFile(.{ .sub_path = "tracked.zig", .data = "const value = 2;\n" });
    const tracked = try resolve(std.testing.allocator, root, null, null);
    try std.testing.expect(tracked.implementation_dirty);
    try temporary.dir.writeFile(.{ .sub_path = "new.zig", .data = "const new = true;\n" });
    const with_untracked = try resolve(std.testing.allocator, root, null, null);
    try std.testing.expect(!std.mem.eql(
        u8,
        &tracked.dirty_content_sha256.?,
        &with_untracked.dirty_content_sha256.?,
    ));
    const repeated = try resolve(std.testing.allocator, root, null, null);
    try std.testing.expectEqualSlices(
        u8,
        &with_untracked.dirty_content_sha256.?,
        &repeated.dirty_content_sha256.?,
    );
}

fn runGitForTest(root: []const u8, arguments: []const []const u8) !void {
    const result = try runGit(std.testing.allocator, root, arguments, 4096);
    defer std.testing.allocator.free(result.stdout);
    defer std.testing.allocator.free(result.stderr);
    try requireSuccess(result.term);
}
