//! Validated filesystem views over immutable proving artifacts.

const std = @import("std");
const builtin = @import("builtin");

extern "c" fn fclonefileat(
    source_fd: std.posix.fd_t,
    destination_dir_fd: std.posix.fd_t,
    destination: [*:0]const u8,
    flags: u32,
) c_int;

const clone_no_owner_copy: u32 = 0x0002;

pub const evaluations_name = "preprocessed-evaluations.bin";
pub const tree0_merkle_name = evaluations_name ++ ".tree0-merkle";
pub const composition_name = "composition.bin";
pub const composition_metal_name = "composition.metal";
pub const composition_metallib_name = "composition.metallib";

/// A reference returned by the authenticated, service-owned artifact store.
/// This layer deliberately does not rehash multi-gigabyte objects. It verifies
/// the content-addressed name, size, type, and read-only mode before publishing.
pub const ImmutableObject = struct {
    path: []const u8,
    object_id: [32]u8,
    bytes: u64,
};

pub const CompositionProgram = union(enum) {
    metal: ImmutableObject,
    metallib: ImmutableObject,
};

pub const Inputs = struct {
    preprocessed_evaluations: ImmutableObject,
    preprocessed_tree0_merkle: ImmutableObject,
    composition: ImmutableObject,
    composition_program: CompositionProgram,
    expected_tree0_root: ?[32]u8 = null,
};

pub const TreeLimits = struct {
    max_file_bytes: u64 = 64 * 1024 * 1024 * 1024,
    max_layer_bytes: u64 = 32 * 1024 * 1024 * 1024,
    max_layers: u32 = 64,
};

pub const View = struct {
    directory: []u8,
    preprocessed_evaluations: []u8,
    preprocessed_tree0_merkle: []u8,
    composition: []u8,
    composition_program: []u8,
    composition_program_kind: std.meta.Tag(CompositionProgram),
    tree0_root: [32]u8,
    cleanup_on_deinit: bool,

    pub fn deinit(self: *View, allocator: std.mem.Allocator) void {
        if (self.cleanup_on_deinit)
            std.fs.deleteTreeAbsolute(self.directory) catch {};
        self.freePaths(allocator);
        self.* = undefined;
    }

    fn freePaths(self: *View, allocator: std.mem.Allocator) void {
        allocator.free(self.composition_program);
        allocator.free(self.composition);
        allocator.free(self.preprocessed_tree0_merkle);
        allocator.free(self.preprocessed_evaluations);
        allocator.free(self.directory);
    }
};

/// Creates an exclusive, private request view under `parent_directory`.
/// Passing an artifact Store's `root_path` places the view under that Store;
/// callers may instead provide another private, service-owned directory.
pub fn create(
    allocator: std.mem.Allocator,
    parent_directory: []const u8,
    request_name: []const u8,
    inputs: Inputs,
    cleanup_on_deinit: bool,
) !View {
    if (!std.fs.path.isAbsolute(parent_directory)) return error.InvalidViewParent;
    if (!validRequestName(request_name)) return error.InvalidViewName;

    const view_component = try std.fmt.allocPrint(allocator, "view-{s}", .{request_name});
    defer allocator.free(view_component);
    const directory = try std.fs.path.join(allocator, &.{ parent_directory, view_component });
    errdefer allocator.free(directory);
    std.posix.mkdir(directory, 0o700) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ArtifactViewConflict,
        else => return err,
    };
    var directory_created = true;
    errdefer if (directory_created) std.fs.deleteTreeAbsolute(directory) catch {};

    var view_directory = try std.fs.openDirAbsolute(directory, .{
        .iterate = true,
        .no_follow = true,
    });
    defer view_directory.close();
    var parent = try std.fs.openDirAbsolute(parent_directory, .{
        .iterate = true,
        .no_follow = true,
    });
    defer parent.close();
    try syncDirectory(parent);

    const evaluations_path = try std.fs.path.join(allocator, &.{ directory, evaluations_name });
    errdefer allocator.free(evaluations_path);
    const tree_path = try std.fs.path.join(allocator, &.{ directory, tree0_merkle_name });
    errdefer allocator.free(tree_path);
    const composition_path = try std.fs.path.join(allocator, &.{ directory, composition_name });
    errdefer allocator.free(composition_path);
    const program_name: []const u8 = switch (inputs.composition_program) {
        .metal => composition_metal_name,
        .metallib => composition_metallib_name,
    };
    const program_path = try std.fs.path.join(allocator, &.{ directory, program_name });
    errdefer allocator.free(program_path);

    try cloneObject(inputs.preprocessed_evaluations, evaluations_path);
    try cloneObject(inputs.preprocessed_tree0_merkle, tree_path);
    try cloneObject(inputs.composition, composition_path);
    switch (inputs.composition_program) {
        .metal => |object| try cloneObject(object, program_path),
        .metallib => |object| try cloneObject(object, program_path),
    }

    const tree0_root = try deriveTree0Root(tree_path);
    if (inputs.expected_tree0_root) |expected|
        if (!std.mem.eql(u8, &tree0_root, &expected)) return error.Tree0RootMismatch;

    try syncDirectory(view_directory);
    try syncDirectory(parent);
    directory_created = false;
    return .{
        .directory = directory,
        .preprocessed_evaluations = evaluations_path,
        .preprocessed_tree0_merkle = tree_path,
        .composition = composition_path,
        .composition_program = program_path,
        .composition_program_kind = std.meta.activeTag(inputs.composition_program),
        .tree0_root = tree0_root,
        .cleanup_on_deinit = cleanup_on_deinit,
    };
}

pub fn deriveTree0Root(path: []const u8) ![32]u8 {
    return deriveTree0RootWithLimits(path, .{});
}

/// Strictly parses an authenticated STWZMRK v1 object without retaining any
/// non-root layer. The caller must obtain ImmutableObject from its artifact
/// Store; this layer preserves that object by APFS clone or an exclusive copy
/// fallback and treats the final retained layer as authoritative.
pub fn deriveTree0RootWithLimits(path: []const u8, limits: TreeLimits) ![32]u8 {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidMerkleObjectPath;
    if (limits.max_layers == 0 or limits.max_file_bytes == 0 or limits.max_layer_bytes == 0)
        return error.InvalidMerkleLimits;
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size > limits.max_file_bytes)
        return error.InvalidMerkleObject;

    var buffer: [64 * 1024]u8 = undefined;
    var file_reader = file.reader(&buffer);
    const reader = &file_reader.interface;
    const magic = try takeArray8(reader);
    if (!std.mem.eql(u8, &magic, "STWZMRK\x00")) return error.InvalidMerkleMagic;
    if (try takeLittle(reader, u32) != 1) return error.UnsupportedMerkleVersion;
    if (try takeLittle(reader, u32) != 0) return error.InvalidMerkleTreeIndex;
    const layer_count = try takeLittle(reader, u32);
    if (layer_count == 0 or layer_count > limits.max_layers)
        return error.InvalidMerkleLayerCount;

    var root: [32]u8 = undefined;
    var layer_index: u32 = 0;
    while (layer_index < layer_count) : (layer_index += 1) {
        const layer_bytes = try takeLittle(reader, u64);
        if (layer_index + 1 == layer_count) {
            if (layer_bytes != root.len) return error.InvalidMerkleRootLayer;
            try readExact(reader, &root);
        } else {
            if (layer_bytes == 0 or layer_bytes > limits.max_layer_bytes or layer_bytes % 32 != 0)
                return error.InvalidMerkleLayerSize;
            try discardExact(reader, layer_bytes);
        }
    }
    var trailing: [1]u8 = undefined;
    if (try reader.readSliceShort(&trailing) != 0) return error.MerkleTrailingData;
    return root;
}

fn validRequestName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
        return false;
    for (name) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
        else => return false,
    };
    return true;
}

fn cloneObject(object: ImmutableObject, destination: []const u8) !void {
    if (!std.fs.path.isAbsolute(object.path) or object.bytes == 0)
        return error.InvalidImmutableObject;
    const basename = std.fs.path.basename(object.path);
    const digest_hex = std.fmt.bytesToHex(object.object_id, .lower);
    if (!validContentObjectName(basename, &digest_hex))
        return error.InvalidContentObjectAddress;

    const no_follow = try std.posix.fstatat(std.posix.AT.FDCWD, object.path, std.posix.AT.SYMLINK_NOFOLLOW);
    if (no_follow.mode & std.posix.S.IFMT != std.posix.S.IFREG)
        return error.InvalidImmutableObject;
    const source = try std.fs.openFileAbsolute(object.path, .{});
    defer source.close();
    const source_stat = try source.stat();
    if (source_stat.kind != .file or source_stat.size != object.bytes or source_stat.mode & 0o222 != 0)
        return error.InvalidImmutableObject;

    const cloned = if (comptime builtin.os.tag == .macos)
        try cloneObjectApfs(source, destination)
    else
        false;
    if (!cloned) try copyObject(source, source_stat, destination);

    const published = try std.fs.openFileAbsolute(destination, .{});
    defer published.close();
    const published_stat = try published.stat();
    if (published_stat.kind != .file or published_stat.inode == source_stat.inode or
        published_stat.size != source_stat.size or published_stat.mode & 0o222 != 0)
        return error.ImmutableObjectChanged;
    try published.sync();
}

fn validContentObjectName(basename: []const u8, digest_hex: []const u8) bool {
    if (basename.len <= digest_hex.len or
        !std.mem.eql(u8, basename[0..digest_hex.len], digest_hex))
    {
        return false;
    }
    const suffix = basename[digest_hex.len..];
    return std.mem.eql(u8, suffix, ".blob") or
        std.mem.eql(u8, suffix, ".artifact");
}

fn cloneObjectApfs(source: std.fs.File, destination: []const u8) !bool {
    const destination_z = try std.posix.toPosixPath(destination);
    const result = fclonefileat(
        source.handle,
        std.posix.AT.FDCWD,
        &destination_z,
        clone_no_owner_copy,
    );
    return switch (std.posix.errno(result)) {
        .SUCCESS => true,
        .EXIST => return error.ArtifactViewConflict,
        .XDEV, .OPNOTSUPP => false,
        .ACCES, .PERM => return error.AccessDenied,
        .NOSPC, .DQUOT => return error.NoSpaceLeft,
        .IO => return error.InputOutput,
        .ROFS => return error.ReadOnlyFileSystem,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        else => |err| return std.posix.unexpectedErrno(err),
    };
}

fn copyObject(source: std.fs.File, source_stat: std.fs.File.Stat, destination: []const u8) !void {
    try source.seekTo(0);
    const output = std.fs.createFileAbsolute(destination, .{
        .read = true,
        .exclusive = true,
        .mode = 0o600,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return error.ArtifactViewConflict,
        else => return err,
    };
    defer output.close();
    errdefer std.fs.deleteFileAbsolute(destination) catch {};

    var buffer: [256 * 1024]u8 = undefined;
    var bytes: u64 = 0;
    while (true) {
        const count = try source.read(&buffer);
        if (count == 0) break;
        try output.writeAll(buffer[0..count]);
        bytes = std.math.add(u64, bytes, count) catch return error.InvalidImmutableObject;
    }
    const source_after = try source.stat();
    if (bytes != source_stat.size or source_after.inode != source_stat.inode or
        source_after.size != source_stat.size or source_after.mode != source_stat.mode or
        source_after.mtime != source_stat.mtime or source_after.ctime != source_stat.ctime)
        return error.ImmutableObjectChanged;
    try output.chmod(0o400);
    try output.sync();
}

fn syncDirectory(directory: std.fs.Dir) !void {
    try std.posix.fsync(directory.fd);
}

fn takeArray8(reader: *std.Io.Reader) ![8]u8 {
    const value = reader.takeArray(8) catch |err| switch (err) {
        error.EndOfStream => return error.TruncatedMerkleObject,
        else => return err,
    };
    return value.*;
}

fn takeLittle(reader: *std.Io.Reader, comptime T: type) !T {
    return reader.takeInt(T, .little) catch |err| switch (err) {
        error.EndOfStream => error.TruncatedMerkleObject,
        else => err,
    };
}

fn readExact(reader: *std.Io.Reader, destination: []u8) !void {
    reader.readSliceAll(destination) catch |err| switch (err) {
        error.EndOfStream => return error.TruncatedMerkleObject,
        else => return err,
    };
}

fn discardExact(reader: *std.Io.Reader, bytes: u64) !void {
    reader.discardAll64(bytes) catch |err| switch (err) {
        error.EndOfStream => return error.TruncatedMerkleObject,
        else => return err,
    };
}

fn digestFile(path: []const u8) ![32]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var digest = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [4096]u8 = undefined;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        digest.update(buffer[0..count]);
    }
    return digest.finalResult();
}

fn testObject(
    allocator: std.mem.Allocator,
    temporary: *std.testing.TmpDir,
    temporary_name: []const u8,
) !ImmutableObject {
    const temporary_path = try temporary.dir.realpathAlloc(allocator, temporary_name);
    defer allocator.free(temporary_path);
    const object_id = try digestFile(temporary_path);
    const digest_hex = std.fmt.bytesToHex(object_id, .lower);
    const object_name = try std.fmt.allocPrint(allocator, "{s}.artifact", .{digest_hex});
    defer allocator.free(object_name);
    try temporary.dir.rename(temporary_name, object_name);
    const path = try temporary.dir.realpathAlloc(allocator, object_name);
    errdefer allocator.free(path);
    const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    const stat = try file.stat();
    try file.chmod(0o400);
    try file.sync();
    file.close();
    return .{ .path = path, .object_id = object_id, .bytes = stat.size };
}

fn freeTestObject(allocator: std.mem.Allocator, object: ImmutableObject) void {
    allocator.free(object.path);
}

fn writeTreeObject(
    allocator: std.mem.Allocator,
    temporary: *std.testing.TmpDir,
    name: []const u8,
    final_layer_bytes: u64,
    trailing: []const u8,
) !ImmutableObject {
    const file = try temporary.dir.createFile(name, .{ .exclusive = true });
    var buffer: [4096]u8 = undefined;
    var file_writer = file.writer(&buffer);
    const writer = &file_writer.interface;
    try writer.writeAll("STWZMRK\x00");
    try writer.writeInt(u32, 1, .little);
    try writer.writeInt(u32, 0, .little);
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, 64, .little);
    try writer.splatByteAll(0x11, 64);
    try writer.writeInt(u64, final_layer_bytes, .little);
    var index: u64 = 0;
    while (index < final_layer_bytes) : (index += 1)
        try writer.writeByte(@intCast(index));
    try writer.writeAll(trailing);
    try writer.flush();
    try file.sync();
    file.close();
    return testObject(allocator, temporary, name);
}

test "creates exact runner adjacency with one selected composition program" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "eval.tmp", .data = "evaluations" });
    try temporary.dir.writeFile(.{ .sub_path = "composition.tmp", .data = "composition" });
    try temporary.dir.writeFile(.{ .sub_path = "program.tmp", .data = "metal-source" });
    const evaluations = try testObject(std.testing.allocator, &temporary, "eval.tmp");
    defer freeTestObject(std.testing.allocator, evaluations);
    const composition = try testObject(std.testing.allocator, &temporary, "composition.tmp");
    defer freeTestObject(std.testing.allocator, composition);
    const program = try testObject(std.testing.allocator, &temporary, "program.tmp");
    defer freeTestObject(std.testing.allocator, program);
    const tree = try writeTreeObject(std.testing.allocator, &temporary, "tree.tmp", 32, "");
    defer freeTestObject(std.testing.allocator, tree);
    const parent = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(parent);
    const source_before_file = try std.fs.openFileAbsolute(evaluations.path, .{});
    const source_before = try source_before_file.stat();
    source_before_file.close();

    var expected_root: [32]u8 = undefined;
    for (&expected_root, 0..) |*byte, index| byte.* = @intCast(index);
    var view = try create(std.testing.allocator, parent, "request-17", .{
        .preprocessed_evaluations = evaluations,
        .preprocessed_tree0_merkle = tree,
        .composition = composition,
        .composition_program = .{ .metal = program },
        .expected_tree0_root = expected_root,
    }, true);
    var view_live = true;
    defer if (view_live) view.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(evaluations_name, std.fs.path.basename(view.preprocessed_evaluations));
    try std.testing.expectEqualStrings(tree0_merkle_name, std.fs.path.basename(view.preprocessed_tree0_merkle));
    try std.testing.expectEqualStrings(composition_name, std.fs.path.basename(view.composition));
    try std.testing.expectEqualStrings(composition_metal_name, std.fs.path.basename(view.composition_program));
    try std.testing.expectEqual(.metal, view.composition_program_kind);
    try std.testing.expectEqual(expected_root, view.tree0_root);
    const alternate = try std.fs.path.join(std.testing.allocator, &.{ view.directory, composition_metallib_name });
    defer std.testing.allocator.free(alternate);
    try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(alternate, .{}));
    const cloned = try std.fs.openFileAbsolute(view.preprocessed_evaluations, .{});
    defer cloned.close();
    const original = try std.fs.openFileAbsolute(evaluations.path, .{});
    defer original.close();
    const source_after = try original.stat();
    try std.testing.expect(source_after.inode != (try cloned.stat()).inode);
    try std.testing.expectEqual(source_before.inode, source_after.inode);
    try std.testing.expectEqual(source_before.size, source_after.size);
    try std.testing.expectEqual(source_before.mtime, source_after.mtime);
    try std.testing.expectEqual(source_before.ctime, source_after.ctime);

    var metallib_view = try create(std.testing.allocator, parent, "request-18", .{
        .preprocessed_evaluations = evaluations,
        .preprocessed_tree0_merkle = tree,
        .composition = composition,
        .composition_program = .{ .metallib = program },
    }, true);
    var metallib_view_live = true;
    defer if (metallib_view_live) metallib_view.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(composition_metallib_name, std.fs.path.basename(metallib_view.composition_program));
    try std.testing.expectEqual(.metallib, metallib_view.composition_program_kind);
    const metal_alternate = try std.fs.path.join(std.testing.allocator, &.{ metallib_view.directory, composition_metal_name });
    defer std.testing.allocator.free(metal_alternate);
    try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(metal_alternate, .{}));

    metallib_view.deinit(std.testing.allocator);
    metallib_view_live = false;
    view.deinit(std.testing.allocator);
    view_live = false;
    const final_source = try std.fs.openFileAbsolute(evaluations.path, .{});
    defer final_source.close();
    const source_after_cleanup = try final_source.stat();
    try std.testing.expectEqual(source_before.inode, source_after_cleanup.inode);
    try std.testing.expectEqual(source_before.size, source_after_cleanup.size);
    try std.testing.expectEqual(source_before.mtime, source_after_cleanup.mtime);
    try std.testing.expectEqual(source_before.ctime, source_after_cleanup.ctime);
}

test "rejects an existing request view without replacement" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const parent = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(parent);
    try temporary.dir.makeDir("view-duplicate");
    const placeholder = ImmutableObject{ .path = parent, .object_id = [_]u8{0} ** 32, .bytes = 1 };
    try std.testing.expectError(error.ArtifactViewConflict, create(
        std.testing.allocator,
        parent,
        "duplicate",
        .{
            .preprocessed_evaluations = placeholder,
            .preprocessed_tree0_merkle = placeholder,
            .composition = placeholder,
            .composition_program = .{ .metallib = placeholder },
        },
        true,
    ));
}

test "derived root is authoritative and mismatch removes partial view" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "eval.tmp", .data = "evaluations" });
    try temporary.dir.writeFile(.{ .sub_path = "composition.tmp", .data = "composition" });
    try temporary.dir.writeFile(.{ .sub_path = "program.tmp", .data = "metallib" });
    const evaluations = try testObject(std.testing.allocator, &temporary, "eval.tmp");
    defer freeTestObject(std.testing.allocator, evaluations);
    const composition = try testObject(std.testing.allocator, &temporary, "composition.tmp");
    defer freeTestObject(std.testing.allocator, composition);
    const program = try testObject(std.testing.allocator, &temporary, "program.tmp");
    defer freeTestObject(std.testing.allocator, program);
    const tree = try writeTreeObject(std.testing.allocator, &temporary, "tree.tmp", 32, "");
    defer freeTestObject(std.testing.allocator, tree);
    const parent = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(parent);
    const wrong_root = [_]u8{0xff} ** 32;
    try std.testing.expectError(error.Tree0RootMismatch, create(
        std.testing.allocator,
        parent,
        "root-mismatch",
        .{
            .preprocessed_evaluations = evaluations,
            .preprocessed_tree0_merkle = tree,
            .composition = composition,
            .composition_program = .{ .metallib = program },
            .expected_tree0_root = wrong_root,
        },
        true,
    ));
    const rejected = try std.fs.path.join(std.testing.allocator, &.{ parent, "view-root-mismatch" });
    defer std.testing.allocator.free(rejected);
    try std.testing.expectError(error.FileNotFound, std.fs.accessAbsolute(rejected, .{}));
}

test "strict STWZMRK parser rejects wrong root size and trailing data" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const short_root = try writeTreeObject(std.testing.allocator, &temporary, "short.tmp", 31, "");
    defer freeTestObject(std.testing.allocator, short_root);
    try std.testing.expectError(error.InvalidMerkleRootLayer, deriveTree0Root(short_root.path));

    const trailing = try writeTreeObject(std.testing.allocator, &temporary, "trailing.tmp", 32, "x");
    defer freeTestObject(std.testing.allocator, trailing);
    try std.testing.expectError(error.MerkleTrailingData, deriveTree0Root(trailing.path));

    try std.testing.expectError(
        error.InvalidMerkleLayerCount,
        deriveTree0RootWithLimits(trailing.path, .{ .max_layers = 1 }),
    );
    try std.testing.expectError(
        error.InvalidMerkleObject,
        deriveTree0RootWithLimits(trailing.path, .{ .max_file_bytes = 1 }),
    );

    try temporary.dir.writeFile(.{ .sub_path = "truncated.bin", .data = "STWZMRK\x00" });
    const truncated = try temporary.dir.realpathAlloc(std.testing.allocator, "truncated.bin");
    defer std.testing.allocator.free(truncated);
    try std.testing.expectError(error.TruncatedMerkleObject, deriveTree0Root(truncated));
}
