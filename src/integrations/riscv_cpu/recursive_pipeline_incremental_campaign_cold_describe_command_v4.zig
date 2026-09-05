//! Read-only controller bridge for a sealed campaign import.
//!
//! Inputs are exactly one canonical STWCIR04 path and one Zig Store root.
//! Stdout is one canonical path-free JSON description followed by LF.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const artifact_store = @import("stwo_artifact_store");
const cold_describe =
    @import("recursive_pipeline_incremental_campaign_cold_describe_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");

pub const command_name =
    "recursive-pipeline-incremental-campaign-cold-describe-v4";
pub const PRODUCTION_ACTIVE = false;

pub const OptionsV4 = struct {
    campaign_import_receipt: []const u8,
    artifact_store_root: []const u8,

    pub fn parse(arguments: []const []const u8) !OptionsV4 {
        if (arguments.len != 4) return error.InvalidArguments;
        var receipt: ?[]const u8 = null;
        var store: ?[]const u8 = null;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            const name = arguments[index];
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--campaign-import-receipt")) {
                try setOnce(&receipt, value);
            } else if (std.mem.eql(u8, name, "--artifact-store-root")) {
                try setOnce(&store, value);
            } else return error.InvalidArguments;
        }
        return .{
            .campaign_import_receipt = receipt orelse
                return error.InvalidArguments,
            .artifact_store_root = store orelse return error.InvalidArguments,
        };
    }

    pub fn resolve(
        self: OptionsV4,
        allocator: std.mem.Allocator,
    ) !OwnedOptionsV4 {
        const receipt = try artifact_io.resolveAbsolute(
            allocator,
            self.campaign_import_receipt,
        );
        errdefer allocator.free(receipt);
        const store = try artifact_io.resolveAbsolute(
            allocator,
            self.artifact_store_root,
        );
        errdefer allocator.free(store);
        if (pathContains(receipt, store) or pathContains(store, receipt))
            return error.IncrementalCampaignColdDescribePathMismatchV4;
        return .{
            .campaign_import_receipt = receipt,
            .artifact_store_root = store,
        };
    }
};

pub const OwnedOptionsV4 = struct {
    campaign_import_receipt: []u8,
    artifact_store_root: []u8,

    pub fn deinit(self: *OwnedOptionsV4, allocator: std.mem.Allocator) void {
        allocator.free(self.artifact_store_root);
        allocator.free(self.campaign_import_receipt);
        self.* = undefined;
    }
};

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len == 0) return error.InvalidArguments;
    try run(allocator, arguments[1..], std.fs.File.stdout());
}

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
    output: std.fs.File,
) !void {
    const parsed = try OptionsV4.parse(arguments);
    var options = try parsed.resolve(allocator);
    defer options.deinit(allocator);
    const receipt_bytes = try readReceipt(options.campaign_import_receipt);

    // The descriptor is read-only. Require the CAS root to pre-exist before
    // opening the stable Store API, then rebuild its index by rehashing every
    // immutable object rather than trusting filenames or a Python digest.
    try requireExistingStoreRoot(options.artifact_store_root);
    var store = try artifact_store.Store.openOrCreate(
        allocator,
        options.artifact_store_root,
        false,
    );
    defer store.deinit();
    try store.auditAndRebuildIndex();
    const encoded = try cold_describe.coldDescribeWorkerCanonicalJsonAlloc(
        allocator,
        &store,
        &receipt_bytes,
    );
    defer allocator.free(encoded);
    try output.writeAll(encoded);
}

fn requireExistingStoreRoot(path: []const u8) !void {
    var root = try std.fs.openDirAbsolute(
        path,
        .{ .iterate = true, .no_follow = true },
    );
    defer root.close();
    var objects = try root.openDir(
        "objects",
        .{ .iterate = true, .no_follow = true },
    );
    defer objects.close();
    var sha256 = try objects.openDir(
        "sha256",
        .{ .iterate = true, .no_follow = true },
    );
    sha256.close();
}

fn readReceipt(path: []const u8) ![receipt_mod.ENCODED_BYTE_COUNT]u8 {
    if (!std.fs.path.isAbsolute(path)) return error.AbsolutePathRequired;
    const parent_path = std.fs.path.dirname(path) orelse
        return error.InvalidArtifactPath;
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, "..")) return error.InvalidArtifactPath;
    var parent = try std.fs.openDirAbsolute(
        parent_path,
        .{ .no_follow = true },
    );
    defer parent.close();
    const entry = try std.posix.fstatat(
        parent.fd,
        basename,
        std.posix.AT.SYMLINK_NOFOLLOW,
    );
    if (entry.mode & std.posix.S.IFMT != std.posix.S.IFREG)
        return error.InvalidArtifactPath;
    var flags: std.posix.O = .{ .ACCMODE = .RDONLY };
    if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
    if (@hasField(std.posix.O, "NOFOLLOW")) flags.NOFOLLOW = true;
    const fd = try std.posix.openat(parent.fd, basename, flags, 0);
    errdefer std.posix.close(fd);
    const file = std.fs.File{ .handle = fd };
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.inode != entry.ino or
        before.size != receipt_mod.ENCODED_BYTE_COUNT)
    {
        return error.InvalidIncrementalCampaignImportReceiptV4;
    }
    var bytes: [receipt_mod.ENCODED_BYTE_COUNT]u8 = undefined;
    if (try file.readAll(&bytes) != bytes.len)
        return error.InvalidIncrementalCampaignImportReceiptV4;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0)
        return error.InvalidIncrementalCampaignImportReceiptV4;
    const after = try file.stat();
    if (after.inode != before.inode or after.size != before.size or
        after.mtime != before.mtime or after.ctime != before.ctime)
    {
        return error.ArtifactChangedDuringMeasurement;
    }
    return bytes;
}

fn setOnce(slot: *?[]const u8, value: []const u8) !void {
    if (slot.* != null) return error.DuplicateArgument;
    slot.* = value;
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, child)) return true;
    if (parent.len == 1 and parent[0] == std.fs.path.sep) return true;
    return child.len > parent.len and
        std.mem.startsWith(u8, child, parent) and
        child[parent.len] == std.fs.path.sep;
}
