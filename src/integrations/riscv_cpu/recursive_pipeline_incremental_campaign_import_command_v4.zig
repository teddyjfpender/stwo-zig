//! Create-only command for importing one sealed incremental V4 campaign.
//!
//! The retained materialization, sealed publication, and shared Zig CAS are
//! separate custody roots.  The command cold-opens the retained authority,
//! delegates all campaign validation and CAS writes to the recovery-aware
//! STWCIT04 importer, then publishes one path-free typed receipt last.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const retained_mod =
    @import("ethereum_incremental_capture_retained_authority_v4.zig");
const importer =
    @import("recursive_pipeline_incremental_campaign_importer_v4.zig");
const receipt_mod =
    @import("recursive_pipeline_incremental_campaign_import_receipt_v4.zig");

pub const command_name = "recursive-pipeline-incremental-campaign-import-v4";
pub const PRODUCTION_ACTIVE = false;
pub const RECOVERY_AWARE_IMPORT = true;
pub const RECEIPT_SEALED_LAST = true;
pub const GENERIC_CAMPAIGN_COUNTS = true;

pub const OptionsV4 = struct {
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    artifact_store_root: []const u8,
    table_receipt_out: []const u8,

    pub fn parse(arguments: []const []const u8) !OptionsV4 {
        if (arguments.len != 8) return error.InvalidArguments;
        var retained: ?[]const u8 = null;
        var publication: ?[]const u8 = null;
        var store: ?[]const u8 = null;
        var receipt: ?[]const u8 = null;
        var index: usize = 0;
        while (index < arguments.len) : (index += 2) {
            const name = arguments[index];
            const value = arguments[index + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(
                u8,
                name,
                "--retained-materialization-result",
            )) {
                try setOnce(&retained, value);
            } else if (std.mem.eql(u8, name, "--publication-root")) {
                try setOnce(&publication, value);
            } else if (std.mem.eql(u8, name, "--artifact-store-root")) {
                try setOnce(&store, value);
            } else if (std.mem.eql(u8, name, "--table-receipt-out")) {
                try setOnce(&receipt, value);
            } else return error.InvalidArguments;
        }
        return .{
            .retained_materialization_result = retained orelse
                return error.InvalidArguments,
            .publication_root = publication orelse
                return error.InvalidArguments,
            .artifact_store_root = store orelse
                return error.InvalidArguments,
            .table_receipt_out = receipt orelse
                return error.InvalidArguments,
        };
    }

    pub fn resolve(
        self: OptionsV4,
        allocator: std.mem.Allocator,
    ) !OwnedOptionsV4 {
        var paths: [4][]u8 = undefined;
        var initialized: usize = 0;
        errdefer for (paths[0..initialized]) |path| allocator.free(path);
        inline for (.{
            self.retained_materialization_result,
            self.publication_root,
            self.artifact_store_root,
            self.table_receipt_out,
        }, 0..) |path, ordinal| {
            paths[ordinal] = try artifact_io.resolveAbsolute(allocator, path);
            initialized += 1;
        }
        try validateResolvedCustodyPaths(
            paths[0],
            paths[1],
            paths[2],
            paths[3],
        );
        return .{
            .retained_materialization_result = paths[0],
            .publication_root = paths[1],
            .artifact_store_root = paths[2],
            .table_receipt_out = paths[3],
        };
    }
};

pub const OwnedOptionsV4 = struct {
    retained_materialization_result: []u8,
    publication_root: []u8,
    artifact_store_root: []u8,
    table_receipt_out: []u8,

    pub fn deinit(self: *OwnedOptionsV4, allocator: std.mem.Allocator) void {
        allocator.free(self.table_receipt_out);
        allocator.free(self.artifact_store_root);
        allocator.free(self.publication_root);
        allocator.free(self.retained_materialization_result);
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
    return run(allocator, arguments[1..]);
}

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    const parsed = try OptionsV4.parse(arguments);
    var options = try parsed.resolve(allocator);
    defer options.deinit(allocator);

    var retained = try retained_mod.RetainedAuthorityV4.open(
        allocator,
        options.retained_materialization_result,
    );
    defer retained.deinit();
    var imported = try importer.importSealedCampaignAlloc(
        allocator,
        options.publication_root,
        options.artifact_store_root,
        &retained,
    );
    defer imported.deinit();

    const receipt = try receipt_mod.ReceiptV4.seal(.{
        .segment_count = imported.segment_count,
        .table_ref = imported.table_ref,
        .content_sha256 = undefined,
    });
    const encoded = try receipt_mod.encode(&receipt);
    try artifact_io.publishCreateOnlyDurable(
        options.table_receipt_out,
        &encoded,
    );
}

/// Lexical custody isolation over already-normalized absolute paths.  The
/// retained materialization and receipt are files, while publication and CAS
/// are directory trees; no argument may equal, contain, or be contained by
/// another.  This is checked before the importer opens or creates the CAS.
pub fn validateResolvedCustodyPaths(
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    artifact_store_root: []const u8,
    table_receipt_out: []const u8,
) !void {
    inline for (.{
        retained_materialization_result,
        publication_root,
        artifact_store_root,
        table_receipt_out,
    }) |path| if (!std.fs.path.isAbsolute(path))
        return error.IncrementalCampaignImportCommandPathMismatchV4;

    const paths = [_][]const u8{
        retained_materialization_result,
        publication_root,
        artifact_store_root,
        table_receipt_out,
    };
    for (paths, 0..) |left, left_index| {
        for (paths[0..left_index]) |right| {
            if (pathContains(left, right) or pathContains(right, left))
                return error.IncrementalCampaignImportCommandPathMismatchV4;
        }
    }
    try importer.validateDisjointRoots(publication_root, artifact_store_root);
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
