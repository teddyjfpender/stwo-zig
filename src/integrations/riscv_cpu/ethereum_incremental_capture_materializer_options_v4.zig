//! Typed CLI options for the retained-authority V4 capture transaction.

const std = @import("std");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");

pub const RootModeV4 = enum { create_under_parent, reopen_unsealed };

pub const OptionsV4 = struct {
    retained_materialization_result: []const u8,
    publication_root: []const u8,
    root_mode: RootModeV4,

    pub fn parse(arguments: []const []const u8) !OptionsV4 {
        if (arguments.len != 4) return error.InvalidArguments;
        var materialization: ?[]const u8 = null;
        var root: ?[]const u8 = null;
        var mode: ?RootModeV4 = null;
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
                if (materialization != null) return error.DuplicateArgument;
                materialization = value;
            } else if (std.mem.eql(u8, name, "--publication-root-parent")) {
                if (root != null) return error.DuplicateArgument;
                root = value;
                mode = .create_under_parent;
            } else if (std.mem.eql(u8, name, "--publication-root")) {
                if (root != null) return error.DuplicateArgument;
                root = value;
                mode = .reopen_unsealed;
            } else return error.InvalidArguments;
        }
        return .{
            .retained_materialization_result = materialization orelse
                return error.InvalidArguments,
            .publication_root = root orelse return error.InvalidArguments,
            .root_mode = mode orelse return error.InvalidArguments,
        };
    }

    pub fn resolve(
        self: OptionsV4,
        allocator: std.mem.Allocator,
    ) !OwnedOptionsV4 {
        const materialization = try artifact_io.resolveAbsolute(
            allocator,
            self.retained_materialization_result,
        );
        errdefer allocator.free(materialization);
        const root = switch (self.root_mode) {
            .create_under_parent => try artifact_io.resolveCreateOnlyChild(
                allocator,
                self.publication_root,
                "ethereum-incremental-capture-v4",
            ),
            .reopen_unsealed => try artifact_io.resolveAbsolute(
                allocator,
                self.publication_root,
            ),
        };
        return .{
            .retained_materialization_result = materialization,
            .publication_root = root,
            .root_mode = self.root_mode,
        };
    }
};

pub const OwnedOptionsV4 = struct {
    retained_materialization_result: []u8,
    publication_root: []u8,
    root_mode: RootModeV4,

    pub fn deinit(self: *OwnedOptionsV4, allocator: std.mem.Allocator) void {
        allocator.free(self.publication_root);
        allocator.free(self.retained_materialization_result);
        self.* = undefined;
    }
};
