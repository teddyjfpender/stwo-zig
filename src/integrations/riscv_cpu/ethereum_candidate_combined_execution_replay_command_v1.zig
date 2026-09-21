//! Typed two-path CLI for independent combined-candidate execution replay.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const replay_mod =
    @import("ethereum_candidate_combined_execution_replay_v1.zig");

pub const command_name = "ethereum-candidate-combined-execution-replay-v1";

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    return replay_mod.replay(allocator, .{
        .result_path = options.result_path,
        .replay_receipt_path = options.replay_receipt_path,
    });
}

const Options = struct {
    result_path: []u8,
    replay_receipt_path: []u8,

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 4) return error.InvalidArguments;
        var result_path: ?[]const u8 = null;
        var replay_receipt_path: ?[]const u8 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--result")) {
                if (result_path != null) return error.DuplicateArgument;
                result_path = value;
            } else if (std.mem.eql(u8, name, "--replay-receipt")) {
                if (replay_receipt_path != null) return error.DuplicateArgument;
                replay_receipt_path = value;
            } else return error.InvalidArguments;
        }
        const resolved_result = try artifact_io.resolveAbsolute(
            allocator,
            result_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_result);
        const resolved_receipt = try artifact_io.resolveAbsolute(
            allocator,
            replay_receipt_path orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_receipt);
        if (std.mem.eql(u8, resolved_result, resolved_receipt))
            return error.DuplicatePath;
        return .{
            .result_path = resolved_result,
            .replay_receipt_path = resolved_receipt,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.result_path);
        allocator.free(self.replay_receipt_path);
        self.* = undefined;
    }
};

test "replay CLI accepts only a result and a distinct create-only receipt" {
    const arguments = [_][]const u8{
        "--result",
        "/tmp/candidate-execution-capture-v1.json",
        "--replay-receipt",
        "/tmp/candidate-execution-replay-v1.json",
    };
    var options = try Options.parseAndResolve(std.testing.allocator, &arguments);
    defer options.deinit(std.testing.allocator);
    try std.testing.expect(std.fs.path.isAbsolute(options.result_path));
    try std.testing.expect(std.fs.path.isAbsolute(options.replay_receipt_path));
    const duplicate = [_][]const u8{
        "--result",
        "/tmp/same.json",
        "--replay-receipt",
        "/tmp/same.json",
    };
    try std.testing.expectError(
        error.DuplicatePath,
        Options.parseAndResolve(std.testing.allocator, &duplicate),
    );
}
