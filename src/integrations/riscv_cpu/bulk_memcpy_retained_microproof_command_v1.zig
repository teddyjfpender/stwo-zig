//! Minimal typed CLI for the diagnostic retained bulk-memcpy microproof.

const std = @import("std");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const bridge = @import("bulk_memcpy_retained_microproof_v1.zig");
const receipt = @import("bulk_memcpy_retained_microproof_receipt_v2.zig");

pub const command_name = "ethereum-bulk-memcpy-retained-microproof";

pub fn run(
    allocator: std.mem.Allocator,
    arguments: []const []const u8,
) !void {
    var options = try Options.parseAndResolve(allocator, arguments);
    defer options.deinit(allocator);
    try bridge.run(allocator, .{
        .source_request_path = options.source_request,
        .observation_path = options.observation,
        .output_root = options.output_root,
        .memcpy_entry_pc = options.memcpy_entry_pc,
        .max_word_rows = options.max_word_rows,
        .hard_cap_ns = options.hard_cap_ns,
    });
}

const Options = struct {
    source_request: []u8,
    observation: []u8,
    output_root: []u8,
    memcpy_entry_pc: u32,
    max_word_rows: u32,
    hard_cap_ns: u64,

    fn parseAndResolve(
        allocator: std.mem.Allocator,
        arguments: []const []const u8,
    ) !Options {
        if (arguments.len != 12) return error.InvalidArguments;
        var source_request: ?[]const u8 = null;
        var observation: ?[]const u8 = null;
        var output_root: ?[]const u8 = null;
        var memcpy_entry_pc: ?u32 = null;
        var max_word_rows: ?u32 = null;
        var hard_cap_seconds: ?u64 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (value.len == 0) return error.InvalidArguments;
            if (std.mem.eql(u8, name, "--source-request")) {
                if (source_request != null) return error.DuplicateArgument;
                source_request = value;
            } else if (std.mem.eql(u8, name, "--observation")) {
                if (observation != null) return error.DuplicateArgument;
                observation = value;
            } else if (std.mem.eql(u8, name, "--output-root")) {
                if (output_root != null) return error.DuplicateArgument;
                output_root = value;
            } else if (std.mem.eql(u8, name, "--memcpy-entry-pc")) {
                if (memcpy_entry_pc != null) return error.DuplicateArgument;
                memcpy_entry_pc = try parseUnsigned(u32, value);
            } else if (std.mem.eql(u8, name, "--max-word-rows")) {
                if (max_word_rows != null) return error.DuplicateArgument;
                max_word_rows = try parseUnsigned(u32, value);
            } else if (std.mem.eql(u8, name, "--hard-cap-seconds")) {
                if (hard_cap_seconds != null) return error.DuplicateArgument;
                hard_cap_seconds = try parseUnsigned(u64, value);
            } else return error.InvalidArguments;
        }
        const rows = max_word_rows orelse return error.InvalidArguments;
        if (rows != receipt.maximum_word_row_cap)
            return error.InvalidArguments;
        const seconds = hard_cap_seconds orelse return error.InvalidArguments;
        const hard_cap_ns = std.math.mul(
            u64,
            seconds,
            std.time.ns_per_s,
        ) catch return error.InvalidArguments;
        if (hard_cap_ns == 0 or hard_cap_ns > receipt.maximum_hard_cap_ns)
            return error.InvalidArguments;

        const resolved_source = try artifact_io.resolveAbsolute(
            allocator,
            source_request orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_source);
        const resolved_observation = try artifact_io.resolveAbsolute(
            allocator,
            observation orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_observation);
        const resolved_output = try artifact_io.resolveAbsolute(
            allocator,
            output_root orelse return error.InvalidArguments,
        );
        errdefer allocator.free(resolved_output);
        if (std.mem.eql(u8, resolved_source, resolved_observation) or
            std.mem.eql(u8, resolved_source, resolved_output) or
            std.mem.eql(u8, resolved_observation, resolved_output))
        {
            return error.DuplicateRetainedMicroproofPath;
        }
        return .{
            .source_request = resolved_source,
            .observation = resolved_observation,
            .output_root = resolved_output,
            .memcpy_entry_pc = memcpy_entry_pc orelse
                return error.InvalidArguments,
            .max_word_rows = rows,
            .hard_cap_ns = hard_cap_ns,
        };
    }

    fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        allocator.free(self.source_request);
        allocator.free(self.observation);
        allocator.free(self.output_root);
        self.* = undefined;
    }
};

fn parseUnsigned(comptime T: type, value: []const u8) !T {
    return std.fmt.parseUnsigned(T, value, 10) catch
        return error.InvalidArguments;
}
