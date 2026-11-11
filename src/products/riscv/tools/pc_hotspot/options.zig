//! Existing CLI admission policy for this bounded observer.
const std = @import("std");
const maximum_sample_segments: u32 = 64;

pub const Options = struct {
    elf: []const u8,
    input: []const u8,
    execution_journal: []const u8,
    segment_count: u32,

    pub fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 10) return error.InvalidArguments;
        var elf: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var first: ?u32 = null;
        var count: ?u32 = null;
        var cursor: usize = 0;
        while (cursor < arguments.len) : (cursor += 2) {
            const name = arguments[cursor];
            const value = arguments[cursor + 1];
            if (std.mem.eql(u8, name, "--elf")) {
                if (elf != null) return error.DuplicateArgument;
                elf = value;
            } else if (std.mem.eql(u8, name, "--input")) {
                if (input != null) return error.DuplicateArgument;
                input = value;
            } else if (std.mem.eql(u8, name, "--execution-journal")) {
                if (journal != null) return error.DuplicateArgument;
                journal = value;
            } else if (std.mem.eql(u8, name, "--first-segment-index")) {
                if (first != null) return error.DuplicateArgument;
                first = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (count != null) return error.DuplicateArgument;
                count = try std.fmt.parseInt(u32, value, 10);
            } else return error.InvalidArguments;
        }
        if ((first orelse return error.InvalidArguments) != 0)
            return error.NonPrefixSampleUnavailable;
        const segment_count = count orelse return error.InvalidArguments;
        if (segment_count == 0 or segment_count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        return .{
            .elf = elf orelse return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .segment_count = segment_count,
        };
    }
};

test "pc-hotspot options retain prefix count and radix admission" {
    var args = [_][]const u8{ "--elf", "a", "--input", "b", "--execution-journal", "c", "--first-segment-index", "0", "--segment-count", "1" };
    try std.testing.expectEqual(@as(u32, 1), (try Options.parse(&args)).segment_count);
    args[7] = "1";
    try std.testing.expectError(error.NonPrefixSampleUnavailable, Options.parse(&args));
    args[7] = "0";
    for ([_][]const u8{ "0", "65" }) |count| {
        args[9] = count;
        try std.testing.expectError(error.InvalidSegmentCount, Options.parse(&args));
    }
    args[9] = "0x2";
    try std.testing.expectError(error.InvalidCharacter, Options.parse(&args));
}
