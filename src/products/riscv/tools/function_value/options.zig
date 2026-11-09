//! Existing CLI admission policy for this bounded observer.
const std = @import("std");
const maximum_sample_segments: u32 = 64;

pub const Options = struct {
    elf: []const u8,
    input: []const u8,
    execution_journal: []const u8,
    segment_count: u32,
    entry_pc: u32,
    entry_instruction_word: u32,
    value_pc: u32,
    value_instruction_word: u32,

    pub fn parse(arguments: []const []const u8) !Options {
        if (arguments.len != 16) return error.InvalidArguments;
        var elf: ?[]const u8 = null;
        var input: ?[]const u8 = null;
        var journal: ?[]const u8 = null;
        var count: ?u32 = null;
        var entry_pc: ?u32 = null;
        var entry_instruction: ?u32 = null;
        var value_pc: ?u32 = null;
        var value_instruction: ?u32 = null;
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
            } else if (std.mem.eql(u8, name, "--segment-count")) {
                if (count != null) return error.DuplicateArgument;
                count = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--entry-pc")) {
                if (entry_pc != null) return error.DuplicateArgument;
                entry_pc = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--entry-instruction-word")) {
                if (entry_instruction != null) return error.DuplicateArgument;
                entry_instruction = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--value-pc")) {
                if (value_pc != null) return error.DuplicateArgument;
                value_pc = try parseU32(value);
            } else if (std.mem.eql(u8, name, "--value-instruction-word")) {
                if (value_instruction != null) return error.DuplicateArgument;
                value_instruction = try parseU32(value);
            } else return error.InvalidArguments;
        }
        const segment_count = count orelse return error.InvalidArguments;
        if (segment_count == 0 or segment_count > maximum_sample_segments)
            return error.InvalidSegmentCount;
        const resolved_entry_pc = entry_pc orelse return error.InvalidArguments;
        const resolved_value_pc = value_pc orelse return error.InvalidArguments;
        if (resolved_entry_pc == resolved_value_pc)
            return error.InvalidArguments;
        return .{
            .elf = elf orelse return error.InvalidArguments,
            .input = input orelse return error.InvalidArguments,
            .execution_journal = journal orelse return error.InvalidArguments,
            .segment_count = segment_count,
            .entry_pc = resolved_entry_pc,
            .entry_instruction_word = entry_instruction orelse
                return error.InvalidArguments,
            .value_pc = resolved_value_pc,
            .value_instruction_word = value_instruction orelse
                return error.InvalidArguments,
        };
    }
};

fn parseU32(value: []const u8) !u32 {
    if (std.mem.startsWith(u8, value, "0x"))
        return std.fmt.parseInt(u32, value[2..], 16);
    return std.fmt.parseInt(u32, value, 10);
}

test "options accept exact hex PCs and instruction words" {
    const args = [_][]const u8{
        "--elf",           "a",       "--input",                  "b",          "--execution-journal",      "c",
        "--segment-count", "31",      "--entry-pc",               "0xbd490",    "--entry-instruction-word", "0xfc010113",
        "--value-pc",      "0xbd4c4", "--value-instruction-word", "0x0085a903",
    };
    const options = try Options.parse(&args);
    try std.testing.expectEqual(@as(u32, 0xbd490), options.entry_pc);
    try std.testing.expectEqual(@as(u32, 0xbd4c4), options.value_pc);
    try std.testing.expectEqual(@as(u32, 0x0085a903), options.value_instruction_word);
}

test "function-value options retain bounded sample admission" {
    var args = [_][]const u8{
        "--elf",      "a",    "--input",                  "b",    "--execution-journal", "c",    "--segment-count",          "1",
        "--entry-pc", "0x10", "--entry-instruction-word", "0x13", "--value-pc",          "0x14", "--value-instruction-word", "0x13",
    };
    for ([_][]const u8{ "0", "65" }) |count| {
        args[7] = count;
        try std.testing.expectError(error.InvalidSegmentCount, Options.parse(&args));
    }
}
