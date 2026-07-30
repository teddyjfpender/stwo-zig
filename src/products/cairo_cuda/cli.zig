//! Strict command contract for the resident Cairo CUDA product.

const std = @import("std");

pub const Prove = struct {
    input: []const u8,
    output: []const u8,
    report_out: []const u8,
    repeat: u32,
};

pub const Parsed = union(enum) {
    prove: Prove,
    help,
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 1 and isHelp(argv[0])) return .help;
    if (argv.len == 0 or !std.mem.eql(u8, argv[0], "prove"))
        return error.MissingProveCommand;

    var input: ?[]const u8 = null;
    var output: ?[]const u8 = null;
    var report: ?[]const u8 = null;
    var repeat: u32 = 1;
    var seen_backend = false;
    var seen_repeat = false;
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 >= argv.len) return error.MissingArgumentValue;
        const flag = argv[index];
        const value = argv[index + 1];
        if (std.mem.eql(u8, flag, "--backend")) {
            if (seen_backend) return error.DuplicateArgument;
            seen_backend = true;
            if (!std.mem.eql(u8, value, "cuda"))
                return error.UnsupportedBackend;
        } else if (std.mem.eql(u8, flag, "--input")) {
            if (input != null) return error.DuplicateArgument;
            input = try path(value);
        } else if (std.mem.eql(u8, flag, "--output")) {
            if (output != null) return error.DuplicateArgument;
            output = try path(value);
        } else if (std.mem.eql(u8, flag, "--report-out")) {
            if (report != null) return error.DuplicateArgument;
            report = try path(value);
        } else if (std.mem.eql(u8, flag, "--repeat")) {
            if (seen_repeat) return error.DuplicateArgument;
            seen_repeat = true;
            repeat = std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidRepeatCount;
            if (repeat == 0 or repeat > 16)
                return error.InvalidRepeatCount;
        } else {
            return error.UnknownArgument;
        }
    }
    if (!seen_backend) return error.MissingBackend;
    const proof_output = output orelse return error.MissingOutput;
    const report_output = report orelse return error.MissingReportOutput;
    if (std.mem.eql(u8, proof_output, report_output))
        return error.OutputPathCollision;
    return .{ .prove = .{
        .input = input orelse return error.MissingInput,
        .output = proof_output,
        .report_out = report_output,
        .repeat = repeat,
    } };
}

pub fn writeUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage:
        \\  stwo-cairo-cuda prove --backend cuda --input <adapted-input> \
        \\    --output <proof.json> --report-out <report.json> [--repeat N]
        \\
    );
}

fn path(value: []const u8) ![]const u8 {
    if (value.len == 0 or value[0] == '-') return error.InvalidPath;
    return value;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or
        std.mem.eql(u8, value, "-h");
}

test "SN2 prove command is explicit and fail closed" {
    const parsed = try parse(&.{
        "prove",
        "--backend",
        "cuda",
        "--input",
        "sn2.bin",
        "--output",
        "proof.json",
        "--report-out",
        "report.json",
        "--repeat",
        "3",
    });
    try std.testing.expectEqual(@as(u32, 3), parsed.prove.repeat);
    try std.testing.expectEqualStrings("sn2.bin", parsed.prove.input);
}

test "non-CUDA and output aliasing are rejected" {
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove",
        "--backend",
        "cpu",
        "--input",
        "sn2.bin",
        "--output",
        "proof.json",
        "--report-out",
        "report.json",
    }));
    try std.testing.expectError(error.OutputPathCollision, parse(&.{
        "prove",
        "--backend",
        "cuda",
        "--input",
        "sn2.bin",
        "--output",
        "same.json",
        "--report-out",
        "same.json",
    }));
}
