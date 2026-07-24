//! Strict command contract for the focused Native CUDA product.

const std = @import("std");

pub const protocol_name = "raw-stwo-wide-v1";
pub const air_name = "wide_fibonacci";
pub const backend_name = "cuda";

pub const Prove = struct {
    log_n_rows: u32,
    sequence_len: u32,
    output: []const u8,
    report_out: ?[]const u8,
    self_check: bool,
};

pub const Parsed = union(enum) {
    prove: Prove,
    help,
};

const Flag = enum {
    air,
    backend,
    protocol,
    log_n_rows,
    sequence_len,
    output,
    report_out,
    self_check,
    count,
};

const Scratch = struct {
    seen: [@intFromEnum(Flag.count)]bool =
        [_]bool{false} ** @intFromEnum(Flag.count),
    air: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    protocol: ?[]const u8 = null,
    log_n_rows: ?u32 = null,
    sequence_len: ?u32 = null,
    output: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    self_check: bool = false,

    fn mark(self: *Scratch, flag: Flag) !void {
        const index = @intFromEnum(flag);
        if (self.seen[index]) return error.DuplicateArgument;
        self.seen[index] = true;
    }
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 1 and isHelp(argv[0])) return .help;
    if (argv.len == 0) return error.MissingCommand;
    if (!std.mem.eql(u8, argv[0], "prove")) return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1])) return .help;

    var scratch = Scratch{};
    var index: usize = 1;
    while (index < argv.len) {
        const flag = parseFlag(argv[index]) orelse return error.UnknownArgument;
        try scratch.mark(flag);
        index += 1;
        if (flag == .self_check) {
            scratch.self_check = true;
            continue;
        }
        if (index == argv.len) return error.MissingArgumentValue;
        try assign(&scratch, flag, argv[index]);
        index += 1;
    }
    return .{ .prove = try finish(scratch) };
}

fn finish(scratch: Scratch) !Prove {
    if (!std.mem.eql(
        u8,
        scratch.air orelse return error.MissingAir,
        air_name,
    )) return error.UnsupportedAir;
    if (!std.mem.eql(
        u8,
        scratch.backend orelse return error.MissingBackend,
        backend_name,
    )) return error.UnsupportedBackend;
    if (!std.mem.eql(
        u8,
        scratch.protocol orelse return error.MissingProtocol,
        protocol_name,
    )) return error.UnsupportedProtocol;

    const output = try requiredPath(scratch.output, error.MissingOutput);
    const report_out = try optionalPath(scratch.report_out);
    if (report_out) |report| {
        if (std.mem.eql(u8, output, report)) return error.OutputPathCollision;
    }
    return .{
        .log_n_rows = scratch.log_n_rows orelse return error.MissingLogRows,
        .sequence_len = scratch.sequence_len orelse
            return error.MissingSequenceLength,
        .output = output,
        .report_out = report_out,
        .self_check = scratch.self_check,
    };
}

fn parseFlag(value: []const u8) ?Flag {
    if (!std.mem.startsWith(u8, value, "--")) return null;
    var normalized: [32]u8 = undefined;
    const raw = value[2..];
    if (raw.len > normalized.len) return null;
    for (raw, 0..) |byte, index| {
        normalized[index] = if (byte == '-') '_' else byte;
    }
    return std.meta.stringToEnum(Flag, normalized[0..raw.len]);
}

fn assign(scratch: *Scratch, flag: Flag, value: []const u8) !void {
    switch (flag) {
        .air => scratch.air = value,
        .backend => scratch.backend = value,
        .protocol => scratch.protocol = value,
        .log_n_rows => scratch.log_n_rows =
            std.fmt.parseInt(u32, value, 10) catch return error.InvalidLogRows,
        .sequence_len => scratch.sequence_len =
            std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidSequenceLength,
        .output => scratch.output = value,
        .report_out => scratch.report_out = value,
        .self_check, .count => unreachable,
    }
}

fn requiredPath(path: ?[]const u8, comptime missing: anyerror) ![]const u8 {
    const value = path orelse return missing;
    if (value.len == 0) return error.InvalidPath;
    return value;
}

fn optionalPath(path: ?[]const u8) !?[]const u8 {
    if (path) |value| if (value.len == 0) return error.InvalidPath;
    return path;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or
        std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: stwo-zig-native-cuda prove [options]
        \\
        \\  --air wide_fibonacci
        \\  --backend cuda
        \\  --protocol raw-stwo-wide-v1
        \\  --log-n-rows N
        \\  --sequence-len N
        \\  --output PATH
        \\  --report-out PATH     Persist the machine-readable residency report
        \\  --self-check          Require exact CUDA/CPU canonical proof parity
        \\
        \\The v1 product is strict-AOT and rejects CPU fallback, unsealed
        \\protocols, unsupported trace topology, and nonterminal device reads.
        \\
    );
}

test "parser admits only the sealed CUDA wide-Fibonacci product" {
    const request = (try parse(&.{
        "prove",
        "--air",
        air_name,
        "--backend",
        backend_name,
        "--protocol",
        protocol_name,
        "--log-n-rows",
        "14",
        "--sequence-len",
        "100",
        "--output",
        "proof.json",
        "--self-check",
    })).prove;
    try std.testing.expectEqual(@as(u32, 14), request.log_n_rows);
    try std.testing.expectEqual(@as(u32, 100), request.sequence_len);
    try std.testing.expect(request.self_check);

    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove",
        "--air",
        air_name,
        "--backend",
        "cpu",
        "--protocol",
        protocol_name,
        "--log-n-rows",
        "14",
        "--sequence-len",
        "100",
        "--output",
        "proof.json",
    }));
    try std.testing.expectError(error.UnsupportedProtocol, parse(&.{
        "prove",
        "--air",
        air_name,
        "--backend",
        backend_name,
        "--protocol",
        "custom",
        "--log-n-rows",
        "14",
        "--sequence-len",
        "100",
        "--output",
        "proof.json",
    }));
}

test "parser requires explicit topology and collision-free outputs" {
    try std.testing.expectError(error.MissingLogRows, parse(&.{
        "prove",
        "--air",
        air_name,
        "--backend",
        backend_name,
        "--protocol",
        protocol_name,
        "--sequence-len",
        "100",
        "--output",
        "proof.json",
    }));
    try std.testing.expectError(error.OutputPathCollision, parse(&.{
        "prove",
        "--air",
        air_name,
        "--backend",
        backend_name,
        "--protocol",
        protocol_name,
        "--log-n-rows",
        "14",
        "--sequence-len",
        "100",
        "--output",
        "proof.json",
        "--report-out",
        "proof.json",
    }));
}
