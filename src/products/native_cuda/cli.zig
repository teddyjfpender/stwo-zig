//! Strict command contract for the focused Native CUDA product.

const std = @import("std");

pub const wide_protocol_name = "raw-stwo-wide-v1";
pub const xor_protocol_name = "raw-stwo-xor-v1";
pub const protocol_name = wide_protocol_name;
pub const air_name = "wide_fibonacci";
pub const backend_name = "cuda";
pub const max_repetitions: u32 = 16;

pub const Air = enum {
    wide_fibonacci,
    xor,

    pub fn protocolName(self: Air) []const u8 {
        return switch (self) {
            .wide_fibonacci => wide_protocol_name,
            .xor => xor_protocol_name,
        };
    }
};

pub const ExecutionMode = enum {
    graphs,
    direct,
};

pub const Prove = struct {
    air: Air,
    log_n_rows: ?u32,
    sequence_len: ?u32,
    log_size: ?u32,
    log_step: ?u32,
    offset: ?u64,
    output: []const u8,
    report_out: ?[]const u8,
    repeat: u32,
    execution_mode: ExecutionMode,
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
    log_size,
    log_step,
    offset,
    output,
    report_out,
    repeat,
    execution_mode,
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
    log_size: ?u32 = null,
    log_step: ?u32 = null,
    offset: ?u64 = null,
    output: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    repeat: ?u32 = null,
    execution_mode: ?ExecutionMode = null,

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
        if (index == argv.len) return error.MissingArgumentValue;
        try assign(&scratch, flag, argv[index]);
        index += 1;
    }
    return .{ .prove = try finish(scratch) };
}

fn finish(scratch: Scratch) !Prove {
    const air = std.meta.stringToEnum(
        Air,
        scratch.air orelse return error.MissingAir,
    ) orelse return error.UnsupportedAir;
    if (!std.mem.eql(
        u8,
        scratch.backend orelse return error.MissingBackend,
        backend_name,
    )) return error.UnsupportedBackend;
    if (!std.mem.eql(
        u8,
        scratch.protocol orelse return error.MissingProtocol,
        air.protocolName(),
    )) return error.UnsupportedProtocol;

    const output = try requiredPath(scratch.output, error.MissingOutput);
    const report_out = try optionalPath(scratch.report_out);
    if (report_out) |report| {
        if (std.mem.eql(u8, output, report)) return error.OutputPathCollision;
    }
    const repeat = scratch.repeat orelse 1;
    if (repeat == 0 or repeat > max_repetitions)
        return error.InvalidRepeatCount;
    switch (air) {
        .wide_fibonacci => {
            if (scratch.log_size != null or
                scratch.log_step != null or
                scratch.offset != null)
            {
                return error.UnexpectedShapeArgument;
            }
            _ = scratch.log_n_rows orelse return error.MissingLogRows;
            _ = scratch.sequence_len orelse
                return error.MissingSequenceLength;
        },
        .xor => {
            if (scratch.log_n_rows != null or scratch.sequence_len != null)
                return error.UnexpectedShapeArgument;
            _ = scratch.log_size orelse return error.MissingLogSize;
            _ = scratch.log_step orelse return error.MissingLogStep;
            _ = scratch.offset orelse return error.MissingOffset;
        },
    }
    return .{
        .air = air,
        .log_n_rows = scratch.log_n_rows,
        .sequence_len = scratch.sequence_len,
        .log_size = scratch.log_size,
        .log_step = scratch.log_step,
        .offset = scratch.offset,
        .output = output,
        .report_out = report_out,
        .repeat = repeat,
        .execution_mode = scratch.execution_mode orelse .graphs,
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
        .log_size => scratch.log_size =
            std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidLogSize,
        .log_step => scratch.log_step =
            std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidLogStep,
        .offset => scratch.offset =
            std.fmt.parseInt(u64, value, 10) catch
                return error.InvalidOffset,
        .output => scratch.output = value,
        .report_out => scratch.report_out = value,
        .repeat => scratch.repeat =
            std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidRepeatCount,
        .execution_mode => scratch.execution_mode =
            std.meta.stringToEnum(ExecutionMode, value) orelse
            return error.InvalidExecutionMode,
        .count => unreachable,
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
        \\  --air wide_fibonacci | xor
        \\  --backend cuda
        \\  --protocol raw-stwo-wide-v1 | raw-stwo-xor-v1
        \\  wide_fibonacci: --log-n-rows N --sequence-len N
        \\  xor:            --log-size N --log-step N --offset N
        \\  --output PATH
        \\  --report-out PATH     Persist the machine-readable residency report
        \\  --repeat N            Same-process CUDA repetitions (1-16; default 1)
        \\  --execution-mode MODE Graphs (default) or forced direct execution
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
    })).prove;
    try std.testing.expectEqual(Air.wide_fibonacci, request.air);
    try std.testing.expectEqual(@as(u32, 14), request.log_n_rows.?);
    try std.testing.expectEqual(@as(u32, 100), request.sequence_len.?);
    try std.testing.expectEqual(@as(u32, 1), request.repeat);
    try std.testing.expectEqual(ExecutionMode.graphs, request.execution_mode);

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

test "parser admits only the exact XOR shape and protocol" {
    const request = (try parse(&.{
        "prove",
        "--air",
        "xor",
        "--backend",
        backend_name,
        "--protocol",
        xor_protocol_name,
        "--log-size",
        "16",
        "--log-step",
        "2",
        "--offset",
        "3",
        "--output",
        "proof.json",
    })).prove;
    try std.testing.expectEqual(Air.xor, request.air);
    try std.testing.expectEqual(@as(u32, 16), request.log_size.?);
    try std.testing.expectEqual(@as(u32, 2), request.log_step.?);
    try std.testing.expectEqual(@as(u64, 3), request.offset.?);
    try std.testing.expect(request.log_n_rows == null);

    try std.testing.expectError(error.UnexpectedShapeArgument, parse(&.{
        "prove",
        "--air",
        "xor",
        "--backend",
        backend_name,
        "--protocol",
        xor_protocol_name,
        "--log-size",
        "16",
        "--log-step",
        "2",
        "--offset",
        "3",
        "--sequence-len",
        "8",
        "--output",
        "proof.json",
    }));
}

test "parser admits explicit direct execution and rejects ambiguous modes" {
    const prefix = [_][]const u8{
        "prove",          "--air",            air_name,
        "--backend",      backend_name,       "--protocol",
        protocol_name,    "--log-n-rows",     "14",
        "--sequence-len", "100",              "--output",
        "proof.json",     "--execution-mode",
    };
    var direct = prefix ++ [_][]const u8{"direct"};
    const request = (try parse(&direct)).prove;
    try std.testing.expectEqual(ExecutionMode.direct, request.execution_mode);

    var unsupported = prefix ++ [_][]const u8{"automatic"};
    try std.testing.expectError(
        error.InvalidExecutionMode,
        parse(&unsupported),
    );
    var duplicate = direct ++ [_][]const u8{ "--execution-mode", "graphs" };
    try std.testing.expectError(error.DuplicateArgument, parse(&duplicate));
}

test "parser rejects in-process CPU proving capability" {
    try std.testing.expectError(error.UnknownArgument, parse(&.{
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
    }));
}

test "parser bounds process repetitions" {
    const prefix = [_][]const u8{
        "prove",          "--air",        air_name,
        "--backend",      backend_name,   "--protocol",
        protocol_name,    "--log-n-rows", "14",
        "--sequence-len", "100",          "--output",
        "proof.json",     "--repeat",
    };
    var zero = prefix ++ [_][]const u8{"0"};
    try std.testing.expectError(error.InvalidRepeatCount, parse(&zero));
    var excessive = prefix ++ [_][]const u8{"17"};
    try std.testing.expectError(error.InvalidRepeatCount, parse(&excessive));
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
