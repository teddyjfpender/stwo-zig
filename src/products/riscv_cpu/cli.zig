//! Strict command contract for the focused RISC-V CPU product.

const std = @import("std");

pub const Command = enum { prove, bench, verify, applications };
pub const Protocol = enum { secure, functional, smoke };

pub const Run = struct {
    elf_path: []const u8,
    input_path: ?[]const u8,
    protocol: Protocol,
    experimental: bool,
};

pub const Prove = struct {
    run: Run,
    output: []const u8,
    report_out: ?[]const u8,
};

pub const Bench = struct {
    run: Run,
    report_out: ?[]const u8,
    proof_out: ?[]const u8,
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const Verify = struct {
    artifact: []const u8,
    elf_path: []const u8,
    protocol: Protocol,
    expected_statement_digest: ?[32]u8,
};

pub const Parsed = union(enum) {
    prove: Prove,
    bench: Bench,
    verify: Verify,
    applications: void,
    help: ?Command,
};

const Flag = enum {
    elf,
    input,
    backend,
    protocol,
    output,
    artifact,
    report_out,
    proof_out,
    warmups,
    samples,
    profiled,
    experimental,
    expect_statement_digest,
    count,
};

const Scratch = struct {
    seen: [@intFromEnum(Flag.count)]bool = [_]bool{false} ** @intFromEnum(Flag.count),
    elf: ?[]const u8 = null,
    input: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    protocol: Protocol = .secure,
    output: ?[]const u8 = null,
    artifact: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    proof_out: ?[]const u8 = null,
    warmups: usize = 10,
    samples: usize = 5,
    profiled: bool = false,
    experimental: bool = false,
    expected_statement_digest: ?[32]u8 = null,

    fn mark(self: *Scratch, flag: Flag) !void {
        const index = @intFromEnum(flag);
        if (self.seen[index]) return error.DuplicateArgument;
        self.seen[index] = true;
    }

    fn has(self: Scratch, flag: Flag) bool {
        return self.seen[@intFromEnum(flag)];
    }
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 0) return error.MissingCommand;
    if (isHelp(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .help = null };
    }
    const command = std.meta.stringToEnum(Command, argv[0]) orelse return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1])) return .{ .help = command };
    if (command == .applications) {
        if (argv.len != 1) return error.IrrelevantArgument;
        return .{ .applications = {} };
    }

    var scratch = Scratch{};
    var index: usize = 1;
    while (index < argv.len) {
        const flag = parseFlag(argv[index]) orelse return error.UnknownArgument;
        try scratch.mark(flag);
        index += 1;
        if (flag == .profiled or flag == .experimental) {
            if (flag == .profiled) scratch.profiled = true;
            if (flag == .experimental) scratch.experimental = true;
            continue;
        }
        if (index == argv.len) return error.MissingArgumentValue;
        try assign(&scratch, flag, argv[index]);
        index += 1;
    }
    return finish(command, scratch);
}

fn finish(command: Command, scratch: Scratch) !Parsed {
    switch (command) {
        .prove => {
            try requireOnly(scratch, &.{
                .elf,          .input, .backend, .protocol, .output, .report_out,
                .experimental,
            });
            return .{ .prove = .{
                .run = try makeRun(scratch),
                .output = try requiredPath(scratch.output, error.MissingOutput),
                .report_out = try optionalPath(scratch.report_out),
            } };
        },
        .bench => {
            try requireOnly(scratch, &.{
                .elf,     .input,   .backend,  .protocol,     .report_out, .proof_out,
                .warmups, .samples, .profiled, .experimental,
            });
            if (scratch.warmups > 10) return error.WarmupsTooLarge;
            if (scratch.samples == 0 or scratch.samples > 21) return error.InvalidSamples;
            return .{ .bench = .{
                .run = try makeRun(scratch),
                .report_out = try optionalPath(scratch.report_out),
                .proof_out = try optionalPath(scratch.proof_out),
                .warmups = scratch.warmups,
                .samples = scratch.samples,
                .profiled = scratch.profiled,
            } };
        },
        .verify => {
            try requireOnly(scratch, &.{ .artifact, .elf, .protocol, .expect_statement_digest });
            return .{ .verify = .{
                .artifact = try requiredPath(scratch.artifact, error.MissingArtifact),
                .elf_path = try requiredPath(scratch.elf, error.MissingElf),
                .protocol = scratch.protocol,
                .expected_statement_digest = scratch.expected_statement_digest,
            } };
        },
        .applications => unreachable,
    }
}

fn makeRun(scratch: Scratch) !Run {
    const backend = scratch.backend orelse return error.MissingBackend;
    if (!std.mem.eql(u8, backend, "cpu")) return error.UnsupportedBackend;
    return .{
        .elf_path = try requiredPath(scratch.elf, error.MissingElf),
        .input_path = try optionalPath(scratch.input),
        .protocol = scratch.protocol,
        .experimental = scratch.experimental,
    };
}

fn parseFlag(value: []const u8) ?Flag {
    const prefix = "--";
    if (!std.mem.startsWith(u8, value, prefix)) return null;
    var normalized: [32]u8 = undefined;
    const raw = value[prefix.len..];
    if (raw.len > normalized.len) return null;
    for (raw, 0..) |byte, index| normalized[index] = if (byte == '-') '_' else byte;
    return std.meta.stringToEnum(Flag, normalized[0..raw.len]);
}

fn assign(scratch: *Scratch, flag: Flag, value: []const u8) !void {
    switch (flag) {
        .elf => scratch.elf = value,
        .input => scratch.input = value,
        .backend => scratch.backend = value,
        .protocol => scratch.protocol = std.meta.stringToEnum(Protocol, value) orelse
            return error.InvalidProtocol,
        .output => scratch.output = value,
        .artifact => scratch.artifact = value,
        .report_out => scratch.report_out = value,
        .proof_out => scratch.proof_out = value,
        .warmups => scratch.warmups = try std.fmt.parseInt(usize, value, 10),
        .samples => scratch.samples = try std.fmt.parseInt(usize, value, 10),
        .expect_statement_digest => scratch.expected_statement_digest = try parseSha256(value),
        .profiled, .experimental, .count => unreachable,
    }
}

fn requireOnly(scratch: Scratch, allowed: []const Flag) !void {
    for (0..@intFromEnum(Flag.count)) |index| {
        if (!scratch.seen[index]) continue;
        const flag: Flag = @enumFromInt(index);
        if (std.mem.indexOfScalar(Flag, allowed, flag) == null) return error.IrrelevantArgument;
    }
}

fn parseSha256(encoded: []const u8) ![32]u8 {
    if (encoded.len != 64) return error.InvalidSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, encoded) catch return error.InvalidSha256;
    const canonical = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, encoded, &canonical)) return error.InvalidSha256;
    return digest;
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
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(writer: anytype, command: ?Command) !void {
    if (command == null) return writer.writeAll(
        \\Usage: stwo-zig-riscv-cpu <command> [options]
        \\
        \\Commands:
        \\  prove          Prove and verify one Sail-profile RV32IM ELF
        \\  bench          Benchmark the verified RISC-V proving path
        \\  verify         Verify a RISC-V proof artifact
        \\  applications   List the compiled frontend and backend
        \\
        \\Backend: CPU scalar/SIMD only; no runtime fallback.
        \\
    );
    switch (command.?) {
        .prove => try writer.writeAll(
            \\Usage: stwo-zig-riscv-cpu prove --elf PATH --backend cpu --output PATH [options]
            \\  --input PATH       Guest input bytes
            \\  --report-out PATH  Write the machine-readable proving report
            \\  --experimental     Admit the adapter before its release gate
            \\
        ),
        .bench => try writer.writeAll(
            \\Usage: stwo-zig-riscv-cpu bench --elf PATH --backend cpu [options]
            \\  --input PATH       Guest input bytes
            \\  --report-out PATH  Write the machine-readable benchmark report
            \\  --proof-out PATH   Retain the final verified proof artifact
            \\  --warmups N        Verified warmups (default 10, maximum 10)
            \\  --samples N        Verified samples (default 5, maximum 21)
            \\  --profiled         Enable stage instrumentation
            \\  --experimental     Admit the adapter before its release gate
            \\
        ),
        .verify => try writer.writeAll(
            \\Usage: stwo-zig-riscv-cpu verify --artifact PATH --elf PATH [options]
            \\  --elf PATH                         Rebuild and bind the decoded program root
            \\  --protocol NAME                    secure, functional, or smoke
            \\  --expect-statement-digest SHA256   Require the external statement digest
            \\
        ),
        .applications => try writer.writeAll("Usage: stwo-zig-riscv-cpu applications\n"),
    }
}

test "only ELF and CPU are accepted" {
    const parsed = (try parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "cpu", "--output", "proof.json",
    })).prove;
    try std.testing.expectEqualStrings("guest.elf", parsed.run.elf_path);
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal-hybrid", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnknownArgument, parse(&.{
        "prove", "--air", "wide_fibonacci", "--backend", "cpu", "--output", "proof.json",
    }));
}

test "focused RISC-V verification requires the source ELF" {
    try std.testing.expectError(error.MissingElf, parse(&.{
        "verify", "--artifact", "proof.json",
    }));
    const request = (try parse(&.{
        "verify", "--artifact", "proof.json", "--elf", "guest.elf",
    })).verify;
    try std.testing.expectEqualStrings("guest.elf", request.elf_path);
}

test "help does not advertise unrelated products" {
    var storage: [4096]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try writeUsage(&output, null);
    inline for (.{ "metal", "cuda", "cairo", "wide_fibonacci", "native" }) |forbidden| {
        try std.testing.expect(std.mem.indexOf(u8, output.buffered(), forbidden) == null);
    }
}
