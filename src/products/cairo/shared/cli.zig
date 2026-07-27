//! Strict command contract shared by focused Cairo proving products.

const std = @import("std");

pub const Command = enum {
    prove,
    run_and_prove,
    capabilities,
    identity,
};

pub const ProofFormat = enum {
    json,
    binary,
    cairo_serde,

    pub fn name(self: ProofFormat) []const u8 {
        return switch (self) {
            .json => "json",
            .binary => "binary",
            .cairo_serde => "cairo-serde",
        };
    }
};

pub const Prove = struct {
    prover_input: []const u8,
    proof: []const u8,
    params: ?[]const u8,
    report_out: ?[]const u8,
    proof_format: ProofFormat,
    verify: bool,
};

pub const ProgramType = enum {
    json,
    executable,

    pub fn name(self: ProgramType) []const u8 {
        return @tagName(self);
    }
};

pub const RunAndProve = struct {
    program: []const u8,
    program_type: ProgramType,
    arguments: ?[]const u8,
    proof: []const u8,
    params: ?[]const u8,
    report_out: ?[]const u8,
    proof_format: ProofFormat,
    verify: bool,
};

pub const Parsed = union(enum) {
    prove: Prove,
    run_and_prove: RunAndProve,
    capabilities,
    identity,
    help: ?Command,
};

const Flag = enum {
    prover_input,
    program,
    program_type,
    arguments,
    proof,
    params,
    report_out,
    proof_format,
    verify,
    count,
};

const Scratch = struct {
    seen: [@intFromEnum(Flag.count)]bool =
        [_]bool{false} ** @intFromEnum(Flag.count),
    prover_input: ?[]const u8 = null,
    program: ?[]const u8 = null,
    program_type: ProgramType = .json,
    arguments: ?[]const u8 = null,
    proof: ?[]const u8 = null,
    params: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    proof_format: ProofFormat = .json,
    verify: bool = false,

    fn mark(self: *Scratch, flag: Flag) !void {
        const index = @intFromEnum(flag);
        if (self.seen[index]) return error.DuplicateArgument;
        self.seen[index] = true;
    }
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 0) return error.MissingCommand;
    if (isHelp(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .help = null };
    }
    const command = parseCommand(argv[0]) orelse return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1]))
        return .{ .help = command };
    switch (command) {
        .capabilities, .identity => {
            if (argv.len != 1) return error.IrrelevantArgument;
            return if (command == .capabilities) .capabilities else .identity;
        },
        .prove, .run_and_prove => {},
    }

    var scratch = Scratch{};
    var index: usize = 1;
    while (index < argv.len) {
        const flag = parseFlag(argv[index]) orelse
            return error.UnknownArgument;
        try scratch.mark(flag);
        index += 1;
        if (flag == .verify) {
            scratch.verify = true;
            continue;
        }
        if (index == argv.len) return error.MissingArgumentValue;
        try assign(&scratch, flag, argv[index]);
        index += 1;
    }
    const proof = try requiredPath(scratch.proof, error.MissingProofOutput);
    const params = try optionalPath(scratch.params);
    const report_out = try optionalPath(scratch.report_out);
    return switch (command) {
        .prove => blk: {
            if (scratch.seen[@intFromEnum(Flag.program)] or
                scratch.seen[@intFromEnum(Flag.program_type)] or
                scratch.seen[@intFromEnum(Flag.arguments)])
                return error.IrrelevantArgument;
            break :blk .{ .prove = .{
                .prover_input = try requiredPath(
                    scratch.prover_input,
                    error.MissingProverInput,
                ),
                .proof = proof,
                .params = params,
                .report_out = report_out,
                .proof_format = scratch.proof_format,
                .verify = scratch.verify,
            } };
        },
        .run_and_prove => blk: {
            if (scratch.seen[@intFromEnum(Flag.prover_input)])
                return error.IrrelevantArgument;
            break :blk .{ .run_and_prove = .{
                .program = try requiredPath(
                    scratch.program,
                    error.MissingProgram,
                ),
                .program_type = scratch.program_type,
                .arguments = try optionalPath(scratch.arguments),
                .proof = proof,
                .params = params,
                .report_out = report_out,
                .proof_format = scratch.proof_format,
                .verify = scratch.verify,
            } };
        },
        .capabilities, .identity => unreachable,
    };
}

fn parseCommand(value: []const u8) ?Command {
    if (std.mem.eql(u8, value, "run-and-prove")) return .run_and_prove;
    return std.meta.stringToEnum(Command, value);
}

fn parseFlag(value: []const u8) ?Flag {
    if (!std.mem.startsWith(u8, value, "--")) return null;
    var normalized: [32]u8 = undefined;
    const raw = value[2..];
    if (raw.len > normalized.len) return null;
    for (raw, 0..) |byte, index|
        normalized[index] = if (byte == '-') '_' else byte;
    return std.meta.stringToEnum(Flag, normalized[0..raw.len]);
}

fn assign(scratch: *Scratch, flag: Flag, value: []const u8) !void {
    switch (flag) {
        .prover_input => scratch.prover_input = value,
        .program => scratch.program = value,
        .program_type => scratch.program_type =
            std.meta.stringToEnum(ProgramType, value) orelse
            return error.InvalidProgramType,
        .arguments => scratch.arguments = value,
        .proof => scratch.proof = value,
        .params => scratch.params = value,
        .report_out => scratch.report_out = value,
        .proof_format => {
            if (std.mem.eql(u8, value, "cairo-serde")) {
                scratch.proof_format = .cairo_serde;
            } else {
                scratch.proof_format =
                    std.meta.stringToEnum(ProofFormat, value) orelse
                    return error.InvalidProofFormat;
            }
        },
        .verify, .count => unreachable,
    }
}

fn requiredPath(path: ?[]const u8, comptime missing: anyerror) ![]const u8 {
    return (try optionalPath(path)) orelse return missing;
}

fn optionalPath(path: ?[]const u8) !?[]const u8 {
    if (path) |value| {
        if (value.len == 0 or value[0] == '-')
            return error.InvalidPath;
    }
    return path;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or
        std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(
    writer: anytype,
    command: ?Command,
    product_name: []const u8,
    backend_description: []const u8,
) !void {
    if (command == null) {
        try writer.print(
            \\Usage: {s} <command> [options]
            \\
        , .{product_name});
        try writer.writeAll(
            \\
            \\Commands:
            \\  prove          Prove one official Stwo-Cairo ProverInput
            \\  run-and-prove  Execute and prove one compiled Cairo program
            \\  capabilities   Print the machine-readable capability contract
            \\  identity       Print the immutable product identity
            \\
        );
        return writer.print("Backend: {s}\n", .{backend_description});
    }
    try writer.print("Usage: {s} ", .{product_name});
    switch (command.?) {
        .prove => try writer.writeAll(
            \\prove --prover-input PATH --proof PATH [options]
            \\  --params PATH          Authenticated proving-profile manifest
            \\  --proof-format FORMAT  json, cairo-serde, or binary
            \\  --report-out PATH      Write the machine-readable proving report
            \\  --verify               Verify before publishing the proof
            \\
        ),
        .run_and_prove => try writer.writeAll(
            \\run-and-prove --program PATH --proof PATH [options]
            \\  --program-type TYPE    Compiled program type: json or executable
            \\  --arguments PATH       Optional program arguments JSON
            \\  --params PATH          Authenticated proving-profile manifest
            \\  --proof-format FORMAT  json, cairo-serde, or binary
            \\  --report-out PATH      Write the machine-readable proving report
            \\  --verify               Verify before publishing the proof
            \\
        ),
        .capabilities => try writer.writeAll("capabilities\n"),
        .identity => try writer.writeAll("identity\n"),
    }
}

test "Cairo usage is parameterized by product identity" {
    var storage: [2048]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try writeUsage(
        &output,
        null,
        "stwo-cairo-test",
        "test backend",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.buffered(),
        "Usage: stwo-cairo-test",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.buffered(),
        "Backend: test backend",
    ) != null);
}

test "Cairo CPU prove command is explicit and strict" {
    const parsed = try parse(&.{
        "prove",
        "--prover-input",
        "program.json",
        "--proof",
        "proof.json",
        "--params",
        "params.json",
        "--verify",
    });
    try std.testing.expectEqualStrings(
        "program.json",
        parsed.prove.prover_input,
    );
    try std.testing.expect(parsed.prove.verify);
    try std.testing.expectEqual(ProofFormat.json, parsed.prove.proof_format);
}

test "Cairo CPU CLI admits the released Cairo-serde spelling" {
    const parsed = try parse(&.{
        "prove",
        "--prover-input",
        "program.json",
        "--proof",
        "proof.json",
        "--proof-format",
        "cairo-serde",
    });
    try std.testing.expectEqual(
        ProofFormat.cairo_serde,
        parsed.prove.proof_format,
    );
    try std.testing.expectEqualStrings(
        "cairo-serde",
        parsed.prove.proof_format.name(),
    );
}

test "Cairo CPU CLI admits the official compressed binary format" {
    const parsed = try parse(&.{
        "prove",
        "--prover-input",
        "program.json",
        "--proof",
        "proof.bin",
        "--proof-format",
        "binary",
    });
    try std.testing.expectEqual(ProofFormat.binary, parsed.prove.proof_format);
    try std.testing.expectEqualStrings(
        "binary",
        parsed.prove.proof_format.name(),
    );
}

test "Cairo CPU run-and-prove keeps execution arguments separate" {
    const parsed = try parse(&.{
        "run-and-prove",
        "--program",
        "compiled.json",
        "--program-type",
        "json",
        "--arguments",
        "arguments.json",
        "--proof",
        "proof.bin",
        "--proof-format",
        "binary",
        "--verify",
    });
    try std.testing.expectEqualStrings(
        "compiled.json",
        parsed.run_and_prove.program,
    );
    try std.testing.expectEqual(
        ProgramType.json,
        parsed.run_and_prove.program_type,
    );
    try std.testing.expectEqualStrings(
        "arguments.json",
        parsed.run_and_prove.arguments.?,
    );
    try std.testing.expect(parsed.run_and_prove.verify);
}

test "Cairo CPU run-and-prove admits modern executable artifacts" {
    const parsed = try parse(&.{
        "run-and-prove",
        "--program",
        "add_one.executable.json",
        "--program-type",
        "executable",
        "--arguments",
        "arguments.json",
        "--proof",
        "proof.json",
    });
    try std.testing.expectEqual(
        ProgramType.executable,
        parsed.run_and_prove.program_type,
    );
}

test "Cairo CPU CLI rejects unsupported and duplicate arguments" {
    try std.testing.expectError(error.DuplicateArgument, parse(&.{
        "prove",
        "--proof",
        "first.json",
        "--proof",
        "second.json",
        "--prover-input",
        "input.json",
    }));
    try std.testing.expectError(error.InvalidProofFormat, parse(&.{
        "prove",
        "--proof",
        "proof.json",
        "--prover-input",
        "input.json",
        "--proof-format",
        "postcard",
    }));
    try std.testing.expectError(error.InvalidProgramType, parse(&.{
        "run-and-prove",
        "--program",
        "program.sierra.json",
        "--program-type",
        "sierra",
        "--proof",
        "proof.json",
    }));
}
