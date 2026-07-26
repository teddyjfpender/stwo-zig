//! Strict command contract for the focused Cairo CPU/SIMD product.

const std = @import("std");

pub const Command = enum {
    prove,
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

pub const Parsed = union(enum) {
    prove: Prove,
    capabilities,
    identity,
    help: ?Command,
};

const Flag = enum {
    prover_input,
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
    const command = std.meta.stringToEnum(Command, argv[0]) orelse
        return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1]))
        return .{ .help = command };
    switch (command) {
        .capabilities, .identity => {
            if (argv.len != 1) return error.IrrelevantArgument;
            return if (command == .capabilities) .capabilities else .identity;
        },
        .prove => {},
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
    return .{ .prove = .{
        .prover_input = try requiredPath(
            scratch.prover_input,
            error.MissingProverInput,
        ),
        .proof = try requiredPath(scratch.proof, error.MissingProofOutput),
        .params = try optionalPath(scratch.params),
        .report_out = try optionalPath(scratch.report_out),
        .proof_format = scratch.proof_format,
        .verify = scratch.verify,
    } };
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

pub fn writeUsage(writer: anytype, command: ?Command) !void {
    if (command == null) return writer.writeAll(
        \\Usage: stwo-cairo-cpu <command> [options]
        \\
        \\Commands:
        \\  prove          Prove one official Stwo-Cairo ProverInput
        \\  capabilities   Print the machine-readable capability contract
        \\  identity       Print the immutable product identity
        \\
        \\Backend: CPU scalar/SIMD only; no runtime fallback.
        \\
    );
    switch (command.?) {
        .prove => try writer.writeAll(
            \\Usage: stwo-cairo-cpu prove --prover-input PATH --proof PATH [options]
            \\  --params PATH          Authenticated proving-profile manifest
            \\  --proof-format FORMAT  json, cairo-serde, or binary
            \\  --report-out PATH      Write the machine-readable proving report
            \\  --verify               Verify before publishing the proof
            \\
        ),
        .capabilities => try writer.writeAll(
            \\Usage: stwo-cairo-cpu capabilities
            \\
        ),
        .identity => try writer.writeAll(
            \\Usage: stwo-cairo-cpu identity
            \\
        ),
    }
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
}
