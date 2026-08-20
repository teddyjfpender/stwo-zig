//! Strict command contract for the focused RISC-V Metal product.
//!
//! The parser itself is the shared, spec-driven one in
//! `src/products/riscv_shared/cli.zig`; this file is the binding that fixes the
//! Metal product's vocabulary and re-exports the resulting surface. Because the
//! parser is shared, this CLI accepts exactly the command and flag shape the CPU
//! CLI accepts — that is what makes a CPU run and a Metal run comparable — while
//! `spec.backend` makes `metal` the only token `--backend` will accept here.

const std = @import("std");
const shared = @import("riscv_shared_cli");

pub const spec = shared.Spec{
    .executable = "stwo-zig-riscv-metal",
    .backend = "metal",
    .backend_note = "Backend: fail-closed Apple Metal only; no runtime fallback.",
};

const impl = shared.Cli(spec);

pub const Command = impl.Command;
pub const Protocol = impl.Protocol;
pub const Run = impl.Run;
pub const Prove = impl.Prove;
pub const Bench = impl.Bench;
pub const Verify = impl.Verify;
pub const Parsed = impl.Parsed;
pub const parse = impl.parse;

pub const GuestCommand = enum { prove, verify };

pub const GuestProve = struct {
    elf_path: []const u8,
    input_path: ?[]const u8,
    output: []const u8,
    report_out: ?[]const u8,
    max_steps: usize,
    protocol: Protocol,
};

pub const GuestVerify = struct {
    artifact: []const u8,
    protocol: Protocol,
};

pub const GuestParsed = union(enum) {
    prove: GuestProve,
    verify: GuestVerify,
    help: GuestCommand,
};

const GuestFlag = enum {
    elf,
    input,
    backend,
    protocol,
    output,
    artifact,
    report_out,
    max_steps,
    count,
};

const GuestScratch = struct {
    seen: [@intFromEnum(GuestFlag.count)]bool =
        [_]bool{false} ** @intFromEnum(GuestFlag.count),
    elf: ?[]const u8 = null,
    input: ?[]const u8 = null,
    backend: ?[]const u8 = null,
    protocol: Protocol = .secure,
    output: ?[]const u8 = null,
    artifact: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
    max_steps: ?usize = null,

    fn mark(self: *GuestScratch, flag: GuestFlag) !void {
        const index = @intFromEnum(flag);
        if (self.seen[index]) return error.DuplicateArgument;
        self.seen[index] = true;
    }
};

/// Parse only the exact guest-Poseidon2 command family. A null result means the
/// unchanged base CLI owns the argv. Unknown commands under this prefix fail
/// closed instead of being reinterpreted as a base command.
pub fn parseGuest(argv: []const []const u8) !?GuestParsed {
    if (argv.len == 0) return null;
    const command: GuestCommand = if (std.mem.eql(
        u8,
        argv[0],
        "guest-poseidon2-prove",
    ))
        .prove
    else if (std.mem.eql(u8, argv[0], "guest-poseidon2-verify"))
        .verify
    else {
        if (std.mem.startsWith(u8, argv[0], "guest-poseidon2-"))
            return error.UnknownCommand;
        return null;
    };
    if (argv.len == 2 and isHelp(argv[1])) return .{ .help = command };

    var scratch = GuestScratch{};
    var index: usize = 1;
    while (index < argv.len) {
        const flag = parseGuestFlag(argv[index]) orelse return error.UnknownArgument;
        try scratch.mark(flag);
        index += 1;
        if (index == argv.len) return error.MissingArgumentValue;
        try assignGuest(&scratch, flag, argv[index]);
        index += 1;
    }

    switch (command) {
        .prove => {
            if (scratch.backend == null) return error.MissingBackend;
            try requireGuestFlags(scratch, &.{
                .elf,
                .input,
                .backend,
                .protocol,
                .output,
                .report_out,
                .max_steps,
            });
        },
        .verify => try requireGuestFlags(scratch, &.{ .artifact, .protocol }),
    }

    return switch (command) {
        .prove => .{ .prove = .{
            .elf_path = try requiredPath(scratch.elf, error.MissingElf),
            .input_path = try optionalPath(scratch.input),
            .output = try requiredPath(scratch.output, error.MissingOutput),
            .report_out = try optionalPath(scratch.report_out),
            .max_steps = scratch.max_steps orelse return error.MissingMaxSteps,
            .protocol = scratch.protocol,
        } },
        .verify => .{ .verify = .{
            .artifact = try requiredPath(scratch.artifact, error.MissingArtifact),
            .protocol = scratch.protocol,
        } },
    };
}

fn parseGuestFlag(value: []const u8) ?GuestFlag {
    if (!std.mem.startsWith(u8, value, "--")) return null;
    const raw = value[2..];
    var normalized: [32]u8 = undefined;
    if (raw.len > normalized.len) return null;
    for (raw, 0..) |byte, index|
        normalized[index] = if (byte == '-') '_' else byte;
    return std.meta.stringToEnum(GuestFlag, normalized[0..raw.len]);
}

fn assignGuest(scratch: *GuestScratch, flag: GuestFlag, value: []const u8) !void {
    switch (flag) {
        .elf => scratch.elf = value,
        .input => scratch.input = value,
        .backend => {
            if (!std.mem.eql(u8, value, spec.backend))
                return error.UnsupportedBackend;
            scratch.backend = value;
        },
        .protocol => {
            scratch.protocol = std.meta.stringToEnum(Protocol, value) orelse
                return error.InvalidProtocol;
            if (scratch.protocol == .smoke) return error.UnsupportedGuestProtocol;
        },
        .output => scratch.output = value,
        .artifact => scratch.artifact = value,
        .report_out => scratch.report_out = value,
        .max_steps => {
            const parsed = try std.fmt.parseInt(usize, value, 10);
            if (parsed == 0 or parsed > 50_000_000) return error.InvalidMaxSteps;
            scratch.max_steps = parsed;
        },
        .count => unreachable,
    }
}

fn requireGuestFlags(
    scratch: GuestScratch,
    allowed: []const GuestFlag,
) !void {
    for (0..@intFromEnum(GuestFlag.count)) |index| {
        if (!scratch.seen[index]) continue;
        const flag: GuestFlag = @enumFromInt(index);
        if (std.mem.indexOfScalar(GuestFlag, allowed, flag) == null)
            return error.IrrelevantArgument;
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
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(writer: anytype, command: ?Command) !void {
    try impl.writeUsage(writer, command);
    if (command == null) {
        try writer.writeAll(
            "  guest-poseidon2-prove   Prove the exact version-1 guest profile\n" ++
                "  guest-poseidon2-verify  Verify its bounded binary artifact\n\n",
        );
    }
}

pub fn writeGuestUsage(writer: anytype, command: GuestCommand) !void {
    switch (command) {
        .prove => try writer.writeAll(
            "Usage: stwo-zig-riscv-metal guest-poseidon2-prove\n" ++
                "       --elf PATH [--input PATH] --backend metal --max-steps N\n" ++
                "       --output PATH [--report-out PATH]\n" ++
                "       [--protocol secure|functional]\n\n" ++
                "The default secure PCS policy is release-facing. Functional is an\n" ++
                "explicit development/evidence policy and is labelled as such.\n\n",
        ),
        .verify => try writer.writeAll(
            "Usage: stwo-zig-riscv-metal guest-poseidon2-verify\n" ++
                "       --artifact PATH [--protocol secure|functional]\n\n",
        ),
    }
}

test "only ELF and Metal are accepted" {
    const parsed = (try parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal", "--output", "proof.json",
    })).prove;
    try std.testing.expectEqualStrings("guest.elf", parsed.run.elf_path);
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "cpu", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnsupportedBackend, parse(&.{
        "prove", "--elf", "guest.elf", "--backend", "metal-hybrid", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnknownArgument, parse(&.{
        "prove", "--air", "wide_fibonacci", "--backend", "metal", "--output", "proof.json",
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

test "the benchmark contract matches the CPU lane it is compared against" {
    const request = (try parse(&.{
        "bench",
        "--elf",
        "guest.elf",
        "--backend",
        "metal",
        "--protocol",
        "secure",
        "--warmups",
        "1",
        "--samples",
        "3",
        "--proof-out",
        "proof.json",
    })).bench;
    try std.testing.expectEqual(@as(usize, 1), request.warmups);
    try std.testing.expectEqual(@as(usize, 3), request.samples);
    try std.testing.expectEqual(Protocol.secure, request.run.protocol);
    try std.testing.expect(!request.run.experimental);
}

test "exact guest Poseidon2 commands are opt in and profile bounded" {
    const prove = (try parseGuest(&.{
        "guest-poseidon2-prove",
        "--elf",
        "guest.elf",
        "--input",
        "input.bin",
        "--backend",
        "metal",
        "--max-steps",
        "900000",
        "--output",
        "proof.stw",
        "--protocol",
        "functional",
    })).?.prove;
    try std.testing.expectEqualStrings("guest.elf", prove.elf_path);
    try std.testing.expectEqualStrings("input.bin", prove.input_path.?);
    try std.testing.expectEqual(@as(usize, 900_000), prove.max_steps);
    try std.testing.expectEqual(Protocol.functional, prove.protocol);

    const verify = (try parseGuest(&.{
        "guest-poseidon2-verify",
        "--artifact",
        "proof.stw",
    })).?.verify;
    try std.testing.expectEqual(Protocol.secure, verify.protocol);
    try std.testing.expect((try parseGuest(&.{
        "prove", "--elf", "base.elf", "--backend", "metal", "--output", "proof.json",
    })) == null);
}

test "guest Poseidon2 parser rejects generic profiles and unsafe ambiguity" {
    try std.testing.expectError(error.UnknownCommand, parseGuest(&.{
        "guest-poseidon2-bench",
    }));
    try std.testing.expectError(error.UnsupportedBackend, parseGuest(&.{
        "guest-poseidon2-prove", "--elf", "guest.elf", "--backend", "cpu",
        "--max-steps",           "1",     "--output",  "proof.stw",
    }));
    try std.testing.expectError(error.MissingMaxSteps, parseGuest(&.{
        "guest-poseidon2-prove", "--elf",     "guest.elf", "--backend", "metal",
        "--output",              "proof.stw",
    }));
    try std.testing.expectError(error.UnsupportedGuestProtocol, parseGuest(&.{
        "guest-poseidon2-verify", "--artifact", "proof.stw", "--protocol", "smoke",
    }));
    try std.testing.expectError(error.IrrelevantArgument, parseGuest(&.{
        "guest-poseidon2-verify", "--artifact", "proof.stw", "--backend", "metal",
    }));
}

test "help does not advertise unrelated products" {
    var storage: [4096]u8 = undefined;
    var root_output = std.Io.Writer.fixed(&storage);
    try writeUsage(&root_output, null);
    const root_text = root_output.buffered();
    try expectFocusedHelp(root_text);
    try std.testing.expect(
        std.mem.indexOf(u8, root_text, "guest-poseidon2-prove") != null,
    );

    inline for (.{ Command.prove, Command.bench, Command.verify, Command.applications }) |command| {
        var output = std.Io.Writer.fixed(&storage);
        try writeUsage(&output, command);
        const text = output.buffered();
        try expectFocusedHelp(text);
    }
}

fn expectFocusedHelp(text: []const u8) !void {
    try std.testing.expect(
        std.mem.indexOf(u8, text, "stwo-zig-riscv-metal") != null,
    );
    inline for (.{ "cpu", "cuda", "cairo", "wide_fibonacci", "native" }) |forbidden|
        try std.testing.expect(std.mem.indexOf(u8, text, forbidden) == null);
}
