//! Command contract for Native example AIRs on CPU scalar/SIMD.

const std = @import("std");
const runner = @import("native_proof_runner");

pub const Command = enum { prove, bench, verify, applications };
pub const SecurityPolicy = enum { secure, functional, smoke };

pub const Prove = struct {
    args: runner.config.Args,
    output: []const u8,
    report_out: ?[]const u8,
};

pub const Bench = struct {
    args: runner.config.Args,
    proof_out: ?[]const u8,
    report_out: ?[]const u8,
};

pub const Verify = struct {
    artifact: []const u8,
    security_policy: SecurityPolicy,
};

pub const Parsed = union(enum) {
    prove: Prove,
    bench: Bench,
    verify: Verify,
    applications: void,
    help: ?Command,
};

const ShellPaths = struct {
    output: ?[]const u8 = null,
    proof_out: ?[]const u8 = null,
    report_out: ?[]const u8 = null,
};

pub fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 0) return error.MissingCommand;
    if (isHelp(argv[0])) {
        if (argv.len != 1) return error.UnexpectedArgument;
        return .{ .help = null };
    }
    const command = std.meta.stringToEnum(Command, argv[0]) orelse return error.UnknownCommand;
    if (argv.len == 2 and isHelp(argv[1])) return .{ .help = command };
    return switch (command) {
        .prove => parseProve(argv[1..]),
        .bench => parseBench(argv[1..]),
        .verify => .{ .verify = try parseVerify(argv[1..]) },
        .applications => if (argv.len == 1)
            .{ .applications = {} }
        else
            error.IrrelevantArgument,
    };
}

fn parseProve(argv: []const []const u8) !Parsed {
    var storage: [64][]const u8 = undefined;
    const extracted = try extractRun(argv, &storage, .prove);
    var args = (try runner.config.parseArgs(.cpu_native, extracted.argv)).run;
    args.warmups = 0;
    args.samples = 1;
    args.profiled = false;
    return .{ .prove = .{
        .args = args,
        .output = try requiredPath(extracted.paths.output, error.MissingOutput),
        .report_out = try optionalPath(extracted.paths.report_out),
    } };
}

fn parseBench(argv: []const []const u8) !Parsed {
    var storage: [64][]const u8 = undefined;
    const extracted = try extractRun(argv, &storage, .bench);
    return .{ .bench = .{
        .args = (try runner.config.parseArgs(.cpu_native, extracted.argv)).run,
        .proof_out = try optionalPath(extracted.paths.proof_out),
        .report_out = try optionalPath(extracted.paths.report_out),
    } };
}

const Extracted = struct { argv: []const []const u8, paths: ShellPaths };

fn extractRun(
    argv: []const []const u8,
    storage: *[64][]const u8,
    command: enum { prove, bench },
) !Extracted {
    var count: usize = 0;
    var paths = ShellPaths{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const flag = argv[index];
        if (isForeignCapability(flag)) return error.UnsupportedCapability;
        if (std.mem.eql(u8, flag, "--proof-artifact-out"))
            return error.UnsupportedOutputFlag;
        const shell_path: ?enum { output, proof_out, report_out } = if (std.mem.eql(u8, flag, "--output"))
            .output
        else if (std.mem.eql(u8, flag, "--proof-out"))
            .proof_out
        else if (std.mem.eql(u8, flag, "--report-out"))
            .report_out
        else
            null;
        if (shell_path) |selected| {
            index += 1;
            if (index == argv.len) return error.MissingArgumentValue;
            const value = argv[index];
            switch (selected) {
                .output => {
                    if (paths.output != null) return error.DuplicateArgument;
                    paths.output = value;
                },
                .proof_out => {
                    if (paths.proof_out != null) return error.DuplicateArgument;
                    paths.proof_out = value;
                },
                .report_out => {
                    if (paths.report_out != null) return error.DuplicateArgument;
                    paths.report_out = value;
                },
            }
            continue;
        }
        if (command == .prove and (std.mem.eql(u8, flag, "--warmups") or
            std.mem.eql(u8, flag, "--samples") or std.mem.eql(u8, flag, "--profiled")))
            return error.BenchmarkOptionForProve;
        if (count == storage.len) return error.TooManyArguments;
        storage[count] = flag;
        count += 1;
    }
    if (command == .prove and paths.proof_out != null) return error.IrrelevantArgument;
    if (command == .bench and paths.output != null) return error.IrrelevantArgument;
    return .{ .argv = storage[0..count], .paths = paths };
}

fn parseVerify(argv: []const []const u8) !Verify {
    var artifact: ?[]const u8 = null;
    var security_policy: SecurityPolicy = .secure;
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const flag = argv[index];
        index += 1;
        if (index == argv.len) return error.MissingArgumentValue;
        const value = argv[index];
        if (std.mem.eql(u8, flag, "--artifact")) {
            if (artifact != null) return error.DuplicateArgument;
            artifact = value;
        } else if (std.mem.eql(u8, flag, "--protocol")) {
            security_policy = std.meta.stringToEnum(SecurityPolicy, value) orelse
                return error.InvalidProtocol;
        } else return error.UnknownArgument;
    }
    return .{
        .artifact = try requiredPath(artifact, error.MissingArtifact),
        .security_policy = security_policy,
    };
}

fn isForeignCapability(value: []const u8) bool {
    return std.mem.eql(u8, value, "--backend") or
        std.mem.startsWith(u8, value, "--metal-") or
        std.mem.startsWith(u8, value, "--cuda-") or
        std.mem.eql(u8, value, "--elf") or
        std.mem.eql(u8, value, "--input");
}

fn requiredPath(value: ?[]const u8, comptime missing: anyerror) ![]const u8 {
    const path = value orelse return missing;
    if (path.len == 0) return error.InvalidPath;
    return path;
}

fn optionalPath(value: ?[]const u8) !?[]const u8 {
    if (value) |path| if (path.len == 0) return error.InvalidPath;
    return value;
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

pub fn writeUsage(writer: anytype, command: ?Command) !void {
    if (command == null) return writer.writeAll(
        \\Usage: stwo-zig-native-cpu <command> [options]
        \\
        \\Commands:
        \\  prove          Produce and verify one Native proof
        \\  bench          Benchmark verified proving requests
        \\  verify         Independently verify a Native proof artifact
        \\  applications   Print the compiled application registry
        \\
        \\Backend: CPU scalar/SIMD only; no runtime fallback.
        \\
    );
    switch (command.?) {
        .prove => try writeRunUsage(writer, "prove --output PATH"),
        .bench => try writeRunUsage(writer, "bench [--proof-out PATH] [--report-out PATH]"),
        .verify => try writer.writeAll(
            \\Usage: stwo-zig-native-cpu verify --artifact PATH [--protocol secure|functional|smoke]
            \\
        ),
        .applications => try writer.writeAll("Usage: stwo-zig-native-cpu applications\n"),
    }
}

fn writeRunUsage(writer: anytype, command: []const u8) !void {
    try writer.print(
        \\Usage: stwo-zig-native-cpu {s} [options]
        \\  --example NAME       wide_fibonacci, xor, plonk, plonk_logup, state_machine, blake, poseidon
        \\  --protocol NAME      smoke, functional, or secure
        \\  --blake2-backend     auto, scalar, or simd
        \\  --report-out PATH    Write the machine-readable report
        \\
    , .{command});
}

test "focused parser admits Native CPU workloads and rejects foreign capabilities" {
    const request = (try parse(&.{
        "prove",          "--example", "wide_fibonacci", "--log-n-rows", "5",
        "--sequence-len", "8",         "--protocol",     "smoke",        "--output",
        "proof.json",
    })).prove;
    try std.testing.expectEqualStrings("proof.json", request.output);
    try std.testing.expectEqual(@as(usize, 1), request.args.samples);
    try std.testing.expectError(error.UnsupportedCapability, parse(&.{
        "prove", "--backend", "cpu", "--output", "proof.json",
    }));
    try std.testing.expectError(error.UnsupportedCapability, parse(&.{
        "bench", "--metal-runtime", "source-jit",
    }));
}

test "help contains only compiled capabilities" {
    var storage: [4096]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try writeUsage(&output, null);
    inline for (.{ "metal", "cuda", "cairo", "riscv", "stark-v", "elf" }) |forbidden|
        try std.testing.expect(std.mem.indexOf(u8, output.buffered(), forbidden) == null);
}
