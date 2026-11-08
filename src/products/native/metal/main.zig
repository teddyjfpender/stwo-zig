//! Focused Native Metal production proof lifecycle.

const std = @import("std");
const stwo = @import("stwo_native_metal");
const runner = @import("native_proof_runner");
const transaction = @import("native_transaction");
const identity = @import("identity.zig");
const registry = @import("registry.zig");

const atomic_file = stwo.interop.atomic_file;
const artifacts = stwo.interop.examples_artifact;
const artifact_verifier = stwo.interop.examples_artifact_verifier;

const Verify = struct {
    artifact: []const u8,
    protocol: runner.config.Protocol,
};

const Parsed = union(enum) {
    help,
    applications,
    prove: runner.config.Args,
    bench: runner.config.Args,
    verify: Verify,
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);
    switch (try parse(process_args[1..])) {
        .help => try writeUsage(std.fs.File.stdout().deprecatedWriter()),
        .applications => try writeApplications(),
        .prove => |args| {
            const output = args.proof_artifact_out orelse return error.MissingProofOutput;
            var request = args;
            request.warmups = 0;
            request.samples = 1;
            try transaction.prove(
                atomic_file,
                allocator,
                output,
                null,
                MetalRun{ .allocator = allocator, .args = request },
                MetalRun.execute,
            );
        },
        .bench => |args| try transaction.bench(
            atomic_file,
            allocator,
            args.proof_artifact_out,
            null,
            MetalRun{ .allocator = allocator, .args = args },
            MetalRun.execute,
        ),
        .verify => |request| {
            const encoded = try transaction.verifyPath(
                artifact_verifier,
                artifacts,
                allocator,
                request.artifact,
                securityPolicy(request.protocol),
                identity.value(),
            );
            defer allocator.free(encoded);
            try transaction.writeLine(std.fs.File.stdout().deprecatedWriter(), encoded);
        },
    }
}

const MetalRun = struct {
    allocator: std.mem.Allocator,
    args: runner.config.Args,

    fn execute(self: MetalRun, temporary: ?[]const u8, output: ?[]const u8) ![]u8 {
        var args = self.args;
        args.proof_artifact_out = temporary;
        args.proof_artifact_report_path = output;
        args.product_identity = identity.value();
        return runner.run(
            stwo.backends.metal.MetalProverEngine,
            .metal_hybrid,
            self.allocator,
            args,
        );
    }
};

fn parse(argv: []const []const u8) !Parsed {
    if (argv.len == 0 or (argv.len == 1 and isHelp(argv[0]))) return .help;
    if (std.mem.eql(u8, argv[0], "applications")) {
        if (argv.len != 1) return error.IrrelevantArgument;
        return .applications;
    }
    if (std.mem.eql(u8, argv[0], "verify")) return .{ .verify = try parseVerify(argv[1..]) };
    const mode: enum { prove, bench } = if (std.mem.eql(u8, argv[0], "prove"))
        .prove
    else if (std.mem.eql(u8, argv[0], "bench"))
        .bench
    else
        .bench;
    const run_argv = if (mode == .bench and !std.mem.eql(u8, argv[0], "bench")) argv else argv[1..];
    for (run_argv) |arg| {
        if (std.mem.eql(u8, arg, "--backend") or
            std.mem.startsWith(u8, arg, "--cuda-") or
            std.mem.eql(u8, arg, "--elf") or
            std.mem.eql(u8, arg, "--input")) return error.UnsupportedCapability;
    }
    const args = switch (try runner.config.parseArgs(.metal_hybrid, run_argv)) {
        .help => return .help,
        .run => |value| value,
    };
    if (args.metal_runtime.mode != .source_jit or
        args.metal_runtime.aot_bundle != null or
        args.metal_runtime.manifest_sha256 != null)
        return error.RuntimeIdentityMismatch;
    return if (mode == .prove) .{ .prove = args } else .{ .bench = args };
}

fn parseVerify(argv: []const []const u8) !Verify {
    var artifact: ?[]const u8 = null;
    var protocol: runner.config.Protocol = .secure;
    var index: usize = 0;
    while (index < argv.len) : (index += 2) {
        if (index + 1 >= argv.len) return error.MissingArgumentValue;
        if (std.mem.eql(u8, argv[index], "--artifact")) {
            artifact = argv[index + 1];
        } else if (std.mem.eql(u8, argv[index], "--protocol")) {
            protocol = std.meta.stringToEnum(runner.config.Protocol, argv[index + 1]) orelse
                return error.InvalidProtocol;
        } else return error.UnknownArgument;
    }
    return .{ .artifact = artifact orelse return error.MissingArtifact, .protocol = protocol };
}

fn securityPolicy(protocol: runner.config.Protocol) artifact_verifier.SecurityPolicy {
    return switch (protocol) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    };
}

fn isHelp(value: []const u8) bool {
    return std.mem.eql(u8, value, "--help") or std.mem.eql(u8, value, "-h");
}

fn writeUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: stwo-zig-native-metal <prove|bench|verify|applications> [options]
        \\
        \\  prove --proof-artifact-out PATH   Produce and self-verify one proof
        \\  bench [--proof-artifact-out PATH] Benchmark verified proof requests
        \\  verify --artifact PATH            Independently verify an artifact
        \\  --metal-runtime source-jit        Exact compiled runtime variant
        \\
        \\Backend: Apple Metal only. Device-labelled runs never fall back to CPU.
        \\
    );
}

fn writeApplications() !void {
    var buffer: [4096]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try registry.write(&output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

test "source-JIT product rejects authenticated AOT runtime selection" {
    try std.testing.expectError(error.RuntimeIdentityMismatch, parse(&.{
        "prove",
        "--proof-artifact-out",
        "proof.json",
        "--metal-runtime",
        "authenticated-aot",
        "--metal-aot-bundle",
        "/tmp/aot",
        "--metal-aot-manifest-sha256",
        "abababababababababababababababababababababababababababababababab",
    }));
}
