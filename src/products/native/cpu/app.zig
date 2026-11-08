//! Lifecycle, verification, and publication for the Native CPU/SIMD CLI.

const std = @import("std");
const stwo = @import("stwo_native_cpu");
const runner = @import("native_proof_runner");
const cli = @import("cli.zig");
const identity = @import("identity.zig");
const lifecycle = @import("native_transaction");
const registry = @import("registry.zig");

const artifacts = stwo.interop.examples_artifact;
const artifact_verifier = stwo.interop.examples_artifact_verifier;
const atomic_file = stwo.interop.atomic_file;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);
    const parsed = cli.parse(process_args[1..]) catch |err| {
        try cli.writeUsage(std.fs.File.stderr().deprecatedWriter(), null);
        return err;
    };
    switch (parsed) {
        .help => |command| try cli.writeUsage(std.fs.File.stdout().deprecatedWriter(), command),
        .applications => try writeApplications(),
        .verify => |request| try verifyArtifact(allocator, request),
        .prove => |request| try prove(allocator, request),
        .bench => |request| try bench(allocator, request),
    }
}

fn prove(allocator: std.mem.Allocator, request: cli.Prove) !void {
    try lifecycle.prove(
        atomic_file,
        allocator,
        request.output,
        request.report_out,
        FocusedRun{ .allocator = allocator, .args = request.args },
        FocusedRun.execute,
    );
}

fn bench(allocator: std.mem.Allocator, request: cli.Bench) !void {
    try lifecycle.bench(
        atomic_file,
        allocator,
        request.proof_out,
        request.report_out,
        FocusedRun{ .allocator = allocator, .args = request.args },
        FocusedRun.execute,
    );
}

const FocusedRun = struct {
    allocator: std.mem.Allocator,
    args: runner.config.Args,

    fn execute(self: FocusedRun, temporary: ?[]const u8, output: ?[]const u8) ![]u8 {
        var args = self.args;
        args.proof_artifact_out = temporary;
        args.proof_artifact_report_path = output;
        args.product_identity = identity.value();
        return run(self.allocator, args);
    }
};

fn run(allocator: std.mem.Allocator, args: runner.config.Args) ![]u8 {
    return runner.run(
        stwo.examples.wide_fibonacci.CpuProverEngine,
        .cpu_native,
        allocator,
        args,
    );
}

fn verifyArtifact(allocator: std.mem.Allocator, request: cli.Verify) !void {
    const encoded = try lifecycle.verifyPath(
        artifact_verifier,
        artifacts,
        allocator,
        request.artifact,
        switch (request.security_policy) {
            .secure => .secure,
            .functional => .functional,
            .smoke => .smoke,
        },
        identity.value(),
    );
    defer allocator.free(encoded);
    try writeLine(std.fs.File.stdout().deprecatedWriter(), encoded);
}

fn writeApplications() !void {
    var buffer: [4096]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try registry.write(&output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn writeLine(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

test "bounded proving report carries the exact focused product identity" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const proof_path = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(proof_path);
    const artifact_path = try std.fs.path.join(std.testing.allocator, &.{ proof_path, "proof.json" });
    defer std.testing.allocator.free(artifact_path);
    var args = runner.config.Args{
        .protocol = .smoke,
        .warmups = 0,
        .samples = 1,
        .proof_artifact_out = artifact_path,
        .proof_artifact_report_path = "proof.json",
        .product_identity = identity.value(),
    };
    args.wide_fibonacci = .{ .log_n_rows = 5, .sequence_len = 8 };
    const report = try run(std.testing.allocator, args);
    defer std.testing.allocator.free(report);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, report, .{});
    defer parsed.deinit();
    const product = parsed.value.object.get("product_identity").?.object;
    try std.testing.expectEqualStrings("stwo-native-cpu", product.get("name").?.string);
    try std.testing.expectEqualStrings("cpu", product.get("backend").?.string);
    _ = try artifact_verifier.verifyPath(std.testing.allocator, artifact_path, .smoke);
    const proof_artifact = try std.fs.openFileAbsolute(artifact_path, .{});
    defer proof_artifact.close();
    const artifact_bytes = try proof_artifact.readToEndAlloc(std.testing.allocator, 1 << 20);
    defer std.testing.allocator.free(artifact_bytes);
    const product_identity = identity.value();
    try std.testing.expect(std.mem.indexOf(
        u8,
        artifact_bytes,
        product_identity.identity_sha256,
    ) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        artifact_bytes,
        product_identity.implementation_commit,
    ) == null);
}
