//! Lifecycle and publication boundary for the focused RISC-V CPU product.

const std = @import("std");
const stwo = @import("stwo_riscv_cpu");
const adapter = @import("riscv_adapter");
const cli = @import("cli.zig");
const registry = @import("registry.zig");

const atomic_file = stwo.interop.atomic_file;
const output_transaction = @import("output_transaction");

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
        .prove => |request| try runElf(
            allocator,
            request.run,
            .prove,
            request.output,
            request.report_out,
        ),
        .bench => |request| try runElf(
            allocator,
            request.run,
            .{ .bench = .{
                .warmups = request.warmups,
                .samples = request.samples,
                .profiled = request.profiled,
            } },
            request.proof_out,
            request.report_out,
        ),
    }
}

fn runElf(
    allocator: std.mem.Allocator,
    run: cli.Run,
    mode: adapter.Mode,
    proof_output: ?[]const u8,
    report_output: ?[]const u8,
) !void {
    try output_transaction.prepare(proof_output, report_output);

    const proof_temporary = if (proof_output) |path|
        try atomic_file.temporaryPathAlloc(allocator, path, "proof")
    else
        null;
    defer if (proof_temporary) |path| allocator.free(path);
    defer if (proof_temporary) |path| std.fs.cwd().deleteFile(path) catch {};

    const report = adapter.run(allocator, run.elf_path, run.input_path, .{
        .backend = .cpu,
        .protocol = protocol(run.protocol),
        .mode = mode,
        .experimental = run.experimental,
        .proof_temporary = proof_temporary,
        .proof_report_path = proof_output,
    }) catch |err| switch (err) {
        error.AdapterNotReleaseGated => {
            try writeLine(std.fs.File.stderr().deprecatedWriter(), adapter.PENDING_DIAGNOSTIC);
            std.process.exit(1);
        },
        else => return err,
    };
    defer allocator.free(report);

    if (proof_output) |path| {
        try output_transaction.publishResult(
            atomic_file,
            allocator,
            proof_temporary.?,
            path,
            report,
            report_output,
            std.fs.File.stdout().deprecatedWriter(),
        );
    } else {
        try output_transaction.publishReport(
            atomic_file,
            allocator,
            report,
            report_output,
            std.fs.File.stdout().deprecatedWriter(),
        );
    }
}

fn verifyArtifact(allocator: std.mem.Allocator, request: cli.Verify) !void {
    var classified = try stwo.interop.riscv_artifact.classifyPath(allocator, request.artifact);
    defer classified.deinit(allocator);
    switch (classified) {
        .riscv => |parsed| {
            const expected = request.expected_statement_digest orelse
                return error.MissingExpectedStatementDigest;
            return adapter.verifyArtifact(
                allocator,
                parsed.value,
                protocol(request.protocol),
                expected,
                request.elf_path,
            );
        },
        .other => return error.UnsupportedArtifactKind,
    }
}

fn protocol(value: cli.Protocol) adapter.Protocol {
    return switch (value) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    };
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

test "focused verifier rejects non-RISC-V artifacts" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "artifact.json", .data = "{}" });
    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "artifact.json");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.UnsupportedArtifactKind, verifyArtifact(
        std.testing.allocator,
        .{
            .artifact = path,
            .elf_path = "guest.elf",
            .protocol = .functional,
            .expected_statement_digest = [_]u8{0} ** 32,
        },
    ));
}
