//! Production proof CLI lifecycle, dispatch, verification, and publication.

const std = @import("std");
const stwo = @import("stwo");
const cli = @import("cli.zig");
const native_dispatch = @import("native_dispatch.zig");
const native_transaction = @import("native_transaction");
const output_transaction = @import("output_transaction");
const product_identity = @import("native_product_identity");
const registry = @import("registry.zig");
const riscv_adapter = @import("riscv_adapter");

const atomic_file = stwo.interop.atomic_file;
const artifact_verifier = stwo.interop.examples_artifact_verifier;

/// The aggregate CLI's RISC-V prover engine and the adapter backend tag that
/// names it. `riscv_adapter` is engine-generic, so the engine is bound here at
/// the product boundary exactly as `src/products/riscv_cpu/app.zig` binds it for
/// the focused product. This CLI links only the CPU commitment backend, so `.cpu`
/// is the only tag it may ever pass; a request for any other device backend is
/// still mapped to `.unavailable_device` below and fails closed inside `run`.
const RiscVEngine = stwo.integrations.riscv_cpu.CpuProverEngine;
const riscv_backend: riscv_adapter.Backend = .cpu;

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
        .verify => |request| verifyArtifact(allocator, request) catch |err| switch (err) {
            error.AdapterNotReleaseGated => {
                try writeLine(std.fs.File.stderr().deprecatedWriter(), riscv_adapter.PENDING_DIAGNOSTIC);
                std.process.exit(1);
            },
            else => return err,
        },
        .prove => |request| try prove(allocator, request),
        .bench => |request| try bench(allocator, request),
        .prove_elf => |request| try runElf(allocator, request.run, .prove, request.output, request.report_out),
        .bench_elf => |request| try runElf(
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
    run: cli.ElfRun,
    mode: riscv_adapter.Mode,
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

    const report = riscv_adapter.run(RiscVEngine, riscv_backend, allocator, run.elf_path, run.input_path, .{
        .backend = switch (run.backend) {
            .cpu => .cpu,
            .metal_hybrid => .unavailable_device,
        },
        .protocol = riscvProtocol(run.protocol),
        .mode = mode,
        .experimental = run.experimental,
        .proof_temporary = proof_temporary,
        .proof_report_path = proof_output,
    }) catch |err| switch (err) {
        error.AdapterNotReleaseGated => {
            try writeLine(std.fs.File.stderr().deprecatedWriter(), riscv_adapter.PENDING_DIAGNOSTIC);
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

fn prove(allocator: std.mem.Allocator, request: cli.Prove) !void {
    try native_transaction.prove(
        atomic_file,
        allocator,
        request.output,
        request.report_out,
        NativeRun{ .allocator = allocator, .run = request.run },
        NativeRun.prove,
    );
}

fn bench(allocator: std.mem.Allocator, request: cli.Bench) !void {
    try native_transaction.bench(
        atomic_file,
        allocator,
        request.proof_out,
        request.report_out,
        NativeRun{
            .allocator = allocator,
            .run = request.run,
            .warmups = request.warmups,
            .samples = request.samples,
            .profiled = request.profiled,
        },
        NativeRun.execute,
    );
}

const NativeRun = struct {
    allocator: std.mem.Allocator,
    run: cli.Run,
    warmups: usize = 0,
    samples: usize = 1,
    profiled: bool = false,

    fn prove(self: NativeRun, temporary: ?[]const u8, output: ?[]const u8) ![]u8 {
        return self.runWith(temporary, output);
    }

    fn execute(self: NativeRun, temporary: ?[]const u8, output: ?[]const u8) ![]u8 {
        return self.runWith(temporary, output);
    }

    fn runWith(self: NativeRun, temporary: ?[]const u8, output: ?[]const u8) ![]u8 {
        return native_dispatch.run(self.allocator, self.run, .{
            .warmups = self.warmups,
            .samples = self.samples,
            .profiled = self.profiled,
            .proof_temporary = temporary,
            .proof_report_path = output,
        });
    }
};

fn verifyArtifact(allocator: std.mem.Allocator, request: cli.Verify) !void {
    var classified = try stwo.interop.riscv_artifact.classifyPath(allocator, request.artifact);
    defer classified.deinit(allocator);
    const native_bytes: []const u8 = switch (classified) {
        .riscv => |parsed| {
            const expected = request.expected_statement_digest orelse
                return error.MissingExpectedStatementDigest;
            const elf_path = request.elf_path orelse return error.MissingElf;
            return riscv_adapter.verifyArtifact(
                RiscVEngine,
                allocator,
                parsed.value,
                riscvProtocol(request.protocol),
                expected,
                elf_path,
            );
        },
        .other => |raw| raw,
    };
    if (request.expected_statement_digest != null)
        return error.ExpectedStatementDigestRequiresRiscVArtifact;
    if (request.elf_path != null) return error.ElfRequiresRiscVArtifact;
    const encoded = try native_transaction.verifyBytes(
        artifact_verifier,
        stwo.interop.examples_artifact,
        allocator,
        native_bytes,
        switch (request.protocol) {
            .secure => .secure,
            .functional => .functional,
            .smoke => .smoke,
        },
        product_identity.value(),
    );
    defer allocator.free(encoded);
    try writeLine(std.fs.File.stdout().deprecatedWriter(), encoded);
}

fn writeApplications() !void {
    const stdout = std.fs.File.stdout().deprecatedWriter();
    try registry.write(stdout);
    try stdout.writeByte('\n');
}

fn riscvProtocol(value: cli.Protocol) riscv_adapter.Protocol {
    return switch (value) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    };
}

fn writeLine(writer: anytype, bytes: []const u8) !void {
    try writer.writeAll(bytes);
    try writer.writeByte('\n');
}

test "RISC-V adapter: CPU path is live while unavailable device backends fail closed" {
    // Prove mode reaches real execution: a missing ELF surfaces as a file
    // error, proving the staged path is wired rather than gated.
    try std.testing.expectError(error.FileNotFound, riscv_adapter.run(
        RiscVEngine,
        riscv_backend,
        std.testing.allocator,
        "definitely-missing-guest.elf",
        null,
        .{
            .backend = .cpu,
            .protocol = .secure,
            .mode = .prove,
            .experimental = !registry.RISCV_ADAPTER_RELEASE_GATED,
            .proof_temporary = "proof.tmp",
            .proof_report_path = "proof.json",
        },
    ));
    // Device backends remain gated until a device-native RISC-V engine lands.
    try std.testing.expectError(error.AdapterNotReleaseGated, riscv_adapter.run(
        RiscVEngine,
        riscv_backend,
        std.testing.allocator,
        "guest.elf",
        null,
        .{
            .backend = .unavailable_device,
            .protocol = .secure,
            .mode = .prove,
            .experimental = !registry.RISCV_ADAPTER_RELEASE_GATED,
            .proof_temporary = "proof.tmp",
            .proof_report_path = "proof.json",
        },
    ));
}

test "publication rejects an existing report without exposing its proof" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_temporary = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.tmp" });
    defer std.testing.allocator.free(proof_temporary);
    const proof_output = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_output);
    const report_output = try std.fs.path.join(std.testing.allocator, &.{ root, "report.json" });
    defer std.testing.allocator.free(report_output);

    try atomic_file.writeExclusive(std.testing.allocator, proof_temporary, "proof");
    try atomic_file.writeExclusive(std.testing.allocator, report_output, "existing");
    try std.testing.expectError(
        error.OutputAlreadyExists,
        output_transaction.publishResult(
            atomic_file,
            std.testing.allocator,
            proof_temporary,
            proof_output,
            "report",
            report_output,
            std.fs.File.stdout().deprecatedWriter(),
        ),
    );
    try std.testing.expectError(
        error.FileNotFound,
        std.fs.cwd().access(proof_output, .{}),
    );
    const report = try std.fs.cwd().readFileAlloc(std.testing.allocator, report_output, 32);
    defer std.testing.allocator.free(report);
    try std.testing.expectEqualStrings("existing", report);
}

test "production transaction proves and verifies a bounded Native workload" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const proof_path = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(proof_path);

    const report = try native_dispatch.run(std.testing.allocator, .{
        .backend = .cpu,
        .protocol = .smoke,
        .workload = .{ .wide_fibonacci = .{ .log_n_rows = 5, .sequence_len = 8 } },
        .blake2_backend = .auto,
        .metal_runtime = .{},
        .resource_profile = .standard,
    }, .{
        .warmups = 0,
        .samples = 1,
        .profiled = false,
        .proof_temporary = proof_path,
        .proof_report_path = proof_path,
    });
    defer std.testing.allocator.free(report);
    const verified = try artifact_verifier.verifyPath(std.testing.allocator, proof_path, .smoke);
    try std.testing.expectEqual(artifact_verifier.Example.wide_fibonacci, verified.example);
    try std.testing.expect(verified.proof_bytes > 0);
}
