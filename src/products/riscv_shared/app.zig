//! Backend-independent lifecycle and publication boundary for the focused
//! RISC-V products.
//!
//! `App(Deps)` is the CPU product's former `app.zig` with every backend-specific
//! binding lifted into `Deps`. The CPU product binds `CpuProverEngine, .cpu` and
//! the Metal product binds `MetalProverEngine, .metal`, so the output
//! transaction, the atomic publication order and the adapter error mapping exist
//! exactly once instead of once per backend.
//!
//! `Deps` is a namespace type that must expose:
//!
//!   * `stwo` — the product facade; only `interop.atomic_file` and
//!     `interop.riscv_artifact` are used here.
//!   * `adapter` — the engine-generic proof adapter (`Backend`, `Mode`,
//!     `Protocol`, `Options`, `PENDING_DIAGNOSTIC`, `run`, `verifyArtifact`).
//!   * `cli` — the product's command contract (`Command`, `Protocol`, `Run`,
//!     `Verify`, `parse`, `writeUsage`).
//!   * `registry` — the product's `applications` writer (`write`).
//!   * `output_transaction` — the proof/report publication transaction.
//!   * `Engine` — the prover engine bound at this product boundary.
//!   * `backend` — the `adapter.Backend` tag that names `Engine`.
//!
//! `output_transaction` is carried by `Deps` rather than imported here so this
//! file needs no named build module of its own: it imports `std` and nothing
//! else, and every product-specific module arrives through the binding.

const std = @import("std");

pub fn App(comptime Deps: type) type {
    return struct {
        const stwo = Deps.stwo;
        const adapter = Deps.adapter;
        const cli = Deps.cli;
        const registry = Deps.registry;
        const output_transaction = Deps.output_transaction;
        const Engine = Deps.Engine;
        const backend: adapter.Backend = Deps.backend;

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
                .help => |command| try cli.writeUsage(
                    std.fs.File.stdout().deprecatedWriter(),
                    command,
                ),
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

        pub fn runElf(
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

            const report = adapter.run(Engine, backend, allocator, run.elf_path, run.input_path, .{
                .backend = backend,
                .protocol = protocol(run.protocol),
                .mode = mode,
                .experimental = run.experimental,
                .proof_temporary = proof_temporary,
                .proof_report_path = proof_output,
            }) catch |err| switch (err) {
                error.AdapterNotReleaseGated => {
                    try writeLine(
                        std.fs.File.stderr().deprecatedWriter(),
                        adapter.PENDING_DIAGNOSTIC,
                    );
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

        pub fn verifyArtifact(allocator: std.mem.Allocator, request: cli.Verify) !void {
            var classified = try stwo.interop.riscv_artifact.classifyPath(
                allocator,
                request.artifact,
            );
            defer classified.deinit(allocator);
            switch (classified) {
                .riscv => |parsed| {
                    const expected = request.expected_statement_digest orelse
                        return error.MissingExpectedStatementDigest;
                    return adapter.verifyArtifact(
                        Engine,
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
    };
}
