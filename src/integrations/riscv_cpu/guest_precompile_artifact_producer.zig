//! C-009 process one: prove the canonical one-call guest and publish its bytes.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const support = @import("guest_precompile_artifact_support.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print(
            "usage: guest-precompile-artifact-producer <artifact-output>\n",
            .{},
        );
        return error.InvalidArguments;
    }

    try produce(allocator, arguments[1]);
}

fn produce(allocator: std.mem.Allocator, output_path: []const u8) !void {
    const elf = frontend.testing.guest_precompile_test_elf.build(true, .self_loop);
    var run = try frontend.runner.runPoseidon2Extension(
        allocator,
        &elf,
        support.max_steps,
    );
    defer run.deinit();
    if (run.base.completion_reason != .self_loop or run.calls.len() != 1 or
        run.execution_rows.rows().len != 1)
    {
        return error.InvalidFunctionalFixture;
    }

    var public = try support.OwnedPublicData.init(allocator, &run);
    defer public.deinit(allocator);
    var output = try support.riscv_cpu.provePoseidon2WithPublicData(
        allocator,
        support.pcs_config,
        &run.base.execution_trace,
        &run.calls,
        &run.execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        null,
        public.value,
    );
    defer output.deinit(allocator);

    const encoded = try support.proof_artifact.encodeAllocWithLimits(
        allocator,
        .{
            .pcs_config = support.pcs_config,
            .statement = &output.statement,
            .extension = &output.extension,
            .artifact = output.artifact,
            .interaction_claim = output.interaction_claim,
            .proof = &output.proof,
        },
        support.artifact_limits,
    );
    defer allocator.free(encoded);
    try writeAtomic(output_path, encoded);
}

fn writeAtomic(path: []const u8, bytes: []const u8) !void {
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or
        std.mem.eql(u8, basename, ".."))
    {
        return error.InvalidOutputPath;
    }
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = if (std.fs.path.isAbsolute(parent_path))
        try std.fs.openDirAbsolute(parent_path, .{})
    else
        try std.fs.cwd().openDir(parent_path, .{});
    defer parent.close();

    var write_buffer: [64 * 1024]u8 = undefined;
    var transaction = try parent.atomicFile(basename, .{
        .write_buffer = &write_buffer,
    });
    defer transaction.deinit();
    try transaction.file_writer.interface.writeAll(bytes);
    try transaction.finish();
}
