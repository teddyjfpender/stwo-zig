//! Fresh process one: prove the tiny joined Ethereum leaf and publish v2.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const support = @import("ethereum_precompile_artifact_support.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    if (arguments.len != 2) {
        std.debug.print("usage: ethereum-precompile-artifact-producer <artifact-output>\n", .{});
        return error.InvalidArguments;
    }
    try produce(allocator, arguments[1]);
}

fn produce(allocator: std.mem.Allocator, output_path: []const u8) !void {
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
    const offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
        return error.InvalidFunctionalFixture;
    std.mem.writeInt(u32, elf[offset..][0..4], 0x0000_006f, .little);
    var run = try frontend.runner.runEthereumExtension(
        allocator,
        &elf,
        support.max_steps,
    );
    defer run.deinit();
    if (run.base.completion_reason != .self_loop or
        run.keccakf_calls.len() != 1 or
        run.signer_recovery_calls.len() != 1)
    {
        return error.InvalidFunctionalFixture;
    }

    var public = try support.OwnedPublicData.init(allocator, &run);
    defer public.deinit(allocator);
    var output = try frontend.prover_mod.proveEthereumWithEngineUsingExecution(
        support.Engine,
        allocator,
        support.pcs_config,
        &run.base.execution_trace,
        &run.keccakf_calls,
        &run.keccakf_execution_rows,
        &run.signer_recovery_calls,
        &run.signer_recovery_execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        null,
        public.value,
        .{ .cpu = .{
            .worker_count = 1,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        } },
    );
    defer output.deinit(allocator);
    const encoded = try support.proof_artifact.encodeAllocWithLimits(
        allocator,
        .{
            .pcs_config = support.pcs_config,
            .statement = &output.statement,
            .extension = &output.extension,
            .base_claim = output.base_claim,
            .extension_claim = &output.extension_claim,
            .proof = &output.proof,
        },
        support.artifact_limits,
    );
    defer allocator.free(encoded);
    try artifact_io.publishCreateOnly(output_path, encoded);
}
