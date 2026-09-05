//! End-to-end combined Ethereum profile and continuation custody.

const std = @import("std");
const keccak_authority = @import("../../air/guest_precompile/keccakf_authority.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const runner = @import("../mod.zig");
const test_elf = @import("test_elf.zig");

fn descriptorOffset(elf: []const u8) usize {
    return std.mem.indexOf(u8, elf, execution_profile.admission.descriptor_magic) orelse
        unreachable;
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

test "Ethereum admission rejects every combined-profile identity drift" {
    const valid = test_elf.buildEthereum();
    const descriptor = descriptorOffset(&valid);
    try std.testing.expectEqual(
        runner.elf_loader.ExecutionProfile.rv32im_zkvm_ethereum_v1,
        try runner.elf_loader.requestedExecutionProfile(&valid),
    );

    {
        var elf = valid;
        put(u64, &elf, descriptor + 12, execution_profile.keccakf_capability_bit);
        try std.testing.expectError(
            error.UnsupportedRequiredCapabilities,
            runner.elf_loader.requestedExecutionProfile(&elf),
        );
    }
    {
        var elf = valid;
        put(u16, &elf, descriptor + 20, execution_profile.ethereum_abi_version + 1);
        try std.testing.expectError(
            error.UnsupportedEthereumAbi,
            runner.elf_loader.requestedExecutionProfile(&elf),
        );
    }
    {
        var elf = valid;
        elf[descriptor + 24] ^= 1;
        try std.testing.expectError(
            error.EthereumSemanticDigestMismatch,
            runner.elf_loader.requestedExecutionProfile(&elf),
        );
    }
}

test "Ethereum profile retires independent signer and Keccak tapes" {
    const elf = test_elf.buildEthereum();
    try std.testing.expectEqual(
        runner.elf_loader.ExecutionProfile.rv32im_zkvm_ethereum_v1,
        try runner.elf_loader.requestedExecutionProfile(&elf),
    );
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.run(std.testing.allocator, &elf, 16),
    );
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.runPoseidon2Extension(std.testing.allocator, &elf, 16),
    );
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.runKeccakfExtension(std.testing.allocator, &elf, 16),
    );

    var result = try runner.runEthereumExtension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 6), result.base.step_count);
    try std.testing.expectEqual(@as(usize, 4), result.base.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 1), result.signer_recovery_execution_rows.rows().len);
    try std.testing.expectEqual(@as(usize, 1), result.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 1), result.keccakf_execution_rows.rows().len);
    try std.testing.expectEqual(
        @as(u32, 3),
        result.signer_recovery_calls.records()[0].execution_clock,
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        result.keccakf_calls.records()[0].execution_clock,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        result.signer_recovery_execution_rows.rows()[0].call_index,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        result.keccakf_execution_rows.rows()[0].call_index,
    );
    try result.base.execution_trace.validateClockRange(0, 6, 2);

    var expected_keccak: keccak_authority.State = undefined;
    for (&expected_keccak, 0..) |*lane, index| {
        const input = result.keccakf_calls.records()[0].input;
        lane.* = input[2 * index] | (@as(u64, input[2 * index + 1]) << 32);
    }
    keccak_authority.permute(&expected_keccak);
    for (expected_keccak, 0..) |lane, index| {
        const output = result.keccakf_calls.records()[0].output;
        try std.testing.expectEqual(@as(u32, @truncate(lane)), output[2 * index]);
        try std.testing.expectEqual(@as(u32, @truncate(lane >> 32)), output[2 * index + 1]);
    }
}

test "Ethereum profile keeps each precompile tape segment-owned across resume" {
    const elf = test_elf.buildEthereum();
    var session = try runner.EthereumExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    var first = try session.startSegment(3);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 16);
    defer second.deinit();

    try std.testing.expectEqual(@as(usize, 1), first.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 0), first.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 0), second.signer_recovery_calls.len());
    try std.testing.expectEqual(@as(usize, 1), second.keccakf_calls.len());
    try first.base.execution_trace.validateClockRange(0, 3, 1);
    try second.base.execution_trace.validateClockRange(3, 6, 1);
    try first.base.rw_memory.requireContinuationTo(second.base.rw_memory);
    try std.testing.expectEqual(runner.CompletionReason.ecall, second.base.completion_reason.?);
}
