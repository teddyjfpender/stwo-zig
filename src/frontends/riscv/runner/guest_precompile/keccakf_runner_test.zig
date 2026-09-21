//! End-to-end Keccak-f profile execution and segmented clock custody.

const std = @import("std");
const authority = @import("../../air/guest_precompile/keccakf_authority.zig");
const runner = @import("../mod.zig");
const test_elf = @import("test_elf.zig");

fn fixtureInput() authority.State {
    var state: authority.State = undefined;
    for (&state, 0..) |*lane, index| {
        const low: u64 = 2 * index;
        const high: u64 = 2 * index + 1;
        lane.* = low | (high << 32);
    }
    return state;
}

test "Keccak-f profile retires one call outside the base trace" {
    const elf = test_elf.buildKeccakf(.ecall);
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.run(std.testing.allocator, &elf, 16),
    );
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.runPoseidon2Extension(std.testing.allocator, &elf, 16),
    );

    var result = try runner.runKeccakfExtension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), result.base.step_count);
    try std.testing.expectEqual(@as(usize, 3), result.base.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len());
    try std.testing.expectEqual(@as(usize, 1), result.execution_rows.rows().len);
    try std.testing.expectEqual(@as(u32, 3), result.calls.records()[0].execution_clock);
    try std.testing.expectEqual(@as(u32, 0x1008), result.calls.records()[0].pc);
    try result.base.execution_trace.validateClockRange(0, 4, 1);

    var expected = fixtureInput();
    authority.permute(&expected);
    for (expected, 0..) |lane, index| {
        try std.testing.expectEqual(
            @as(u32, @truncate(lane)),
            result.calls.records()[0].output[2 * index],
        );
        try std.testing.expectEqual(
            @as(u32, @truncate(lane >> 32)),
            result.calls.records()[0].output[2 * index + 1],
        );
    }
}

test "Keccak-f call and clock authority remain segment-owned across resume" {
    const elf = test_elf.buildKeccakf(.ecall);
    var session = try runner.KeccakfExecutionSession.init(std.testing.allocator, &elf, .{});
    defer session.deinit();
    var first = try session.startSegment(2);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 16);
    defer second.deinit();

    try std.testing.expectEqual(@as(usize, 0), first.calls.len());
    try std.testing.expectEqual(@as(usize, 1), second.calls.len());
    try first.base.execution_trace.validateClockRange(0, 2, 0);
    try second.base.execution_trace.validateClockRange(2, 4, 1);
    try first.base.rw_memory.requireContinuationTo(second.base.rw_memory);
    try std.testing.expectEqual(
        runner.CompletionReason.ecall,
        second.base.completion_reason.?,
    );
}
