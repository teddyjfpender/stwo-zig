//! End-to-end extension-runner tests with exact admission metadata.

const std = @import("std");
const runner = @import("../mod.zig");
const test_elf = @import("test_elf.zig");

test "explicit extension runner retires one custom call outside the base trace" {
    const elf = test_elf.build(true, .ecall);
    try std.testing.expectError(
        error.RequiredCapabilityUnavailable,
        runner.run(std.testing.allocator, &elf, 16),
    );

    var result = try runner.runPoseidon2Extension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 4), result.base.step_count);
    try std.testing.expectEqual(@as(usize, 3), result.base.execution_trace.rows.items.len);
    try std.testing.expectEqual(@as(usize, 1), result.calls.len());
    try std.testing.expectEqual(@as(usize, 1), result.execution_rows.rows().len);
    try std.testing.expectEqual(@as(u32, 3), result.calls.records()[0].execution_clock);
    try std.testing.expectEqual(@as(u32, 0x1008), result.calls.records()[0].pc);
    try std.testing.expectEqual(@as(u32, 0), result.execution_rows.rows()[0].call_index);
}

test "extension runner freezes zero calls canonically without changing base API" {
    const elf = test_elf.build(false, .ecall);
    var result = try runner.runPoseidon2Extension(std.testing.allocator, &elf, 16);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.calls.len());
    try std.testing.expectEqual(@as(usize, 0), result.calls.capacity());
    try std.testing.expectEqual(@as(usize, 0), result.execution_rows.rows().len);
    try std.testing.expectEqual(@as(usize, 0), result.execution_rows.capacity());
}
