//! Core behavior the scalar CPU backend delegates to; no consumer runtime work.
const std = @import("std");
const core = @import("stwo_core");
const cpu = @import("stwo_cpu_backend");
const M31 = core.fields.m31.M31;

comptime {
    if (cpu.CpuBackend.ColumnType(M31) != []M31 or
        cpu.CpuBackend.ColumnType(core.fields.qm31.QM31) != []core.fields.qm31.QM31)
        @compileError("actual CPU backend columns lost the canonical core field types");
}

fn invert(allocator: std.mem.Allocator) !void {
    const input: cpu.CpuBackend.ColumnType(M31) = try allocator.dupe(M31, &.{ M31.fromCanonical(2), M31.fromCanonical(3), M31.fromCanonical(4) });
    defer allocator.free(input);
    const before = [_]M31{ input[0], input[1], input[2] };
    const output = try core.fields.batchInverse(M31, allocator, input);
    defer allocator.free(output);
    const expected = [_]u32{ 1073741824, 1431655765, 536870912 };
    try std.testing.expectEqual(expected.len, output.len);
    try std.testing.expect(@intFromPtr(output.ptr) != @intFromPtr(input.ptr));
    for (output, expected) |actual, value| try std.testing.expect(actual.eql(M31.fromCanonical(value)));
    for (input, before) |actual, original| try std.testing.expect(actual.eql(original));
}

test "cdc: CPU batch inverse owns canonical exact results without changing input" {
    try invert(std.testing.allocator);
}

test "cdc: CPU batch inverse zero refusal preserves input and releases output" {
    const input = try std.testing.allocator.dupe(M31, &.{ M31.fromCanonical(7), M31.zero(), M31.fromCanonical(11) });
    defer std.testing.allocator.free(input);
    const before = [_]M31{ input[0], input[1], input[2] };
    try std.testing.expectError(error.DivisionByZero, core.fields.batchInverse(M31, std.testing.allocator, input));
    for (input, before) |actual, original| try std.testing.expect(actual.eql(original));
}

test "cdc: CPU batch inverse cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, invert, .{});
}
