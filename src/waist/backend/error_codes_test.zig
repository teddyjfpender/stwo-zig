//! Codes belong to the arena-plan error origin, not arbitrary error names.
const std = @import("std");
const backend = @import("mod.zig");
const core = @import("stwo_core");

test "backend arena diagnostics pin typed append-only meanings and foreign refusal" {
    const C = backend.error_codes;
    const function = @typeInfo(@TypeOf(C.fromArena)).@"fn";
    try std.testing.expect(function.params[0].type.? == (backend.arena_plan.Error || std.mem.Allocator.Error));
    try std.testing.expect(function.return_type.? == core.error_codes.Entry);
    const errors = [_]C.ArenaPlanError{ error.EmptySchedule, error.DuplicateLogicalId, error.UnsortedBindings, error.InvalidAlignment, error.InvalidTick, error.InvalidUseOrder, error.SizeOverflow, error.BudgetExceeded, error.AliasOverlap, error.UnknownBinding, error.BindingOutOfBounds, error.NarrowAddressOverflow, error.OutOfMemory };
    try std.testing.expectEqual(errors.len, C.table.len);
    for (errors, 0..) |err, index| {
        const entry = C.fromArena(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x2001 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqual(if (err == error.BudgetExceeded or err == error.OutOfMemory) core.error_codes.Class.resource_exhausted else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, C.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x2000, 0x200e, 0x4001, 0x5002, 65535 }) |code| try std.testing.expect(C.lookup(code) == null);
}

fn build(allocator: std.mem.Allocator) !void {
    const buffers = [_]backend.arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 64, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    var plan = try backend.arena_plan.build(allocator, &buffers, 16 * 1024);
    defer plan.deinit();
    try plan.validate(16 * 1024);
    try std.testing.expectEqual(@as(u64, 64), (try plan.binding(7)).size_bytes);
}

test "backend coded arena refusals retain primary errors and allocation cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, build, .{});
    try std.testing.expectError(error.EmptySchedule, backend.arena_plan.build(std.testing.allocator, &.{}, 0));
    const buffers = [_]backend.arena_plan.LogicalBuffer{.{ .id = 7, .size_bytes = 64, .alignment = 16, .live_ranges = &.{.{ .first = 0, .last = 1 }} }};
    try std.testing.expectError(error.BudgetExceeded, backend.arena_plan.build(std.testing.allocator, &buffers, 16 * 1024 - 1));
    var failure = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, backend.arena_plan.build(failure.allocator(), &buffers, 16 * 1024));
    try std.testing.expectEqual(failure.allocated_bytes, failure.freed_bytes);
}
