const std = @import("std");
const R = @import("rom.zig");
const A = @import("../word16_index_control/authority.zig");
const Source = @import("trace.zig").Source;
const Public = @import("public.zig").Public;
const Record = @import("../../retirement.zig").Retirement;
const a = std.testing.allocator;
const AND: u32 = 0x0020f1b3;
fn same(view: R.MetadataView, pc: u64) !void {
    var reference = view;
    reference.contiguous = false;
    if (reference.lookup(pc)) |expected| {
        try std.testing.expectEqual(expected, try view.lookup(pc));
    } else |expected| {
        try std.testing.expectError(expected, view.lookup(pc));
    }
}
test "immutable contiguous lookup matches sparse authority at full64 high and maximum boundaries" {
    for ([_]u64{ 0, 1024, 0x8000000000000400, std.math.maxInt(u64) - 7 }) |base| {
        var setup = try R.Setup.init(a, .{ .base = base, .words = &.{ AND, AND } });
        defer setup.deinit();
        try std.testing.expect(setup.contiguous);
        const view = setup.metadataView();
        try std.testing.expectEqual(@as(usize, 0), try view.lookup(base));
        try std.testing.expectEqual(@as(usize, 1), try view.lookup(base + 4));
        for ([_]u64{ base, base + 1, base + 4, base +% 8, base -% 4, base & 0x0000ffffffffffff }) |pc| try same(view, pc);
    }
    try std.testing.expect(!R.contiguousAddresses(&.{}));
    try std.testing.expect(!R.contiguousAddresses(&.{ std.math.maxInt(u64) - 3, 0 }));
    try std.testing.expect(!R.contiguousAddresses(&.{ 4, 4 }));
    const high: u64 = 0x8000000000000400;
    const addresses = [_]u64{ 0, 4, high, std.math.maxInt(u64) - 3 };
    var sparse = try R.Setup.init(a, .{ .base = 0, .words = &.{ AND, AND, AND, AND }, .addresses = &addresses });
    defer sparse.deinit();
    try std.testing.expect(!sparse.contiguous);
    for (addresses, 0..) |pc, i| try std.testing.expectEqual(i, try sparse.lookup(pc));
    for ([_]u64{ 8, 1024, high + 4, high + 1 }) |pc| try std.testing.expectError(error.UnknownWord16CpuPc, sparse.lookup(pc));
}
fn checkInvalid(authority: *const A.Authority, pc: u64) !void {
    var view = authority.metadataView();
    // Deliberately remove decode storage: rejection must precede ALL cache reads.
    view.decoded = &.{};
    try std.testing.expectError(error.InvalidWord16CpuRecords, view.lookup(pc));
    const public = Public{ .steps = 1, .initial_pc = pc, .final_pc = pc +% 4, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    const records = [_]Record{std.mem.zeroes(Record)};
    try std.testing.expectError(error.InvalidWord16CpuRecords, Source.initMetadata(a, view, public, 5, &records));
}
test "both lookup paths check immutable admission before decoded cache access" {
    var contiguous = try A.Authority.init(a, .{ .base = 1024, .words = &.{ 0, AND } });
    defer contiguous.deinit();
    try std.testing.expect(contiguous.contiguous);
    try checkInvalid(&contiguous, 1024);
    const high: u64 = 0x8000000000000400;
    var sparse = try A.Authority.init(a, .{ .base = 0, .words = &.{ AND, 0 }, .addresses = &.{ 0, high } });
    defer sparse.deinit();
    try std.testing.expect(!sparse.contiguous);
    try checkInvalid(&sparse, high);
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var raw = try R.Setup.init(allocator, .{ .base = std.math.maxInt(u64) - 7, .words = &.{ AND, AND } });
    defer raw.deinit();
    var index = try A.Authority.init(allocator, .{ .base = 0, .words = &.{ 0, AND }, .addresses = &.{ 0, 0x8000000000000400 } });
    defer index.deinit();
}
test "immutable lookup derivation retains all setup allocation failure cleanup" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
