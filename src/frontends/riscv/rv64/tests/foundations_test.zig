const std = @import("std");
const rv = @import("../mod.zig");
const cache = @import("../decode_cache.zig");
const machine = @import("../machine.zig");
const mem = @import("../memory.zig");
const equal = std.testing.expectEqual;
const expect = std.testing.expect;
const alloc = std.testing.allocator;

fn code(memory: *mem.Memory, address: u64, word: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, word, .little);
    try memory.initialize(address, &bytes);
}

fn setup(allocator: std.mem.Allocator) !mem.Memory {
    var memory = mem.Memory.init(allocator, .{});
    errdefer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 4096, .permissions = .{ .read = true, .execute = true } });
    try code(&memory, 0x1000, 0x00108093); // addi x1,x1,1
    try code(&memory, 0x1004, 0x00108093);
    try code(&memory, 0x1008, 0x00100073); // breakpoint
    return memory;
}

test "rv64 foundation: cached and uncached retirements are identical" {
    var memory = try setup(alloc);
    defer memory.deinit();
    var decoder = try cache.Cache.init(alloc, 1);
    defer decoder.deinit();
    var a = machine.Cpu.init(0x1000, 0);
    var b = a;
    for (0..2) |_| try equal(try a.step(&memory), try b.stepCached(&memory, &decoder));
    try equal(a, b);
    try std.testing.expectError(error.Breakpoint, b.stepCached(&memory, &decoder));
    try equal(a, b);
}

test "rv64 foundation: code writes and cache collisions cannot reuse stale decoding" {
    var memory = try setup(alloc);
    defer memory.deinit();
    var decoder = try cache.Cache.init(alloc, 1);
    defer decoder.deinit();
    var cpu = machine.Cpu.init(0x1000, 0);
    _ = try cpu.stepCached(&memory, &decoder);
    try code(&memory, 0x1004, 0x00708093);
    _ = try cpu.stepCached(&memory, &decoder);
    try equal(@as(u64, 8), cpu.read(1));
    try code(&memory, 0x1008, 0);
    const before = cpu;
    try std.testing.expectError(error.IllegalInstruction, cpu.stepCached(&memory, &decoder));
    try equal(before, cpu);
    try code(&memory, 0x1008, 0x00108093);
    _ = try cpu.stepCached(&memory, &decoder);
    try equal(@as(u64, 9), cpu.read(1));
}

test "rv64 foundation: bounded batches preserve prefixes, global clocks and exact budgets" {
    var memory = try setup(alloc);
    defer memory.deinit();
    var session = try rv.Session.init(alloc, machine.Cpu.init(0x1000, 0), &memory, .{ .max_retirements = 2 });
    defer session.deinit();
    try equal(@as(usize, 0), session.runInto(&.{}).written);
    var rows: [3]machine.Retirement = undefined;
    const first = session.runInto(rows[0..1]);
    try equal(@as(usize, 1), first.written);
    try expect(first.stop == null);
    try equal(@as(u64, 1), rows[0].clock);
    const next = session.runInto(&rows);
    try equal(@as(usize, 1), next.written);
    try equal(@as(?@import("../session.zig").Error, error.StepLimit), next.stop);
    try equal(@as(u64, 2), rows[0].clock);
    try equal(@as(u64, 1), rows[0].previous_rd.toInt());
    session.max_retirements = 3;
    const trapped = session.runInto(&rows);
    try equal(@as(usize, 0), trapped.written);
    try equal(@as(?@import("../session.zig").Error, error.Breakpoint), trapped.stop);
    try equal(@as(u64, 2), session.cpu.retired);
}

test "rv64 foundation: retirement canonicalizes unused encoding fields" {
    var memory = try setup(alloc);
    defer memory.deinit();
    try code(&memory, 0x1000, 0x01f00093); // addi x1,x0,31, encoding rs2=31
    try code(&memory, 0x1004, 0x0ff2828f); // fence with reserved rd/rs1
    var cpu = machine.Cpu.init(0x1000, 0);
    cpu.regs[31] = 999;
    const immediate = try cpu.step(&memory);
    try equal(@as(u5, 0), immediate.rs2);
    try equal(@as(u64, 0), immediate.rhs.toInt());
    try equal(@as(u64, 31), immediate.immediate.toInt());
    const fence = try cpu.step(&memory);
    try equal(@as(u5, 0), fence.rs1);
    try equal(@as(u5, 0), fence.rs2);
    try equal(@as(u5, 0), fence.rd);
    try expect(!fence.writes_rd);
    try equal(@as(u64, 0), fence.previous_rd.toInt());
}

test "rv64 foundation: partial write observations preserve neighbouring bytes on write-only mappings" {
    var memory = mem.Memory.init(alloc, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x2000, .size = 8, .permissions = .{ .write = true } });
    try memory.initialize(0x2000, &.{ 1, 2, 3, 4, 5, 6, 7, 8 });
    const observed = try memory.storeObserved(0x2002, 2, 0xffffabcd);
    try equal(@as(u64, 0x0807060504030201), observed.before_word);
    try equal(@as(u64, 0x08070605abcd0201), observed.after_word);
    try equal(@as(u64, 0xabcd), observed.value);
    try std.testing.expectError(error.AccessDenied, memory.load(0x2000, 8));
}

test "rv64 foundation: permission cache never widens access across sub-page boundaries" {
    var memory = mem.Memory.init(alloc, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1002, .size = 2, .permissions = .{} });
    try memory.map(.{ .start = 0x1000, .size = 2, .permissions = .{ .read = true, .execute = true } });
    try memory.initialize(0x1000, &.{ 1, 2, 3, 4 });
    try equal(@as(u64, 0x201), try memory.load(0x1000, 2));
    try std.testing.expectError(error.AccessDenied, memory.load(0x1000, 4));
    try std.testing.expectError(error.AccessDenied, memory.fetch(0x1000));
    try std.testing.expectError(error.UnmappedAddress, memory.load(0x1004, 1));
    try equal(@as(u64, 1), try memory.load(0x1000, 1));
}

test "rv64 foundation: page cache tags full addresses and does not cache zero misses" {
    var memory = mem.Memory.init(alloc, .{});
    defer memory.deinit();
    const addresses = [_]u64{ 0x4000, 0x8000, 0x100004000, 0xfffffffffffff000 };
    for (addresses) |address| try memory.map(.{ .start = address, .size = 4096, .permissions = .{ .read = true, .write = true } });
    for (addresses) |address| try equal(@as(u64, 0), try memory.load(address, 8));
    for (addresses, 0..) |address, i| try memory.store(address, 8, i + 1);
    for (0..8) |_| for (addresses, 0..) |address, i| try equal(@as(u64, i + 1), try memory.load(address, 8));
    try memory.store(std.math.maxInt(u64), 1, 255);
    try equal(@as(u64, 255), try memory.load(std.math.maxInt(u64), 1));
}

test "rv64 foundation: region metadata is independently bounded" {
    var memory = mem.Memory.init(alloc, .{ .max_regions = 1 });
    defer memory.deinit();
    try memory.map(.{ .start = 0, .size = 1, .permissions = .{} });
    try std.testing.expectError(error.ResourceLimit, memory.map(.{ .start = 8, .size = 1, .permissions = .{} }));
}

fn failureTransaction(allocator: std.mem.Allocator) !void {
    var memory = mem.Memory.init(allocator, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1000, .size = 12288, .permissions = .{ .read = true, .write = true } });
    try memory.store(0x1000, 8, 123);
    const before = memory.pageCount();
    const bytes = [_]u8{0xa5} ** 8193;
    memory.initialize(0x1000, &bytes) catch |err| {
        try equal(before, memory.pageCount());
        try equal(@as(u64, 123), try memory.load(0x1000, 8));
        try equal(@as(u64, 0), try memory.load(0x2000, 8));
        try equal(@as(u64, 0), try memory.load(0x3000, 8));
        return err;
    };
}

test "rv64 foundation: every bulk-allocation failure rolls back page inventory and existing bytes" {
    try std.testing.checkAllAllocationFailures(alloc, failureTransaction, .{});
}

test "rv64 foundation: warmed execution allocates nothing" {
    var failing = std.testing.FailingAllocator.init(alloc, .{});
    var memory = try setup(failing.allocator());
    defer memory.deinit();
    var session = try rv.Session.init(failing.allocator(), machine.Cpu.init(0x1000, 0), &memory, .{});
    defer session.deinit();
    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    for (0..1000) |_| {
        session.cpu.pc = 0x1000;
        _ = try session.step();
    }
    try equal(allocation_count, failing.alloc_index);
}

test "rv64 foundation: decode cache rejects invalid sizes and init failures leak nothing" {
    for ([_]usize{ 0, 3, 65537 }) |size| try std.testing.expectError(error.InvalidCacheSize, cache.Cache.init(alloc, size));
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, cache.Cache.init(failing.allocator(), 1024));
}

test "rv64 foundation: batch allocation failure returns committed prefix and supports exact retry" {
    var failing = std.testing.FailingAllocator.init(alloc, .{});
    var memory = try setup(failing.allocator());
    defer memory.deinit();
    try code(&memory, 0x1004, 0x00113023); // sd x1,0(x2)
    try memory.map(.{ .start = 0x100004000, .size = 4096, .permissions = .{ .read = true, .write = true } });
    var session = try rv.Session.init(failing.allocator(), machine.Cpu.init(0x1000, 0x100004000), &memory, .{});
    defer session.deinit();
    const initial_pages = memory.pageCount();
    failing.fail_index = failing.alloc_index;
    var rows: [2]machine.Retirement = undefined;
    const failed = session.runInto(&rows);
    try equal(@as(usize, 1), failed.written);
    try equal(@as(?@import("../session.zig").Error, error.OutOfMemory), failed.stop);
    try equal(@as(u64, 1), session.cpu.retired);
    try equal(@as(u64, 0x1004), session.cpu.pc);
    try equal(initial_pages, memory.pageCount());
    try equal(@as(u64, 0), try memory.load(0x100004000, 8));
    failing.fail_index = std.math.maxInt(usize);
    const retried = session.runInto(rows[0..1]);
    try expect(retried.stop == null);
    try equal(@as(u64, 2), rows[0].clock);
    try equal(@as(u64, 1), try memory.load(0x100004000, 8));
}

test "rv64 foundation: decoded instruction stays compact without type specialization" {
    try expect(@sizeOf(rv.decode.Instruction) <= 16);
    try equal(@as(usize, 1), @sizeOf(rv.decode.Opcode));
}
