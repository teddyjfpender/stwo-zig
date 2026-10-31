const std = @import("std");
const service = @import("../service_session.zig");
const memory = @import("../memory.zig");
const machine = @import("../machine.zig");
const a = std.testing.allocator;
const zero_expected = [_]u64{ 0xf1258f7940e1dde7, 0x84d5ccf933c0478a, 0xd598261ea65aa9ee, 0xbd1547306f80494d, 0x8b284e056253d057, 0xff97a42d7f8e6fd4, 0x90fee5a0a44647c4, 0x8c5bda0cd6192e76, 0xad30a6f71b19059c, 0x30935ab7d08ffc64, 0xeb5aa93f2317d635, 0xa9a6e6260d712103, 0x81a57c16dbcf555f, 0x43b831cd0347c826, 0x01f22f1a11a5569f, 0x05e5635a21d9ae61, 0x64befef28cc970f2, 0x613670957bc46611, 0xb87c5a554fd00ecb, 0x8c3ee88a1ccf32c8, 0x940c7922ae3a2614, 0x1841f924a2c509e4, 0x16f53526e70465c2, 0x75f644e97f30a13b, 0xeaf1ff7b5ceca249 };
fn setup(allocator: std.mem.Allocator, writable: bool) !memory.Memory {
    var m = memory.Memory.init(allocator, .{});
    errdefer m.deinit();
    try m.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .execute = true } });
    try m.initialize(0x1000, &.{ 0x73, 0, 0, 0, 0x13, 0, 0, 0 });
    // The 200-byte state crosses a page boundary. Pages start absent/zero.
    try m.map(.{ .start = 0x2ff0, .size = 200, .permissions = .{ .read = true, .write = writable } });
    return m;
}
fn cpu() machine.Cpu {
    var c = machine.Cpu.init(0x1000, 0);
    c.regs[10] = 0x2ff0;
    c.regs[17] = service.KECCAK_TAG;
    return c;
}
fn run(allocator: std.mem.Allocator) !void {
    var m = try setup(allocator, true);
    defer m.deinit();
    var session = try service.Session.init(allocator, cpu(), &m, .{ .cache_entries = 1, .max_retirements = 2 });
    defer session.deinit();
    const before_cpu = session.base.cpu;
    const pages = m.pageCount();
    var call: service.Call = undefined;
    const row = session.step(&call) catch |err| {
        try std.testing.expectEqualDeep(before_cpu, session.base.cpu);
        try std.testing.expectEqual(pages, m.pageCount());
        for (0..25) |i| try std.testing.expectEqual(@as(u64, 0), try m.load(0x2ff0 + i * 8, 8));
        return err;
    };
    try std.testing.expect(row == null);
    try std.testing.expectEqual(@as(u64, 1), call.call_id);
    try std.testing.expectEqual(@as(u64, 1), call.clock);
    try std.testing.expectEqualDeep([_]u64{0} ** 25, call.before);
    try std.testing.expectEqualDeep(zero_expected, call.after);
    const retirement = call.retirement();
    try std.testing.expectEqual(call.clock, retirement.clock);
    try std.testing.expectEqual(@as(u5, 10), retirement.rs1);
    try std.testing.expectEqual(@as(u5, 17), retirement.rs2);
    try std.testing.expect(retirement.memory == null and !retirement.writes_rd);
    for (call.after, 0..) |word, i| try std.testing.expectEqual(word, try m.load(0x2ff0 + i * 8, 8));
    try std.testing.expectEqualDeep(before_cpu.regs, session.base.cpu.regs);
    try std.testing.expectEqual(@as(u64, 0x1004), session.base.cpu.pc);
    try std.testing.expectEqual(@as(u64, 1), session.base.cpu.retired);
    try std.testing.expect((try session.step(&call)) != null);
    try std.testing.expectError(error.StepLimit, session.step(&call));
}
test "RV64 service: atomic two-page permutation, register preservation and failure cleanup" {
    try run(a);
    try std.testing.checkAllAllocationFailures(a, run, .{});
}
test "RV64 service: ordinary ECALL still traps; bad tag alignment span permissions cannot retire" {
    var m = try setup(a, false);
    defer m.deinit();
    var c = cpu();
    try std.testing.expectError(error.EnvironmentCall, c.step(&m));
    var session = try service.Session.init(a, c, &m, .{ .cache_entries = 1 });
    defer session.deinit();
    var call: service.Call = undefined;
    const pages = m.pageCount();
    try std.testing.expectError(error.AccessDenied, session.step(&call));
    session.base.cpu.regs[17] = 0;
    try std.testing.expectError(error.UnsupportedService, session.step(&call));
    session.base.cpu.regs[17] = 0x100010001;
    try std.testing.expectError(error.UnsupportedService, session.step(&call));
    session.base.cpu.regs[17] = service.KECCAK_TAG;
    session.base.cpu.regs[10] += 1;
    try std.testing.expectError(error.MisalignedAddress, session.step(&call));
    session.base.cpu.regs[10] = 0xfffffffffffffff8;
    try std.testing.expectError(error.AddressOverflow, session.step(&call));
    try std.testing.expectEqual(@as(u64, 0), session.base.cpu.retired);
    try std.testing.expectEqual(@as(u64, 0), session.calls);
    try std.testing.expectEqual(pages, m.pageCount());
}
test "RV64 service: pointer and architectural record retain all64addressbits" {
    var m = try setup(a, true);
    defer m.deinit();
    const pointer: u64 = 0x100002ff0;
    try m.map(.{ .start = pointer, .size = 200, .permissions = .{ .read = true, .write = true } });
    var c = cpu();
    c.regs[10] = pointer;
    var session = try service.Session.init(a, c, &m, .{ .cache_entries = 1 });
    defer session.deinit();
    var call: service.Call = undefined;
    try std.testing.expect((try session.step(&call)) == null);
    try std.testing.expectEqual(pointer, call.pointer);
    try std.testing.expectEqual(pointer, call.retirement().lhs.toInt());
    for (zero_expected, 0..) |word, i| try std.testing.expectEqual(word, try m.load(pointer + i * 8, 8));
    for (0..25) |i| try std.testing.expectEqual(@as(u64, 0), try m.load(0x2ff0 + i * 8, 8));
}
