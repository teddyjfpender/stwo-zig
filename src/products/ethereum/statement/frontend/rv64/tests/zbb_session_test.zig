const std = @import("std");
const rv = @import("stwo_riscv_rv64");
const profile = rv.execution_profile;
const memory = rv.memory;
const machine = rv.machine;
const eth = @import("../ethereum_services/session.zig");
const t = std.testing;

fn sessionRun(p: profile.Profile) !u64 {
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try mem.map(.{ .start = 0x1000, .size = 8, .permissions = .{ .read = true, .execute = true } });
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u32, bytes[0..4], 0x6b85d513, .little); // rev8 a0,a1
    std.mem.writeInt(u32, bytes[4..8], 0x40c5f533, .little); // andn a0,a1,a2
    try mem.initialize(0x1000, &bytes);
    var c = machine.Cpu.init(0x1000, 0);
    c.regs[11] = 0x0102_0304_0506_0708;
    c.regs[12] = 0xff;
    var s = try eth.Session.initWithProfile(t.allocator, c, &mem, .{ .cache_entries = 4, .max_retirements = 2 }, p);
    defer s.deinit();
    var event: eth.Event = undefined;
    _ = try s.step(&event);
    try t.expectEqual(@as(u64, 0x0807_0605_0403_0201), s.keccak.base.cpu.regs[10]);
    _ = try s.step(&event);
    return s.keccak.base.cpu.regs[10];
}

test "v3_zbb session retires the subset; v3 traps without any state change" {
    try t.expectEqual(@as(u64, 0x0102_0304_0506_0700), try sessionRun(.ethereum_services_v3_zbb));
    try t.expectError(error.IllegalInstruction, sessionRun(.ethereum_services_v3));
    // A caller cannot widen a pre-Zbb profile through Options.isa.
    var mem = memory.Memory.init(t.allocator, .{});
    defer mem.deinit();
    try t.expectError(error.UnsupportedService, eth.Session.initWithProfile(t.allocator, machine.Cpu.init(0x1000, 0), &mem, .{ .isa = .rv64im_zbb_binary }, .ethereum_services_v3));
}
