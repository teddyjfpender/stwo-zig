//! Shared bodies for the scheduler contract tests declared in machine.zig.

const std = @import("std");

pub fn eiDelay(
    comptime runner: type,
    comptime Machine: type,
    comptime SchedulerEvent: type,
    interrupt_enable: u16,
    interrupt_flags: u16,
) !void {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(interrupt_enable, 1);
    memory.write(interrupt_flags, 1);
    memory.write(0, 0xfb);
    memory.write(1, 0x00);
    var machine = Machine.init(&memory, .{ .sp = 0xc000 });

    try std.testing.expect((try machine.step()).instruction != null);
    try std.testing.expect((try machine.step()).instruction != null);
    const service = try machine.step();
    try std.testing.expect(service.instruction == null);
    try std.testing.expectEqual(SchedulerEvent.interrupt_service, service.event);
    try std.testing.expectEqual(@as(?u3, 0), service.interrupt_index);
    try std.testing.expectEqual(@as(u3, 5), service.m_cycles);
    try std.testing.expectEqual(@as(u16, 2), service.before.cpu.pc);
    try std.testing.expect(service.before.cpu.ime);
    try std.testing.expectEqual(@as(u16, 0x40), service.after.cpu.pc);
    try std.testing.expect(service.hasCanonicalShape());
    var forged_service = service;
    forged_service.after.cpu.pc = 0x48;
    try std.testing.expect(!forged_service.hasCanonicalShape());
    try std.testing.expectEqual(@as(u16, 0x40), machine.cpu.pc);
    try std.testing.expectEqual(@as(u16, 0xbffe), machine.cpu.sp);
    try std.testing.expectEqual(@as(u8, 0), memory.read(0xbfff));
    try std.testing.expectEqual(@as(u8, 2), memory.read(0xbffe));
    try std.testing.expectEqual(@as(u8, 0), memory.read(interrupt_flags) & 1);

    memory.write(0, 0xfb);
    memory.write(1, 0xf3);
    memory.write(2, 0x00);
    memory.write(interrupt_flags, 1);
    machine = Machine.init(&memory, .{ .sp = 0xc000 });
    _ = try machine.step();
    _ = try machine.step();
    const after_di = try machine.step();
    try std.testing.expect(after_di.instruction != null);
    try std.testing.expectEqual(SchedulerEvent.instruction, after_di.event);
    try std.testing.expect(after_di.hasCanonicalShape());
    try std.testing.expectEqual(@as(u16, 3), machine.cpu.pc);
    try std.testing.expectEqual(
        @as(u8, 1),
        memory.read(interrupt_flags) & 1,
    );
}

pub fn haltWake(
    comptime runner: type,
    comptime Machine: type,
    comptime SchedulerEvent: type,
    interrupt_enable: u16,
    interrupt_flags: u16,
    timer_interrupt: u8,
) !void {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    memory.write(interrupt_enable, timer_interrupt);
    memory.write(interrupt_flags, 0);
    var machine = Machine.init(&memory, .{ .halted = true });

    const idle = try machine.step();
    try std.testing.expectEqual(SchedulerEvent.halt_idle, idle.event);
    try std.testing.expect(idle.instruction == null);
    try std.testing.expectEqual(@as(u3, 1), idle.m_cycles);
    try std.testing.expectEqual(@as(u16, 0), idle.before.cpu.pc);
    try std.testing.expectEqual(@as(u16, 0), idle.after.cpu.pc);
    try std.testing.expectEqual(@as(u16, 4), idle.after.div_counter);
    try std.testing.expect(idle.hasCanonicalShape());
    var forged_idle = idle;
    forged_idle.m_cycles = 2;
    try std.testing.expect(!forged_idle.hasCanonicalShape());

    memory.write(interrupt_flags, timer_interrupt);
    const wake = try machine.step();
    try std.testing.expect(wake.instruction == null);
    try std.testing.expectEqual(SchedulerEvent.halt_wake, wake.event);
    try std.testing.expect(wake.before.cpu.halted);
    try std.testing.expect(!wake.after.cpu.halted);
    try std.testing.expectEqual(@as(u3, 1), wake.m_cycles);
    try std.testing.expect(wake.hasCanonicalShape());
    try std.testing.expect(!machine.cpu.halted);
    try std.testing.expectEqual(@as(u16, 0), machine.cpu.pc);

    const result = try machine.step();
    try std.testing.expect(result.instruction != null);
    try std.testing.expectEqual(@as(u16, 1), machine.cpu.pc);
    try std.testing.expectEqual(
        timer_interrupt,
        memory.read(interrupt_flags) & timer_interrupt,
    );
}

pub fn haltedService(
    comptime runner: type,
    comptime Machine: type,
    comptime SchedulerEvent: type,
    interrupt_enable: u16,
    interrupt_flags: u16,
) !void {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var machine = Machine.init(
        &memory,
        .{ .halted = true, .ime_enable_pending = true, .sp = 0xc000 },
    );

    const idle = try machine.step();
    try std.testing.expectEqual(SchedulerEvent.halt_idle, idle.event);
    try std.testing.expect(idle.after.cpu.halted);
    try std.testing.expect(idle.after.cpu.ime);
    try std.testing.expect(!idle.after.cpu.ime_enable_pending);
    try std.testing.expect(idle.hasCanonicalShape());

    memory.write(interrupt_enable, 1);
    memory.write(interrupt_flags, 1);
    const service = try machine.step();
    try std.testing.expectEqual(
        SchedulerEvent.interrupt_service,
        service.event,
    );
    try std.testing.expectEqual(@as(u3, 6), service.m_cycles);
    try std.testing.expectEqual(@as(?u3, 0), service.interrupt_index);
    try std.testing.expectEqual(@as(u16, 0x40), service.after.cpu.pc);
    try std.testing.expectEqual(
        @as(u16, 24),
        service.after.div_counter -% idle.after.div_counter,
    );
    try std.testing.expect(service.hasCanonicalShape());
}

pub fn haltBug(
    comptime runner: type,
    comptime Machine: type,
    comptime SchedulerEvent: type,
    interrupt_enable: u16,
    interrupt_flags: u16,
) !void {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x76);
    memory.write(1, 0x06);
    memory.write(2, 0x99);
    memory.write(interrupt_enable, 1);
    memory.write(interrupt_flags, 1);
    var machine = Machine.init(&memory, .{});

    const halt = try machine.step();
    try std.testing.expectEqual(SchedulerEvent.instruction, halt.event);
    try std.testing.expect(!halt.after.cpu.halted);
    try std.testing.expect(halt.after.halt_bug);

    const duplicated = try machine.step();
    try std.testing.expectEqual(SchedulerEvent.instruction, duplicated.event);
    try std.testing.expect(duplicated.before.halt_bug);
    try std.testing.expect(!duplicated.after.halt_bug);
    try std.testing.expectEqual(@as(u8, 0x06), duplicated.after.cpu.b);
    try std.testing.expectEqual(@as(u16, 2), duplicated.after.cpu.pc);
    try std.testing.expectEqual(
        duplicated.instruction.?.cycles[0].address,
        duplicated.instruction.?.cycles[1].address,
    );
    try std.testing.expect(duplicated.hasCanonicalShape());
}

pub fn interruptAlias(
    comptime runner: type,
    comptime Machine: type,
    interrupt_enable: u16,
    interrupt_flags: u16,
) !void {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(interrupt_enable, 1);
    memory.write(interrupt_flags, 1);
    var machine = Machine.init(
        &memory,
        .{ .pc = 0x0000, .sp = 0x0000, .ime = true },
    );

    const cancelled = try machine.step();
    try std.testing.expectEqual(@as(?u3, null), cancelled.interrupt_index);
    try std.testing.expectEqual(@as(u16, 0), cancelled.after.cpu.pc);
    try std.testing.expectEqual(@as(u8, 0), cancelled.after.interrupt_enable);
    try std.testing.expectEqual(
        @as(u8, 1),
        cancelled.after.interrupt_flags & 1,
    );
    try std.testing.expect(cancelled.hasCanonicalShape());

    memory.write(interrupt_enable, 1);
    memory.write(interrupt_flags, 3);
    machine = Machine.init(
        &memory,
        .{ .pc = 0x0200, .sp = 0x0000, .ime = true },
    );
    const reprioritized = try machine.step();
    try std.testing.expectEqual(@as(?u3, 1), reprioritized.interrupt_index);
    try std.testing.expectEqual(@as(u16, 0x48), reprioritized.after.cpu.pc);
    try std.testing.expectEqual(
        @as(u8, 2),
        reprioritized.after.interrupt_enable,
    );
    try std.testing.expectEqual(
        @as(u8, 1),
        reprioritized.after.interrupt_flags & 3,
    );
    try std.testing.expect(reprioritized.hasCanonicalShape());
}
