const std = @import("std");
const machine_runner = @import("machine.zig");
const runner = @import("mod.zig");

const DIV: u16 = 0xff04;
const TIMA: u16 = 0xff05;
const TMA: u16 = 0xff06;
const TAC: u16 = 0xff07;
const IF: u16 = 0xff0f;
const TIMER_INTERRUPT = runner.timer.TIMER_INTERRUPT;

test "flat restore preserves timer and HALT checkpoint without boot reset" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    const checkpoint = runner.timer.Timer{
        .div_counter = 0xabcc,
        .tima = 0x42,
        .tma = 0x31,
        .tac = 0x05,
        .reload_state = .reloaded,
    };
    const restored = try machine_runner.Machine.restore(
        &memory,
        .{ .pc = 0, .halted = true },
        checkpoint,
        true,
    );
    try std.testing.expectEqualDeep(checkpoint, restored.timer);
    try std.testing.expect(restored.cpu.halted);
    try std.testing.expect(restored.halt_bug);
    try std.testing.expectEqual(@as(u8, 0xab), memory.read(DIV));

    var already_attached = runner.timer.Timer{};
    memory.attachTimer(&already_attached);
    defer memory.detachTimer();
    try std.testing.expectError(
        error.TimerAlreadyAttached,
        machine_runner.Machine.restore(&memory, .{}, checkpoint, false),
    );
}

test "timer falling edge delays reload and interrupt by one M-cycle" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    memory.write(TIMA, 0xff);
    memory.write(TMA, 0x42);
    memory.write(TAC, 0x05);
    var machine = machine_runner.Machine.init(&memory, .{});
    machine.timer.div_counter = 0x000f;

    const result = try machine.step();
    try std.testing.expect(result.instruction != null);
    try std.testing.expectEqual(
        machine_runner.SchedulerEvent.instruction,
        result.event,
    );
    try std.testing.expectEqual(@as(u3, 1), result.m_cycles);
    try std.testing.expectEqual(@as(u16, 0x000f), result.before.div_counter);
    try std.testing.expectEqual(@as(u16, 0x0013), result.after.div_counter);
    try std.testing.expectEqual(@as(u8, 0xff), result.before.tima);
    try std.testing.expectEqual(@as(u8, 0), result.after.tima);
    try std.testing.expect(result.hasCanonicalShape());
    var forged_instruction = result;
    forged_instruction.before.cpu.pc +%= 1;
    try std.testing.expect(!forged_instruction.hasCanonicalShape());
    try std.testing.expectEqual(@as(u8, 0), memory.read(TIMA));
    try std.testing.expectEqual(@as(u8, 0), memory.read(IF) & TIMER_INTERRUPT);

    const reload = try machine.step();
    try std.testing.expectEqual(@as(u8, 0x42), reload.after.tima);
    try std.testing.expectEqual(@as(u8, 0x42), memory.read(TIMA));
    try std.testing.expect(memory.read(IF) & TIMER_INTERRUPT != 0);
}
