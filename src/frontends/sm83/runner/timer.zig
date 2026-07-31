//! SM83 divider and programmable timer state.
//!
//! This mirrors the timer boundary in pinned SameBoy:
//! - `Core/timing.c:GB_set_internal_div_counter` increments TIMA on a selected
//!   divider-bit falling edge.
//! - `Core/timing.c:advance_tima_state_machine` delays the interrupt request by
//!   one M-cycle after overflow.
//! - `Core/memory.c` defines the DIV, TIMA, TMA, and TAC write conflicts.

const std = @import("std");

pub const TIMER_INTERRUPT: u8 = 1 << 2;

pub const ReloadState = enum(u2) {
    running,
    reloading,
    reloaded,
};

pub const Timer = struct {
    div_counter: u16 = 0,
    tima: u8 = 0,
    tma: u8 = 0,
    tac: u3 = 0,
    reload_state: ReloadState = .running,

    /// SameBoy advances this state machine before adding four divider clocks.
    /// `true` means the caller must set IF bit 2.
    pub fn tickMcycle(self: *Timer) bool {
        const request_interrupt = self.advanceReload();
        self.setDivCounter(self.div_counter +% 4);
        return request_interrupt;
    }

    /// Returns whether any elapsed M-cycle requested the timer interrupt.
    pub fn tickMcycles(self: *Timer, count: usize) bool {
        var request_interrupt = false;
        for (0..count) |_| request_interrupt = self.tickMcycle() or request_interrupt;
        return request_interrupt;
    }

    pub fn readDiv(self: Timer) u8 {
        return @truncate(self.div_counter >> 8);
    }

    pub fn readTima(self: Timer) u8 {
        // SameBoy exposes zero while the overflow is waiting to request IF.
        return if (self.reload_state == .reloading) 0 else self.tima;
    }

    pub fn readTma(self: Timer) u8 {
        return self.tma;
    }

    pub fn readTac(self: Timer) u8 {
        return @as(u8, self.tac) | 0xf8;
    }

    /// The written value is ignored. Resetting DIV can create a timer edge.
    pub fn writeDiv(self: *Timer) void {
        self.setDivCounter(0);
    }

    pub fn writeTima(self: *Timer, value: u8) void {
        // SameBoy accepts writes while reloading and ignores them for the
        // following reloaded M-cycle.
        if (self.reload_state != .reloaded) self.tima = value;
    }

    pub fn writeTma(self: *Timer, value: u8) void {
        self.tma = value;
        // SameBoy copies TMA into TIMA throughout both reload states.
        if (self.reload_state != .running) self.tima = value;
    }

    /// Changing TAC can create the same falling edge as divider progression.
    pub fn writeTac(self: *Timer, value: u8) void {
        const new_tac: u3 = @truncate(value);
        const old_signal = self.signal(self.tac);
        const new_signal = self.signal(new_tac);
        if (old_signal and !new_signal) self.incrementTima();
        self.tac = new_tac;
    }

    /// Used by DIV writes and state restoration. Like SameBoy, every selected
    /// divider bit that changes from one to zero produces one TIMA increment.
    pub fn setDivCounter(self: *Timer, value: u16) void {
        const falling_bits = self.div_counter & ~value;
        if (self.tac & 0x04 != 0 and falling_bits & triggerMask(self.tac) != 0)
            self.incrementTima();
        self.div_counter = value;
    }

    fn advanceReload(self: *Timer) bool {
        return switch (self.reload_state) {
            .running => false,
            .reloading => request: {
                self.reload_state = .reloaded;
                break :request true;
            },
            .reloaded => resumed: {
                self.reload_state = .running;
                break :resumed false;
            },
        };
    }

    fn incrementTima(self: *Timer) void {
        self.tima +%= 1;
        if (self.tima == 0) {
            // SameBoy stores TMA immediately but makes TIMA read as zero until
            // the next M-cycle requests IF.
            self.tima = self.tma;
            self.reload_state = .reloading;
        }
    }

    fn signal(self: Timer, tac: u3) bool {
        return tac & 0x04 != 0 and self.div_counter & triggerMask(tac) != 0;
    }

    fn triggerMask(tac: u3) u16 {
        // SameBoy Core/timing.c:TAC_TRIGGER_BITS = {512, 8, 32, 128}.
        return switch (tac & 0x03) {
            0 => 1 << 9,
            1 => 1 << 3,
            2 => 1 << 5,
            3 => 1 << 7,
            else => unreachable,
        };
    }
};

test "all TAC frequencies increment TIMA on the selected falling edge" {
    for ([_]u16{ 1 << 9, 1 << 3, 1 << 5, 1 << 7 }, 0..) |mask, select| {
        var timer = Timer{
            .div_counter = mask * 2 - 4,
            .tima = 0x20,
            .tac = @intCast(0x04 | select),
        };
        try std.testing.expect(!timer.tickMcycle());
        try std.testing.expectEqual(@as(u8, 0x21), timer.tima);
    }

    var disabled = Timer{ .div_counter = 12, .tima = 0x20, .tac = 1 };
    try std.testing.expect(!disabled.tickMcycle());
    try std.testing.expectEqual(@as(u8, 0x20), disabled.tima);
}

test "overflow reads zero then requests IF one M-cycle later" {
    var timer = Timer{
        .div_counter = 12,
        .tima = 0xff,
        .tma = 0x42,
        .tac = 0x05,
    };

    try std.testing.expect(!timer.tickMcycle());
    try std.testing.expectEqual(ReloadState.reloading, timer.reload_state);
    try std.testing.expectEqual(@as(u8, 0), timer.readTima());
    try std.testing.expectEqual(@as(u8, 0x42), timer.tima);

    try std.testing.expect(timer.tickMcycle());
    try std.testing.expectEqual(ReloadState.reloaded, timer.reload_state);
    try std.testing.expectEqual(@as(u8, 0x42), timer.readTima());

    try std.testing.expect(!timer.tickMcycle());
    try std.testing.expectEqual(ReloadState.running, timer.reload_state);
}

test "DIV reset increments only when it drops the selected timer input" {
    var high = Timer{ .div_counter = 8, .tima = 9, .tac = 0x05 };
    high.writeDiv();
    try std.testing.expectEqual(@as(u16, 0), high.div_counter);
    try std.testing.expectEqual(@as(u8, 10), high.tima);

    var low = Timer{ .div_counter = 7, .tima = 9, .tac = 0x05 };
    low.writeDiv();
    try std.testing.expectEqual(@as(u8, 9), low.tima);
}

test "TAC write increments only when it drops an enabled timer input" {
    var disabled = Timer{ .div_counter = 8, .tima = 1, .tac = 0x05 };
    disabled.writeTac(0);
    try std.testing.expectEqual(@as(u8, 2), disabled.tima);
    try std.testing.expectEqual(@as(u8, 0xf8), disabled.readTac());

    var switched_low = Timer{ .div_counter = 8, .tima = 1, .tac = 0x05 };
    switched_low.writeTac(0x06);
    try std.testing.expectEqual(@as(u8, 2), switched_low.tima);

    var switched_high = Timer{ .div_counter = 0x28, .tima = 1, .tac = 0x05 };
    switched_high.writeTac(0x06);
    try std.testing.expectEqual(@as(u8, 1), switched_high.tima);

    var enabled = Timer{ .div_counter = 8, .tima = 1, .tac = 0x01 };
    enabled.writeTac(0x05);
    try std.testing.expectEqual(@as(u8, 1), enabled.tima);
}

test "TIMA and TMA writes follow SameBoy reload conflicts" {
    var timer = Timer{
        .div_counter = 12,
        .tima = 0xff,
        .tma = 0x42,
        .tac = 0x05,
    };
    _ = timer.tickMcycle();

    timer.writeTima(0x77);
    try std.testing.expectEqual(@as(u8, 0), timer.readTima());
    timer.writeTma(0x66);
    try std.testing.expectEqual(@as(u8, 0x66), timer.tima);

    try std.testing.expect(timer.tickMcycle());
    timer.writeTima(0x88);
    try std.testing.expectEqual(@as(u8, 0x66), timer.tima);
    timer.writeTma(0x99);
    try std.testing.expectEqual(@as(u8, 0x99), timer.tima);

    _ = timer.tickMcycle();
    timer.writeTima(0xaa);
    timer.writeTma(0xbb);
    try std.testing.expectEqual(@as(u8, 0xaa), timer.tima);
    try std.testing.expectEqual(@as(u8, 0xbb), timer.tma);
}

test "DIV and TAC reads expose hardware-visible bits" {
    const timer = Timer{
        .div_counter = 0xabcd,
        .tac = 0x05,
    };
    try std.testing.expectEqual(@as(u8, 0xab), timer.readDiv());
    try std.testing.expectEqual(@as(u8, 0xfd), timer.readTac());
}

test "batched M-cycles preserve an interrupt request" {
    var timer = Timer{
        .div_counter = 12,
        .tima = 0xff,
        .tma = 0x42,
        .tac = 0x05,
    };
    try std.testing.expect(timer.tickMcycles(3));
    try std.testing.expectEqual(ReloadState.running, timer.reload_state);
    try std.testing.expectEqual(@as(u16, 24), timer.div_counter);
}
