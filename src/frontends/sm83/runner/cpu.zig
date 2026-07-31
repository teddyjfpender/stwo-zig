const std = @import("std");

pub const Flag = enum(u8) {
    carry = 0x10,
    half_carry = 0x20,
    subtract = 0x40,
    zero = 0x80,
};

pub const Cpu = struct {
    a: u8 = 0,
    b: u8 = 0,
    c: u8 = 0,
    d: u8 = 0,
    e: u8 = 0,
    f: u8 = 0,
    h: u8 = 0,
    l: u8 = 0,
    sp: u16 = 0,
    pc: u16 = 0,
    ime: bool = false,
    ime_enable_pending: bool = false,
    halted: bool = false,
    stopped: bool = false,

    pub fn flag(self: Cpu, which: Flag) bool {
        return self.f & @intFromEnum(which) != 0;
    }

    pub fn setFlag(self: *Cpu, which: Flag, value: bool) void {
        const mask = @intFromEnum(which);
        if (value) self.f |= mask else self.f &= ~mask;
        self.f &= 0xf0;
    }

    pub fn bc(self: Cpu) u16 {
        return pair(self.b, self.c);
    }

    pub fn de(self: Cpu) u16 {
        return pair(self.d, self.e);
    }

    pub fn hl(self: Cpu) u16 {
        return pair(self.h, self.l);
    }

    pub fn af(self: Cpu) u16 {
        return pair(self.a, self.f);
    }

    pub fn setBc(self: *Cpu, value: u16) void {
        setPair(&self.b, &self.c, value);
    }

    pub fn setDe(self: *Cpu, value: u16) void {
        setPair(&self.d, &self.e, value);
    }

    pub fn setHl(self: *Cpu, value: u16) void {
        setPair(&self.h, &self.l, value);
    }

    pub fn setAf(self: *Cpu, value: u16) void {
        setPair(&self.a, &self.f, value);
        self.f &= 0xf0;
    }
};

fn pair(high: u8, low: u8) u16 {
    return (@as(u16, high) << 8) | low;
}

fn setPair(high: *u8, low: *u8, value: u16) void {
    high.* = @truncate(value >> 8);
    low.* = @truncate(value);
}

test "CPU pairs and flag register preserve SM83 width" {
    var cpu = Cpu{};
    cpu.setAf(0x12ff);
    cpu.setBc(0x3456);
    try std.testing.expectEqual(@as(u16, 0x12f0), cpu.af());
    try std.testing.expectEqual(@as(u16, 0x3456), cpu.bc());
}
