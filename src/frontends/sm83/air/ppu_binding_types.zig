//! Canonical public state and event types for PPU execution binding.

const std = @import("std");
const ppu = @import("../runner/ppu_timing.zig");

pub const Register = enum(u3) {
    lcdc,
    stat,
    scy,
    scx,
    ly,
    lyc,
    wy,
};

pub const LATCH_REGISTERS = [_]Register{ .scy, .scx, .wy };

pub fn latchIndex(register: Register) ?usize {
    return switch (register) {
        .scy => 0,
        .scx => 1,
        .wy => 2,
        else => null,
    };
}

pub const ExecutionPosition = struct {
    execution_row: u32,
    cycle: u3,
};

pub const ExecutionDot = struct {
    position: ExecutionPosition,
    phase: u2,
};

pub const Provenance = union(enum) {
    detached,
    execution_write: ExecutionPosition,
    execution_tick: ExecutionDot,
};

pub const State = struct {
    timing: ppu.State = .{},
    lcdc: u8 = 0,
    scy: u8 = 0,
    scx: u8 = 0,
    wy: u8 = 0,

    pub fn validate(self: State) !void {
        try self.timing.validate();
        if ((self.lcdc & 0x80 != 0) != self.timing.lcd_enabled)
            return error.LcdcEnableMismatch;
    }

    pub fn read(self: State, register: Register) u8 {
        return switch (register) {
            .lcdc => self.lcdc,
            .stat => self.timing.readStat(),
            .scy => self.scy,
            .scx => self.scx,
            .ly => self.timing.readLy(),
            .lyc => self.timing.lyc,
            .wy => self.wy,
        };
    }

    pub fn latches(self: State) [3]u8 {
        return .{ self.scy, self.scx, self.wy };
    }

    pub fn writeLatch(self: *State, register: Register, value: u8) bool {
        switch (register) {
            .scy => self.scy = value,
            .scx => self.scx = value,
            .wy => self.wy = value,
            else => return false,
        }
        return true;
    }
};

pub const RegisterAccess = struct { register: Register, value: u8 };

pub const Access = union(enum) {
    read: RegisterAccess,
    write: RegisterAccess,
};

pub const Cycle = struct {
    access: ?Access = null,
    execution_position: ?ExecutionPosition = null,
};

pub const EventRow = struct {
    mcycle: u32,
    transition: ppu.Transition,
    lcdc_before: u8,
    lcdc_after: u8,
    latches_before: [3]u8 = .{ 0, 0, 0 },
    latches_after: [3]u8 = .{ 0, 0, 0 },
    latch_write: ?RegisterAccess = null,
    dot_phase: ?u2 = null,
    read_register: ?Register = null,
    ignored_ly_write: ?u8 = null,
    provenance: Provenance = .detached,
};

pub const Trace = struct {
    rows: []EventRow,
    final_state: State,
    final_mcycle: u32,

    pub fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};
