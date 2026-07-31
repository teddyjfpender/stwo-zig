//! Minimal DMG-B PPU MMIO overlay for the deterministic timing runner.
//!
//! Oracle: SameBoy commit `213a12ce93d66b105a113debd9396306066a7cfc`.
//! - `Core/memory.c:471-495,622-668` synchronizes and reads PPU registers,
//!   including the unmasked SCY, SCX, and WY latches.
//! - `Core/memory.c:1425-1449` stores every SCY, SCX, and WY write byte.
//! - `Core/memory.c:1452-1482` writes LYC and refreshes STAT.
//! - `Core/memory.c:1503-1550` stores LCDC and starts/stops the LCD.
//! - `Core/memory.c:1552-1570` masks STAT writes and refreshes its edge.
//! - `Core/memory.c:1768-1774` ignores LY writes through the default case.
//! - `Core/display.c:149-164,523-593,2151-2239` supplies timing and IF edges.
//!
//! MMIO events and four-dot CPU M-cycles are separate so a machine scheduler
//! can commit their ordering. This leaf inherits `ppu_timing`'s fixed
//! empty-line mode-3 ceiling and makes no rendering, contention, corruption,
//! palette, FIFO, or timing-sensitive PPU-ROM claim.

const std = @import("std");
const ppu = @import("ppu_timing.zig");

pub const LCDC_ADDRESS: u16 = 0xff40;
pub const STAT_ADDRESS: u16 = 0xff41;
pub const SCY_ADDRESS: u16 = 0xff42;
pub const SCX_ADDRESS: u16 = 0xff43;
pub const LY_ADDRESS: u16 = 0xff44;
pub const LYC_ADDRESS: u16 = 0xff45;
pub const WY_ADDRESS: u16 = 0xff4a;
pub const DOTS_PER_M_CYCLE: usize = 4;

pub const Access = struct {
    address: u16,
    value: u8,
};

pub const Event = union(enum) {
    read: u16,
    write: Access,
    tick_mcycle,
};

pub const ValidationError = ppu.ValidationError || error{
    LcdcEnableMismatch,
};
pub const TransitionError = ValidationError || error{
    UnsupportedAddress,
};

/// Checkpoint-complete PPU register overlay.
///
/// `interrupt_flags` is the raw IF storage supplied by the machine. This
/// overlay can only OR VBlank/STAT requests into it; clearing or replacing IF
/// is an external CPU-MMIO event and must be committed separately.
pub const State = struct {
    timing: ppu.State = .{},
    lcdc: u8 = 0,
    /// CPU-visible scroll/window latches. Rendering-side sampling is outside
    /// this fixed-timing, non-rendering runner.
    scy: u8 = 0,
    scx: u8 = 0,
    wy: u8 = 0,
    interrupt_flags: u8 = 0,

    pub fn restore(checkpoint: State) ValidationError!State {
        try checkpoint.validate();
        return checkpoint;
    }

    pub fn validate(self: State) ValidationError!void {
        try self.timing.validate();
        if ((self.lcdc & 0x80 != 0) != self.timing.lcd_enabled)
            return error.LcdcEnableMismatch;
    }

    pub fn read(self: State, address: u16) ?u8 {
        return switch (address) {
            LCDC_ADDRESS => self.lcdc,
            STAT_ADDRESS => self.timing.readStat(),
            SCY_ADDRESS => self.scy,
            SCX_ADDRESS => self.scx,
            LY_ADDRESS => self.timing.readLy(),
            LYC_ADDRESS => self.timing.lyc,
            WY_ADDRESS => self.wy,
            else => null,
        };
    }

    pub fn write(
        self: *State,
        address: u16,
        value: u8,
    ) error{UnsupportedAddress}!ppu.Interrupts {
        const interrupts = switch (address) {
            LCDC_ADDRESS => update: {
                self.lcdc = value;
                break :update self.timing.writeLcdc(value);
            },
            STAT_ADDRESS => self.timing.writeStat(value),
            SCY_ADDRESS => latch: {
                self.scy = value;
                break :latch ppu.Interrupts{};
            },
            SCX_ADDRESS => latch: {
                self.scx = value;
                break :latch ppu.Interrupts{};
            },
            LY_ADDRESS => ppu.Interrupts{},
            LYC_ADDRESS => self.timing.writeLyc(value),
            WY_ADDRESS => latch: {
                self.wy = value;
                break :latch ppu.Interrupts{};
            },
            else => return error.UnsupportedAddress,
        };
        self.requestInterrupts(interrupts);
        return interrupts;
    }

    pub fn tickMcycle(self: *State) ppu.Interrupts {
        const interrupts = self.timing.tickDots(DOTS_PER_M_CYCLE);
        self.requestInterrupts(interrupts);
        return interrupts;
    }

    fn requestInterrupts(
        self: *State,
        interrupts: ppu.Interrupts,
    ) void {
        self.interrupt_flags |= interrupts.mask();
    }
};

pub const Transition = struct {
    before: State,
    after: State,
    event: Event,
    read_value: ?u8,
    interrupts: ppu.Interrupts,

    pub fn apply(
        before: State,
        event: Event,
    ) TransitionError!Transition {
        try before.validate();
        var after = before;
        var read_value: ?u8 = null;
        const interrupts = switch (event) {
            .read => |address| read: {
                read_value = after.read(address) orelse
                    return error.UnsupportedAddress;
                break :read ppu.Interrupts{};
            },
            .write => |access| try after.write(
                access.address,
                access.value,
            ),
            .tick_mcycle => after.tickMcycle(),
        };
        try after.validate();
        return .{
            .before = before,
            .after = after,
            .event = event,
            .read_value = read_value,
            .interrupts = interrupts,
        };
    }

    pub fn validate(self: Transition) error{InvalidTransition}!void {
        const expected = Transition.apply(self.before, self.event) catch
            return error.InvalidTransition;
        if (!std.meta.eql(expected, self))
            return error.InvalidTransition;
    }
};

test "all PPU register reads expose hardware masks" {
    var state = State{};
    try std.testing.expectEqual(@as(?u8, 0), state.read(LCDC_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0x80), state.read(STAT_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0), state.read(SCY_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0), state.read(SCX_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0), state.read(LY_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0), state.read(LYC_ADDRESS));
    try std.testing.expectEqual(@as(?u8, 0), state.read(WY_ADDRESS));
    try std.testing.expectEqual(@as(?u8, null), state.read(0xff47));

    _ = try state.write(LCDC_ADDRESS, 0x91);
    _ = try state.write(STAT_ADDRESS, 0x78);
    _ = try state.write(LYC_ADDRESS, 0xa5);
    try std.testing.expectEqual(@as(?u8, 0x91), state.read(LCDC_ADDRESS));
    try std.testing.expectEqual(
        @as(?u8, 0xf8 | @as(u8, @intFromEnum(state.timing.mode()))),
        state.read(STAT_ADDRESS),
    );
    try std.testing.expectEqual(@as(?u8, 0xa5), state.read(LYC_ADDRESS));

    for ([_]u16{
        LCDC_ADDRESS,
        STAT_ADDRESS,
        SCY_ADDRESS,
        SCX_ADDRESS,
        LY_ADDRESS,
        LYC_ADDRESS,
        WY_ADDRESS,
    }) |address| {
        const transition = try Transition.apply(
            state,
            .{ .read = address },
        );
        try transition.validate();
        try std.testing.expectEqual(state.read(address), transition.read_value);
        try std.testing.expect(std.meta.eql(state, transition.after));
    }
}

test "LCDC STAT LYC store every value and LY writes are ignored" {
    for (0..256) |raw| {
        const value: u8 = @intCast(raw);

        var lcdc = State{};
        const lcdc_edge = try lcdc.write(LCDC_ADDRESS, value);
        try lcdc.validate();
        try std.testing.expectEqual(value, lcdc.lcdc);
        try std.testing.expectEqual(value & 0x80 != 0, lcdc.timing.lcd_enabled);
        try std.testing.expectEqual(
            lcdc_edge.mask(),
            lcdc.interrupt_flags,
        );

        var stat = State{};
        _ = try stat.write(LCDC_ADDRESS, 0x80);
        const old_mode = stat.timing.mode();
        _ = try stat.write(STAT_ADDRESS, value);
        try stat.validate();
        try std.testing.expectEqual(
            @as(u4, @truncate(value >> 3)),
            stat.timing.stat_enable,
        );
        try std.testing.expectEqual(old_mode, stat.timing.mode());
        try std.testing.expectEqual(
            @as(u8, 0x80 | (value & 0x78) |
                (@as(u8, @intFromBool(stat.timing.coincidence)) << 2) |
                @intFromEnum(old_mode)),
            stat.timing.readStat(),
        );

        var lyc = State{};
        _ = try lyc.write(LYC_ADDRESS, value);
        try lyc.validate();
        try std.testing.expectEqual(value, lyc.timing.lyc);

        var ly = canonicalState(42, 100, 0xff, 0, 0x12);
        const before = ly;
        const ignored = try ly.write(LY_ADDRESS, value);
        try std.testing.expectEqual(@as(u2, 0), @as(u2, @bitCast(ignored)));
        try std.testing.expect(std.meta.eql(before, ly));
    }
}

test "SCY SCX and WY are unmasked CPU-visible byte latches" {
    for (0..256) |raw| {
        const value: u8 = @intCast(raw);
        inline for (.{
            .{ SCY_ADDRESS, "scy" },
            .{ SCX_ADDRESS, "scx" },
            .{ WY_ADDRESS, "wy" },
        }) |item| {
            var state = State{};
            const interrupts = try state.write(item[0], value);
            try state.validate();
            try std.testing.expectEqual(
                @as(u2, 0),
                @as(u2, @bitCast(interrupts)),
            );
            try std.testing.expectEqual(@as(?u8, value), state.read(item[0]));
            try std.testing.expectEqual(
                value,
                @field(state, item[1]),
            );

            const read = try Transition.apply(
                state,
                .{ .read = item[0] },
            );
            try read.validate();
            try std.testing.expectEqual(@as(?u8, value), read.read_value);
            try std.testing.expect(std.meta.eql(state, read.after));
        }
    }
}

test "scroll and window latches survive timing and LCD transitions" {
    var state = State{
        .scy = 0x12,
        .scx = 0x34,
        .wy = 0x56,
    };
    state = (try Transition.apply(state, .{ .write = .{
        .address = LCDC_ADDRESS,
        .value = 0x91,
    } })).after;
    state = (try Transition.apply(state, .tick_mcycle)).after;
    state = (try Transition.apply(state, .{ .write = .{
        .address = LCDC_ADDRESS,
        .value = 0x11,
    } })).after;
    try state.validate();
    try std.testing.expectEqual(@as(u8, 0x12), state.scy);
    try std.testing.expectEqual(@as(u8, 0x34), state.scx);
    try std.testing.expectEqual(@as(u8, 0x56), state.wy);
    try std.testing.expectEqualDeep(state, try State.restore(state));
}

test "transition validation rejects every forged PPU latch" {
    inline for (.{
        .{ SCY_ADDRESS, "scy" },
        .{ SCX_ADDRESS, "scx" },
        .{ WY_ADDRESS, "wy" },
    }) |item| {
        const transition = try Transition.apply(
            State{},
            .{ .write = .{ .address = item[0], .value = 0xa5 } },
        );
        try transition.validate();

        var forged_after = transition;
        @field(forged_after.after, item[1]) ^= 1;
        try std.testing.expectError(
            error.InvalidTransition,
            forged_after.validate(),
        );

        var forged_event = transition;
        forged_event.event.write.value ^= 1;
        try std.testing.expectError(
            error.InvalidTransition,
            forged_event.validate(),
        );

        const read = try Transition.apply(
            transition.after,
            .{ .read = item[0] },
        );
        var forged_before = read;
        @field(forged_before.before, item[1]) ^= 1;
        try std.testing.expectError(
            error.InvalidTransition,
            forged_before.validate(),
        );

        var forged_value = read;
        forged_value.read_value.? ^= 1;
        try std.testing.expectError(
            error.InvalidTransition,
            forged_value.validate(),
        );
    }
}

test "one M-cycle advances exactly four dots across every boundary" {
    const lines = [_]u8{ 0, 1, 143, 144, 152, 153 };
    const dots = [_]u16{
        0,  1,  2,  4,   5,   6,   7,   8,   10, 11, 12,
        76, 79, 80, 248, 251, 252, 452, 455,
    };
    var count: usize = 0;
    for (lines) |line| {
        for (dots) |dot| {
            var state = canonicalState(line, dot, 0xff, 0, 0x20);
            var expected = state.timing;
            const expected_interrupts =
                expected.tickDots(DOTS_PER_M_CYCLE);
            const transition = try Transition.apply(
                state,
                .tick_mcycle,
            );
            try transition.validate();
            try std.testing.expect(std.meta.eql(
                expected,
                transition.after.timing,
            ));
            try std.testing.expectEqual(
                expected_interrupts,
                transition.interrupts,
            );
            state = transition.after;
            try state.validate();
            count += 1;
        }
    }
    try std.testing.expectEqual(lines.len * dots.len, count);
}

test "VBlank and STAT requests only OR their IF bits" {
    for (0..256) |raw_if| {
        const initial_if: u8 = @intCast(raw_if);

        const vblank = canonicalState(144, 0, 0xff, 0, initial_if);
        const vblank_edge = try Transition.apply(
            vblank,
            .tick_mcycle,
        );
        try std.testing.expect(vblank_edge.interrupts.vblank);
        try std.testing.expect(!vblank_edge.interrupts.stat);
        try std.testing.expectEqual(
            initial_if | ppu.VBLANK_INTERRUPT,
            vblank_edge.after.interrupt_flags,
        );

        const both = canonicalState(144, 0, 0xff, 0x4, initial_if);
        const both_edges = try Transition.apply(both, .tick_mcycle);
        try std.testing.expect(both_edges.interrupts.vblank);
        try std.testing.expect(both_edges.interrupts.stat);
        try std.testing.expectEqual(
            initial_if | ppu.VBLANK_INTERRUPT | ppu.STAT_INTERRUPT,
            both_edges.after.interrupt_flags,
        );

        var stat = State{ .interrupt_flags = initial_if };
        _ = try stat.write(STAT_ADDRESS, 0x40);
        const stat_edge = try Transition.apply(
            stat,
            .{ .write = .{
                .address = LCDC_ADDRESS,
                .value = 0x80,
            } },
        );
        try std.testing.expect(stat_edge.interrupts.stat);
        try std.testing.expectEqual(
            initial_if | ppu.STAT_INTERRUPT,
            stat_edge.after.interrupt_flags,
        );
    }
}

test "LCDC restart and LYC writes propagate only new STAT edges" {
    var state = State{};
    _ = try state.write(STAT_ADDRESS, 0x40);
    try std.testing.expectEqual(@as(u8, 0), state.interrupt_flags);

    const enabled = try Transition.apply(state, .{ .write = .{
        .address = LCDC_ADDRESS,
        .value = 0x91,
    } });
    try std.testing.expect(enabled.interrupts.stat);
    try std.testing.expectEqual(
        @as(u8, ppu.STAT_INTERRUPT),
        enabled.after.interrupt_flags,
    );
    try std.testing.expect(enabled.after.timing.startup_line);

    const same_lyc = try Transition.apply(
        enabled.after,
        .{ .write = .{
            .address = LYC_ADDRESS,
            .value = 0,
        } },
    );
    try std.testing.expect(!same_lyc.interrupts.stat);

    const disabled = try Transition.apply(
        same_lyc.after,
        .{ .write = .{
            .address = LCDC_ADDRESS,
            .value = 0x11,
        } },
    );
    try std.testing.expect(!disabled.after.timing.lcd_enabled);
    try std.testing.expectEqual(@as(u8, 0), disabled.after.timing.readLy());
    try std.testing.expectEqual(@as(u8, 0x11), disabled.after.lcdc);
    try std.testing.expectEqual(
        same_lyc.after.interrupt_flags,
        disabled.after.interrupt_flags,
    );
}

test "checkpoint and transition validation reject mismatches" {
    var mismatch = State{ .lcdc = 0x80 };
    try std.testing.expectError(
        error.LcdcEnableMismatch,
        mismatch.validate(),
    );

    const transition = try Transition.apply(
        State{},
        .{ .write = .{
            .address = LCDC_ADDRESS,
            .value = 0x80,
        } },
    );
    var forged = transition;
    forged.after.interrupt_flags ^= ppu.STAT_INTERRUPT;
    try std.testing.expectError(
        error.InvalidTransition,
        forged.validate(),
    );

    try std.testing.expectError(
        error.UnsupportedAddress,
        Transition.apply(State{}, .{ .read = 0xff47 }),
    );
    try std.testing.expectError(
        error.UnsupportedAddress,
        Transition.apply(State{}, .{ .write = .{
            .address = 0xff47,
            .value = 0,
        } }),
    );

    mismatch = transition.after;
    mismatch.timing.dot = ppu.DOTS_PER_LINE;
    try std.testing.expectError(error.InvalidDot, mismatch.validate());
}

fn canonicalState(
    line: u8,
    dot: u16,
    lyc: u8,
    stat_enable: u4,
    interrupt_flags: u8,
) State {
    var state = State{
        .timing = .{
            .lcd_enabled = true,
            .line = line,
            .dot = dot,
            .lyc = lyc,
            .stat_enable = stat_enable,
        },
        .lcdc = 0x80,
        .interrupt_flags = interrupt_flags,
    };
    if (line != 153) {
        state.timing.coincidence = line == lyc;
        state.timing.lyc_interrupt_line = state.timing.coincidence;
    } else if (dot >= 6 and dot < 8) {
        state.timing.coincidence = lyc == 153;
        state.timing.lyc_interrupt_line = state.timing.coincidence;
    } else if (dot >= 12) {
        state.timing.coincidence = lyc == 0;
        state.timing.lyc_interrupt_line = state.timing.coincidence;
    }
    const mode_enabled = switch (state.timing.mode()) {
        .hblank => stat_enable & 0x1 != 0,
        .vblank => stat_enable & 0x2 != 0,
        .oam => stat_enable & 0x4 != 0,
        .transfer => false,
    };
    state.timing.stat_interrupt_line =
        mode_enabled or (stat_enable & 0x8 != 0 and
            state.timing.lyc_interrupt_line);
    std.debug.assert((State.restore(state) catch null) != null);
    return state;
}
