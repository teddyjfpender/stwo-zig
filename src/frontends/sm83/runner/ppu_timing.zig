//! Minimal deterministic DMG-B PPU timing for CPU execution proofs.
//!
//! Oracle: SameBoy commit `213a12ce93d66b105a113debd9396306066a7cfc`.
//! - `Core/display.c:149-164` fixes the empty-line 80/172/204-dot modes.
//! - `Core/display.c:523-560` defines coincidence and the combined STAT edge.
//! - `Core/display.c:562-593` defines the LCD-off state.
//! - `Core/display.c:1664-1714` makes the first enabled line skip mode 2.
//! - `Core/display.c:2151-2202` defines VBlank and its DMG mode-2 STAT edge.
//! - `Core/display.c:2217-2239` defines the DMG line-153 LY transition.
//! - `Core/memory.c:1452-1482,1503-1569` defines LYC/LCDC/STAT writes.
//!
//! This leaf intentionally does not render. Its fixed mode-3 length is exact
//! only without scrolling, objects, or a window. VRAM/OAM contention, OAM
//! corruption, palettes, pixel FIFOs, and the first-line sub-dot skew remain
//! outside this state and must be added before timing-sensitive PPU ROMs are a
//! proving gate.

const std = @import("std");

pub const SAMEBOY_COMMIT = "213a12ce93d66b105a113debd9396306066a7cfc";

pub const DOTS_PER_LINE: u16 = 456;
pub const VISIBLE_LINES: u8 = 144;
pub const LINES_PER_FRAME: u8 = 154;
pub const MODE2_DOTS: u16 = 80;
pub const MODE3_DOTS: u16 = 172;
pub const MODE0_START: u16 = MODE2_DOTS + MODE3_DOTS;

pub const VBLANK_INTERRUPT: u8 = 1 << 0;
pub const STAT_INTERRUPT: u8 = 1 << 1;

pub const Mode = enum(u2) {
    hblank = 0,
    vblank = 1,
    oam = 2,
    transfer = 3,
};

pub const Interrupts = packed struct(u2) {
    vblank: bool = false,
    stat: bool = false,

    pub fn mask(self: Interrupts) u8 {
        return (@as(u8, @intFromBool(self.vblank)) * VBLANK_INTERRUPT) |
            (@as(u8, @intFromBool(self.stat)) * STAT_INTERRUPT);
    }

    fn merge(self: *Interrupts, other: Interrupts) void {
        self.vblank = self.vblank or other.vblank;
        self.stat = self.stat or other.stat;
    }
};

pub const Event = union(enum) {
    tick_dot,
    write_lcdc: u8,
    write_stat: u8,
    write_lyc: u8,
};

pub const ValidationError = error{
    InvalidLine,
    InvalidDot,
    InvalidDisabledPosition,
    InvalidStartupLine,
    InvalidCoincidence,
    InvalidLycInterruptLine,
    InvalidStatInterruptLine,
};

/// Complete checkpoint state for the deterministic timing model.
///
/// `coincidence` is visible STAT bit 2. `lyc_interrupt_line` is separate
/// because SameBoy retains its hidden line while comparison is unavailable
/// during line 153. `stat_interrupt_line` must also be committed: STAT requests
/// are rising edges, so restoring only the visible registers is ambiguous.
pub const State = struct {
    lcd_enabled: bool = false,
    line: u8 = 0,
    dot: u16 = 0,
    startup_line: bool = false,
    lyc: u8 = 0,
    /// STAT bits 3...6, shifted down to bits 0...3.
    stat_enable: u4 = 0,
    coincidence: bool = false,
    lyc_interrupt_line: bool = false,
    stat_interrupt_line: bool = false,

    pub fn restore(checkpoint: State) ValidationError!State {
        try checkpoint.validate();
        return checkpoint;
    }

    pub fn validate(self: State) ValidationError!void {
        if (self.line >= LINES_PER_FRAME) return error.InvalidLine;
        if (self.dot >= DOTS_PER_LINE) return error.InvalidDot;
        if (!self.lcd_enabled) {
            if (self.line != 0 or self.dot != 0)
                return error.InvalidDisabledPosition;
            if (self.startup_line) return error.InvalidStartupLine;
            // SameBoy freezes all three interrupt fields while LCD is off.
            return;
        }
        if (self.startup_line and self.line != 0)
            return error.InvalidStartupLine;

        if (self.comparisonValue()) |value| {
            const expected = value == self.lyc;
            if (self.coincidence != expected)
                return error.InvalidCoincidence;
            if (self.lyc_interrupt_line != expected)
                return error.InvalidLycInterruptLine;
        } else if (self.coincidence) {
            return error.InvalidCoincidence;
        }

        if (self.stat_interrupt_line != self.combinedStatLine())
            return error.InvalidStatInterruptLine;
    }

    pub fn mode(self: State) Mode {
        if (!self.lcd_enabled) return .hblank;
        // SameBoy changes STAT to mode 1 together with the VBlank request,
        // after 2 + 2 + 1 dots on physical line 144. Its four-dot delayed
        // mode phase maps that edge to canonical dot 1.
        if (self.line >= VISIBLE_LINES) {
            if (self.line == VISIBLE_LINES and self.dot == 0)
                return .hblank;
            return .vblank;
        }
        if (self.startup_line and self.dot < MODE2_DOTS)
            return .hblank;
        if (self.dot < MODE2_DOTS) return .oam;
        if (self.dot < MODE0_START) return .transfer;
        return .hblank;
    }

    pub fn readLy(self: State) u8 {
        if (!self.lcd_enabled) return 0;
        if (self.line != LINES_PER_FRAME - 1) return self.line;

        // DMG-B: LY still reads 152 for two dots, then 153 for four dots,
        // before reading zero for the remainder of physical line 153.
        if (self.dot < 2) return LINES_PER_FRAME - 2;
        if (self.dot < 6) return LINES_PER_FRAME - 1;
        return 0;
    }

    pub fn readStat(self: State) u8 {
        return 0x80 |
            (@as(u8, self.stat_enable) << 3) |
            (@as(u8, @intFromBool(self.coincidence)) << 2) |
            @intFromEnum(self.mode());
    }

    /// Advances one PPU dot and returns IF edges for the caller to OR in.
    pub fn tickDot(self: *State) Interrupts {
        if (!self.lcd_enabled) return .{};

        self.dot += 1;
        if (self.dot == DOTS_PER_LINE) {
            self.dot = 0;
            self.line = if (self.line + 1 == LINES_PER_FRAME)
                0
            else
                self.line + 1;
            self.startup_line = false;
        }

        const entered_vblank =
            self.line == VISIBLE_LINES and self.dot == 1;
        var interrupts = Interrupts{ .vblank = entered_vblank };

        // On DMG, the mode-2 source also pulses at VBlank entry even though
        // the visible mode becomes 1. It is blocked by an already-high line.
        if (entered_vblank and
            !self.stat_interrupt_line and
            self.stat_enable & 0x4 != 0)
        {
            interrupts.stat = true;
        }
        interrupts.stat = self.refreshStat() or interrupts.stat;
        return interrupts;
    }

    pub fn tickDots(self: *State, count: usize) Interrupts {
        var interrupts = Interrupts{};
        for (0..count) |_| interrupts.merge(self.tickDot());
        return interrupts;
    }

    pub fn writeLcdc(self: *State, value: u8) Interrupts {
        const enabled = value & 0x80 != 0;
        if (enabled == self.lcd_enabled) return .{};

        if (!enabled) {
            self.lcd_enabled = false;
            self.line = 0;
            self.dot = 0;
            self.startup_line = false;
            // Coincidence and both hidden lines freeze until LCD is enabled.
            return .{};
        }

        self.lcd_enabled = true;
        self.line = 0;
        self.dot = 0;
        self.startup_line = true;
        return .{ .stat = self.refreshStat() };
    }

    pub fn writeStat(self: *State, value: u8) Interrupts {
        self.stat_enable = @truncate(value >> 3);
        if (!self.lcd_enabled) return .{};
        return .{ .stat = self.refreshStat() };
    }

    pub fn writeLyc(self: *State, value: u8) Interrupts {
        self.lyc = value;
        if (!self.lcd_enabled) return .{};
        return .{ .stat = self.refreshStat() };
    }

    fn refreshStat(self: *State) bool {
        const previous = self.stat_interrupt_line;
        if (self.comparisonValue()) |value| {
            self.coincidence = value == self.lyc;
            self.lyc_interrupt_line = self.coincidence;
        } else {
            self.coincidence = false;
        }
        self.stat_interrupt_line = self.combinedStatLine();
        return self.stat_interrupt_line and !previous;
    }

    fn combinedStatLine(self: State) bool {
        const mode_line = switch (self.interruptMode()) {
            .hblank => self.stat_enable & 0x1 != 0,
            .vblank => self.stat_enable & 0x2 != 0,
            .oam => self.stat_enable & 0x4 != 0,
            .transfer => false,
        };
        return mode_line or
            (self.stat_enable & 0x8 != 0 and self.lyc_interrupt_line);
    }

    fn interruptMode(self: State) Mode {
        // The first enabled line reports mode 0 but SameBoy suppresses its
        // mode source until the initial mode-3 entry.
        if (self.startup_line and self.dot < MODE2_DOTS)
            return .transfer;
        return self.mode();
    }

    fn comparisonValue(self: State) ?u8 {
        if (!self.lcd_enabled) return null;
        if (self.line != LINES_PER_FRAME - 1) return self.line;

        // SameBoy's DMG-B comparison phases on physical line 153:
        // unavailable [0,6), 153 [6,8), unavailable [8,12), then 0.
        if (self.dot < 6) return null;
        if (self.dot < 8) return LINES_PER_FRAME - 1;
        if (self.dot < 12) return null;
        return 0;
    }
};

pub const Transition = struct {
    before: State,
    after: State,
    event: Event,
    interrupts: Interrupts,
    ly_read: u8,
    stat_read: u8,

    pub fn apply(before: State, event: Event) ValidationError!Transition {
        try before.validate();
        var after = before;
        const interrupts = switch (event) {
            .tick_dot => after.tickDot(),
            .write_lcdc => |value| after.writeLcdc(value),
            .write_stat => |value| after.writeStat(value),
            .write_lyc => |value| after.writeLyc(value),
        };
        try after.validate();
        return .{
            .before = before,
            .after = after,
            .event = event,
            .interrupts = interrupts,
            .ly_read = after.readLy(),
            .stat_read = after.readStat(),
        };
    }

    pub fn validate(self: Transition) error{InvalidTransition}!void {
        const expected = Transition.apply(self.before, self.event) catch
            return error.InvalidTransition;
        if (!std.meta.eql(expected, self))
            return error.InvalidTransition;
    }
};

pub const ReferencePoint = struct {
    line: u8,
    dot: u16,
    mode: Mode,
    ly: u8,
};

/// Pinned fixed-scanline vector from the SameBoy ranges cited above.
pub const REFERENCE_VECTOR = [_]ReferencePoint{
    .{ .line = 0, .dot = 0, .mode = .oam, .ly = 0 },
    .{ .line = 0, .dot = 79, .mode = .oam, .ly = 0 },
    .{ .line = 0, .dot = 80, .mode = .transfer, .ly = 0 },
    .{ .line = 0, .dot = 251, .mode = .transfer, .ly = 0 },
    .{ .line = 0, .dot = 252, .mode = .hblank, .ly = 0 },
    .{ .line = 143, .dot = 455, .mode = .hblank, .ly = 143 },
    .{ .line = 144, .dot = 0, .mode = .hblank, .ly = 144 },
    .{ .line = 144, .dot = 1, .mode = .vblank, .ly = 144 },
    .{ .line = 152, .dot = 455, .mode = .vblank, .ly = 152 },
    .{ .line = 153, .dot = 0, .mode = .vblank, .ly = 152 },
    .{ .line = 153, .dot = 2, .mode = .vblank, .ly = 153 },
    .{ .line = 153, .dot = 6, .mode = .vblank, .ly = 0 },
    .{ .line = 153, .dot = 455, .mode = .vblank, .ly = 0 },
};

fn canonicalState(
    line: u8,
    dot: u16,
    startup_line: bool,
    lyc: u8,
    stat_enable: u4,
) State {
    var state = State{
        .lcd_enabled = true,
        .line = line,
        .dot = dot,
        .startup_line = startup_line,
        .lyc = lyc,
        .stat_enable = stat_enable,
    };
    _ = state.refreshStat();
    return state;
}

test "pinned reference vector fixes modes and DMG line 153 LY" {
    for (REFERENCE_VECTOR) |point| {
        const state = canonicalState(
            point.line,
            point.dot,
            false,
            0xff,
            0,
        );
        try state.validate();
        try std.testing.expectEqual(point.mode, state.mode());
        try std.testing.expectEqual(point.ly, state.readLy());
    }
}

test "one full fixed frame exhaustively preserves mode geometry" {
    var state = canonicalState(0, 0, false, 0xff, 0);
    var counts = [_]usize{0} ** 4;
    for (0..@as(usize, LINES_PER_FRAME) * DOTS_PER_LINE) |_| {
        try state.validate();
        counts[@intFromEnum(state.mode())] += 1;
        _ = state.tickDot();
    }

    try std.testing.expectEqual(
        @as(usize, VISIBLE_LINES) * (DOTS_PER_LINE - MODE0_START) + 1,
        counts[@intFromEnum(Mode.hblank)],
    );
    try std.testing.expectEqual(
        @as(usize, LINES_PER_FRAME - VISIBLE_LINES) * DOTS_PER_LINE - 1,
        counts[@intFromEnum(Mode.vblank)],
    );
    try std.testing.expectEqual(
        @as(usize, VISIBLE_LINES) * MODE2_DOTS,
        counts[@intFromEnum(Mode.oam)],
    );
    try std.testing.expectEqual(
        @as(usize, VISIBLE_LINES) * MODE3_DOTS,
        counts[@intFromEnum(Mode.transfer)],
    );
    try std.testing.expectEqual(@as(u8, 0), state.line);
    try std.testing.expectEqual(@as(u16, 0), state.dot);
}

test "every STAT mask produces only combined-line and VBlank mode-2 edges" {
    for (0..16) |raw_enable| {
        const stat_enable: u4 = @intCast(raw_enable);
        var state = canonicalState(0, 0, false, 0xff, stat_enable);
        for (0..@as(usize, LINES_PER_FRAME) * DOTS_PER_LINE) |_| {
            const previous_line = state.stat_interrupt_line;
            const interrupts = state.tickDot();
            const entered_vblank =
                state.line == VISIBLE_LINES and state.dot == 1;
            const special_mode2 = entered_vblank and
                !previous_line and stat_enable & 0x4 != 0;
            const expected_stat =
                (state.stat_interrupt_line and !previous_line) or
                special_mode2;

            try std.testing.expectEqual(entered_vblank, interrupts.vblank);
            try std.testing.expectEqual(expected_stat, interrupts.stat);
            try state.validate();
        }
    }
}

test "LCD restart is canonical from every frame dot" {
    for (0..LINES_PER_FRAME) |raw_line| {
        const line: u8 = @intCast(raw_line);
        for (0..DOTS_PER_LINE) |raw_dot| {
            const dot: u16 = @intCast(raw_dot);
            var state = canonicalState(line, dot, false, 0xff, 0);

            _ = state.writeLcdc(0);
            try state.validate();
            try std.testing.expectEqual(@as(u8, 0), state.line);
            try std.testing.expectEqual(@as(u16, 0), state.dot);
            try std.testing.expectEqual(Mode.hblank, state.mode());

            _ = state.writeLcdc(0x80);
            try state.validate();
            try std.testing.expectEqual(@as(u8, 0), state.line);
            try std.testing.expectEqual(@as(u16, 0), state.dot);
            try std.testing.expect(state.startup_line);
        }
    }
}

test "VBlank requests IF once and DMG mode 2 source shares its edge" {
    var plain = canonicalState(143, 455, false, 0xff, 0);
    try std.testing.expect(!plain.tickDot().vblank);
    try std.testing.expectEqual(Mode.hblank, plain.mode());
    const entered = plain.tickDot();
    try std.testing.expect(entered.vblank);
    try std.testing.expect(!entered.stat);
    try std.testing.expectEqual(@as(u8, VISIBLE_LINES), plain.line);
    try std.testing.expect(!plain.tickDot().vblank);

    var mode2 = canonicalState(143, 455, false, 0xff, 0x4);
    try std.testing.expect(!mode2.tickDot().stat);
    const shared = mode2.tickDot();
    try std.testing.expect(shared.vblank);
    try std.testing.expect(shared.stat);
    try std.testing.expect(!mode2.stat_interrupt_line);

    var blocked = canonicalState(143, 455, false, 0xff, 0x1 | 0x4);
    try std.testing.expect(blocked.stat_interrupt_line);
    try std.testing.expect(!blocked.tickDot().stat);
    const blocked_edge = blocked.tickDot();
    try std.testing.expect(blocked_edge.vblank);
    try std.testing.expect(!blocked_edge.stat);
}

test "pinned Pokemon checkpoint requests VBlank after record 16047 opcode" {
    // boundary-000000.s1 projects to line 8/dot 228 at M-cycle
    // 13,312,966. SameBoy record 16,047 is the ordinary one-cycle opcode 0x91
    // at 13,363,525; VBlank is serviced only after that opcode.
    var state = canonicalState(8, 228, false, 0xff, 0);
    const before_callback_mcycles = 13_363_525 - 13_312_966 - 1;
    _ = state.tickDots(before_callback_mcycles * 4);
    try std.testing.expectEqual(@as(u8, 143), state.line);
    try std.testing.expectEqual(@as(u16, 452), state.dot);

    const callback_boundary = state.tickDots(4);
    try std.testing.expect(!callback_boundary.vblank);
    try std.testing.expectEqual(@as(u8, 144), state.line);
    try std.testing.expectEqual(@as(u16, 0), state.dot);
    try std.testing.expectEqual(Mode.hblank, state.mode());

    const opcode_91 = state.tickDots(4);
    try std.testing.expect(opcode_91.vblank);
    try std.testing.expectEqual(@as(u16, 4), state.dot);
    try std.testing.expectEqual(Mode.vblank, state.mode());
}

test "STAT mode and LYC requests require a low to high combined edge" {
    var hblank = canonicalState(7, MODE0_START - 1, false, 0xff, 0x1);
    try std.testing.expect(!hblank.stat_interrupt_line);
    try std.testing.expect(hblank.tickDot().stat);
    try std.testing.expect(hblank.stat_interrupt_line);
    try std.testing.expect(!hblank.tickDot().stat);

    var oam = canonicalState(7, DOTS_PER_LINE - 1, false, 0xff, 0x4);
    try std.testing.expect(oam.tickDot().stat);
    try std.testing.expectEqual(Mode.oam, oam.mode());

    var lyc = canonicalState(42, 100, false, 0xff, 0x8);
    try std.testing.expect(lyc.writeLyc(42).stat);
    try std.testing.expect(lyc.coincidence);
    try std.testing.expect(!lyc.writeLyc(42).stat);
    try std.testing.expect(!lyc.writeLyc(41).stat);
    try std.testing.expect(lyc.writeLyc(42).stat);

    // A matching LYC source keeps the line high through mode 3 and blocks the
    // following HBlank source, as exercised by Mooneye stat_irq_blocking.
    var combined = canonicalState(9, MODE0_START - 1, false, 9, 0x9);
    try std.testing.expect(combined.stat_interrupt_line);
    try std.testing.expect(!combined.tickDot().stat);
}

test "LCD disable freezes STAT comparison and enable restarts first line" {
    var state = canonicalState(144, 12, false, 144, 0x8);
    try std.testing.expect(state.stat_interrupt_line);
    try std.testing.expect(!state.writeLcdc(0).stat);
    try std.testing.expectEqual(@as(u8, 0), state.readLy());
    try std.testing.expectEqual(Mode.hblank, state.mode());
    try std.testing.expect(state.coincidence);
    try std.testing.expect(state.stat_interrupt_line);

    _ = state.writeLyc(0);
    _ = state.writeStat(0x40);
    _ = state.tickDots(1000);
    try std.testing.expectEqual(@as(u16, 0), state.dot);
    try std.testing.expect(state.coincidence);

    // The retained high line suppresses a new LYC interrupt when the new
    // LY=0 comparison is also true.
    try std.testing.expect(!state.writeLcdc(0x80).stat);
    try std.testing.expect(state.startup_line);
    try std.testing.expectEqual(Mode.hblank, state.mode());
    try std.testing.expect(state.coincidence);

    // First line 0 skips mode 2 and enters mode 3, then uses normal HBlank.
    _ = state.tickDots(MODE2_DOTS);
    try std.testing.expectEqual(Mode.transfer, state.mode());
    _ = state.tickDots(MODE3_DOTS);
    try std.testing.expectEqual(Mode.hblank, state.mode());
    _ = state.tickDots(DOTS_PER_LINE - MODE0_START);
    try std.testing.expectEqual(@as(u8, 1), state.line);
    try std.testing.expectEqual(Mode.oam, state.mode());
    try std.testing.expect(!state.startup_line);

    var low = State{};
    low.lyc = 1;
    low.stat_enable = 0x8;
    try std.testing.expect(!low.writeLcdc(0x80).stat);
    try std.testing.expect(low.writeLyc(0).stat);
}

test "line 153 comparison phases retain the hidden LYC line" {
    var state = canonicalState(152, 455, false, 152, 0x8);
    try std.testing.expect(state.stat_interrupt_line);

    _ = state.tickDot();
    try std.testing.expectEqual(@as(u8, 152), state.readLy());
    try std.testing.expect(!state.coincidence);
    try std.testing.expect(state.lyc_interrupt_line);
    try std.testing.expect(state.stat_interrupt_line);

    _ = state.tickDots(6);
    try std.testing.expectEqual(@as(u8, 0), state.readLy());
    try std.testing.expect(!state.lyc_interrupt_line);
    try std.testing.expect(!state.stat_interrupt_line);

    _ = state.writeLyc(153);
    try std.testing.expect(state.coincidence);
    try std.testing.expect(state.stat_interrupt_line);
    _ = state.tickDots(2);
    try std.testing.expect(!state.coincidence);
    try std.testing.expect(state.lyc_interrupt_line);
}

test "checkpoint and transition validation reject mutations" {
    const before = canonicalState(10, MODE0_START - 1, false, 0xff, 0x1);
    const transition = try Transition.apply(before, .tick_dot);
    try transition.validate();

    var bad_transition = transition;
    bad_transition.interrupts.stat = false;
    try std.testing.expectError(
        error.InvalidTransition,
        bad_transition.validate(),
    );

    var bad_dot = before;
    bad_dot.dot = DOTS_PER_LINE;
    try std.testing.expectError(error.InvalidDot, bad_dot.validate());

    var bad_mode_line = before;
    bad_mode_line.stat_interrupt_line = true;
    try std.testing.expectError(
        error.InvalidStatInterruptLine,
        bad_mode_line.validate(),
    );

    var bad_coincidence = canonicalState(4, 1, false, 4, 0);
    bad_coincidence.coincidence = false;
    try std.testing.expectError(
        error.InvalidCoincidence,
        bad_coincidence.validate(),
    );
}

test "interrupt mask uses Game Boy IF bit positions" {
    try std.testing.expectEqual(
        @as(u8, VBLANK_INTERRUPT | STAT_INTERRUPT),
        (Interrupts{ .vblank = true, .stat = true }).mask(),
    );
}
