//! Witness-only layout and auxiliary construction for the PPU timing AIR.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ppu = @import("../runner/ppu_timing.zig");

pub const BASE_N_MAIN_COLUMNS: usize = 106;
pub const N_LINE_SEGMENTS: usize = 12;
pub const N_DOT_SEGMENTS: usize = 25;
pub const N_EQUALITIES: usize = 3;
pub const N_STATE_LOGIC: usize = 4;
pub const BEFORE_LINE_SEGMENT_OFFSET: usize = BASE_N_MAIN_COLUMNS;
pub const BEFORE_DOT_SEGMENT_OFFSET: usize =
    BEFORE_LINE_SEGMENT_OFFSET + N_LINE_SEGMENTS;
pub const BEFORE_EQUALITY_OFFSET: usize =
    BEFORE_DOT_SEGMENT_OFFSET + N_DOT_SEGMENTS;
pub const BEFORE_LOGIC_OFFSET: usize =
    BEFORE_EQUALITY_OFFSET + N_EQUALITIES;
pub const AFTER_LINE_SEGMENT_OFFSET: usize =
    BEFORE_LOGIC_OFFSET + N_STATE_LOGIC;
pub const AFTER_DOT_SEGMENT_OFFSET: usize =
    AFTER_LINE_SEGMENT_OFFSET + N_LINE_SEGMENTS;
pub const AFTER_EQUALITY_OFFSET: usize =
    AFTER_DOT_SEGMENT_OFFSET + N_DOT_SEGMENTS;
pub const AFTER_LOGIC_OFFSET: usize =
    AFTER_EQUALITY_OFFSET + N_EQUALITIES;
pub const CONTROL_OFFSET: usize = AFTER_LOGIC_OFFSET + N_STATE_LOGIC;
pub const STARTUP_TICK_OFFSET: usize = CONTROL_OFFSET + 3;
pub const REFRESH_OFFSET: usize = STARTUP_TICK_OFFSET + 1;
pub const VBLANK_POSITION_OFFSET: usize = REFRESH_OFFSET + 1;
pub const SPECIAL_MODE2_OFFSET: usize = VBLANK_POSITION_OFFSET + 1;
pub const REFRESH_RISE_OFFSET: usize = SPECIAL_MODE2_OFFSET + 1;
pub const N_BOOLEAN_COLUMNS: usize = REFRESH_RISE_OFFSET + 1;
pub const TICK_LINE_OFFSET: usize = N_BOOLEAN_COLUMNS;
pub const BEFORE_INVERSE_OFFSET: usize = TICK_LINE_OFFSET + 1;
pub const AFTER_INVERSE_OFFSET: usize =
    BEFORE_INVERSE_OFFSET + N_EQUALITIES;
pub const N_MAIN_COLUMNS: usize = AFTER_INVERSE_OFFSET + N_EQUALITIES;

pub const Segment = struct {
    start: usize,
    log_size: u4,
};

pub const LINE_SEGMENTS = [_]Segment{
    .{ .start = 0, .log_size = 7 },
    .{ .start = 128, .log_size = 3 },
    .{ .start = 136, .log_size = 2 },
    .{ .start = 140, .log_size = 1 },
    .{ .start = 142, .log_size = 0 },
    .{ .start = 143, .log_size = 0 },
    .{ .start = 144, .log_size = 0 },
    .{ .start = 145, .log_size = 0 },
    .{ .start = 146, .log_size = 1 },
    .{ .start = 148, .log_size = 2 },
    .{ .start = 152, .log_size = 0 },
    .{ .start = 153, .log_size = 0 },
};

pub const DOT_SEGMENTS = [_]Segment{
    .{ .start = 0, .log_size = 0 },
    .{ .start = 1, .log_size = 0 },
    .{ .start = 2, .log_size = 1 },
    .{ .start = 4, .log_size = 1 },
    .{ .start = 6, .log_size = 1 },
    .{ .start = 8, .log_size = 2 },
    .{ .start = 12, .log_size = 2 },
    .{ .start = 16, .log_size = 4 },
    .{ .start = 32, .log_size = 5 },
    .{ .start = 64, .log_size = 4 },
    .{ .start = 80, .log_size = 4 },
    .{ .start = 96, .log_size = 5 },
    .{ .start = 128, .log_size = 6 },
    .{ .start = 192, .log_size = 5 },
    .{ .start = 224, .log_size = 4 },
    .{ .start = 240, .log_size = 3 },
    .{ .start = 248, .log_size = 2 },
    .{ .start = 252, .log_size = 2 },
    .{ .start = 256, .log_size = 6 },
    .{ .start = 320, .log_size = 6 },
    .{ .start = 384, .log_size = 6 },
    .{ .start = 448, .log_size = 2 },
    .{ .start = 452, .log_size = 1 },
    .{ .start = 454, .log_size = 0 },
    .{ .start = 455, .log_size = 0 },
};

pub fn fill(out: []M31, transition: ppu.Transition) void {
    std.debug.assert(out.len == N_MAIN_COLUMNS);
    setStateAuxiliaries(
        out,
        BEFORE_LINE_SEGMENT_OFFSET,
        BEFORE_DOT_SEGMENT_OFFSET,
        BEFORE_EQUALITY_OFFSET,
        BEFORE_LOGIC_OFFSET,
        BEFORE_INVERSE_OFFSET,
        transition.before,
    );
    setStateAuxiliaries(
        out,
        AFTER_LINE_SEGMENT_OFFSET,
        AFTER_DOT_SEGMENT_OFFSET,
        AFTER_EQUALITY_OFFSET,
        AFTER_LOGIC_OFFSET,
        AFTER_INVERSE_OFFSET,
        transition.after,
    );

    const tag = std.meta.activeTag(transition.event);
    const tick = tag == .tick_dot;
    const write_lcdc = tag == .write_lcdc;
    const write_stat = tag == .write_stat;
    const write_lyc = tag == .write_lyc;
    const action: u8 = switch (transition.event) {
        .tick_dot => 0,
        .write_lcdc => |value| value,
        .write_stat => |value| value,
        .write_lyc => |value| value,
    };
    const action_enable = action & 0x80 != 0;
    const lcdc_enable =
        write_lcdc and !transition.before.lcd_enabled and action_enable;
    const lcdc_disable =
        write_lcdc and transition.before.lcd_enabled and !action_enable;
    out[CONTROL_OFFSET] = boolean(lcdc_enable);
    out[CONTROL_OFFSET + 1] = boolean(lcdc_disable);
    out[CONTROL_OFFSET + 2] =
        boolean(write_lcdc and !lcdc_enable and !lcdc_disable);

    const last_dot = transition.before.dot == ppu.DOTS_PER_LINE - 1;
    const tick_line = if (transition.before.lcd_enabled and last_dot)
        if (transition.before.line + 1 == ppu.LINES_PER_FRAME)
            0
        else
            transition.before.line + 1
    else
        transition.before.line;
    out[TICK_LINE_OFFSET] = M31.fromU64(tick_line);
    out[STARTUP_TICK_OFFSET] = boolean(
        transition.before.startup_line and
            !(transition.before.lcd_enabled and last_dot),
    );
    const refresh =
        (tick and transition.before.lcd_enabled) or
        lcdc_enable or
        (transition.before.lcd_enabled and (write_stat or write_lyc));
    out[REFRESH_OFFSET] = boolean(refresh);
    out[VBLANK_POSITION_OFFSET] = boolean(
        transition.before.line == ppu.VISIBLE_LINES and
            transition.before.dot == 0,
    );
    out[SPECIAL_MODE2_OFFSET] = boolean(
        transition.interrupts.vblank and
            transition.before.stat_enable & 0x4 != 0 and
            !transition.before.stat_interrupt_line,
    );
    out[REFRESH_RISE_OFFSET] = boolean(
        refresh and transition.after.stat_interrupt_line and
            !transition.before.stat_interrupt_line,
    );
}

fn setStateAuxiliaries(
    out: []M31,
    line_segment_offset: usize,
    dot_segment_offset: usize,
    equality_offset: usize,
    logic_offset: usize,
    inverse_offset: usize,
    state: ppu.State,
) void {
    out[line_segment_offset + segmentIndex(&LINE_SEGMENTS, state.line)] =
        M31.one();
    out[dot_segment_offset + segmentIndex(&DOT_SEGMENTS, state.dot)] =
        M31.one();

    const line = M31.fromU64(state.line);
    const lyc = M31.fromU64(state.lyc);
    const deltas = [N_EQUALITIES]M31{
        line.sub(lyc),
        lyc.sub(M31.fromU64(153)),
        lyc,
    };
    const equalities = [_]bool{
        state.line == state.lyc,
        state.lyc == 153,
        state.lyc == 0,
    };
    for (deltas, equalities, 0..) |delta, equal, index| {
        out[equality_offset + index] = boolean(equal);
        out[inverse_offset + index] = inverseOrZero(delta);
    }

    const comparison_valid = state.lcd_enabled and
        (state.line != ppu.LINES_PER_FRAME - 1 or
            (state.dot >= 6 and state.dot < 8) or state.dot >= 12);
    const comparison_matches =
        if (state.line != ppu.LINES_PER_FRAME - 1)
            state.line == state.lyc
        else if (state.dot >= 6 and state.dot < 8)
            state.lyc == ppu.LINES_PER_FRAME - 1
        else if (state.dot >= 12)
            state.lyc == 0
        else
            false;
    out[logic_offset] = boolean(comparison_valid);
    out[logic_offset + 1] = boolean(comparison_matches);
    const interrupt_mode: ppu.Mode =
        if (state.startup_line and state.dot < ppu.MODE2_DOTS)
            .transfer
        else
            state.mode();
    const mode_line = switch (interrupt_mode) {
        .hblank => state.stat_enable & 0x1 != 0,
        .vblank => state.stat_enable & 0x2 != 0,
        .oam => state.stat_enable & 0x4 != 0,
        .transfer => false,
    };
    out[logic_offset + 2] = boolean(mode_line);
    out[logic_offset + 3] = boolean(
        state.stat_enable & 0x8 != 0 and state.lyc_interrupt_line,
    );
}

fn segmentIndex(segments: []const Segment, value: usize) usize {
    for (segments, 0..) |segment, index| {
        if (value >= segment.start and
            value < segment.start + (@as(usize, 1) << segment.log_size))
            return index;
    }
    unreachable;
}

fn inverseOrZero(value: M31) M31 {
    if (value.isZero()) return M31.zero();
    return value.invUncheckedNonZero();
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
