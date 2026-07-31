//! PPU binding trace geometry and row encoding.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const types = @import("ppu_binding_types.zig");
const ppu_air = @import("ppu_timing.zig");
const ppu_component = @import("ppu_timing_component.zig");

pub const MCYCLE_OFFSET: usize = ppu_component.N_MAIN_COLUMNS;
pub const PHASE_OFFSET: usize = MCYCLE_OFFSET + 1;
pub const READ_MARKER_OFFSET: usize = PHASE_OFFSET + 4;
pub const READ_VALUE_OFFSET: usize = READ_MARKER_OFFSET + 7;
pub const LY_WRITE_ENABLED_OFFSET: usize = READ_VALUE_OFFSET + 8;
pub const LATCH_WRITE_MARKER_OFFSET: usize = LY_WRITE_ENABLED_OFFSET + 1;
pub const LATCH_WRITE_VALUE_OFFSET: usize = LATCH_WRITE_MARKER_OFFSET + 3;
pub const LATCH_BEFORE_OFFSET: usize = LATCH_WRITE_VALUE_OFFSET + 1;
pub const LATCH_AFTER_OFFSET: usize = LATCH_BEFORE_OFFSET + 3;
pub const LCDC_BEFORE_OFFSET: usize = LATCH_AFTER_OFFSET + 3;
pub const LCDC_AFTER_OFFSET: usize = LCDC_BEFORE_OFFSET + 8;
pub const REQUEST_SEEN_OFFSET: usize = LCDC_AFTER_OFFSET + 8;
pub const N_MAIN_COLUMNS: usize = REQUEST_SEEN_OFFSET + 1;

pub const Witness = struct {
    log_size: u32,
    event_count: usize,
    main: [N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Witness) void {
        self.owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn encode(row: types.EventRow) ![N_MAIN_COLUMNS]M31 {
    const validated = ppu_air.ValidatedStep.init(row.transition) catch
        return error.InvalidPpuTransition;
    var result = inactive();
    const semantic = ppu_component.columns(validated);
    @memcpy(result[0..ppu_component.N_MAIN_COLUMNS], &semantic);
    result[MCYCLE_OFFSET] = M31.fromCanonical(row.mcycle);
    if (row.dot_phase) |phase|
        result[PHASE_OFFSET + phase] = M31.one();
    if (row.read_register) |register| {
        result[READ_MARKER_OFFSET + @intFromEnum(register)] = M31.one();
        writeBits(
            result[READ_VALUE_OFFSET..LY_WRITE_ENABLED_OFFSET],
            stateBefore(row).read(register),
        );
    }
    if (row.ignored_ly_write != null)
        result[LY_WRITE_ENABLED_OFFSET] = M31.one();
    if (row.latch_write) |write| {
        const index = types.latchIndex(write.register) orelse
            return error.InvalidPpuLatchWrite;
        result[LATCH_WRITE_MARKER_OFFSET + index] = M31.one();
        result[LATCH_WRITE_VALUE_OFFSET] = M31.fromCanonical(write.value);
    }
    for (row.latches_before, 0..) |value, index|
        result[LATCH_BEFORE_OFFSET + index] = M31.fromCanonical(value);
    for (row.latches_after, 0..) |value, index|
        result[LATCH_AFTER_OFFSET + index] = M31.fromCanonical(value);
    writeBits(result[LCDC_BEFORE_OFFSET..LCDC_AFTER_OFFSET], row.lcdc_before);
    writeBits(result[LCDC_AFTER_OFFSET..REQUEST_SEEN_OFFSET], row.lcdc_after);
    return result;
}

pub fn inactive() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

fn stateBefore(row: types.EventRow) types.State {
    return .{
        .timing = row.transition.before,
        .lcdc = row.lcdc_before,
        .scy = row.latches_before[0],
        .scx = row.latches_before[1],
        .wy = row.latches_before[2],
    };
}

fn writeBits(out: []M31, value: u8) void {
    for (out, 0..) |*destination, index|
        destination.* = M31.fromCanonical(
            @intCast(value >> @intCast(index) & 1),
        );
}
