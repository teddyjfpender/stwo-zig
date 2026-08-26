//! Test-only oracle for the retired handwritten SHIFTS_IMM witness writer.

const w = @import("writer.zig");

const Shift = struct {
    sign: u32,
    bit_markers: [8]u32,
    limb_markers: [4]u32,
    carries: [4]u32,
};

fn compute(value: u32, amount: u5, left: bool, arithmetic: bool) Shift {
    const bit_shift: u3 = @truncate(amount);
    const limb_shift: u2 = @truncate(amount >> 3);
    var result = Shift{
        .sign = if (arithmetic) value >> 31 else 0,
        .bit_markers = .{0} ** 8,
        .limb_markers = .{0} ** 4,
        .carries = .{0} ** 4,
    };
    result.bit_markers[bit_shift] = 1;
    result.limb_markers[limb_shift] = 1;
    for (0..4) |index| {
        const byte: u8 = @truncate(value >> @intCast(8 * index));
        result.carries[index] = if (bit_shift == 0)
            0
        else if (left)
            @as(u32, byte) >> @intCast(8 - @as(u4, bit_shift))
        else
            @as(u32, byte) & ((@as(u32, 1) << bit_shift) - 1);
    }
    return result;
}

fn shiftedValue(value: u32, amount: u5, left: bool, arithmetic: bool) u32 {
    if (left) return value << amount;
    if (!arithmetic) return value >> amount;
    const signed: i32 = @bitCast(value);
    return @bitCast(signed >> amount);
}

pub inline fn writeRow(columns: anytype, index: usize, row: anytype) void {
    const amount: u5 = @truncate(@as(u32, @bitCast(row.imm)));
    const left = row.opcode == .SLLI;
    const arithmetic = row.opcode == .SRAI;
    const shift = compute(row.rs1_val, amount, left, arithmetic);
    const multiplier = @as(u32, 1) << @as(u3, @truncate(amount));

    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.set(columns, index, 22, w.u(shift.sign));
    w.set(columns, index, 23, w.u(amount));
    w.set(columns, index, 24, w.bit(left));
    w.set(columns, index, 25, w.bit(!left and !arithmetic));
    w.set(columns, index, 26, w.bit(arithmetic));
    w.set(columns, index, 27, w.u(if (left) multiplier else 0));
    w.set(columns, index, 28, w.u(if (left) 0 else multiplier));
    for (shift.bit_markers, 0..) |marker, marker_index|
        w.set(columns, index, 29 + marker_index, w.u(marker));
    for (shift.limb_markers, 0..) |marker, marker_index|
        w.set(columns, index, 37 + marker_index, w.u(marker));
    for (shift.carries, 0..) |carry, carry_index|
        w.set(columns, index, 41 + carry_index, w.u(carry));
    w.writeLimbs(columns, index, 45, shiftedValue(row.rs1_val, amount, left, arithmetic));
    w.destination(columns, index, 49, row.rd);
}
