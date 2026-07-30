//! Exact hot-one shift witnesses from the pinned Stark-V runner.

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
    for (0..4) |i| {
        const byte: u8 = @truncate(value >> @intCast(8 * i));
        result.carries[i] = if (bit_shift == 0)
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

fn suffix(columns: anytype, index: usize, start: usize, row: anytype, amount: u5) void {
    const left = row.opcode == .SLL or row.opcode == .SLLI;
    const arithmetic = row.opcode == .SRA or row.opcode == .SRAI;
    const witness = compute(row.rs1_val, amount, left, arithmetic);
    // The multiplier column is 2^bit_shift (the sub-byte component only);
    // the limb component is carried by the hot-one limb markers.
    const multiplier = @as(u32, 1) << @as(u3, @truncate(amount));
    w.set(columns, index, start, w.u(witness.sign));
    w.set(columns, index, start + 1, w.bit(left));
    w.set(columns, index, start + 2, w.bit(!left and !arithmetic));
    w.set(columns, index, start + 3, w.bit(arithmetic));
    w.set(columns, index, start + 4, w.u(if (left) multiplier else 0));
    w.set(columns, index, start + 5, w.u(if (left) 0 else multiplier));
    for (witness.bit_markers, 0..) |marker, i| w.set(columns, index, start + 6 + i, w.u(marker));
    for (witness.limb_markers, 0..) |marker, i| w.set(columns, index, start + 14 + i, w.u(marker));
    for (witness.carries, 0..) |carry, i| w.set(columns, index, start + 18 + i, w.u(carry));
}

pub fn reg(columns: anytype, index: usize, row: anytype) void {
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    const amount: u5 = @truncate(row.rs2_val);
    suffix(columns, index, 32, row, amount);
    const left = row.opcode == .SLL;
    const arithmetic = row.opcode == .SRA;
    w.writeLimbs(columns, index, 54, shiftedValue(row.rs1_val, amount, left, arithmetic));
    w.destination(columns, index, 58, row.rd);
}

pub fn immediate(columns: anytype, index: usize, row: anytype) void {
    const amount: u5 = @truncate(@as(u32, @bitCast(row.imm)));
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.set(columns, index, 22, w.u(if (row.opcode == .SRAI) row.rs1_val >> 31 else 0));
    w.set(columns, index, 23, w.u(amount));
    // `suffix` includes rs1_sign, so write its remaining fields shifted by one.
    const left = row.opcode == .SLLI;
    const arithmetic = row.opcode == .SRAI;
    const witness = compute(row.rs1_val, amount, left, arithmetic);
    const multiplier = @as(u32, 1) << @as(u3, @truncate(amount));
    w.set(columns, index, 24, w.bit(left));
    w.set(columns, index, 25, w.bit(!left and !arithmetic));
    w.set(columns, index, 26, w.bit(arithmetic));
    w.set(columns, index, 27, w.u(if (left) multiplier else 0));
    w.set(columns, index, 28, w.u(if (left) 0 else multiplier));
    for (witness.bit_markers, 0..) |marker, i| w.set(columns, index, 29 + i, w.u(marker));
    for (witness.limb_markers, 0..) |marker, i| w.set(columns, index, 37 + i, w.u(marker));
    for (witness.carries, 0..) |carry, i| w.set(columns, index, 41 + i, w.u(carry));
    w.writeLimbs(columns, index, 45, shiftedValue(row.rs1_val, amount, left, arithmetic));
    w.destination(columns, index, 49, row.rd);
}

const std_probe = @import("std");
const M31_probe = @import("stwo_core").fields.m31.M31;
const QM31_probe = @import("stwo_core").fields.qm31.QM31;
const shifts_imm_semantics = @import("../../air/semantics/mod.zig").shifts_imm;

test "shift witness: SLLI by 8 satisfies pinned semantics" {
    const n = shifts_imm_semantics.N_ORACLE_COLUMNS;
    var storage: [n][1]M31_probe = .{.{M31_probe.zero()}} ** n;
    var columns: [n][]M31_probe = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;

    const TestRow = struct {
        clk: u32 = 1,
        pc: u32 = 0x1000,
        opcode: @import("../decode.zig").Opcode = .SLLI,
        rd: u5 = 6,
        rs1: u5 = 1,
        rs2: u5 = 0,
        imm: i32 = 8,
        rs1_val: u32 = 0xF0F0_F0F0,
        rs1_prev_clk: u32 = 0,
        rs2_val: u32 = 0,
        rs2_prev_clk: u32 = 0,
        rd_prev_val: u32 = 0,
        rd_prev_clk: u32 = 0,
        rd_val: u32 = 0xF0F0_F000,
        mem_addr: u32 = 0,
        mem_prev_word: u32 = 0,
        mem_prev_clk: u32 = 0,
        mem_next_word: u32 = 0,
        is_load: bool = false,
        is_store: bool = false,
    };
    immediate(&columns, 0, TestRow{});

    var sampled: [n]QM31_probe = undefined;
    for (&sampled, columns) |*value, column| value.* = QM31_probe.fromBase(column[0]);
    const row = try shifts_imm_semantics.Row.fromOracleColumns(&sampled);
    const constraints = shifts_imm_semantics.evaluate(row);
    var failing: usize = 0;
    for (constraints.values, 0..) |value, i| {
        if (!value.eql(QM31_probe.zero())) {
            std_probe.debug.print("SLLI8 constraint {d} nonzero\n", .{i});
            failing += 1;
        }
    }
    try std_probe.testing.expectEqual(@as(usize, 0), failing);
}
