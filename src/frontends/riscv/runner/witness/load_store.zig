//! Exact load/store role-separated witness.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const Opcode = @import("../decode.zig").Opcode;
const load_store_semantics = @import("../../air/semantics/mod.zig").load_store;
const w = @import("writer.zig");

fn loadResult(row: anytype) u32 {
    return switch (row.opcode) {
        .LB => @bitCast(@as(i32, @as(i8, @bitCast(@as(u8, @truncate(row.mem_val)))))),
        .LH => @bitCast(@as(i32, @as(i16, @bitCast(@as(u16, @truncate(row.mem_val)))))),
        .LBU, .LHU, .LW => row.mem_val,
        else => 0,
    };
}

pub fn fill(columns: anytype, index: usize, row: anytype) void {
    w.common(columns, index, 0, row);
    w.loadStoreDst(columns, index, 2, row);
    w.readRs1(columns, index, 12, row);
    w.readLoadStoreSrc(columns, index, 18, row);

    const byte_op = row.opcode == .LB or row.opcode == .LBU or row.opcode == .SB;
    const half_op = row.opcode == .LH or row.opcode == .LHU or row.opcode == .SH;
    const offset = row.mem_addr & 3;
    const shift = if (byte_op) offset else if (half_op) offset & 2 else 0;
    const r2 = if (row.is_load) @as(u32, row.rd) else @as(u32, row.rs2);
    const aligned = row.mem_addr -% shift;
    const src_selector = if (row.is_load) aligned else r2;
    const dst_selector = if (row.is_load) r2 else aligned;
    const result = loadResult(row);
    const selected_msb: u32 = if (row.opcode == .LB)
        (result >> 31) & 1
    else if (row.opcode == .LH)
        (result >> 31) & 1
    else
        0;

    w.set(columns, index, 24, w.u(r2));
    w.set(columns, index, 25, w.signed(row.imm));
    w.set(columns, index, 26, w.u(selected_msb));
    w.set(columns, index, 27, w.u(shift));
    w.set(columns, index, 28, w.u(src_selector));
    w.set(columns, index, 29, w.u(dst_selector));
    for (0..4) |limb| {
        const marked = if (byte_op)
            limb == offset
        else if (half_op)
            (offset < 2 and limb < 2) or (offset >= 2 and limb >= 2)
        else
            false;
        w.set(columns, index, 30 + limb, w.bit(marked));
    }
    const flags = [_]bool{
        row.opcode == .LB, row.opcode == .LH, row.opcode == .LBU, row.opcode == .LHU,
        row.opcode == .LW, row.opcode == .SB, row.opcode == .SH,  row.opcode == .SW,
    };
    for (flags, 0..) |flag, i| w.set(columns, index, 34 + i, w.bit(flag));
    w.writeLimbs(columns, index, 42, result);
    w.destination(columns, index, 46, @intCast(r2));
}

fn semanticRow(row: anytype) !load_store_semantics.Row {
    const n = load_store_semantics.N_ORACLE_COLUMNS;
    var storage: [n][1]M31 = .{.{M31.zero()}} ** n;
    var columns: [n][]M31 = undefined;
    for (&columns, &storage) |*column, *values| column.* = values;
    fill(&columns, 0, row);

    var sampled: [n]QM31 = undefined;
    for (&sampled, columns) |*value, column| value.* = QM31.fromBase(column[0]);
    return load_store_semantics.Row.fromOracleColumns(&sampled);
}

test "load store witness: aligned SW and LW satisfy pinned semantics" {
    const TestRow = struct {
        clk: u32 = 1,
        pc: u32 = 0x1000,
        opcode: Opcode,
        rd: u5 = 0,
        rs1: u5 = 2,
        rs2: u5 = 0,
        imm: i32 = 0,
        rs1_val: u32 = 0x2000,
        rs1_prev_clk: u32 = 0,
        rs2_val: u32 = 0,
        rs2_prev_clk: u32 = 0,
        rd_prev_val: u32 = 0,
        rd_prev_clk: u32 = 0,
        rd_val: u32 = 0,
        mem_addr: u32 = 0x2000,
        mem_val: u32 = 0,
        mem_prev_word: u32 = 0,
        mem_prev_clk: u32 = 0,
        mem_next_word: u32 = 0,
        is_load: bool = false,
        is_store: bool = false,
    };

    const value: u32 = 0xCAFE_BABE;
    const sw = try semanticRow(TestRow{
        .opcode = .SW,
        .rs2 = 3,
        .rs2_val = value,
        .mem_next_word = value,
        .is_store = true,
    });
    try std.testing.expect(load_store_semantics.evaluate(sw).allZero());
    try std.testing.expect(sw.dst.addr.eql(QM31.fromBase(M31.fromU64(0x2000))));
    try std.testing.expect(sw.src.addr.eql(QM31.fromBase(M31.fromU64(3))));

    const lw = try semanticRow(TestRow{
        .clk = 2,
        .pc = 0x1004,
        .opcode = .LW,
        .rd = 4,
        .rd_val = value,
        .mem_val = value,
        .mem_prev_word = value,
        .mem_prev_clk = 1,
        .mem_next_word = value,
        .is_load = true,
    });
    try std.testing.expect(load_store_semantics.evaluate(lw).allZero());
    try std.testing.expect(lw.src.addr.eql(QM31.fromBase(M31.fromU64(0x2000))));
    try std.testing.expect(lw.dst.addr.eql(QM31.fromBase(M31.fromU64(4))));
}
