//! Exact upper-immediate and jump witnesses.

const w = @import("writer.zig");

fn leading(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.rd(columns, index, 3, row);
}

pub fn lui(columns: anytype, index: usize, row: anytype) void {
    leading(columns, index, row);
    const immediate = @as(u32, @bitCast(row.imm)) >> 12;
    w.set(columns, index, 13, w.u(immediate & 0xf));
    w.set(columns, index, 14, w.u((immediate >> 4) & 0xff));
    w.set(columns, index, 15, w.u(immediate >> 12));
    w.destination(columns, index, 16, row.rd);
}

pub fn auipc(columns: anytype, index: usize, row: anytype) void {
    leading(columns, index, row);
    w.set(columns, index, 13, w.signed(row.imm));
    w.writeLimbs(columns, index, 14, row.pc +% @as(u32, @bitCast(row.imm)));
    w.destination(columns, index, 18, row.rd);
    w.writeLimbs(columns, index, 20, row.pc);
    w.writeLimbs(columns, index, 24, @bitCast(row.imm));
    w.set(columns, index, 28, w.bit(row.imm < 0));
}

pub fn jal(columns: anytype, index: usize, row: anytype) void {
    leading(columns, index, row);
    w.set(columns, index, 13, w.signed(row.imm));
    w.writeLimbs(columns, index, 14, row.pc +% 4);
    w.destination(columns, index, 18, row.rd);
}

pub fn jalr(columns: anytype, index: usize, row: anytype) void {
    leading(columns, index, row);
    w.rs1(columns, index, 13, row);
    const unaligned = row.rs1_val +% @as(u32, @bitCast(row.imm));
    const target = unaligned & ~@as(u32, 1);
    const target_word = target >> 2;
    const immediate_bits: u32 = @bitCast(row.imm);
    const immediate_12 = immediate_bits & 0xfff;
    // Preserve the complete 32-column Stark-V prefix byte-for-byte.
    w.set(columns, index, 23, w.u(target / 2));
    w.set(columns, index, 24, w.u(unaligned & 1));
    w.set(columns, index, 25, w.signed(row.imm));
    w.writeLimbs(columns, index, 26, row.pc +% 4);
    w.destination(columns, index, 30, row.rd);
    // Sail-authoritative row-local target binding appended after the prefix.
    w.set(columns, index, 32, w.u(target_word & ((@as(u32, 1) << 20) - 1)));
    w.set(columns, index, 33, w.u(target_word >> 20));
    w.writeLimbs(columns, index, 34, target);
    w.set(columns, index, 38, w.u(immediate_12 & 0xff));
    w.set(columns, index, 39, w.u(immediate_12 >> 8));
    w.set(columns, index, 40, w.bit(row.imm < 0));
}

pub fn fence(columns: anytype, index: usize, row: anytype) void {
    w.set(columns, index, 0, w.u(1));
    w.common(columns, index, 1, row);
    w.set(columns, index, 3, w.u(row.rd));
    w.set(columns, index, 4, w.u(row.rs1));
    w.set(columns, index, 5, w.u(@as(u32, @bitCast(row.imm)) & 0xfff));
}
