//! Column writer shared by the pinned family witness builders.

const M31 = @import("stwo_core").fields.m31.M31;

pub inline fn set(columns: anytype, row: usize, column: usize, value: M31) void {
    columns[column][row] = value;
}

pub inline fn u(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

pub inline fn bit(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
}

pub fn signed(value: i32) M31 {
    if (value >= 0) return u(value);
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
}

pub fn signedByte(value: u8) M31 {
    return signed(@as(i8, @bitCast(value)));
}

pub fn limbs(value: u32) [4]M31 {
    return .{ u(value & 0xff), u((value >> 8) & 0xff), u((value >> 16) & 0xff), u(value >> 24) };
}

pub fn writeLimbs(columns: anytype, row: usize, start: usize, value: u32) void {
    for (limbs(value), 0..) |limb, i| set(columns, row, start + i, limb);
}

/// Commit the exact architectural write-enable and its address inverse.
/// Keeping the enable as its own bit witness lets AIR result links remain
/// degree two, including for writes that Sail discards at x0.
pub fn destination(columns: anytype, row: usize, start: usize, address: u5) void {
    const address_felt = u(address);
    const nonzero = address != 0;
    set(columns, row, start, bit(nonzero));
    set(
        columns,
        row,
        start + 1,
        if (nonzero) address_felt.invUncheckedNonZero() else M31.zero(),
    );
}

fn access(
    columns: anytype,
    row_index: usize,
    start: usize,
    address: u32,
    previous: u32,
    previous_clock: u32,
    next: u32,
) void {
    set(columns, row_index, start, u(address));
    writeLimbs(columns, row_index, start + 1, previous);
    set(columns, row_index, start + 5, u(previous_clock));
    writeLimbs(columns, row_index, start + 6, next);
}

pub fn rd(columns: anytype, index: usize, start: usize, row: anytype) void {
    access(columns, index, start, row.rd, row.rd_prev_val, row.rd_prev_clk, row.rd_val);
}

pub fn rs1(columns: anytype, index: usize, start: usize, row: anytype) void {
    access(columns, index, start, row.rs1, row.rs1_val, row.rs1_prev_clk, row.rs1_val);
}

pub fn rs2(columns: anytype, index: usize, start: usize, row: anytype) void {
    access(columns, index, start, row.rs2, row.rs2_val, row.rs2_prev_clk, row.rs2_val);
}

pub fn memory(columns: anytype, index: usize, start: usize, row: anytype) void {
    access(
        columns,
        index,
        start,
        row.mem_addr & ~@as(u32, 3),
        row.mem_prev_word,
        row.mem_prev_clk,
        row.mem_next_word,
    );
}

pub fn loadStoreDst(columns: anytype, index: usize, start: usize, row: anytype) void {
    if (row.is_store) memory(columns, index, start, row) else rd(columns, index, start, row);
}

pub fn loadStoreSrc(columns: anytype, index: usize, start: usize, row: anytype) void {
    if (row.is_load) memory(columns, index, start, row) else rs2(columns, index, start, row);
}

pub fn common(columns: anytype, index: usize, clock_column: usize, row: anytype) void {
    set(columns, index, clock_column, u(row.clk));
    set(columns, index, clock_column + 1, u(row.pc));
}
