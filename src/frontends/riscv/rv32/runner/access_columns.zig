//! Register and memory access witness column encoding.

const M31 = @import("stwo_core").fields.m31.M31;

fn write(columns: anytype, column: usize, row: usize, value: M31) void {
    if (columns[column].len != 0) columns[column][row] = value;
}

fn writeU32Limbs(columns: anytype, row_idx: usize, start: usize, value: u32) void {
    write(columns, start, row_idx, M31.fromU64(value & 0xff));
    write(columns, start + 1, row_idx, M31.fromU64((value >> 8) & 0xff));
    write(columns, start + 2, row_idx, M31.fromU64((value >> 16) & 0xff));
    write(columns, start + 3, row_idx, M31.fromU64((value >> 24) & 0xff));
}

fn writeAccess(
    columns: anytype,
    row_idx: usize,
    start: usize,
    addr: u32,
    previous_value: u32,
    previous_clock: u32,
    next_value: u32,
) void {
    write(columns, start, row_idx, M31.fromU64(addr));
    writeU32Limbs(columns, row_idx, start + 1, previous_value);
    write(columns, start + 5, row_idx, M31.fromU64(previous_clock));
    writeU32Limbs(columns, row_idx, start + 6, next_value);
}

pub fn writeRd(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    writeAccess(columns, row_idx, start, row.rd, row.rd_prev_val, row.rd_prev_clk, row.rd_val);
}

pub fn writeRs1(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    writeAccess(columns, row_idx, start, row.rs1, row.rs1_val, row.rs1_prev_clk, row.rs1_val);
}

pub fn writeRs2(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    writeAccess(columns, row_idx, start, row.rs2, row.rs2_val, row.rs2_prev_clk, row.rs2_val);
}

pub fn writeMemory(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    writeAccess(
        columns,
        row_idx,
        start,
        row.mem_addr & ~@as(u32, 3),
        row.mem_prev_word,
        row.mem_prev_clk,
        row.mem_next_word,
    );
}

pub fn writeLoadStoreDst(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    if (row.is_store) return writeMemory(columns, row_idx, start, row);
    writeRd(columns, row_idx, start, row);
}

pub fn writeLoadStoreSrc(columns: anytype, row_idx: usize, start: usize, row: anytype) void {
    if (row.is_load) return writeMemory(columns, row_idx, start, row);
    writeRs2(columns, row_idx, start, row);
}
