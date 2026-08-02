//! Legacy program-ROM and memory-access infrastructure column generators.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const program_table = @import("../air/program/table.zig");
const trace_columns = @import("../air/trace_columns.zig");
const trace_mod = @import("../runner/trace.zig");
const StateChainTracker = @import("../runner/state_chain.zig").StateChainTracker;
const permutation = @import("permutation.zig");

pub const PROGRAM_TRACE_COLS: usize = trace_columns.ProgramColumns.N_COLUMNS - 1;
pub const MEMORY_TRACE_COLS: usize = trace_columns.MemoryCheckColumns.N_COLUMNS - 2;

pub const MemoryColumnsResult = struct {
    columns: [MEMORY_TRACE_COLS][]M31,
    n_real_rows: usize,
};

/// Generate the populated program ROM columns in committed order.
pub fn genProgramColumns(
    allocator: std.mem.Allocator,
    exec_trace: *const trace_mod.Trace,
    log_size: u32,
) !struct { columns: [PROGRAM_TRACE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, PROGRAM_TRACE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);

    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    const fetches = try allocator.alloc(program_table.Fetch, exec_trace.rows.items.len);
    defer allocator.free(fetches);
    for (exec_trace.rows.items, fetches) |row, *fetch| {
        fetch.* = .{ .pc = row.pc, .word = row.inst_word };
    }
    var decoded = try program_table.generate(allocator, fetches);
    defer decoded.deinit();
    if (decoded.rows.len > domain_size) return error.InvalidTraceShape;

    for (decoded.rows, 0..) |row, row_index| {
        const values = row.relationValues();
        permutation.placeValue(columns[0], row_index, placement, M31.one());
        for (values, 0..) |value, column| {
            permutation.placeValue(
                columns[1 + column],
                row_index,
                placement,
                M31.fromU64(value),
            );
        }
        permutation.placeValue(
            columns[6],
            row_index,
            placement,
            M31.fromU64(row.multiplicity),
        );
        const word_address = row.pc >> 2;
        permutation.placeValue(
            columns[7],
            row_index,
            placement,
            M31.fromU64(word_address & ((@as(u32, 1) << 20) - 1)),
        );
        permutation.placeValue(
            columns[8],
            row_index,
            placement,
            M31.fromU64(word_address >> 20),
        );
    }
    return .{ .columns = columns, .n_real_rows = decoded.rows.len };
}

pub fn freeProgramColumns(
    allocator: std.mem.Allocator,
    columns: *[PROGRAM_TRACE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

pub fn genMemoryColumns(
    allocator: std.mem.Allocator,
    chain: *const StateChainTracker,
    log_size: u32,
) !MemoryColumnsResult {
    return genMemoryColumnsRange(allocator, chain, log_size, 0, chain.accesses.items.len);
}

pub fn genMemoryColumnsRange(
    allocator: std.mem.Allocator,
    chain: *const StateChainTracker,
    log_size: u32,
    access_start: usize,
    access_end: usize,
) !MemoryColumnsResult {
    if (access_start > access_end or access_end > chain.accesses.items.len)
        return error.InvalidAccessRange;
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, MEMORY_TRACE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);

    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    var row_index: usize = 0;
    for (chain.accesses.items[access_start..access_end]) |access| {
        if (row_index >= domain_size) break;
        permutation.placeValue(columns[0], row_index, placement, M31.one());
        permutation.placeValue(
            columns[1],
            row_index,
            placement,
            M31.fromCanonical(access.addr & 0x7fff_ffff),
        );
        permutation.placeValue(columns[2], row_index, placement, M31.fromCanonical(access.clk));
        for (access.valueLimbs(), 0..) |value, limb| {
            permutation.placeValue(columns[3 + limb], row_index, placement, value);
        }
        row_index += 1;
    }
    return .{ .columns = columns, .n_real_rows = row_index };
}

pub fn freeMemoryColumns(
    allocator: std.mem.Allocator,
    columns: *[MEMORY_TRACE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}
