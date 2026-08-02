//! Legacy and production clock-gap infrastructure column generators.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const state_chain = @import("../runner/state_chain.zig");
const trace_columns = @import("../air/trace_columns.zig");
const permutation = @import("permutation.zig");

const StateChainTracker = state_chain.StateChainTracker;

pub const MEM_CLOCK_UPDATE_COLS: usize = trace_columns.MemClockUpdateColumns.N_COLUMNS;
pub const REG_CLOCK_UPDATE_COLS: usize = trace_columns.RegClockUpdateColumns.N_COLUMNS;
/// enabler, address space, address, previous clock, four value bytes,
/// previous-clock low20, previous-clock high6.
///
/// The decomposition is a soundness boundary, not redundant witness data.
/// Opcode access clocks are four-wide refinements of at most `2^24`
/// instruction clocks. Bounding every synthetic predecessor below `2^26`
/// prevents an M31-wrapped clock cycle from balancing the memory bus.
pub const CLOCK_UPDATE_COLS: usize = 10;

pub fn genMemClockUpdateColumns(
    allocator: std.mem.Allocator,
    chain: *const StateChainTracker,
    log_size: u32,
) !struct { columns: [MEM_CLOCK_UPDATE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, MEM_CLOCK_UPDATE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    for (chain.clock_updates_mem.items, 0..) |update, row| {
        if (row >= domain_size) break;
        permutation.placeValue(columns[0], row, placement, M31.one());
        permutation.placeValue(
            columns[1],
            row,
            placement,
            M31.fromCanonical(update.addr & 0x7fff_ffff),
        );
        permutation.placeValue(columns[2], row, placement, M31.fromCanonical(update.clk));
        permutation.placeValue(columns[3], row, placement, M31.fromCanonical(update.clk_prev));
        const value_limbs = update.valueLimbs();
        for (value_limbs[0..3], 0..) |value, limb| {
            permutation.placeValue(columns[4 + limb], row, placement, value);
        }
    }
    return .{ .columns = columns, .n_real_rows = chain.clock_updates_mem.items.len };
}

pub fn freeMemClockUpdateColumns(
    allocator: std.mem.Allocator,
    columns: *[MEM_CLOCK_UPDATE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

pub fn genRegClockUpdateColumns(
    allocator: std.mem.Allocator,
    chain: *const StateChainTracker,
    log_size: u32,
) !struct { columns: [REG_CLOCK_UPDATE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, REG_CLOCK_UPDATE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    for (chain.clock_updates_reg.items, 0..) |update, row| {
        if (row >= domain_size) break;
        permutation.placeValue(columns[0], row, placement, M31.one());
        permutation.placeValue(
            columns[1],
            row,
            placement,
            M31.fromCanonical(update.addr & 0x7fff_ffff),
        );
        permutation.placeValue(columns[2], row, placement, M31.fromCanonical(update.clk_prev));
        for (update.valueLimbs(), 0..) |value, limb| {
            permutation.placeValue(columns[3 + limb], row, placement, value);
        }
    }
    return .{ .columns = columns, .n_real_rows = chain.clock_updates_reg.items.len };
}

pub fn freeRegClockUpdateColumns(
    allocator: std.mem.Allocator,
    columns: *[REG_CLOCK_UPDATE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

/// Generate the unified Stark-V clock-gap layout.
pub fn genClockUpdateColumns(
    allocator: std.mem.Allocator,
    chain: *const StateChainTracker,
    log_size: u32,
) !struct { columns: [CLOCK_UPDATE_COLS][]M31, n_real_rows: usize } {
    const domain_size = @as(usize, 1) << @intCast(log_size);
    var columns = try permutation.allocZeroColumns(allocator, CLOCK_UPDATE_COLS, domain_size);
    errdefer for (&columns) |column| allocator.free(column);
    const placement = try permutation.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);

    var row: usize = 0;
    for (chain.clock_updates_reg.items) |update| {
        if (row >= domain_size) break;
        placeClockUpdateRow(&columns, row, placement, 0, update);
        row += 1;
    }
    for (chain.clock_updates_mem.items) |update| {
        if (row >= domain_size) break;
        placeClockUpdateRow(&columns, row, placement, 1, update);
        row += 1;
    }
    return .{
        .columns = columns,
        .n_real_rows = chain.clock_updates_reg.items.len + chain.clock_updates_mem.items.len,
    };
}

pub fn freeClockUpdateColumns(
    allocator: std.mem.Allocator,
    columns: *[CLOCK_UPDATE_COLS][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

fn placeClockUpdateRow(
    columns: *[CLOCK_UPDATE_COLS][]M31,
    row: usize,
    placement: permutation.BitReversalTable,
    address_space: u32,
    update: state_chain.ClockUpdate,
) void {
    permutation.placeValue(columns[0], row, placement, M31.one());
    permutation.placeValue(columns[1], row, placement, M31.fromCanonical(address_space));
    permutation.placeValue(
        columns[2],
        row,
        placement,
        M31.fromCanonical(update.addr & 0x7fff_ffff),
    );
    permutation.placeValue(columns[3], row, placement, M31.fromCanonical(update.clk_prev));
    for (update.valueLimbs(), 0..) |value, limb| {
        permutation.placeValue(columns[4 + limb], row, placement, value);
    }
    permutation.placeValue(
        columns[8],
        row,
        placement,
        M31.fromCanonical(
            update.clk_prev & ((@as(u32, 1) << state_chain.CLOCK_PREV_LOW_BITS) - 1),
        ),
    );
    permutation.placeValue(
        columns[9],
        row,
        placement,
        M31.fromCanonical(update.clk_prev >> state_chain.CLOCK_PREV_LOW_BITS),
    );
}
