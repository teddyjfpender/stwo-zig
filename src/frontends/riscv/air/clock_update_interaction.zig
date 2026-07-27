//! Exact Stark-V lookup source and interaction trace for clock-gap rows.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../infra_trace.zig");
const state_chain = @import("../runner/state_chain.zig");
const common = @import("semantics/common.zig");
const entry = @import("lookups/entry.zig");
const counter = @import("lookups/tables/counter.zig");
const logup = @import("logup.zig");
const relations_mod = @import("relation_challenges.zig");

pub const N_MAIN_COLUMNS: usize = 8;
pub const N_INTERACTION_COLUMNS: usize = 4;
pub const RANGE_CHECK_20_ENTRIES_PER_ROW: usize = 0;
pub const CHUNK_ROWS: usize = 4096;

comptime {
    std.debug.assert(infra.CLOCK_UPDATE_COLS == N_MAIN_COLUMNS);
}

pub const Row = struct {
    enabler: QM31,
    addr_space: QM31,
    addr: QM31,
    clock_prev: QM31,
    value: [4]QM31,

    pub fn fromMain(main: []const QM31) !Row {
        if (main.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
        return .{
            .enabler = main[0],
            .addr_space = main[1],
            .addr = main[2],
            .clock_prev = main[3],
            .value = .{ main[4], main[5], main[6], main[7] },
        };
    }
};

/// Pinned Stark-V emits only the two memory-bus sides. The range-check table
/// defines the fixed gap constant; clock-update rows are not table consumers.
pub fn orderedEntries(row: Row) entry.List {
    var result = entry.List{};
    entry.memory(&result, row.enabler.neg(), memoryTuple(row, row.clock_prev));
    entry.memory(
        &result,
        row.enabler,
        memoryTuple(row, row.clock_prev.add(q(state_chain.MAX_CLOCK_DIFF))),
    );
    return result;
}

pub fn pair(row: Row, relations: *const relations_mod.Relations) !logup.RowPair {
    return (orderedEntries(row)).pair(0, relations);
}

/// Explicit pre-commit hook. It validates the target counter and deliberately
/// registers nothing, matching `clock_gap.bound_by: range_check_20` upstream.
pub fn registerRangeCheck20Counter(target: *counter.Counter) !void {
    if (target.kind != .range_check_20) return error.InvalidRelationDomain;
}

pub const InteractionTrace = struct {
    columns: [N_INTERACTION_COLUMNS][]M31 = .{&.{}} ** N_INTERACTION_COLUMNS,
    previous: [N_INTERACTION_COLUMNS][]M31 = .{&.{}} ** N_INTERACTION_COLUMNS,
    claim: QM31 = QM31.zero(),

    pub fn takeColumns(self: *InteractionTrace) [N_INTERACTION_COLUMNS][]M31 {
        const result = self.columns;
        self.columns = .{&.{}} ** N_INTERACTION_COLUMNS;
        return result;
    }

    pub fn deinit(self: *InteractionTrace, allocator: std.mem.Allocator) void {
        for (self.columns) |column| if (column.len != 0) allocator.free(column);
        for (self.previous) |column| allocator.free(column);
        self.* = undefined;
    }
};

/// Builds cumulative columns from the exact bit-reversed main buffers that are
/// handed to Tree 1. No reconstructed host-side clock rows are accepted.
pub fn generate(
    allocator: std.mem.Allocator,
    main: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !InteractionTrace {
    const size = @as(usize, 1) << @intCast(log_size);
    try validateColumns(main, size);
    var result = InteractionTrace{};
    var current_initialized: usize = 0;
    var previous_initialized: usize = 0;
    errdefer {
        for (result.columns[0..current_initialized]) |column| allocator.free(column);
        for (result.previous[0..previous_initialized]) |column| allocator.free(column);
    }
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, size);
        current_initialized += 1;
    }
    for (&result.previous) |*column| {
        column.* = try allocator.alloc(M31, size);
        previous_initialized += 1;
    }

    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    const chunk_capacity = @min(size, CHUNK_ROWS);
    const numerators = try allocator.alloc(QM31, chunk_capacity);
    defer allocator.free(numerators);
    const denominators = try allocator.alloc(QM31, chunk_capacity);
    defer allocator.free(denominators);
    const inverses = try allocator.alloc(QM31, chunk_capacity);
    defer allocator.free(inverses);
    var sampled: [N_MAIN_COLUMNS]QM31 = undefined;

    var row_start: usize = 0;
    while (row_start < size) {
        const chunk_len = @min(CHUNK_ROWS, size - row_start);
        for (0..chunk_len) |local_row| {
            const committed_row = placement.map(row_start + local_row);
            for (main, &sampled) |column, *value| {
                value.* = QM31.fromBase(column[committed_row]);
            }
            const row_pair = try pair(try Row.fromMain(&sampled), relations);
            denominators[local_row] = row_pair.d1.mul(row_pair.d2);
            numerators[local_row] = row_pair.n1.mul(row_pair.d2)
                .add(row_pair.n2.mul(row_pair.d1));
        }
        try fields.batchInverseInPlace(
            QM31,
            denominators[0..chunk_len],
            inverses[0..chunk_len],
        );
        for (0..chunk_len) |local_row| {
            const logical_row = row_start + local_row;
            result.claim = result.claim.add(numerators[local_row].mul(inverses[local_row]));
            const coordinates = result.claim.toM31Array();
            const committed_row = placement.map(logical_row);
            for (coordinates, &result.columns) |value, column| column[committed_row] = value;
        }
        row_start += chunk_len;
    }

    for (0..size) |logical_row| {
        const current_row = placement.map(logical_row);
        const previous_row = placement.map((logical_row + size - 1) % size);
        for (&result.previous, &result.columns) |previous, current| {
            previous[current_row] = current[previous_row];
        }
    }
    return result;
}

fn memoryTuple(row: Row, clock: QM31) common.Qm31.MemoryAccessTuple {
    return .{
        .addr_space = row.addr_space,
        .addr = row.addr,
        .clock = clock,
        .limbs = row.value,
    };
}

fn validateColumns(columns: []const []const M31, size: usize) !void {
    if (columns.len != N_MAIN_COLUMNS) return error.InvalidColumnCount;
    for (columns) |column| {
        if (column.len != size) return error.InvalidColumnLength;
    }
}

fn q(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}
