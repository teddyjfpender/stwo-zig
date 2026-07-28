//! Sparse interaction sources for Cairo tables whose lookup tuples are implicit.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const memory_tables = @import("memory_tables.zig");
const fixed_table_bundle = @import("fixed_table_bundle.zig");
const interaction_trace = @import("interaction_trace.zig");
const cpu_memory_multiplicity = @import("cpu_memory_multiplicity.zig");
const multiplicity_tables = @import("../conformance/multiplicity_tables.zig");

pub const BorrowedColumns = struct {
    allocator: std.mem.Allocator,
    columns: [][]const u32,
    zeros: []u32,
    rows: u32,

    pub fn deinit(self: *BorrowedColumns) void {
        self.allocator.free(self.zeros);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn xor12View(self: BorrowedColumns) !interaction_trace.SourceView {
        return interaction_trace.SourceView.bitwiseXor12(
            try interaction_trace.SparseColumns.init(self.columns, self.rows),
            @intCast(self.columns.len),
            self.rows,
        );
    }
};

pub const OwnedColumns = struct {
    allocator: std.mem.Allocator,
    storage: []u32,
    columns: [][]const u32,
    rows: u32,

    pub fn deinit(self: *OwnedColumns) void {
        self.allocator.free(self.columns);
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn addressView(self: OwnedColumns) !interaction_trace.SourceView {
        return interaction_trace.SourceView.memoryAddress(
            try interaction_trace.SparseColumns.init(self.columns, self.rows),
            memory_tables.address_split,
            self.rows,
        );
    }

    pub fn bigView(
        self: OwnedColumns,
        source_offset_rows: u32,
    ) !interaction_trace.SourceView {
        return interaction_trace.SourceView.memoryBig(
            try interaction_trace.SparseColumns.init(self.columns, self.rows),
            memory_tables.big_limb_count,
            self.rows,
            source_offset_rows,
        );
    }

    pub fn smallView(self: OwnedColumns) !interaction_trace.SourceView {
        return interaction_trace.SourceView.memorySmall(
            try interaction_trace.SparseColumns.init(self.columns, self.rows),
            memory_tables.small_limb_count,
            self.rows,
            0,
        );
    }

    fn mutableColumn(self: *OwnedColumns, index: usize) []u32 {
        std.debug.assert(index < self.columns.len);
        const first = index * self.rows;
        return self.storage[first..][0..self.rows];
    }
};

pub fn fixedMultiplicities(
    allocator: std.mem.Allocator,
    entry: fixed_table_bundle.Entry,
    tables: *multiplicity_tables.Tables,
) !BorrowedColumns {
    const columns = try allocator.alloc([]const u32, entry.multiplicity_columns);
    errdefer allocator.free(columns);
    const zeros = try allocator.alloc(u32, entry.row_count);
    errdefer allocator.free(zeros);
    @memset(zeros, 0);
    for (columns, 0..) |*column, index|
        column.* = try tables.column(entry.component, @intCast(index), zeros);
    return .{
        .allocator = allocator,
        .columns = columns,
        .zeros = zeros,
        .rows = entry.row_count,
    };
}

pub fn memoryAddress(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
) !OwnedColumns {
    const rows: u32 = @intCast(try memory_tables.addressRowCount(input));
    var result = try initOwned(
        allocator,
        rows,
        memory_tables.address_column_count,
    );
    errdefer result.deinit();
    for (0..memory_tables.address_split) |chunk| {
        const ids = result.mutableColumn(chunk * 2);
        const multiplicities = result.mutableColumn(chunk * 2 + 1);
        for (0..rows) |row| {
            const flat = chunk * rows + row;
            ids[row] = if (flat < input.memory.address_to_id.len -| 1)
                input.memory.address_to_id[flat + 1].raw
            else
                0;
            multiplicities[row] =
                if (flat < counts.address.len) counts.address[flat] else 0;
        }
    }
    return result;
}

pub fn memoryBig(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
    component: usize,
) !OwnedColumns {
    const rows: u32 = @intCast(try memory_tables.bigRowCount(input, component));
    var result = try initOwned(allocator, rows, memory_tables.big_column_count);
    errdefer result.deinit();
    for (0..memory_tables.big_limb_count) |column|
        try memory_tables.writeBigValueColumn(
            input,
            component,
            column,
            result.mutableColumn(column),
        );
    const offset = std.math.mul(usize, component, memory_tables.max_big_rows) catch
        return error.AllocationSizeOverflow;
    const multiplicities = result.mutableColumn(memory_tables.big_limb_count);
    for (multiplicities, 0..) |*value, row|
        value.* = if (offset + row < counts.big.len) counts.big[offset + row] else 0;
    return result;
}

pub fn memorySmall(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
) !OwnedColumns {
    const rows: u32 = @intCast(try memory_tables.smallRowCount(input));
    var result = try initOwned(allocator, rows, memory_tables.small_column_count);
    errdefer result.deinit();
    for (0..memory_tables.small_limb_count) |column|
        try memory_tables.writeSmallValueColumn(
            input,
            column,
            result.mutableColumn(column),
        );
    const multiplicities = result.mutableColumn(memory_tables.small_limb_count);
    for (multiplicities, 0..) |*value, row|
        value.* = if (row < counts.small.len) counts.small[row] else 0;
    return result;
}

fn initOwned(
    allocator: std.mem.Allocator,
    rows: u32,
    column_count: usize,
) !OwnedColumns {
    const value_count = std.math.mul(usize, rows, column_count) catch
        return error.AllocationSizeOverflow;
    const storage = try allocator.alloc(u32, value_count);
    errdefer allocator.free(storage);
    const columns = try allocator.alloc([]const u32, column_count);
    errdefer allocator.free(columns);
    for (columns, 0..) |*column, index|
        column.* = storage[index * rows ..][0..rows];
    return .{
        .allocator = allocator,
        .storage = storage,
        .columns = columns,
        .rows = rows,
    };
}
