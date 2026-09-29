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
    var destinations: [memory_tables.address_column_count][]u32 = undefined;
    for (&destinations, 0..) |*destination, index| destination.* = result.mutableColumn(index);
    try memoryAddressInto(input, counts, &destinations);
    return result;
}

/// Fill disjoint final columns in the canonical interaction source order.
/// The caller retains all storage, including on validation failure.
pub fn memoryAddressInto(
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
    columns: []const []u32,
) !void {
    const rows = try memory_tables.addressRowCount(input);
    try validateDestinations(columns, memory_tables.address_column_count, rows);
    try fillColumns(.address, input, counts, 0, columns, rows);
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
    var destinations: [memory_tables.big_column_count][]u32 = undefined;
    for (&destinations, 0..) |*destination, index| destination.* = result.mutableColumn(index);
    try memoryBigInto(input, counts, component, &destinations);
    return result;
}

pub fn memoryBigInto(
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
    component: usize,
    columns: []const []u32,
) !void {
    try validateDestinations(columns, memory_tables.big_column_count, try memory_tables.bigRowCount(input, component));
    try fillColumns(.big, input, counts, component, columns, columns[0].len);
}

pub fn memorySmall(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
) !OwnedColumns {
    const rows: u32 = @intCast(try memory_tables.smallRowCount(input));
    var result = try initOwned(allocator, rows, memory_tables.small_column_count);
    errdefer result.deinit();
    var destinations: [memory_tables.small_column_count][]u32 = undefined;
    for (&destinations, 0..) |*destination, index| destination.* = result.mutableColumn(index);
    try memorySmallInto(input, counts, &destinations);
    return result;
}

pub fn memorySmallInto(
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
    columns: []const []u32,
) !void {
    try validateDestinations(columns, memory_tables.small_column_count, try memory_tables.smallRowCount(input));
    try fillColumns(.small, input, counts, 0, columns, columns[0].len);
}

const Table = enum { address, big, small };

/// Writers own disjoint columns. Parallelism adds only stack job descriptors,
/// never another table slab or private multiplicity histogram.
fn fillColumns(
    table: Table,
    input: *const adapter.ProverInput,
    counts: *const cpu_memory_multiplicity.Counts,
    component: usize,
    columns: []const []u32,
    rows: usize,
) !void {
    const split = @import("pool_split.zig");
    const units = if (table == .address) memory_tables.address_split else columns.len;
    const workers = @min(@min(units, 8), split.workerCount(.{ .rows = rows * units, .min_rows_per_worker = 1 << 17 }));
    const Work = struct {
        table: Table,
        input: *const adapter.ProverInput,
        counts: *const cpu_memory_multiplicity.Counts,
        component: usize,
        columns: []const []u32,
        rows: usize,
        range: split.Span,
        failure: ?anyerror = null,

        pub fn run(self: *@This()) void {
            self.fill() catch |err| {
                self.failure = err;
            };
        }

        fn fill(self: *@This()) !void {
            for (self.range.start..self.range.end) |index| switch (self.table) {
                .address => {
                    const ids = self.columns[index * 2];
                    const multiplicities = self.columns[index * 2 + 1];
                    for (ids, multiplicities, 0..) |*id, *count, row| {
                        const flat = index * self.rows + row;
                        id.* = if (flat < self.input.memory.address_to_id.len -| 1)
                            self.input.memory.address_to_id[flat + 1].raw
                        else
                            0;
                        count.* = if (flat < self.counts.address.len) self.counts.address[flat] else 0;
                    }
                },
                .big => {
                    if (index < memory_tables.big_limb_count) {
                        try memory_tables.writeBigValueColumn(self.input, self.component, index, self.columns[index]);
                    } else {
                        const offset = std.math.mul(usize, self.component, memory_tables.max_big_rows) catch return error.AllocationSizeOverflow;
                        for (self.columns[index], 0..) |*count, row|
                            count.* = if (offset + row < self.counts.big.len) self.counts.big[offset + row] else 0;
                    }
                },
                .small => {
                    if (index < memory_tables.small_limb_count) {
                        try memory_tables.writeSmallValueColumn(self.input, index, self.columns[index]);
                    } else {
                        for (self.columns[index], 0..) |*count, row|
                            count.* = if (row < self.counts.small.len) self.counts.small[row] else 0;
                    }
                },
            };
        }
    };
    var jobs: [8]Work = undefined;
    for (jobs[0..workers], 0..) |*job, index| job.* = .{
        .table = table,
        .input = input,
        .counts = counts,
        .component = component,
        .columns = columns,
        .rows = rows,
        .range = split.span(units, index, workers),
    };
    try split.dispatch(Work, jobs[0..workers]);
}

fn validateDestinations(columns: []const []u32, width: usize, rows: usize) !void {
    if (columns.len != width) return error.InvalidBaseTraceGeometry;
    for (columns) |column| if (column.len != rows) return error.InvalidBaseTraceGeometry;
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

fn testFinalTables(allocator: std.mem.Allocator) !void {
    const mem = @import("../common/memory.zig");
    var ids: [18]mem.EncodedMemoryValueId = undefined;
    for (&ids, 0..) |*id, index| id.* = mem.EncodedMemoryValueId.small(@intCast(index));
    var big: [17]mem.F252 = undefined;
    for (&big, 0..) |*value, index| {
        value.* = [_]u32{0} ** 8;
        value[0] = @intCast(index * 1027);
        value[7] = 0x08000000;
    }
    var small: [17]u128 = undefined;
    for (&small, 0..) |*value, index| value.* = (@as(u128, 1) << 65) + index * 513;
    var input: adapter.ProverInput = undefined;
    input.memory = .{ .config = .{}, .address_to_id = &ids, .f252_values = &big, .small_values = &small };
    var address_counts = [_]u32{13} ** 17;
    var big_counts = [_]u32{19} ** 17;
    var small_counts = [_]u32{23} ** 17;
    const counts = cpu_memory_multiplicity.Counts{ .allocator = allocator, .address = &address_counts, .big = &big_counts, .small = &small_counts };
    // A column slab with guards catches writes past padded domains. Expected
    // limbs are extracted independently from the raw 252-bit input.
    const rows: usize = 32;
    const width = memory_tables.big_column_count;
    const slab = try allocator.alloc(u32, width * (rows + 2));
    defer allocator.free(slab);
    @memset(slab, 0xdeadbeef);
    var natural: [width][]u32 = undefined;
    for (&natural, 0..) |*column, index| column.* = slab[index * (rows + 2) + 1 ..][0..rows];
    try memoryBigInto(&input, &counts, 0, &natural);
    for (0..width) |column| {
        try std.testing.expectEqual(@as(u32, 0xdeadbeef), slab[column * (rows + 2)]);
        try std.testing.expectEqual(@as(u32, 0xdeadbeef), slab[(column + 1) * (rows + 2) - 1]);
        for (natural[column], 0..) |value, row| {
            const expected: u32 = if (row >= big.len) 0 else if (column == memory_tables.big_limb_count)
                19
            else blk: {
                const shift: u8 = @intCast(column * 9);
                var raw: u256 = 0;
                for (big[row], 0..) |word, limb| raw |= @as(u256, word) << @as(u8, @intCast(limb * 32));
                break :blk @intCast((raw >> shift) & 511);
            };
            try std.testing.expectEqual(expected, value);
        }
    }
    var address_slab: [memory_tables.address_column_count][16]u32 = undefined;
    var address_columns: [memory_tables.address_column_count][]u32 = undefined;
    for (&address_slab, &address_columns) |*values, *column| column.* = values;
    try memoryAddressInto(&input, &counts, &address_columns);
    for (0..memory_tables.address_split) |chunk| for (0..16) |row| {
        const flat = chunk * 16 + row;
        try std.testing.expectEqual(if (flat < 17) @as(u32, @intCast(flat + 1)) else 0, address_columns[chunk * 2][row]);
        try std.testing.expectEqual(if (flat < 17) @as(u32, 13) else 0, address_columns[chunk * 2 + 1][row]);
    };
    try memorySmallInto(&input, &counts, natural[0..memory_tables.small_column_count]);
    for (natural[0..memory_tables.small_column_count], 0..) |column, index| for (column, 0..) |value, row| {
        const expected: u32 = if (row >= small.len) 0 else if (index == memory_tables.small_limb_count)
            23
        else
            @intCast((small[row] >> @as(u7, @intCast(index * 9))) & 511);
        try std.testing.expectEqual(expected, value);
    };
    try std.testing.expectError(error.InvalidBaseTraceGeometry, memoryBigInto(&input, &counts, 0, natural[0 .. width - 1]));
    var malformed = natural;
    malformed[0] = malformed[0][0..31];
    try std.testing.expectError(error.InvalidBaseTraceGeometry, memoryBigInto(&input, &counts, 0, &malformed));
    // Component 1 is `opt_n_id_to_big_components` padding, one 16-row zero
    // block, which these 32-row columns do not fit; past the enable slots
    // there is no component at all.
    try std.testing.expectError(error.InvalidBaseTraceGeometry, memoryBigInto(&input, &counts, 1, &natural));
    try std.testing.expectError(error.InvalidComponent, memoryBigInto(&input, &counts, memory_tables.max_big_components, &natural));
    small[0] = @as(u128, 1) << 72;
    try std.testing.expectError(error.InvalidEncoding, memorySmallInto(&input, &counts, natural[0..memory_tables.small_column_count]));
}

test "Cairo witness final storage implicit tables preserve independent row formulas and guarded padding" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testFinalTables, .{});
}

test "Cairo witness final storage implicit parallel writes agree with independent limbs" {
    const prover = @import("stwo_prover_engine");
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const a = std.testing.allocator;
    const values = try a.alloc(u128, 1 << 17);
    defer a.free(values);
    for (values, 0..) |*value, row| value.* = (@as(u128, 1) << 65) + row * 513;
    var input: adapter.ProverInput = undefined;
    input.memory = .{ .config = .{}, .address_to_id = &.{}, .f252_values = &.{}, .small_values = values };
    const counts = cpu_memory_multiplicity.Counts{ .allocator = a, .address = &.{}, .big = &.{}, .small = &.{} };
    var output = try initOwned(a, @intCast(values.len), memory_tables.small_column_count);
    defer output.deinit();
    var destinations: [memory_tables.small_column_count][]u32 = undefined;
    for (&destinations, 0..) |*destination, index| destination.* = output.mutableColumn(index);
    try memorySmallInto(&input, &counts, &destinations);
    for (destinations, 0..) |column, index| for (column, 0..) |value, row| {
        const expected: u32 = if (index == memory_tables.small_limb_count) 0 else @intCast((values[row] >> @as(u7, @intCast(index * 9))) & 511);
        try std.testing.expectEqual(expected, value);
    };
}
