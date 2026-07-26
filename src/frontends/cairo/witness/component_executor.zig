//! Backend-neutral execution of one recorded Cairo witness component.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const checkpoint = @import("../conformance/checkpoint.zig");
const deductions = @import("deductions/mod.zig");
const execution_tables = @import("execution_tables.zig");
const program_mod = @import("program.zig");

pub const Error = error{
    AllocationSizeOverflow,
    InvalidReceiptGeometry,
    UnsupportedMultiplicityTable,
    WitnessInputCountMismatch,
};

pub const MismatchKind = enum {
    column_count,
    column_digest,
};

pub const Mismatch = struct {
    kind: MismatchKind,
    component_ordinal: u32,
    component_label: []const u8,
    column_ordinal: ?u32 = null,
    expected_count: ?u64 = null,
    actual_count: ?u64 = null,
    expected_digest: ?checkpoint.Digest = null,
    actual_digest: ?checkpoint.Digest = null,
};

pub const Execution = struct {
    allocator: std.mem.Allocator,
    row_count: usize,
    output_storage: []u32,
    output_columns: [][]u32,
    lookup_words: []u32,
    sub_words: []u32,

    pub fn deinit(self: *Execution) void {
        self.allocator.free(self.sub_words);
        self.allocator.free(self.lookup_words);
        self.allocator.free(self.output_columns);
        self.allocator.free(self.output_storage);
        self.* = undefined;
    }

    pub fn compare(self: Execution, expected: checkpoint.Component) !?Mismatch {
        if (expected.columns.len != self.output_columns.len) return .{
            .kind = .column_count,
            .component_ordinal = expected.ordinal,
            .component_label = expected.label,
            .expected_count = expected.columns.len,
            .actual_count = self.output_columns.len,
        };
        for (expected.columns, self.output_columns) |expected_column, values| {
            const actual_digest = try checkpoint.digestColumn(
                expected.ordinal,
                expected.label,
                expected_column.ordinal,
                values,
            );
            if (!std.mem.eql(u8, &expected_column.sha256, &actual_digest)) return .{
                .kind = .column_digest,
                .component_ordinal = expected.ordinal,
                .component_label = expected.label,
                .column_ordinal = expected_column.ordinal,
                .expected_digest = expected_column.sha256,
                .actual_digest = actual_digest,
            };
        }
        return null;
    }
};

pub fn execute(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program_mod.Program,
    source: anytype,
    expected: checkpoint.Component,
) !Execution {
    if (witness_program.n_inputs != source.columnCount())
        return Error.WitnessInputCountMismatch;
    if (witness_program.n_mult_tables != 0)
        return Error.UnsupportedMultiplicityTable;
    const row_count = try validateGeometry(expected);
    source.validateRowCount(row_count) catch return Error.InvalidReceiptGeometry;

    const input_words = std.math.mul(usize, source.columnCount(), row_count) catch
        return Error.AllocationSizeOverflow;
    const output_words = std.math.mul(usize, witness_program.n_cols, row_count) catch
        return Error.AllocationSizeOverflow;
    const lookup_words = std.math.mul(usize, witness_program.n_lookup_words, row_count) catch
        return Error.AllocationSizeOverflow;
    const sub_words = std.math.mul(usize, witness_program.n_sub_words, row_count) catch
        return Error.AllocationSizeOverflow;

    const input_storage = try allocator.alloc(u32, input_words);
    defer allocator.free(input_storage);
    const input_columns = try allocator.alloc([]const u32, source.columnCount());
    defer allocator.free(input_columns);
    for (input_columns, 0..) |*column, column_index| {
        const start = column_index * row_count;
        const values = input_storage[start .. start + row_count];
        try source.writeColumn(column_index, values);
        column.* = values;
    }

    var result = Execution{
        .allocator = allocator,
        .row_count = row_count,
        .output_storage = try allocator.alloc(u32, output_words),
        .output_columns = &.{},
        .lookup_words = &.{},
        .sub_words = &.{},
    };
    errdefer allocator.free(result.output_storage);
    result.output_columns = try allocator.alloc([]u32, witness_program.n_cols);
    errdefer allocator.free(result.output_columns);
    for (result.output_columns, 0..) |*column, column_index| {
        const start = column_index * row_count;
        column.* = result.output_storage[start .. start + row_count];
    }
    result.lookup_words = try allocator.alloc(u32, lookup_words);
    errdefer allocator.free(result.lookup_words);
    result.sub_words = try allocator.alloc(u32, sub_words);
    errdefer allocator.free(result.sub_words);

    const registers = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(registers);
    const deduce_args = try allocator.alloc(u32, witness_program.n_regs);
    defer allocator.free(deduce_args);
    const no_multiplicity_tables = [_][]u32{};
    try program_mod.executeAll(
        witness_program,
        input_columns,
        result.output_columns,
        .{
            .lookup_words = result.lookup_words,
            .sub_words = result.sub_words,
            .multiplicity_tables = &no_multiplicity_tables,
        },
        registers,
        deduce_args,
        execution_tables.fromInput(input),
        deductions.context(),
    );
    return result;
}

fn validateGeometry(expected: checkpoint.Component) Error!usize {
    if (expected.columns.len == 0) return Error.InvalidReceiptGeometry;
    const row_count = std.math.cast(usize, expected.columns[0].row_count) orelse
        return Error.InvalidReceiptGeometry;
    for (expected.columns, 0..) |column, column_index| {
        if (column.ordinal != column_index or column.row_count != row_count)
            return Error.InvalidReceiptGeometry;
    }
    return row_count;
}
