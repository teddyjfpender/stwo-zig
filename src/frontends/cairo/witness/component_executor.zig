//! Backend-neutral execution of one recorded Cairo witness component.

const std = @import("std");
const adapter = @import("../adapter/mod.zig");
const component_layout = @import("component_layout.zig");
const deductions = @import("deductions/mod.zig");
const execution_tables = @import("execution_tables.zig");
const program_mod = @import("program.zig");

pub const Error = error{
    AllocationSizeOverflow,
    InvalidReceiptGeometry,
    UnsupportedMultiplicityTable,
    WitnessInputCountMismatch,
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
};

pub fn execute(
    allocator: std.mem.Allocator,
    input: *const adapter.ProverInput,
    witness_program: program_mod.Program,
    source: anytype,
    layout: component_layout.ComponentLayout,
) !Execution {
    layout.validate() catch return Error.InvalidReceiptGeometry;
    if (witness_program.n_inputs != source.columnCount())
        return Error.WitnessInputCountMismatch;
    if (witness_program.n_cols != layout.column_count)
        return Error.InvalidReceiptGeometry;
    if (witness_program.n_mult_tables != 0)
        return Error.UnsupportedMultiplicityTable;
    const row_count = layout.row_count;
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
