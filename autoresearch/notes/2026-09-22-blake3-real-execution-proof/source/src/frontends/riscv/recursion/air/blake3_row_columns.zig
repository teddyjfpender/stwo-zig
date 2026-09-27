//! Canonical row projection and lookup registration for typed BLAKE3 provers.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const binding = @import("universal_relation_binding.zig");
const framework = @import("framework_interaction.zig");
const schema = @import("../../air/lookups/tables/schema.zig");
const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
pub fn padded(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, log: u32) ![]Air.Row {
    const result = try allocator.alloc(Air.Row, @as(usize, 1) << @intCast(log));
    @memset(result, @splat(M31.zero()));
    @memcpy(result[0..rows.len], rows);
    return result;
}
pub fn project(comptime Air: type, allocator: std.mem.Allocator, rows: []const Air.Row, log: u32, comptime tree: usize, columns: *std.ArrayList(Column)) !void {
    return projectChunks(Air, allocator, &.{rows}, log, tree, columns);
}
/// Concatenated logical input view without an intermediate row buffer.
pub fn projectChunks(comptime Air: type, allocator: std.mem.Allocator, chunks: []const []const Air.Row, log: u32, comptime tree: usize, columns: *std.ArrayList(Column)) !void {
    if (log == 0 or log > 24) return error.InvalidTraceShape;
    const size = @as(usize, 1) << @intCast(log);
    var count_rows: usize = 0;
    for (chunks) |rows| {
        if (rows.len > size - count_rows) return error.InvalidTraceShape;
        count_rows += rows.len;
    }
    const original_len = columns.items.len;
    errdefer {
        for (columns.items[original_len..]) |column| allocator.free(column.values);
        columns.shrinkRetainingCapacity(original_len);
    }
    const count = if (tree == 0) Air.PREPROCESSED_COLUMN_COUNT else Air.PHYSICAL_MAIN_COLUMN_COUNT;
    var values: [count][]M31 = undefined;
    for (&values) |*column| {
        column.* = try allocator.alloc(M31, @as(usize, 1) << @intCast(log));
        @memset(column.*, M31.zero());
        columns.append(allocator, .{ .log_size = log, .values = column.* }) catch |err| {
            allocator.free(column.*);
            return err;
        };
    }
    var first: usize = 0;
    for (chunks) |rows| {
        if (rows.len != 0) @import("framework_device_interaction.zig").writeColumnsAt(Air, rows, log, tree, &values, first);
        first += rows.len;
    }
}
pub fn register(comptime Air: type, plan: *const binding.Binding(Air).Plan, rows: []const Air.Row, counters: anytype) !void {
    for (rows) |row| try registerRepeated(Air, plan, row, 1, counters);
}
pub fn columnView(comptime Air: type, columns: []const Column, metadata: []const Air.Row, count: usize, log: u32) !framework.Runtime(binding.Binding(Air).Runtime).ColumnRows {
    if (columns.len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidTraceShape;
    const Runtime = framework.Runtime(binding.Binding(Air).Runtime);
    var view = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = count, .main_count = Air.PHYSICAL_MAIN_COLUMN_COUNT, .metadata = metadata };
    for (view.columns[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], columns) |*destination, column| {
        if (column.log_size != log) return error.InvalidTraceShape;
        destination.* = column.values;
    }
    try view.validate(log);
    return view;
}
pub fn registerColumns(comptime Air: type, plan: *const binding.Binding(Air).Plan, view: framework.Runtime(binding.Binding(Air).Runtime).ColumnRows, log: u32, counters: anytype) !void {
    try view.validate(log);
    for (0..view.count) |index| try registerRepeated(Air, plan, view.read(index, log), 1, counters);
}
/// Repeated identical rows contribute the same tuples with scaled signed weights.
pub fn registerRepeated(comptime Air: type, plan: *const binding.Binding(Air).Plan, row: Air.Row, count: usize, counters: anytype) !void {
    if (count == 0) return;
    const lang = @import("../../air/lang/mod.zig");
    const scale = core.fields.qm31.QM31.fromBase(M31.fromU64(count));
    for (plan.preparedEntries(row)) |entry| {
        const index: usize = if (entry.schema == lang.relation.id(.bitwise)) 0 else if (entry.schema == lang.relation.id(.range_check_8_8)) 1 else continue;
        const target = if (comptime @TypeOf(counters) == *@import("../../air/lookups/tables/counter.zig").Set)
            counters.get(if (index == 0) .bitwise else .range_check_8_8)
        else
            &counters[index];
        try target.registerRaw(entry.numerator.mul(scale), entry.values[0..entry.arity]);
    }
}

pub fn tablePreprocessed(allocator: std.mem.Allocator, kind: schema.Kind, columns: *std.ArrayList(Column)) !void {
    const log = schema.logSize(kind);
    const count = schema.arity(kind) + 1;
    var values: [schema.MAX_ARITY + 1][]M31 = undefined;
    for (values[0..count]) |*column| {
        column.* = try allocator.alloc(M31, schema.size(kind));
        try columns.append(allocator, .{ .log_size = log, .values = column.* });
    }
    for (0..schema.size(kind)) |row| {
        const dst = framework.committedRow(row, log);
        values[0][dst] = if (row == 0) M31.one() else M31.zero();
        const tuple = try schema.tupleAt(kind, row);
        for (tuple.slice(), values[1..count]) |value, column| column[dst] = value;
    }
}
pub fn columnLogs(allocator: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try allocator.alloc(u32, columns.len);
    for (result, columns) |*log, column| log.* = column.log_size;
    return result;
}
