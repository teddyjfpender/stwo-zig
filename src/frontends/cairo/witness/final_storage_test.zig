//! Ownership and failure coverage for direct final-column witness writes.
const std = @import("std");
const executor = @import("component_executor.zig");
const program = @import("program.zig");
const adapter = @import("../adapter/mod.zig");
const lowering = @import("column_lowering.zig");
const M31 = @import("stwo_core").fields.m31.M31;

const Source = struct {
    pub fn columnCount(_: @This()) usize {
        return 0;
    }
    pub fn validateRowCount(_: @This(), rows: usize) !void {
        if (rows != 16) return error.BadRows;
    }
    pub fn writeColumn(_: @This(), _: usize, _: []u32) !void {
        return error.UnexpectedInput;
    }
};
const instructions = [_]program.Inst{
    .{ .op = @intFromEnum(program.Op.constant), .dst = 0, .a = 0, .b = 0, .imm = 123 },
    .{ .op = @intFromEnum(program.Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    .{ .op = @intFromEnum(program.Op.lookup_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    .{ .op = @intFromEnum(program.Op.sub_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
};
const fixture = program.Program{ .insts = &instructions, .n_regs = 1, .n_inputs = 0, .n_cols = 2, .n_mult_tables = 0, .n_lookup_words = 1, .n_sub_words = 1 };
const layout = @import("component_layout.zig").ComponentLayout{ .ordinal = 0, .label = "storage-test", .row_count = 16, .column_count = 2 };

fn ownershipCase(allocator: std.mem.Allocator) !void {
    var input = std.mem.zeroes(adapter.ProverInput);
    var words = [_]u32{0xfeed} ** 40;
    const columns = [_][]u32{ words[4..20], words[20..36] };
    var result = try executor.executeInto(allocator, &input, fixture, null, null, 1, Source{}, layout, null, null, &columns);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.output_storage.len);
    try std.testing.expect(result.output_columns[0].ptr == columns[0].ptr);
    for (result.output_columns[0]) |word| try std.testing.expectEqual(@as(u32, 123), word);
    for (result.output_columns[1]) |word| try std.testing.expectEqual(@as(u32, 0), word);
    for (result.lookup_words) |word| try std.testing.expectEqual(@as(u32, 123), word);
    for (result.sub_words) |word| try std.testing.expectEqual(@as(u32, 123), word);
    for (words[0..4]) |word| try std.testing.expectEqual(@as(u32, 0xfeed), word);
    for (words[36..]) |word| try std.testing.expectEqual(@as(u32, 0xfeed), word);
}

test "Cairo witness final storage retains borrowed columns through all allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ownershipCase, .{});
}

test "Cairo witness final storage validates all destinations before writing" {
    var input = std.mem.zeroes(adapter.ProverInput);
    var words = [_]u32{0xfeed} ** 32;
    const wrong_width = [_][]u32{words[0..16]};
    const wrong_rows = [_][]u32{ words[0..16], words[16..31] };
    try std.testing.expectError(error.InvalidReceiptGeometry, executor.executeInto(std.testing.allocator, &input, fixture, null, null, 1, Source{}, layout, null, null, &wrong_width));
    try std.testing.expectError(error.InvalidReceiptGeometry, executor.executeInto(std.testing.allocator, &input, fixture, null, null, 1, Source{}, layout, null, null, &wrong_rows));
    for (words) |word| try std.testing.expectEqual(@as(u32, 0xfeed), word);
}

test "Cairo witness final storage matches owned outputs and accepts final-column lowering" {
    var input = std.mem.zeroes(adapter.ProverInput);
    var values: [32]M31 = undefined;
    const raw: [*]u32 = @ptrCast(&values);
    const columns = [_][]u32{ raw[0..16], raw[16..32] };
    var borrowed = try executor.executeInto(std.testing.allocator, &input, fixture, null, null, 1, Source{}, layout, null, null, &columns);
    defer borrowed.deinit();
    var owned = try executor.execute(std.testing.allocator, &input, fixture, null, null, 1, Source{}, layout, null, null);
    defer owned.deinit();
    for (borrowed.output_columns, owned.output_columns) |a, b| try std.testing.expectEqualSlices(u32, b, a);
    const sources = [_][]const u32{ columns[0], columns[1] };
    const outputs = [_][]M31{ values[0..16], values[16..32] };
    try lowering.lower(&sources, &outputs, false);
    for (values[0..16]) |value| try std.testing.expectEqual(@as(u32, 123), value.v);
    for (values[16..]) |value| try std.testing.expectEqual(@as(u32, 0), value.v);
}

const BorrowedSource = struct {
    values: []const u32,
    pub fn columnCount(_: @This()) usize {
        return 1;
    }
    pub fn validateRowCount(self: @This(), rows: usize) !void {
        if (self.values.len != rows) return error.BadRows;
    }
    pub fn borrowColumn(self: @This(), column: usize) ![]const u32 {
        if (column != 0) return error.BadColumn;
        return self.values;
    }
    pub fn writeColumn(_: @This(), _: usize, _: []u32) !void {
        return error.UnexpectedCopy;
    }
};

fn borrowedInputCase(allocator: std.mem.Allocator) !void {
    var input = std.mem.zeroes(adapter.ProverInput);
    var source_words: [16]u32 = undefined;
    for (&source_words, 0..) |*word, i| word.* = @intCast(i * 3 + 1);
    const insts = [_]program.Inst{
        .{ .op = @intFromEnum(program.Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        instructions[1],
        instructions[2],
        instructions[3],
    };
    var borrowed_program = fixture;
    borrowed_program.n_inputs = 1;
    borrowed_program.insts = &insts;
    var output: [32]u32 = undefined;
    const columns = [_][]u32{ output[0..16], output[16..32] };
    var result = try executor.executeInto(allocator, &input, borrowed_program, null, null, 1, BorrowedSource{ .values = &source_words }, layout, null, null, &columns);
    defer result.deinit();
    try std.testing.expectEqualSlices(u32, &source_words, columns[0]);
    for (source_words, 0..) |word, i| try std.testing.expectEqual(@as(u32, @intCast(i * 3 + 1)), word);
}

test "Cairo witness final storage borrows immutable source columns across allocation failures" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, borrowedInputCase, .{});
    const gathered = @import("gathered_inputs.zig");
    var words = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const source = gathered.GatheredInput{ .allocator = std.testing.allocator, .storage = &words, .rows = 3, .columns = 2, .active_rows = 3 };
    try std.testing.expect((try source.borrowColumn(1)).ptr == words[3..].ptr);
    try std.testing.expectEqualSlices(u32, &.{ 4, 5, 6 }, try source.borrowColumn(1));
    try std.testing.expectError(error.InvalidEdge, source.borrowColumn(2));
    var invalid = source;
    invalid.storage = words[0..5];
    try std.testing.expectError(error.InvalidRowCount, invalid.borrowColumn(1));
}
