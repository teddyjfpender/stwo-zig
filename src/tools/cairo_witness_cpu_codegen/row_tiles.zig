//! Bounded row-local storage for wide native witness programs.
//! Gather and publication traverse each used SoA column contiguously; deductions
//! retain their original order and ABI. Only written channels are published.
const std = @import("std");
const model = @import("model.zig");

pub const Plan = struct {
    inputs: usize,
    outputs: usize,
    lookups: usize,

    pub fn init(program: model.Program) ?Plan {
        if (@as(u64, program.n_cols) + program.n_lookup_words < 64 and program.n_inputs < 16) return null;
        return .{
            .inputs = padded(program.n_inputs),
            .outputs = padded(program.n_cols),
            .lookups = padded(program.n_lookup_words),
        };
    }

    // An odd count of 128-byte blocks avoids power-of-two row strides. Empty
    // channel families retain a valid C array extent but are never accessed.
    fn padded(words: usize) usize {
        if (words == 0) return 1;
        return (((words + 31) / 32) | 1) * 32;
    }

    pub fn wordsPerRow(self: Plan) usize {
        return self.inputs + self.outputs + self.lookups;
    }

    pub fn declarations(self: Plan, writer: *std.Io.Writer, rows: usize) !void {
        try writer.print("        uint32_t input_tile[{}][{}];\n" ++
            "        uint32_t output_tile[{}][{}];\n" ++
            "        uint32_t lookup_tile[{}][{}];\n", .{ rows, self.inputs, rows, self.outputs, rows, self.lookups });
    }

    pub fn gather(_: Plan, writer: *std.Io.Writer, program: model.Program) !void {
        try emitChannels(writer, program, .input, program.n_inputs);
    }

    pub fn flush(_: Plan, writer: *std.Io.Writer, program: model.Program) !void {
        try emitChannels(writer, program, .col_write, program.n_cols);
        try emitChannels(writer, program, .lookup_word, program.n_lookup_words);
    }
};

fn emitChannels(writer: *std.Io.Writer, program: model.Program, op: model.Op, count: usize) !void {
    const used = try std.heap.page_allocator.alloc(bool, count);
    defer std.heap.page_allocator.free(used);
    @memset(used, false);
    for (program.insts) |inst| {
        if (inst.op != op) continue;
        const index = if (op == .input) inst.a else inst.imm;
        if (index >= used.len) return error.InvalidTileColumn;
        used[index] = true;
    }
    for (used, 0..) |present, index| {
        if (!present) continue;
        try writer.writeAll("        for (size_t lane = 0; lane < count; ++lane)\n");
        switch (op) {
            .input => try writer.print("            input_tile[lane][{}] = run->input_columns[{}].ptr[base + lane];\n", .{ index, index }),
            .col_write => try writer.print("            run->output_columns[{}].ptr[base + lane] = output_tile[lane][{}];\n", .{ index, index }),
            .lookup_word => try writer.print("            run->lookup_words[{} * run->row_count + base + lane] = lookup_tile[lane][{}];\n", .{ index, index }),
            else => unreachable,
        }
    }
}
