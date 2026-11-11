//! Straight-line C writer emission for one authenticated witness program.

const std = @import("std");
const model = @import("model.zig");
const register_plan = @import("register_plan.zig");
const row_tiles = @import("row_tiles.zig");

pub fn emit(
    writer: *std.Io.Writer,
    authenticated_program: model.Program,
) !void {
    const digest = authenticated_program.semanticIdentity();
    const owned = try register_plan.compact(std.heap.page_allocator, authenticated_program);
    defer owned.deinit();
    const witness_program = owned.program;
    const symbol = std.mem.readInt(u64, digest[0..8], .little);
    try writePreamble(writer);
    try writer.print(
        \\int cairo_witness_{x}(const native_range_execution *run) {{
        \\
    , .{symbol});
    if (batchPlan(witness_program)) |plan| {
        try writer.print("    uint32_t batch_registers[{}][{}];\n    uint32_t batch_args[{}][{}];\n" ++
            "    for (size_t base = run->start; base < run->end;) {{\n" ++
            "        const size_t count = run->end - base < {} ? run->end - base : {};\n", .{ plan.rows, witness_program.n_regs, plan.rows, plan.args, plan.rows, plan.rows });
        if (plan.tiles) |tiles| {
            try tiles.declarations(writer, plan.rows);
            try tiles.gather(writer, witness_program);
        }
        var phase_start: usize = 0;
        var pending: usize = 0;
        for (witness_program.insts, 0..) |inst, index| {
            if (inst.op == .deduce_arg) pending += 1;
            if (inst.op != .deduce_call) continue;
            if (batchable(inst, pending)) {
                try emitTileRows(writer, witness_program, witness_program.insts[phase_start..index], false, plan.tiles != null);
                try writer.print("        if (run->deduce_batch_fn(run->bridge_context, {}, &batch_args[0][0], {}, {}, &batch_registers[0][{}], {}, {}, count) != 0) return 1;\n", .{ inst.imm, pending, plan.args, inst.dst, inst.b, witness_program.n_regs });
                phase_start = index + 1;
            }
            pending = 0;
        }
        try emitTileRows(writer, witness_program, witness_program.insts[phase_start..], true, plan.tiles != null);
        if (plan.tiles) |tiles| try tiles.flush(writer, witness_program);
        try writer.writeAll("        base += count;\n    }\n");
    } else {
        try writer.writeAll(
            \\    uint32_t *restrict registers = run->registers;
            \\    uint32_t *restrict deduce_args = run->deduce_args;
            \\    for (size_t row = run->start; row < run->end; ++row) {
            \\
        );
        try emitInstructions(writer, witness_program, witness_program.insts, true, false);
        try writer.writeAll("    }\n");
    }
    try writer.writeAll("    return 0;\n}\n");
}

const BatchPlan = struct { args: usize, rows: usize, tiles: ?row_tiles.Plan = null };

fn batchable(inst: model.Inst, args: usize) bool {
    const selector = std.meta.intToEnum(model.DeduceKind, inst.imm) catch return false;
    const shape = selector.shape();
    return selector.benefitsFromBatch() and args == shape.args and inst.b == shape.outputs;
}

fn batchPlan(witness_program: model.Program) ?BatchPlan {
    var arguments: usize = 0;
    var max_arguments: usize = 0;
    var eligible = false;
    for (witness_program.insts) |inst| {
        if (inst.op == .deduce_arg) arguments += 1;
        if (inst.op == .deduce_call) {
            eligible = eligible or batchable(inst, arguments);
            max_arguments = @max(max_arguments, arguments);
            arguments = 0;
        }
    }
    max_arguments = @max(1, max_arguments);
    if (row_tiles.Plan.init(witness_program)) |tiles| {
        const words = @as(usize, witness_program.n_regs) + max_arguments + tiles.wordsPerRow();
        const rows = @min(32, model.deduction_contract.batch_scratch_bytes / @sizeOf(u32) / words);
        if (rows >= 2) return .{ .args = max_arguments, .rows = rows, .tiles = tiles };
    }
    if (!eligible) return null;
    const words_per_row = @as(usize, witness_program.n_regs) + max_arguments;
    const rows = @min(model.deduction_contract.max_batch_rows, model.deduction_contract.batch_scratch_bytes / @sizeOf(u32) / words_per_row);
    if (rows < 2) return null;
    return .{ .args = max_arguments, .rows = rows };
}

fn emitTileRows(writer: *std.Io.Writer, witness_program: model.Program, insts: []const model.Inst, complete: bool, tiled: bool) !void {
    if (insts.len == 0) return;
    try writer.writeAll("        for (size_t lane = 0; lane < count; ++lane) {\n" ++
        "            const size_t row = base + lane;\n" ++
        "            uint32_t *restrict registers = batch_registers[lane];\n" ++
        "            uint32_t *restrict deduce_args = batch_args[lane];\n");
    if (tiled) try emitInstructions(writer, witness_program, insts, complete, true) else try emitInstructions(writer, witness_program, insts, complete, false);
    try writer.writeAll("        }\n");
}

fn emitInstructions(writer: *std.Io.Writer, witness_program: model.Program, insts: []const model.Inst, complete: bool, comptime tiled: bool) !void {
    var pending_arguments: usize = 0;
    for (insts) |inst| {
        switch (inst.op) {
            .col_write => try writer.print(
                if (tiled) "        output_tile[lane][{}] = registers[{}];\n" else "        run->output_columns[{}].ptr[row] = registers[{}];\n",
                .{ inst.imm, inst.a },
            ),
            .lookup_word => try writer.print(
                if (tiled) "        lookup_tile[lane][{}] = registers[{}];\n" else "        run->lookup_words[{} * run->row_count + row] = registers[{}];\n",
                .{ inst.imm, inst.a },
            ),
            .sub_word => try writer.print(
                "        run->sub_words[row * {} + {}] = registers[{}];\n",
                .{ witness_program.n_sub_words, inst.imm, inst.a },
            ),
            .mult_push => return error.UnsupportedMultiplicityTable,
            .deduce_arg => {
                try writer.print(
                    "        deduce_args[{}] = registers[{}];\n",
                    .{ pending_arguments, inst.a },
                );
                pending_arguments += 1;
            },
            .deduce_call => {
                if (pending_arguments == 0) return error.InvalidDeduce;
                try writer.print(
                    "        if (run->deduce_fn(run->bridge_context, {}, deduce_args, {}, &registers[{}], {}) != 0) return 1;\n",
                    .{
                        inst.imm,
                        pending_arguments,
                        inst.dst,
                        inst.b,
                    },
                );
                pending_arguments = 0;
            },
            else => {
                try writer.print("        registers[{}] = ", .{inst.dst});
                try emitValue(writer, inst, tiled);
                try writer.writeAll(";\n");
            },
        }
    }
    if (complete and pending_arguments != 0) return error.InvalidDeduce;
}

fn writePreamble(writer: *std.Io.Writer) !void {
    try writer.writeAll(
        \\#include <stddef.h>
        \\#include <stdint.h>
        \\
        \\typedef struct {
        \\    const uint32_t *ptr;
        \\    size_t len;
        \\} const_column_view;
        \\
        \\typedef struct {
        \\    uint32_t *ptr;
        \\    size_t len;
        \\} column_view;
        \\
        \\typedef struct native_range_execution {
        \\    const const_column_view *input_columns;
        \\    const column_view *output_columns;
        \\    uint32_t *lookup_words;
        \\    uint32_t *sub_words;
        \\    uint32_t *registers;
        \\    uint32_t *deduce_args;
        \\    size_t row_count;
        \\    size_t start;
        \\    size_t end;
        \\    void *bridge_context;
        \\    uint32_t (*table_limb_fn)(void *, uint32_t, uint32_t, uint32_t);
        \\    int (*deduce_fn)(
        \\        void *,
        \\        uint32_t,
        \\        const uint32_t *,
        \\        size_t,
        \\        uint32_t *,
        \\        size_t
        \\    );
        \\    int (*deduce_batch_fn)(void *, uint32_t, const uint32_t *, size_t,
        \\        size_t, uint32_t *, size_t, size_t, size_t);
        \\} native_range_execution;
        \\
        \\static inline uint32_t m31_add(uint32_t a, uint32_t b) {
        \\    const uint32_t sum = a + b;
        \\    return sum >= UINT32_C(0x7fffffff)
        \\        ? sum - UINT32_C(0x7fffffff)
        \\        : sum;
        \\}
        \\
        \\static inline uint32_t m31_sub(uint32_t a, uint32_t b) {
        \\    return a >= b ? a - b : (a + UINT32_C(0x7fffffff)) - b;
        \\}
        \\
        \\static inline uint32_t m31_mul(uint32_t a, uint32_t b) {
        \\    const uint64_t product = (uint64_t)a * (uint64_t)b;
        \\    const uint64_t folded =
        \\        (product & UINT64_C(0x7fffffff)) + (product >> 31);
        \\    const uint32_t value = (uint32_t)folded;
        \\    return value >= UINT32_C(0x7fffffff)
        \\        ? value - UINT32_C(0x7fffffff)
        \\        : value;
        \\}
        \\
        \\static inline uint32_t m31_neg(uint32_t value) {
        \\    return value == 0 ? 0 : UINT32_C(0x7fffffff) - value;
        \\}
        \\
        \\static inline uint32_t m31_inverse(uint32_t value) {
        \\    if (value == 0) return 0;
        \\    uint32_t base = value;
        \\    uint32_t exponent = UINT32_C(0x7ffffffd);
        \\    uint32_t result = 1;
        \\    while (exponent != 0) {
        \\        if ((exponent & 1) != 0) result = m31_mul(result, base);
        \\        base = m31_mul(base, base);
        \\        exponent >>= 1;
        \\    }
        \\    return result;
        \\}
        \\
    );
}

fn emitValue(writer: *std.Io.Writer, inst: model.Inst, comptime tiled: bool) !void {
    switch (inst.op) {
        .input => try writer.print(
            if (tiled) "input_tile[lane][{}]" else "run->input_columns[{}].ptr[row]",
            .{inst.a},
        ),
        .constant => try writer.print("UINT32_C({})", .{inst.imm}),
        .m31_add => try writer.print(
            "m31_add(registers[{}], registers[{}])",
            .{ inst.a, inst.b },
        ),
        .m31_sub => try writer.print(
            "m31_sub(registers[{}], registers[{}])",
            .{ inst.a, inst.b },
        ),
        .m31_mul => try writer.print(
            "m31_mul(registers[{}], registers[{}])",
            .{ inst.a, inst.b },
        ),
        .m31_neg => try writer.print(
            "m31_neg(registers[{}])",
            .{inst.a},
        ),
        .u16_add => try writer.print(
            "(registers[{}] + registers[{}]) & UINT32_C(0xffff)",
            .{ inst.a, inst.b },
        ),
        .u16_shl => try writer.print(
            "(registers[{}] << {}) & UINT32_C(0xffff)",
            .{ inst.a, inst.imm & 15 },
        ),
        .u16_shr => try writer.print(
            "(registers[{}] & UINT32_C(0xffff)) >> {}",
            .{ inst.a, inst.imm & 15 },
        ),
        .u16_and, .u32_and => try writer.print(
            "registers[{}] & UINT32_C({})",
            .{ inst.a, inst.imm },
        ),
        .u32_add => try writer.print(
            "registers[{}] + registers[{}]",
            .{ inst.a, inst.b },
        ),
        .u32_sub => try writer.print(
            "registers[{}] - registers[{}]",
            .{ inst.a, inst.b },
        ),
        .u32_mul => try writer.print(
            "registers[{}] * registers[{}]",
            .{ inst.a, inst.b },
        ),
        .u32_shl => try writer.print(
            "registers[{}] << {}",
            .{ inst.a, inst.imm & 31 },
        ),
        .u32_shr => try writer.print(
            "registers[{}] >> {}",
            .{ inst.a, inst.imm & 31 },
        ),
        .u32_xor => try writer.print(
            "registers[{}] ^ registers[{}]",
            .{ inst.a, inst.b },
        ),
        .as_m31 => try writer.print(
            "registers[{}] % UINT32_C(0x7fffffff)",
            .{inst.a},
        ),
        .trunc16 => try writer.print(
            "registers[{}] & UINT32_C(0xffff)",
            .{inst.a},
        ),
        .table_limb => try writer.print(
            "run->table_limb_fn(run->bridge_context, {}, registers[{}], {})",
            .{ inst.b, inst.a, inst.imm },
        ),
        .m31_inverse => try writer.print(
            "m31_inverse(registers[{}])",
            .{inst.a},
        ),
        .m31_eq => try writer.print(
            "(uint32_t)(registers[{}] == registers[{}])",
            .{ inst.a, inst.b },
        ),
        else => unreachable,
    }
}
