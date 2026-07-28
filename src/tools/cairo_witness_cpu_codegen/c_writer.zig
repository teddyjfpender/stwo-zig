//! Straight-line C writer emission for one authenticated witness program.

const std = @import("std");
const model = @import("model.zig");

pub fn emit(
    writer: *std.Io.Writer,
    witness_program: model.Program,
) !void {
    const digest = witness_program.semanticIdentity();
    const symbol = std.mem.readInt(u64, digest[0..8], .little);
    try writePreamble(writer);
    try writer.print(
        \\int cairo_witness_{x}(const native_range_execution *run) {{
        \\
    , .{symbol});
    try writer.writeAll(
        \\    uint32_t *restrict registers = run->registers;
        \\    uint32_t *restrict deduce_args = run->deduce_args;
        \\    for (size_t row = run->start; row < run->end; ++row) {
        \\
    );
    var pending_arguments: usize = 0;
    for (witness_program.insts) |inst| {
        switch (inst.op) {
            .col_write => try writer.print(
                "        run->output_columns[{}].ptr[row] = registers[{}];\n",
                .{ inst.imm, inst.a },
            ),
            .lookup_word => try writer.print(
                "        run->lookup_words[{} * run->row_count + row] = registers[{}];\n",
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
                try emitValue(writer, inst);
                try writer.writeAll(";\n");
            },
        }
    }
    if (pending_arguments != 0) return error.InvalidDeduce;
    try writer.writeAll(
        \\    }
        \\    return 0;
        \\}
        \\
    );
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

fn emitValue(writer: *std.Io.Writer, inst: model.Inst) !void {
    switch (inst.op) {
        .input => try writer.print(
            "run->input_columns[{}].ptr[row]",
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
