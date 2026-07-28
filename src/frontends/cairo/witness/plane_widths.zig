//! Structural value-width analysis for recorded Cairo witness programs.
//!
//! Every recorded program is straight-line SSA: `Program.validate` enforces
//! `inst.dst == next_register` with a monotonically increasing register
//! counter, so a single forward pass assigns each register a sound upper bound
//! on the value it can ever hold. The bound is a function of the recorded
//! bytecode alone — no workload, no input, no per-program table of names — so
//! a column admitted as narrow here is narrow for every proof the program can
//! ever produce.
//!
//! The two structural width sources this pass relies on:
//!
//!  * opcode semantics in `program.executeRow` (the `u16_*` family masks to
//!    `0xffff`, `trunc16` masks to `0xffff`, `*_and` is bounded by its
//!    immediate, `m31_eq` yields 0 or 1, and the M31 family is bounded by the
//!    modulus);
//!  * `execution_tables.MEMORY_VALUE_TABLE` limbs, which are masked to nine
//!    bits at `execution_tables.zig:60` and `execution_tables.zig:65`.
//!
//! Anything the pass cannot prove stays 32-bit. Narrowing is a storage
//! representation change only: the widened value is bit-identical.

const std = @import("std");
const execution_tables = @import("execution_tables.zig");
const program_mod = @import("program.zig");

const Op = program_mod.Op;
const Program = program_mod.Program;

const u32_max: u64 = std.math.maxInt(u32);
/// Largest canonical M31 residue.
const m31_max: u64 = @import("stwo_core").fields.m31.Modulus - 1;
pub const narrow_max: u64 = std.math.maxInt(u16);

/// One hoisted destination write: `plane[index][row] = registers[reg]`.
///
/// Hoisting the writes out of the instruction switch is what keeps the width
/// decision off the per-row path — a narrow plane and a wide plane are two
/// separate loops, never a branch inside one. Declared next to the interpreter
/// that consumes it.
pub const ColumnWrite = program_mod.ColumnWrite;

pub const Plan = struct {
    allocator: std.mem.Allocator,
    /// `true` when column `i` is provably <= 16 bits.
    narrow: []bool,
    narrow_writes: []ColumnWrite,
    wide_writes: []ColumnWrite,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.narrow);
        self.allocator.free(self.narrow_writes);
        self.allocator.free(self.wide_writes);
        self.* = undefined;
    }

    pub fn narrowCount(self: Plan) usize {
        var count: usize = 0;
        for (self.narrow) |flag| {
            if (flag) count += 1;
        }
        return count;
    }
};

/// Sound forward bound on every register, then on every written column.
///
/// `bounds` must hold `program.n_cols` entries and receives the per-column
/// maximum. Columns no instruction writes keep bound zero: `initializeAllOutputs`
/// clears them and nothing else touches them.
pub fn columnBounds(
    allocator: std.mem.Allocator,
    program: Program,
    bounds: []u64,
) !void {
    std.debug.assert(bounds.len == program.n_cols);
    @memset(bounds, 0);
    const registers = try allocator.alloc(u64, program.n_regs);
    defer allocator.free(registers);
    @memset(registers, u32_max);

    var next: u32 = 0;
    for (program.insts) |inst| {
        const op: Op = std.meta.intToEnum(Op, inst.op) catch return error.InvalidOpcode;
        const a: u64 = if (inst.a < next) registers[inst.a] else 0;
        const b: u64 = if (inst.b < next) registers[inst.b] else 0;
        // `@min` narrows its result type, so every product below is taken in
        // explicit saturating u64 arithmetic: a wrapped bound would be a
        // *smaller* bound, which is exactly the unsound direction.
        const am: u64 = @min(a, m31_max);
        const bm: u64 = @min(b, m31_max);
        const a16: u64 = @min(a, 0xffff);
        const value: u64 = switch (op) {
            .col_write => {
                if (inst.imm >= program.n_cols) return error.InvalidOutput;
                bounds[inst.imm] = @max(bounds[inst.imm], a);
                continue;
            },
            .mult_push, .lookup_word, .sub_word, .deduce_arg => continue,
            .deduce_call => {
                // Deduction outputs are opaque to this pass.
                var produced: u32 = 0;
                while (produced < inst.b) : (produced += 1) {
                    if (next >= registers.len) return error.InvalidRegister;
                    registers[next] = u32_max;
                    next += 1;
                }
                continue;
            },
            .input => u32_max,
            .constant => inst.imm,
            // `M31.fromCanonical` reduces, so a bound below the modulus is
            // preserved through add and mul; sub, neg and inverse can wrap up
            // to the modulus.
            .m31_add => @min(am +| bm, m31_max),
            .m31_mul => @min(am *| bm, m31_max),
            .as_m31 => am,
            .m31_sub, .m31_neg, .m31_inverse => m31_max,
            .u16_add, .u16_shl => 0xffff,
            .u16_shr => a16 >> @intCast(inst.imm & 15),
            .u16_and, .u32_and => @min(a, @as(u64, inst.imm)),
            .u32_add => @min(a +| b, u32_max),
            .u32_sub => u32_max,
            .u32_mul => @min(a *| b, u32_max),
            .u32_shl => @min(a <<| @as(u6, @intCast(inst.imm & 31)), u32_max),
            .u32_shr => a >> @intCast(inst.imm & 31),
            .u32_xor => (@as(u64, 1) << @intCast(@max(bitLen(a), bitLen(b)))) - 1,
            .trunc16 => a16,
            // Only the memory-value table has a structurally masked limb.
            .table_limb => if (inst.b == execution_tables.MEMORY_VALUE_TABLE)
                0x1ff
            else
                u32_max,
            .m31_eq => 1,
        };
        if (next >= registers.len) return error.InvalidRegister;
        registers[next] = value;
        next += 1;
    }
}

fn bitLen(value: u64) u7 {
    return @intCast(64 - @clz(value));
}

/// Builds the split write plan for one program.
pub fn plan(allocator: std.mem.Allocator, program: Program) !Plan {
    const bounds = try allocator.alloc(u64, program.n_cols);
    defer allocator.free(bounds);
    try columnBounds(allocator, program, bounds);

    const narrow = try allocator.alloc(bool, program.n_cols);
    errdefer allocator.free(narrow);
    for (bounds, narrow) |bound, *flag| flag.* = bound <= narrow_max;

    var narrow_count: usize = 0;
    for (program.insts) |inst| {
        if (inst.op == @intFromEnum(Op.col_write) and narrow[inst.imm]) narrow_count += 1;
    }
    var wide_count: usize = 0;
    for (program.insts) |inst| {
        if (inst.op == @intFromEnum(Op.col_write) and !narrow[inst.imm]) wide_count += 1;
    }

    const narrow_writes = try allocator.alloc(ColumnWrite, narrow_count);
    errdefer allocator.free(narrow_writes);
    const wide_writes = try allocator.alloc(ColumnWrite, wide_count);
    errdefer allocator.free(wide_writes);

    var narrow_at: usize = 0;
    var wide_at: usize = 0;
    for (program.insts) |inst| {
        if (inst.op != @intFromEnum(Op.col_write)) continue;
        const write = ColumnWrite{ .reg = inst.a, .index = inst.imm };
        if (narrow[inst.imm]) {
            narrow_writes[narrow_at] = write;
            narrow_at += 1;
        } else {
            wide_writes[wide_at] = write;
            wide_at += 1;
        }
    }

    return .{
        .allocator = allocator,
        .narrow = narrow,
        .narrow_writes = narrow_writes,
        .wide_writes = wide_writes,
    };
}

test "plane widths: masked opcodes admit narrow columns, unknown inputs do not" {
    const insts = [_]program_mod.Inst{
        .{ .op = @intFromEnum(Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        // column 0: raw input, not provable
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.trunc16), .dst = 1, .a = 0, .b = 0, .imm = 0 },
        // column 1: masked to 16 bits
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 1, .b = 0, .imm = 1 },
        .{ .op = @intFromEnum(Op.as_m31), .dst = 2, .a = 1, .b = 0, .imm = 0 },
        // column 2: as_m31 over a 16-bit value stays 16-bit
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 2 },
        .{
            .op = @intFromEnum(Op.table_limb),
            .dst = 3,
            .a = 0,
            .b = execution_tables.MEMORY_VALUE_TABLE,
            .imm = 0,
        },
        // column 3: nine-bit memory limb
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 3, .b = 0, .imm = 3 },
        .{
            .op = @intFromEnum(Op.table_limb),
            .dst = 4,
            .a = 0,
            .b = execution_tables.ADDRESS_TO_ID_TABLE,
            .imm = 0,
        },
        // column 4: encoded id, full width
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 4, .b = 0, .imm = 4 },
    };
    const program = Program{
        .insts = &insts,
        .n_regs = 5,
        .n_inputs = 1,
        .n_cols = 5,
        .n_mult_tables = 0,
        .n_lookup_words = 0,
        .n_sub_words = 0,
    };
    try program.validate();
    var built = try plan(std.testing.allocator, program);
    defer built.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, true, false },
        built.narrow,
    );
    try std.testing.expectEqual(@as(usize, 3), built.narrow_writes.len);
    try std.testing.expectEqual(@as(usize, 2), built.wide_writes.len);
    try std.testing.expectEqual(@as(u32, 1), built.narrow_writes[0].index);
    try std.testing.expectEqual(@as(u32, 0), built.wide_writes[0].index);
}

test "plane widths: m31 arithmetic over narrow operands stays narrow" {
    const insts = [_]program_mod.Inst{
        .{ .op = @intFromEnum(Op.constant), .dst = 0, .a = 0, .b = 0, .imm = 100 },
        .{ .op = @intFromEnum(Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 200 },
        .{ .op = @intFromEnum(Op.m31_add), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.m31_mul), .dst = 3, .a = 0, .b = 1, .imm = 0 },
        // 100 * 200 = 20000, still 16-bit
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 3, .b = 0, .imm = 1 },
        .{ .op = @intFromEnum(Op.m31_sub), .dst = 4, .a = 0, .b = 1, .imm = 0 },
        // subtraction wraps modulo the prime
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 4, .b = 0, .imm = 2 },
    };
    const program = Program{
        .insts = &insts,
        .n_regs = 5,
        .n_inputs = 0,
        .n_cols = 3,
        .n_mult_tables = 0,
        .n_lookup_words = 0,
        .n_sub_words = 0,
    };
    try program.validate();
    var built = try plan(std.testing.allocator, program);
    defer built.deinit();
    try std.testing.expectEqualSlices(bool, &.{ true, true, false }, built.narrow);
}
