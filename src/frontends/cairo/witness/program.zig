//! Canonical stwo-cairo witness bytecode shared with the generated Rust writers.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const Blake3Hasher = stwo_core.vcs.blake3_hash.Blake3Hasher;

pub const Op = enum(u8) {
    input = 0,
    constant = 1,
    m31_add = 2,
    m31_sub = 3,
    m31_mul = 4,
    m31_neg = 5,
    u16_add = 6,
    u16_shl = 7,
    u16_shr = 8,
    u16_and = 9,
    u32_add = 10,
    u32_sub = 11,
    u32_mul = 12,
    u32_shl = 13,
    u32_shr = 14,
    u32_and = 15,
    u32_xor = 16,
    as_m31 = 17,
    trunc16 = 18,
    table_limb = 19,
    col_write = 20,
    mult_push = 21,
    lookup_word = 22,
    sub_word = 23,
    m31_inverse = 24,
    m31_eq = 25,
    deduce_arg = 26,
    deduce_call = 27,
};

pub const Inst = extern struct {
    op: u8,
    pad: u8 = 0,
    dst: u16,
    a: u32,
    b: u32,
    imm: u32,
};

comptime {
    if (@sizeOf(Inst) != 16 or @alignOf(Inst) != 4) @compileError("Cairo witness instruction ABI drift");
}

pub const Program = struct {
    insts: []const Inst,
    n_regs: u32,
    n_inputs: u32,
    n_cols: u32,
    n_mult_tables: u32,
    n_lookup_words: u32,
    n_sub_words: u32,

    pub fn semanticHash(self: Program) u64 {
        var hash: u64 = 0xcbf29ce484222325;
        for (std.mem.sliceAsBytes(self.insts)) |byte| {
            hash ^= byte;
            hash *%= 0x100000001b3;
        }
        for ([_]u32{ self.n_regs, self.n_inputs, self.n_cols, self.n_mult_tables, self.n_lookup_words, self.n_sub_words }) |count| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, count, .little);
            for (bytes) |byte| {
                hash ^= byte;
                hash *%= 0x100000001b3;
            }
        }
        return hash;
    }

    /// Collision-resistant identity shared with the CUDA recorded-witness AOT
    /// authority. The diagnostic label is deliberately excluded.
    pub fn semanticIdentity(self: Program) [32]u8 {
        var hash = Blake3Hasher.init();
        hash.update("stwo-cuda-witness-program-semantic-identity-v1\x00");
        hashLittle(&hash, u64, self.insts.len);
        for (self.insts) |inst| {
            hash.update(&.{ inst.op, inst.pad });
            hashLittle(&hash, u16, inst.dst);
            hashLittle(&hash, u32, inst.a);
            hashLittle(&hash, u32, inst.b);
            hashLittle(&hash, u32, inst.imm);
        }
        for ([_]u32{
            self.n_regs,
            self.n_inputs,
            self.n_cols,
            self.n_mult_tables,
            self.n_lookup_words,
            self.n_sub_words,
        }) |count| hashLittle(&hash, u32, count);
        return hash.finalize();
    }

    pub const DeductionRequirements = packed struct {
        pedersen_table: bool = false,
        poseidon_constants: bool = false,
    };

    /// Reports fixed data required by generated fast-deduction calls. This is
    /// semantic capability data; backends must reject a program when their AOT
    /// module has not bound every required table.
    pub fn deductionRequirements(self: Program) DeductionRequirements {
        var requirements = DeductionRequirements{};
        for (self.insts) |inst| {
            const op = std.meta.intToEnum(Op, inst.op) catch continue;
            if (op != .deduce_call) continue;
            switch (inst.imm) {
                2, 3 => requirements.pedersen_table = true,
                8, 10, 11 => requirements.poseidon_constants = true,
                else => {},
            }
        }
        return requirements;
    }

    pub fn validate(self: Program) !void {
        var next_register: u32 = 0;
        var pending_deduce_args: u32 = 0;
        for (self.insts) |inst| {
            if (inst.pad != 0) return error.InvalidPadding;
            const op = std.meta.intToEnum(Op, inst.op) catch return error.InvalidOpcode;
            const reads_a = switch (op) {
                .input, .constant, .deduce_call => false,
                else => true,
            };
            const reads_b = switch (op) {
                .m31_add, .m31_sub, .m31_mul, .m31_eq, .u16_add, .u32_add, .u32_sub, .u32_mul, .u32_xor => true,
                else => false,
            };
            if (reads_a and inst.a >= next_register) return error.InvalidRegister;
            if (reads_b and inst.b >= next_register) return error.InvalidRegister;
            switch (op) {
                .input => if (inst.a >= self.n_inputs) return error.InvalidInput,
                .col_write => if (inst.imm >= self.n_cols) return error.InvalidOutput,
                .mult_push => if (inst.imm >= self.n_mult_tables) return error.InvalidOutput,
                .lookup_word => if (inst.imm >= self.n_lookup_words) return error.InvalidOutput,
                .sub_word => if (inst.imm >= self.n_sub_words) return error.InvalidOutput,
                .deduce_arg => pending_deduce_args += 1,
                .deduce_call => {
                    if (pending_deduce_args == 0 or inst.b == 0) return error.InvalidDeduce;
                    if (inst.dst != next_register) return error.InvalidRegister;
                    next_register += inst.b;
                    pending_deduce_args = 0;
                    continue;
                },
                else => {},
            }
            if (writesRegister(op)) {
                if (inst.dst != next_register) return error.InvalidRegister;
                next_register += 1;
            }
        }
        if (pending_deduce_args != 0 or next_register != self.n_regs) return error.InvalidRegister;
    }
};

fn hashLittle(hash: *Blake3Hasher, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn writesRegister(op: Op) bool {
    return switch (op) {
        .col_write, .mult_push, .lookup_word, .sub_word, .deduce_arg => false,
        else => true,
    };
}

pub const Outputs = struct {
    columns: []u32,
    lookup_words: []u32,
    sub_words: []u32,
    mult_tables: []u32,

    pub fn deinit(self: *Outputs, allocator: std.mem.Allocator) void {
        allocator.free(self.columns);
        allocator.free(self.lookup_words);
        allocator.free(self.sub_words);
        allocator.free(self.mult_tables);
        self.* = undefined;
    }
};

pub const TableContext = struct {
    context: *anyopaque,
    limb_fn: *const fn (*anyopaque, u32, u32, u32) u32,

    pub fn limb(self: TableContext, table: u32, row: u32, limb_index: u32) u32 {
        return self.limb_fn(self.context, table, row, limb_index);
    }

    pub fn zero() TableContext {
        return .{ .context = undefined, .limb_fn = zeroLimb };
    }

    fn zeroLimb(_: *anyopaque, _: u32, _: u32, _: u32) u32 {
        return 0;
    }
};

pub const DeduceContext = struct {
    context: *anyopaque,
    call_fn: *const fn (*anyopaque, u32, []const u32, []u32) anyerror!void,

    pub fn call(self: DeduceContext, selector: u32, args: []const u32, outputs: []u32) !void {
        try self.call_fn(self.context, selector, args, outputs);
    }

    pub fn unsupported() DeduceContext {
        return .{ .context = undefined, .call_fn = unsupportedCall };
    }

    fn unsupportedCall(_: *anyopaque, _: u32, _: []const u32, _: []u32) !void {
        return error.ComputedDeduceRequired;
    }
};

/// Allocation-free column-major witness execution. `registers` and
/// `deduce_args` are caller-owned scratch and are reused for every row.
pub fn executeColumn(
    program: Program,
    input_columns: []const []const u32,
    column_index: u32,
    destination: []u32,
    registers: []u32,
    deduce_args: []u32,
    tables: TableContext,
    deduce: DeduceContext,
) !void {
    try program.validate();
    if (column_index >= program.n_cols or registers.len < program.n_regs or deduce_args.len < program.n_regs)
        return error.InvalidOutput;
    if (input_columns.len < program.n_inputs) return error.InvalidInput;
    for (input_columns[0..program.n_inputs]) |input| if (input.len < destination.len) return error.InvalidInput;
    for (destination, 0..) |*output, row| {
        output.* = 0;
        try executeRow(program, input_columns, @intCast(row), column_index, output, null, null, registers, deduce_args, tables, deduce);
    }
}

/// Executes a recorded program once per row and writes every trace column.
pub fn executeColumns(
    program: Program,
    input_columns: []const []const u32,
    output_columns: []const []u32,
    registers: []u32,
    deduce_args: []u32,
    tables: TableContext,
    deduce: DeduceContext,
) !void {
    return executeAll(program, input_columns, output_columns, null, registers, deduce_args, tables, deduce);
}

pub const AuxiliaryOutputs = struct {
    lookup_words: []u32,
    sub_words: []u32,
    multiplicity_tables: []const []u32,
};

pub fn executeAll(
    program: Program,
    input_columns: []const []const u32,
    output_columns: []const []u32,
    auxiliary: ?AuxiliaryOutputs,
    registers: []u32,
    deduce_args: []u32,
    tables: TableContext,
    deduce: DeduceContext,
) !void {
    try program.validate();
    if (input_columns.len < program.n_inputs or output_columns.len != program.n_cols or
        registers.len < program.n_regs or deduce_args.len < program.n_regs)
        return error.InvalidOutput;
    const row_count = output_columns[0].len;
    for (input_columns[0..program.n_inputs]) |input| if (input.len < row_count) return error.InvalidInput;
    for (output_columns) |output| {
        if (output.len != row_count) return error.InvalidOutput;
        @memset(output, 0);
    }
    if (auxiliary) |outputs| {
        if (outputs.lookup_words.len != row_count * program.n_lookup_words or
            outputs.sub_words.len != row_count * program.n_sub_words or
            outputs.multiplicity_tables.len != program.n_mult_tables)
            return error.InvalidOutput;
        @memset(outputs.lookup_words, 0);
        @memset(outputs.sub_words, 0);
        for (outputs.multiplicity_tables) |table| @memset(table, 0);
    }
    for (0..row_count) |row| {
        try executeRow(program, input_columns, @intCast(row), null, null, output_columns, auxiliary, registers, deduce_args, tables, deduce);
    }
}

fn executeRow(
    program: Program,
    input_columns: []const []const u32,
    row: u32,
    selected_column: ?u32,
    selected_output: ?*u32,
    output_columns: ?[]const []u32,
    auxiliary: ?AuxiliaryOutputs,
    registers: []u32,
    deduce_args: []u32,
    tables: TableContext,
    deduce: DeduceContext,
) !void {
    var pending_args: usize = 0;
    for (program.insts) |inst| {
        const op: Op = @enumFromInt(inst.op);
        const a = if (inst.a < registers.len) registers[inst.a] else 0;
        const b = if (inst.b < registers.len) registers[inst.b] else 0;
        const value: u32 = switch (op) {
            .input => input_columns[inst.a][row],
            .constant => inst.imm,
            .m31_add => M31.fromCanonical(a).add(M31.fromCanonical(b)).v,
            .m31_sub => M31.fromCanonical(a).sub(M31.fromCanonical(b)).v,
            .m31_mul => M31.fromCanonical(a).mul(M31.fromCanonical(b)).v,
            .m31_neg => M31.fromCanonical(a).neg().v,
            .u16_add => (a +% b) & 0xffff,
            .u16_shl => (a << @intCast(inst.imm & 15)) & 0xffff,
            .u16_shr => (a & 0xffff) >> @intCast(inst.imm & 15),
            .u16_and, .u32_and => a & inst.imm,
            .u32_add => a +% b,
            .u32_sub => a -% b,
            .u32_mul => a *% b,
            .u32_shl => a << @intCast(inst.imm & 31),
            .u32_shr => a >> @intCast(inst.imm & 31),
            .u32_xor => a ^ b,
            .as_m31 => a % @import("stwo_core").fields.m31.Modulus,
            .trunc16 => a & 0xffff,
            .table_limb => tables.limb(inst.b, a, inst.imm),
            .m31_inverse => (M31.fromCanonical(a).inv() catch M31.zero()).v,
            .m31_eq => @intFromBool(a == b),
            .col_write => {
                if (selected_column) |column| {
                    if (inst.imm == column) selected_output.?.* = a;
                } else {
                    output_columns.?[inst.imm][row] = a;
                }
                continue;
            },
            .lookup_word => {
                if (auxiliary) |outputs| outputs.lookup_words[@as(usize, row) * program.n_lookup_words + inst.imm] = a;
                continue;
            },
            .sub_word => {
                if (auxiliary) |outputs| outputs.sub_words[@as(usize, row) * program.n_sub_words + inst.imm] = a;
                continue;
            },
            .mult_push => {
                if (auxiliary) |outputs| {
                    const table = outputs.multiplicity_tables[inst.imm];
                    if (a >= table.len) return error.InvalidMultiplicityKey;
                    table[a] +%= 1;
                }
                continue;
            },
            .deduce_arg => {
                if (pending_args >= deduce_args.len) return error.InvalidDeduce;
                deduce_args[pending_args] = a;
                pending_args += 1;
                continue;
            },
            .deduce_call => {
                const output_count: usize = inst.b;
                if (inst.dst + output_count > registers.len) return error.InvalidDeduce;
                try deduce.call(inst.imm, deduce_args[0..pending_args], registers[inst.dst .. inst.dst + output_count]);
                pending_args = 0;
                continue;
            },
        };
        registers[inst.dst] = value;
    }
}

pub fn interpretCore(
    allocator: std.mem.Allocator,
    program: Program,
    inputs: []const u32,
    tableContext: anytype,
) !Outputs {
    try program.validate();
    if (inputs.len < program.n_inputs) return error.InvalidInput;
    const registers = try allocator.alloc(u32, program.n_regs);
    defer allocator.free(registers);
    var outputs = Outputs{
        .columns = try allocator.alloc(u32, program.n_cols),
        .lookup_words = try allocator.alloc(u32, program.n_lookup_words),
        .sub_words = try allocator.alloc(u32, program.n_sub_words),
        .mult_tables = try allocator.alloc(u32, program.n_mult_tables),
    };
    errdefer outputs.deinit(allocator);
    @memset(outputs.columns, 0);
    @memset(outputs.lookup_words, 0);
    @memset(outputs.sub_words, 0);
    @memset(outputs.mult_tables, 0);

    for (program.insts) |inst| {
        const op: Op = @enumFromInt(inst.op);
        const a = if (inst.a < registers.len) registers[inst.a] else 0;
        const b = if (inst.b < registers.len) registers[inst.b] else 0;
        const value: u32 = switch (op) {
            .input => inputs[inst.a],
            .constant => inst.imm,
            .m31_add => M31.fromCanonical(a).add(M31.fromCanonical(b)).v,
            .m31_sub => M31.fromCanonical(a).sub(M31.fromCanonical(b)).v,
            .m31_mul => M31.fromCanonical(a).mul(M31.fromCanonical(b)).v,
            .m31_neg => M31.fromCanonical(a).neg().v,
            .u16_add => (a +% b) & 0xffff,
            .u16_shl => (a << @intCast(inst.imm & 15)) & 0xffff,
            .u16_shr => (a & 0xffff) >> @intCast(inst.imm & 15),
            .u16_and, .u32_and => a & inst.imm,
            .u32_add => a +% b,
            .u32_sub => a -% b,
            .u32_mul => a *% b,
            .u32_shl => a << @intCast(inst.imm & 31),
            .u32_shr => a >> @intCast(inst.imm & 31),
            .u32_xor => a ^ b,
            .as_m31 => a % @import("stwo_core").fields.m31.Modulus,
            .trunc16 => a & 0xffff,
            .table_limb => tableContext.tableLimb(inst.b, a, inst.imm),
            .m31_inverse => (M31.fromCanonical(a).inv() catch M31.zero()).v,
            .m31_eq => @intFromBool(a == b),
            .col_write => {
                outputs.columns[inst.imm] = a;
                continue;
            },
            .lookup_word => {
                outputs.lookup_words[inst.imm] = a;
                continue;
            },
            .sub_word => {
                outputs.sub_words[inst.imm] = a;
                continue;
            },
            .mult_push => {
                outputs.mult_tables[inst.imm] +%= 1;
                continue;
            },
            .deduce_arg, .deduce_call => return error.ComputedDeduceRequired,
        };
        registers[inst.dst] = value;
    }
    return outputs;
}

test "cairo witness program: ABI, validation, and core interpretation" {
    const insts = [_]Inst{
        .{ .op = @intFromEnum(Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 7 },
        .{ .op = @intFromEnum(Op.m31_mul), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 0 },
    };
    const program = Program{ .insts = &insts, .n_regs = 3, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    try program.validate();
    const NoTables = struct {
        fn tableLimb(_: @This(), _: u32, _: u32, _: u32) u32 {
            return 0;
        }
    };
    var outputs = try interpretCore(std.testing.allocator, program, &.{9}, NoTables{});
    defer outputs.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 63), outputs.columns[0]);
}

test "cairo witness program: allocation-free selected-column execution" {
    const insts = [_]Inst{
        .{ .op = @intFromEnum(Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.constant), .dst = 1, .a = 0, .b = 0, .imm = 3 },
        .{ .op = @intFromEnum(Op.u32_add), .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 2, .b = 0, .imm = 0 },
    };
    const program = Program{ .insts = &insts, .n_regs = 3, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
    const input = [_]u32{ 1, 4, 9, 16 };
    const inputs = [_][]const u32{&input};
    var destination = [_]u32{0} ** input.len;
    var registers: [3]u32 = undefined;
    var deduce_args: [3]u32 = undefined;
    try executeColumn(program, &inputs, 0, &destination, &registers, &deduce_args, .zero(), .unsupported());
    try std.testing.expectEqualSlices(u32, &.{ 4, 7, 12, 19 }, &destination);
}

test "cairo witness program: grouped execution preserves lookup and feed outputs" {
    const insts = [_]Inst{
        .{ .op = @intFromEnum(Op.input), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.col_write), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.lookup_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.sub_word), .dst = 0, .a = 0, .b = 0, .imm = 0 },
        .{ .op = @intFromEnum(Op.mult_push), .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    const program = Program{ .insts = &insts, .n_regs = 1, .n_inputs = 1, .n_cols = 1, .n_mult_tables = 1, .n_lookup_words = 1, .n_sub_words = 1 };
    const input = [_]u32{ 1, 2, 1, 3 };
    const inputs = [_][]const u32{&input};
    var trace = [_]u32{0} ** input.len;
    const traces = [_][]u32{&trace};
    var lookup = [_]u32{0} ** input.len;
    var sub = [_]u32{0} ** input.len;
    var counts = [_]u32{0} ** 4;
    const count_tables = [_][]u32{&counts};
    var registers: [1]u32 = undefined;
    var deduce_args: [1]u32 = undefined;
    try executeAll(
        program,
        &inputs,
        &traces,
        .{ .lookup_words = &lookup, .sub_words = &sub, .multiplicity_tables = &count_tables },
        &registers,
        &deduce_args,
        .zero(),
        .unsupported(),
    );
    try std.testing.expectEqualSlices(u32, &input, &trace);
    try std.testing.expectEqualSlices(u32, &input, &lookup);
    try std.testing.expectEqualSlices(u32, &input, &sub);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 1, 1 }, &counts);
}
