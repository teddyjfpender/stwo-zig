//! Exact output-store scheduling for recorded-witness CUDA generation.

const std = @import("std");
const model = @import("cairo_witness_model");

pub const Output = struct {
    op: model.Op,
    register: u32,
    ordinal: u32,
};

const Definition = struct {
    instruction: usize,
    deduce_bank_offset: ?usize,
};

const Anchor = union(enum) {
    instruction: usize,
    deduce_arguments: usize,
    deduce_register: struct {
        instruction: usize,
        register: usize,
        bank_offset: usize,
    },

    fn rank(self: Anchor) struct { instruction: usize, phase: usize } {
        return switch (self) {
            .instruction => |instruction| .{
                .instruction = instruction,
                .phase = std.math.maxInt(usize),
            },
            .deduce_arguments => |instruction| .{
                .instruction = instruction,
                .phase = 0,
            },
            .deduce_register => |value| .{
                .instruction = value.instruction,
                .phase = value.bank_offset + 1,
            },
        };
    }
};

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    after_instruction: []std.ArrayList(Output),
    after_deduce_arguments: []std.ArrayList(Output),
    after_deduce_register: []std.ArrayList(Output),

    pub fn deinit(self: *Schedule) void {
        for (self.after_instruction) |*items| items.deinit(self.allocator);
        for (self.after_deduce_arguments) |*items| items.deinit(self.allocator);
        for (self.after_deduce_register) |*items| items.deinit(self.allocator);
        self.allocator.free(self.after_instruction);
        self.allocator.free(self.after_deduce_arguments);
        self.allocator.free(self.after_deduce_register);
        self.* = undefined;
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    program: model.Program,
) !Schedule {
    const register_count: usize = @intCast(program.n_regs);
    const definitions = try allocator.alloc(?Definition, register_count);
    defer allocator.free(definitions);
    @memset(definitions, null);
    const last_use = try allocator.alloc(?usize, register_count);
    defer allocator.free(last_use);
    @memset(last_use, null);
    const last_deduce_use = try allocator.alloc(?usize, register_count);
    defer allocator.free(last_deduce_use);
    @memset(last_deduce_use, null);
    var pending: std.ArrayList(u32) = .empty;
    defer pending.deinit(allocator);
    var outputs: std.ArrayList(Output) = .empty;
    defer outputs.deinit(allocator);

    for (program.insts, 0..) |inst, instruction| {
        switch (inst.op) {
            .input => {
                if (inst.a >= program.n_inputs) return error.InvalidInput;
                try define(inst.dst, instruction, null, definitions, last_use);
            },
            .constant => try define(
                inst.dst,
                instruction,
                null,
                definitions,
                last_use,
            ),
            .m31_add,
            .m31_sub,
            .m31_mul,
            .u16_add,
            .u32_add,
            .u32_sub,
            .u32_mul,
            .u32_xor,
            .m31_eq,
            => {
                try markUse(inst.a, instruction, definitions, last_use);
                try markUse(inst.b, instruction, definitions, last_use);
                try define(
                    inst.dst,
                    instruction,
                    null,
                    definitions,
                    last_use,
                );
            },
            .m31_neg,
            .u16_shl,
            .u16_shr,
            .u16_and,
            .u32_shl,
            .u32_shr,
            .u32_and,
            .as_m31,
            .trunc16,
            .table_limb,
            .m31_inverse,
            => {
                try markUse(inst.a, instruction, definitions, last_use);
                try define(
                    inst.dst,
                    instruction,
                    null,
                    definitions,
                    last_use,
                );
            },
            .mult_push => try markUse(
                inst.a,
                instruction,
                definitions,
                last_use,
            ),
            .deduce_arg => {
                _ = try definition(inst.a, definitions);
                try pending.append(allocator, inst.a);
            },
            .deduce_call => {
                const kind = std.meta.intToEnum(
                    model.DeduceKind,
                    inst.imm,
                ) catch return error.InvalidDeduce;
                const shape = kind.shape();
                if (pending.items.len != shape.args or
                    inst.b != shape.outputs)
                    return error.InvalidDeduce;
                for (pending.items) |register| {
                    try markUse(
                        register,
                        instruction,
                        definitions,
                        last_use,
                    );
                    last_deduce_use[register] = instruction;
                }
                pending.clearRetainingCapacity();
                const end = std.math.add(
                    usize,
                    inst.dst,
                    shape.outputs,
                ) catch return error.InvalidRegister;
                if (end > register_count) return error.InvalidRegister;
                for (inst.dst..end, 0..) |register, bank_offset| {
                    try define(
                        @intCast(register),
                        instruction,
                        bank_offset,
                        definitions,
                        last_use,
                    );
                }
            },
            .col_write, .lookup_word, .sub_word => {
                _ = try definition(inst.a, definitions);
                const bound = switch (inst.op) {
                    .col_write => program.n_cols,
                    .lookup_word => program.n_lookup_words,
                    .sub_word => program.n_sub_words,
                    else => unreachable,
                };
                if (inst.imm >= bound) return error.InvalidOutput;
                try outputs.append(allocator, .{
                    .op = inst.op,
                    .register = inst.a,
                    .ordinal = inst.imm,
                });
            },
        }
    }
    if (pending.items.len != 0) return error.InvalidDeduce;
    for (definitions, last_use) |defined, used| {
        if (defined == null or used == null) return error.InvalidRegister;
    }

    var result = Schedule{
        .allocator = allocator,
        .after_instruction = try emptyLists(
            allocator,
            program.insts.len,
        ),
        .after_deduce_arguments = try emptyLists(
            allocator,
            program.insts.len,
        ),
        .after_deduce_register = try emptyLists(
            allocator,
            register_count,
        ),
    };
    errdefer result.deinit();
    var previous = std.AutoHashMap(u64, Anchor).init(allocator);
    defer previous.deinit();
    for (outputs.items) |output| {
        const register: usize = @intCast(output.register);
        const defined = definitions[register].?;
        const used = last_use[register].?;
        var anchor: Anchor = if (last_deduce_use[register] == used)
            .{ .deduce_arguments = used }
        else if (defined.deduce_bank_offset) |bank_offset|
            if (used == defined.instruction)
                .{ .deduce_register = .{
                    .instruction = defined.instruction,
                    .register = register,
                    .bank_offset = bank_offset,
                } }
            else
                .{ .instruction = used }
        else
            .{ .instruction = used };
        const target = (@as(u64, @intFromEnum(output.op)) << 32) |
            output.ordinal;
        if (previous.get(target)) |prior| {
            const prior_rank = prior.rank();
            const rank = anchor.rank();
            if (prior_rank.instruction > rank.instruction or
                (prior_rank.instruction == rank.instruction and
                    prior_rank.phase > rank.phase))
                anchor = prior;
        }
        try previous.put(target, anchor);
        switch (anchor) {
            .instruction => |instruction| try result
                .after_instruction[instruction].append(allocator, output),
            .deduce_arguments => |instruction| try result
                .after_deduce_arguments[instruction].append(
                allocator,
                output,
            ),
            .deduce_register => |value| try result
                .after_deduce_register[value.register].append(
                allocator,
                output,
            ),
        }
    }
    return result;
}

fn emptyLists(
    allocator: std.mem.Allocator,
    count: usize,
) ![]std.ArrayList(Output) {
    const lists = try allocator.alloc(std.ArrayList(Output), count);
    for (lists) |*list| list.* = .empty;
    return lists;
}

fn definition(
    register: u32,
    definitions: []const ?Definition,
) !Definition {
    if (register >= definitions.len) return error.InvalidRegister;
    return definitions[register] orelse error.InvalidRegister;
}

fn markUse(
    register: u32,
    instruction: usize,
    definitions: []const ?Definition,
    last_use: []?usize,
) !void {
    _ = try definition(register, definitions);
    last_use[register] = instruction;
}

fn define(
    register: u16,
    instruction: usize,
    bank_offset: ?usize,
    definitions: []?Definition,
    last_use: []?usize,
) !void {
    if (register >= definitions.len or definitions[register] != null)
        return error.InvalidRegister;
    definitions[register] = .{
        .instruction = instruction,
        .deduce_bank_offset = bank_offset,
    };
    last_use[register] = instruction;
}
