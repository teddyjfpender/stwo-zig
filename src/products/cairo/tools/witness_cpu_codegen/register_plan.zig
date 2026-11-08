//! Linear-scan allocation for authenticated SSA witness registers.
//! Deduction results remain contiguous to preserve the native callback ABI.
const std = @import("std");
const model = @import("model.zig");

pub const Owned = struct {
    allocator: std.mem.Allocator,
    program: model.Program,
    pub fn deinit(self: Owned) void {
        self.allocator.free(self.program.insts);
    }
};

pub fn readsA(op: model.Op) bool {
    return switch (op) {
        .input, .constant, .deduce_call => false,
        else => true,
    };
}
pub fn readsB(op: model.Op) bool {
    return switch (op) {
        .m31_add, .m31_sub, .m31_mul, .m31_eq, .u16_add, .u32_add, .u32_sub, .u32_mul, .u32_xor => true,
        else => false,
    };
}
fn outputWidth(inst: model.Inst) usize {
    return switch (inst.op) {
        .col_write, .mult_push, .lookup_word, .sub_word, .deduce_arg => 0,
        .deduce_call => inst.b,
        else => 1,
    };
}

pub fn compact(allocator: std.mem.Allocator, source: model.Program) !Owned {
    const last_use = try allocator.alloc(usize, source.n_regs);
    defer allocator.free(last_use);
    @memset(last_use, 0);
    var defined: usize = 0;
    var pending: usize = 0;
    for (source.insts, 0..) |inst, index| {
        if (readsA(inst.op)) {
            if (inst.a >= defined) return error.InvalidRegister;
            last_use[inst.a] = index;
        }
        if (readsB(inst.op)) {
            if (inst.b >= defined) return error.InvalidRegister;
            last_use[inst.b] = index;
        }
        if (inst.op == .deduce_arg) pending += 1;
        if (inst.op == .deduce_call) {
            if (pending == 0 or inst.b == 0) return error.InvalidDeduce;
            pending = 0;
        }
        const width = outputWidth(inst);
        if (width != 0) {
            if (inst.dst != defined or width > source.n_regs - defined) return error.InvalidRegister;
            for (defined..defined + width) |reg| last_use[reg] = index;
            defined += width;
        }
    }
    if (defined != source.n_regs or pending != 0) return error.InvalidRegister;
    const mapping = try allocator.alloc(u32, source.n_regs);
    defer allocator.free(mapping);
    const expires = try allocator.alloc(usize, source.n_regs);
    defer allocator.free(expires);
    const insts = try allocator.dupe(model.Inst, source.insts);
    errdefer allocator.free(insts);
    var peak: usize = 0;
    for (source.insts, insts, 0..) |original, *inst, index| {
        if (readsA(inst.op)) inst.a = mapping[original.a];
        if (readsB(inst.op)) inst.b = mapping[original.b];
        const width = outputWidth(original);
        if (width == 0) continue;
        var slot: usize = 0;
        while (slot < peak) {
            var conflict: ?usize = null;
            for (slot..@min(slot + width, peak)) |candidate| {
                if (expires[candidate] >= index) {
                    conflict = candidate;
                    break;
                }
            }
            if (conflict) |candidate| {
                slot = candidate + 1;
            } else break;
        }
        if (slot + width > source.n_regs or slot > std.math.maxInt(u16)) return error.InvalidRegister;
        peak = @max(peak, slot + width);
        for (0..width) |i| {
            mapping[@as(usize, original.dst) + i] = @intCast(slot + i);
            expires[slot + i] = last_use[@as(usize, original.dst) + i];
        }
        inst.dst = @intCast(slot);
    }
    var result = source;
    result.insts = insts;
    result.n_regs = @intCast(peak);
    return .{ .allocator = allocator, .program = result };
}

fn value(op: model.Op, dst: u16, a: u32, b: u32, imm: u32) model.Inst {
    return .{ .op = op, .dst = dst, .a = a, .b = b, .imm = imm };
}
fn testProgram(insts: []const model.Inst, regs: u32) model.Program {
    return .{ .label = "differential", .semantic_hash = 0, .insts = insts, .n_regs = regs, .n_inputs = 0, .n_cols = 1, .n_mult_tables = 0, .n_lookup_words = 0, .n_sub_words = 0 };
}
fn evaluate(p: model.Program, registers: []u32) u32 {
    var output: u32 = 0;
    var arg: u32 = 0;
    for (p.insts) |inst| switch (inst.op) {
        .constant => registers[inst.dst] = inst.imm,
        .u32_add => registers[inst.dst] = registers[inst.a] +% registers[inst.b],
        .deduce_arg => arg = registers[inst.a],
        .deduce_call => for (0..inst.b) |i| {
            registers[@as(usize, inst.dst) + i] = arg +% @as(u32, @intCast(i));
        },
        .col_write => output = registers[inst.a],
        else => unreachable,
    };
    return output;
}

test "register compaction preserves long-lived values and contiguous deduction results" {
    const instructions = [_]model.Inst{
        value(.constant, 0, 0, 0, 0xf1234567), value(.constant, 1, 0, 0, 18),
        value(.u32_add, 2, 0, 1, 0),           value(.deduce_arg, 0, 2, 0, 0),
        value(.deduce_call, 3, 0, 4, 7),       value(.u32_add, 7, 3, 6, 0),
        value(.u32_add, 8, 0, 7, 0),           value(.col_write, 0, 8, 0, 0),
    };
    const original = testProgram(&instructions, 9);
    const plan = try compact(std.testing.allocator, original);
    defer plan.deinit();
    try std.testing.expect(plan.program.n_regs < original.n_regs);
    var a: [9]u32 = undefined;
    var b: [9]u32 = undefined;
    try std.testing.expectEqual(evaluate(original, &a), evaluate(plan.program, &b));
    try std.testing.expectEqual(@as(u32, 4), plan.program.insts[4].b);
}

test "register compaction rejects a forward register read" {
    const instructions = [_]model.Inst{ value(.constant, 0, 0, 0, 1), value(.u32_add, 1, 0, 2, 0) };
    try std.testing.expectError(error.InvalidRegister, compact(std.testing.allocator, testProgram(&instructions, 2)));
}
