//! Per-run partition of a captured AIR program into row-invariant and
//! row-varying instructions.
//!
//! The template interpreter re-executes the complete instruction stream once
//! per four-row group. A large part of that stream does not depend on the row:
//! `constant` and `param` instructions materialise the same register value on
//! every group. `build` partitions the stream once per evaluated range so the
//! row loop only runs instructions whose value actually varies, and the
//! invariant prefix primes the register file once.
//!
//! Admission is a structural property of the program alone: an instruction is
//! hoisted only when it is row-invariant *and* its destination register is
//! written exactly once in the whole stream, so that register provably holds
//! the same value for the entire execution. Nothing here inspects a workload
//! name, path, digest, or component identity.

const std = @import("std");
const eval = @import("../../witness/eval_program.zig");

/// Instruction order is preserved inside each partition, which is what keeps
/// the interpreted result bit-identical to the unpartitioned stream.
pub const Plan = struct {
    base_storage: []eval.BaseInst,
    ext_storage: []eval.ExtInst,
    invariant_base_len: usize,
    invariant_ext_len: usize,

    /// Executed once per range, before the row loop.
    pub fn invariantBase(self: Plan) []const eval.BaseInst {
        return self.base_storage[0..self.invariant_base_len];
    }

    /// Executed once per four-row group.
    pub fn loopBase(self: Plan) []const eval.BaseInst {
        return self.base_storage[self.invariant_base_len..];
    }

    pub fn invariantExt(self: Plan) []const eval.ExtInst {
        return self.ext_storage[0..self.invariant_ext_len];
    }

    pub fn loopExt(self: Plan) []const eval.ExtInst {
        return self.ext_storage[self.invariant_ext_len..];
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.ext_storage);
        allocator.free(self.base_storage);
        self.* = undefined;
    }
};

pub fn build(allocator: std.mem.Allocator, program: eval.Program) !Plan {
    const base_writes = try allocator.alloc(u32, program.header.max_base_regs);
    defer allocator.free(base_writes);
    @memset(base_writes, 0);
    for (program.base_insts) |instruction| base_writes[instruction.dst] += 1;

    const ext_writes = try allocator.alloc(u32, program.header.max_ext_regs);
    defer allocator.free(ext_writes);
    @memset(ext_writes, 0);
    for (program.ext_insts) |instruction| ext_writes[instruction.dst] += 1;

    const base_storage = try allocator.alloc(eval.BaseInst, program.base_insts.len);
    errdefer allocator.free(base_storage);
    const invariant_base_len = partition(
        eval.BaseInst,
        isInvariantBase,
        program.base_insts,
        base_writes,
        base_storage,
    );

    const ext_storage = try allocator.alloc(eval.ExtInst, program.ext_insts.len);
    errdefer allocator.free(ext_storage);
    const invariant_ext_len = partition(
        eval.ExtInst,
        isInvariantExt,
        program.ext_insts,
        ext_writes,
        ext_storage,
    );

    return .{
        .base_storage = base_storage,
        .ext_storage = ext_storage,
        .invariant_base_len = invariant_base_len,
        .invariant_ext_len = invariant_ext_len,
    };
}

/// Stable partition: invariant instructions first, both partitions keeping
/// their original relative order. Returns the invariant prefix length.
fn partition(
    comptime Inst: type,
    comptime invariant: fn (Inst, []const u32) bool,
    source: []const Inst,
    writes: []const u32,
    destination: []Inst,
) usize {
    var head: usize = 0;
    for (source) |instruction| {
        if (!invariant(instruction, writes)) continue;
        destination[head] = instruction;
        head += 1;
    }
    var tail = head;
    for (source) |instruction| {
        if (invariant(instruction, writes)) continue;
        destination[tail] = instruction;
        tail += 1;
    }
    return head;
}

fn isInvariantBase(instruction: eval.BaseInst, writes: []const u32) bool {
    return instruction.op == .constant and writes[instruction.dst] == 1;
}

fn isInvariantExt(instruction: eval.ExtInst, writes: []const u32) bool {
    return (instruction.op == .param or instruction.op == .constant) and
        writes[instruction.dst] == 1;
}

test "program plan: stable partition keeps both orders and hoists only unique dsts" {
    const allocator = std.testing.allocator;
    const insts = [_]eval.BaseInst{
        .{ .op = .constant, .interaction = 0, .dst = 0, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .trace_col, .interaction = 1, .dst = 1, .a = 0, .b = 0, .imm = 0 },
        // Written twice, so it must stay in the row loop even though it is a
        // constant: hoisting it would change what the second write observes.
        .{ .op = .constant, .interaction = 0, .dst = 2, .a = 9, .b = 0, .imm = 0 },
        .{ .op = .add, .interaction = 0, .dst = 2, .a = 0, .b = 1, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 3, .a = 11, .b = 0, .imm = 0 },
    };
    var writes = [_]u32{ 0, 0, 0, 0 };
    for (insts) |instruction| writes[instruction.dst] += 1;
    const storage = try allocator.alloc(eval.BaseInst, insts.len);
    defer allocator.free(storage);
    const head = partition(eval.BaseInst, isInvariantBase, &insts, &writes, storage);

    try std.testing.expectEqual(@as(usize, 2), head);
    try std.testing.expectEqual(@as(u32, 7), storage[0].a);
    try std.testing.expectEqual(@as(u32, 11), storage[1].a);
    try std.testing.expectEqual(eval.BaseOpcode.trace_col, storage[2].op);
    try std.testing.expectEqual(eval.BaseOpcode.constant, storage[3].op);
    try std.testing.expectEqual(@as(u32, 9), storage[3].a);
    try std.testing.expectEqual(eval.BaseOpcode.add, storage[4].op);
}

test "program plan: build partitions a program end to end" {
    const allocator = std.testing.allocator;
    const program = eval.Program{
        .allocator = allocator,
        .header = .{
            .flags = 0,
            .semantic_hash = 0,
            .capability_bits = 0,
            .n_interactions = 3,
            .n_base_params = 0,
            .n_ext_params = 2,
            .n_constraints = 1,
            .max_base_regs = 2,
            .max_ext_regs = 3,
            .domain_log_size = 4,
        },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = @constCast(&[_]eval.BaseInst{
            .{ .op = .trace_col, .interaction = 1, .dst = 0, .a = 0, .b = 0, .imm = 0 },
            .{ .op = .constant, .interaction = 0, .dst = 1, .a = 5, .b = 0, .imm = 0 },
        }),
        .ext_insts = @constCast(&[_]eval.ExtInst{
            .{ .op = .param, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
            .{ .op = .secure_col, .dst = 1, .a = 0, .b = 1, .c = 0, .d = 1 },
            .{ .op = .constant, .dst = 2, .a = 3, .b = 0, .c = 0, .d = 0 },
        }),
        .constraint_roots = @constCast(&[_]u32{1}),
    };
    var plan = try build(allocator, program);
    defer plan.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), plan.invariantBase().len);
    try std.testing.expectEqual(eval.BaseOpcode.constant, plan.invariantBase()[0].op);
    try std.testing.expectEqual(@as(usize, 1), plan.loopBase().len);
    try std.testing.expectEqual(eval.BaseOpcode.trace_col, plan.loopBase()[0].op);
    try std.testing.expectEqual(@as(usize, 2), plan.invariantExt().len);
    try std.testing.expectEqual(@as(usize, 1), plan.loopExt().len);
    try std.testing.expectEqual(eval.ExtOpcode.secure_col, plan.loopExt()[0].op);
}
