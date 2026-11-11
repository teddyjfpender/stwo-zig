//! Immutable OP Miller-line arithmetic DAG. This is source-owned program
//! authority, not producer-supplied microcode. Production admission is closed.
const std = @import("std");
const wide = @import("spec.zig");
const base = @import("../curves/spec.zig");
const F = @import("../curves/native.zig").Bn;
pub const INPUTS = 20;
pub const STEPS = 32;
pub const VALUES = INPUTS + STEPS;
pub const ZERO: u8 = VALUES;
pub const NINE: u8 = VALUES + 1;
pub const OPERANDS = 7;
pub const Instruction = struct {
    products: [3][2]u8 = @splat(.{ ZERO, ZERO }),
    addend: u8 = ZERO,
    addend_negative: bool = false,
    output_negative: bool = true,
    output: u8,
    pub fn operands(self: Instruction) [OPERANDS]u8 {
        return .{ self.products[0][0], self.products[0][1], self.products[1][0], self.products[1][1], self.products[2][0], self.products[2][1], self.addend };
    }
};
fn value(v: base.Vec) u8 {
    return switch (v) {
        .in => |i| i,
        .wit => |i| 20 + i,
        .out => |i| 34 + i,
    };
}
/// Every old carried equation is factored into at most three positive scalar
/// products plus a signed addend/result. Six real equations need two steps.
/// The schedule is fixed by the same source relation authority as the reference.
pub const PROGRAM: [STEPS]Instruction = blk: {
    @setEvalBranchQuota(100_000);
    var program: [STEPS]Instruction = undefined;
    var at: usize = 0;
    var temporary: u8 = 46;
    for (wide.def(.mul034).relations) |terms| {
        const destination = terms[terms.len - 1];
        if (destination.b != null or destination.coef != -1) @compileError("DAG destination must be final negative linear term");
        var positive: [3][2]u8 = @splat(.{ ZERO, ZERO });
        var negative: [3][2]u8 = @splat(.{ ZERO, ZERO });
        var positives: usize = 0;
        var negatives: usize = 0;
        var addend: u8 = ZERO;
        var addend_negative = false;
        for (terms[0 .. terms.len - 1]) |term| {
            if (term.b) |b| {
                if (term.coef == 1) {
                    positive[positives] = .{ value(term.a), value(b) };
                    positives += 1;
                } else if (term.coef == -1) {
                    negative[negatives] = .{ value(term.a), value(b) };
                    negatives += 1;
                } else @compileError("unexpected signed product coefficient");
            } else if (term.coef == 9) {
                positive[positives] = .{ value(term.a), NINE };
                positives += 1;
            } else {
                if (addend != ZERO or (term.coef != 1 and term.coef != -1)) @compileError("DAG has more than one unit addend");
                addend = value(term.a);
                addend_negative = term.coef == -1;
            }
        }
        if (negatives != 0) {
            if (addend != ZERO or negatives != 3 or positives != 3) @compileError("unexpected real-half shape");
            program[at] = .{ .products = positive, .output = temporary };
            at += 1;
            // negative_products - positive_partial + result = 0.
            program[at] = .{ .products = negative, .addend = temporary, .addend_negative = true, .output_negative = false, .output = value(destination.a) };
            temporary += 1;
        } else {
            program[at] = .{ .products = positive, .addend = addend, .addend_negative = addend_negative, .output = value(destination.a) };
        }
        at += 1;
    }
    if (at != STEPS or temporary != VALUES) @compileError("incomplete immutable Miller-line DAG");
    break :blk program;
};
/// Exact read fanouts. Constants are fixed row literals and never bus entries.
/// Inputs are supplied by a 20-row/call authenticated Wire35 frontier. Every
/// intermediate has exactly one writer in PROGRAM; all reads have unit weight.
pub const FANOUT: [VALUES]u8 = blk: {
    var fanout: [VALUES]u8 = @splat(0);
    var available: [VALUES]bool = @splat(false);
    @memset(available[0..INPUTS], true);
    for (PROGRAM) |instruction| {
        for (instruction.operands()) |id| {
            if (id >= VALUES) {
                if (id != ZERO and id != NINE) @compileError("unknown immutable literal");
                continue;
            }
            if (!available[id]) @compileError("non-topological or invented SSA read");
            fanout[id] += 1;
        }
        if (available[instruction.output]) @compileError("repeated SSA writer");
        available[instruction.output] = true;
    }
    for (available) |yes| if (!yes) {
        @compileError("missing SSA writer");
    };
    for (fanout, 0..) |count, id| if (count == 0 and (id < 34 or id >= 46)) {
        @compileError("unused private value");
    };
    break :blk fanout;
};
pub fn literal(id: u8) ?u256 {
    return switch (id) {
        ZERO => 0,
        NINE => 9,
        else => null,
    };
}
pub fn read(values: *const [VALUES]u256, id: u8) u256 {
    return literal(id) orelse values[id];
}
pub fn result(instruction: Instruction, operands: *const [OPERANDS]u256) u256 {
    var sum: u256 = 0;
    for (0..3) |i| sum = F.add(sum, F.mul(operands[2 * i] % base.BN254_P, operands[2 * i + 1] % base.BN254_P));
    const addend = operands[6] % base.BN254_P;
    sum = if (instruction.addend_negative) F.sub(sum, addend) else F.add(sum, addend);
    return if (instruction.output_negative or sum == 0) sum else base.BN254_P - sum;
}
pub fn evaluate(input: *const [INPUTS]u256) [VALUES]u256 {
    var values: [VALUES]u256 = undefined;
    @memcpy(values[0..INPUTS], input);
    for (PROGRAM) |instruction| {
        var operands: [OPERANDS]u256 = undefined;
        for (&operands, instruction.operands()) |*operand, id| operand.* = read(&values, id);
        values[instruction.output] = result(instruction, &operands);
    }
    return values;
}
/// Exact source-owned local relation mass. Both sides count multiplicities,
/// never a producer-supplied fanout or a free negative weight.
pub const READS: usize = blk: {
    var sum: usize = 0;
    for (FANOUT) |n| sum += n;
    break :blk sum;
};
comptime {
    if (READS >= base.M31) @compileError("one DAG relation exceeds base-field mass");
}
