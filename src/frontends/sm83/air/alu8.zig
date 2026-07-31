//! Selector-shaped 8-bit ALU constraints.
//!
//! Values are bit-decomposed in the committed row, so byte and half-carry
//! meaning is enforced directly rather than assumed from witness generation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

pub const N_MAIN_COLUMNS: usize = 52;
pub const N_CONSTRAINTS: usize = 70;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 38;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,

    pub fn init(trace: runner.StepTrace) error{NotAlu8}!ValidatedStep {
        if (trace.decoded.instruction.family() != .alu8) return error.NotAlu8;
        return .{ .trace = trace };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            selectors: [8]S,
            sources: [9]S,
            lhs_bits: [8]S,
            rhs_bits: [8]S,
            result_bits: [8]S,
            input_flags: [4]S,
            zero_inverse: S,
            zero: S,
            subtract: S,
            half_carry: S,
            carry: S,
            pc_carry: S,
            fetch_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .selectors = values[0..8].*,
                    .sources = values[8..17].*,
                    .lhs_bits = values[17..25].*,
                    .rhs_bits = values[25..33].*,
                    .result_bits = values[33..41].*,
                    .input_flags = values[41..45].*,
                    .zero_inverse = values[45],
                    .zero = values[46],
                    .subtract = values[47],
                    .half_carry = values[48],
                    .carry = values[49],
                    .pc_carry = values[50],
                    .fetch_carry = values[51],
                };
            }
        };

        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub const BoundEvaluation = struct {
            values: [N_BOUND_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value| if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;
            const one = S.one();

            var active = S.zero();
            for (row.selectors) |selector| {
                out[index] = bit(selector);
                index += 1;
                active = active.add(selector);
            }
            out[index] = bit(active);
            index += 1;
            var source_active = S.zero();
            for (row.sources) |selector| {
                out[index] = bit(selector);
                index += 1;
                source_active = source_active.add(selector);
            }
            out[index] = source_active.sub(active);
            index += 1;
            for (row.lhs_bits ++ row.rhs_bits ++ row.result_bits) |value| {
                out[index] = bit(value);
                index += 1;
            }
            for (row.input_flags ++ [4]S{
                row.zero,
                row.subtract,
                row.half_carry,
                row.carry,
            }) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = active.sub(is_active);
            index += 1;

            const lhs = compose(row.lhs_bits);
            const rhs = compose(row.rhs_bits);
            const result = compose(row.result_bits);
            const lhs_low = compose(row.lhs_bits[0..4].*);
            const rhs_low = compose(row.rhs_bits[0..4].*);
            const result_low = compose(row.result_bits[0..4].*);
            const add = row.selectors[0].add(row.selectors[1]);
            const sub = row.selectors[2].add(row.selectors[3]).add(row.selectors[7]);
            const bitwise = row.selectors[4].add(row.selectors[5]).add(row.selectors[6]);
            const carry_used = row.input_flags[3].mul(
                row.selectors[1].add(row.selectors[3]),
            );

            out[index] = active.mul(result).mul(row.zero);
            index += 1;
            out[index] = active.mul(
                result.mul(row.zero_inverse).sub(one.sub(row.zero)),
            );
            index += 1;
            out[index] = row.subtract.sub(sub);
            index += 1;
            out[index] = add.mul(
                lhs.add(rhs).add(carry_used).sub(result).sub(q(256).mul(row.carry)),
            );
            index += 1;
            out[index] = sub.mul(
                lhs.sub(rhs).sub(carry_used).sub(result).add(q(256).mul(row.carry)),
            );
            index += 1;
            out[index] = add.mul(
                lhs_low.add(rhs_low).add(carry_used).sub(result_low)
                    .sub(q(16).mul(row.half_carry)),
            );
            index += 1;
            out[index] = sub.mul(
                lhs_low.sub(rhs_low).sub(carry_used).sub(result_low)
                    .add(q(16).mul(row.half_carry)),
            );
            index += 1;

            for (row.lhs_bits, row.rhs_bits, row.result_bits) |left, right, actual| {
                const product = left.mul(right);
                const and_expected = product;
                const xor_expected = left.add(right).sub(q(2).mul(product));
                const or_expected = left.add(right).sub(product);
                out[index] = row.selectors[4].mul(actual.sub(and_expected))
                    .add(row.selectors[5].mul(actual.sub(xor_expected)))
                    .add(row.selectors[6].mul(actual.sub(or_expected)));
                index += 1;
            }
            out[index] = row.selectors[4].mul(row.half_carry.sub(one));
            index += 1;
            out[index] = row.selectors[5].add(row.selectors[6]).mul(row.half_carry);
            index += 1;
            out[index] = bitwise.mul(row.carry);
            index += 1;

            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        pub fn evaluateBound(
            row: Row,
            machine: execution.Row(S),
            is_active: S,
        ) BoundEvaluation {
            const semantic = Self.evaluate(row, is_active);
            var out: [N_BOUND_CONSTRAINTS]S = undefined;
            @memcpy(out[0..N_CONSTRAINTS], &semantic.values);
            var index: usize = N_CONSTRAINTS;
            const one = S.one();
            const lhs = compose(row.lhs_bits);
            const rhs = compose(row.rhs_bits);
            const result = compose(row.result_bits);
            const immediate = row.sources[8];
            const indirect_hl = row.sources[6];
            const second_cycle = immediate.add(indirect_hl);
            var operation_index = S.zero();
            for (row.selectors, 0..) |selector, operation| {
                operation_index = operation_index.add(q(operation).mul(selector));
            }
            var source_index = S.zero();
            for (row.sources[0..8], 0..) |selector, source| {
                source_index = source_index.add(q(source).mul(selector));
            }
            const register_opcode = q(0x80)
                .add(q(8).mul(operation_index))
                .add(source_index);
            const immediate_opcode = q(0xc6).add(q(8).mul(operation_index));
            const opcode = is_active.sub(immediate).mul(register_opcode)
                .add(immediate.mul(immediate_opcode));
            out[index] = is_active.mul(machine.bus[0].value.sub(opcode));
            index += 1;

            const before_a = machine.before.at(.a);
            out[index] = is_active.mul(lhs.sub(before_a));
            index += 1;
            const source_values = [9]S{
                machine.before.at(.b),
                machine.before.at(.c),
                machine.before.at(.d),
                machine.before.at(.e),
                machine.before.at(.h),
                machine.before.at(.l),
                machine.bus[1].value,
                before_a,
                machine.bus[1].value,
            };
            var expected_rhs = S.zero();
            for (row.sources, source_values) |selector, value| {
                expected_rhs = expected_rhs.add(selector.mul(value));
            }
            out[index] = is_active.mul(rhs).sub(expected_rhs);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f)).sub(
                flags(row.input_flags),
            );
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f)).sub(flags(.{
                row.zero,
                row.subtract,
                row.half_carry,
                row.carry,
            }));
            index += 1;
            const compare = row.selectors[7];
            out[index] = is_active.mul(machine.after.at(.a))
                .sub(is_active.sub(compare).mul(result))
                .sub(compare.mul(before_a));
            index += 1;
            out[index] = is_active.mul(
                machine.after.at(.pc)
                    .sub(machine.before.at(.pc))
                    .sub(one)
                    .sub(immediate)
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;
            out[index] = bit(row.pc_carry);
            index += 1;
            out[index] = row.pc_carry.mul(one.sub(is_active));
            index += 1;
            out[index] = bit(row.fetch_carry);
            index += 1;
            out[index] = row.fetch_carry.mul(one.sub(immediate));
            index += 1;

            out[index] = is_active.mul(machine.bus[0].active.sub(one));
            index += 1;
            out[index] = is_active.mul(machine.bus[0].read.sub(one));
            index += 1;
            out[index] = is_active.mul(machine.bus[0].write);
            index += 1;
            out[index] = is_active.mul(machine.bus[0].program.sub(one));
            index += 1;
            out[index] = is_active.mul(
                machine.bus[0].address.sub(machine.before.at(.pc)),
            );
            index += 1;

            out[index] = is_active.mul(machine.bus[1].active.sub(second_cycle));
            index += 1;
            out[index] = is_active.mul(machine.bus[1].read.sub(second_cycle));
            index += 1;
            out[index] = is_active.mul(machine.bus[1].write);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].program.sub(immediate));
            index += 1;
            out[index] = is_active.mul(
                machine.bus[1].value.sub(second_cycle.mul(rhs)),
            );
            index += 1;
            const hl = q(256).mul(machine.before.at(.h))
                .add(machine.before.at(.l));
            const next_pc = machine.before.at(.pc).add(one)
                .sub(q(65536).mul(row.fetch_carry));
            out[index] = is_active.mul(
                machine.bus[1].address
                    .sub(immediate.mul(next_pc))
                    .sub(indirect_hl.mul(hl)),
            );
            index += 1;
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;
            for (machine.bus[2..]) |cycle| {
                out[index] = is_active.mul(cycle.active);
                index += 1;
            }
            for ([_]execution.StateIndex{
                .b,
                .c,
                .d,
                .e,
                .h,
                .l,
                .sp,
            }) |field| {
                out[index] = is_active.mul(
                    machine.after.at(field).sub(machine.before.at(field)),
                );
                index += 1;
            }
            for (execution.imeDelayConstraints(
                S,
                machine.before,
                machine.after,
            )) |constraint| {
                out[index] = is_active.mul(constraint);
                index += 1;
            }
            for ([_]execution.StateIndex{ .halted, .stopped }) |field| {
                out[index] = is_active.mul(
                    machine.after.at(field).sub(machine.before.at(field)),
                );
                index += 1;
            }

            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }

        fn compose(bits: anytype) S {
            var value = S.zero();
            inline for (bits, 0..) |bit_value, bit_index| {
                value = value.add(q(@as(u64, 1) << bit_index).mul(bit_value));
            }
            return value;
        }

        fn flags(values: [4]S) S {
            return q(128).mul(values[0])
                .add(q(64).mul(values[1]))
                .add(q(32).mul(values[2]))
                .add(q(16).mul(values[3]));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const trace = step.trace;
    const operation = trace.decoded.instruction.operation;
    const lhs = trace.before.a;
    const rhs = sourceValue(trace);
    const result = trace.result orelse unreachable;
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[selectorIndex(operation)] = M31.one();
    output[8 + sourceIndex(trace.decoded.instruction.src)] = M31.one();
    writeBits(output[17..25], lhs);
    writeBits(output[25..33], rhs);
    writeBits(output[33..41], result);
    output[41] = M31.fromCanonical(@intFromBool(trace.before.flag(.zero)));
    output[42] = M31.fromCanonical(@intFromBool(trace.before.flag(.subtract)));
    output[43] = M31.fromCanonical(@intFromBool(trace.before.flag(.half_carry)));
    output[44] = M31.fromCanonical(@intFromBool(trace.before.flag(.carry)));
    output[45] = if (result == 0)
        M31.zero()
    else
        M31.fromCanonical(result).inv() catch unreachable;
    output[46] = M31.fromCanonical(@intFromBool(trace.after.flag(.zero)));
    output[47] = M31.fromCanonical(@intFromBool(trace.after.flag(.subtract)));
    output[48] = M31.fromCanonical(@intFromBool(trace.after.flag(.half_carry)));
    output[49] = M31.fromCanonical(@intFromBool(trace.after.flag(.carry)));
    const pc_sum = @as(u32, trace.before.pc) + trace.decoded.instruction.length;
    output[50] = M31.fromCanonical(@intFromBool(pc_sum > 0xffff));
    output[51] = M31.fromCanonical(@intFromBool(
        trace.decoded.instruction.src == .imm8 and trace.before.pc == 0xffff,
    ));
    return output;
}

pub fn evaluate(columns_value: [N_MAIN_COLUMNS]M31) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns_value) |*destination, value| destination.* = QM31.fromBase(value);
    return Shipped.evaluate(try Shipped.Row.fromColumns(&lifted), QM31.one());
}

pub fn evaluateBound(
    columns_value: [N_MAIN_COLUMNS]M31,
    execution_columns: [execution.N_MAIN_COLUMNS]M31,
) !Shipped.BoundEvaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, columns_value) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    for (&machine, execution_columns) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    return Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine),
        QM31.one(),
    );
}

fn sourceValue(trace: runner.StepTrace) u8 {
    const source = trace.decoded.instruction.src;
    return switch (source) {
        .a => trace.before.a,
        .b => trace.before.b,
        .c => trace.before.c,
        .d => trace.before.d,
        .e => trace.before.e,
        .h => trace.before.h,
        .l => trace.before.l,
        .imm8 => @truncate(trace.decoded.immediate),
        .indirect_hl => blk: {
            for (trace.activeCycles()[trace.decoded.instruction.length..]) |cycle| {
                if (cycle.action == .read) break :blk cycle.value;
            }
            unreachable;
        },
        else => unreachable,
    };
}

fn selectorIndex(operation: isa.Operation) usize {
    return switch (operation) {
        .add8 => 0,
        .add_carry8 => 1,
        .subtract8 => 2,
        .subtract_carry8 => 3,
        .and8 => 4,
        .xor8 => 5,
        .or8 => 6,
        .compare8 => 7,
        else => unreachable,
    };
}

fn sourceIndex(source: isa.Operand) usize {
    return switch (source) {
        .b => 0,
        .c => 1,
        .d => 2,
        .e => 3,
        .h => 4,
        .l => 5,
        .indirect_hl => 6,
        .a => 7,
        .imm8 => 8,
        else => unreachable,
    };
}

fn writeBits(destination: []M31, value: u8) void {
    std.debug.assert(destination.len == 8);
    for (destination, 0..) |*bit_value, bit_index| {
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
    }
}

test "ALU8 AIR accepts an honest half-carry row and rejects mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0xc6);
    memory.write(1, 1);
    var state = runner.Cpu{ .a = 0x0f };
    const trace = try runner.step(&state, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    try std.testing.expect((try evaluate(witness)).allZero());

    witness[48] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness[48] = M31.one();
    witness[33] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
}

test "ALU8 AIR binds opcode state bus and cycle semantics" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0xc6);
    memory.write(1, 1);
    var state = runner.Cpu{
        .a = 0x0f,
        .ime_enable_pending = true,
    };
    const trace = try runner.step(&state, &memory);
    try std.testing.expect(trace.after.ime);
    try std.testing.expect(!trace.after.ime_enable_pending);
    const witness = columns(try ValidatedStep.init(trace));
    var machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());
    machine[2 * execution.N_STATE_COLUMNS + 1] = M31.fromCanonical(0xd6);
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
}
