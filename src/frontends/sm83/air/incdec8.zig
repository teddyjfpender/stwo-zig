//! Direct and execution-bound constraints for SM83 INC r8 and DEC r8.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

pub const N_MAIN_COLUMNS: usize = 37;
pub const N_CONSTRAINTS: usize = 45;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 77;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,

    pub fn init(
        trace: runner.StepTrace,
    ) error{NotIncrementDecrement8}!ValidatedStep {
        const instruction = trace.decoded.instruction;
        const target = targetIndex(instruction.dst) orelse
            return error.NotIncrementDecrement8;
        const expected_opcode: u16 =
            4 + 8 * @as(u16, @intCast(target)) +
            @as(u16, @intFromBool(instruction.operation == .decrement8));
        const expected_cycles: u3 = if (instruction.dst == .indirect_hl) 3 else 1;
        if (instruction.family() != .increment_decrement8 or
            instruction.src != .none or
            instruction.condition != .always or
            instruction.length != 1 or
            instruction.m_cycles != expected_cycles or
            instruction.taken_m_cycles != expected_cycles or
            instruction.parameter != 0 or
            trace.decoded.raw_opcode != expected_opcode or
            trace.decoded.immediate != 0)
        {
            return error.NotIncrementDecrement8;
        }
        return .{ .trace = trace };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [2]S,
            targets: [8]S,
            before_bits: [8]S,
            after_bits: [8]S,
            input_flags: [4]S,
            output_flags: [4]S,
            zero_inverse: S,
            wrap: S,
            pc_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..2].*,
                    .targets = values[2..10].*,
                    .before_bits = values[10..18].*,
                    .after_bits = values[18..26].*,
                    .input_flags = values[26..30].*,
                    .output_flags = values[30..34].*,
                    .zero_inverse = values[34],
                    .wrap = values[35],
                    .pc_carry = values[36],
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

            var operation_active = S.zero();
            for (row.operations) |selector| {
                out[index] = bit(selector);
                index += 1;
                operation_active = operation_active.add(selector);
            }
            out[index] = operation_active.sub(is_active);
            index += 1;

            var target_active = S.zero();
            for (row.targets) |selector| {
                out[index] = bit(selector);
                index += 1;
                target_active = target_active.add(selector);
            }
            out[index] = target_active.sub(is_active);
            index += 1;

            for (row.before_bits ++ row.after_bits) |value| {
                out[index] = bit(value);
                index += 1;
            }
            for (row.input_flags ++ row.output_flags) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = bit(row.wrap);
            index += 1;

            const increment = row.operations[0];
            const decrement = row.operations[1];
            const before = compose(row.before_bits);
            const after = compose(row.after_bits);
            const before_low = compose(row.before_bits[0..4].*);
            const after_low = compose(row.after_bits[0..4].*);
            const output_zero = row.output_flags[0];
            const output_subtract = row.output_flags[1];
            const output_half_carry = row.output_flags[2];
            const output_carry = row.output_flags[3];

            out[index] = after.mul(output_zero);
            index += 1;
            out[index] = after.mul(row.zero_inverse)
                .sub(is_active.sub(output_zero));
            index += 1;
            out[index] = output_subtract.sub(decrement);
            index += 1;
            out[index] = output_carry.sub(row.input_flags[3]);
            index += 1;
            out[index] = increment.mul(
                before.add(one).sub(after).sub(q(256).mul(row.wrap)),
            );
            index += 1;
            out[index] = decrement.mul(
                before.sub(one).sub(after).add(q(256).mul(row.wrap)),
            );
            index += 1;
            out[index] = increment.mul(
                before_low.add(one).sub(after_low)
                    .sub(q(16).mul(output_half_carry)),
            );
            index += 1;
            out[index] = decrement.mul(
                before_low.sub(one).sub(after_low)
                    .add(q(16).mul(output_half_carry)),
            );
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
            const before = compose(row.before_bits);
            const after = compose(row.after_bits);
            const indirect_hl = row.targets[6];

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            var selected_target = S.zero();
            for (row.targets, 0..) |selector, target| {
                selected_target = selected_target.add(q(target).mul(selector));
            }
            const expected_opcode = q(4).mul(is_active)
                .add(q(8).mul(selected_target))
                .add(row.operations[1]);
            out[index] = is_active.mul(machine.bus[0].value)
                .sub(expected_opcode);
            index += 1;

            const source_values = [8]S{
                machine.before.at(.b),
                machine.before.at(.c),
                machine.before.at(.d),
                machine.before.at(.e),
                machine.before.at(.h),
                machine.before.at(.l),
                machine.bus[1].value,
                machine.before.at(.a),
            };
            var expected_before = S.zero();
            for (row.targets, source_values) |selector, value| {
                expected_before = expected_before.add(selector.mul(value));
            }
            out[index] = is_active.mul(before).sub(expected_before);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f)).sub(
                flags(row.input_flags),
            );
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f)).sub(
                flags(row.output_flags),
            );
            index += 1;

            const register_fields = [_]execution.StateIndex{
                .b, .c, .d, .e, .h, .l, .a,
            };
            const register_targets = [_]usize{ 0, 1, 2, 3, 4, 5, 7 };
            for (register_fields, register_targets) |field, target| {
                out[index] = is_active.mul(
                    machine.after.at(field).sub(machine.before.at(field)),
                ).sub(
                    row.targets[target].mul(
                        after.sub(machine.before.at(field)),
                    ),
                );
                index += 1;
            }

            out[index] = is_active.mul(
                machine.after.at(.pc)
                    .sub(machine.before.at(.pc))
                    .sub(one)
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;
            out[index] = bit(row.pc_carry);
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

            const hl = q(256).mul(machine.before.at(.h))
                .add(machine.before.at(.l));
            out[index] = is_active.mul(machine.bus[1].active).sub(indirect_hl);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].read).sub(indirect_hl);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].write);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].program);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].address)
                .sub(indirect_hl.mul(hl));
            index += 1;
            out[index] = is_active.mul(machine.bus[1].value)
                .sub(indirect_hl.mul(before));
            index += 1;

            out[index] = is_active.mul(machine.bus[2].active).sub(indirect_hl);
            index += 1;
            out[index] = is_active.mul(machine.bus[2].read);
            index += 1;
            out[index] = is_active.mul(machine.bus[2].write).sub(indirect_hl);
            index += 1;
            out[index] = is_active.mul(machine.bus[2].program);
            index += 1;
            out[index] = is_active.mul(machine.bus[2].address)
                .sub(indirect_hl.mul(hl));
            index += 1;
            out[index] = is_active.mul(machine.bus[2].value)
                .sub(indirect_hl.mul(after));
            index += 1;
            for (machine.bus[3..]) |cycle| {
                out[index] = is_active.mul(cycle.active);
                index += 1;
            }
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;
            for ([_]execution.StateIndex{.sp}) |field| {
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
    const target = targetIndex(trace.decoded.instruction.dst).?;
    const before = targetValue(trace.before, trace, target, false);
    const after = targetValue(trace.after, trace, target, true);
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[@intFromBool(operation == .decrement8)] = M31.one();
    output[2 + target] = M31.one();
    writeBits(output[10..18], before);
    writeBits(output[18..26], after);
    writeFlags(output[26..30], trace.before);
    writeFlags(output[30..34], trace.after);
    output[34] = if (after == 0)
        M31.zero()
    else
        M31.fromCanonical(after).inv() catch unreachable;
    output[35] = boolean(if (operation == .increment8)
        before == 0xff
    else
        before == 0);
    output[36] = boolean(trace.before.pc == 0xffff);
    return output;
}

pub fn evaluate(values: [N_MAIN_COLUMNS]M31) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    return Shipped.evaluate(
        try Shipped.Row.fromColumns(&lifted),
        QM31.one(),
    );
}

pub fn evaluateBound(
    values: [N_MAIN_COLUMNS]M31,
    execution_values: [execution.N_MAIN_COLUMNS]M31,
) !Shipped.BoundEvaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    for (&machine, execution_values) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    return Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine),
        QM31.one(),
    );
}

fn targetIndex(target: isa.Operand) ?usize {
    return switch (target) {
        .b => 0,
        .c => 1,
        .d => 2,
        .e => 3,
        .h => 4,
        .l => 5,
        .indirect_hl => 6,
        .a => 7,
        else => null,
    };
}

fn targetValue(
    cpu: runner.Cpu,
    trace: runner.StepTrace,
    target: usize,
    after: bool,
) u8 {
    return switch (target) {
        0 => cpu.b,
        1 => cpu.c,
        2 => cpu.d,
        3 => cpu.e,
        4 => cpu.h,
        5 => cpu.l,
        6 => trace.cycles[if (after) 2 else 1].value,
        7 => cpu.a,
        else => unreachable,
    };
}

fn setTarget(cpu: *runner.Cpu, memory: *runner.Memory, target: usize, value: u8) void {
    switch (target) {
        0 => cpu.b = value,
        1 => cpu.c = value,
        2 => cpu.d = value,
        3 => cpu.e = value,
        4 => cpu.h = value,
        5 => cpu.l = value,
        6 => memory.write(cpu.hl(), value),
        7 => cpu.a = value,
        else => unreachable,
    }
}

fn writeBits(destination: []M31, value: u8) void {
    std.debug.assert(destination.len == 8);
    for (destination, 0..) |*bit_value, bit_index| {
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
    }
}

fn writeFlags(destination: []M31, cpu: runner.Cpu) void {
    std.debug.assert(destination.len == 4);
    destination[0] = boolean(cpu.flag(.zero));
    destination[1] = boolean(cpu.flag(.subtract));
    destination[2] = boolean(cpu.flag(.half_carry));
    destination[3] = boolean(cpu.flag(.carry));
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "INC DEC r8 AIR exhaustively binds semantics and execution" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();

    for (0..8) |target| {
        for (0..2) |operation| {
            const opcode: u8 = @intCast(4 + 8 * target + operation);
            memory.write(0, opcode);
            for (0..256) |value| {
                for (0..2) |carry| {
                    var cpu = runner.Cpu{
                        .a = 0x11,
                        .b = 0x22,
                        .c = 0x33,
                        .d = 0x44,
                        .e = 0x55,
                        .f = @as(u8, @intCast(carry)) << 4,
                        .h = 0x80,
                        .l = 0x00,
                        .sp = 0xcafe,
                        .ime = true,
                        .ime_enable_pending = true,
                    };
                    setTarget(&cpu, &memory, target, @intCast(value));
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect(
                        (try evaluateBound(
                            witness,
                            execution.columns(trace, 0),
                        )).allZero(),
                    );
                }
            }
        }
    }
}

test "INC DEC r8 AIR rejects semantic bus state and family mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x34);
    memory.write(0x8000, 0x0f);
    var cpu = runner.Cpu{ .f = 0x10, .h = 0x80 };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[32] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[18] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    var forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS + 1] =
        M31.fromCanonical(0x35);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS + execution.N_BUS_COLUMNS + 0] =
        M31.fromCanonical(0x8001);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS + 2 * execution.N_BUS_COLUMNS + 1] =
        M31.fromCanonical(0x0f);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0x35;
    try std.testing.expectError(
        error.NotIncrementDecrement8,
        ValidatedStep.init(forged_trace),
    );

    memory.write(0, 0x00);
    cpu.pc = 0;
    const nop = try runner.step(&cpu, &memory);
    try std.testing.expectError(
        error.NotIncrementDecrement8,
        ValidatedStep.init(nop),
    );
}
