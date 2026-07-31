//! Direct and execution-bound constraints for RLCA, RRCA, RLA, and RRA.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

pub const N_MAIN_COLUMNS: usize = 29;
pub const N_CONSTRAINTS: usize = 42;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 58;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,

    pub fn init(
        trace: runner.StepTrace,
    ) error{NotAccumulatorRotate}!ValidatedStep {
        const instruction = trace.decoded.instruction;
        const operation = operationIndex(instruction.operation) orelse
            return error.NotAccumulatorRotate;
        if (instruction.family() != .rotate_accumulator or
            instruction.dst != .a or
            instruction.src != .none or
            instruction.condition != .always or
            instruction.length != 1 or
            instruction.m_cycles != 1 or
            instruction.taken_m_cycles != 1 or
            instruction.parameter != 0 or
            trace.decoded.raw_opcode != opcode(operation) or
            trace.decoded.immediate != 0)
        {
            return error.NotAccumulatorRotate;
        }
        return .{ .trace = trace };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [4]S,
            before_bits: [8]S,
            after_bits: [8]S,
            input_flags: [4]S,
            output_flags: [4]S,
            pc_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..4].*,
                    .before_bits = values[4..12].*,
                    .after_bits = values[12..20].*,
                    .input_flags = values[20..24].*,
                    .output_flags = values[24..28].*,
                    .pc_carry = values[28],
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

            var operation_active = S.zero();
            for (row.operations) |selector| {
                out[index] = bit(selector);
                index += 1;
                operation_active = operation_active.add(selector);
            }
            out[index] = operation_active.sub(is_active);
            index += 1;

            for (
                row.before_bits ++ row.after_bits ++
                    row.input_flags ++ row.output_flags,
            ) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = bit(row.pc_carry);
            index += 1;

            out[index] = row.output_flags[0];
            index += 1;
            out[index] = row.output_flags[1];
            index += 1;
            out[index] = row.output_flags[2];
            index += 1;

            const input_carry = row.input_flags[3];
            for (row.after_bits, 0..) |after_bit, bit_index| {
                const left_source = if (bit_index == 0)
                    row.before_bits[7]
                else
                    row.before_bits[bit_index - 1];
                const right_source = if (bit_index == 7)
                    row.before_bits[0]
                else
                    row.before_bits[bit_index + 1];
                const expected = row.operations[0].mul(left_source)
                    .add(row.operations[1].mul(right_source))
                    .add(row.operations[2].mul(
                        if (bit_index == 0) input_carry else left_source,
                    ))
                    .add(row.operations[3].mul(
                    if (bit_index == 7) input_carry else right_source,
                ));
                out[index] = after_bit.sub(expected);
                index += 1;
            }

            out[index] = row.output_flags[3].sub(
                row.operations[0].add(row.operations[2]).mul(row.before_bits[7])
                    .add(
                    row.operations[1].add(row.operations[3]).mul(
                        row.before_bits[0],
                    ),
                ),
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

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            var expected_opcode = S.zero();
            inline for (0..4) |operation| {
                expected_opcode = expected_opcode.add(
                    q(opcode(operation)).mul(row.operations[operation]),
                );
            }
            out[index] = is_active.mul(machine.bus[0].value)
                .sub(expected_opcode);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.a).sub(before));
            index += 1;
            out[index] = is_active.mul(machine.after.at(.a).sub(after));
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f))
                .sub(is_active.mul(flags(row.input_flags)));
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f))
                .sub(is_active.mul(flags(row.output_flags)));
            index += 1;

            out[index] = is_active.mul(
                machine.after.at(.pc)
                    .sub(machine.before.at(.pc))
                    .sub(one)
                    .add(q(65536).mul(row.pc_carry)),
            );
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
            for (machine.bus[1..]) |cycle| {
                out[index] = is_active.mul(cycle.active);
                index += 1;
            }
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;

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

        fn compose(bits: [8]S) S {
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
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[operationIndex(trace.decoded.instruction.operation).?] = M31.one();
    writeBits(output[4..12], trace.before.a);
    writeBits(output[12..20], trace.after.a);
    writeFlags(output[20..24], trace.before);
    writeFlags(output[24..28], trace.after);
    output[28] = boolean(trace.before.pc == 0xffff);
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

fn operationIndex(operation: isa.Operation) ?usize {
    return switch (operation) {
        .rotate_left_circular_a => 0,
        .rotate_right_circular_a => 1,
        .rotate_left_a => 2,
        .rotate_right_a => 3,
        else => null,
    };
}

fn opcode(operation: usize) u8 {
    std.debug.assert(operation < 4);
    return @intCast(0x07 + 8 * operation);
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

test "accumulator rotate AIR exhaustively binds all four operations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();

    var cases: usize = 0;
    for (0..4) |operation| {
        memory.write(0xffff, opcode(operation));
        for (0..256) |a| {
            for (0..2) |input_carry| {
                var cpu = runner.Cpu{
                    .a = @intCast(a),
                    .b = 0x12,
                    .c = 0x34,
                    .d = 0x56,
                    .e = 0x78,
                    .f = 0xe0 | (@as(u8, @intCast(input_carry)) << 4),
                    .h = 0x9a,
                    .l = 0xbc,
                    .sp = 0xdef0,
                    .pc = 0xffff,
                    .ime = true,
                    .ime_enable_pending = true,
                    .halted = true,
                    .stopped = true,
                };
                const trace = try runner.step(&cpu, &memory);
                const witness = columns(try ValidatedStep.init(trace));
                try std.testing.expect((try evaluate(witness)).allZero());
                try std.testing.expect(
                    (try evaluateBound(
                        witness,
                        execution.columns(trace, 7),
                    )).allZero(),
                );
                cases += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 4 * 256 * 2), cases);
}

test "accumulator rotate AIR rejects result carry opcode state bus and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x17);
    var cpu = runner.Cpu{
        .a = 0x80,
        .b = 0x22,
        .f = 0xf0,
        .sp = 0xcafe,
        .ime = true,
    };
    const trace = try runner.step(&cpu, &memory);
    const honest = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(honest, machine)).allZero());

    var witness = honest;
    witness[12] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    witness = honest;
    witness[27] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    var forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS + 1] =
        M31.fromCanonical(0x07);
    try std.testing.expect(
        !(try evaluateBound(honest, forged_machine)).allZero(),
    );

    forged_machine = machine;
    forged_machine[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.b)
    ] = M31.fromCanonical(0x23);
    try std.testing.expect(
        !(try evaluateBound(honest, forged_machine)).allZero(),
    );

    forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS] = M31.one();
    try std.testing.expect(
        !(try evaluateBound(honest, forged_machine)).allZero(),
    );

    witness = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    try std.testing.expect(!(try evaluate(witness)).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0x07;
    try std.testing.expectError(
        error.NotAccumulatorRotate,
        ValidatedStep.init(forged_trace),
    );

    memory.write(0, 0x00);
    cpu.pc = 0;
    const nop = try runner.step(&cpu, &memory);
    try std.testing.expectError(
        error.NotAccumulatorRotate,
        ValidatedStep.init(nop),
    );
}
