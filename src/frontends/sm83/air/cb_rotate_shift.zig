//! Direct and execution-bound constraints for all 64 CB rotate/shift opcodes.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_OPERATIONS = 8;
const N_TARGETS = 8;

pub const N_MAIN_COLUMNS: usize =
    N_OPERATIONS + N_TARGETS + 8 + 8 + 4 + 4 + 3;
pub const N_CONSTRAINTS: usize = 58;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 3 + 7 + 2 +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1 + 5;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    operation: usize,
    target: usize,

    pub fn init(trace: runner.StepTrace) error{NotCbRotateShift}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw < 0xcb00 or raw > 0xcb3f)
            return error.NotCbRotateShift;
        const suffix: u8 = @truncate(raw);
        const instruction = trace.decoded.instruction;
        const operation = operationIndex(instruction.operation) orelse
            return error.NotCbRotateShift;
        const target = targetIndex(instruction.dst) orelse
            return error.NotCbRotateShift;
        const expected_cycles: u3 = if (target == 6) 4 else 2;
        if (!std.meta.eql(instruction, isa.cb_table[suffix]) or
            instruction.family() != .rotate_shift or
            instruction.src != .none or
            instruction.condition != .always or
            instruction.length != 2 or
            instruction.m_cycles != expected_cycles or
            instruction.taken_m_cycles != expected_cycles or
            instruction.parameter != operation or
            suffix != 8 * operation + target or
            trace.decoded.immediate != 0)
        {
            return error.NotCbRotateShift;
        }
        return .{
            .trace = trace,
            .operation = operation,
            .target = target,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [N_OPERATIONS]S,
            targets: [N_TARGETS]S,
            before_bits: [8]S,
            after_bits: [8]S,
            input_flags: [4]S,
            output_flags: [4]S,
            zero_inverse: S,
            pc_carry: S,
            fetch_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..8].*,
                    .targets = values[8..16].*,
                    .before_bits = values[16..24].*,
                    .after_bits = values[24..32].*,
                    .input_flags = values[32..36].*,
                    .output_flags = values[36..40].*,
                    .zero_inverse = values[40],
                    .pc_carry = values[41],
                    .fetch_carry = values[42],
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

            for (row.operations) |selector| {
                out[index] = bit(selector);
                index += 1;
            }
            out[index] = sum(row.operations).sub(is_active);
            index += 1;
            for (row.targets) |selector| {
                out[index] = bit(selector);
                index += 1;
            }
            out[index] = sum(row.targets).sub(is_active);
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
            out[index] = bit(row.fetch_carry);
            index += 1;

            const after = compose(row.after_bits);
            const output_zero = row.output_flags[0];
            out[index] = after.mul(output_zero);
            index += 1;
            out[index] = after.mul(row.zero_inverse)
                .sub(is_active.sub(output_zero));
            index += 1;
            out[index] = output_zero.mul(row.zero_inverse);
            index += 1;
            out[index] = row.output_flags[1];
            index += 1;
            out[index] = row.output_flags[2];
            index += 1;

            const input_carry = row.input_flags[3];
            for (row.after_bits, 0..) |after_bit, bit_index| {
                const left = if (bit_index == 0)
                    row.before_bits[7]
                else
                    row.before_bits[bit_index - 1];
                const right = if (bit_index == 7)
                    row.before_bits[0]
                else
                    row.before_bits[bit_index + 1];
                var expected = row.operations[0].mul(left)
                    .add(row.operations[1].mul(right))
                    .add(row.operations[2].mul(
                        if (bit_index == 0) input_carry else left,
                    ))
                    .add(row.operations[3].mul(
                        if (bit_index == 7) input_carry else right,
                    ))
                    .add(row.operations[4].mul(
                        if (bit_index == 0) S.zero() else left,
                    ))
                    .add(row.operations[5].mul(
                        if (bit_index == 7) row.before_bits[7] else right,
                    ))
                    .add(row.operations[6].mul(
                    row.before_bits[(bit_index + 4) % 8],
                ));
                expected = expected.add(row.operations[7].mul(
                    if (bit_index == 7) S.zero() else right,
                ));
                out[index] = after_bit.sub(expected);
                index += 1;
            }

            const left_carry = row.operations[0]
                .add(row.operations[2]).add(row.operations[4]);
            const right_carry = row.operations[1]
                .add(row.operations[3]).add(row.operations[5])
                .add(row.operations[7]);
            out[index] = row.output_flags[3].sub(
                left_carry.mul(row.before_bits[7])
                    .add(right_carry.mul(row.before_bits[0])),
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

            const source_values = [N_TARGETS]S{
                machine.before.at(.b),
                machine.before.at(.c),
                machine.before.at(.d),
                machine.before.at(.e),
                machine.before.at(.h),
                machine.before.at(.l),
                machine.bus[2].value,
                machine.before.at(.a),
            };
            var expected_before = S.zero();
            for (row.targets, source_values) |selector, value|
                expected_before = expected_before.add(selector.mul(value));
            out[index] = is_active.mul(before).sub(expected_before);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f))
                .sub(flags(row.input_flags));
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f))
                .sub(flags(row.output_flags));
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
                machine.after.at(.pc).sub(machine.before.at(.pc))
                    .sub(q(2)).add(q(65536).mul(row.pc_carry)),
            );
            index += 1;
            out[index] = is_active.mul(row.fetch_carry)
                .sub(row.pc_carry.mul(machine.after.at(.pc)));
            index += 1;

            var operation_index = S.zero();
            var target_index = S.zero();
            for (row.operations, 0..) |selector, operation|
                operation_index = operation_index.add(q(operation).mul(selector));
            for (row.targets, 0..) |selector, target|
                target_index = target_index.add(q(target).mul(selector));
            const suffix = q(8).mul(operation_index).add(target_index);
            const hl = q(256).mul(machine.before.at(.h))
                .add(machine.before.at(.l));
            var buses = [_]execution.Bus(S){.{
                .address = S.zero(),
                .value = S.zero(),
                .active = S.zero(),
                .read = S.zero(),
                .write = S.zero(),
                .program = S.zero(),
            }} ** execution.N_BUS_CYCLES;
            buses[0] = .{
                .address = is_active.mul(machine.before.at(.pc)),
                .value = q(0xcb).mul(is_active),
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };
            buses[1] = .{
                .address = is_active.mul(
                    machine.before.at(.pc).add(one)
                        .sub(q(65536).mul(row.fetch_carry)),
                ),
                .value = suffix,
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };
            buses[2] = .{
                .address = indirect_hl.mul(hl),
                .value = indirect_hl.mul(before),
                .active = indirect_hl,
                .read = indirect_hl,
                .write = S.zero(),
                .program = S.zero(),
            };
            buses[3] = .{
                .address = indirect_hl.mul(hl),
                .value = indirect_hl.mul(after),
                .active = indirect_hl,
                .read = S.zero(),
                .write = indirect_hl,
                .program = S.zero(),
            };
            for (machine.bus, buses) |actual, expected| {
                inline for (std.meta.fields(execution.Bus(S))) |field| {
                    out[index] = is_active.mul(@field(actual, field.name))
                        .sub(@field(expected, field.name));
                    index += 1;
                }
            }
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;

            out[index] = is_active.mul(
                machine.after.at(.sp).sub(machine.before.at(.sp)),
            );
            index += 1;
            for (
                execution.imeDelayConstraints(S, machine.before, machine.after),
            ) |constraint| {
                out[index] = is_active.mul(constraint);
                index += 1;
            }
            for ([_]execution.StateIndex{
                .halted,
                .stopped,
            }) |field| {
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

        fn sum(values: anytype) S {
            var total = S.zero();
            for (values) |value| total = total.add(value);
            return total;
        }

        fn compose(bits: [8]S) S {
            var value = S.zero();
            inline for (bits, 0..) |bit_value, bit_index|
                value = value.add(q(@as(u64, 1) << bit_index).mul(bit_value));
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
    const before = targetValue(trace.before, trace, step.target, false);
    const after = targetValue(trace.after, trace, step.target, true);
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[step.operation] = M31.one();
    output[8 + step.target] = M31.one();
    writeBits(output[16..24], before);
    writeBits(output[24..32], after);
    writeFlags(output[32..36], trace.before);
    writeFlags(output[36..40], trace.after);
    output[40] = if (after == 0)
        M31.zero()
    else
        M31.fromCanonical(after).inv() catch unreachable;
    output[41] = boolean(trace.before.pc >= 0xfffe);
    output[42] = boolean(trace.before.pc == 0xffff);
    return output;
}

pub fn evaluate(values: [N_MAIN_COLUMNS]M31) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluate(try Shipped.Row.fromColumns(&lifted), QM31.one());
}

pub fn evaluateBound(
    values: [N_MAIN_COLUMNS]M31,
    execution_values: [execution.N_MAIN_COLUMNS]M31,
) !Shipped.BoundEvaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&machine, execution_values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine),
        QM31.one(),
    );
}

fn operationIndex(operation: isa.Operation) ?usize {
    return switch (operation) {
        .rotate_left_circular => 0,
        .rotate_right_circular => 1,
        .rotate_left => 2,
        .rotate_right => 3,
        .shift_left_arithmetic => 4,
        .shift_right_arithmetic => 5,
        .swap => 6,
        .shift_right_logical => 7,
        else => null,
    };
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
        6 => trace.cycles[if (after) 3 else 2].value,
        7 => cpu.a,
        else => unreachable,
    };
}

fn setTarget(
    cpu: *runner.Cpu,
    memory: *runner.Memory,
    target: usize,
    value: u8,
) void {
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
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
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

test "CB rotate shift AIR exhaustively binds all operations and targets" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var cases: usize = 0;
    for (0..N_OPERATIONS) |operation| {
        for (0..N_TARGETS) |target| {
            memory.write(0x100, 0xcb);
            memory.write(0x101, @intCast(8 * operation + target));
            for (0..256) |value| {
                for (0..2) |carry| {
                    var cpu = runner.Cpu{
                        .a = 0x11,
                        .b = 0x22,
                        .c = 0x33,
                        .d = 0x44,
                        .e = 0x55,
                        .f = 0xe0 | (@as(u8, @intCast(carry)) << 4),
                        .h = 0x80,
                        .l = 0x00,
                        .sp = 0xcafe,
                        .pc = 0x100,
                        .ime = true,
                        .ime_enable_pending = true,
                        .halted = true,
                        .stopped = true,
                    };
                    setTarget(&cpu, &memory, target, @intCast(value));
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect((try evaluateBound(
                        witness,
                        execution.columns(trace, 7),
                    )).allZero());
                    cases += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(
        @as(usize, N_OPERATIONS * N_TARGETS * 256 * 2),
        cases,
    );
}

test "CB rotate shift AIR rejects semantic bus state metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0xcb);
    memory.write(0, 0x16);
    memory.write(0x8000, 0x80);
    var cpu = runner.Cpu{
        .a = 0x11,
        .b = 0x22,
        .f = 0xf0,
        .h = 0x80,
        .sp = 0xcafe,
        .pc = 0xffff,
        .ime = true,
        .ime_enable_pending = true,
    };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[24] = if (witness[24].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[39] = if (witness[39].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[0] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[8] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[41] = M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));

    const bus_offset = 2 * execution.N_STATE_COLUMNS;
    var forged = machine;
    forged[bus_offset + execution.N_BUS_COLUMNS + 1] =
        M31.fromCanonical(0x17);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[bus_offset + 2 * execution.N_BUS_COLUMNS] =
        M31.fromCanonical(0x8001);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[bus_offset + 3 * execution.N_BUS_COLUMNS + 1] =
        M31.fromCanonical(0x00);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.b)
    ] = M31.fromCanonical(0x23);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0xcb17;
    try std.testing.expectError(
        error.NotCbRotateShift,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.immediate = 1;
    try std.testing.expectError(
        error.NotCbRotateShift,
        ValidatedStep.init(forged_trace),
    );

    var inactive = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    inactive[24] = M31.one();
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine_lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, inactive) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&machine_lifted, machine) |*destination, value|
        destination.* = QM31.fromBase(value);
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine_lifted),
        QM31.zero(),
    )).allZero());

    memory.write(0xffff, 0x00);
    cpu.pc = 0xffff;
    try std.testing.expectError(
        error.NotCbRotateShift,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}
