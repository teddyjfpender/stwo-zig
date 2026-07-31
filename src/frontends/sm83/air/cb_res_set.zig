//! Direct and execution-bound constraints for all 128 CB RES/SET opcodes.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_OPERATIONS = 2;
const N_BITS = 8;
const N_TARGETS = 8;

pub const N_MAIN_COLUMNS: usize =
    N_OPERATIONS + N_BITS + N_TARGETS + 8 + 8 + 4 + 4 + 2;
pub const N_CONSTRAINTS: usize = 59;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 3 + 7 + 2 +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1 + 5;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    operation: usize,
    bit_index: usize,
    target: usize,

    pub fn init(trace: runner.StepTrace) error{NotCbResSet}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw < 0xcb80 or raw > 0xcbff) return error.NotCbResSet;
        const suffix: u8 = @truncate(raw);
        const instruction = trace.decoded.instruction;
        const operation: usize = switch (instruction.operation) {
            .reset_bit => 0,
            .set_bit => 1,
            else => return error.NotCbResSet,
        };
        const target = targetIndex(instruction.dst) orelse
            return error.NotCbResSet;
        const bit_index: usize = instruction.parameter;
        const expected_cycles: u3 = if (target == 6) 4 else 2;
        if (!std.meta.eql(instruction, isa.cb_table[suffix]) or
            instruction.family() != .reset_set or
            instruction.src != .none or
            instruction.condition != .always or
            instruction.length != 2 or
            instruction.m_cycles != expected_cycles or
            instruction.taken_m_cycles != expected_cycles or
            bit_index >= N_BITS or
            suffix != 0x80 + 0x40 * operation + 8 * bit_index + target or
            trace.decoded.immediate != 0)
        {
            return error.NotCbResSet;
        }
        return .{
            .trace = trace,
            .operation = operation,
            .bit_index = bit_index,
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
            bits: [N_BITS]S,
            targets: [N_TARGETS]S,
            before_bits: [8]S,
            after_bits: [8]S,
            input_flags: [4]S,
            output_flags: [4]S,
            pc_carry: S,
            fetch_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..2].*,
                    .bits = values[2..10].*,
                    .targets = values[10..18].*,
                    .before_bits = values[18..26].*,
                    .after_bits = values[26..34].*,
                    .input_flags = values[34..38].*,
                    .output_flags = values[38..42].*,
                    .pc_carry = values[42],
                    .fetch_carry = values[43],
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
            for (row.bits) |selector| {
                out[index] = bit(selector);
                index += 1;
            }
            out[index] = sum(row.bits).sub(is_active);
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

            for (row.before_bits, row.after_bits, row.bits) |
                before,
                after,
                selected,
            | {
                const expected = is_active.mul(before).add(
                    selected.mul(row.operations[1].sub(before)),
                );
                out[index] = after.sub(expected);
                index += 1;
            }
            for (row.input_flags, row.output_flags) |before, after| {
                out[index] = after.sub(before);
                index += 1;
            }

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

            var bit_index = S.zero();
            var target_index = S.zero();
            for (row.bits, 0..) |selector, selected|
                bit_index = bit_index.add(q(selected).mul(selector));
            for (row.targets, 0..) |selector, selected|
                target_index = target_index.add(q(selected).mul(selector));
            const suffix = q(0x80).mul(is_active)
                .add(q(0x40).mul(row.operations[1]))
                .add(q(8).mul(bit_index)).add(target_index);
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
    output[2 + step.bit_index] = M31.one();
    output[10 + step.target] = M31.one();
    writeBits(output[18..26], before);
    writeBits(output[26..34], after);
    writeFlags(output[34..38], trace.before);
    writeFlags(output[38..42], trace.after);
    output[42] = boolean(trace.before.pc >= 0xfffe);
    output[43] = boolean(trace.before.pc == 0xffff);
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

test "CB RES SET AIR exhaustively binds operation bit target and byte" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var cases: usize = 0;
    for (0..N_OPERATIONS) |operation| {
        for (0..N_BITS) |bit_index| {
            for (0..N_TARGETS) |target| {
                memory.write(0x100, 0xcb);
                memory.write(
                    0x101,
                    @intCast(0x80 + 0x40 * operation + 8 * bit_index + target),
                );
                for (0..256) |value| {
                    var cpu = runner.Cpu{
                        .a = 0x11,
                        .b = 0x22,
                        .c = 0x33,
                        .d = 0x44,
                        .e = 0x55,
                        .f = 0xf0,
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
        @as(usize, N_OPERATIONS * N_BITS * N_TARGETS * 256),
        cases,
    );
}

test "CB RES SET AIR rejects result state bus metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0xcb);
    memory.write(0, 0xde);
    memory.write(0x8000, 0x00);
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

    witness[29] = if (witness[29].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[38] = if (witness[38].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[0] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[2] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[10] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[42] = M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));

    const bus_offset = 2 * execution.N_STATE_COLUMNS;
    var forged = machine;
    forged[bus_offset + execution.N_BUS_COLUMNS + 1] =
        M31.fromCanonical(0xdf);
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
    forged_trace.decoded.raw_opcode = 0xcbdf;
    try std.testing.expectError(
        error.NotCbResSet,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.immediate = 1;
    try std.testing.expectError(
        error.NotCbResSet,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.instruction.parameter = 4;
    try std.testing.expectError(
        error.NotCbResSet,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.instruction.m_cycles = 3;
    try std.testing.expectError(
        error.NotCbResSet,
        ValidatedStep.init(forged_trace),
    );

    var inactive = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    inactive[26] = M31.one();
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

    memory.write(0xfffe, 0xcb);
    memory.write(0xffff, 0xc0);
    var wrap_cpu = runner.Cpu{ .b = 0, .pc = 0xfffe };
    const wrap_trace = try runner.step(&wrap_cpu, &memory);
    const wrap_witness = columns(try ValidatedStep.init(wrap_trace));
    try std.testing.expect(wrap_witness[42].eql(M31.one()));
    try std.testing.expect(wrap_witness[43].isZero());
    try std.testing.expect((try evaluateBound(
        wrap_witness,
        execution.columns(wrap_trace, 0),
    )).allZero());

    memory.write(0xffff, 0x00);
    cpu.pc = 0xffff;
    try std.testing.expectError(
        error.NotCbResSet,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}
