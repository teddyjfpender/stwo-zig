//! Direct and execution-bound constraints for SM83 INC rr and DEC rr.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

pub const N_MAIN_COLUMNS: usize = 40;
pub const N_CONSTRAINTS: usize = 43;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 74;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,

    pub fn init(trace: runner.StepTrace) error{NotIncrementDecrement16}!ValidatedStep {
        const instruction = trace.decoded.instruction;
        switch (instruction.operation) {
            .increment16, .decrement16 => {},
            else => return error.NotIncrementDecrement16,
        }
        const target = targetIndex(instruction.dst) orelse
            return error.NotIncrementDecrement16;
        const expected_opcode: u16 =
            3 + 16 * @as(u16, @intCast(target)) + 8 * @as(u16, @intFromBool(
                instruction.operation == .decrement16,
            ));
        if (instruction.family() != .increment_decrement16 or
            instruction.src != .none or
            instruction.condition != .always or
            instruction.length != 1 or
            instruction.m_cycles != 2 or
            instruction.taken_m_cycles != 2 or
            instruction.parameter != 0 or
            trace.decoded.raw_opcode != expected_opcode or
            trace.decoded.immediate != 0)
        {
            return error.NotIncrementDecrement16;
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
            targets: [4]S,
            before_bits: [16]S,
            after_bits: [16]S,
            wrap: S,
            pc_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..2].*,
                    .targets = values[2..6].*,
                    .before_bits = values[6..22].*,
                    .after_bits = values[22..38].*,
                    .wrap = values[38],
                    .pc_carry = values[39],
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
            out[index] = bit(row.wrap);
            index += 1;

            const before = compose(row.before_bits);
            const after = compose(row.after_bits);
            out[index] = row.operations[0].mul(
                before.add(one).sub(after).sub(q(65536).mul(row.wrap)),
            );
            index += 1;
            out[index] = row.operations[1].mul(
                before.sub(one).sub(after).add(q(65536).mul(row.wrap)),
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
            const after_low = compose(row.after_bits[0..8].*);
            const after_high = compose(row.after_bits[8..16].*);

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
            const opcode = q(3).mul(is_active)
                .add(q(16).mul(selected_target))
                .add(q(8).mul(row.operations[1]));
            out[index] = is_active.mul(machine.bus[0].value).sub(opcode);
            index += 1;

            const pair_values = [4]S{
                q(256).mul(machine.before.at(.b)).add(machine.before.at(.c)),
                q(256).mul(machine.before.at(.d)).add(machine.before.at(.e)),
                q(256).mul(machine.before.at(.h)).add(machine.before.at(.l)),
                machine.before.at(.sp),
            };
            var expected_before = S.zero();
            for (row.targets, pair_values) |selector, value| {
                expected_before = expected_before.add(selector.mul(value));
            }
            out[index] = is_active.mul(before).sub(expected_before);
            index += 1;

            const pair_fields = [_][2]execution.StateIndex{
                .{ .b, .c },
                .{ .d, .e },
                .{ .h, .l },
            };
            for (pair_fields, 0..) |fields, target| {
                out[index] = is_active.mul(
                    machine.after.at(fields[0]).sub(machine.before.at(fields[0])),
                ).sub(
                    row.targets[target].mul(
                        after_high.sub(machine.before.at(fields[0])),
                    ),
                );
                index += 1;
                out[index] = is_active.mul(
                    machine.after.at(fields[1]).sub(machine.before.at(fields[1])),
                ).sub(
                    row.targets[target].mul(
                        after_low.sub(machine.before.at(fields[1])),
                    ),
                );
                index += 1;
            }
            out[index] = is_active.mul(
                machine.after.at(.sp).sub(machine.before.at(.sp)),
            ).sub(
                row.targets[3].mul(after.sub(machine.before.at(.sp))),
            );
            index += 1;

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

            out[index] = is_active.mul(machine.bus[1].active.sub(one));
            index += 1;
            out[index] = is_active.mul(machine.bus[1].read);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].write);
            index += 1;
            out[index] = is_active.mul(machine.bus[1].program);
            index += 1;
            out[index] = is_active.mul(
                machine.bus[1].address.sub(machine.before.at(.pc)),
            );
            index += 1;
            out[index] = is_active.mul(machine.bus[1].value.sub(opcode));
            index += 1;
            for (machine.bus[2..]) |cycle| {
                out[index] = is_active.mul(cycle.active);
                index += 1;
            }
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;

            for ([_]execution.StateIndex{
                .a,
                .f,
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
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const trace = step.trace;
    const instruction = trace.decoded.instruction;
    const target = targetIndex(instruction.dst).?;
    const before = targetValue(trace.before, target);
    const after = targetValue(trace.after, target);
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[@intFromBool(instruction.operation == .decrement16)] = M31.one();
    output[2 + target] = M31.one();
    writeBits(output[6..22], before);
    writeBits(output[22..38], after);
    output[38] = boolean(if (instruction.operation == .increment16)
        before == 0xffff
    else
        before == 0);
    output[39] = boolean(trace.before.pc == 0xffff);
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
        .bc => 0,
        .de => 1,
        .hl => 2,
        .sp => 3,
        else => null,
    };
}

fn targetValue(cpu: runner.Cpu, target: usize) u16 {
    return switch (target) {
        0 => cpu.bc(),
        1 => cpu.de(),
        2 => cpu.hl(),
        3 => cpu.sp,
        else => unreachable,
    };
}

fn setTarget(cpu: *runner.Cpu, target: usize, value: u16) void {
    switch (target) {
        0 => cpu.setBc(value),
        1 => cpu.setDe(value),
        2 => cpu.setHl(value),
        3 => cpu.sp = value,
        else => unreachable,
    }
}

fn writeBits(destination: []M31, value: u16) void {
    std.debug.assert(destination.len == 16);
    for (destination, 0..) |*bit_value, bit_index| {
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
    }
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "INC DEC rr AIR binds 16384 edge-stratified execution rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const low_edges = [_]u16{ 0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff };
    var checked: usize = 0;

    for (0..4) |target| {
        for (0..2) |operation| {
            const opcode: u8 = @intCast(3 + 16 * target + 8 * operation);
            memory.write(0, opcode);
            memory.write(0xffff, opcode);
            for (0..256) |high| {
                for (low_edges) |low| {
                    const value = (@as(u16, @intCast(high)) << 8) | low;
                    var cpu = runner.Cpu{
                        .a = 0x11,
                        .b = 0x22,
                        .c = 0x33,
                        .d = 0x44,
                        .e = 0x55,
                        .f = @as(u8, @intCast(high & 0xf)) << 4,
                        .h = 0x66,
                        .l = 0x77,
                        .sp = 0xcafe,
                        .pc = if (value == 0xffff) 0xffff else 0,
                        .ime = high & 1 != 0,
                        .ime_enable_pending = high & 2 != 0,
                    };
                    setTarget(&cpu, target, value);
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect(
                        (try evaluateBound(
                            witness,
                            execution.columns(trace, 0),
                        )).allZero(),
                    );
                    checked += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 16384), checked);
}

test "INC DEC rr AIR rejects result opcode state bus and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x23);
    var cpu = runner.Cpu{
        .a = 0x11,
        .f = 0xf0,
        .h = 0xff,
        .l = 0xff,
        .sp = 0xcafe,
        .ime = true,
    };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[22] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[38] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[0] = M31.zero();
    witness[1] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));

    var forged_machine = machine;
    const bus = 2 * execution.N_STATE_COLUMNS;
    forged_machine[bus + 1] = M31.fromCanonical(0x24);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.a)] =
        M31.fromCanonical(0x12);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.f)] =
        M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[bus + execution.N_BUS_COLUMNS + 2] = M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
    forged_machine = machine;
    forged_machine[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.pc)] =
        M31.fromCanonical(2);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());

    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var lifted_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, witness) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    for (&lifted_machine, machine) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0x13;
    try std.testing.expectError(
        error.NotIncrementDecrement16,
        ValidatedStep.init(forged_trace),
    );

    memory.write(0, 0x00);
    cpu.pc = 0;
    const nop = try runner.step(&cpu, &memory);
    try std.testing.expectError(
        error.NotIncrementDecrement16,
        ValidatedStep.init(nop),
    );
}
