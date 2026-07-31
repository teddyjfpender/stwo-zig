//! Direct and execution-bound constraints for SM83 16-bit arithmetic.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_OPERATIONS = 3;
const N_SOURCES = 4;

pub const N_MAIN_COLUMNS: usize = 75;
pub const N_CONSTRAINTS: usize = 89;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 132;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

const Operation = enum(usize) {
    add_hl,
    add_sp_e8,
    load_hl_sp_e8,
};

const Selection = struct {
    operation: Operation,
    source: ?usize = null,
};

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    selection: Selection,

    pub fn init(trace: runner.StepTrace) error{NotAlu16}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff or
            !std.meta.eql(
                trace.decoded.instruction,
                isa.base_table[@intCast(raw)],
            ) or
            trace.decoded.instruction.family() != .alu16 or
            trace.cycle_count != trace.decoded.instruction.m_cycles or
            trace.decoded.immediate != switch (trace.decoded.instruction.length) {
                1 => 0,
                2 => trace.cycles[1].value,
                else => return error.NotAlu16,
            })
        {
            return error.NotAlu16;
        }
        return .{
            .trace = trace,
            .selection = classify(trace.decoded.instruction) orelse
                return error.NotAlu16,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [N_OPERATIONS]S,
            sources: [N_SOURCES]S,
            left_bits: [16]S,
            right_bits: [16]S,
            result_bits: [16]S,
            offset_bits: [8]S,
            input_flags: [4]S,
            output_flags: [4]S,
            wrap_up: S,
            wrap_down: S,
            pc_carry: S,
            fetch_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..3].*,
                    .sources = values[3..7].*,
                    .left_bits = values[7..23].*,
                    .right_bits = values[23..39].*,
                    .result_bits = values[39..55].*,
                    .offset_bits = values[55..63].*,
                    .input_flags = values[63..67].*,
                    .output_flags = values[67..71].*,
                    .wrap_up = values[71],
                    .wrap_down = values[72],
                    .pc_carry = values[73],
                    .fetch_carry = values[74],
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
            const add_hl = row.operations[@intFromEnum(Operation.add_hl)];
            const signed = row.operations[@intFromEnum(Operation.add_sp_e8)]
                .add(row.operations[@intFromEnum(Operation.load_hl_sp_e8)]);

            for (row.values) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = sum(row.operations).sub(is_active);
            index += 1;
            out[index] = sum(row.sources).sub(add_hl);
            index += 1;

            const left = compose(row.left_bits);
            const right = compose(row.right_bits);
            const result = compose(row.result_bits);
            const offset = compose(row.offset_bits);
            out[index] = signed.mul(right);
            index += 1;
            out[index] = add_hl.mul(offset);
            index += 1;
            out[index] = row.wrap_up.mul(row.wrap_down);
            index += 1;
            out[index] = add_hl.mul(row.wrap_up.add(row.wrap_down));
            index += 1;
            out[index] = add_hl.mul(row.fetch_carry);
            index += 1;

            out[index] = add_hl.mul(
                left.add(right).sub(result)
                    .sub(q(65536).mul(row.output_flags[3])),
            );
            index += 1;
            out[index] = add_hl.mul(
                compose(row.left_bits[0..12].*)
                    .add(compose(row.right_bits[0..12].*))
                    .sub(compose(row.result_bits[0..12].*))
                    .sub(q(4096).mul(row.output_flags[2])),
            );
            index += 1;

            out[index] = signed.mul(
                left.add(offset)
                    .sub(q(256).mul(row.offset_bits[7]))
                    .sub(result)
                    .sub(q(65536).mul(row.wrap_up))
                    .add(q(65536).mul(row.wrap_down)),
            );
            index += 1;
            out[index] = signed.mul(
                compose(row.left_bits[0..4].*)
                    .add(compose(row.offset_bits[0..4].*))
                    .sub(compose(row.result_bits[0..4].*))
                    .sub(q(16).mul(row.output_flags[2])),
            );
            index += 1;
            out[index] = signed.mul(
                compose(row.left_bits[0..8].*)
                    .add(offset)
                    .sub(compose(row.result_bits[0..8].*))
                    .sub(q(256).mul(row.output_flags[3])),
            );
            index += 1;

            out[index] = row.output_flags[0].sub(
                add_hl.mul(row.input_flags[0]),
            );
            index += 1;
            out[index] = row.output_flags[1];
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
            const add_hl = row.operations[@intFromEnum(Operation.add_hl)];
            const add_sp = row.operations[@intFromEnum(Operation.add_sp_e8)];
            const load_hl =
                row.operations[@intFromEnum(Operation.load_hl_sp_e8)];
            const signed = add_sp.add(load_hl);
            const writes_hl = add_hl.add(load_hl);
            const left = compose(row.left_bits);
            const right = compose(row.right_bits);
            const result = compose(row.result_bits);
            const offset = compose(row.offset_bits);

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            const source_values = [N_SOURCES]S{
                q(256).mul(machine.before.at(.b)).add(machine.before.at(.c)),
                q(256).mul(machine.before.at(.d)).add(machine.before.at(.e)),
                q(256).mul(machine.before.at(.h)).add(machine.before.at(.l)),
                machine.before.at(.sp),
            };
            var expected_opcode = q(0xe8).mul(add_sp)
                .add(q(0xf8).mul(load_hl));
            var expected_right = S.zero();
            for (row.sources, source_values, 0..) |selector, value, source| {
                expected_opcode = expected_opcode.add(
                    q(0x09 + 0x10 * source).mul(selector),
                );
                expected_right = expected_right.add(selector.mul(value));
            }
            out[index] = is_active.mul(machine.bus[0].value)
                .sub(expected_opcode);
            index += 1;
            out[index] = is_active.mul(left).sub(
                add_hl.mul(
                    q(256).mul(machine.before.at(.h))
                        .add(machine.before.at(.l)),
                ).add(signed.mul(machine.before.at(.sp))),
            );
            index += 1;
            out[index] = is_active.mul(right).sub(expected_right);
            index += 1;
            out[index] = is_active.mul(result).sub(
                writes_hl.mul(
                    q(256).mul(machine.after.at(.h))
                        .add(machine.after.at(.l)),
                ).add(add_sp.mul(machine.after.at(.sp))),
            );
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
                    .sub(one.add(signed))
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;

            const fetch_address = machine.before.at(.pc).add(one)
                .sub(q(65536).mul(row.fetch_carry));
            for (machine.bus, 0..) |cycle, cycle_index| {
                const active = switch (cycle_index) {
                    0, 1 => is_active,
                    2 => signed,
                    3 => add_sp,
                    else => S.zero(),
                };
                const read = switch (cycle_index) {
                    0 => is_active,
                    1 => signed,
                    else => S.zero(),
                };
                const address = switch (cycle_index) {
                    0 => is_active.mul(machine.before.at(.pc)),
                    1 => add_hl.mul(machine.before.at(.pc))
                        .add(signed.mul(fetch_address)),
                    2 => signed.mul(fetch_address),
                    3 => add_sp.mul(fetch_address),
                    else => S.zero(),
                };
                const value = switch (cycle_index) {
                    0 => expected_opcode,
                    1 => add_hl.mul(expected_opcode).add(signed.mul(offset)),
                    2 => signed.mul(offset),
                    3 => add_sp.mul(offset),
                    else => S.zero(),
                };
                out[index] = is_active.mul(cycle.active).sub(active);
                index += 1;
                out[index] = is_active.mul(cycle.read).sub(read);
                index += 1;
                out[index] = is_active.mul(cycle.write);
                index += 1;
                out[index] = is_active.mul(cycle.program).sub(read);
                index += 1;
                out[index] = is_active.mul(cycle.address).sub(address);
                index += 1;
                out[index] = is_active.mul(cycle.value).sub(value);
                index += 1;
            }
            out[index] = is_active.mul(machine.branch_taken);
            index += 1;

            for ([_]execution.StateIndex{ .a, .b, .c, .d, .e }) |field| {
                out[index] = is_active.mul(
                    machine.after.at(field).sub(machine.before.at(field)),
                );
                index += 1;
            }
            const result_high = compose(row.result_bits[8..16].*);
            const result_low = compose(row.result_bits[0..8].*);
            out[index] = is_active.mul(
                machine.after.at(.h).sub(machine.before.at(.h)),
            ).sub(
                writes_hl.mul(result_high.sub(machine.before.at(.h))),
            );
            index += 1;
            out[index] = is_active.mul(
                machine.after.at(.l).sub(machine.before.at(.l)),
            ).sub(
                writes_hl.mul(result_low.sub(machine.before.at(.l))),
            );
            index += 1;
            out[index] = is_active.mul(
                machine.after.at(.sp).sub(machine.before.at(.sp)),
            ).sub(add_sp.mul(result.sub(machine.before.at(.sp))));
            index += 1;
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

        fn sum(values: anytype) S {
            var result = S.zero();
            for (values) |value| result = result.add(value);
            return result;
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
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[@intFromEnum(step.selection.operation)] = M31.one();
    if (step.selection.source) |source| output[3 + source] = M31.one();

    const signed = step.selection.operation != .add_hl;
    const left = if (signed) trace.before.sp else trace.before.hl();
    const right = if (step.selection.source) |source|
        pairValue(trace.before, source)
    else
        0;
    const result = switch (step.selection.operation) {
        .add_hl, .load_hl_sp_e8 => trace.after.hl(),
        .add_sp_e8 => trace.after.sp,
    };
    const offset: u8 = if (signed) @truncate(trace.decoded.immediate) else 0;
    writeBits(output[7..23], left);
    writeBits(output[23..39], right);
    writeBits(output[39..55], result);
    writeBits(output[55..63], offset);
    writeFlags(output[63..67], trace.before.f);
    writeFlags(output[67..71], trace.after.f);

    if (signed) {
        const signed_offset: i16 = @as(i8, @bitCast(offset));
        const wide = @as(i32, trace.before.sp) + signed_offset;
        output[71] = boolean(wide > 0xffff);
        output[72] = boolean(wide < 0);
        output[74] = boolean(trace.before.pc == 0xffff);
    }
    output[73] = boolean(
        @as(u32, trace.before.pc) + trace.decoded.instruction.length > 0xffff,
    );
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

fn classify(instruction: isa.Instruction) ?Selection {
    return switch (instruction.operation) {
        .add16 => blk: {
            if (instruction.dst != .hl) break :blk null;
            break :blk .{
                .operation = .add_hl,
                .source = sourceIndex(instruction.src) orelse break :blk null,
            };
        },
        .add_sp_e8 => if (instruction.dst == .sp and instruction.src == .rel8)
            .{ .operation = .add_sp_e8 }
        else
            null,
        .load_hl_sp_e8 => if (instruction.dst == .hl and instruction.src == .rel8)
            .{ .operation = .load_hl_sp_e8 }
        else
            null,
        else => null,
    };
}

fn sourceIndex(source: isa.Operand) ?usize {
    return switch (source) {
        .bc => 0,
        .de => 1,
        .hl => 2,
        .sp => 3,
        else => null,
    };
}

fn pairValue(cpu: runner.Cpu, source: usize) u16 {
    return switch (source) {
        0 => cpu.bc(),
        1 => cpu.de(),
        2 => cpu.hl(),
        3 => cpu.sp,
        else => unreachable,
    };
}

fn setPair(cpu: *runner.Cpu, source: usize, value: u16) void {
    switch (source) {
        0 => cpu.setBc(value),
        1 => cpu.setDe(value),
        2 => cpu.setHl(value),
        3 => cpu.sp = value,
        else => unreachable,
    }
}

fn writeBits(destination: []M31, value: u16) void {
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
}

fn writeFlags(destination: []M31, flags: u8) void {
    for (destination, [_]u8{ 0x80, 0x40, 0x20, 0x10 }) |*value, mask|
        value.* = boolean(flags & mask != 0);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "ALU16 AIR binds ADD HL rr edge-stratified rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const edges = [_]u16{
        0,      1,      0x000f, 0x0010, 0x00ff, 0x0100,
        0x07ff, 0x0800, 0x0fff, 0x1000, 0x7fff, 0x8000,
        0xfeff, 0xff00, 0xfffe, 0xffff,
    };
    var checked: usize = 0;

    for (0..N_SOURCES) |source| {
        const opcode: u8 = @intCast(0x09 + 0x10 * source);
        for (edges) |left| {
            for (edges) |right| {
                for (0..2) |zero_flag| {
                    const pc: u16 = if ((left ^ right) & 1 == 0) 0 else 0xffff;
                    memory.write(pc, opcode);
                    var cpu = runner.Cpu{
                        .a = 0xa5,
                        .f = if (zero_flag == 1) 0xf0 else 0x70,
                        .sp = 0xcafe,
                        .pc = pc,
                        .ime = true,
                        .ime_enable_pending = true,
                    };
                    cpu.setHl(left);
                    if (source != 2) setPair(&cpu, source, right);
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect((try evaluateBound(
                        witness,
                        execution.columns(trace, 11),
                    )).allZero());
                    checked += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2048), checked);
}

test "ALU16 AIR exhausts signed offsets across SP wrap boundaries" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const bases = [_]u16{
        0,      1,      0x007f, 0x0080, 0x00ff, 0x0100,
        0x0fff, 0x1000, 0x7fff, 0x8000, 0xff00, 0xff7f,
        0xff80, 0xffff,
    };
    var checked: usize = 0;

    for ([_]u8{ 0xe8, 0xf8 }) |opcode| {
        for (bases) |base| {
            for (0..256) |encoded| {
                const pc: u16 = switch (encoded & 3) {
                    0 => 0,
                    1 => 0xfffe,
                    else => 0xffff,
                };
                memory.write(pc, opcode);
                memory.write(pc +% 1, @intCast(encoded));
                var cpu = runner.Cpu{
                    .a = 0xa5,
                    .b = 0x12,
                    .c = 0x34,
                    .d = 0x56,
                    .e = 0x78,
                    .f = 0xf0,
                    .h = 0x9a,
                    .l = 0xbc,
                    .sp = base,
                    .pc = pc,
                    .ime = true,
                };
                const trace = try runner.step(&cpu, &memory);
                const witness = columns(try ValidatedStep.init(trace));
                try std.testing.expect((try evaluate(witness)).allZero());
                try std.testing.expect((try evaluateBound(
                    witness,
                    execution.columns(trace, 19),
                )).allZero());
                checked += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 7168), checked);
}

test "ALU16 AIR rejects arithmetic metadata bus state and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0xe8);
    memory.write(0, 0x80);
    var cpu = runner.Cpu{
        .a = 0xa5,
        .b = 0x12,
        .c = 0x34,
        .f = 0xf0,
        .h = 0x9a,
        .l = 0xbc,
        .sp = 0x007f,
        .pc = 0xffff,
        .ime = true,
    };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 3);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[39] = if (witness[39].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[69] = if (witness[69].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[71] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[1] = M31.zero();
    witness[2] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));

    var forged_machine = machine;
    const bus = 2 * execution.N_STATE_COLUMNS;
    forged_machine[bus + 1] = M31.fromCanonical(0xf8);
    try std.testing.expect(
        !(try evaluateBound(witness, forged_machine)).allZero(),
    );
    forged_machine = machine;
    forged_machine[bus + 2 * execution.N_BUS_COLUMNS + 2] = M31.zero();
    try std.testing.expect(
        !(try evaluateBound(witness, forged_machine)).allZero(),
    );
    forged_machine = machine;
    forged_machine[
        execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.sp)
    ] = M31.fromCanonical(0x0100);
    try std.testing.expect(
        !(try evaluateBound(witness, forged_machine)).allZero(),
    );
    forged_machine = machine;
    forged_machine[
        execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.pc)
    ] = M31.zero();
    try std.testing.expect(
        !(try evaluateBound(witness, forged_machine)).allZero(),
    );

    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var lifted_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, witness) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&lifted_machine, machine) |*destination, value|
        destination.* = QM31.fromBase(value);
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0xf8;
    try std.testing.expectError(error.NotAlu16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.immediate ^= 1;
    try std.testing.expectError(error.NotAlu16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.instruction.m_cycles = 3;
    try std.testing.expectError(error.NotAlu16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.cycle_count -= 1;
    try std.testing.expectError(error.NotAlu16, ValidatedStep.init(forged_trace));

    memory.write(0xffff, 0x00);
    cpu.pc = 0xffff;
    try std.testing.expectError(
        error.NotAlu16,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}
