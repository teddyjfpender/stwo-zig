//! Direct and execution-bound constraints for the executable misc opcodes.
//!
//! DAA has its own leaf. The CB prefix is decode metadata, not an instruction.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_OPERATIONS = 6;

pub const N_MAIN_COLUMNS: usize = 48;
pub const N_CONSTRAINTS: usize = 67;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 103;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

const Operation = enum(usize) {
    nop,
    complement_a,
    set_carry,
    complement_carry,
    halt,
    stop,
};

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    operation: Operation,

    pub fn init(trace: runner.StepTrace) error{NotMisc}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff) return error.NotMisc;
        const instruction = trace.decoded.instruction;
        const operation = operationOf(instruction.operation) orelse
            return error.NotMisc;
        if (!std.meta.eql(instruction, isa.base_table[@intCast(raw)]) or
            instruction.family() != .misc or
            trace.cycle_count != instruction.length)
        {
            return error.NotMisc;
        }
        const immediate: u16 = switch (instruction.length) {
            1 => 0,
            2 => trace.cycles[1].value,
            else => return error.NotMisc,
        };
        if (trace.decoded.immediate != immediate)
            return error.NotMisc;
        return .{ .trace = trace, .operation = operation };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [N_OPERATIONS]S,
            before_a_bits: [8]S,
            after_a_bits: [8]S,
            before_f_bits: [8]S,
            after_f_bits: [8]S,
            immediate_bits: [8]S,
            pc_carry: S,
            fetch_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..6].*,
                    .before_a_bits = values[6..14].*,
                    .after_a_bits = values[14..22].*,
                    .before_f_bits = values[22..30].*,
                    .after_f_bits = values[30..38].*,
                    .immediate_bits = values[38..46].*,
                    .pc_carry = values[46],
                    .fetch_carry = values[47],
                };
            }
        };

        pub const Evaluation = struct {
            values: [N_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub const BoundEvaluation = struct {
            values: [N_BOUND_CONSTRAINTS]S,

            pub fn allZero(self: @This()) bool {
                for (self.values) |value|
                    if (!value.isZero()) return false;
                return true;
            }
        };

        pub fn evaluate(row: Row, is_active: S) Evaluation {
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;
            const one = S.one();
            const cpl = operation(row, .complement_a);
            const scf = operation(row, .set_carry);
            const ccf = operation(row, .complement_carry);
            const stop = operation(row, .stop);

            var selected = S.zero();
            for (row.operations) |selector| {
                out[index] = bit(selector);
                index += 1;
                selected = selected.add(selector);
            }
            out[index] = selected.sub(is_active);
            index += 1;

            for (
                row.before_a_bits ++ row.after_a_bits ++
                    row.before_f_bits ++ row.after_f_bits ++
                    row.immediate_bits,
            ) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = bit(row.pc_carry);
            index += 1;
            out[index] = bit(row.fetch_carry);
            index += 1;

            for (row.after_a_bits, row.before_a_bits) |after, before| {
                const expected = cpl.mul(one.sub(before))
                    .add(is_active.sub(cpl).mul(before));
                out[index] = after.sub(expected);
                index += 1;
            }

            const preserves_low = is_active.sub(cpl).sub(scf).sub(ccf);
            for (row.after_f_bits, row.before_f_bits, 0..) |after, before, flag| {
                const expected = switch (flag) {
                    0...3 => preserves_low.mul(before),
                    4 => scf
                        .add(ccf.mul(one.sub(before)))
                        .add(is_active.sub(scf).sub(ccf).mul(before)),
                    5, 6 => cpl.add(preserves_low.mul(before)),
                    7 => is_active.mul(before),
                    else => unreachable,
                };
                out[index] = after.sub(expected);
                index += 1;
            }

            out[index] = is_active.sub(stop).mul(compose(row.immediate_bits));
            index += 1;
            out[index] = is_active.sub(stop).mul(row.fetch_carry);
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
            const halt = operation(row, .halt);
            const stop = operation(row, .stop);
            const before_a = compose(row.before_a_bits);
            const after_a = compose(row.after_a_bits);
            const before_f = compose(row.before_f_bits);
            const after_f = compose(row.after_f_bits);
            const immediate = compose(row.immediate_bits);

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            var opcode = S.zero();
            inline for (0..N_OPERATIONS) |selected| {
                opcode = opcode.add(
                    q(opcodeOf(@enumFromInt(selected))).mul(
                        row.operations[selected],
                    ),
                );
            }
            out[index] = is_active.mul(machine.bus[0].value).sub(opcode);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.a)).sub(before_a);
            index += 1;
            out[index] = is_active.mul(machine.after.at(.a)).sub(after_a);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f)).sub(before_f);
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f)).sub(after_f);
            index += 1;

            out[index] = is_active.mul(
                machine.after.at(.pc)
                    .sub(machine.before.at(.pc))
                    .sub(is_active.add(stop))
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;

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
                .value = opcode,
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };
            buses[1] = .{
                .address = stop.mul(
                    machine.before.at(.pc).add(one)
                        .sub(q(65536).mul(row.fetch_carry)),
                ),
                .value = immediate,
                .active = stop,
                .read = stop,
                .write = S.zero(),
                .program = stop,
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
            for (
                execution.imeDelayConstraints(S, machine.before, machine.after),
            ) |constraint| {
                out[index] = is_active.mul(constraint);
                index += 1;
            }
            out[index] = is_active.mul(
                machine.after.at(.halted).sub(machine.before.at(.halted)),
            ).sub(halt.mul(one.sub(machine.before.at(.halted))));
            index += 1;
            out[index] = is_active.mul(
                machine.after.at(.stopped).sub(machine.before.at(.stopped)),
            ).sub(stop.mul(one.sub(machine.before.at(.stopped))));
            index += 1;

            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        fn operation(row: Row, selected: Operation) S {
            return row.operations[@intFromEnum(selected)];
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn compose(bits: [8]S) S {
            var value = S.zero();
            inline for (bits, 0..) |bit_value, bit_index| {
                value = value.add(
                    q(@as(u64, 1) << bit_index).mul(bit_value),
                );
            }
            return value;
        }

        fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const trace = step.trace;
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[@intFromEnum(step.operation)] = M31.one();
    writeBits(output[6..14], trace.before.a);
    writeBits(output[14..22], trace.after.a);
    writeBits(output[22..30], trace.before.f);
    writeBits(output[30..38], trace.after.f);
    writeBits(output[38..46], @truncate(trace.decoded.immediate));
    output[46] = boolean(
        @as(u32, trace.before.pc) +
            trace.decoded.instruction.length > 0xffff,
    );
    output[47] = boolean(
        step.operation == .stop and trace.before.pc == 0xffff,
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

fn operationOf(operation: isa.Operation) ?Operation {
    return switch (operation) {
        .nop => .nop,
        .complement_a => .complement_a,
        .set_carry => .set_carry,
        .complement_carry => .complement_carry,
        .halt => .halt,
        .stop => .stop,
        else => null,
    };
}

fn opcodeOf(operation: Operation) u8 {
    return switch (operation) {
        .nop => 0x00,
        .complement_a => 0x2f,
        .set_carry => 0x37,
        .complement_carry => 0x3f,
        .halt => 0x76,
        .stop => 0x10,
    };
}

fn writeBits(destination: []M31, value: u8) void {
    std.debug.assert(destination.len == 8);
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "misc AIR binds 1536 edge-stratified runner transitions" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const operations = std.enums.values(Operation);
    const pcs = [_]u16{ 0, 0xfffd, 0xfffe, 0xffff };
    var checked: usize = 0;

    for (operations) |operation| {
        for (0..256) |edge| {
            const pc = pcs[edge & 3];
            memory.write(pc, opcodeOf(operation));
            memory.write(pc +% 1, @intCast(edge));
            var cpu = runner.Cpu{
                .a = @intCast(std.math.rotl(u8, @as(u8, @intCast(edge)), 3)),
                .b = 0x12,
                .c = 0x34,
                .d = 0x56,
                .e = 0x78,
                .f = @intCast(edge),
                .h = 0x9a,
                .l = 0xbc,
                .sp = 0xdef0,
                .pc = pc,
                .ime = edge & 1 != 0,
                .ime_enable_pending = edge & 2 != 0,
                .halted = edge & 4 != 0,
                .stopped = edge & 8 != 0,
            };
            const trace = try runner.step(&cpu, &memory);
            const witness = columns(try ValidatedStep.init(trace));
            try std.testing.expect((try evaluate(witness)).allZero());
            try std.testing.expect((try evaluateBound(
                witness,
                execution.columns(trace, 11),
            )).allZero());
            if (operation == .stop) {
                try std.testing.expectEqual(@as(u3, 1), trace.decoded.instruction.m_cycles);
                try std.testing.expectEqual(@as(u3, 2), trace.cycle_count);
            } else if (operation == .halt) {
                try std.testing.expectEqual(@as(u3, 1), trace.cycle_count);
                try std.testing.expect(trace.after.halted);
            }
            checked += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1536), checked);

    var classified: usize = 0;
    for (isa.base_table) |instruction|
        classified += @intFromBool(operationOf(instruction.operation) != null);
    try std.testing.expectEqual(@as(usize, operations.len), classified);
}

test "misc AIR rejects flags state PC opcode bus metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();

    memory.write(0xffff, 0x10);
    memory.write(0, 0xa5);
    var cpu = runner.Cpu{
        .a = 0x96,
        .f = 0x5f,
        .pc = 0xffff,
        .ime_enable_pending = true,
        .halted = true,
    };
    const stop_trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(stop_trace));
    const stop_machine = execution.columns(stop_trace, 0);
    try std.testing.expect((try evaluateBound(witness, stop_machine)).allZero());

    witness[38] = if (witness[38].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, stop_machine)).allZero());
    witness = columns(try ValidatedStep.init(stop_trace));
    witness[@intFromEnum(Operation.stop)] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    var forged = stop_machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.stopped)
    ] = M31.zero();
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(stop_trace)),
        forged,
    )).allZero());
    forged = stop_machine;
    forged[
        execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.pc)
    ] = M31.fromCanonical(0);
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(stop_trace)),
        forged,
    )).allZero());
    const bus = 2 * execution.N_STATE_COLUMNS;
    forged = stop_machine;
    forged[bus + 1] = M31.fromCanonical(0x00);
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(stop_trace)),
        forged,
    )).allZero());
    forged = stop_machine;
    forged[bus + execution.N_BUS_COLUMNS] = M31.one();
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(stop_trace)),
        forged,
    )).allZero());
    forged = stop_machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(stop_trace)),
        forged,
    )).allZero());

    memory.write(0, 0x76);
    cpu = .{ .pc = 0 };
    const halt_trace = try runner.step(&cpu, &memory);
    forged = execution.columns(halt_trace, 0);
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.halted)
    ] = M31.zero();
    try std.testing.expect(!(try evaluateBound(
        columns(try ValidatedStep.init(halt_trace)),
        forged,
    )).allZero());

    memory.write(0, 0x2f);
    cpu = .{ .a = 0x96, .f = 0x8f };
    const cpl_trace = try runner.step(&cpu, &memory);
    witness = columns(try ValidatedStep.init(cpl_trace));
    witness[30 + 6] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    var forged_trace = stop_trace;
    forged_trace.decoded.raw_opcode = 0x00;
    try std.testing.expectError(error.NotMisc, ValidatedStep.init(forged_trace));
    forged_trace = stop_trace;
    forged_trace.decoded.immediate ^= 1;
    try std.testing.expectError(error.NotMisc, ValidatedStep.init(forged_trace));
    forged_trace = stop_trace;
    forged_trace.decoded.instruction.m_cycles = 2;
    try std.testing.expectError(error.NotMisc, ValidatedStep.init(forged_trace));
    forged_trace = stop_trace;
    forged_trace.cycle_count = 1;
    try std.testing.expectError(error.NotMisc, ValidatedStep.init(forged_trace));

    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var lifted_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    const honest = columns(try ValidatedStep.init(stop_trace));
    for (&lifted, honest) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&lifted_machine, stop_machine) |*destination, value|
        destination.* = QM31.fromBase(value);
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());
    const zero = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    try std.testing.expect((Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&zero),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());

    var daa = stop_trace;
    daa.decoded = try isa.decode(&.{0x27});
    daa.cycle_count = 1;
    try std.testing.expectError(error.NotMisc, ValidatedStep.init(daa));
}
