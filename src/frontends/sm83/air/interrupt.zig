//! Direct and execution-bound constraints for RETI, DI, and EI.
//!
//! EI follows the runner's explicit delay latch. A pending prior EI promotes
//! IME before this row executes, so a consecutive EI is a no-op.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const opcodes = [_]u8{ 0xd9, 0xf3, 0xfb };

const Operation = enum(usize) {
    reti,
    disable,
    enable,
};

const N_OPERATIONS = opcodes.len;
const RETURN_OFFSET = N_OPERATIONS;
const BEFORE_SP_OFFSET = RETURN_OFFSET + 16;
const MIDDLE_SP_OFFSET = BEFORE_SP_OFFSET + 16;
const AFTER_SP_OFFSET = MIDDLE_SP_OFFSET + 16;
const BEFORE_IME_OFFSET = AFTER_SP_OFFSET + 16;
const BEFORE_PENDING_OFFSET = BEFORE_IME_OFFSET + 1;
const AFTER_IME_OFFSET = BEFORE_PENDING_OFFSET + 1;
const AFTER_PENDING_OFFSET = AFTER_IME_OFFSET + 1;
const PC_CARRY_OFFSET = AFTER_PENDING_OFFSET + 1;
const SP_CARRY_OFFSET = PC_CARRY_OFFSET + 1;

pub const N_MAIN_COLUMNS: usize = SP_CARRY_OFFSET + 2;
pub const N_CONSTRAINTS: usize = N_MAIN_COLUMNS + 7;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 1 + 4 + 2 + 1 + 10 +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    operation: Operation,

    pub fn init(trace: runner.StepTrace) error{NotInterrupt}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff) return error.NotInterrupt;
        const operation = findOpcode(@intCast(raw)) orelse
            return error.NotInterrupt;
        const instruction = trace.decoded.instruction;
        if (!std.meta.eql(instruction, isa.base_table[@intCast(raw)]) or
            instruction.family() != .interrupt or
            instruction.length != 1 or
            trace.cycle_count != instruction.m_cycles or
            trace.decoded.immediate != 0 or
            trace.branch_taken or
            trace.result != null)
        {
            return error.NotInterrupt;
        }
        return .{ .trace = trace, .operation = operation };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            operations: [N_OPERATIONS]S,
            return_bits: [16]S,
            before_sp_bits: [16]S,
            middle_sp_bits: [16]S,
            after_sp_bits: [16]S,
            before_ime: S,
            before_pending: S,
            after_ime: S,
            after_pending: S,
            pc_carry: S,
            sp_carries: [2]S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .operations = values[0..N_OPERATIONS].*,
                    .return_bits = values[RETURN_OFFSET..BEFORE_SP_OFFSET].*,
                    .before_sp_bits = values[BEFORE_SP_OFFSET..MIDDLE_SP_OFFSET].*,
                    .middle_sp_bits = values[MIDDLE_SP_OFFSET..AFTER_SP_OFFSET].*,
                    .after_sp_bits = values[AFTER_SP_OFFSET..BEFORE_IME_OFFSET].*,
                    .before_ime = values[BEFORE_IME_OFFSET],
                    .before_pending = values[BEFORE_PENDING_OFFSET],
                    .after_ime = values[AFTER_IME_OFFSET],
                    .after_pending = values[AFTER_PENDING_OFFSET],
                    .pc_carry = values[PC_CARRY_OFFSET],
                    .sp_carries = values[SP_CARRY_OFFSET..N_MAIN_COLUMNS].*,
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
            const reti = operation(row, .reti);
            const disable = operation(row, .disable);
            const enable = operation(row, .enable);
            const non_reti = disable.add(enable);
            const promoted_ime = row.before_ime.add(row.before_pending)
                .sub(row.before_ime.mul(row.before_pending));

            var selected = S.zero();
            for (row.values) |value| {
                out[index] = bit(value);
                index += 1;
            }
            for (row.operations) |selector| selected = selected.add(selector);
            out[index] = selected.sub(is_active);
            index += 1;

            out[index] = non_reti.mul(compose(row.return_bits));
            index += 1;

            const before_sp = compose(row.before_sp_bits);
            const middle_sp = compose(row.middle_sp_bits);
            const after_sp = compose(row.after_sp_bits);
            out[index] = before_sp.add(reti).sub(middle_sp)
                .sub(q(65536).mul(row.sp_carries[0]));
            index += 1;
            out[index] = middle_sp.add(reti).sub(after_sp)
                .sub(q(65536).mul(row.sp_carries[1]));
            index += 1;
            out[index] = reti.mul(row.pc_carry);
            index += 1;

            out[index] = row.after_ime.sub(
                reti.add(enable.mul(promoted_ime)),
            );
            index += 1;
            out[index] = row.after_pending.sub(
                enable.mul(S.one().sub(promoted_ime)),
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
            const reti = operation(row, .reti);
            const disable = operation(row, .disable);
            const enable = operation(row, .enable);
            const non_reti = disable.add(enable);
            const return_value = compose(row.return_bits);
            const return_low = compose(row.return_bits[0..8].*);
            const return_high = compose(row.return_bits[8..16].*);
            const before_sp = compose(row.before_sp_bits);
            const middle_sp = compose(row.middle_sp_bits);
            const after_sp = compose(row.after_sp_bits);
            const before = machine.before;
            const after = machine.after;

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            var opcode = S.zero();
            for (row.operations, opcodes) |selector, raw|
                opcode = opcode.add(q(raw).mul(selector));
            out[index] = is_active.mul(machine.bus[0].value).sub(opcode);
            index += 1;

            for ([_]struct { field: execution.StateIndex, value: S }{
                .{ .field = .ime, .value = row.before_ime },
                .{ .field = .ime_enable_pending, .value = row.before_pending },
            }) |binding| {
                out[index] = is_active.mul(before.at(binding.field))
                    .sub(binding.value);
                index += 1;
            }
            for ([_]struct { field: execution.StateIndex, value: S }{
                .{ .field = .ime, .value = row.after_ime },
                .{
                    .field = .ime_enable_pending,
                    .value = row.after_pending,
                },
            }) |binding| {
                out[index] = is_active.mul(after.at(binding.field))
                    .sub(binding.value);
                index += 1;
            }

            out[index] = is_active.mul(before.at(.sp)).sub(before_sp);
            index += 1;
            out[index] = is_active.mul(after.at(.sp)).sub(after_sp);
            index += 1;
            out[index] = reti.mul(after.at(.pc).sub(return_value)).add(
                non_reti.mul(
                    after.at(.pc).sub(before.at(.pc)).sub(one)
                        .add(q(65536).mul(row.pc_carry)),
                ),
            );
            index += 1;

            for ([_]execution.StateIndex{
                .a,
                .b,
                .c,
                .d,
                .e,
                .f,
                .h,
                .l,
                .halted,
                .stopped,
            }) |field| {
                out[index] = is_active.mul(
                    after.at(field).sub(before.at(field)),
                );
                index += 1;
            }

            var buses = [_]execution.Bus(S){zeroBus()} **
                execution.N_BUS_CYCLES;
            buses[0] = .{
                .address = is_active.mul(before.at(.pc)),
                .value = opcode,
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };
            buses[1] = .{
                .address = reti.mul(before_sp),
                .value = reti.mul(return_low),
                .active = reti,
                .read = reti,
                .write = S.zero(),
                .program = S.zero(),
            };
            buses[2] = .{
                .address = reti.mul(middle_sp),
                .value = reti.mul(return_high),
                .active = reti,
                .read = reti,
                .write = S.zero(),
                .program = S.zero(),
            };
            buses[3] = .{
                .address = reti.mul(middle_sp),
                .value = reti.mul(return_high),
                .active = reti,
                .read = S.zero(),
                .write = S.zero(),
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

            std.debug.assert(index == out.len);
            return .{ .values = out };
        }

        fn operation(row: Row, selected: Operation) S {
            return row.operations[@intFromEnum(selected)];
        }

        fn zeroBus() execution.Bus(S) {
            return .{
                .address = S.zero(),
                .value = S.zero(),
                .active = S.zero(),
                .read = S.zero(),
                .write = S.zero(),
                .program = S.zero(),
            };
        }

        fn bit(value: S) S {
            return value.mul(value.sub(S.one()));
        }

        fn compose(bits: anytype) S {
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
    const reti = step.operation == .reti;
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[@intFromEnum(step.operation)] = M31.one();

    const return_value: u16 = if (reti)
        @as(u16, trace.cycles[1].value) |
            (@as(u16, trace.cycles[2].value) << 8)
    else
        0;
    writeBits(output[RETURN_OFFSET..BEFORE_SP_OFFSET], return_value);
    writeBits(
        output[BEFORE_SP_OFFSET..MIDDLE_SP_OFFSET],
        trace.before.sp,
    );
    const middle = trace.before.sp +% @as(u16, @intFromBool(reti));
    writeBits(output[MIDDLE_SP_OFFSET..AFTER_SP_OFFSET], middle);
    writeBits(output[AFTER_SP_OFFSET..BEFORE_IME_OFFSET], trace.after.sp);
    output[BEFORE_IME_OFFSET] = boolean(trace.before.ime);
    output[BEFORE_PENDING_OFFSET] =
        boolean(trace.before.ime_enable_pending);
    output[AFTER_IME_OFFSET] = boolean(trace.after.ime);
    output[AFTER_PENDING_OFFSET] =
        boolean(trace.after.ime_enable_pending);
    output[PC_CARRY_OFFSET] =
        boolean(!reti and trace.before.pc == 0xffff);
    output[SP_CARRY_OFFSET] =
        boolean(reti and trace.before.sp == 0xffff);
    output[SP_CARRY_OFFSET + 1] = boolean(reti and middle == 0xffff);
    return output;
}

pub fn evaluate(values: [N_MAIN_COLUMNS]M31) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value|
        destination.* = QM31.fromBase(value);
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

fn findOpcode(opcode: u8) ?Operation {
    for (opcodes, 0..) |candidate, operation|
        if (candidate == opcode) return @enumFromInt(operation);
    return null;
}

fn writeBits(destination: []M31, value: u16) void {
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* =
            M31.fromCanonical((value >> @intCast(bit_index)) & 1);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "interrupt AIR binds 608 RETI DI EI edge rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const sp_edges = [_]u16{ 0, 1, 0xfffe, 0xffff };
    const byte_edges = [_]u8{ 0, 1, 0x7f, 0x80, 0xfe, 0xff };
    var checked: usize = 0;

    memory.write(0x4000, opcodes[@intFromEnum(Operation.reti)]);
    for (sp_edges) |sp| {
        for (byte_edges) |low| {
            for (byte_edges) |high| {
                for (0..4) |interrupt_state| {
                    memory.write(sp, low);
                    memory.write(sp +% 1, high);
                    var cpu = runner.Cpu{
                        .a = 0x12,
                        .b = 0x34,
                        .c = 0x56,
                        .d = 0x78,
                        .e = 0x9a,
                        .f = 0xb0,
                        .h = 0xcd,
                        .l = 0xef,
                        .sp = sp,
                        .pc = 0x4000,
                        .ime = interrupt_state & 1 != 0,
                        .ime_enable_pending = interrupt_state & 2 != 0,
                        .halted = low & 1 != 0,
                        .stopped = high & 1 != 0,
                    };
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect((try evaluateBound(
                        witness,
                        execution.columns(trace, 13),
                    )).allZero());
                    checked += 1;
                }
            }
        }
    }

    const pc_edges = [_]u16{ 0, 0x7fff, 0xfffe, 0xffff };
    for ([_]Operation{ .disable, .enable }) |operation| {
        for (pc_edges, 0..) |pc, edge| {
            memory.write(pc, opcodes[@intFromEnum(operation)]);
            for (0..4) |interrupt_state| {
                var cpu = runner.Cpu{
                    .a = 0xa5,
                    .f = 0x50,
                    .sp = sp_edges[(edge + interrupt_state) & 3],
                    .pc = pc,
                    .ime = interrupt_state & 1 != 0,
                    .ime_enable_pending = interrupt_state & 2 != 0,
                };
                const trace = try runner.step(&cpu, &memory);
                const witness = columns(try ValidatedStep.init(trace));
                try std.testing.expect((try evaluate(witness)).allZero());
                try std.testing.expect((try evaluateBound(
                    witness,
                    execution.columns(trace, 29),
                )).allZero());
                if (operation == .enable) {
                    const expected_ime = trace.before.ime or
                        trace.before.ime_enable_pending;
                    try std.testing.expectEqual(
                        expected_ime,
                        trace.after.ime,
                    );
                    try std.testing.expectEqual(
                        !expected_ime,
                        trace.after.ime_enable_pending,
                    );
                } else {
                    try std.testing.expect(!trace.after.ime);
                    try std.testing.expect(
                        !trace.after.ime_enable_pending,
                    );
                }
                checked += 1;
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 608), checked);

    var classified: usize = 0;
    for (isa.base_table) |instruction|
        classified += @intFromBool(instruction.family() == .interrupt);
    try std.testing.expectEqual(@as(usize, opcodes.len), classified);
}

test "interrupt AIR binds EI followed by DI and makes consecutive EI a no-op" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();

    memory.write(0, 0xfb);
    memory.write(1, 0xf3);
    var cpu = runner.Cpu{};
    const first_enable = try runner.step(&cpu, &memory);
    const disable = try runner.step(&cpu, &memory);
    try std.testing.expect(first_enable.after.ime_enable_pending);
    try std.testing.expect(disable.before.ime_enable_pending);
    try std.testing.expect(!disable.after.ime);
    try std.testing.expect(!disable.after.ime_enable_pending);
    const disable_witness = columns(try ValidatedStep.init(disable));
    const disable_machine = execution.columns(disable, 1);
    try std.testing.expect(
        (try evaluateBound(disable_witness, disable_machine)).allZero(),
    );

    memory.write(0, 0xfb);
    memory.write(1, 0xfb);
    cpu = .{};
    _ = try runner.step(&cpu, &memory);
    const second_enable = try runner.step(&cpu, &memory);
    try std.testing.expect(second_enable.before.ime_enable_pending);
    try std.testing.expect(second_enable.after.ime);
    try std.testing.expect(!second_enable.after.ime_enable_pending);
    const enable_witness = columns(try ValidatedStep.init(second_enable));
    const enable_machine = execution.columns(second_enable, 1);
    try std.testing.expect(
        (try evaluateBound(enable_witness, enable_machine)).allZero(),
    );

    var forged = enable_machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.ime)] =
        M31.zero();
    try expectRejected(enable_witness, forged);
    forged = enable_machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try expectRejected(enable_witness, forged);

    var old_behavior_witness = enable_witness;
    old_behavior_witness[AFTER_PENDING_OFFSET] = M31.one();
    var old_behavior_machine = enable_machine;
    old_behavior_machine[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(
        !(try evaluateBound(
            old_behavior_witness,
            old_behavior_machine,
        )).allZero(),
    );
}

test "interrupt AIR rejects state bus metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0x4000, 0xd9);
    memory.write(0xffff, 0x34);
    memory.write(0, 0x12);
    var cpu = runner.Cpu{
        .a = 0xa5,
        .f = 0xb0,
        .sp = 0xffff,
        .pc = 0x4000,
        .ime = false,
        .ime_enable_pending = true,
    };
    const trace = try runner.step(&cpu, &memory);
    const witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 7);
    try std.testing.expectEqual(@as(u16, 0x1234), trace.after.pc);
    try std.testing.expectEqual(@as(u16, 1), trace.after.sp);
    try std.testing.expect(trace.after.ime);
    try std.testing.expect(!trace.after.ime_enable_pending);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    var forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.pc)] =
        M31.fromCanonical(0x1235);
    try expectRejected(witness, forged);
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.sp)] =
        M31.fromCanonical(0);
    try expectRejected(witness, forged);
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.ime)] =
        M31.zero();
    try expectRejected(witness, forged);
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try expectRejected(witness, forged);
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.f)] =
        M31.fromCanonical(0xa0);
    try expectRejected(witness, forged);

    const bus = 2 * execution.N_STATE_COLUMNS;
    forged = machine;
    forged[bus + execution.N_BUS_COLUMNS] = M31.fromCanonical(0xfffe);
    try expectRejected(witness, forged);
    forged = machine;
    forged[bus + 1] = M31.fromCanonical(0xf3);
    try expectRejected(witness, forged);
    forged = machine;
    forged[bus + 3 * execution.N_BUS_COLUMNS + 2] = M31.zero();
    try expectRejected(witness, forged);

    var mutated_witness = witness;
    mutated_witness[AFTER_PENDING_OFFSET] = M31.one();
    try std.testing.expect(!(try evaluate(mutated_witness)).allZero());
    mutated_witness = witness;
    mutated_witness[@intFromEnum(Operation.reti)] = M31.zero();
    try std.testing.expect(!(try evaluate(mutated_witness)).allZero());

    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var lifted_machine: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, witness) |*destination, value|
        destination.* = QM31.fromBase(value);
    for (&lifted_machine, machine) |*destination, value|
        destination.* = QM31.fromBase(value);
    const machine_row =
        try execution.Row(QM31).fromColumns(&lifted_machine);
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        machine_row,
        QM31.zero(),
    )).allZero());
    const zero = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    try std.testing.expect((Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&zero),
        machine_row,
        QM31.zero(),
    )).allZero());

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0xf3;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.instruction.m_cycles = 3;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.decoded.immediate = 1;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.cycle_count -= 1;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(forged_trace),
    );
    forged_trace = trace;
    forged_trace.branch_taken = true;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(forged_trace),
    );

    memory.write(0x4000, 0x00);
    cpu.pc = 0x4000;
    try std.testing.expectError(
        error.NotInterrupt,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}

fn expectRejected(
    witness: [N_MAIN_COLUMNS]M31,
    machine: [execution.N_MAIN_COLUMNS]M31,
) !void {
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
}
