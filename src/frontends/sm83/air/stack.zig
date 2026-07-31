//! Direct and execution-bound constraints for SM83 PUSH and POP.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const stack_opcodes = [_]u8{
    0xc1, 0xc5, 0xd1, 0xd5, 0xe1, 0xe5, 0xf1, 0xf5,
};

const N_PATHS = stack_opcodes.len;
const VALUE_OFFSET = N_PATHS;
const FLAGS_OFFSET = VALUE_OFFSET + 16;
const BEFORE_SP_OFFSET = FLAGS_OFFSET + 4;
const MIDDLE_SP_OFFSET = BEFORE_SP_OFFSET + 16;
const AFTER_SP_OFFSET = MIDDLE_SP_OFFSET + 16;
const PC_CARRY_OFFSET = AFTER_SP_OFFSET + 16;
const SP_CARRY_OFFSET = PC_CARRY_OFFSET + 1;

pub const N_MAIN_COLUMNS: usize = SP_CARRY_OFFSET + 2;
pub const N_CONSTRAINTS: usize = N_MAIN_COLUMNS + 7;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 1 + 1 + 1 + 8 + 2 + 1 + 4 +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    path: usize,

    pub fn init(trace: runner.StepTrace) error{NotStack}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff) return error.NotStack;
        const path = findOpcode(@intCast(raw)) orelse return error.NotStack;
        const instruction = trace.decoded.instruction;
        if (!std.meta.eql(instruction, isa.base_table[@intCast(raw)]) or
            instruction.family() != .stack or
            trace.cycle_count != instruction.m_cycles or
            trace.decoded.immediate != 0 or
            trace.branch_taken)
        {
            return error.NotStack;
        }
        return .{ .trace = trace, .path = path };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            paths: [N_PATHS]S,
            value_bits: [16]S,
            flags: [4]S,
            before_sp_bits: [16]S,
            middle_sp_bits: [16]S,
            after_sp_bits: [16]S,
            pc_carry: S,
            sp_carries: [2]S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .paths = values[0..N_PATHS].*,
                    .value_bits = values[VALUE_OFFSET..FLAGS_OFFSET].*,
                    .flags = values[FLAGS_OFFSET..BEFORE_SP_OFFSET].*,
                    .before_sp_bits = values[BEFORE_SP_OFFSET..MIDDLE_SP_OFFSET].*,
                    .middle_sp_bits = values[MIDDLE_SP_OFFSET..AFTER_SP_OFFSET].*,
                    .after_sp_bits = values[AFTER_SP_OFFSET..PC_CARRY_OFFSET].*,
                    .pc_carry = values[PC_CARRY_OFFSET],
                    .sp_carries = values[SP_CARRY_OFFSET..N_MAIN_COLUMNS].*,
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
            const pop = popSelector(row);
            const push = pushSelector(row);

            var selected = S.zero();
            for (row.values) |value| {
                out[index] = bit(value);
                index += 1;
            }
            for (row.paths) |selector| selected = selected.add(selector);
            out[index] = selected.sub(is_active);
            index += 1;

            const before_sp = compose(row.before_sp_bits);
            const middle_sp = compose(row.middle_sp_bits);
            const after_sp = compose(row.after_sp_bits);
            out[index] = push.mul(
                before_sp.sub(one).sub(middle_sp)
                    .add(q(65536).mul(row.sp_carries[0])),
            ).add(pop.mul(
                before_sp.add(one).sub(middle_sp)
                    .sub(q(65536).mul(row.sp_carries[0])),
            ));
            index += 1;
            out[index] = push.mul(
                middle_sp.sub(one).sub(after_sp)
                    .add(q(65536).mul(row.sp_carries[1])),
            ).add(pop.mul(
                middle_sp.add(one).sub(after_sp)
                    .sub(q(65536).mul(row.sp_carries[1])),
            ));
            index += 1;

            for (row.value_bits[0..4]) |low_bit| {
                out[index] = row.paths[7].mul(low_bit);
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
            const pop = popSelector(row);
            const push = pushSelector(row);
            const value = compose(row.value_bits);
            const value_low = compose(row.value_bits[0..8].*);
            const value_high = compose(row.value_bits[8..16].*);
            const masked_low = q(16).mul(compose(row.value_bits[4..8].*));
            const before_sp = compose(row.before_sp_bits);
            const middle_sp = compose(row.middle_sp_bits);
            const after_sp = compose(row.after_sp_bits);
            const before = machine.before;
            const after = machine.after;

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |column| {
                out[index] = one.sub(is_active).mul(column);
                index += 1;
            }

            var opcode = S.zero();
            for (row.paths, stack_opcodes) |selector, raw|
                opcode = opcode.add(q(raw).mul(selector));
            out[index] = is_active.mul(machine.bus[0].value).sub(opcode);
            index += 1;

            const pairs = [_][2]execution.StateIndex{
                .{ .b, .c },
                .{ .d, .e },
                .{ .h, .l },
                .{ .a, .f },
            };
            var pushed_value = S.zero();
            for (pairs, 0..) |fields, pair| {
                const source = q(256).mul(before.at(fields[0]))
                    .add(before.at(fields[1]));
                pushed_value = pushed_value.add(
                    row.paths[2 * pair + 1].mul(source),
                );
            }
            out[index] = push.mul(value).sub(pushed_value);
            index += 1;
            out[index] = is_active.mul(before.at(.f))
                .sub(flagsValue(row.flags));
            index += 1;

            for (pairs, 0..) |fields, pair| {
                const selector = row.paths[2 * pair];
                const low = if (pair == 3) masked_low else value_low;
                out[index] = is_active.mul(
                    after.at(fields[0]).sub(before.at(fields[0])),
                ).sub(selector.mul(value_high.sub(before.at(fields[0]))));
                index += 1;
                out[index] = is_active.mul(
                    after.at(fields[1]).sub(before.at(fields[1])),
                ).sub(selector.mul(low.sub(before.at(fields[1]))));
                index += 1;
            }

            out[index] = is_active.mul(before.at(.sp)).sub(before_sp);
            index += 1;
            out[index] = is_active.mul(after.at(.sp)).sub(after_sp);
            index += 1;
            out[index] = is_active.mul(
                after.at(.pc).sub(before.at(.pc)).sub(one)
                    .add(q(65536).mul(row.pc_carry)),
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
                .address = push.mul(before.at(.pc)).add(pop.mul(before_sp)),
                .value = push.mul(opcode).add(pop.mul(value_low)),
                .active = is_active,
                .read = pop,
                .write = S.zero(),
                .program = S.zero(),
            };
            buses[2] = .{
                .address = middle_sp,
                .value = value_high,
                .active = is_active,
                .read = pop,
                .write = push,
                .program = S.zero(),
            };
            buses[3] = .{
                .address = push.mul(after_sp),
                .value = push.mul(value_low),
                .active = push,
                .read = S.zero(),
                .write = push,
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

        fn popSelector(row: Row) S {
            return row.paths[0].add(row.paths[2])
                .add(row.paths[4]).add(row.paths[6]);
        }

        fn pushSelector(row: Row) S {
            return row.paths[1].add(row.paths[3])
                .add(row.paths[5]).add(row.paths[7]);
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

        fn flagsValue(flags: [4]S) S {
            return q(128).mul(flags[0])
                .add(q(64).mul(flags[1]))
                .add(q(32).mul(flags[2]))
                .add(q(16).mul(flags[3]));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const trace = step.trace;
    const push = step.path & 1 == 1;
    const pair = step.path / 2;
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[step.path] = M31.one();

    const value: u16 = if (push)
        pairValue(trace.before, pair)
    else
        @as(u16, trace.cycles[1].value) |
            (@as(u16, trace.cycles[2].value) << 8);
    writeBits(output[VALUE_OFFSET..FLAGS_OFFSET], value);
    writeFlags(output[FLAGS_OFFSET..BEFORE_SP_OFFSET], trace.before.f);
    writeBits(
        output[BEFORE_SP_OFFSET..MIDDLE_SP_OFFSET],
        trace.before.sp,
    );
    const middle = if (push)
        trace.before.sp -% 1
    else
        trace.before.sp +% 1;
    writeBits(output[MIDDLE_SP_OFFSET..AFTER_SP_OFFSET], middle);
    writeBits(output[AFTER_SP_OFFSET..PC_CARRY_OFFSET], trace.after.sp);
    output[PC_CARRY_OFFSET] = boolean(trace.before.pc == 0xffff);
    output[SP_CARRY_OFFSET] = boolean(
        if (push) trace.before.sp == 0 else trace.before.sp == 0xffff,
    );
    output[SP_CARRY_OFFSET + 1] = boolean(
        if (push) middle == 0 else middle == 0xffff,
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

fn findOpcode(opcode: u8) ?usize {
    for (stack_opcodes, 0..) |candidate, path|
        if (candidate == opcode) return path;
    return null;
}

fn pairValue(cpu: runner.Cpu, pair: usize) u16 {
    return switch (pair) {
        0 => cpu.bc(),
        1 => cpu.de(),
        2 => cpu.hl(),
        3 => cpu.af(),
        else => unreachable,
    };
}

fn setPair(cpu: *runner.Cpu, pair: usize, value: u16) void {
    switch (pair) {
        0 => cpu.setBc(value),
        1 => cpu.setDe(value),
        2 => cpu.setHl(value),
        3 => cpu.setAf(value),
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

test "stack AIR binds 65536 edge-stratified PUSH POP rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const stack_edges = [_]u16{ 0, 1, 0xfffe, 0xffff };
    const low_edges = [_]u8{ 0, 1, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff };
    const pc: u16 = 0x4000;
    var checked: usize = 0;

    for (stack_opcodes, 0..) |opcode, path| {
        const push = path & 1 == 1;
        const pair = path / 2;
        for (stack_edges) |sp| {
            for (0..256) |high| {
                for (low_edges, 0..) |low, edge| {
                    memory.write(pc, opcode);
                    const value = (@as(u16, @intCast(high)) << 8) | low;
                    var cpu = runner.Cpu{
                        .a = 0xa5,
                        .b = 0x12,
                        .c = 0x34,
                        .d = 0x56,
                        .e = 0x78,
                        .f = @as(u8, @intCast((high + edge) & 0xf)) << 4,
                        .h = 0x9a,
                        .l = 0xbc,
                        .sp = sp,
                        .pc = pc,
                        .ime = high & 1 != 0,
                        .ime_enable_pending = high & 2 != 0,
                        .halted = high & 4 != 0,
                        .stopped = high & 8 != 0,
                    };
                    if (push) {
                        setPair(&cpu, pair, value);
                    } else {
                        memory.write(sp, low);
                        memory.write(sp +% 1, @intCast(high));
                    }
                    const trace = try runner.step(&cpu, &memory);
                    const witness = columns(try ValidatedStep.init(trace));
                    try std.testing.expect((try evaluate(witness)).allZero());
                    try std.testing.expect((try evaluateBound(
                        witness,
                        execution.columns(trace, 17),
                    )).allZero());
                    checked += 1;
                }
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 65536), checked);

    var classified: usize = 0;
    for (isa.base_table) |instruction|
        classified += @intFromBool(instruction.family() == .stack);
    try std.testing.expectEqual(@as(usize, stack_opcodes.len), classified);
}

test "stack AIR rejects SP result memory opcode metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0xf1);
    memory.write(0x8000, 0x3f);
    memory.write(0x8001, 0xa5);
    var cpu = runner.Cpu{
        .a = 0x12,
        .f = 0xf0,
        .sp = 0x8000,
        .pc = 0xffff,
        .ime = true,
        .ime_enable_pending = true,
    };
    const pop_trace = try runner.step(&cpu, &memory);
    try std.testing.expectEqual(@as(u8, 0xa5), pop_trace.after.a);
    try std.testing.expectEqual(@as(u8, 0x30), pop_trace.after.f);
    var witness = columns(try ValidatedStep.init(pop_trace));
    const machine = execution.columns(pop_trace, 5);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[VALUE_OFFSET] =
        if (witness[VALUE_OFFSET].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(pop_trace));

    var forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.sp)] =
        M31.fromCanonical(0x8001);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.a)] =
        M31.fromCanonical(0xa4);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    const bus = 2 * execution.N_STATE_COLUMNS;
    for (0..execution.N_BUS_COLUMNS) |column| {
        std.mem.swap(
            M31,
            &forged[bus + execution.N_BUS_COLUMNS + column],
            &forged[bus + 2 * execution.N_BUS_COLUMNS + column],
        );
    }
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[bus + execution.N_BUS_COLUMNS + 1] = M31.fromCanonical(0x3e);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[bus + 1] = M31.fromCanonical(0xf5);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());

    memory.write(0x4000, 0xf5);
    var push_cpu = runner.Cpu{
        .a = 0xa5,
        .f = 0x30,
        .sp = 0,
        .pc = 0x4000,
    };
    const push_trace = try runner.step(&push_cpu, &memory);
    const push_witness = columns(try ValidatedStep.init(push_trace));
    const push_machine = execution.columns(push_trace, 9);
    var forged_push = push_machine;
    for (0..execution.N_BUS_COLUMNS) |column| {
        std.mem.swap(
            M31,
            &forged_push[bus + 2 * execution.N_BUS_COLUMNS + column],
            &forged_push[bus + 3 * execution.N_BUS_COLUMNS + column],
        );
    }
    try std.testing.expect(
        !(try evaluateBound(push_witness, forged_push)).allZero(),
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
    const zero = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    try std.testing.expect((Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&zero),
        try execution.Row(QM31).fromColumns(&lifted_machine),
        QM31.zero(),
    )).allZero());

    var forged_trace = pop_trace;
    forged_trace.decoded.raw_opcode = 0xc1;
    try std.testing.expectError(error.NotStack, ValidatedStep.init(forged_trace));
    forged_trace = pop_trace;
    forged_trace.decoded.immediate = 1;
    try std.testing.expectError(error.NotStack, ValidatedStep.init(forged_trace));
    forged_trace = pop_trace;
    forged_trace.decoded.instruction.m_cycles = 4;
    try std.testing.expectError(error.NotStack, ValidatedStep.init(forged_trace));
    forged_trace = pop_trace;
    forged_trace.cycle_count -= 1;
    try std.testing.expectError(error.NotStack, ValidatedStep.init(forged_trace));
    forged_trace = pop_trace;
    forged_trace.branch_taken = true;
    try std.testing.expectError(error.NotStack, ValidatedStep.init(forged_trace));

    memory.write(0x4000, 0x00);
    push_cpu.pc = 0x4000;
    try std.testing.expectError(
        error.NotStack,
        ValidatedStep.init(try runner.step(&push_cpu, &memory)),
    );
}
