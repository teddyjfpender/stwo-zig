//! Direct and execution-bound constraints for all six SM83 16-bit loads.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_SHAPES = 3;
const N_TARGETS = 4;

pub const N_MAIN_COLUMNS: usize = 43;
pub const N_CONSTRAINTS: usize = N_MAIN_COLUMNS + 7;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 3 + execution.N_STATE_COLUMNS +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

const Shape = enum(usize) {
    immediate,
    store_sp,
    sp_from_hl,
};

const Selection = union(Shape) {
    immediate: usize,
    store_sp,
    sp_from_hl,
};

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    selection: Selection,

    pub fn init(trace: runner.StepTrace) error{NotLoad16}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff) return error.NotLoad16;
        const instruction = trace.decoded.instruction;
        if (!std.meta.eql(instruction, isa.base_table[@intCast(raw)]) or
            instruction.family() != .load16 or
            trace.cycle_count != instruction.m_cycles)
        {
            return error.NotLoad16;
        }
        const immediate: u16 = switch (instruction.length) {
            1 => 0,
            3 => @as(u16, trace.cycles[1].value) |
                (@as(u16, trace.cycles[2].value) << 8),
            else => return error.NotLoad16,
        };
        if (trace.decoded.immediate != immediate) return error.NotLoad16;
        return .{
            .trace = trace,
            .selection = classify(instruction) orelse return error.NotLoad16,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            shapes: [N_SHAPES]S,
            targets: [N_TARGETS]S,
            value_bits: [16]S,
            address_bits: [16]S,
            pc_carry: S,
            fetch1_carry: S,
            fetch2_carry: S,
            address_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .shapes = values[0..3].*,
                    .targets = values[3..7].*,
                    .value_bits = values[7..23].*,
                    .address_bits = values[23..39].*,
                    .pc_carry = values[39],
                    .fetch1_carry = values[40],
                    .fetch2_carry = values[41],
                    .address_carry = values[42],
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
            const immediate = shape(row, .immediate);
            const store = shape(row, .store_sp);
            const length3 = immediate.add(store);

            for (row.values) |value| {
                out[index] = bit(value);
                index += 1;
            }
            out[index] = sum(row.shapes).sub(is_active);
            index += 1;
            out[index] = sum(row.targets).sub(immediate);
            index += 1;
            out[index] = one.sub(store).mul(compose(row.address_bits));
            index += 1;
            out[index] = row.fetch1_carry.mul(one.sub(length3));
            index += 1;
            out[index] = row.fetch2_carry.mul(one.sub(length3));
            index += 1;
            out[index] = row.fetch1_carry.mul(one.sub(row.fetch2_carry));
            index += 1;
            out[index] = row.address_carry.mul(one.sub(store));
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
            const immediate = shape(row, .immediate);
            const store = shape(row, .store_sp);
            const copy = shape(row, .sp_from_hl);
            const length3 = immediate.add(store);
            const value = compose(row.value_bits);
            const value_low = compose(row.value_bits[0..8].*);
            const value_high = compose(row.value_bits[8..16].*);
            const address = compose(row.address_bits);
            const address_low = compose(row.address_bits[0..8].*);
            const address_high = compose(row.address_bits[8..16].*);
            const before = machine.before;
            const after = machine.after;

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |column| {
                out[index] = one.sub(is_active).mul(column);
                index += 1;
            }

            var selected_target = S.zero();
            for (row.targets, 0..) |selector, target| {
                selected_target = selected_target.add(q(target).mul(selector));
            }
            const expected_opcode = immediate.mul(
                one.add(q(16).mul(selected_target)),
            ).add(q(0x08).mul(store))
                .add(q(0xf9).mul(copy));
            out[index] = is_active.mul(machine.bus[0].value)
                .sub(expected_opcode);
            index += 1;
            out[index] = is_active.mul(value).sub(
                immediate.mul(
                    q(256).mul(machine.bus[2].value)
                        .add(machine.bus[1].value),
                ).add(store.mul(before.at(.sp)))
                    .add(copy.mul(
                    q(256).mul(before.at(.h)).add(before.at(.l)),
                )),
            );
            index += 1;
            out[index] = is_active.mul(address).sub(
                store.mul(
                    q(256).mul(machine.bus[2].value)
                        .add(machine.bus[1].value),
                ),
            );
            index += 1;

            const pairs = [_][2]execution.StateIndex{
                .{ .b, .c },
                .{ .d, .e },
                .{ .h, .l },
            };
            for (pairs, 0..) |fields, target| {
                out[index] = is_active.mul(
                    after.at(fields[0]).sub(before.at(fields[0])),
                ).sub(
                    row.targets[target].mul(
                        value_high.sub(before.at(fields[0])),
                    ),
                );
                index += 1;
                out[index] = is_active.mul(
                    after.at(fields[1]).sub(before.at(fields[1])),
                ).sub(
                    row.targets[target].mul(
                        value_low.sub(before.at(fields[1])),
                    ),
                );
                index += 1;
            }
            const writes_sp = row.targets[3].add(copy);
            out[index] = is_active.mul(
                after.at(.sp).sub(before.at(.sp)),
            ).sub(writes_sp.mul(value.sub(before.at(.sp))));
            index += 1;
            out[index] = is_active.mul(
                after.at(.pc).sub(before.at(.pc))
                    .sub(q(3).mul(length3).add(copy))
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;
            for ([_]execution.StateIndex{
                .a,
                .f,
            }) |field| {
                out[index] = is_active.mul(
                    after.at(field).sub(before.at(field)),
                );
                index += 1;
            }
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

            var buses = [_]execution.Bus(S){.{
                .address = S.zero(),
                .value = S.zero(),
                .active = S.zero(),
                .read = S.zero(),
                .write = S.zero(),
                .program = S.zero(),
            }} ** execution.N_BUS_CYCLES;
            buses[0] = .{
                .address = is_active.mul(before.at(.pc)),
                .value = expected_opcode,
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };
            buses[1] = .{
                .address = length3.mul(
                    before.at(.pc).add(one)
                        .sub(q(65536).mul(row.fetch1_carry)),
                ).add(copy.mul(before.at(.pc))),
                .value = immediate.mul(value_low)
                    .add(store.mul(address_low))
                    .add(copy.mul(expected_opcode)),
                .active = is_active,
                .read = length3,
                .write = S.zero(),
                .program = length3,
            };
            buses[2] = .{
                .address = length3.mul(
                    before.at(.pc).add(q(2))
                        .sub(q(65536).mul(row.fetch2_carry)),
                ),
                .value = immediate.mul(value_high)
                    .add(store.mul(address_high)),
                .active = length3,
                .read = length3,
                .write = S.zero(),
                .program = length3,
            };
            buses[3] = .{
                .address = store.mul(address),
                .value = store.mul(value_low),
                .active = store,
                .read = S.zero(),
                .write = store,
                .program = S.zero(),
            };
            buses[4] = .{
                .address = store.mul(
                    address.add(one)
                        .sub(q(65536).mul(row.address_carry)),
                ),
                .value = store.mul(value_high),
                .active = store,
                .read = S.zero(),
                .write = store,
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

        fn shape(row: Row, selected: Shape) S {
            return row.shapes[@intFromEnum(selected)];
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
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const value: u16 = switch (step.selection) {
        .immediate => |target| blk: {
            output[@intFromEnum(Shape.immediate)] = M31.one();
            output[3 + target] = M31.one();
            break :blk trace.decoded.immediate;
        },
        .store_sp => blk: {
            output[@intFromEnum(Shape.store_sp)] = M31.one();
            writeBits(output[23..39], trace.decoded.immediate);
            break :blk trace.before.sp;
        },
        .sp_from_hl => blk: {
            output[@intFromEnum(Shape.sp_from_hl)] = M31.one();
            break :blk trace.before.hl();
        },
    };
    writeBits(output[7..23], value);
    output[39] = boolean(
        @as(u32, trace.before.pc) + trace.decoded.instruction.length > 0xffff,
    );
    const length3 = trace.decoded.instruction.length == 3;
    output[40] = boolean(length3 and trace.before.pc == 0xffff);
    output[41] = boolean(length3 and trace.before.pc >= 0xfffe);
    output[42] = boolean(
        step.selection == .store_sp and trace.decoded.immediate == 0xffff,
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
    if (instruction.operation != .load) return null;
    if (targetIndex(instruction.dst)) |target| {
        if (instruction.src == .imm16) return .{ .immediate = target };
    }
    if (instruction.dst == .indirect_imm16 and instruction.src == .sp)
        return .store_sp;
    if (instruction.dst == .sp and instruction.src == .hl)
        return .sp_from_hl;
    return null;
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

fn writeBits(destination: []M31, value: u16) void {
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "LOAD16 AIR binds 12288 edge-stratified execution rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    const opcodes = [_]u8{ 0x01, 0x08, 0x11, 0x21, 0x31, 0xf9 };
    const low_edges = [_]u16{ 0x00, 0x01, 0x0f, 0x10, 0x7f, 0x80, 0xfe, 0xff };
    const pcs = [_]u16{ 0, 0xfffd, 0xfffe, 0xffff };
    var checked: usize = 0;

    for (opcodes) |opcode| {
        for (0..256) |high| {
            for (low_edges, 0..) |low, edge| {
                const encoded = (@as(u16, @intCast(high)) << 8) | low;
                const pc = pcs[(high + edge + opcode) & 3];
                memory.write(pc, opcode);
                const instruction = isa.base_table[opcode];
                if (instruction.length == 3) {
                    memory.write(pc +% 1, @truncate(encoded));
                    memory.write(pc +% 2, @truncate(encoded >> 8));
                }
                var cpu = runner.Cpu{
                    .a = 0xa5,
                    .b = 0x12,
                    .c = 0x34,
                    .d = 0x56,
                    .e = 0x78,
                    .f = @as(u8, @intCast(high & 0xf)) << 4,
                    .h = 0x9a,
                    .l = 0xbc,
                    .sp = 0xcafe,
                    .pc = pc,
                    .ime = high & 1 != 0,
                    .ime_enable_pending = high & 2 != 0,
                    .halted = high & 4 != 0,
                    .stopped = high & 8 != 0,
                };
                if (opcode == 0x08) {
                    cpu.sp = std.math.rotl(u16, encoded, 8);
                } else if (opcode == 0xf9) {
                    cpu.setHl(encoded);
                }
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
    try std.testing.expectEqual(@as(usize, 12288), checked);

    var classified: usize = 0;
    for (isa.base_table) |instruction|
        classified += @intFromBool(instruction.family() == .load16);
    try std.testing.expectEqual(@as(usize, opcodes.len), classified);
}

test "LOAD16 AIR rejects result state bus metadata and vacuity mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xfffe, 0x08);
    memory.write(0xffff, 0xff);
    memory.write(0, 0xff);
    var cpu = runner.Cpu{
        .a = 0xa5,
        .f = 0xf0,
        .h = 0x12,
        .l = 0x34,
        .sp = 0x5aa5,
        .pc = 0xfffe,
        .ime = true,
        .ime_enable_pending = true,
    };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 7);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[7] = if (witness[7].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[23] = M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[42] = M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[@intFromEnum(Shape.store_sp)] = M31.zero();
    witness[@intFromEnum(Shape.sp_from_hl)] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));

    var forged = machine;
    const bus = 2 * execution.N_STATE_COLUMNS;
    forged[bus + 1] = M31.fromCanonical(0x09);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[bus + 4 * execution.N_BUS_COLUMNS] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS + @intFromEnum(execution.StateIndex.sp)
    ] = M31.fromCanonical(0x5aa4);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());

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

    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0xf9;
    try std.testing.expectError(error.NotLoad16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.immediate ^= 1;
    try std.testing.expectError(error.NotLoad16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.instruction.m_cycles = 4;
    try std.testing.expectError(error.NotLoad16, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.cycle_count -= 1;
    try std.testing.expectError(error.NotLoad16, ValidatedStep.init(forged_trace));

    memory.write(0xfffe, 0x00);
    cpu.pc = 0xfffe;
    try std.testing.expectError(
        error.NotLoad16,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}
