//! Direct and execution-bound constraints for all 85 SM83 8-bit loads.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const N_SHAPES = 3;
const N_TARGETS = 8;
const N_INDIRECTS = 14;
const N_CARRIES = 5;

pub const N_MAIN_COLUMNS: usize =
    N_SHAPES + 2 * N_TARGETS + N_INDIRECTS + 8 + N_CARRIES;
pub const N_CONSTRAINTS: usize = N_MAIN_COLUMNS + 10;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize =
    1 + N_MAIN_COLUMNS + 1 + 1 + 13 + 1 + 2 +
    execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS + 1;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

const Shape = enum(usize) { matrix, immediate, indirect };
const Direction = enum(usize) { store, load };
const AddressMode = enum(usize) {
    bc,
    de,
    hl_increment,
    hl_decrement,
    high_c,
    high_immediate,
    immediate16,
};

const Selection = union(Shape) {
    matrix: struct { dst: usize, src: usize },
    immediate: usize,
    indirect: struct { mode: AddressMode, direction: Direction },
};

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    selection: Selection,

    pub fn init(trace: runner.StepTrace) error{NotLoad8}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff or
            !std.meta.eql(
                trace.decoded.instruction,
                isa.base_table[@intCast(raw)],
            ) or
            trace.decoded.instruction.family() != .load8 or
            trace.decoded.immediate != switch (trace.decoded.instruction.length) {
                1 => 0,
                2 => trace.cycles[1].value,
                3 => @as(u16, trace.cycles[1].value) |
                    (@as(u16, trace.cycles[2].value) << 8),
                else => unreachable,
            })
        {
            return error.NotLoad8;
        }
        return .{
            .trace = trace,
            .selection = classify(trace.decoded.instruction) orelse
                return error.NotLoad8,
        };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            shapes: [N_SHAPES]S,
            destinations: [N_TARGETS]S,
            sources: [N_TARGETS]S,
            indirects: [N_INDIRECTS]S,
            value_bits: [8]S,
            pc_carry: S,
            fetch1_carry: S,
            fetch2_carry: S,
            hl_low_wrap: S,
            hl_high_wrap: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .shapes = values[0..3].*,
                    .destinations = values[3..11].*,
                    .sources = values[11..19].*,
                    .indirects = values[19..33].*,
                    .value_bits = values[33..41].*,
                    .pc_carry = values[41],
                    .fetch1_carry = values[42],
                    .fetch2_carry = values[43],
                    .hl_low_wrap = values[44],
                    .hl_high_wrap = values[45],
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

            for (row.values) |value| {
                out[index] = bit(value);
                index += 1;
            }
            const matrix = row.shapes[@intFromEnum(Shape.matrix)];
            const immediate = row.shapes[@intFromEnum(Shape.immediate)];
            const indirect_shape = row.shapes[@intFromEnum(Shape.indirect)];
            out[index] = sum(row.shapes).sub(is_active);
            index += 1;
            out[index] = sum(row.destinations).sub(matrix.add(immediate));
            index += 1;
            out[index] = sum(row.sources).sub(matrix);
            index += 1;
            out[index] = sum(row.indirects).sub(indirect_shape);
            index += 1;
            out[index] = row.destinations[6].mul(row.sources[6]);
            index += 1;

            const high_immediate = mode(row, .high_immediate);
            const immediate16 = mode(row, .immediate16);
            const post = mode(row, .hl_increment).add(mode(row, .hl_decrement));
            out[index] = row.fetch1_carry.mul(
                one.sub(immediate.add(high_immediate).add(immediate16)),
            );
            index += 1;
            out[index] = row.fetch2_carry.mul(one.sub(immediate16));
            index += 1;
            out[index] = row.hl_low_wrap.mul(one.sub(post));
            index += 1;
            out[index] = row.hl_high_wrap.mul(one.sub(post));
            index += 1;
            out[index] = row.hl_high_wrap.mul(one.sub(row.hl_low_wrap));
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
            const matrix = row.shapes[@intFromEnum(Shape.matrix)];
            const immediate = row.shapes[@intFromEnum(Shape.immediate)];
            const value = compose(row.value_bits);
            const before = machine.before;
            const after = machine.after;

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |column| {
                out[index] = one.sub(is_active).mul(column);
                index += 1;
            }

            var dst_index = S.zero();
            var src_index = S.zero();
            for (row.destinations, 0..) |selector, operand|
                dst_index = dst_index.add(q(operand).mul(selector));
            for (row.sources, 0..) |selector, operand|
                src_index = src_index.add(q(operand).mul(selector));
            const matrix_opcode = matrix.mul(
                q(0x40).add(q(8).mul(dst_index)).add(src_index),
            );
            const immediate_opcode = immediate.mul(
                q(0x06).add(q(8).mul(dst_index)),
            );
            const indirect_opcodes = [_]u8{
                0x02, 0x0a, 0x12, 0x1a, 0x22, 0x2a, 0x32,
                0x3a, 0xe2, 0xf2, 0xe0, 0xf0, 0xea, 0xfa,
            };
            var expected_opcode = matrix_opcode.add(immediate_opcode);
            for (row.indirects, indirect_opcodes) |selector, opcode|
                expected_opcode = expected_opcode.add(q(opcode).mul(selector));
            out[index] = is_active.mul(machine.bus[0].value)
                .sub(expected_opcode);
            index += 1;

            const register_values = [N_TARGETS]S{
                before.at(.b), before.at(.c), before.at(.d),        before.at(.e),
                before.at(.h), before.at(.l), machine.bus[1].value, before.at(.a),
            };
            var expected_value = immediate.mul(machine.bus[1].value);
            for (row.sources, register_values) |selector, source|
                expected_value = expected_value.add(selector.mul(source));
            const stores = direction(row, .store);
            expected_value = expected_value.add(stores.mul(before.at(.a)));
            for (0..7) |address_mode| {
                const load = row.indirects[2 * address_mode + 1];
                const cycle: usize = switch (@as(AddressMode, @enumFromInt(address_mode))) {
                    .high_immediate => 2,
                    .immediate16 => 3,
                    else => 1,
                };
                expected_value = expected_value.add(
                    load.mul(machine.bus[cycle].value),
                );
            }
            out[index] = is_active.mul(value).sub(expected_value);
            index += 1;

            const fields = [_]execution.StateIndex{
                .b, .c, .d, .e, .h, .l, .a,
            };
            for (fields, [_]usize{ 0, 1, 2, 3, 4, 5, 7 }) |field, target| {
                var selected = row.destinations[target];
                if (field == .a) selected = selected.add(direction(row, .load));
                const post = if (field == .h or field == .l)
                    mode(row, .hl_increment).add(mode(row, .hl_decrement))
                else
                    S.zero();
                out[index] = is_active.sub(post).mul(
                    after.at(field).sub(before.at(field)),
                ).sub(selected.mul(value.sub(before.at(field))));
                index += 1;
            }
            for ([_]execution.StateIndex{ .f, .sp }) |field| {
                out[index] = is_active.mul(
                    after.at(field).sub(before.at(field)),
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
                    after.at(field).sub(before.at(field)),
                );
                index += 1;
            }

            const high_immediate = mode(row, .high_immediate);
            const immediate16 = mode(row, .immediate16);
            const basic = row.shapes[@intFromEnum(Shape.indirect)]
                .sub(high_immediate).sub(immediate16);
            const length = matrix.add(basic)
                .add(q(2).mul(immediate.add(high_immediate)))
                .add(q(3).mul(immediate16));
            out[index] = is_active.mul(
                after.at(.pc).sub(before.at(.pc)).sub(length)
                    .add(q(65536).mul(row.pc_carry)),
            );
            index += 1;

            const increment = mode(row, .hl_increment);
            const decrement = mode(row, .hl_decrement);
            out[index] = increment.mul(
                before.at(.l).add(one).sub(after.at(.l))
                    .sub(q(256).mul(row.hl_low_wrap)),
            ).add(decrement.mul(
                before.at(.l).sub(one).sub(after.at(.l))
                    .add(q(256).mul(row.hl_low_wrap)),
            ));
            index += 1;
            out[index] = increment.mul(
                before.at(.h).add(row.hl_low_wrap).sub(after.at(.h))
                    .sub(q(256).mul(row.hl_high_wrap)),
            ).add(decrement.mul(
                before.at(.h).sub(row.hl_low_wrap).sub(after.at(.h))
                    .add(q(256).mul(row.hl_high_wrap)),
            ));
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
                .address = is_active.mul(before.at(.pc)),
                .value = expected_opcode,
                .active = is_active,
                .read = is_active,
                .write = S.zero(),
                .program = is_active,
            };

            const dst_hl = immediate.mul(row.destinations[6]);
            const matrix_read = matrix.mul(row.sources[6]);
            const matrix_write = matrix.mul(row.destinations[6]);
            const matrix_memory = matrix_read.add(matrix_write);
            const basic_load = basicDirection(row, .load);
            const basic_store = basicDirection(row, .store);
            const high_load = indirect(row, .high_immediate, .load);
            const high_store = indirect(row, .high_immediate, .store);
            const absolute_load = indirect(row, .immediate16, .load);
            const absolute_store = indirect(row, .immediate16, .store);
            const fetch1 = immediate.add(high_immediate).add(immediate16);
            const hl = q(256).mul(before.at(.h)).add(before.at(.l));
            var basic_address = S.zero();
            const addresses = [5]S{
                q(256).mul(before.at(.b)).add(before.at(.c)),
                q(256).mul(before.at(.d)).add(before.at(.e)),
                hl,
                hl,
                q(0xff00).add(before.at(.c)),
            };
            for (addresses, 0..) |address, address_mode|
                basic_address = basic_address.add(
                    modeIndex(row, address_mode).mul(address),
                );
            buses[1] = .{
                .address = matrix_memory.mul(hl).add(basic_address).add(
                    fetch1.mul(
                        before.at(.pc).add(one)
                            .sub(q(65536).mul(row.fetch1_carry)),
                    ),
                ),
                .value = matrix_memory.add(immediate).add(basic).mul(value)
                    .add(high_immediate.add(immediate16).mul(machine.bus[1].value)),
                .active = matrix_memory.add(immediate)
                    .add(row.shapes[@intFromEnum(Shape.indirect)]),
                .read = matrix_read.add(immediate).add(basic_load)
                    .add(high_immediate).add(immediate16),
                .write = matrix_write.add(basic_store),
                .program = fetch1,
            };
            buses[2] = .{
                .address = dst_hl.mul(hl)
                    .add(high_immediate.mul(
                        q(0xff00).add(machine.bus[1].value),
                    ))
                    .add(immediate16.mul(
                    before.at(.pc).add(q(2))
                        .sub(q(65536).mul(row.fetch2_carry)),
                )),
                .value = dst_hl.add(high_immediate).mul(value)
                    .add(immediate16.mul(machine.bus[2].value)),
                .active = dst_hl.add(high_immediate).add(immediate16),
                .read = high_load.add(immediate16),
                .write = dst_hl.add(high_store),
                .program = immediate16,
            };
            buses[3] = .{
                .address = immediate16.mul(
                    machine.bus[1].value
                        .add(q(256).mul(machine.bus[2].value)),
                ),
                .value = immediate16.mul(value),
                .active = immediate16,
                .read = absolute_load,
                .write = absolute_store,
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

        fn mode(row: Row, address_mode: AddressMode) S {
            return modeIndex(row, @intFromEnum(address_mode));
        }

        fn modeIndex(row: Row, address_mode: usize) S {
            return row.indirects[2 * address_mode]
                .add(row.indirects[2 * address_mode + 1]);
        }

        fn direction(row: Row, which: Direction) S {
            var selected = S.zero();
            for (0..7) |address_mode|
                selected = selected.add(
                    row.indirects[2 * address_mode + @intFromEnum(which)],
                );
            return selected;
        }

        fn basicDirection(row: Row, which: Direction) S {
            var selected = S.zero();
            for (0..5) |address_mode|
                selected = selected.add(
                    row.indirects[2 * address_mode + @intFromEnum(which)],
                );
            return selected;
        }

        fn indirect(row: Row, address_mode: AddressMode, which: Direction) S {
            return row.indirects[
                2 * @intFromEnum(address_mode) + @intFromEnum(which)
            ];
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
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    switch (step.selection) {
        .matrix => |selected| {
            output[@intFromEnum(Shape.matrix)] = M31.one();
            output[3 + selected.dst] = M31.one();
            output[11 + selected.src] = M31.one();
        },
        .immediate => |dst| {
            output[@intFromEnum(Shape.immediate)] = M31.one();
            output[3 + dst] = M31.one();
        },
        .indirect => |selected| {
            output[@intFromEnum(Shape.indirect)] = M31.one();
            output[
                19 + 2 * @intFromEnum(selected.mode) +
                    @intFromEnum(selected.direction)
            ] = M31.one();
        },
    }
    writeBits(output[33..41], transferredValue(step));
    const trace = step.trace;
    output[41] = boolean(
        @as(u32, trace.before.pc) + trace.decoded.instruction.length > 0xffff,
    );
    output[42] = boolean(
        trace.decoded.instruction.length >= 2 and trace.before.pc == 0xffff,
    );
    output[43] = boolean(
        trace.decoded.instruction.length >= 3 and trace.before.pc >= 0xfffe,
    );
    const post_increment = modeSelected(step.selection, .hl_increment);
    const post_decrement = modeSelected(step.selection, .hl_decrement);
    output[44] = boolean(
        (post_increment and trace.before.l == 0xff) or
            (post_decrement and trace.before.l == 0),
    );
    output[45] = boolean(
        (post_increment and trace.before.hl() == 0xffff) or
            (post_decrement and trace.before.hl() == 0),
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
    const dst = targetIndex(instruction.dst);
    const src = targetIndex(instruction.src);
    if (dst != null and src != null and !(dst.? == 6 and src.? == 6))
        return .{ .matrix = .{ .dst = dst.?, .src = src.? } };
    if (dst != null and instruction.src == .imm8)
        return .{ .immediate = dst.? };
    if (indirectMode(instruction.dst)) |address_mode| {
        if (instruction.src == .a)
            return .{ .indirect = .{
                .mode = address_mode,
                .direction = .store,
            } };
    }
    if (instruction.dst == .a) {
        if (indirectMode(instruction.src)) |address_mode|
            return .{ .indirect = .{
                .mode = address_mode,
                .direction = .load,
            } };
    }
    return null;
}

fn targetIndex(operand: isa.Operand) ?usize {
    return switch (operand) {
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

fn indirectMode(operand: isa.Operand) ?AddressMode {
    return switch (operand) {
        .indirect_bc => .bc,
        .indirect_de => .de,
        .indirect_hl_increment => .hl_increment,
        .indirect_hl_decrement => .hl_decrement,
        .high_c => .high_c,
        .high_imm8 => .high_immediate,
        .indirect_imm16 => .immediate16,
        else => null,
    };
}

fn modeSelected(selection: Selection, wanted: AddressMode) bool {
    return switch (selection) {
        .indirect => |selected| selected.mode == wanted,
        else => false,
    };
}

fn transferredValue(step: ValidatedStep) u8 {
    return switch (step.selection) {
        .matrix => |selected| switch (selected.src) {
            0 => step.trace.before.b,
            1 => step.trace.before.c,
            2 => step.trace.before.d,
            3 => step.trace.before.e,
            4 => step.trace.before.h,
            5 => step.trace.before.l,
            6 => step.trace.cycles[1].value,
            7 => step.trace.before.a,
            else => unreachable,
        },
        .immediate => step.trace.cycles[1].value,
        .indirect => |selected| if (selected.direction == .store)
            step.trace.before.a
        else
            step.trace.cycles[
                switch (selected.mode) {
                    .high_immediate => 2,
                    .immediate16 => 3,
                    else => 1,
                }
            ].value,
    };
}

fn writeBits(destination: []M31, value: u8) void {
    for (destination, 0..) |*bit_value, bit_index|
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

test "LOAD8 AIR covers all 85 encodings and edge values" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    var count: usize = 0;
    for (isa.base_table, 0..) |instruction, opcode| {
        if (instruction.family() != .load8) continue;
        count += 1;
        memory.write(0x100, @intCast(opcode));
        memory.write(0x101, 0x34);
        memory.write(0x102, 0x80);
        var cpu = runner.Cpu{
            .a = 0xa5,
            .b = 0x12,
            .c = 0x34,
            .d = 0x56,
            .e = 0x78,
            .f = 0xf0,
            .h = 0x80,
            .l = 0x10,
            .sp = 0xcafe,
            .pc = 0x100,
            .ime = true,
            .ime_enable_pending = true,
        };
        for ([_]u16{ cpu.bc(), cpu.de(), cpu.hl(), 0xff34, 0x8034 }) |address|
            memory.write(address, 0x5a);
        const trace = try runner.step(&cpu, &memory);
        const witness = columns(try ValidatedStep.init(trace));
        try std.testing.expect((try evaluate(witness)).allZero());
        try std.testing.expect((try evaluateBound(
            witness,
            execution.columns(trace, 7),
        )).allZero());
    }
    try std.testing.expectEqual(@as(usize, 85), count);
}

test "LOAD8 AIR binds wrap opcode state bus and activity" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    for ([_]struct { opcode: u8, hl: u16, expected: u16 }{
        .{ .opcode = 0x22, .hl = 0xffff, .expected = 0 },
        .{ .opcode = 0x2a, .hl = 0xffff, .expected = 0 },
        .{ .opcode = 0x32, .hl = 0, .expected = 0xffff },
        .{ .opcode = 0x3a, .hl = 0, .expected = 0xffff },
    }) |case| {
        memory.write(0x100, case.opcode);
        memory.write(case.hl, 0x81);
        var edge_cpu = runner.Cpu{ .a = 0xff, .pc = 0x100 };
        edge_cpu.setHl(case.hl);
        const edge = try runner.step(&edge_cpu, &memory);
        try std.testing.expectEqual(case.expected, edge.after.hl());
        try std.testing.expect((try evaluateBound(
            columns(try ValidatedStep.init(edge)),
            execution.columns(edge, 0),
        )).allZero());
    }

    memory.write(0xffff, 0xfa);
    memory.write(0, 0x34);
    memory.write(1, 0x80);
    memory.write(0x8034, 0x81);
    var cpu = runner.Cpu{ .pc = 0xffff, .h = 0xff, .l = 0xff };
    const trace = try runner.step(&cpu, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());

    witness[33] = if (witness[33].isZero()) M31.one() else M31.zero();
    try std.testing.expect(!(try evaluateBound(witness, machine)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    var forged = machine;
    forged[2 * execution.N_STATE_COLUMNS + 1] = M31.fromCanonical(0xfb);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    forged = machine;
    forged[2 * execution.N_STATE_COLUMNS + 3 * execution.N_BUS_COLUMNS] =
        M31.fromCanonical(0x8035);
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
    var forged_trace = trace;
    forged_trace.decoded.raw_opcode = 0xf0;
    try std.testing.expectError(error.NotLoad8, ValidatedStep.init(forged_trace));
    forged_trace = trace;
    forged_trace.decoded.immediate ^= 1;
    try std.testing.expectError(error.NotLoad8, ValidatedStep.init(forged_trace));

    var inactive = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    inactive[33] = M31.one();
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    var machine_lifted: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, inactive) |*dst, source| dst.* = QM31.fromBase(source);
    for (&machine_lifted, machine) |*dst, source| dst.* = QM31.fromBase(source);
    try std.testing.expect(!(Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine_lifted),
        QM31.zero(),
    )).allZero());

    memory.write(0xffff, 0x00);
    cpu.pc = 0xffff;
    try std.testing.expectError(
        error.NotLoad8,
        ValidatedStep.init(try runner.step(&cpu, &memory)),
    );
}
