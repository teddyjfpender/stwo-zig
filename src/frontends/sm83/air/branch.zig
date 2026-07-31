//! Direct and execution-bound constraints for SM83 jumps, calls, returns, and
//! restart vectors.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const isa = @import("../isa/mod.zig");
const runner = @import("../runner/mod.zig");

const branch_opcodes = [_]u8{
    0x18, 0x20, 0x28, 0x30, 0x38,
    0xc0, 0xc2, 0xc3, 0xc4, 0xc7,
    0xc8, 0xc9, 0xca, 0xcc, 0xcd,
    0xcf, 0xd0, 0xd2, 0xd4, 0xd7,
    0xd8, 0xda, 0xdc, 0xdf, 0xe7,
    0xe9, 0xef, 0xf7, 0xff,
};

const N_PATHS = 45;
pub const N_MAIN_COLUMNS: usize = 98;
pub const N_CONSTRAINTS: usize = 107;
pub const N_EXECUTION_BINDING_CONSTRAINTS: usize = 155;
pub const N_BOUND_CONSTRAINTS: usize =
    N_CONSTRAINTS + N_EXECUTION_BINDING_CONSTRAINTS;

const Kind = enum { jr, jp_imm, jp_hl, call, ret, restart };

pub const ValidatedStep = struct {
    trace: runner.StepTrace,
    opcode_index: usize,

    pub fn init(trace: runner.StepTrace) error{NotBranch}!ValidatedStep {
        const raw = trace.decoded.raw_opcode;
        if (raw > 0xff) return error.NotBranch;
        const opcode_index = findOpcode(@intCast(raw)) orelse return error.NotBranch;
        const instruction = trace.decoded.instruction;
        if (!std.meta.eql(instruction, isa.base_table[@intCast(raw)]) or
            instruction.family() != .branch or
            trace.cycle_count < instruction.length or
            trace.cycle_count != (if (trace.branch_taken)
                instruction.taken_m_cycles
            else
                instruction.m_cycles) or
            trace.decoded.immediate != immediateFromTrace(trace))
        {
            return error.NotBranch;
        }
        return .{ .trace = trace, .opcode_index = opcode_index };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            paths: [N_PATHS]S,
            target_bits: [16]S,
            fallthrough_bits: [16]S,
            offset_bits: [8]S,
            flags: [4]S,
            pc_carries: [3]S,
            jr_wrap_up: S,
            jr_wrap_down: S,
            sp_minus_carries: [2]S,
            sp_plus_carries: [2]S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS)
                    return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .paths = values[0..45].*,
                    .target_bits = values[45..61].*,
                    .fallthrough_bits = values[61..77].*,
                    .offset_bits = values[77..85].*,
                    .flags = values[85..89].*,
                    .pc_carries = values[89..92].*,
                    .jr_wrap_up = values[92],
                    .jr_wrap_down = values[93],
                    .sp_minus_carries = values[94..96].*,
                    .sp_plus_carries = values[96..98].*,
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
            @setEvalBranchQuota(100_000);
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;
            const one = S.one();
            var active = S.zero();
            for (row.paths) |selector| {
                out[index] = bit(selector);
                index += 1;
                active = active.add(selector);
            }
            out[index] = active.sub(is_active);
            index += 1;
            for (row.target_bits ++ row.fallthrough_bits ++
                row.offset_bits ++ row.flags) |value|
            {
                out[index] = bit(value);
                index += 1;
            }
            for (row.pc_carries ++ .{
                row.jr_wrap_up,
                row.jr_wrap_down,
            } ++ row.sp_minus_carries ++ row.sp_plus_carries) |value| {
                out[index] = bit(value);
                index += 1;
            }

            var jr = S.zero();
            var length_one = S.zero();
            var length_two = S.zero();
            var push = S.zero();
            var pop = S.zero();
            comptime var cursor: usize = 0;
            inline for (branch_opcodes) |opcode| {
                const instruction = isa.base_table[opcode];
                const kind = kindOf(instruction);
                if (instruction.condition == .always) {
                    const selector = row.paths[cursor];
                    cursor += 1;
                    if (kind == .jr) jr = jr.add(selector);
                    if (instruction.length == 1) length_one = length_one.add(selector);
                    if (instruction.length == 2) length_two = length_two.add(selector);
                    if (kind == .call or kind == .restart) push = push.add(selector);
                    if (kind == .ret) pop = pop.add(selector);
                } else {
                    const not_taken = row.paths[cursor];
                    const taken = row.paths[cursor + 1];
                    cursor += 2;
                    const selected = not_taken.add(taken);
                    if (kind == .jr) jr = jr.add(selected);
                    if (instruction.length == 1) length_one = length_one.add(selected);
                    if (instruction.length == 2) length_two = length_two.add(selected);
                    if (kind == .call) push = push.add(taken);
                    if (kind == .ret) pop = pop.add(taken);
                }
            }
            comptime std.debug.assert(cursor == N_PATHS);

            const target = compose(row.target_bits);
            const fallthrough = compose(row.fallthrough_bits);
            const offset = compose(row.offset_bits);
            out[index] = row.jr_wrap_up.mul(row.jr_wrap_down);
            index += 1;
            out[index] = one.sub(jr).mul(offset);
            index += 1;
            out[index] = one.sub(jr).mul(
                row.jr_wrap_up.add(row.jr_wrap_down),
            );
            index += 1;
            out[index] = jr.mul(
                fallthrough.add(offset)
                    .sub(q(256).mul(row.offset_bits[7]))
                    .sub(target)
                    .sub(q(65536).mul(row.jr_wrap_up))
                    .add(q(65536).mul(row.jr_wrap_down)),
            );
            index += 1;
            out[index] = length_one.mul(row.pc_carries[1]);
            index += 1;
            out[index] = length_one.add(length_two).mul(row.pc_carries[2]);
            index += 1;
            out[index] = one.sub(push).mul(
                row.sp_minus_carries[0].add(row.sp_minus_carries[1]),
            );
            index += 1;
            out[index] = one.sub(pop).mul(
                row.sp_plus_carries[0].add(row.sp_plus_carries[1]),
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
            @setEvalBranchQuota(500_000);
            const semantic = Self.evaluate(row, is_active);
            var out: [N_BOUND_CONSTRAINTS]S = undefined;
            @memcpy(out[0..N_CONSTRAINTS], &semantic.values);
            var index: usize = N_CONSTRAINTS;
            const one = S.one();
            const target = compose(row.target_bits);
            const target_low = compose(row.target_bits[0..8].*);
            const target_high = compose(row.target_bits[8..16].*);
            const fallthrough = compose(row.fallthrough_bits);
            const return_low = compose(row.fallthrough_bits[0..8].*);
            const return_high = compose(row.fallthrough_bits[8..16].*);
            const offset = compose(row.offset_bits);
            const pc = machine.before.at(.pc);
            const pc1 = pc.add(one).sub(q(65536).mul(row.pc_carries[0]));
            const pc2 = pc1.add(one).sub(q(65536).mul(row.pc_carries[1]));
            const pc3 = pc2.add(one).sub(q(65536).mul(row.pc_carries[2]));
            const sp = machine.before.at(.sp);
            const sp_minus1 = sp.sub(one)
                .add(q(65536).mul(row.sp_minus_carries[0]));
            const sp_minus2 = sp_minus1.sub(one)
                .add(q(65536).mul(row.sp_minus_carries[1]));
            const sp_plus1 = sp.add(one)
                .sub(q(65536).mul(row.sp_plus_carries[0]));
            const sp_plus2 = sp_plus1.add(one)
                .sub(q(65536).mul(row.sp_plus_carries[1]));

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }

            var expected_bus = [_]execution.Bus(S){zeroBus()} **
                execution.N_BUS_CYCLES;
            var length_one = S.zero();
            var length_two = S.zero();
            var length_three = S.zero();
            var trace_taken = S.zero();
            var control_taken = S.zero();
            var conditional_taken = S.zero();
            var expected_conditional_taken = S.zero();
            var push = S.zero();
            var pop = S.zero();
            var expected_cycles = S.zero();
            var target_binding = S.zero();
            comptime var cursor: usize = 0;
            inline for (branch_opcodes) |opcode| {
                const instruction = isa.base_table[opcode];
                const kind = kindOf(instruction);
                if (instruction.condition == .always) {
                    const selector = row.paths[cursor];
                    cursor += 1;
                    addPath(
                        &expected_bus,
                        selector,
                        instruction,
                        true,
                        pc,
                        pc1,
                        pc2,
                        sp,
                        sp_minus1,
                        sp_minus2,
                        sp_plus1,
                        target_low,
                        target_high,
                        return_low,
                        return_high,
                        offset,
                    );
                    addLength(
                        instruction.length,
                        selector,
                        &length_one,
                        &length_two,
                        &length_three,
                    );
                    control_taken = control_taken.add(selector);
                    if (kind != .restart) trace_taken = trace_taken.add(selector);
                    if (kind == .call or kind == .restart) push = push.add(selector);
                    if (kind == .ret) pop = pop.add(selector);
                    expected_cycles = expected_cycles.add(
                        q(instruction.m_cycles).mul(selector),
                    );
                    target_binding = target_binding.add(switch (kind) {
                        .jp_hl => selector.mul(
                            target.sub(
                                q(256).mul(machine.before.at(.h))
                                    .add(machine.before.at(.l)),
                            ),
                        ),
                        .restart => selector.mul(
                            target.sub(q(instruction.parameter)),
                        ),
                        else => S.zero(),
                    });
                } else {
                    const not_taken = row.paths[cursor];
                    const taken = row.paths[cursor + 1];
                    cursor += 2;
                    const selected = not_taken.add(taken);
                    addPath(
                        &expected_bus,
                        not_taken,
                        instruction,
                        false,
                        pc,
                        pc1,
                        pc2,
                        sp,
                        sp_minus1,
                        sp_minus2,
                        sp_plus1,
                        target_low,
                        target_high,
                        return_low,
                        return_high,
                        offset,
                    );
                    addPath(
                        &expected_bus,
                        taken,
                        instruction,
                        true,
                        pc,
                        pc1,
                        pc2,
                        sp,
                        sp_minus1,
                        sp_minus2,
                        sp_plus1,
                        target_low,
                        target_high,
                        return_low,
                        return_high,
                        offset,
                    );
                    addLength(
                        instruction.length,
                        selected,
                        &length_one,
                        &length_two,
                        &length_three,
                    );
                    conditional_taken = conditional_taken.add(taken);
                    expected_conditional_taken = expected_conditional_taken.add(
                        selected.mul(conditionValue(row.flags, instruction.condition)),
                    );
                    trace_taken = trace_taken.add(taken);
                    control_taken = control_taken.add(taken);
                    if (kind == .call) push = push.add(taken);
                    if (kind == .ret) {
                        pop = pop.add(taken);
                        target_binding = target_binding.add(not_taken.mul(target));
                    }
                    expected_cycles = expected_cycles
                        .add(q(instruction.m_cycles).mul(not_taken))
                        .add(q(instruction.taken_m_cycles).mul(taken));
                }
            }
            comptime std.debug.assert(cursor == N_PATHS);

            out[index] = conditional_taken.sub(expected_conditional_taken);
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f))
                .sub(is_active.mul(flags(row.flags)));
            index += 1;
            out[index] = is_active.mul(fallthrough).sub(
                length_one.mul(pc1)
                    .add(length_two.mul(pc2))
                    .add(length_three.mul(pc3)),
            );
            index += 1;
            out[index] = is_active.mul(machine.after.at(.pc)).sub(
                control_taken.mul(target)
                    .add(is_active.sub(control_taken).mul(fallthrough)),
            );
            index += 1;
            out[index] = is_active.mul(machine.after.at(.sp)).sub(
                push.mul(sp_minus2)
                    .add(pop.mul(sp_plus2))
                    .add(is_active.sub(push).sub(pop).mul(sp)),
            );
            index += 1;
            out[index] = is_active.mul(machine.branch_taken).sub(trace_taken);
            index += 1;
            out[index] = is_active.mul(
                machine.mcycle_after.sub(machine.mcycle_before),
            ).sub(expected_cycles);
            index += 1;
            out[index] = target_binding;
            index += 1;

            for (machine.bus, expected_bus) |actual, expected| {
                inline for (@typeInfo(execution.Bus(S)).@"struct".fields) |field| {
                    out[index] = is_active.mul(@field(actual, field.name))
                        .sub(@field(expected, field.name));
                    index += 1;
                }
            }
            for ([_]execution.StateIndex{
                .a,
                .b,
                .c,
                .d,
                .e,
                .f,
                .h,
                .l,
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

        fn addPath(
            buses: *[execution.N_BUS_CYCLES]execution.Bus(S),
            selector: S,
            comptime instruction: isa.Instruction,
            comptime taken: bool,
            pc: S,
            pc1: S,
            pc2: S,
            sp: S,
            sp_minus1: S,
            sp_minus2: S,
            sp_plus1: S,
            target_low: S,
            target_high: S,
            return_low: S,
            return_high: S,
            offset: S,
        ) void {
            const opcode = q(findRaw(instruction));
            addCycle(&buses[0], selector, true, false, true, pc, opcode);
            switch (kindOf(instruction)) {
                .jr => {
                    addCycle(&buses[1], selector, true, false, true, pc1, offset);
                    if (taken)
                        addCycle(&buses[2], selector, false, false, false, pc1, offset);
                },
                .jp_imm => {
                    addCycle(&buses[1], selector, true, false, true, pc1, target_low);
                    addCycle(&buses[2], selector, true, false, true, pc2, target_high);
                    if (taken)
                        addCycle(&buses[3], selector, false, false, false, pc2, target_high);
                },
                .jp_hl => {},
                .call => {
                    addCycle(&buses[1], selector, true, false, true, pc1, target_low);
                    addCycle(&buses[2], selector, true, false, true, pc2, target_high);
                    if (taken) {
                        addCycle(&buses[3], selector, false, false, false, pc2, target_high);
                        addCycle(
                            &buses[4],
                            selector,
                            false,
                            true,
                            false,
                            sp_minus1,
                            return_high,
                        );
                        addCycle(
                            &buses[5],
                            selector,
                            false,
                            true,
                            false,
                            sp_minus2,
                            return_low,
                        );
                    }
                },
                .ret => {
                    if (instruction.condition != .always)
                        addCycle(&buses[1], selector, false, false, false, pc, opcode);
                    if (taken) {
                        const low_cycle: usize =
                            if (instruction.condition == .always) 1 else 2;
                        addCycle(
                            &buses[low_cycle],
                            selector,
                            true,
                            false,
                            false,
                            sp,
                            target_low,
                        );
                        addCycle(
                            &buses[low_cycle + 1],
                            selector,
                            true,
                            false,
                            false,
                            sp_plus1,
                            target_high,
                        );
                        addCycle(
                            &buses[low_cycle + 2],
                            selector,
                            false,
                            false,
                            false,
                            sp_plus1,
                            target_high,
                        );
                    }
                },
                .restart => {
                    addCycle(&buses[1], selector, false, false, false, pc, opcode);
                    addCycle(
                        &buses[2],
                        selector,
                        false,
                        true,
                        false,
                        sp_minus1,
                        return_high,
                    );
                    addCycle(
                        &buses[3],
                        selector,
                        false,
                        true,
                        false,
                        sp_minus2,
                        return_low,
                    );
                },
            }
        }

        fn addCycle(
            cycle: *execution.Bus(S),
            selector: S,
            comptime read: bool,
            comptime write: bool,
            comptime program: bool,
            address: S,
            value: S,
        ) void {
            cycle.active = cycle.active.add(selector);
            if (read) cycle.read = cycle.read.add(selector);
            if (write) cycle.write = cycle.write.add(selector);
            if (program) cycle.program = cycle.program.add(selector);
            cycle.address = cycle.address.add(selector.mul(address));
            cycle.value = cycle.value.add(selector.mul(value));
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

        fn flags(values: [4]S) S {
            return q(128).mul(values[0])
                .add(q(64).mul(values[1]))
                .add(q(32).mul(values[2]))
                .add(q(16).mul(values[3]));
        }

        fn conditionValue(values: [4]S, condition: isa.Condition) S {
            return switch (condition) {
                .nonzero => S.one().sub(values[0]),
                .zero => values[0],
                .no_carry => S.one().sub(values[3]),
                .carry => values[3],
                .always => unreachable,
            };
        }

        fn addLength(
            comptime length: u2,
            selector: S,
            one: *S,
            two: *S,
            three: *S,
        ) void {
            switch (length) {
                1 => one.* = one.add(selector),
                2 => two.* = two.add(selector),
                3 => three.* = three.add(selector),
                else => unreachable,
            }
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const trace = step.trace;
    const instruction = trace.decoded.instruction;
    const kind = kindOf(instruction);
    const fallthrough = trace.before.pc +% instruction.length;
    const target: u16 = switch (kind) {
        .jr => addSigned(fallthrough, @truncate(trace.decoded.immediate)),
        .jp_imm, .call => trace.decoded.immediate,
        .jp_hl => trace.before.hl(),
        .ret => if (trace.branch_taken) trace.after.pc else 0,
        .restart => instruction.parameter,
    };
    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    output[pathIndex(step.opcode_index, trace.branch_taken)] = M31.one();
    writeBits(output[45..61], target);
    writeBits(output[61..77], fallthrough);
    if (kind == .jr)
        writeBits(output[77..85], @as(u8, @truncate(trace.decoded.immediate)));
    writeFlags(output[85..89], trace.before.f);

    var next_pc = trace.before.pc;
    for (0..instruction.length) |step_index| {
        const carry = next_pc == 0xffff;
        next_pc +%= 1;
        output[89 + step_index] = boolean(carry);
    }
    if (kind == .jr) {
        const signed: i16 = @as(i8, @bitCast(@as(u8, @truncate(trace.decoded.immediate))));
        const wide = @as(i32, fallthrough) + signed;
        output[92] = boolean(wide > 0xffff);
        output[93] = boolean(wide < 0);
    }

    const push = (kind == .call and trace.branch_taken) or kind == .restart;
    const pop = kind == .ret and trace.branch_taken;
    if (push) {
        var sp = trace.before.sp;
        output[94] = boolean(sp == 0);
        sp -%= 1;
        output[95] = boolean(sp == 0);
    }
    if (pop) {
        var sp = trace.before.sp;
        output[96] = boolean(sp == 0xffff);
        sp +%= 1;
        output[97] = boolean(sp == 0xffff);
    }
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
    for (branch_opcodes, 0..) |candidate, index|
        if (candidate == opcode) return index;
    return null;
}

fn findRaw(instruction: isa.Instruction) u8 {
    for (branch_opcodes) |opcode|
        if (std.meta.eql(instruction, isa.base_table[opcode])) return opcode;
    unreachable;
}

fn kindOf(instruction: isa.Instruction) Kind {
    return switch (instruction.operation) {
        .jump_relative => .jr,
        .jump => if (instruction.src == .hl) .jp_hl else .jp_imm,
        .call => .call,
        .ret => .ret,
        .restart => .restart,
        else => unreachable,
    };
}

fn pathIndex(opcode_index: usize, taken: bool) usize {
    var result: usize = 0;
    for (branch_opcodes[0..opcode_index]) |opcode| {
        result += if (isa.base_table[opcode].condition == .always) 1 else 2;
    }
    if (isa.base_table[branch_opcodes[opcode_index]].condition != .always and taken)
        result += 1;
    return result;
}

fn immediateFromTrace(trace: runner.StepTrace) u16 {
    return switch (trace.decoded.instruction.length) {
        1 => 0,
        2 => trace.cycles[1].value,
        3 => @as(u16, trace.cycles[1].value) |
            (@as(u16, trace.cycles[2].value) << 8),
        else => unreachable,
    };
}

fn addSigned(base: u16, encoded: u8) u16 {
    const signed: i16 = @as(i8, @bitCast(encoded));
    return @bitCast(@as(i16, @bitCast(base)) +% signed);
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

test {
    _ = @import("branch_test.zig");
}

test "branch AIR rejects delayed IME promotion mutation" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x18);
    memory.write(1, 0);
    var cpu = runner.Cpu{ .ime_enable_pending = true };
    const trace = try runner.step(&cpu, &memory);
    const witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());
    var forged = machine;
    forged[
        execution.N_STATE_COLUMNS +
            @intFromEnum(execution.StateIndex.ime_enable_pending)
    ] = M31.one();
    try std.testing.expect(!(try evaluateBound(witness, forged)).allZero());
}
