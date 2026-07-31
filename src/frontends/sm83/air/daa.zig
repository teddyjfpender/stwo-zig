//! Direct constraints for the SM83 decimal-adjust instruction.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const execution = @import("execution.zig");
const runner = @import("../runner/mod.zig");

pub const N_MAIN_COLUMNS: usize = 34;
pub const N_CONSTRAINTS: usize = 47;
pub const N_BOUND_CONSTRAINTS: usize = N_CONSTRAINTS + 1 + N_MAIN_COLUMNS + 28;

pub const ValidatedStep = struct {
    trace: runner.StepTrace,

    pub fn init(trace: runner.StepTrace) error{NotDecimalAdjust}!ValidatedStep {
        if (trace.decoded.instruction.operation != .decimal_adjust)
            return error.NotDecimalAdjust;
        return .{ .trace = trace };
    }
};

pub fn Semantics(comptime S: type) type {
    return struct {
        const Self = @This();

        pub const Row = struct {
            values: [N_MAIN_COLUMNS]S,
            before_bits: [8]S,
            after_bits: [8]S,
            input_n: S,
            input_h: S,
            input_c: S,
            input_z: S,
            output_z: S,
            output_n: S,
            output_h: S,
            output_c: S,
            zero_inverse: S,
            low_gt9: S,
            high_gt9: S,
            high_eq9: S,
            high_middle_zero: S,
            a_gt99: S,
            low_correction: S,
            high_correction: S,
            wrap: S,
            pc_carry: S,

            pub fn fromColumns(values: []const S) !Row {
                if (values.len != N_MAIN_COLUMNS) return error.InvalidMainTraceShape;
                return .{
                    .values = values[0..N_MAIN_COLUMNS].*,
                    .before_bits = values[0..8].*,
                    .after_bits = values[8..16].*,
                    .input_n = values[16],
                    .input_h = values[17],
                    .input_c = values[18],
                    .output_z = values[19],
                    .output_n = values[20],
                    .output_h = values[21],
                    .output_c = values[22],
                    .zero_inverse = values[23],
                    .low_gt9 = values[24],
                    .high_gt9 = values[25],
                    .high_eq9 = values[26],
                    .high_middle_zero = values[27],
                    .a_gt99 = values[28],
                    .low_correction = values[29],
                    .high_correction = values[30],
                    .wrap = values[31],
                    .pc_carry = values[32],
                    .input_z = values[33],
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
            const one = S.one();
            var out: [N_CONSTRAINTS]S = undefined;
            var index: usize = 0;

            for (row.before_bits ++ row.after_bits) |value| {
                out[index] = bit(value);
                index += 1;
            }
            for ([_]S{
                row.input_n,
                row.input_h,
                row.input_c,
                row.input_z,
                row.output_z,
                row.output_n,
                row.output_h,
                row.output_c,
                row.low_gt9,
                row.high_gt9,
                row.high_eq9,
                row.high_middle_zero,
                row.a_gt99,
                row.low_correction,
                row.high_correction,
                row.wrap,
            }) |value| {
                out[index] = bit(value);
                index += 1;
            }

            const before = compose(row.before_bits);
            const after = compose(row.after_bits);
            const low_or = orBit(row.before_bits[2], row.before_bits[1]);
            const high_or = orBit(row.before_bits[6], row.before_bits[5]);
            const high_equal9_low_gt9 = row.high_eq9.mul(row.low_gt9);

            out[index] = row.high_middle_zero.sub(
                is_active.sub(row.before_bits[6]).mul(
                    is_active.sub(row.before_bits[5]),
                ),
            );
            index += 1;
            out[index] = row.low_gt9.sub(row.before_bits[3].mul(low_or));
            index += 1;
            out[index] = row.high_gt9.sub(row.before_bits[7].mul(high_or));
            index += 1;
            out[index] = row.high_eq9.sub(
                row.before_bits[7].mul(row.high_middle_zero).mul(row.before_bits[4]),
            );
            index += 1;
            out[index] = row.a_gt99.sub(orBit(row.high_gt9, high_equal9_low_gt9));
            index += 1;

            out[index] = row.low_correction.sub(
                row.input_h.add(
                    is_active.sub(row.input_n)
                        .mul(row.low_gt9.sub(row.input_h.mul(row.low_gt9))),
                ),
            );
            index += 1;
            out[index] = row.high_correction.sub(
                row.input_c.add(
                    is_active.sub(row.input_n)
                        .mul(row.a_gt99.sub(row.input_c.mul(row.a_gt99))),
                ),
            );
            index += 1;
            out[index] = row.output_c.sub(
                row.input_n.mul(row.input_c)
                    .add(one.sub(row.input_n).mul(row.high_correction)),
            );
            index += 1;
            out[index] = row.output_n.sub(row.input_n);
            index += 1;
            out[index] = row.output_h;
            index += 1;

            const correction = q(6).mul(row.low_correction)
                .add(q(96).mul(row.high_correction));
            out[index] = is_active.sub(row.input_n).mul(
                before.add(correction).sub(after).sub(q(256).mul(row.wrap)),
            );
            index += 1;
            out[index] = row.input_n.mul(
                before.sub(correction).sub(after).add(q(256).mul(row.wrap)),
            );
            index += 1;
            out[index] = after.mul(row.output_z);
            index += 1;
            out[index] = after.mul(row.zero_inverse).sub(is_active.sub(row.output_z));
            index += 1;
            out[index] = bit(row.pc_carry);
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

            out[index] = bit(is_active);
            index += 1;
            for (row.values) |value| {
                out[index] = one.sub(is_active).mul(value);
                index += 1;
            }
            out[index] = is_active.mul(machine.bus[0].value.sub(q(0x27)));
            index += 1;
            out[index] = is_active.mul(before.sub(machine.before.at(.a)));
            index += 1;
            out[index] = is_active.mul(after.sub(machine.after.at(.a)));
            index += 1;
            out[index] = is_active.mul(machine.before.at(.f)).sub(
                is_active.mul(flags(.{
                    row.input_n,
                    row.input_h,
                    row.input_c,
                }, row.input_z)),
            );
            index += 1;
            out[index] = is_active.mul(machine.after.at(.f)).sub(
                is_active.mul(flags(.{
                    row.output_n,
                    row.output_h,
                    row.output_c,
                }, row.output_z)),
            );
            index += 1;
            out[index] = is_active.mul(
                machine.after.at(.pc)
                    .sub(machine.before.at(.pc))
                    .sub(one)
                    .add(q(65536).mul(row.pc_carry)),
            );
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
            for (machine.bus[1..]) |cycle| {
                out[index] = is_active.mul(cycle.active);
                index += 1;
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

        fn orBit(left: S, right: S) S {
            return left.add(right).sub(left.mul(right));
        }

        fn compose(bits: [8]S) S {
            var value = S.zero();
            inline for (bits, 0..) |bit_value, bit_index| {
                value = value.add(q(@as(u64, 1) << bit_index).mul(bit_value));
            }
            return value;
        }

        fn q(value: u64) S {
            return S.fromBase(M31.fromU64(value));
        }

        fn flags(nhc: [3]S, zero: S) S {
            return q(128).mul(zero)
                .add(q(64).mul(nhc[0]))
                .add(q(32).mul(nhc[1]))
                .add(q(16).mul(nhc[2]));
        }
    };
}

pub const Shipped = Semantics(QM31);

pub fn columns(step: ValidatedStep) [N_MAIN_COLUMNS]M31 {
    const before = step.trace.before;
    const after = step.trace.after;
    const input_n = before.flag(.subtract);
    const input_h = before.flag(.half_carry);
    const input_c = before.flag(.carry);
    const low_gt9 = (before.a & 0x0f) > 9;
    const high_gt9 = (before.a >> 4) > 9;
    const high_eq9 = (before.a >> 4) == 9;
    const a_gt99 = before.a > 0x99;
    const low_correction = if (input_n) input_h else input_h or low_gt9;
    const high_correction = if (input_n) input_c else input_c or a_gt99;
    const correction = @as(u8, @intFromBool(low_correction)) * 6 +
        @as(u8, @intFromBool(high_correction)) * 96;
    const wrap = if (input_n)
        before.a < correction
    else
        @as(u16, before.a) + correction > 0xff;

    var output = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    writeBits(output[0..8], before.a);
    writeBits(output[8..16], after.a);
    output[16] = boolean(input_n);
    output[17] = boolean(input_h);
    output[18] = boolean(input_c);
    output[19] = boolean(after.flag(.zero));
    output[20] = boolean(after.flag(.subtract));
    output[21] = boolean(after.flag(.half_carry));
    output[22] = boolean(after.flag(.carry));
    output[23] = if (after.a == 0)
        M31.zero()
    else
        M31.fromCanonical(after.a).inv() catch unreachable;
    output[24] = boolean(low_gt9);
    output[25] = boolean(high_gt9);
    output[26] = boolean(high_eq9);
    output[27] = boolean(before.a & 0x60 == 0);
    output[28] = boolean(a_gt99);
    output[29] = boolean(low_correction);
    output[30] = boolean(high_correction);
    output[31] = boolean(wrap);
    output[32] = boolean(before.pc == 0xffff);
    output[33] = boolean(before.flag(.zero));
    return output;
}

pub fn evaluate(values: [N_MAIN_COLUMNS]M31) !Shipped.Evaluation {
    var lifted: [N_MAIN_COLUMNS]QM31 = undefined;
    for (&lifted, values) |*destination, value| destination.* = QM31.fromBase(value);
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
    for (&lifted, values) |*destination, value| destination.* = QM31.fromBase(value);
    for (&machine, execution_values) |*destination, value| {
        destination.* = QM31.fromBase(value);
    }
    return Shipped.evaluateBound(
        try Shipped.Row.fromColumns(&lifted),
        try execution.Row(QM31).fromColumns(&machine),
        QM31.one(),
    );
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}

fn writeBits(destination: []M31, value: u8) void {
    std.debug.assert(destination.len == 8);
    for (destination, 0..) |*bit_value, bit_index| {
        bit_value.* = M31.fromCanonical((value >> @intCast(bit_index)) & 1);
    }
}

test "DAA AIR accepts every input and rejects correction mutations" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x27);
    for (0..256) |a| {
        for (0..8) |flags_value| {
            var state = runner.Cpu{
                .a = @intCast(a),
                .f = @as(u8, @intCast(flags_value)) << 4,
            };
            const trace = try runner.step(&state, &memory);
            const witness = columns(try ValidatedStep.init(trace));
            try std.testing.expect((try evaluate(witness)).allZero());
        }
    }

    var state = runner.Cpu{ .a = 0x9a };
    const trace = try runner.step(&state, &memory);
    var witness = columns(try ValidatedStep.init(trace));
    witness[30] = M31.zero();
    try std.testing.expect(!(try evaluate(witness)).allZero());
    witness = columns(try ValidatedStep.init(trace));
    witness[8] = M31.one();
    try std.testing.expect(!(try evaluate(witness)).allZero());

    witness = columns(try ValidatedStep.init(trace));
    const machine = execution.columns(trace, 0);
    try std.testing.expect((try evaluateBound(witness, machine)).allZero());
    var forged_machine = machine;
    forged_machine[2 * execution.N_STATE_COLUMNS + 1] = M31.fromCanonical(0x2f);
    try std.testing.expect(!(try evaluateBound(witness, forged_machine)).allZero());
}
