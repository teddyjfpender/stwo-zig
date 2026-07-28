//! Fixed-width SIMD interpreter for captured Cairo AIR programs.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const eval = @import("../../witness/eval_program.zig");
const audit = @import("composition_audit.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const lane_count = m31.VEC_WIDTH;
pub const PackedM31 = m31.Vec4u32;

const PackedQm31 = struct {
    coordinates: [4]PackedM31,

    fn zero() PackedQm31 {
        return .{ .coordinates = @splat(@as(PackedM31, @splat(0))) };
    }

    fn splat(value: QM31) PackedQm31 {
        const coordinates = value.toM31Array();
        return .{ .coordinates = .{
            @splat(coordinates[0].toU32()),
            @splat(coordinates[1].toU32()),
            @splat(coordinates[2].toU32()),
            @splat(coordinates[3].toU32()),
        } };
    }

    fn add(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.addVec4(
                lhs.coordinates[coordinate],
                rhs.coordinates[coordinate],
            );
        }
        return result;
    }

    fn sub(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.subVec4(
                lhs.coordinates[coordinate],
                rhs.coordinates[coordinate],
            );
        }
        return result;
    }

    fn neg(value: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.subVec4(
                @splat(0),
                value.coordinates[coordinate],
            );
        }
        return result;
    }

    fn mulBase(value: PackedQm31, scalar: PackedM31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.mulVec4(
                value.coordinates[coordinate],
                scalar,
            );
        }
        return result;
    }

    fn mul(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        const a = lhs.coordinates;
        const b = rhs.coordinates;
        const x0 = m31.subVec4(
            m31.mulVec4(a[0], b[0]),
            m31.mulVec4(a[1], b[1]),
        );
        const x1 = m31.addVec4(
            m31.mulVec4(a[0], b[1]),
            m31.mulVec4(a[1], b[0]),
        );
        const y0 = m31.subVec4(
            m31.mulVec4(a[2], b[2]),
            m31.mulVec4(a[3], b[3]),
        );
        const y1 = m31.addVec4(
            m31.mulVec4(a[2], b[3]),
            m31.mulVec4(a[3], b[2]),
        );
        const c0 = m31.subVec4(
            m31.mulVec4(a[0], b[2]),
            m31.mulVec4(a[1], b[3]),
        );
        const c1 = m31.addVec4(
            m31.mulVec4(a[0], b[3]),
            m31.mulVec4(a[1], b[2]),
        );
        const c2 = m31.subVec4(
            m31.mulVec4(a[2], b[0]),
            m31.mulVec4(a[3], b[1]),
        );
        const c3 = m31.addVec4(
            m31.mulVec4(a[2], b[1]),
            m31.mulVec4(a[3], b[0]),
        );
        return .{ .coordinates = .{
            m31.addVec4(x0, m31.subVec4(m31.addVec4(y0, y0), y1)),
            m31.addVec4(x1, m31.addVec4(y0, m31.addVec4(y1, y1))),
            m31.addVec4(c0, c2),
            m31.addVec4(c1, c3),
        } };
    }

    fn lane(self: PackedQm31, index: usize) QM31 {
        return QM31.fromU32Unchecked(
            self.coordinates[0][index],
            self.coordinates[1][index],
            self.coordinates[2][index],
            self.coordinates[3][index],
        );
    }
};

pub const TraceReader = struct {
    context: *const anyopaque,
    read: *const fn (
        context: *const anyopaque,
        interaction: u8,
        column: u32,
        row: usize,
        offset: i32,
    ) anyerror!PackedM31,
};

pub const Input = struct {
    evaluation_log_size: u32,
    trace_log_size: u32,
    trace: TraceReader,
    extension_parameters: []const QM31,
    random_coefficients: []const QM31,
    constraint_base: u32,
    denominator_inverses: []const u32,
};

pub fn evaluatePart(
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: Input,
    output: anytype,
) !void {
    const row_count = checkedPow2(input.evaluation_log_size) catch
        return error.InvalidEvaluationInput;
    return evaluatePartRange(
        allocator,
        program,
        input,
        output,
        0,
        row_count,
    );
}

pub fn evaluatePartRange(
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: Input,
    output: anytype,
    row_start: usize,
    row_end: usize,
) !void {
    try program.validate();
    if (program.header.n_base_params != 0 or
        program.header.n_ext_params != input.extension_parameters.len or
        input.constraint_base + program.header.n_constraints > input.random_coefficients.len or
        program.header.domain_log_size != input.trace_log_size or
        input.trace_log_size > input.evaluation_log_size)
    {
        return error.InvalidEvaluationInput;
    }
    const row_count = checkedPow2(input.evaluation_log_size) catch
        return error.InvalidEvaluationInput;
    const denominator_count = checkedPow2(input.evaluation_log_size - input.trace_log_size) catch
        return error.InvalidEvaluationInput;
    if (row_count % lane_count != 0 or
        input.denominator_inverses.len != denominator_count or
        row_start > row_end or
        row_end > row_count or
        row_start % lane_count != 0 or
        row_end % lane_count != 0)
        return error.InvalidEvaluationInput;

    switch (audit.ablation()) {
        inline else => |mode| return runRange(
            mode,
            allocator,
            program,
            input,
            output,
            row_start,
            row_end,
        ),
    }
}

fn runRange(
    comptime mode: audit.Ablation,
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: Input,
    output: anytype,
    row_start: usize,
    row_end: usize,
) !void {
    const base = try allocator.alloc(PackedM31, program.header.max_base_regs);
    defer allocator.free(base);
    const extension = try allocator.alloc(PackedQm31, program.header.max_ext_regs);
    defer allocator.free(extension);
    var sink = PackedQm31.zero();

    var row = row_start;
    while (row < row_end) : (row += lane_count) {
        for (program.base_insts) |instruction| {
            base[instruction.dst] = switch (instruction.op) {
                .trace_col, .preprocessed_col => if (mode == .no_read)
                    @as(PackedM31, @splat(
                        (instruction.a +% @as(u32, @truncate(row))) | 1,
                    ))
                else
                    try input.trace.read(
                        input.trace.context,
                        instruction.interaction,
                        instruction.a,
                        row,
                        if (mode == .no_index) 0 else instruction.imm,
                    ),
                .param => return error.InvalidEvaluationInput,
                .constant => @splat(instruction.a),
                .add => m31.addVec4(base[instruction.a], base[instruction.b]),
                .sub => m31.subVec4(base[instruction.a], base[instruction.b]),
                .mul => m31.mulVec4(base[instruction.a], base[instruction.b]),
                .neg => m31.subVec4(@splat(0), base[instruction.a]),
                .inv => inverse(base[instruction.a]),
            };
        }
        for (program.ext_insts) |instruction| {
            extension[instruction.dst] = switch (instruction.op) {
                .secure_col => .{ .coordinates = .{
                    base[instruction.a],
                    base[instruction.b],
                    base[instruction.c],
                    base[instruction.d],
                } },
                .param => PackedQm31.splat(input.extension_parameters[instruction.a]),
                .constant => PackedQm31.splat(QM31.fromU32Unchecked(
                    instruction.a,
                    instruction.b,
                    instruction.c,
                    instruction.d,
                )),
                .add => PackedQm31.add(
                    extension[instruction.a],
                    extension[instruction.b],
                ),
                .sub => PackedQm31.sub(
                    extension[instruction.a],
                    extension[instruction.b],
                ),
                .mul => PackedQm31.mul(
                    extension[instruction.a],
                    extension[instruction.b],
                ),
                .neg => PackedQm31.neg(extension[instruction.a]),
            };
        }

        var evaluation = PackedQm31.zero();
        for (program.constraint_roots, 0..) |root, local_index| {
            const coefficient_index =
                input.constraint_base + local_index;
            evaluation = PackedQm31.add(
                evaluation,
                PackedQm31.mul(
                    extension[root],
                    PackedQm31.splat(input.random_coefficients[coefficient_index]),
                ),
            );
        }
        var denominator: PackedM31 = undefined;
        if (mode == .no_denominator) {
            denominator = @splat(input.denominator_inverses[0]);
        } else {
            inline for (0..lane_count) |lane| {
                denominator[lane] = input.denominator_inverses[
                    (row + lane) >> @intCast(input.trace_log_size)
                ];
            }
        }
        evaluation = PackedQm31.mulBase(evaluation, denominator);
        if (mode == .no_output) {
            sink = PackedQm31.add(sink, evaluation);
        } else {
            inline for (0..lane_count) |lane| {
                output.accumulate(row + lane, evaluation.lane(lane));
            }
        }
    }
    if (mode == .no_output) std.mem.doNotOptimizeAway(sink);
}

fn inverse(value: PackedM31) PackedM31 {
    var result: PackedM31 = @splat(1);
    var base = value;
    var exponent: u32 = m31.Modulus - 2;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) result = m31.mulVec4(result, base);
        base = m31.mulVec4(base, base);
    }
    return result;
}

fn checkedPow2(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "Cairo SIMD evaluator QM31 multiplication matches the scalar field" {
    const lhs = QM31.fromU32Unchecked(3, 5, 7, 11);
    const rhs = QM31.fromU32Unchecked(13, 17, 19, 23);
    const actual = PackedQm31.mul(PackedQm31.splat(lhs), PackedQm31.splat(rhs));
    for (0..lane_count) |lane| {
        try std.testing.expect(actual.lane(lane).eql(lhs.mul(rhs)));
    }
}
