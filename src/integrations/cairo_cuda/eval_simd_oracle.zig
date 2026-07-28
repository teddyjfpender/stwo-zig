//! Fixed-width Zig SIMD oracle for Cairo row-domain evaluation programs.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const eval = @import("stwo_cairo_frontend").witness.eval_program;

pub const lane_count = m31.VEC_WIDTH;
pub const PackedM31 = m31.Vec4u32;

pub const Qm31Words = [4]u32;

pub const PackedQm31 = struct {
    coordinates: [4]PackedM31,

    pub fn zero() PackedQm31 {
        return .{ .coordinates = @splat(@as(PackedM31, @splat(0))) };
    }

    pub fn splat(words: Qm31Words) PackedQm31 {
        return .{ .coordinates = .{
            @splat(words[0]),
            @splat(words[1]),
            @splat(words[2]),
            @splat(words[3]),
        } };
    }

    pub fn add(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.addVec4(
                lhs.coordinates[coordinate],
                rhs.coordinates[coordinate],
            );
        }
        return result;
    }

    pub fn sub(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.subVec4(
                lhs.coordinates[coordinate],
                rhs.coordinates[coordinate],
            );
        }
        return result;
    }

    pub fn neg(value: PackedQm31) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.subVec4(
                @splat(0),
                value.coordinates[coordinate],
            );
        }
        return result;
    }

    pub fn mulBase(
        value: PackedQm31,
        scalar: PackedM31,
    ) PackedQm31 {
        var result: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            result.coordinates[coordinate] = m31.mulVec4(
                value.coordinates[coordinate],
                scalar,
            );
        }
        return result;
    }

    pub fn mul(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
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
            m31.addVec4(
                x0,
                m31.subVec4(m31.addVec4(y0, y0), y1),
            ),
            m31.addVec4(
                x1,
                m31.addVec4(y0, m31.addVec4(y1, y1)),
            ),
            m31.addVec4(c0, c2),
            m31.addVec4(c1, c3),
        } };
    }

    pub fn lanes(self: PackedQm31) [lane_count]Qm31Words {
        var result: [lane_count]Qm31Words = undefined;
        for (0..lane_count) |lane| {
            inline for (0..4) |coordinate| {
                result[lane][coordinate] =
                    self.coordinates[coordinate][lane];
            }
        }
        return result;
    }
};

pub const Input = struct {
    trace_context: *const anyopaque,
    trace_value: *const fn (
        *const anyopaque,
        interaction: u8,
        column: u32,
        offset: i32,
    ) PackedM31,
    ext_params: []const Qm31Words,
    random_coefficients: []const Qm31Words,
    global_rc_base: u32,
    denominator_inverse: u32,
};

pub fn evaluatePart(
    allocator: std.mem.Allocator,
    program: eval.Program,
    input: Input,
    cumulative: *PackedQm31,
    zero_inversions: *usize,
) !void {
    try program.validate();
    if (program.header.n_base_params != 0 or
        program.header.n_ext_params != input.ext_params.len or
        input.global_rc_base + program.header.n_constraints >
            input.random_coefficients.len)
    {
        return error.InvalidOracleInput;
    }

    const base = try allocator.alloc(
        PackedM31,
        program.header.max_base_regs,
    );
    defer allocator.free(base);
    const extended = try allocator.alloc(
        PackedQm31,
        program.header.max_ext_regs,
    );
    defer allocator.free(extended);

    for (program.base_insts) |instruction| {
        base[instruction.dst] = switch (instruction.op) {
            .trace_col, .preprocessed_col => input.trace_value(
                input.trace_context,
                instruction.interaction,
                instruction.a,
                instruction.imm,
            ),
            .param => return error.InvalidOracleInput,
            .constant => @splat(instruction.a),
            .add => m31.addVec4(
                base[instruction.a],
                base[instruction.b],
            ),
            .sub => m31.subVec4(
                base[instruction.a],
                base[instruction.b],
            ),
            .mul => m31.mulVec4(
                base[instruction.a],
                base[instruction.b],
            ),
            .neg => m31.subVec4(
                @splat(0),
                base[instruction.a],
            ),
            .inv => inverse(base[instruction.a], zero_inversions),
        };
    }
    for (program.ext_insts) |instruction| {
        extended[instruction.dst] = switch (instruction.op) {
            .secure_col => .{ .coordinates = .{
                base[instruction.a],
                base[instruction.b],
                base[instruction.c],
                base[instruction.d],
            } },
            .param => PackedQm31.splat(input.ext_params[instruction.a]),
            .constant => PackedQm31.splat(.{
                instruction.a,
                instruction.b,
                instruction.c,
                instruction.d,
            }),
            .add => PackedQm31.add(
                extended[instruction.a],
                extended[instruction.b],
            ),
            .sub => PackedQm31.sub(
                extended[instruction.a],
                extended[instruction.b],
            ),
            .mul => PackedQm31.mul(
                extended[instruction.a],
                extended[instruction.b],
            ),
            .neg => PackedQm31.neg(extended[instruction.a]),
        };
    }

    var part_accumulator = PackedQm31.zero();
    for (program.constraint_roots, 0..) |root, root_index| {
        const coefficient = PackedQm31.splat(
            input.random_coefficients[
                input.global_rc_base + root_index
            ],
        );
        part_accumulator = PackedQm31.add(
            part_accumulator,
            PackedQm31.mul(extended[root], coefficient),
        );
    }
    cumulative.* = PackedQm31.add(
        cumulative.*,
        PackedQm31.mulBase(
            part_accumulator,
            @splat(input.denominator_inverse),
        ),
    );
}

fn inverse(value: PackedM31, zero_inversions: *usize) PackedM31 {
    if (@reduce(.Or, value == @as(PackedM31, @splat(0))))
        zero_inversions.* += 1;
    var result: PackedM31 = @splat(1);
    var base = value;
    var exponent: u32 = m31.Modulus - 2;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) result = m31.mulVec4(result, base);
        base = m31.mulVec4(base, base);
    }
    return result;
}

test "SIMD QM31 multiplication agrees with the scalar field" {
    const qm31 = @import("stwo_core").fields.qm31;
    const lhs_words: Qm31Words = .{ 3, 5, 7, 11 };
    const rhs_words: Qm31Words = .{ 13, 17, 19, 23 };
    const actual_lanes = PackedQm31.mul(
        PackedQm31.splat(lhs_words),
        PackedQm31.splat(rhs_words),
    ).lanes();
    const expected = qm31.QM31.fromU32Unchecked(
        lhs_words[0],
        lhs_words[1],
        lhs_words[2],
        lhs_words[3],
    ).mul(qm31.QM31.fromU32Unchecked(
        rhs_words[0],
        rhs_words[1],
        rhs_words[2],
        rhs_words[3],
    )).toM31Array();
    for (actual_lanes) |lane| {
        for (lane, expected) |actual, scalar| {
            try std.testing.expectEqual(scalar.toU32(), actual);
        }
    }
}
