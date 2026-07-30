//! Fixed-width SIMD interpreter for captured Cairo AIR programs.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const utils = @import("stwo_core").utils;
const eval = @import("../../witness/eval_program.zig");
const read_plan = @import("read_plan.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const lane_count = m31.VEC_WIDTH;
pub const PackedM31 = m31.Vec4u32;

pub const PackedQm31 = struct {
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

    /// Karatsuba candidate: 9 `mulVec4` instead of the schoolbook 16.
    ///
    /// Every intermediate is produced by `addVec4` / `subVec4` / `mulVec4`,
    /// each of which returns a canonical value in `[0, p)`. So the SQDMULH
    /// precondition in `mulVec4Aarch64` (operands are canonical positive
    /// 31-bit) holds at all nine multiply sites without any extra
    /// reduction, and the result is the exact field product.
    pub fn mul(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
        const a = lhs.coordinates;
        const b = rhs.coordinates;

        // A*C and B*D, Karatsuba over i (3 multiplies each).
        const p = cm31MulKaratsuba(a[0], a[1], b[0], b[1]);
        const q = cm31MulKaratsuba(a[2], a[3], b[2], b[3]);

        // (A+B)*(C+D), Karatsuba over i, on canonical sums.
        const s = cm31MulKaratsuba(
            m31.addVec4(a[0], a[2]),
            m31.addVec4(a[1], a[3]),
            m31.addVec4(b[0], b[2]),
            m31.addVec4(b[1], b[3]),
        );

        // AD + BC = S - P - Q.
        const cross0 = m31.subVec4(m31.subVec4(s[0], p[0]), q[0]);
        const cross1 = m31.subVec4(m31.subVec4(s[1], p[1]), q[1]);

        // (2 + i) * Q = (2q0 - q1) + (q0 + 2q1)i.
        const two_q0 = m31.addVec4(q[0], q[0]);
        const two_q1 = m31.addVec4(q[1], q[1]);
        return .{ .coordinates = .{
            m31.addVec4(p[0], m31.subVec4(two_q0, q[1])),
            m31.addVec4(p[1], m31.addVec4(q[0], two_q1)),
            cross0,
            cross1,
        } };
    }

    /// Schoolbook reference: 16 `mulVec4`. Retained only as the exactness
    /// oracle for `mul`; not on any hot path.
    pub fn mulSchoolbook(lhs: PackedQm31, rhs: PackedQm31) PackedQm31 {
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

/// `(a0 + a1 i) * (b0 + b1 i)` with three base multiplies. Inputs are
/// canonical; `addVec4` / `subVec4` keep every intermediate canonical.
inline fn cm31MulKaratsuba(
    a0: PackedM31,
    a1: PackedM31,
    b0: PackedM31,
    b1: PackedM31,
) [2]PackedM31 {
    const ac = m31.mulVec4(a0, b0);
    const bd = m31.mulVec4(a1, b1);
    const cross = m31.mulVec4(m31.addVec4(a0, a1), m31.addVec4(b0, b1));
    return .{
        m31.subVec4(ac, bd),
        m31.subVec4(m31.subVec4(cross, ac), bd),
    };
}

/// A mask column resolved down to the two facts the row loop needs: where its
/// values live, and the lifting shift that maps an evaluation-domain position
/// onto them. `values.len` is `1 << column_log_size`, so
/// `((position >> shift_amt) << 1) + (position & 1)` is in bounds for every
/// position below the evaluation domain size.
pub const ResolvedColumn = struct {
    values: []const M31,
    shift_amt: std.math.Log2Int(usize),
};

pub const TraceReader = struct {
    context: *const anyopaque,
    /// Called once per read site per evaluated range, never per row. The
    /// callee performs the tree lookup, the component span arithmetic and the
    /// column shape validation that the row loop then never repeats.
    resolve: *const fn (
        context: *const anyopaque,
        interaction: u8,
        column: u32,
    ) anyerror!ResolvedColumn,
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

    const base = try allocator.alloc(PackedM31, program.header.max_base_regs);
    defer allocator.free(base);
    const extension = try allocator.alloc(PackedQm31, program.header.max_ext_regs);
    defer allocator.free(extension);

    var plan = try read_plan.build(
        ResolvedColumn,
        allocator,
        program,
        input.trace.context,
        input.trace.resolve,
    );
    defer plan.deinit(allocator);
    const offsets = plan.offsets;
    const sites = plan.sites;
    // One mapped lane position per distinct mask offset, refreshed per group.
    const positions = try allocator.alloc([lane_count]usize, offsets.len);
    defer allocator.free(positions);

    var row = row_start;
    while (row < row_end) : (row += lane_count) {
        for (offsets, positions) |offset, *mapped| {
            inline for (0..lane_count) |lane| {
                mapped[lane] = if (offset == 0)
                    row + lane
                else
                    utils.offsetBitReversedCircleDomainIndex(
                        row + lane,
                        input.trace_log_size,
                        input.evaluation_log_size,
                        offset,
                    );
            }
        }
        var site_cursor: usize = 0;
        for (program.base_insts) |instruction| {
            base[instruction.dst] = switch (instruction.op) {
                .trace_col, .preprocessed_col => blk: {
                    const site = sites[site_cursor];
                    site_cursor += 1;
                    const mapped = positions[site.offset_slot];
                    var values: PackedM31 = undefined;
                    inline for (0..lane_count) |lane| {
                        const position = mapped[lane];
                        values[lane] = site.column.values[
                            ((position >> site.column.shift_amt) << 1) +
                                (position & 1)
                        ].toU32();
                    }
                    break :blk values;
                },
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
        inline for (0..lane_count) |lane| {
            denominator[lane] = input.denominator_inverses[
                (row + lane) >> @intCast(input.trace_log_size)
            ];
        }
        evaluation = PackedQm31.mulBase(evaluation, denominator);
        inline for (0..lane_count) |lane| {
            output.accumulate(row + lane, evaluation.lane(lane));
        }
    }
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

test "Cairo SIMD evaluator Karatsuba QM31 multiplication is byte-identical to schoolbook" {
    var prng = std.Random.DefaultPrng.init(0x2f41_9d0c_71ab_3e55);
    const rng = prng.random();

    // Per-lane distinct operands, so a lane-crossing error cannot hide.
    var trial: usize = 0;
    while (trial < 20_000) : (trial += 1) {
        var lhs: PackedQm31 = undefined;
        var rhs: PackedQm31 = undefined;
        inline for (0..4) |coordinate| {
            var l: PackedM31 = undefined;
            var r: PackedM31 = undefined;
            for (0..lane_count) |slot| {
                l[slot] = rng.uintLessThan(u32, m31.Modulus);
                r[slot] = rng.uintLessThan(u32, m31.Modulus);
            }
            lhs.coordinates[coordinate] = l;
            rhs.coordinates[coordinate] = r;
        }

        const schoolbook = PackedQm31.mulSchoolbook(lhs, rhs);
        const karatsuba = PackedQm31.mul(lhs, rhs);
        inline for (0..4) |coordinate| {
            for (0..lane_count) |slot| {
                try std.testing.expectEqual(
                    schoolbook.coordinates[coordinate][slot],
                    karatsuba.coordinates[coordinate][slot],
                );
            }
        }
        // And both agree with the scalar field, which is the ground truth.
        for (0..lane_count) |slot| {
            try std.testing.expect(karatsuba.lane(slot).eql(lhs.lane(slot).mul(rhs.lane(slot))));
        }
    }

    // Boundary operands: 0, 1 and p-1 in every coordinate slot.
    const edges = [_]u32{ 0, 1, 2, m31.Modulus - 1, m31.Modulus - 2 };
    for (edges) |e0| for (edges) |e1| for (edges) |e2| for (edges) |e3| {
        const lhs = PackedQm31{ .coordinates = .{
            @splat(e0), @splat(e1), @splat(e2), @splat(e3),
        } };
        for (edges) |f0| for (edges) |f1| {
            const rhs = PackedQm31{ .coordinates = .{
                @splat(f0), @splat(f1), @splat(e3), @splat(e0),
            } };
            const schoolbook = PackedQm31.mul(lhs, rhs);
            const karatsuba = PackedQm31.mul(lhs, rhs);
            inline for (0..4) |coordinate| {
                try std.testing.expectEqual(
                    schoolbook.coordinates[coordinate][0],
                    karatsuba.coordinates[coordinate][0],
                );
            }
        };
    };
}

test "Cairo SIMD evaluator QM31 multiplication matches the scalar field" {
    const lhs = QM31.fromU32Unchecked(3, 5, 7, 11);
    const rhs = QM31.fromU32Unchecked(13, 17, 19, 23);
    const actual = PackedQm31.mul(PackedQm31.splat(lhs), PackedQm31.splat(rhs));
    for (0..lane_count) |lane| {
        try std.testing.expect(actual.lane(lane).eql(lhs.mul(rhs)));
    }
}
