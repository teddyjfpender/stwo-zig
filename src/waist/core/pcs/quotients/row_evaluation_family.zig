//! Backend-independent quotient evaluation for one queried domain row.
//!
//! The allocating and reusable-workspace entry points implement the same law.
//! Optimized backends may replace mechanics, but not line construction,
//! denominator semantics, or accumulation order without oracle evidence.

const std = @import("std");
const circle = @import("../../circle.zig");
const constraints = @import("../../constraints.zig");
const cm31_mod = @import("../../fields/cm31.zig");
const fields = @import("../../fields/mod.zig");
const m31_mod = fields.m31;
const qm31_mod = @import("../../fields/qm31.zig");

const CirclePointM31 = circle.CirclePointM31;
const M31 = m31_mod.M31;

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const CM31 = Secure.InnerField;
        const samples = @import("samples.zig").ForField(Secure);
        const ColumnSampleBatch = samples.ColumnSampleBatch;
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        /// Constants shared by every row evaluated for one sample-batch set.
        pub const QuotientConstants = struct {
            line_coeffs: [][]constraints.LineCoeffsFor(Secure),
            batch_linear_terms: []BatchLinearTerm,

            pub fn deinit(self: *QuotientConstants, allocator: std.mem.Allocator) void {
                for (self.line_coeffs) |batch_coeffs| allocator.free(batch_coeffs);
                allocator.free(self.line_coeffs);
                allocator.free(self.batch_linear_terms);
                self.* = undefined;
            }
        };

        const BatchLinearTerm = struct {
            sum_a: QM31,
            sum_b: QM31,

            inline fn evalAt(self: BatchLinearTerm, domain_y: M31) QM31 {
                return self.sum_a.mulM31(domain_y).add(self.sum_b);
            }
        };

        /// Precomputes line coefficients for every sampled column in each batch.
        pub fn columnLineCoeffs(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
        ) ![][]constraints.LineCoeffsFor(Secure) {
            var outer = std.ArrayList([]constraints.LineCoeffsFor(Secure)).empty;
            defer outer.deinit(allocator);
            errdefer {
                for (outer.items) |batch_coeffs| allocator.free(batch_coeffs);
            }

            for (sample_batches) |batch| {
                const batch_coeffs = try allocator.alloc(constraints.LineCoeffsFor(Secure), batch.cols_vals_randpows.len);
                errdefer allocator.free(batch_coeffs);

                for (batch.cols_vals_randpows, 0..) |sample_data, i| {
                    batch_coeffs[i] = constraints.quadraticConjugateLineCoeffs(
                        Secure,
                        batch.point,
                        sample_data.sample_value,
                        sample_data.random_coeff,
                    ) catch return error.DegenerateLine;
                }
                try outer.append(allocator, batch_coeffs);
            }

            return outer.toOwnedSlice(allocator);
        }

        pub fn quotientConstants(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
        ) !QuotientConstants {
            const line_coeffs = try columnLineCoeffs(allocator, sample_batches);
            errdefer {
                for (line_coeffs) |batch_coeffs| allocator.free(batch_coeffs);
                allocator.free(line_coeffs);
            }

            const batch_linear_terms = try allocator.alloc(BatchLinearTerm, sample_batches.len);
            errdefer allocator.free(batch_linear_terms);
            for (sample_batches, line_coeffs, 0..) |batch, coeffs, batch_idx| {
                if (batch.cols_vals_randpows.len != coeffs.len) return error.ShapeMismatch;
                var sum_a = QM31.zero();
                var sum_b = QM31.zero();
                for (coeffs) |coeff| {
                    sum_a = sum_a.add(coeff.a);
                    sum_b = sum_b.add(coeff.b);
                }
                batch_linear_terms[batch_idx] = .{
                    .sum_a = sum_a,
                    .sum_b = sum_b,
                };
            }

            return .{
                .line_coeffs = line_coeffs,
                .batch_linear_terms = batch_linear_terms,
            };
        }

        /// Computes denominator inverses for one domain point and all sample points.
        pub fn denominatorInverses(
            allocator: std.mem.Allocator,
            sample_points: []const CirclePointQM31,
            domain_point: CirclePointM31,
        ) ![]CM31 {
            const denominators = try allocator.alloc(CM31, sample_points.len);
            defer allocator.free(denominators);
            const inverses = try allocator.alloc(CM31, sample_points.len);
            errdefer allocator.free(inverses);

            try denominatorInversesInto(sample_points, domain_point, denominators, inverses);
            return inverses;
        }

        fn denominatorInversesInto(
            sample_points: []const CirclePointQM31,
            domain_point: CirclePointM31,
            denominators: []CM31,
            denominator_inverses: []CM31,
        ) !void {
            if (denominators.len != sample_points.len) return error.ShapeMismatch;
            if (denominator_inverses.len != sample_points.len) return error.ShapeMismatch;

            for (sample_points, 0..) |sample_point, i| {
                denominators[i] = constraints.quadraticLineDenominator(QM31, sample_point, domain_point);
            }

            try batchInverseIntoCM31(denominators, denominator_inverses);
        }

        const SamplePointComponents = struct {
            determinant: CM31,
            pix: CM31,
            piy: CM31,
        };

        /// Reusable scratch for row-by-row quotient accumulation.
        pub const RowQuotientWorkspace = struct {
            sample_point_components: []SamplePointComponents,
            denominator_scratch: []CM31,
            denominator_inverses: []CM31,
            batch_numerators: []QM31,

            pub fn init(
                allocator: std.mem.Allocator,
                sample_batches: []const ColumnSampleBatch,
            ) !RowQuotientWorkspace {
                const sample_point_components = try allocator.alloc(SamplePointComponents, sample_batches.len);
                errdefer allocator.free(sample_point_components);
                const denominator_scratch = try allocator.alloc(CM31, sample_batches.len);
                errdefer allocator.free(denominator_scratch);
                const denominator_inverses = try allocator.alloc(CM31, sample_batches.len);
                errdefer allocator.free(denominator_inverses);
                const batch_numerators = try allocator.alloc(QM31, sample_batches.len);
                errdefer allocator.free(batch_numerators);

                for (sample_batches, 0..) |batch, i| {
                    const prx = batch.point.x.c0;
                    const pry = batch.point.y.c0;
                    const pix = batch.point.x.c1;
                    const piy = batch.point.y.c1;
                    sample_point_components[i] = .{
                        .determinant = prx.mul(piy).sub(pry.mul(pix)),
                        .pix = pix,
                        .piy = piy,
                    };
                }

                return .{
                    .sample_point_components = sample_point_components,
                    .denominator_scratch = denominator_scratch,
                    .denominator_inverses = denominator_inverses,
                    .batch_numerators = batch_numerators,
                };
            }

            pub fn deinit(self: *RowQuotientWorkspace, allocator: std.mem.Allocator) void {
                allocator.free(self.sample_point_components);
                allocator.free(self.denominator_scratch);
                allocator.free(self.denominator_inverses);
                allocator.free(self.batch_numerators);
                self.* = undefined;
            }

            pub fn beginRow(self: *RowQuotientWorkspace, domain_point: CirclePointM31) !void {
                try denominatorInversesIntoFromComponents(
                    self.sample_point_components,
                    domain_point,
                    self.denominator_scratch,
                    self.denominator_inverses,
                );
                @memset(self.batch_numerators, QM31.zero());
            }

            /// Computes row-major denominator inverses for several domain points with
            /// one batch inversion. The caller owns the bounded chunk storage.
            pub fn prepareDenominatorInversesForRows(
                self: *const RowQuotientWorkspace,
                domain_points: []const CirclePointM31,
                denominators: []CM31,
                denominator_inverses: []CM31,
            ) !void {
                const cell_count = std.math.mul(
                    usize,
                    domain_points.len,
                    self.sample_point_components.len,
                ) catch return error.ScratchSizeOverflow;
                if (denominators.len != cell_count) return error.ShapeMismatch;
                if (denominator_inverses.len != cell_count) return error.ShapeMismatch;

                for (domain_points, 0..) |domain_point, row| {
                    const start = row * self.sample_point_components.len;
                    denominatorValuesIntoFromComponents(
                        self.sample_point_components,
                        domain_point,
                        denominators[start..][0..self.sample_point_components.len],
                    );
                }
                try batchInverseIntoCM31(denominators, denominator_inverses);
            }

            /// Computes batch-major denominator inverses for several domain points.
            /// Keeping adjacent rows contiguous lets quotient finalization load four
            /// CM31 values without gathering from a row-major batch stride.
            pub fn prepareDenominatorInversesForRowsBatchMajor(
                self: *const RowQuotientWorkspace,
                domain_points: []const CirclePointM31,
                denominators: []CM31,
                denominator_inverses: []CM31,
            ) !void {
                const cell_count = std.math.mul(
                    usize,
                    domain_points.len,
                    self.sample_point_components.len,
                ) catch return error.ScratchSizeOverflow;
                if (denominators.len != cell_count) return error.ShapeMismatch;
                if (denominator_inverses.len != cell_count) return error.ShapeMismatch;

                for (self.sample_point_components, 0..) |sample, batch| {
                    const start = batch * domain_points.len;
                    denominatorValuesForSampleBatch(
                        sample,
                        domain_points,
                        denominators[start..][0..domain_points.len],
                    );
                }
                try batchInverseIntoCM31(denominators, denominator_inverses);
            }

            pub inline fn resetNumerators(self: *RowQuotientWorkspace) void {
                @memset(self.batch_numerators, QM31.zero());
            }
        };

        fn denominatorInversesIntoFromComponents(
            sample_point_components: []const SamplePointComponents,
            domain_point: CirclePointM31,
            denominators: []CM31,
            denominator_inverses: []CM31,
        ) !void {
            if (denominators.len != sample_point_components.len) return error.ShapeMismatch;
            if (denominator_inverses.len != sample_point_components.len) return error.ShapeMismatch;

            denominatorValuesIntoFromComponents(sample_point_components, domain_point, denominators);

            try batchInverseIntoCM31(denominators, denominator_inverses);
        }

        fn denominatorValuesIntoFromComponents(
            sample_point_components: []const SamplePointComponents,
            domain_point: CirclePointM31,
            denominators: []CM31,
        ) void {
            std.debug.assert(denominators.len == sample_point_components.len);
            for (sample_point_components, 0..) |sample, i| {
                denominators[i] = denominatorValue(sample, domain_point);
            }
        }

        inline fn denominatorValue(sample: SamplePointComponents, domain_point: CirclePointM31) CM31 {
            // (prx - x) * piy - (pry - y) * pix
            // = prx*piy - pry*pix - x*piy + y*pix.
            return sample.determinant
                .sub(sample.piy.mulM31(domain_point.x))
                .add(sample.pix.mulM31(domain_point.y));
        }

        /// Evaluates one sample-point denominator across adjacent domain rows. The
        /// sample terms are constant, so the four base-field coordinate multiplies
        /// are issued as packed row vectors instead of repeating two CM31 products.
        fn denominatorValuesForSampleBatch(
            sample: SamplePointComponents,
            domain_points: []const CirclePointM31,
            denominators: []CM31,
        ) void {
            std.debug.assert(denominators.len == domain_points.len);
            if (comptime CM31 == @import("../../fields/qm31.zig").QM31) {
                const P = @import("../../fields/packed_qm31.zig").PackedQM31;
                const determinant = P.splat(sample.determinant);
                const pix = P.splat(sample.pix);
                const piy = P.splat(sample.piy);
                var row: usize = 0;
                while (row + m31_mod.PACK_WIDTH <= domain_points.len) : (row += m31_mod.PACK_WIDTH) {
                    var xs: m31_mod.PackedM31 = undefined;
                    var ys: m31_mod.PackedM31 = undefined;
                    for (0..m31_mod.PACK_WIDTH) |i| {
                        xs[i] = domain_points[row + i].x.v;
                        ys[i] = domain_points[row + i].y.v;
                    }
                    const result = determinant.sub(piy.mulBase(xs)).add(pix.mulBase(ys));
                    for (0..m31_mod.PACK_WIDTH) |i| denominators[row + i] = result.lane(i);
                }
                while (row < domain_points.len) : (row += 1) denominators[row] = denominatorValue(sample, domain_points[row]);
            } else {
                comptime {
                    if (@sizeOf(CirclePointM31) != 2 * @sizeOf(M31) or
                        @offsetOf(CirclePointM31, "y") != @sizeOf(M31))
                    {
                        @compileError("packed circle-point layout changed");
                    }
                    if (@sizeOf(CM31) != 2 * @sizeOf(M31) or
                        @offsetOf(CM31, "b") != @sizeOf(M31))
                    {
                        @compileError("packed CM31 layout changed");
                    }
                }

                const point_words: [*]const M31 = @ptrCast(domain_points.ptr);
                const denominator_words: [*]M31 = @ptrCast(denominators.ptr);
                const determinant_re: m31_mod.Vec4u32 = @splat(sample.determinant.a.v);
                const determinant_im: m31_mod.Vec4u32 = @splat(sample.determinant.b.v);
                const piy_re: m31_mod.Vec4u32 = @splat(sample.piy.a.v);
                const piy_im: m31_mod.Vec4u32 = @splat(sample.piy.b.v);
                const pix_re: m31_mod.Vec4u32 = @splat(sample.pix.a.v);
                const pix_im: m31_mod.Vec4u32 = @splat(sample.pix.b.v);

                var row: usize = 0;
                while (row + m31_mod.VEC_WIDTH <= domain_points.len) : (row += m31_mod.VEC_WIDTH) {
                    const raw_lo = m31_mod.loadVec4(point_words + row * 2);
                    const raw_hi = m31_mod.loadVec4(point_words + row * 2 + m31_mod.VEC_WIDTH);
                    const xs = @shuffle(u32, raw_lo, raw_hi, @Vector(4, i32){ 0, 2, -1, -3 });
                    const ys = @shuffle(u32, raw_lo, raw_hi, @Vector(4, i32){ 1, 3, -2, -4 });
                    const real = m31_mod.addVec4(
                        m31_mod.subVec4(determinant_re, m31_mod.mulVec4(xs, piy_re)),
                        m31_mod.mulVec4(ys, pix_re),
                    );
                    const imaginary = m31_mod.addVec4(
                        m31_mod.subVec4(determinant_im, m31_mod.mulVec4(xs, piy_im)),
                        m31_mod.mulVec4(ys, pix_im),
                    );
                    const interleaved_lo = @shuffle(
                        u32,
                        real,
                        imaginary,
                        @Vector(4, i32){ 0, -1, 1, -2 },
                    );
                    const interleaved_hi = @shuffle(
                        u32,
                        real,
                        imaginary,
                        @Vector(4, i32){ 2, -3, 3, -4 },
                    );
                    m31_mod.storeVec4(denominator_words + row * 2, interleaved_lo);
                    m31_mod.storeVec4(
                        denominator_words + row * 2 + m31_mod.VEC_WIDTH,
                        interleaved_hi,
                    );
                }
                while (row < domain_points.len) : (row += 1) {
                    denominators[row] = denominatorValue(sample, domain_points[row]);
                }
            }
        }

        fn batchInverseIntoCM31(values: []const CM31, out: []CM31) !void {
            if (values.len != out.len) return error.ShapeMismatch;
            fields.batchInverseInPlace(CM31, values, out) catch return error.DivisionByZero;
        }

        /// Computes one quotient row using caller-provided reusable scratch.
        pub fn accumulateRowQuotientsWithWorkspace(
            sample_batches: []const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            quotient_constants: *const QuotientConstants,
            domain_point: CirclePointM31,
            workspace: *RowQuotientWorkspace,
        ) !QM31 {
            if (sample_batches.len != quotient_constants.line_coeffs.len) return error.ShapeMismatch;
            if (sample_batches.len != quotient_constants.batch_linear_terms.len) return error.ShapeMismatch;
            if (workspace.sample_point_components.len != sample_batches.len) return error.ShapeMismatch;
            if (workspace.denominator_scratch.len != sample_batches.len) return error.ShapeMismatch;
            if (workspace.denominator_inverses.len != sample_batches.len) return error.ShapeMismatch;
            if (workspace.batch_numerators.len != sample_batches.len) return error.ShapeMismatch;

            try workspace.beginRow(domain_point);

            for (sample_batches, 0..) |batch, batch_idx| {
                const line_coeffs = quotient_constants.line_coeffs[batch_idx];
                if (batch.cols_vals_randpows.len != line_coeffs.len) return error.ShapeMismatch;

                for (batch.cols_vals_randpows, 0..) |sample_data, i| {
                    if (sample_data.column_index >= queried_values_at_row.len) {
                        return error.ColumnIndexOutOfBounds;
                    }
                    const value = line_coeffs[i].c.mulM31(queried_values_at_row[sample_data.column_index]);
                    workspace.batch_numerators[batch_idx] = workspace.batch_numerators[batch_idx].add(value);
                }
            }
            return finalizeRowQuotients(
                quotient_constants,
                domain_point.y,
                workspace.batch_numerators,
                workspace.denominator_inverses,
            );
        }

        /// Computes `sum(alpha^k * (c * value - b))` for one batch and row.
        pub fn accumulateRowPartialNumerators(
            batch: *const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            coeffs: []const constraints.LineCoeffsFor(Secure),
        ) !QM31 {
            if (batch.cols_vals_randpows.len != coeffs.len) return error.ShapeMismatch;

            var numerator = QM31.zero();
            for (batch.cols_vals_randpows, 0..) |sample_data, i| {
                if (sample_data.column_index >= queried_values_at_row.len) {
                    return error.ColumnIndexOutOfBounds;
                }
                const value = coeffs[i].c.mulM31(queried_values_at_row[sample_data.column_index]);
                numerator = numerator.add(value.sub(coeffs[i].b));
            }
            return numerator;
        }

        /// Computes one quotient row with call-local scratch allocations.
        pub fn accumulateRowQuotients(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            quotient_constants: *const QuotientConstants,
            domain_point: CirclePointM31,
        ) !QM31 {
            if (sample_batches.len != quotient_constants.line_coeffs.len) return error.ShapeMismatch;
            if (sample_batches.len != quotient_constants.batch_linear_terms.len) return error.ShapeMismatch;

            const sample_points = try allocator.alloc(CirclePointQM31, sample_batches.len);
            defer allocator.free(sample_points);
            for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

            const denominator_scratch = try allocator.alloc(CM31, sample_batches.len);
            defer allocator.free(denominator_scratch);
            const denominator_inverses = try allocator.alloc(CM31, sample_batches.len);
            defer allocator.free(denominator_inverses);
            const batch_numerators = try allocator.alloc(QM31, sample_batches.len);
            defer allocator.free(batch_numerators);
            try denominatorInversesInto(
                sample_points,
                domain_point,
                denominator_scratch,
                denominator_inverses,
            );
            @memset(batch_numerators, QM31.zero());

            for (sample_batches, 0..) |batch, batch_idx| {
                const line_coeffs = quotient_constants.line_coeffs[batch_idx];
                if (batch.cols_vals_randpows.len != line_coeffs.len) return error.ShapeMismatch;

                for (batch.cols_vals_randpows, 0..) |sample_data, i| {
                    if (sample_data.column_index >= queried_values_at_row.len) {
                        return error.ColumnIndexOutOfBounds;
                    }
                    const value = line_coeffs[i].c.mulM31(queried_values_at_row[sample_data.column_index]);
                    batch_numerators[batch_idx] = batch_numerators[batch_idx].add(value);
                }
            }
            return finalizeRowQuotients(
                quotient_constants,
                domain_point.y,
                batch_numerators,
                denominator_inverses,
            );
        }

        pub fn finalizeRowQuotients(
            quotient_constants: *const QuotientConstants,
            domain_y: M31,
            batch_numerators: []const QM31,
            denominator_inverses: []const CM31,
        ) !QM31 {
            if (quotient_constants.batch_linear_terms.len != batch_numerators.len) return error.ShapeMismatch;
            if (denominator_inverses.len != batch_numerators.len) return error.ShapeMismatch;

            var row_accumulator = QM31.zero();
            for (quotient_constants.batch_linear_terms, batch_numerators, denominator_inverses) |linear_term, numerator_sum, denominator_inverse| {
                const numerator = numerator_sum.sub(linear_term.evalAt(domain_y));
                row_accumulator = row_accumulator.add(numerator.mulInner(denominator_inverse));
            }
            return row_accumulator;
        }
    };
}

test "CM31 batch inversion matches independent inverses" {
    const lengths = [_]usize{ 1, 2, 3, 7, 8, 16, 24, 31, 32, 40, 63, 64 };
    var values: [64]cm31_mod.CM31 = undefined;
    var inverses: [64]cm31_mod.CM31 = undefined;
    for (&values, 0..) |*value, i| {
        value.* = cm31_mod.CM31.fromM31(
            M31.fromU64(17 * i + 3),
            M31.fromU64(29 * i + 5),
        );
    }
    for (lengths) |len| {
        try ForField(qm31_mod.QM31).batchInverseIntoCM31(values[0..len], inverses[0..len]);
        for (values[0..len], inverses[0..len]) |value, inverse| {
            try std.testing.expect(value.mul(inverse).eql(cm31_mod.CM31.one()));
        }
    }
}

test "CM31 batch inversion rejects a zero lane product" {
    var values = [_]cm31_mod.CM31{cm31_mod.CM31.one()} ** 16;
    var inverses: [16]cm31_mod.CM31 = undefined;
    values[11] = cm31_mod.CM31.zero();
    try std.testing.expectError(
        error.DivisionByZero,
        ForField(qm31_mod.QM31).batchInverseIntoCM31(&values, &inverses),
    );
}
