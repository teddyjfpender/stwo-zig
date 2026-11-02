//! Backend-independent PCS quotient construction.
//!
//! This stable facade preserves the public API while focused submodules own
//! sample ordering, row evaluation, and FRI query orchestration.

const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const cm31_mod = @import("../fields/cm31.zig");
const m31_mod = @import("../fields/m31.zig");
const qm31_mod = @import("../fields/qm31.zig");
const pcs_utils = @import("utils.zig");

const CirclePointM31 = circle.CirclePointM31;
const M31 = m31_mod.M31;

pub fn ForField(comptime Secure: type) type {
    return struct {
        const QM31 = Secure;
        const CirclePointQM31 = circle.CirclePoint(Secure);
        const CM31 = Secure.InnerField;
        const sample_ops = @import("quotients/samples.zig").ForField(Secure);
        const row_evaluation = @import("quotients/row_evaluation.zig").ForField(Secure);
        const fri_answers = @import("quotients/fri_answers.zig").ForField(Secure);
        const DEGREE = @typeInfo(@TypeOf(Secure.zero().toM31Array())).array.len;
        pub const TreeVec = pcs_utils.TreeVec;

        pub const PointSample = sample_ops.PointSample;
        pub const SampleWithRandomness = sample_ops.SampleWithRandomness;
        pub const NumeratorData = sample_ops.NumeratorData;
        pub const ColumnSampleBatch = sample_ops.ColumnSampleBatch;

        pub const QuotientConstants = row_evaluation.QuotientConstants;

        /// Precomputes line coefficients for each sampled column in each sample batch.
        pub fn columnLineCoeffs(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
        ) ![][]constraints.LineCoeffsFor(Secure) {
            return row_evaluation.columnLineCoeffs(allocator, sample_batches);
        }

        pub fn quotientConstants(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
        ) !QuotientConstants {
            return row_evaluation.quotientConstants(allocator, sample_batches);
        }

        /// Computes the denominator inverses for one domain point and all sample points.
        pub fn denominatorInverses(
            allocator: std.mem.Allocator,
            sample_points: []const CirclePointQM31,
            domain_point: CirclePointM31,
        ) ![]CM31 {
            return row_evaluation.denominatorInverses(allocator, sample_points, domain_point);
        }

        pub const RowQuotientWorkspace = row_evaluation.RowQuotientWorkspace;

        /// Computes one quotient row using caller-provided reusable scratch.
        pub fn accumulateRowQuotientsWithWorkspace(
            sample_batches: []const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            quotient_constants: *const QuotientConstants,
            domain_point: CirclePointM31,
            workspace: *RowQuotientWorkspace,
        ) !QM31 {
            return row_evaluation.accumulateRowQuotientsWithWorkspace(
                sample_batches,
                queried_values_at_row,
                quotient_constants,
                domain_point,
                workspace,
            );
        }

        /// Computes `sum(alpha^k * (c * value - b))` for one batch and row.
        pub fn accumulateRowPartialNumerators(
            batch: *const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            coeffs: []const constraints.LineCoeffsFor(Secure),
        ) !QM31 {
            return row_evaluation.accumulateRowPartialNumerators(batch, queried_values_at_row, coeffs);
        }

        /// Computes the full quotient accumulation for one queried domain row.
        pub fn accumulateRowQuotients(
            allocator: std.mem.Allocator,
            sample_batches: []const ColumnSampleBatch,
            queried_values_at_row: []const M31,
            quotient_constants: *const QuotientConstants,
            domain_point: CirclePointM31,
        ) !QM31 {
            return row_evaluation.accumulateRowQuotients(
                allocator,
                sample_batches,
                queried_values_at_row,
                quotient_constants,
                domain_point,
            );
        }

        pub fn finalizeRowQuotients(
            quotient_constants: *const QuotientConstants,
            domain_y: M31,
            batch_numerators: []const QM31,
            denominator_inverses: []const CM31,
        ) !QM31 {
            return row_evaluation.finalizeRowQuotients(
                quotient_constants,
                domain_y,
                batch_numerators,
                denominator_inverses,
            );
        }

        /// Attaches random coefficient powers and periodicity checks to all samples.
        pub fn buildSamplesWithRandomnessAndPeriodicity(
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            column_log_sizes: TreeVec([]u32),
            lifting_log_size: u32,
            random_coeff: QM31,
        ) !TreeVec([][]SampleWithRandomness) {
            return sample_ops.buildSamplesWithRandomnessAndPeriodicity(
                allocator,
                sampled_points,
                sampled_values,
                column_log_sizes,
                lifting_log_size,
                random_coeff,
            );
        }

        pub fn buildColumnSampleBatchesFromParallelInputs(
            allocator: std.mem.Allocator,
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            column_log_sizes: TreeVec([]u32),
            lifting_log_size: u32,
            random_coeff: QM31,
        ) ![]ColumnSampleBatch {
            return sample_ops.buildColumnSampleBatchesFromParallelInputs(
                allocator,
                sampled_points,
                sampled_values,
                column_log_sizes,
                lifting_log_size,
                random_coeff,
            );
        }

        /// Computes quotient answers for all queried FRI rows.
        pub fn friAnswers(
            allocator: std.mem.Allocator,
            column_log_sizes: TreeVec([]u32),
            sampled_points: TreeVec([][]CirclePointQM31),
            sampled_values: TreeVec([][]QM31),
            random_coeff: QM31,
            query_positions: []const usize,
            queried_values: TreeVec([][]M31),
            lifting_log_size: u32,
        ) ![]QM31 {
            return fri_answers.friAnswers(
                allocator,
                column_log_sizes,
                sampled_points,
                sampled_values,
                random_coeff,
                query_positions,
                queried_values,
                lifting_log_size,
            );
        }
    };
}
