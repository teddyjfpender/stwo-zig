//! Checked resident out-of-domain sampling dispatch.

const abi = @import("../../abi/stages/oods.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
const stage = telemetry.Stage.oods;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn derivePoints(
            session: anytype,
            oods_parameter: common.SecureFields,
            offset_points: common.CirclePoints,
            fold_counts: common.Words,
            output_indices: common.Words,
            coefficient_log_size: u32,
            sample_points: common.Words,
            evaluation_points: common.Words,
            folding_factors: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const sample_count = try common.count(output_indices.len);
            if (sample_count == 0 or
                offset_points.len < sample_count or
                fold_counts.len < sample_count or
                folding_factors.len < sample_count or
                sample_points.len < sample_count or
                evaluation_points.len < sample_count)
            {
                return error.SizeOverflow;
            }
            const status = Api.stwo_oods_derive_points_on(
                @ptrCast(try common.secure(session, oods_parameter, 1)),
                try common.circles(session, offset_points, sample_count),
                try common.words(session, fold_counts, sample_count),
                try common.words(session, output_indices, sample_count),
                sample_count,
                coefficient_log_size,
                try common.words(session, sample_points, sample_count),
                try common.words(session, evaluation_points, sample_count),
                try common.secure(session, folding_factors, sample_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn evaluateFirst(
            session: anytype,
            coefficients: common.PointerTable,
            coefficient_size: u32,
            folding_factors: common.SecureFields,
            scratch: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const sample_count = try common.count(folding_factors.len);
            try common.requireNonZero(&.{ coefficient_size, sample_count });
            const scratch_elements = @import("std").math.mul(
                usize,
                coefficient_size,
                sample_count,
            ) catch return error.SizeOverflow;
            const status = Api.stwo_oods_eval_first_on(
                try common.constWordTable(session, coefficients, 1),
                coefficient_size,
                sample_count,
                try common.secure(session, folding_factors, sample_count),
                try common.secure(session, scratch, scratch_elements),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn reduce(
            session: anytype,
            input: common.SecureFields,
            input_stride: u32,
            factor_index: u32,
            coefficient_log_size: u32,
            folding_factors: common.SecureFields,
            output: common.SecureFields,
            output_stride: u32,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const sample_count = try common.count(folding_factors.len);
            try common.requireNonZero(&.{ input_stride, sample_count, output_stride });
            const status = Api.stwo_oods_eval_reduce_on(
                try common.secure(session, input, 1),
                try common.count(input.len),
                input_stride,
                factor_index,
                coefficient_log_size,
                sample_count,
                try common.secure(session, folding_factors, sample_count),
                try common.secure(session, output, 1),
                output_stride,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn storeResults(
            session: anytype,
            reduced: common.SecureFields,
            reduced_stride: u32,
            output_indices: common.Words,
            sampled_values: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const sample_count = try common.count(output_indices.len);
            try common.requireNonZero(&.{ reduced_stride, sample_count });
            const status = Api.stwo_oods_store_results_on(
                try common.secure(session, reduced, 1),
                reduced_stride,
                try common.words(session, output_indices, sample_count),
                sample_count,
                try common.secure(session, sampled_values, sample_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn barycentricWeights(
            session: anytype,
            half_coset_initial_index: u32,
            half_coset_step_size: u32,
            log_size: u32,
            evaluation_point: common.Words,
            si0: field.SecureField,
            vanishing_rotation: field.CirclePointBaseField,
            numerator_inverses: common.SecureFields,
            weights: common.SecureFields,
            scales: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const size = try common.count(weights.len);
            if (size == 0 or numerator_inverses.len < size or scales.len < size)
                return error.SizeOverflow;
            const status = Api.stwo_oods_barycentric_weights_on(
                half_coset_initial_index,
                half_coset_step_size,
                size,
                log_size,
                try common.words(session, evaluation_point, 2),
                si0,
                vanishing_rotation,
                try common.secure(session, numerator_inverses, size),
                try common.secure(session, weights, size),
                try common.secure(session, scales, size),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn barycentricEvaluate(
            session: anytype,
            columns: common.PointerTable,
            weights: common.SecureFields,
            partial_sums: common.SecureFields,
            reduction_blocks: u32,
            output_indices: common.Words,
            sampled_values: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const column_count = try common.count(columns.len);
            const size = try common.count(weights.len);
            try common.requireNonZero(&.{ column_count, size, reduction_blocks });
            if (output_indices.len < column_count or sampled_values.len == 0)
                return error.SizeOverflow;
            const partial_count = @import("std").math.mul(
                usize,
                columns.len,
                reduction_blocks,
            ) catch return error.SizeOverflow;
            const status = Api.stwo_oods_barycentric_eval_many_on(
                try common.constWordTable(session, columns, column_count),
                column_count,
                try common.secure(session, weights, size),
                size,
                try common.secure(session, partial_sums, partial_count),
                reduction_blocks,
                try common.words(session, output_indices, column_count),
                try common.secure(session, sampled_values, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}
