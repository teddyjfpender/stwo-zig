//! Checked resident out-of-domain sampling over prepared proof topology.

const std = @import("std");
const abi = @import("../../abi/stages/oods.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const layout = @import("resident_layout.zig");
const plan = @import("oods_plan.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const IndexMap = plan.IndexMap;
pub const SampleMap = plan.SampleMap;
pub const prepareIndexMap = plan.prepareIndexMap;
pub const prepareSampleMap = plan.prepareSampleMap;

const stage = telemetry.Stage.oods;

pub const first_coefficients_per_block: usize = 4096;
pub const reduce_coefficients_per_block: usize = 512;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn derivePoints(
            session: anytype,
            oods_parameter: common.SecureFields,
            offset_points: common.CirclePoints,
            samples: SampleMap,
            coefficient_log_size: u32,
            sample_points: common.SecureCirclePoints,
            evaluation_points: common.SecureCirclePoints,
            folding_factors: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (coefficient_log_size == 0 or coefficient_log_size > 31 or
                samples.indices.device.len == 0 or
                samples.fold_counts.len != samples.indices.device.len or
                samples.indices.output_capacity != sample_points.len)
            {
                return error.InvalidKernelDescriptor;
            }
            const sample_count = try common.count(samples.indices.device.len);
            const factor_count = std.math.mul(
                usize,
                sample_count,
                coefficient_log_size,
            ) catch return error.SizeOverflow;
            if (offset_points.len < sample_count or
                evaluation_points.len < sample_count or
                folding_factors.len < factor_count)
            {
                return error.SizeOverflow;
            }

            const parameter = try layout.resident(
                session,
                field.SecureField,
                oods_parameter,
                1,
            );
            const offsets = try layout.resident(
                session,
                field.CirclePointBaseField,
                offset_points,
                sample_count,
            );
            const folds = try layout.resident(
                session,
                u32,
                samples.fold_counts,
                sample_count,
            );
            const indices = try layout.resident(
                session,
                u32,
                samples.indices.device,
                sample_count,
            );
            const sample_output = try layout.resident(
                session,
                field.SecureCirclePoint,
                sample_points,
                samples.indices.output_capacity,
            );
            const evaluation_output = try layout.resident(
                session,
                field.SecureCirclePoint,
                evaluation_points,
                sample_count,
            );
            const factors_output = try layout.resident(
                session,
                field.SecureField,
                folding_factors,
                factor_count,
            );
            try layout.requireDisjoint(
                &.{
                    sample_output.range,
                    evaluation_output.range,
                    factors_output.range,
                },
                &.{
                    parameter.range,
                    offsets.range,
                    folds.range,
                    indices.range,
                },
            );

            const status = Api.stwo_oods_derive_points_on(
                @ptrCast(parameter.pointer),
                offsets.pointer,
                folds.pointer,
                indices.pointer,
                sample_count,
                coefficient_log_size,
                sample_output.pointer,
                samples.indices.output_capacity,
                evaluation_output.pointer,
                factors_output.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn evaluateFirst(
            session: anytype,
            coefficients: common.WordMatrix,
            coefficient_size: u32,
            folding_factors: common.SecureFields,
            scratch: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (coefficient_size < 2 or !std.math.isPowerOfTwo(coefficient_size))
                return error.InvalidKernelDescriptor;
            const coefficient_log_size = std.math.log2_int(
                u32,
                coefficient_size,
            );
            const coefficient_values = try layout.wordMatrix(
                session,
                coefficients,
                coefficient_size,
            );
            if (coefficient_values.column_count > 65_535)
                return error.InvalidKernelDescriptor;
            const factor_count = std.math.mul(
                usize,
                coefficient_values.column_count,
                coefficient_log_size,
            ) catch return error.SizeOverflow;
            if (folding_factors.len != factor_count)
                return error.InvalidKernelDescriptor;
            const blocks_per_sample = std.math.divCeil(
                usize,
                coefficient_size,
                first_coefficients_per_block,
            ) catch return error.SizeOverflow;
            const scratch_count = std.math.mul(
                usize,
                coefficient_values.column_count,
                blocks_per_sample,
            ) catch return error.SizeOverflow;
            const factors = try layout.resident(
                session,
                field.SecureField,
                folding_factors,
                factor_count,
            );
            const scratch_output = try layout.resident(
                session,
                field.SecureField,
                scratch,
                scratch_count,
            );
            try layout.requireDisjoint(
                &.{scratch_output.range},
                &.{ coefficient_values.range, factors.range },
            );

            const status = Api.stwo_oods_eval_first_on(
                coefficient_values.pointer,
                coefficient_values.stride_words,
                coefficient_size,
                coefficient_values.column_count,
                factors.pointer,
                scratch_output.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn reduce(
            session: anytype,
            input: common.SecureFields,
            input_size: u32,
            input_stride: u32,
            factor_index: u32,
            coefficient_log_size: u32,
            folding_factors: common.SecureFields,
            output: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (input_size < 2 or !std.math.isPowerOfTwo(input_size) or
                input_stride < input_size or coefficient_log_size == 0 or
                coefficient_log_size > 31 or
                factor_index >= coefficient_log_size or
                factor_index + 1 != std.math.log2_int(u32, input_size) or
                folding_factors.len % coefficient_log_size != 0)
            {
                return error.InvalidKernelDescriptor;
            }
            const sample_count_usize =
                folding_factors.len / coefficient_log_size;
            const sample_count = try common.count(sample_count_usize);
            if (sample_count == 0 or sample_count > 65_535)
                return error.InvalidKernelDescriptor;
            const output_stride = std.math.divCeil(
                u32,
                input_size,
                reduce_coefficients_per_block,
            ) catch return error.SizeOverflow;
            const input_count = try matrixElements(
                sample_count_usize,
                input_stride,
                input_size,
            );
            const output_count = std.math.mul(
                usize,
                sample_count_usize,
                output_stride,
            ) catch return error.SizeOverflow;
            const input_values = try layout.resident(
                session,
                field.SecureField,
                input,
                input_count,
            );
            const factors = try layout.resident(
                session,
                field.SecureField,
                folding_factors,
                folding_factors.len,
            );
            const output_values = try layout.resident(
                session,
                field.SecureField,
                output,
                output_count,
            );
            try layout.requireDisjoint(
                &.{output_values.range},
                &.{ input_values.range, factors.range },
            );

            const status = Api.stwo_oods_eval_reduce_on(
                input_values.pointer,
                input_size,
                input_stride,
                factor_index,
                coefficient_log_size,
                sample_count,
                factors.pointer,
                output_values.pointer,
                output_stride,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn storeResults(
            session: anytype,
            reduced: common.SecureFields,
            reduced_stride: u32,
            indices: IndexMap,
            sampled_values: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            if (reduced_stride == 0 or indices.device.len == 0 or
                indices.output_capacity != sampled_values.len)
            {
                return error.InvalidKernelDescriptor;
            }
            const sample_count = try common.count(indices.device.len);
            const reduced_count = try matrixElements(
                indices.device.len,
                reduced_stride,
                1,
            );
            const reduced_values = try layout.resident(
                session,
                field.SecureField,
                reduced,
                reduced_count,
            );
            const output_indices = try layout.resident(
                session,
                u32,
                indices.device,
                sample_count,
            );
            const sampled_output = try layout.resident(
                session,
                field.SecureField,
                sampled_values,
                indices.output_capacity,
            );
            try layout.requireDisjoint(
                &.{sampled_output.range},
                &.{ reduced_values.range, output_indices.range },
            );

            const status = Api.stwo_oods_store_results_on(
                reduced_values.pointer,
                reduced_stride,
                output_indices.pointer,
                sample_count,
                sampled_output.pointer,
                indices.output_capacity,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn barycentricWeights(
            session: anytype,
            half_coset_initial_index: u32,
            half_coset_step_size: u32,
            log_size: u32,
            evaluation_point: common.SecureCirclePoints,
            si0: field.SecureField,
            vanishing_rotation: field.CirclePointBaseField,
            numerator_inverses: common.SecureFields,
            weights: common.SecureFields,
            scales: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const size = try common.count(weights.len);
            if (half_coset_step_size == 0 or log_size == 0 or log_size >= 31 or
                size < 2 or size != (@as(u32, 1) << @intCast(log_size)) or
                numerator_inverses.len != size or scales.len != 2)
            {
                return error.InvalidKernelDescriptor;
            }
            const evaluation = try layout.resident(
                session,
                field.SecureCirclePoint,
                evaluation_point,
                1,
            );
            const numerators = try layout.resident(
                session,
                field.SecureField,
                numerator_inverses,
                size,
            );
            const weight_values = try layout.resident(
                session,
                field.SecureField,
                weights,
                size,
            );
            const scale_values = try layout.resident(
                session,
                field.SecureField,
                scales,
                2,
            );
            try layout.requireDisjoint(
                &.{
                    numerators.range,
                    weight_values.range,
                    scale_values.range,
                },
                &.{evaluation.range},
            );

            const status = Api.stwo_oods_barycentric_weights_on(
                half_coset_initial_index,
                half_coset_step_size,
                size,
                log_size,
                evaluation.pointer,
                si0,
                vanishing_rotation,
                numerators.pointer,
                weight_values.pointer,
                scale_values.pointer,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 4);
        }

        pub fn barycentricEvaluate(
            session: anytype,
            columns: common.WordMatrix,
            weights: common.SecureFields,
            partial_sums: common.SecureFields,
            reduction_blocks: u32,
            indices: IndexMap,
            sampled_values: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const size = try common.count(weights.len);
            if (size == 0 or reduction_blocks == 0 or
                reduction_blocks > std.math.maxInt(u32) / 256 or
                indices.output_capacity != sampled_values.len)
            {
                return error.InvalidKernelDescriptor;
            }
            const column_values = try layout.wordMatrix(session, columns, size);
            if (column_values.column_count > 65_535 or
                indices.device.len != column_values.column_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const partial_count = std.math.mul(
                usize,
                column_values.column_count,
                reduction_blocks,
            ) catch return error.SizeOverflow;
            const weight_values = try layout.resident(
                session,
                field.SecureField,
                weights,
                size,
            );
            const partial_output = try layout.resident(
                session,
                field.SecureField,
                partial_sums,
                partial_count,
            );
            const output_indices = try layout.resident(
                session,
                u32,
                indices.device,
                column_values.column_count,
            );
            const sampled_output = try layout.resident(
                session,
                field.SecureField,
                sampled_values,
                indices.output_capacity,
            );
            try layout.requireDisjoint(
                &.{ partial_output.range, sampled_output.range },
                &.{
                    column_values.range,
                    weight_values.range,
                    output_indices.range,
                },
            );

            const status = Api.stwo_oods_barycentric_eval_many_on(
                column_values.pointer,
                column_values.stride_words,
                column_values.column_count,
                weight_values.pointer,
                size,
                partial_output.pointer,
                reduction_blocks,
                output_indices.pointer,
                sampled_output.pointer,
                indices.output_capacity,
                session.context.stream,
            );
            try common.recordMany(session, stage, status, 2);
        }
    };
}

fn matrixElements(
    row_count: usize,
    row_stride: usize,
    row_elements: usize,
) runtime_error.Error!usize {
    if (row_count == 0 or row_stride < row_elements or row_elements == 0)
        return error.InvalidKernelDescriptor;
    const final_offset = std.math.mul(
        usize,
        row_count - 1,
        row_stride,
    ) catch return error.SizeOverflow;
    return std.math.add(usize, final_offset, row_elements) catch
        return error.SizeOverflow;
}
