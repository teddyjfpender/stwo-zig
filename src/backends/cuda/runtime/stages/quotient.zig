//! Checked resident quotient construction over contiguous coordinate slabs.

const std = @import("std");
const abi = @import("../../abi/stages/quotient.zig");
const field = @import("../../abi/field.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const plan = @import("quotient_plan.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
pub const PreparedGroups = plan.PreparedGroups;
pub const NumeratorTopology = plan.NumeratorTopology;
pub const CombineTopology = plan.CombineTopology;
pub const prepareGroups = plan.prepareGroups;
pub const prepareNumeratorTopology = plan.prepareNumeratorTopology;
pub const prepareCombineTopology = plan.prepareCombineTopology;
const stage = telemetry.Stage.quotient;

pub const CoordinateSlabs = struct {
    c0: common.WordMatrix,
    c1: common.WordMatrix,
    c2: common.WordMatrix,
    c3: common.WordMatrix,
};

pub const CoordinateColumns = struct {
    c0: common.Words,
    c1: common.Words,
    c2: common.Words,
    c3: common.Words,
};

const ResidentCoordinateSlabs = struct {
    c0: layout.WordMatrix,
    c1: layout.WordMatrix,
    c2: layout.WordMatrix,
    c3: layout.WordMatrix,
    stride_words: usize,

    fn ranges(self: @This()) [4]layout.DeviceRange {
        return .{
            self.c0.range,
            self.c1.range,
            self.c2.range,
            self.c3.range,
        };
    }
};

fn residentCoordinateSlabs(
    session: anytype,
    slabs: CoordinateSlabs,
    touched_words_per_column: usize,
    expected_column_count: u32,
) runtime_error.Error!ResidentCoordinateSlabs {
    const c0 = try layout.wordMatrix(
        session,
        slabs.c0,
        touched_words_per_column,
    );
    const c1 = try layout.wordMatrix(
        session,
        slabs.c1,
        touched_words_per_column,
    );
    const c2 = try layout.wordMatrix(
        session,
        slabs.c2,
        touched_words_per_column,
    );
    const c3 = try layout.wordMatrix(
        session,
        slabs.c3,
        touched_words_per_column,
    );
    if (c0.column_count != expected_column_count or
        c1.column_count != expected_column_count or
        c2.column_count != expected_column_count or
        c3.column_count != expected_column_count or
        c1.stride_words != c0.stride_words or
        c2.stride_words != c0.stride_words or
        c3.stride_words != c0.stride_words)
    {
        return error.InvalidKernelDescriptor;
    }
    return .{
        .c0 = c0,
        .c1 = c1,
        .c2 = c2,
        .c3 = c3,
        .stride_words = c0.stride_words,
    };
}

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn prepareTerms(
            session: anytype,
            topology: PreparedGroups,
            sample_points: common.SecureCirclePoints,
            sample_values: common.SecureFields,
            random_coefficient: common.SecureFields,
            term_points: common.SecureCirclePoints,
            line_coefficients: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const term_count = try common.count(topology.descriptors.len);
            const sample_count = topology.sample_count;
            const line_count = std.math.mul(
                usize,
                term_count,
                3,
            ) catch return error.SizeOverflow;
            if (term_count == 0 or sample_count == 0 or
                sample_points.len != sample_count or
                sample_values.len != sample_count or
                random_coefficient.len != 1 or
                term_points.len != term_count or
                line_coefficients.len != line_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const descriptors = try layout.resident(
                session,
                abi.PreparedTermDescriptor,
                topology.descriptors,
                term_count,
            );
            const samples = try layout.resident(
                session,
                field.SecureCirclePoint,
                sample_points,
                sample_count,
            );
            const values = try layout.resident(
                session,
                field.SecureField,
                sample_values,
                sample_count,
            );
            const random = try layout.resident(
                session,
                field.SecureField,
                random_coefficient,
                1,
            );
            const points_output = try layout.resident(
                session,
                field.SecureCirclePoint,
                term_points,
                term_count,
            );
            const lines_output = try layout.resident(
                session,
                field.SecureField,
                line_coefficients,
                line_count,
            );
            try layout.requireDisjoint(
                &.{ points_output.range, lines_output.range },
                &.{
                    descriptors.range,
                    samples.range,
                    values.range,
                    random.range,
                },
            );
            const status = Api.stwo_prepare_quotient_numerator_terms_on(
                descriptors.pointer,
                term_count,
                samples.pointer,
                values.pointer,
                sample_count,
                @ptrCast(random.pointer),
                points_output.pointer,
                lines_output.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn finalizeGroups(
            session: anytype,
            topology: PreparedGroups,
            term_points: common.SecureCirclePoints,
            line_coefficients: common.SecureFields,
            sample_points: common.SecureCirclePoints,
            first_linear_terms: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = topology.group_count;
            const group_term_index_count = try common.count(
                topology.term_indices.len,
            );
            const term_count = try common.count(topology.descriptors.len);
            const line_count = std.math.mul(
                usize,
                term_count,
                3,
            ) catch return error.SizeOverflow;
            if (group_count == 0 or group_term_index_count == 0 or
                term_count == 0 or topology.offsets.len != group_count + 1 or
                term_points.len != term_count or
                line_coefficients.len != line_count or
                sample_points.len != group_count)
            {
                return error.InvalidKernelDescriptor;
            }
            const offsets = try layout.resident(
                session,
                u32,
                topology.offsets,
                group_count + 1,
            );
            const indices = try layout.resident(
                session,
                u32,
                topology.term_indices,
                group_term_index_count,
            );
            const points = try layout.resident(
                session,
                field.SecureCirclePoint,
                term_points,
                term_count,
            );
            const lines = try layout.resident(
                session,
                field.SecureField,
                line_coefficients,
                line_count,
            );
            const sample_output = try layout.resident(
                session,
                field.SecureCirclePoint,
                sample_points,
                group_count,
            );
            const first_output = try layout.resident(
                session,
                field.SecureField,
                first_linear_terms,
                group_count,
            );
            try layout.requireDisjoint(
                &.{ lines.range, sample_output.range, first_output.range },
                &.{ offsets.range, indices.range, points.range },
            );
            const status = Api.stwo_finalize_quotient_numerator_groups_on(
                offsets.pointer,
                indices.pointer,
                group_term_index_count,
                group_count,
                points.pointer,
                term_count,
                lines.pointer,
                sample_output.pointer,
                first_output.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn zeroOutputs(
            session: anytype,
            topology: NumeratorTopology,
            outputs: CoordinateSlabs,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = topology.group_count;
            const max_output_size = topology.max_output_size;
            if (group_count == 0 or !std.math.isPowerOfTwo(max_output_size))
                return error.InvalidKernelDescriptor;
            const logs = try layout.resident(
                session,
                u32,
                topology.group_log_sizes,
                group_count,
            );
            const output = try residentCoordinateSlabs(
                session,
                outputs,
                max_output_size,
                group_count,
            );
            const output_ranges = output.ranges();
            try layout.requireDisjoint(&output_ranges, &.{logs.range});
            const status = Api.stwo_zero_quotient_numerator_outputs_on(
                logs.pointer,
                group_count,
                max_output_size,
                output.c0.pointer,
                output.c1.pointer,
                output.c2.pointer,
                output.c3.pointer,
                output.stride_words,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn accumulate(
            session: anytype,
            topology: NumeratorTopology,
            source_evaluations: common.WordMatrix,
            line_coefficients: common.SecureFields,
            outputs: CoordinateSlabs,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = topology.group_count;
            const term_count = try common.count(topology.terms.len);
            const max_output_size = topology.max_output_size;
            if (group_count == 0 or term_count == 0 or
                !std.math.isPowerOfTwo(max_output_size) or
                topology.offsets.len != group_count + 1 or
                topology.group_log_sizes.len != group_count or
                source_evaluations.column_stride_words !=
                    topology.source_stride_words or
                line_coefficients.len !=
                    @as(usize, topology.line_term_count) * 3)
            {
                return error.InvalidKernelDescriptor;
            }
            const offsets = try layout.resident(
                session,
                u32,
                topology.offsets,
                group_count + 1,
            );
            const descriptors = try layout.resident(
                session,
                abi.BatchTermDescriptor,
                topology.terms,
                term_count,
            );
            const sources = try layout.wordMatrix(
                session,
                source_evaluations,
                source_evaluations.column_stride_words,
            );
            if (sources.column_count != topology.source_count)
                return error.InvalidKernelDescriptor;
            const lines = try layout.resident(
                session,
                field.SecureField,
                line_coefficients,
                line_coefficients.len,
            );
            const logs = try layout.resident(
                session,
                u32,
                topology.group_log_sizes,
                group_count,
            );
            const output = try residentCoordinateSlabs(
                session,
                outputs,
                max_output_size,
                group_count,
            );
            const output_ranges = output.ranges();
            try layout.requireDisjoint(
                &output_ranges,
                &.{
                    offsets.range,
                    descriptors.range,
                    sources.range,
                    lines.range,
                    logs.range,
                },
            );
            const status =
                Api.stwo_accumulate_quotient_numerator_single_write_on(
                    offsets.pointer,
                    descriptors.pointer,
                    term_count,
                    group_count,
                    max_output_size,
                    sources.pointer,
                    sources.stride_words,
                    sources.column_count,
                    lines.pointer,
                    topology.line_term_count,
                    logs.pointer,
                    output.c0.pointer,
                    output.c1.pointer,
                    output.c2.pointer,
                    output.c3.pointer,
                    output.stride_words,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }

        pub fn combine(
            session: anytype,
            half_coset_initial_index: u32,
            half_coset_step_size: u32,
            topology: CombineTopology,
            sample_points: common.SecureCirclePoints,
            first_linear_terms: common.SecureFields,
            partials: CoordinateSlabs,
            result: CoordinateColumns,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const domain_log_size = topology.domain_log_size;
            const domain_size = try domainSize(domain_log_size);
            const sample_count = topology.sample_count;
            if (half_coset_step_size == 0 or sample_count == 0 or
                sample_points.len != sample_count or
                first_linear_terms.len != sample_count or
                topology.partial_log_sizes.len != sample_count or
                partials.c0.column_stride_words !=
                    topology.partial_stride_words)
            {
                return error.InvalidKernelDescriptor;
            }
            const samples = try layout.resident(
                session,
                field.SecureCirclePoint,
                sample_points,
                sample_count,
            );
            const first = try layout.resident(
                session,
                field.SecureField,
                first_linear_terms,
                sample_count,
            );
            const logs = try layout.resident(
                session,
                u32,
                topology.partial_log_sizes,
                sample_count,
            );
            const partial = try residentCoordinateSlabs(
                session,
                partials,
                topology.partial_stride_words,
                sample_count,
            );
            const result_0 = try layout.resident(
                session,
                u32,
                result.c0,
                domain_size,
            );
            const result_1 = try layout.resident(
                session,
                u32,
                result.c1,
                domain_size,
            );
            const result_2 = try layout.resident(
                session,
                u32,
                result.c2,
                domain_size,
            );
            const result_3 = try layout.resident(
                session,
                u32,
                result.c3,
                domain_size,
            );
            const result_ranges = [_]layout.DeviceRange{
                result_0.range,
                result_1.range,
                result_2.range,
                result_3.range,
            };
            const partial_ranges = partial.ranges();
            try layout.requireDisjoint(
                &result_ranges,
                &.{
                    samples.range,
                    first.range,
                    logs.range,
                    partial_ranges[0],
                    partial_ranges[1],
                    partial_ranges[2],
                    partial_ranges[3],
                },
            );
            const status = Api.stwo_combine_quotients_from_numerators_on(
                half_coset_initial_index,
                half_coset_step_size,
                domain_size,
                domain_log_size,
                samples.pointer,
                sample_count,
                first.pointer,
                logs.pointer,
                partial.c0.pointer,
                partial.c1.pointer,
                partial.c2.pointer,
                partial.c3.pointer,
                partial.stride_words,
                result_0.pointer,
                result_1.pointer,
                result_2.pointer,
                result_3.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn domainSize(log_size: u32) runtime_error.Error!u32 {
    if (log_size == 0 or log_size > 30)
        return error.InvalidKernelDescriptor;
    const shift: u5 = @intCast(log_size);
    return @as(u32, 1) << shift;
}
