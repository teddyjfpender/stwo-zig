//! Checked resident quotient construction dispatch.

const abi = @import("../../abi/stages/quotient.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
const stage = telemetry.Stage.quotient;

pub const CoordinateTables = struct {
    c0: common.PointerTable,
    c1: common.PointerTable,
    c2: common.PointerTable,
    c3: common.PointerTable,
};

pub const CoordinateColumns = struct {
    c0: common.Words,
    c1: common.Words,
    c2: common.Words,
    c3: common.Words,
};

pub const PreparedTermDescriptors = column.DeviceSlice(abi.PreparedTermDescriptor);
pub const BatchTermDescriptors = column.DeviceSlice(abi.BatchTermDescriptor);

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn prepareTerms(
            session: anytype,
            term_descriptors: PreparedTermDescriptors,
            sample_points: common.SecureCirclePoints,
            sample_values: common.SecureFields,
            random_coefficient: common.SecureFields,
            term_points: common.SecureCirclePoints,
            line_coefficients: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const term_count = try common.count(term_descriptors.len);
            const line_count = @import("std").math.mul(
                usize,
                term_count,
                3,
            ) catch return error.SizeOverflow;
            if (term_count == 0 or sample_values.len == 0 or
                sample_points.len != sample_values.len or
                term_points.len != term_count or
                line_coefficients.len != line_count)
            {
                return error.SizeOverflow;
            }
            const status = Api.stwo_prepare_quotient_numerator_terms_on(
                try session.context.deviceSlicePointer(
                    abi.PreparedTermDescriptor,
                    term_descriptors,
                    term_count,
                ),
                term_count,
                try common.secureCircles(session, sample_points, 1),
                try common.secure(session, sample_values, 1),
                @ptrCast(try common.secure(session, random_coefficient, 1)),
                try common.secureCircles(session, term_points, term_count),
                try common.secure(session, line_coefficients, line_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn finalizeGroups(
            session: anytype,
            group_offsets: common.Words,
            group_term_indices: common.Words,
            term_points: common.SecureCirclePoints,
            line_coefficients: common.SecureFields,
            sample_points: common.SecureCirclePoints,
            first_linear_terms: common.SecureFields,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = try common.count(first_linear_terms.len);
            const term_count = term_points.len;
            const line_count = @import("std").math.mul(
                usize,
                term_count,
                3,
            ) catch return error.SizeOverflow;
            if (group_count == 0 or group_offsets.len < group_count + 1 or
                group_term_indices.len == 0 or term_count == 0 or
                line_coefficients.len != line_count or
                sample_points.len < group_count)
                return error.SizeOverflow;
            const status = Api.stwo_finalize_quotient_numerator_groups_on(
                try common.words(session, group_offsets, group_count + 1),
                try common.words(session, group_term_indices, 1),
                group_count,
                try common.secureCircles(session, term_points, term_count),
                try common.secure(session, line_coefficients, line_count),
                try common.secureCircles(session, sample_points, group_count),
                try common.secure(session, first_linear_terms, group_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn zeroOutputs(
            session: anytype,
            group_log_sizes: common.Words,
            max_output_size: u32,
            outputs: CoordinateTables,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = try common.count(group_log_sizes.len);
            try common.requireNonZero(&.{ group_count, max_output_size });
            const status = Api.stwo_zero_quotient_numerator_outputs_on(
                try common.words(session, group_log_sizes, group_count),
                group_count,
                max_output_size,
                try common.mutableWordTable(session, outputs.c0, group_count),
                try common.mutableWordTable(session, outputs.c1, group_count),
                try common.mutableWordTable(session, outputs.c2, group_count),
                try common.mutableWordTable(session, outputs.c3, group_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn accumulate(
            session: anytype,
            group_offsets: common.Words,
            term_descriptors: BatchTermDescriptors,
            max_output_size: u32,
            source_evaluations: common.PointerTable,
            line_coefficients: common.SecureFields,
            group_log_sizes: common.Words,
            outputs: CoordinateTables,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const group_count = try common.count(group_log_sizes.len);
            try common.requireNonZero(&.{ group_count, max_output_size });
            if (group_offsets.len < group_count + 1 or
                term_descriptors.len == 0 or line_coefficients.len % 3 != 0)
                return error.SizeOverflow;
            const status = Api.stwo_accumulate_quotient_numerator_single_write_on(
                try common.words(session, group_offsets, group_count + 1),
                try session.context.deviceSlicePointer(
                    abi.BatchTermDescriptor,
                    term_descriptors,
                    1,
                ),
                group_count,
                max_output_size,
                try common.constWordTable(session, source_evaluations, 1),
                try common.secure(session, line_coefficients, 1),
                try common.words(session, group_log_sizes, group_count),
                try common.mutableWordTable(session, outputs.c0, group_count),
                try common.mutableWordTable(session, outputs.c1, group_count),
                try common.mutableWordTable(session, outputs.c2, group_count),
                try common.mutableWordTable(session, outputs.c3, group_count),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn combine(
            session: anytype,
            half_coset_initial_index: u32,
            half_coset_step_size: u32,
            domain_log_size: u32,
            sample_points: common.SecureCirclePoints,
            first_linear_terms: common.SecureFields,
            partial_log_sizes: common.Words,
            partials: CoordinateTables,
            result: CoordinateColumns,
        ) runtime_error.Error!void {
            try common.requireStage(session, stage);
            const domain_size = try domainSize(domain_log_size);
            const sample_size = try common.count(sample_points.len);
            const partial_count = try common.count(partial_log_sizes.len);
            try common.requireNonZero(&.{ sample_size, partial_count });
            const status = Api.stwo_combine_quotients_from_numerators_on(
                half_coset_initial_index,
                half_coset_step_size,
                domain_size,
                domain_log_size,
                try common.secureCircles(session, sample_points, sample_size),
                sample_size,
                try common.secure(session, first_linear_terms, 1),
                try common.words(session, partial_log_sizes, partial_count),
                try common.constWordTable(session, partials.c0, partial_count),
                try common.constWordTable(session, partials.c1, partial_count),
                try common.constWordTable(session, partials.c2, partial_count),
                try common.constWordTable(session, partials.c3, partial_count),
                try common.words(session, result.c0, domain_size),
                try common.words(session, result.c1, domain_size),
                try common.words(session, result.c2, domain_size),
                try common.words(session, result.c3, domain_size),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn domainSize(log_size: u32) runtime_error.Error!u32 {
    if (log_size >= 32) return error.SizeOverflow;
    const shift: u5 = @intCast(log_size);
    return @as(u32, 1) << shift;
}
