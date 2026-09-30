//! Multi-arena quotient accumulation over address-stable resident columns.

const std = @import("std");
const abi = @import("../../abi/stages/quotient.zig");
const field = @import("../../abi/field.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const plan = @import("quotient_plan.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

pub const NativeBucket = struct {
    term_begin: u32,
    term_end: u32,
    source_log_size: u32,
};

pub const BucketExecution = struct {
    buckets: []const NativeBucket,
    group_bucket_offsets: []const u32,
    group_log_sizes: []const u32,
    output_offsets: []const u64,
    group_term_offsets: []const u32,
    group_term_indices: []const u32,
    maximum_scratch_rows: usize,
};

pub fn OpsFor(comptime Api: type) type {
    return struct {
        pub fn accumulateBucketedFinalized(
            session: anytype,
            topology: plan.AddressedNumeratorTopology,
            execution: BucketExecution,
            line_coefficients: common.SecureFields,
            scratch_columns: CoordinateColumns,
            outputs: CoordinateColumns,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.quotient;
            try common.requireStage(session, stage);
            const group_count = topology.group_count;
            const term_count = try common.count(topology.terms.len);
            if (group_count == 0 or term_count == 0 or
                topology.source_count == 0 or
                topology.resident_sources.len != topology.source_count or
                topology.sources.len != topology.source_count or
                topology.offsets.len != group_count + 1 or
                topology.group_log_sizes.len != group_count or
                topology.output_offsets.len != group_count + 1 or
                execution.group_bucket_offsets.len != group_count + 1 or
                execution.group_log_sizes.len != group_count or
                execution.output_offsets.len != group_count + 1 or
                execution.group_term_offsets.len != group_count + 1 or
                execution.group_term_indices.len != term_count or
                execution.group_bucket_offsets[0] != 0 or
                execution.group_bucket_offsets[group_count] != execution.buckets.len or
                execution.output_offsets[0] != 0 or
                execution.output_offsets[group_count] != topology.output_word_count or
                execution.maximum_scratch_rows == 0 or
                line_coefficients.len != @as(usize, topology.line_term_count) * 3)
                return error.InvalidKernelDescriptor;

            var previous_term: u32 = 0;
            for (execution.group_log_sizes, 0..) |group_log, group| {
                const begin = execution.group_bucket_offsets[group];
                const end = execution.group_bucket_offsets[group + 1];
                if (group_log == 0 or group_log > 30 or begin >= end or
                    end > execution.buckets.len or
                    execution.group_term_offsets[group] >= term_count or
                    execution.group_term_offsets[group + 1] <= execution.group_term_offsets[group] or
                    execution.group_term_offsets[group + 1] > term_count or
                    execution.group_term_indices[execution.group_term_offsets[group]] >= topology.line_term_count or
                    execution.output_offsets[group + 1] < execution.output_offsets[group] or
                    execution.output_offsets[group + 1] - execution.output_offsets[group] !=
                        (@as(u64, 1) << @intCast(group_log)))
                    return error.InvalidKernelDescriptor;
                for (execution.buckets[begin..end]) |bucket| {
                    if (bucket.term_begin != previous_term or
                        bucket.term_end <= bucket.term_begin or
                        bucket.term_end > term_count or
                        bucket.source_log_size == 0 or
                        bucket.source_log_size > group_log or
                        (@as(usize, 1) << @intCast(bucket.source_log_size)) > execution.maximum_scratch_rows)
                        return error.InvalidKernelDescriptor;
                    previous_term = bucket.term_end;
                }
            }
            if (previous_term != term_count) return error.InvalidKernelDescriptor;

            const terms = try layout.resident(session, abi.BatchTermDescriptor, topology.terms, term_count);
            const descriptors = try layout.resident(session, abi.AddressedSourceDescriptor, topology.sources, topology.source_count);
            const lines = try layout.resident(session, field.SecureField, line_coefficients, line_coefficients.len);
            const scratch = try residentCoordinateColumns(session, scratch_columns, execution.maximum_scratch_rows);
            const output = try residentCoordinateColumns(session, outputs, topology.output_word_count);
            const writes = output.ranges();
            const temporary = scratch.ranges();
            const reads = [_]layout.DeviceRange{ terms.range, descriptors.range, lines.range };
            try layout.requireDisjoint(&writes, &reads);
            try layout.requireDisjoint(&temporary, &reads);
            try layout.requireDisjoint(&writes, &temporary);
            for (topology.resident_sources) |source| {
                const resident = try layout.resident(session, u32, source, source.len);
                try layout.requireDisjoint(&writes, &.{resident.range});
                try layout.requireDisjoint(&temporary, &.{resident.range});
            }
            for (execution.group_log_sizes, 0..) |group_log, group| {
                const begin = execution.group_bucket_offsets[group];
                const end = execution.group_bucket_offsets[group + 1];
                for (execution.buckets[begin..end], 0..) |bucket, ordinal| {
                    var launches: u32 = 0;
                    const status = Api.stwo_accumulate_quotient_numerator_native_bucket_on(
                        terms.pointer,
                        term_count,
                        bucket.term_begin,
                        bucket.term_end,
                        descriptors.pointer,
                        topology.source_count,
                        lines.pointer,
                        topology.line_term_count,
                        bucket.source_log_size,
                        group_log,
                        execution.group_term_indices[execution.group_term_offsets[group]],
                        execution.output_offsets[group],
                        topology.output_word_count,
                        execution.maximum_scratch_rows,
                        scratch.c0.pointer,
                        scratch.c1.pointer,
                        scratch.c2.pointer,
                        scratch.c3.pointer,
                        output.c0.pointer,
                        output.c1.pointer,
                        output.c2.pointer,
                        output.c3.pointer,
                        ordinal == 0,
                        session.context.stream,
                        &launches,
                    );
                    try common.recordMany(session, stage, status, launches);
                }
            }
        }

        pub fn accumulate(
            session: anytype,
            topology: plan.AddressedNumeratorTopology,
            line_coefficients: common.SecureFields,
            outputs: CoordinateColumns,
        ) runtime_error.Error!void {
            return accumulateImpl(false, session, topology, line_coefficients, outputs);
        }

        pub fn accumulateFinalized(
            session: anytype,
            topology: plan.AddressedNumeratorTopology,
            line_coefficients: common.SecureFields,
            outputs: CoordinateColumns,
        ) runtime_error.Error!void {
            return accumulateImpl(true, session, topology, line_coefficients, outputs);
        }

        fn accumulateImpl(
            comptime finalized: bool,
            session: anytype,
            topology: plan.AddressedNumeratorTopology,
            line_coefficients: common.SecureFields,
            outputs: CoordinateColumns,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.quotient;
            try common.requireStage(session, stage);
            const group_count = topology.group_count;
            const term_count = try common.count(topology.terms.len);
            if (group_count == 0 or term_count == 0 or
                topology.source_count == 0 or
                topology.resident_sources.len != topology.source_count or
                !std.math.isPowerOfTwo(topology.max_output_size) or
                topology.offsets.len != group_count + 1 or
                topology.group_log_sizes.len != group_count or
                topology.output_offsets.len != group_count + 1 or
                topology.output_word_count == 0 or
                topology.sources.len != topology.source_count or
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
            const terms = try layout.resident(
                session,
                abi.BatchTermDescriptor,
                topology.terms,
                term_count,
            );
            const descriptors = try layout.resident(
                session,
                abi.AddressedSourceDescriptor,
                topology.sources,
                topology.source_count,
            );
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
            const output = try residentCoordinateColumns(
                session,
                outputs,
                topology.output_word_count,
            );
            const output_offsets = try layout.resident(
                session,
                u64,
                topology.output_offsets,
                group_count + 1,
            );
            const writes = output.ranges();
            try layout.requireDisjoint(&writes, &.{
                offsets.range,
                terms.range,
                descriptors.range,
                lines.range,
                logs.range,
                output_offsets.range,
            });
            for (topology.resident_sources) |source| {
                const resident = try layout.resident(
                    session,
                    u32,
                    source,
                    source.len,
                );
                try layout.requireDisjoint(&writes, &.{resident.range});
            }
            const status = if (comptime finalized)
                Api.stwo_accumulate_quotient_numerator_addressed_variant_on(
                    offsets.pointer,
                    terms.pointer,
                    term_count,
                    group_count,
                    topology.max_output_size,
                    descriptors.pointer,
                    topology.source_count,
                    lines.pointer,
                    topology.line_term_count,
                    logs.pointer,
                    output_offsets.pointer,
                    topology.output_word_count,
                    output.c0.pointer,
                    output.c1.pointer,
                    output.c2.pointer,
                    output.c3.pointer,
                    true,
                    session.context.stream,
                )
            else
                Api.stwo_accumulate_quotient_numerator_addressed_on(
                    offsets.pointer,
                    terms.pointer,
                    term_count,
                    group_count,
                    topology.max_output_size,
                    descriptors.pointer,
                    topology.source_count,
                    lines.pointer,
                    topology.line_term_count,
                    logs.pointer,
                    output_offsets.pointer,
                    topology.output_word_count,
                    output.c0.pointer,
                    output.c1.pointer,
                    output.c2.pointer,
                    output.c3.pointer,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }
    };
}

pub const CoordinateColumns = struct {
    c0: common.Words,
    c1: common.Words,
    c2: common.Words,
    c3: common.Words,
};

const ResidentCoordinateColumns = struct {
    c0: layout.Resident(u32),
    c1: layout.Resident(u32),
    c2: layout.Resident(u32),
    c3: layout.Resident(u32),

    fn ranges(self: @This()) [4]layout.DeviceRange {
        return .{
            self.c0.range,
            self.c1.range,
            self.c2.range,
            self.c3.range,
        };
    }
};

fn residentCoordinateColumns(
    session: anytype,
    columns: CoordinateColumns,
    word_count: usize,
) runtime_error.Error!ResidentCoordinateColumns {
    const c0 = try layout.resident(
        session,
        u32,
        columns.c0,
        word_count,
    );
    const c1 = try layout.resident(
        session,
        u32,
        columns.c1,
        word_count,
    );
    const c2 = try layout.resident(
        session,
        u32,
        columns.c2,
        word_count,
    );
    const c3 = try layout.resident(
        session,
        u32,
        columns.c3,
        word_count,
    );
    return .{
        .c0 = c0,
        .c1 = c1,
        .c2 = c2,
        .c3 = c3,
    };
}
