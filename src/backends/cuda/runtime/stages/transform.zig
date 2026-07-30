//! Checked resident circle-transform dispatch over contiguous arena slabs.

const std = @import("std");
const abi = @import("../../abi/stages/transform.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);

/// One contiguous allocation with a fixed per-column stride. The column count
/// is derived from the extent, so no pointer table or duplicate count can
/// disagree with the checked descriptor.
pub const WordMatrix = common.WordMatrix;
pub const AddressedLdeDescriptor = abi.AddressedLdeDescriptor;
pub const AddressedLdeDescriptors = column.DeviceSlice(AddressedLdeDescriptor);

/// Validates the immutable descriptor bytes before ingress. Execution consumes
/// only their sealed resident image.
pub fn validateAddressedPlan(
    descriptors: []const AddressedLdeDescriptor,
    arena_words: usize,
    evaluation_tile_offset_words: usize,
    evaluation_log_size: u32,
) runtime_error.Error!void {
    if (descriptors.len == 0 or
        descriptors.len > std.math.maxInt(u32) or
        arena_words > std.math.maxInt(u64))
    {
        return error.InvalidKernelDescriptor;
    }
    const shape = try transformShape(evaluation_log_size);
    const tile_words = std.math.mul(
        usize,
        descriptors.len,
        shape.values,
    ) catch return error.SizeOverflow;
    const tile_end = std.math.add(
        usize,
        evaluation_tile_offset_words,
        tile_words,
    ) catch return error.SizeOverflow;
    if (tile_end > arena_words) return error.InvalidKernelDescriptor;

    for (descriptors, 0..) |descriptor, index| {
        const destination_delta = std.math.mul(
            usize,
            index,
            shape.values,
        ) catch return error.SizeOverflow;
        const expected_destination = std.math.add(
            usize,
            evaluation_tile_offset_words,
            destination_delta,
        ) catch return error.SizeOverflow;
        descriptor.validate(
            @intCast(arena_words),
            @intCast(expected_destination),
            evaluation_log_size,
        ) catch return error.InvalidKernelDescriptor;
        const coefficient_words =
            @as(u64, 1) << @intCast(descriptor.coefficient_log_size);
        const coefficient_end = std.math.add(
            u64,
            descriptor.coefficient_offset_words,
            coefficient_words,
        ) catch return error.SizeOverflow;
        if (rangesOverlapWords(
            descriptor.coefficient_offset_words,
            coefficient_end,
            @intCast(evaluation_tile_offset_words),
            @intCast(tile_end),
        )) return error.OverlappingDeviceRange;
    }
}

pub fn OpsFor(comptime Api: type) type {
    return struct {
        /// Extends an authenticated heterogeneous coefficient batch into one
        /// reusable contiguous evaluation tile in the same proof arena.
        pub fn extendAddressed(
            session: anytype,
            stage: telemetry.Stage,
            arena: common.Words,
            descriptors: AddressedLdeDescriptors,
            evaluation_tile_offset_words: usize,
            log_n: u32,
            twiddles: common.Words,
            before_final_circle: bool,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            if (descriptors.len == 0 or
                descriptors.len > std.math.maxInt(u32))
            {
                return error.InvalidKernelDescriptor;
            }
            const shape = try transformShape(log_n);
            const arena_values = try layout.resident(
                session,
                u32,
                arena,
                arena.len,
            );
            const descriptor_values = try layout.resident(
                session,
                AddressedLdeDescriptor,
                descriptors,
                descriptors.len,
            );
            const twiddle_values = try layout.resident(
                session,
                u32,
                twiddles,
                twiddles.len,
            );
            if (twiddles.len < shape.domain)
                return error.InvalidKernelDescriptor;
            if (!contains(arena_values.range, descriptor_values.range) or
                !contains(arena_values.range, twiddle_values.range))
            {
                return error.InvalidKernelDescriptor;
            }
            const tile_words = std.math.mul(
                usize,
                descriptors.len,
                shape.values,
            ) catch return error.SizeOverflow;
            const tile_range = try offsetWordRange(
                arena_values.range,
                evaluation_tile_offset_words,
                tile_words,
            );
            if (layout.overlap(tile_range, descriptor_values.range) or
                layout.overlap(tile_range, twiddle_values.range))
            {
                return error.OverlappingDeviceRange;
            }

            var launches: u32 = 0;
            const status = Api.stwo_lde_n2b_addressed_on(
                arena_values.pointer,
                arena.len,
                descriptor_values.pointer,
                @intCast(descriptors.len),
                evaluation_tile_offset_words,
                log_n,
                twiddle_values.pointer,
                try common.count(twiddles.len),
                try common.count(shape.domain),
                session.context.stream,
                @intFromBool(!before_final_circle),
                &launches,
            );
            try common.recordMany(session, stage, status, launches);
        }

        /// Writes one normalized N-word coefficient image per column.
        pub fn inverseCompact(
            session: anytype,
            stage: telemetry.Stage,
            inputs: WordMatrix,
            outputs: WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
        ) runtime_error.Error!void {
            return inverse(
                session,
                stage,
                inputs,
                outputs,
                log_n,
                inverse_twiddles,
                false,
            );
        }

        /// Preserves the retained-layout ABI by duplicating the normalized
        /// N-word coefficient image into both halves of every 2N-word column.
        pub fn inverseToRetained(
            session: anytype,
            stage: telemetry.Stage,
            inputs: WordMatrix,
            retained_outputs: WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
        ) runtime_error.Error!void {
            return inverse(
                session,
                stage,
                inputs,
                retained_outputs,
                log_n,
                inverse_twiddles,
                true,
            );
        }

        fn inverse(
            session: anytype,
            stage: telemetry.Stage,
            inputs: WordMatrix,
            outputs: WordMatrix,
            log_n: u32,
            inverse_twiddles: common.Words,
            comptime duplicate_to_retained: bool,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const input = try layout.wordMatrix(
                session,
                inputs,
                shape.values,
            );
            const output = try layout.wordMatrix(
                session,
                outputs,
                if (duplicate_to_retained)
                    shape.retained_values
                else
                    shape.values,
            );
            if (input.column_count != output.column_count)
                return error.InvalidKernelDescriptor;
            if (layout.overlap(input.range, output.range) and
                (input.range.start != output.range.start or
                    input.stride_words != output.stride_words))
            {
                return error.OverlappingDeviceRange;
            }
            if (inverse_twiddles.len < shape.domain)
                return error.InvalidKernelDescriptor;
            const twiddles = try layout.resident(
                session,
                u32,
                inverse_twiddles,
                inverse_twiddles.len,
            );
            if (layout.overlap(output.range, twiddles.range))
                return error.OverlappingDeviceRange;

            var launches: u32 = 0;
            const status = if (duplicate_to_retained)
                Api.stwo_ntt_b2n_columns_to_retained_on(
                    input.pointer,
                    input.stride_words,
                    output.pointer,
                    output.stride_words,
                    log_n,
                    input.column_count,
                    twiddles.pointer,
                    try common.count(inverse_twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                )
            else
                Api.stwo_ntt_b2n_columns_compact_on(
                    input.pointer,
                    input.stride_words,
                    output.pointer,
                    output.stride_words,
                    log_n,
                    input.column_count,
                    twiddles.pointer,
                    try common.count(inverse_twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                );
            try common.recordMany(
                session,
                stage,
                status,
                launches,
            );
        }

        pub fn forwardInPlace(
            session: anytype,
            stage: telemetry.Stage,
            columns: WordMatrix,
            log_n: u32,
            twiddles: common.Words,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const values = try layout.wordMatrix(session, columns, shape.values);
            const twiddle_values = try layout.resident(
                session,
                u32,
                twiddles,
                shape.domain,
            );
            if (layout.overlap(values.range, twiddle_values.range))
                return error.OverlappingDeviceRange;

            var launches: u32 = 0;
            const status = Api.stwo_ntt_n2b_columns_on(
                values.pointer,
                values.stride_words,
                log_n,
                values.column_count,
                twiddle_values.pointer,
                try common.count(twiddles.len),
                try common.count(shape.domain),
                session.context.stream,
                &launches,
            );
            try common.recordMany(
                session,
                stage,
                status,
                launches,
            );
        }

        pub fn extend(
            session: anytype,
            stage: telemetry.Stage,
            coefficients: WordMatrix,
            coefficient_log_sizes: common.Words,
            evaluations: WordMatrix,
            log_n: u32,
            twiddles: common.Words,
            before_final_circle: bool,
        ) runtime_error.Error!void {
            try requireTransformStage(stage);
            try common.requireStage(session, stage);
            const shape = try transformShape(log_n);
            const coefficient_values = try layout.wordMatrix(
                session,
                coefficients,
                shape.domain,
            );
            const evaluation_values = try layout.wordMatrix(
                session,
                evaluations,
                shape.values,
            );
            if (coefficient_values.column_count != evaluation_values.column_count)
                return error.InvalidKernelDescriptor;
            const count: usize = evaluation_values.column_count;
            const sizes = try layout.resident(
                session,
                u32,
                coefficient_log_sizes,
                count,
            );
            const twiddle_values = try layout.resident(
                session,
                u32,
                twiddles,
                shape.domain,
            );
            for ([_]layout.DeviceRange{
                coefficient_values.range,
                sizes.range,
                twiddle_values.range,
            }) |read_range| {
                if (layout.overlap(evaluation_values.range, read_range))
                    return error.OverlappingDeviceRange;
            }

            var launches: u32 = 0;
            const status = if (before_final_circle)
                Api.stwo_lde_n2b_columns_before_circle_on(
                    coefficient_values.pointer,
                    coefficient_values.stride_words,
                    sizes.pointer,
                    evaluation_values.pointer,
                    evaluation_values.stride_words,
                    log_n,
                    evaluation_values.column_count,
                    twiddle_values.pointer,
                    try common.count(twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                )
            else
                Api.stwo_lde_n2b_columns_on(
                    coefficient_values.pointer,
                    coefficient_values.stride_words,
                    sizes.pointer,
                    evaluation_values.pointer,
                    evaluation_values.stride_words,
                    log_n,
                    evaluation_values.column_count,
                    twiddle_values.pointer,
                    try common.count(twiddles.len),
                    try common.count(shape.domain),
                    session.context.stream,
                    &launches,
                );
            try common.recordMany(
                session,
                stage,
                status,
                launches,
            );
        }
    };
}

const TransformShape = struct {
    domain: usize,
    values: usize,
    retained_values: usize,
};

fn transformShape(log_n: u32) runtime_error.Error!TransformShape {
    if (log_n < 3 or log_n > 30) return error.InvalidKernelDescriptor;
    const values = @as(usize, 1) << @intCast(log_n);
    return .{
        .domain = values / 2,
        .values = values,
        .retained_values = std.math.mul(usize, values, 2) catch
            return error.SizeOverflow,
    };
}

fn requireTransformStage(stage: telemetry.Stage) runtime_error.Error!void {
    switch (stage) {
        .ingress,
        .trace_commit,
        .constraint_evaluation,
        .oods,
        .quotient,
        .fri_commit,
        => {},
        else => return error.StageOrderViolation,
    }
}

fn contains(outer: layout.DeviceRange, inner: layout.DeviceRange) bool {
    return outer.start <= inner.start and inner.end <= outer.end;
}

fn offsetWordRange(
    arena: layout.DeviceRange,
    offset_words: usize,
    word_count: usize,
) runtime_error.Error!layout.DeviceRange {
    const offset_bytes = std.math.mul(
        usize,
        offset_words,
        @sizeOf(u32),
    ) catch return error.SizeOverflow;
    const start = std.math.add(
        usize,
        arena.start,
        offset_bytes,
    ) catch return error.SizeOverflow;
    const result = try layout.elementRange(start, word_count, @sizeOf(u32));
    if (!contains(arena, result)) return error.InvalidKernelDescriptor;
    return result;
}

fn rangesOverlapWords(
    left_start: u64,
    left_end: u64,
    right_start: u64,
    right_end: u64,
) bool {
    return left_start < right_end and right_start < left_end;
}

test "composition extension is an admitted transform stage" {
    try requireTransformStage(.constraint_evaluation);
    try requireTransformStage(.ingress);
}
