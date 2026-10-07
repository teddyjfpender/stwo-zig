//! Checked resident Blake2s commitment dispatch.

const std = @import("std");
const abi = @import("../../abi/stages/commitment.zig");
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const layout = @import("resident_layout.zig");
const runtime_error = @import("../error.zig");
const telemetry = @import("../telemetry.zig");

pub const Native = OpsFor(abi);
/// Pinned Stwo-Cairo uses plain BLAKE2s, independently of older proof formats.
pub const PlainNative = OpsFor(@import("../../abi/stages/commitment_plain.zig"));
pub const max_mixed_segments = abi.max_mixed_segments;
pub const max_compact_prefix_log = abi.max_compact_prefix_log;

pub fn OpsFor(comptime Api: type) type {
    return struct {
        /// One register-resident leaf message across packed heterogeneous cohorts.
        pub fn mixedLeaves(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, output: common.Hashes) runtime_error.Error!void {
            try mixedWithSeed(session, stage, size, segments, 0, null, null, output, false, 0, size);
        }

        pub fn mixedPrefix(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: ?common.ProgressiveStates, output: common.ProgressiveStates) runtime_error.Error!void {
            try mixedWithSeed(session, stage, size, segments, absorbed, seed, output, null, false, 0, size);
        }

        pub fn mixedLeavesFromPrefix(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: common.ProgressiveStates, output: common.Hashes) runtime_error.Error!void {
            try mixedWithSeed(session, stage, size, segments, absorbed, seed, null, output, false, 0, size);
        }

        /// Exact mixed-message rows in one bounded range. Called only for a
        /// managed arena; the native ABI stages touched source pages around
        /// this range on the ordered proof stream.
        pub fn mixedRange(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            segments: anytype,
            absorbed: u32,
            seed: ?common.ProgressiveStates,
            prefix: ?common.ProgressiveStates,
            output: ?common.Hashes,
            row_first: u32,
            row_count: u32,
        ) runtime_error.Error!void {
            try mixedWithSeed(session, stage, size, segments, absorbed, seed,
                prefix, output, true, row_first, row_count);
        }

        fn mixedWithSeed(session: anytype, stage: telemetry.Stage, size: u32, segments: anytype, absorbed: u32, seed: ?common.ProgressiveStates, prefix: ?common.ProgressiveStates, output: ?common.Hashes, comptime tiled: bool, row_first: u32, row_count: u32) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            if (size < 2 or !std.math.isPowerOfTwo(size) or
                segments.len == 0 or segments.len > max_mixed_segments or
                row_count == 0 or row_first >= size or row_count > size - row_first or
                (prefix == null) == (output == null)) return error.InvalidKernelDescriptor;
            const output_range = if (prefix) |value| blk: {
                if (value.len != size) return error.SizeOverflow;
                break :blk try layout.elementRange(value.address, value.len, @sizeOf(field.ProgressiveBlake2sState));
            } else blk: {
                if (output.?.len != size) return error.SizeOverflow;
                break :blk try layout.elementRange(output.?.address, output.?.len, @sizeOf(field.Blake2sHash));
            };
            const prefix_pointer = if (prefix) |value| try common.states(session, value, size) else null;
            const hashes_pointer = if (output) |value| try common.hashes(session, value, size) else null;
            const seed_pointer = if (seed) |value| blk: {
                if (absorbed == 0 or value.len < 2 or value.len > size or
                    !std.math.isPowerOfTwo(value.len)) return error.InvalidKernelDescriptor;
                const admitted = try layout.resident(session, field.ProgressiveBlake2sState, value, value.len);
                if (layout.overlap(admitted.range, output_range)) return error.OverlappingDeviceRange;
                break :blk admitted.pointer;
            } else blk: {
                if (absorbed != 0) return error.InvalidKernelDescriptor;
                break :blk null;
            };
            var descriptors: [max_mixed_segments]abi.MixedSegment = undefined;
            var total_columns = absorbed;
            for (segments, descriptors[0..segments.len]) |segment, *descriptor| {
                if (segment.source_size < 2 or segment.source_size > size or
                    !std.math.isPowerOfTwo(segment.source_size)) return error.InvalidKernelDescriptor;
                const source = try layout.wordMatrix(session, segment.columns, segment.source_size);
                if (layout.overlap(source.range, output_range)) return error.OverlappingDeviceRange;
                total_columns = std.math.add(u32, total_columns, source.column_count) catch return error.SizeOverflow;
                descriptor.* = .{ .columns = source.pointer, .stride_words = source.stride_words, .capacity_words = segment.columns.storage.len, .source_size = segment.source_size };
            }
            const status = if (tiled)
                Api.stwo_blake2s_mixed_seeded_range_on(
                    size, row_first, row_count, @intCast(segments.len),
                    &descriptors, absorbed,
                    if (seed) |value| try common.count(value.len) else 0,
                    seed_pointer, prefix_pointer, hashes_pointer,
                    session.context.stream,
                )
            else if (output != null and seed == null and absorbed == 0)
                Api.stwo_blake2s_mixed_leaf_on(size, @intCast(segments.len), &descriptors, hashes_pointer.?, session.context.stream)
            else
                Api.stwo_blake2s_mixed_seeded_on(size, @intCast(segments.len), &descriptors, absorbed, if (seed) |value| try common.count(value.len) else 0, seed_pointer, prefix_pointer, hashes_pointer, session.context.stream);
            try common.record(session, stage, status);
        }

        pub fn contiguousLeaves(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            columns: common.WordMatrix,
            output: common.Hashes,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            const source = try layout.wordMatrix(session, columns, size);
            if (output.len != size) return error.SizeOverflow;
            const hashes = try layout.resident(
                session,
                field.Blake2sHash,
                output,
                output.len,
            );
            if (layout.overlap(source.range, hashes.range))
                return error.OverlappingDeviceRange;
            const status = Api.stwo_blake2s_contiguous_leaf_on(
                size,
                source.pointer,
                source.stride_words,
                columns.storage.len,
                hashes.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn progressiveInit(
            session: anytype,
            stage: telemetry.Stage,
            states: common.ProgressiveStates,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            const size = try common.count(states.len);
            const status = Api.stwo_blake2s_progressive_init_on(
                size,
                try common.states(session, states, 1),
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn progressiveAbsorb(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            absorbed_columns_before: u32,
            columns: common.WordMatrix,
            states: common.ProgressiveStates,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{size});
            const source = try layout.wordMatrix(session, columns, size);
            _ = std.math.add(
                u32,
                absorbed_columns_before,
                source.column_count,
            ) catch return error.SizeOverflow;
            const state_values = try layout.resident(
                session,
                field.ProgressiveBlake2sState,
                states,
                size,
            );
            const source_capacity = try layout.elementRange(
                columns.storage.address,
                columns.storage.len,
                @sizeOf(u32),
            );
            if (layout.overlap(source_capacity, state_values.range))
                return error.OverlappingDeviceRange;
            const status = Api.stwo_blake2s_progressive_absorb_on(
                size,
                absorbed_columns_before,
                source.pointer,
                source.stride_words,
                columns.storage.len,
                state_values.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        /// Absorb one contiguous variable-height group into a lifted leaf
        /// domain. `columns` remains packed at `source_size`; no expanded
        /// pointer table or padded max-height matrix is admitted.
        pub fn progressiveAbsorbLifted(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            source_size: u32,
            absorbed_columns_before: u32,
            columns: common.WordMatrix,
            states: common.ProgressiveStates,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            if (!std.math.isPowerOfTwo(size) or
                !std.math.isPowerOfTwo(source_size) or
                source_size < 2 or
                source_size > size)
            {
                return error.InvalidKernelDescriptor;
            }
            const source = try layout.wordMatrix(
                session,
                columns,
                source_size,
            );
            _ = std.math.add(
                u32,
                absorbed_columns_before,
                source.column_count,
            ) catch return error.SizeOverflow;
            const state_values = try layout.resident(
                session,
                field.ProgressiveBlake2sState,
                states,
                size,
            );
            const source_capacity = try layout.elementRange(
                columns.storage.address,
                columns.storage.len,
                @sizeOf(u32),
            );
            if (layout.overlap(source_capacity, state_values.range))
                return error.OverlappingDeviceRange;
            const status =
                Api.stwo_blake2s_progressive_absorb_lifted_on(
                    size,
                    source_size,
                    absorbed_columns_before,
                    source.pointer,
                    source.stride_words,
                    columns.storage.len,
                    state_values.pointer,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }

        pub fn progressiveFinalize(
            session: anytype,
            stage: telemetry.Stage,
            absorbed_columns: u32,
            states: common.ProgressiveStates,
            output: common.Hashes,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            if (states.len == 0) return error.InvalidKernelDescriptor;
            if (states.len != output.len) return error.SizeOverflow;
            const size = try common.count(states.len);
            const state_values = try layout.resident(
                session,
                field.ProgressiveBlake2sState,
                states,
                states.len,
            );
            const hashes = try layout.resident(
                session,
                field.Blake2sHash,
                output,
                output.len,
            );
            if (layout.overlap(state_values.range, hashes.range))
                return error.OverlappingDeviceRange;
            const status = Api.stwo_blake2s_progressive_finalize_on(
                size,
                absorbed_columns,
                state_values.pointer,
                hashes.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn layer(
            session: anytype,
            stage: telemetry.Stage,
            previous: common.Hashes,
            output: common.Hashes,
            four_levels: bool,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            if (output.len == 0) return error.InvalidKernelDescriptor;
            const expected_input = if (four_levels)
                std.math.mul(usize, output.len, 16) catch
                    return error.SizeOverflow
            else
                std.math.mul(usize, output.len, 2) catch
                    return error.SizeOverflow;
            if (previous.len < expected_input) return error.SizeOverflow;
            const previous_values = try layout.resident(
                session,
                field.Blake2sHash,
                previous,
                expected_input,
            );
            const output_values = try layout.resident(
                session,
                field.Blake2sHash,
                output,
                output.len,
            );
            if (layout.overlap(previous_values.range, output_values.range))
                return error.OverlappingDeviceRange;
            const output_size = try common.count(output.len);
            const status = if (four_levels)
                Api.stwo_blake2s_interior4_on(
                    previous_values.pointer,
                    output_size,
                    output_values.pointer,
                    session.context.stream,
                )
            else
                Api.stwo_blake2s_layer_on(
                    previous_values.pointer,
                    output_size,
                    output_values.pointer,
                    session.context.stream,
                );
            try common.record(session, stage, status);
        }

        pub fn contiguousTail(
            session: anytype,
            stage: telemetry.Stage,
            previous: common.Hashes,
            outputs: common.Hashes,
            level_count: u32,
        ) runtime_error.Error!void {
            try requireCommitStage(stage);
            try common.requireStage(session, stage);
            if (previous.len == 0 or
                !std.math.isPowerOfTwo(previous.len) or
                level_count == 0 or
                level_count >= @bitSizeOf(usize))
            {
                return error.InvalidKernelDescriptor;
            }
            const final_size = previous.len >> @intCast(level_count);
            if (final_size == 0 or outputs.len != previous.len - final_size)
                return error.SizeOverflow;
            const previous_values = try layout.resident(
                session,
                field.Blake2sHash,
                previous,
                previous.len,
            );
            const output_values = try layout.resident(
                session,
                field.Blake2sHash,
                outputs,
                outputs.len,
            );
            if (layout.overlap(previous_values.range, output_values.range))
                return error.OverlappingDeviceRange;
            const status = Api.stwo_blake2s_contiguous_tail_on(
                previous_values.pointer,
                try common.count(previous.len),
                output_values.pointer,
                outputs.len,
                level_count,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }

        pub fn friLeaves(
            session: anytype,
            coordinate_columns: common.WordMatrix,
            evaluation_size: u32,
            log_rows_per_leaf: u32,
            output: common.Hashes,
        ) runtime_error.Error!void {
            const stage = telemetry.Stage.fri_commit;
            try common.requireStage(session, stage);
            try common.requireNonZero(&.{evaluation_size});
            if (!std.math.isPowerOfTwo(evaluation_size) or
                (log_rows_per_leaf != 0 and log_rows_per_leaf != 2))
                return error.InvalidKernelDescriptor;
            const leaf_count = evaluation_size >> @intCast(log_rows_per_leaf);
            if (output.len != leaf_count) return error.SizeOverflow;
            const coordinates = try layout.wordMatrix(
                session,
                coordinate_columns,
                evaluation_size,
            );
            if (coordinates.column_count != 4)
                return error.InvalidKernelDescriptor;
            const hashes = try layout.resident(
                session,
                field.Blake2sHash,
                output,
                leaf_count,
            );
            const source_capacity = try layout.elementRange(
                coordinate_columns.storage.address,
                coordinate_columns.storage.len,
                @sizeOf(u32),
            );
            if (layout.overlap(source_capacity, hashes.range))
                return error.OverlappingDeviceRange;
            const status = Api.stwo_blake2s_fri_leaf_on(
                evaluation_size,
                coordinates.pointer,
                coordinates.stride_words,
                coordinate_columns.storage.len,
                log_rows_per_leaf,
                hashes.pointer,
                session.context.stream,
            );
            try common.record(session, stage, status);
        }
    };
}

fn requireCommitStage(stage: telemetry.Stage) runtime_error.Error!void {
    switch (stage) {
        .trace_commit, .constraint_evaluation, .fri_commit => {},
        else => return error.StageOrderViolation,
    }
}

test "composition commitment is an admitted commitment stage" {
    try requireCommitStage(.constraint_evaluation);
    try std.testing.expectError(
        error.StageOrderViolation,
        requireCommitStage(.ingress),
    );
}
