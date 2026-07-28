//! Resident commitment construction over a host-sealed Merkle layout.

const std = @import("std");
const field = @import("stwo_cuda_backend").abi.field;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const runtime_error = @import("stwo_cuda_backend").runtime.runtime_error;
const telemetry = @import("stwo_cuda_backend").runtime.telemetry;

pub const Error = runtime_error.Error || error{InvalidMerkleLayout};
pub const LiftedSegment = struct {
    columns: common.WordMatrix,
    source_size: u32,
};
// One cooperative block wins only after the remaining tree fits this range.
const upper_tail_max_input_hashes: usize = 512;
const upper_tail_min_levels: usize = 2;

pub fn BuilderFor(comptime Ops: type) type {
    return struct {
        pub fn baseField(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            columns: common.WordMatrix,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            try validateMatrix(size, columns);
            try validateLayout(size, hashes.len, layers);
            const leaves = try layerSlice(hashes, layers[0]);
            try Ops.contiguousLeaves(session, stage, size, columns, leaves);
            return reduce(session, stage, hashes, layers);
        }

        pub fn baseFieldSegmented(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            segments: []const common.WordMatrix,
            states: common.ProgressiveStates,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            if (segments.len < 2 or states.len != size)
                return error.InvalidMerkleLayout;
            try validateLayout(size, hashes.len, layers);
            var absorbed: u32 = 0;
            for (segments) |segment| {
                try validateMatrix(size, segment);
                const columns = std.math.cast(
                    u32,
                    segment.storage.len / segment.column_stride_words,
                ) orelse return error.InvalidMerkleLayout;
                absorbed = std.math.add(u32, absorbed, columns) catch
                    return error.InvalidMerkleLayout;
            }
            const leaves = try layerSlice(hashes, layers[0]);
            try Ops.progressiveInit(session, stage, states);
            var absorbed_before: u32 = 0;
            for (segments) |segment| {
                try Ops.progressiveAbsorb(
                    session,
                    stage,
                    size,
                    absorbed_before,
                    segment,
                    states,
                );
                absorbed_before += @intCast(
                    segment.storage.len / segment.column_stride_words,
                );
            }
            try Ops.progressiveFinalize(
                session,
                stage,
                absorbed,
                states,
                leaves,
            );
            return reduce(session, stage, hashes, layers);
        }

        /// Commit packed mixed-height groups without materializing max-height
        /// columns. Segment order is the exact leaf message order.
        pub fn baseFieldLiftedSegmented(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            segments: []const LiftedSegment,
            states: common.ProgressiveStates,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            if (segments.len == 0 or states.len != size)
                return error.InvalidMerkleLayout;
            try validateLayout(size, hashes.len, layers);
            var absorbed: u32 = 0;
            for (segments) |segment| {
                if (!std.math.isPowerOfTwo(segment.source_size) or
                    segment.source_size < 2 or
                    segment.source_size > size)
                {
                    return error.InvalidMerkleLayout;
                }
                try validateMatrix(segment.source_size, segment.columns);
                const columns = std.math.cast(
                    u32,
                    segment.columns.storage.len /
                        segment.columns.column_stride_words,
                ) orelse return error.InvalidMerkleLayout;
                absorbed = std.math.add(u32, absorbed, columns) catch
                    return error.InvalidMerkleLayout;
            }
            const leaves = try layerSlice(hashes, layers[0]);
            try Ops.progressiveInit(session, stage, states);
            var absorbed_before: u32 = 0;
            for (segments) |segment| {
                try Ops.progressiveAbsorbLifted(
                    session,
                    stage,
                    size,
                    segment.source_size,
                    absorbed_before,
                    segment.columns,
                    states,
                );
                absorbed_before += @intCast(
                    segment.columns.storage.len /
                        segment.columns.column_stride_words,
                );
            }
            try Ops.progressiveFinalize(
                session,
                stage,
                absorbed,
                states,
                leaves,
            );
            return reduce(session, stage, hashes, layers);
        }

        pub fn fri(
            session: anytype,
            evaluation_size: u32,
            log_rows_per_leaf: u32,
            coordinates: common.WordMatrix,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            if (log_rows_per_leaf != 0)
                return error.InvalidMerkleLayout;
            try validateLayout(evaluation_size, hashes.len, layers);
            const leaves = try layerSlice(hashes, layers[0]);
            try Ops.friLeaves(
                session,
                coordinates,
                evaluation_size,
                log_rows_per_leaf,
                leaves,
            );
            return reduce(
                session,
                .fri_commit,
                hashes,
                layers,
            );
        }

        fn reduce(
            session: anytype,
            stage: telemetry.Stage,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            var index: usize = 1;
            while (index < layers.len) : (index += 1) {
                const remaining_levels = layers.len - index;
                if (layers[index - 1].hash_count <=
                    upper_tail_max_input_hashes and
                    remaining_levels >= upper_tail_min_levels)
                {
                    const output_offset = std.math.cast(
                        usize,
                        layers[index].offset_hashes,
                    ) orelse return error.SizeOverflow;
                    try Ops.contiguousTail(
                        session,
                        stage,
                        try layerSlice(hashes, layers[index - 1]),
                        try hashes.sub(
                            output_offset,
                            hashes.len - output_offset,
                        ),
                        @intCast(remaining_levels),
                    );
                    break;
                }
                try Ops.layer(
                    session,
                    stage,
                    try layerSlice(hashes, layers[index - 1]),
                    try layerSlice(hashes, layers[index]),
                    false,
                );
            }
            return layerSlice(hashes, layers[layers.len - 1]);
        }
    };
}

fn validateMatrix(
    size: u32,
    columns: common.WordMatrix,
) error{InvalidMerkleLayout}!void {
    if (size == 0 or columns.storage.len == 0 or
        columns.column_stride_words < size or
        columns.storage.len % columns.column_stride_words != 0)
    {
        return error.InvalidMerkleLayout;
    }
}

pub fn validateLayout(
    leaf_count: u32,
    hash_count: usize,
    layers: []const field.MerkleLayerDescriptor,
) error{InvalidMerkleLayout}!void {
    if (leaf_count == 0 or !std.math.isPowerOfTwo(leaf_count))
        return error.InvalidMerkleLayout;
    const expected_layers = std.math.log2_int(u32, leaf_count) + 1;
    if (layers.len != expected_layers)
        return error.InvalidMerkleLayout;

    var count: usize = leaf_count;
    var offset: usize = 0;
    for (layers) |layer| {
        if (layer.reserved != 0 or
            layer.offset_hashes != offset or
            layer.hash_count != count)
        {
            return error.InvalidMerkleLayout;
        }
        offset = std.math.add(usize, offset, count) catch
            return error.InvalidMerkleLayout;
        count = @max(count / 2, 1);
    }
    if (offset != hash_count or count != 1)
        return error.InvalidMerkleLayout;
}

fn layerSlice(
    hashes: common.Hashes,
    layer: field.MerkleLayerDescriptor,
) runtime_error.Error!common.Hashes {
    const offset = std.math.cast(usize, layer.offset_hashes) orelse
        return error.SizeOverflow;
    return hashes.sub(offset, layer.hash_count);
}

test "resident builder uses one sealed layout for base and FRI trees" {
    const FakeOps = struct {
        var contiguous_calls: usize = 0;
        var init_calls: usize = 0;
        var absorb_calls: usize = 0;
        var finalize_calls: usize = 0;
        var fri_leaf_calls: usize = 0;
        var layer_calls: usize = 0;
        var tail_calls: usize = 0;

        fn reset() void {
            contiguous_calls = 0;
            init_calls = 0;
            absorb_calls = 0;
            finalize_calls = 0;
            fri_leaf_calls = 0;
            layer_calls = 0;
            tail_calls = 0;
        }

        pub fn contiguousLeaves(
            _: anytype,
            _: telemetry.Stage,
            size: u32,
            columns: common.WordMatrix,
            leaves: common.Hashes,
        ) !void {
            try std.testing.expectEqual(@as(u32, 8), size);
            try std.testing.expectEqual(@as(usize, 24), columns.storage.len);
            try std.testing.expectEqual(@as(usize, 8), leaves.len);
            contiguous_calls += 1;
        }

        pub fn progressiveInit(
            _: anytype,
            _: telemetry.Stage,
            states: common.ProgressiveStates,
        ) !void {
            try std.testing.expectEqual(@as(usize, 8), states.len);
            init_calls += 1;
        }

        pub fn progressiveAbsorb(
            _: anytype,
            _: telemetry.Stage,
            size: u32,
            absorbed: u32,
            columns: common.WordMatrix,
            _: common.ProgressiveStates,
        ) !void {
            try std.testing.expectEqual(@as(u32, 8), size);
            try std.testing.expect(absorbed == 0 or absorbed == 1);
            try std.testing.expect(
                columns.storage.len == 8 or columns.storage.len == 16,
            );
            absorb_calls += 1;
        }

        pub fn progressiveFinalize(
            _: anytype,
            _: telemetry.Stage,
            columns: u32,
            _: common.ProgressiveStates,
            leaves: common.Hashes,
        ) !void {
            try std.testing.expectEqual(@as(u32, 3), columns);
            try std.testing.expectEqual(@as(usize, 8), leaves.len);
            finalize_calls += 1;
        }

        pub fn progressiveAbsorbLifted(
            _: anytype,
            _: telemetry.Stage,
            size: u32,
            source_size: u32,
            absorbed: u32,
            columns: common.WordMatrix,
            _: common.ProgressiveStates,
        ) !void {
            try std.testing.expectEqual(@as(u32, 8), size);
            try std.testing.expect(
                (source_size == 2 and absorbed == 0 and
                    columns.storage.len == 2) or
                    (source_size == 4 and absorbed == 1 and
                        columns.storage.len == 8),
            );
            absorb_calls += 1;
        }

        pub fn friLeaves(
            _: anytype,
            _: common.WordMatrix,
            size: u32,
            log_rows_per_leaf: u32,
            leaves: common.Hashes,
        ) !void {
            try std.testing.expectEqual(@as(u32, 8), size);
            try std.testing.expectEqual(@as(u32, 0), log_rows_per_leaf);
            try std.testing.expectEqual(@as(usize, 8), leaves.len);
            fri_leaf_calls += 1;
        }

        pub fn layer(
            _: anytype,
            _: telemetry.Stage,
            previous: common.Hashes,
            output: common.Hashes,
            four_levels: bool,
        ) !void {
            try std.testing.expect(!four_levels);
            try std.testing.expectEqual(previous.len / 2, output.len);
            layer_calls += 1;
        }

        pub fn contiguousTail(
            _: anytype,
            _: telemetry.Stage,
            previous: common.Hashes,
            outputs: common.Hashes,
            level_count: u32,
        ) !void {
            try std.testing.expectEqual(@as(usize, 8), previous.len);
            try std.testing.expectEqual(@as(usize, 7), outputs.len);
            try std.testing.expectEqual(@as(u32, 3), level_count);
            tail_calls += 1;
        }
    };
    const Builder = BuilderFor(FakeOps);
    const layers = [_]field.MerkleLayerDescriptor{
        .{ .offset_hashes = 0, .hash_count = 8 },
        .{ .offset_hashes = 8, .hash_count = 4 },
        .{ .offset_hashes = 12, .hash_count = 2 },
        .{ .offset_hashes = 14, .hash_count = 1 },
    };
    const words = common.Words{
        .address = 0x1000,
        .len = 24,
        .owner = 1,
    };
    const states = common.ProgressiveStates{
        .address = 0x2000,
        .len = 8,
        .owner = 1,
    };
    const hashes = common.Hashes{
        .address = 0x3000,
        .len = 15,
        .owner = 1,
    };
    var session: u8 = 0;

    FakeOps.reset();
    const base_root = try Builder.baseField(
        &session,
        .trace_commit,
        8,
        .{ .storage = words, .column_stride_words = 8 },
        hashes,
        &layers,
    );
    try std.testing.expectEqual(@as(usize, 1), base_root.len);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.contiguous_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.init_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.absorb_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.finalize_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.layer_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.tail_calls);

    FakeOps.reset();
    const lifted_segments = [_]LiftedSegment{
        .{
            .columns = .{
                .storage = .{ .address = 0x6000, .len = 2, .owner = 1 },
                .column_stride_words = 2,
            },
            .source_size = 2,
        },
        .{
            .columns = .{
                .storage = .{ .address = 0x7000, .len = 8, .owner = 1 },
                .column_stride_words = 4,
            },
            .source_size = 4,
        },
    };
    const lifted_root = try Builder.baseFieldLiftedSegmented(
        &session,
        .trace_commit,
        8,
        &lifted_segments,
        states,
        hashes,
        &layers,
    );
    try std.testing.expectEqual(@as(usize, 1), lifted_root.len);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.init_calls);
    try std.testing.expectEqual(@as(usize, 2), FakeOps.absorb_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.finalize_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.tail_calls);

    FakeOps.reset();
    const segments = [_]common.WordMatrix{
        .{
            .storage = .{ .address = 0x4000, .len = 8, .owner = 1 },
            .column_stride_words = 8,
        },
        .{
            .storage = .{ .address = 0x5000, .len = 16, .owner = 1 },
            .column_stride_words = 8,
        },
    };
    const segmented_root = try Builder.baseFieldSegmented(
        &session,
        .trace_commit,
        8,
        &segments,
        states,
        hashes,
        &layers,
    );
    try std.testing.expectEqual(@as(usize, 1), segmented_root.len);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.contiguous_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.init_calls);
    try std.testing.expectEqual(@as(usize, 2), FakeOps.absorb_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.finalize_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.layer_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.tail_calls);

    FakeOps.reset();
    const fri_root = try Builder.fri(
        &session,
        8,
        0,
        .{
            .storage = .{ .address = 0x4000, .len = 32, .owner = 1 },
            .column_stride_words = 8,
        },
        hashes,
        &layers,
    );
    try std.testing.expectEqual(@as(usize, 1), fri_root.len);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.fri_leaf_calls);
    try std.testing.expectEqual(@as(usize, 0), FakeOps.layer_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.tail_calls);
}

test "commitment layout rejects gaps and non-power-of-two leaves" {
    var layers = [_]field.MerkleLayerDescriptor{
        .{ .offset_hashes = 0, .hash_count = 4 },
        .{ .offset_hashes = 4, .hash_count = 2 },
        .{ .offset_hashes = 6, .hash_count = 1 },
    };
    try validateLayout(4, 7, &layers);
    layers[1].offset_hashes += 1;
    try std.testing.expectError(
        error.InvalidMerkleLayout,
        validateLayout(4, 7, &layers),
    );
    try std.testing.expectError(
        error.InvalidMerkleLayout,
        validateLayout(3, 7, &layers),
    );
}
