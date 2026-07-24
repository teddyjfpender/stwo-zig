//! Shared resident commitment construction over a host-sealed Merkle layout.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const telemetry = @import("../../../backends/cuda/runtime/telemetry.zig");

pub const Error = runtime_error.Error || error{InvalidMerkleLayout};

pub fn BuilderFor(comptime Ops: type) type {
    return struct {
        pub fn baseField(
            session: anytype,
            stage: telemetry.Stage,
            size: u32,
            columns: common.WordMatrix,
            states: common.ProgressiveStates,
            hashes: common.Hashes,
            layers: []const field.MerkleLayerDescriptor,
        ) Error!common.Hashes {
            if (columns.storage.len == 0 or
                columns.column_stride_words != size or
                columns.storage.len % size != 0 or
                states.len != size)
            {
                return error.InvalidMerkleLayout;
            }
            try validateLayout(size, hashes.len, layers);
            const leaves = try layerSlice(hashes, layers[0]);
            try Ops.progressiveInit(session, stage, states);
            try Ops.progressiveAbsorb(
                session,
                stage,
                size,
                0,
                columns,
                states,
            );
            try Ops.progressiveFinalize(
                session,
                stage,
                @intCast(columns.storage.len / size),
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
        var init_calls: usize = 0;
        var absorb_calls: usize = 0;
        var finalize_calls: usize = 0;
        var fri_leaf_calls: usize = 0;
        var layer_calls: usize = 0;

        fn reset() void {
            init_calls = 0;
            absorb_calls = 0;
            finalize_calls = 0;
            fri_leaf_calls = 0;
            layer_calls = 0;
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
            try std.testing.expectEqual(@as(u32, 0), absorbed);
            try std.testing.expectEqual(@as(usize, 24), columns.storage.len);
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
        states,
        hashes,
        &layers,
    );
    try std.testing.expectEqual(@as(usize, 1), base_root.len);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.init_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.absorb_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeOps.finalize_calls);
    try std.testing.expectEqual(@as(usize, 3), FakeOps.layer_calls);

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
    try std.testing.expectEqual(@as(usize, 3), FakeOps.layer_calls);
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
