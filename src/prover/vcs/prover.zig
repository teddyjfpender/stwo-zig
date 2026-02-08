const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const vcs_merkle_hasher = @import("../../core/vcs/merkle_hasher.zig");
const vcs_utils = @import("../../core/vcs/utils.zig");
const vcs_verifier = @import("../../core/vcs/verifier.zig");

const M31 = m31.M31;

pub fn MerkleProver(comptime H: type) type {
    comptime vcs_merkle_hasher.assertMerkleHasher(H);
    return struct {
        /// Merkle layers from root to largest layer.
        layers: [][]H.Hash,

        const Self = @This();
        const NodeValue = vcs_verifier.MerkleDecommitmentAux(H).NodeValue;
        const ExtendedDecommitment = vcs_verifier.ExtendedMerkleDecommitment(H);
        const Decommitment = vcs_verifier.MerkleDecommitment(H);
        const LogSizeQueries = vcs_verifier.LogSizeQueries;

        pub const DecommitmentResult = struct {
            queried_values: []M31,
            decommitment: ExtendedDecommitment,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                allocator.free(self.queried_values);
                self.decommitment.deinit(allocator);
                self.* = undefined;
            }
        };

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.layers) |layer| allocator.free(layer);
            allocator.free(self.layers);
            self.* = undefined;
        }

        pub fn root(self: Self) H.Hash {
            return self.layers[0][0];
        }

        pub fn commit(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) !Self {
            const sorted = try sortColumnsByLogSizeDesc(allocator, columns);
            defer allocator.free(sorted);

            if (sorted.len == 0) {
                const layer = try allocator.alloc(H.Hash, 1);
                layer[0] = H.hashNode(null, &[_]M31{});
                const layers = try allocator.alloc([]H.Hash, 1);
                layers[0] = layer;
                return .{ .layers = layers };
            }

            const max_log_size = sorted[0].log_size;

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| allocator.free(layer);
            }

            var layer_log_size: i64 = @intCast(max_log_size);
            while (layer_log_size >= 0) : (layer_log_size -= 1) {
                const log_size: u32 = @intCast(layer_log_size);
                var layer_columns = std.ArrayList(ColumnRef).empty;
                defer layer_columns.deinit(allocator);
                for (sorted) |col| {
                    if (col.log_size == log_size) try layer_columns.append(allocator, col);
                }

                const prev_layer = if (layers_bottom_up.items.len == 0)
                    null
                else
                    layers_bottom_up.items[layers_bottom_up.items.len - 1];

                const next_layer = try commitOnLayer(allocator, log_size, prev_layer, layer_columns.items);
                try layers_bottom_up.append(allocator, next_layer);
            }

            const out_layers = try allocator.alloc([]H.Hash, layers_bottom_up.items.len);
            var i: usize = 0;
            while (i < out_layers.len) : (i += 1) {
                out_layers[i] = layers_bottom_up.items[out_layers.len - 1 - i];
            }
            return .{ .layers = out_layers };
        }

        pub fn decommit(
            self: Self,
            allocator: std.mem.Allocator,
            queries_per_log_size: []const LogSizeQueries,
            columns: []const []const M31,
        ) !DecommitmentResult {
            const sorted = try sortColumnsByLogSizeDesc(allocator, columns);
            defer allocator.free(sorted);

            var queried_values_builder = std.ArrayList(M31).empty;
            defer queried_values_builder.deinit(allocator);

            var hash_witness = std.ArrayList(H.Hash).empty;
            defer hash_witness.deinit(allocator);
            var column_witness = std.ArrayList(M31).empty;
            defer column_witness.deinit(allocator);

            var all_node_values = std.ArrayList([]NodeValue).empty;
            defer {
                for (all_node_values.items) |layer| allocator.free(layer);
                all_node_values.deinit(allocator);
            }

            var last_layer_queries = try allocator.alloc(usize, 0);
            defer allocator.free(last_layer_queries);

            var layer_log_size: i64 = @intCast(self.layers.len - 1);
            while (layer_log_size >= 0) : (layer_log_size -= 1) {
                const log_size: u32 = @intCast(layer_log_size);

                var layer_columns = std.ArrayList(ColumnRef).empty;
                defer layer_columns.deinit(allocator);
                for (sorted) |col| {
                    if (col.log_size == log_size) try layer_columns.append(allocator, col);
                }

                const previous_layer_hashes = if (log_size + 1 < self.layers.len)
                    self.layers[log_size + 1]
                else
                    null;

                var layer_total_queries = std.ArrayList(usize).empty;
                defer layer_total_queries.deinit(allocator);
                var all_node_values_for_layer = std.ArrayList(NodeValue).empty;
                defer all_node_values_for_layer.deinit(allocator);

                const layer_column_queries = queriesForLogSize(queries_per_log_size, log_size);

                var prev_queries_at: usize = 0;
                var layer_queries_at: usize = 0;

                while (vcs_utils.nextDecommitmentNode(
                    last_layer_queries,
                    prev_queries_at,
                    layer_column_queries,
                    layer_queries_at,
                )) |node_index| {
                    if (previous_layer_hashes) |prev_hashes| {
                        const left_index = 2 * node_index;
                        const right_index = left_index + 1;
                        try all_node_values_for_layer.append(allocator, .{
                            .index = left_index,
                            .hash = prev_hashes[left_index],
                        });
                        try all_node_values_for_layer.append(allocator, .{
                            .index = right_index,
                            .hash = prev_hashes[right_index],
                        });

                        if (prev_queries_at < last_layer_queries.len and
                            last_layer_queries[prev_queries_at] == left_index)
                        {
                            prev_queries_at += 1;
                        } else {
                            try hash_witness.append(allocator, prev_hashes[left_index]);
                        }

                        if (prev_queries_at < last_layer_queries.len and
                            last_layer_queries[prev_queries_at] == right_index)
                        {
                            prev_queries_at += 1;
                        } else {
                            try hash_witness.append(allocator, prev_hashes[right_index]);
                        }
                    }

                    var node_values = std.ArrayList(M31).empty;
                    defer node_values.deinit(allocator);
                    for (layer_columns.items) |column| {
                        try node_values.append(allocator, column.values[node_index]);
                    }

                    if (layer_queries_at < layer_column_queries.len and
                        layer_column_queries[layer_queries_at] == node_index)
                    {
                        layer_queries_at += 1;
                        try queried_values_builder.appendSlice(allocator, node_values.items);
                    } else {
                        try column_witness.appendSlice(allocator, node_values.items);
                    }
                    try layer_total_queries.append(allocator, node_index);
                }

                const layer_values_owned = try all_node_values_for_layer.toOwnedSlice(allocator);
                try all_node_values.append(allocator, layer_values_owned);

                allocator.free(last_layer_queries);
                last_layer_queries = try layer_total_queries.toOwnedSlice(allocator);
            }

            return .{
                .queried_values = try queried_values_builder.toOwnedSlice(allocator),
                .decommitment = .{
                    .decommitment = Decommitment{
                        .hash_witness = try hash_witness.toOwnedSlice(allocator),
                        .column_witness = try column_witness.toOwnedSlice(allocator),
                    },
                    .aux = .{
                        .all_node_values = try all_node_values.toOwnedSlice(allocator),
                    },
                },
            };
        }

        fn queriesForLogSize(
            queries_per_log_size: []const LogSizeQueries,
            log_size: u32,
        ) []const usize {
            for (queries_per_log_size) |entry| {
                if (entry.log_size == log_size) return entry.queries;
            }
            return &[_]usize{};
        }

        const ColumnRef = struct {
            values: []const M31,
            log_size: u32,
            original_index: usize,
        };

        fn sortColumnsByLogSizeDesc(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) ![]ColumnRef {
            const out = try allocator.alloc(ColumnRef, columns.len);
            for (columns, 0..) |column, i| {
                if (!std.math.isPowerOfTwo(column.len)) return error.InvalidColumnSize;
                out[i] = .{
                    .values = column,
                    .log_size = @intCast(std.math.log2_int(usize, column.len)),
                    .original_index = i,
                };
            }
            std.sort.heap(ColumnRef, out, {}, lessByLogSizeDescStable);
            return out;
        }

        fn lessByLogSizeDescStable(_: void, lhs: ColumnRef, rhs: ColumnRef) bool {
            if (lhs.log_size == rhs.log_size) return lhs.original_index < rhs.original_index;
            return lhs.log_size > rhs.log_size;
        }

        fn commitOnLayer(
            allocator: std.mem.Allocator,
            log_size: u32,
            prev_layer: ?[]const H.Hash,
            layer_columns: []const ColumnRef,
        ) ![]H.Hash {
            const layer_size = @as(usize, 1) << @intCast(log_size);
            if (prev_layer) |prev| {
                std.debug.assert(prev.len == layer_size * 2);
            }

            const out = try allocator.alloc(H.Hash, layer_size);
            var node_values = try allocator.alloc(M31, layer_columns.len);
            defer allocator.free(node_values);

            var i: usize = 0;
            while (i < layer_size) : (i += 1) {
                for (layer_columns, 0..) |column, col_i| {
                    node_values[col_i] = column.values[i];
                }
                out[i] = H.hashNode(
                    if (prev_layer) |prev|
                        .{ .left = prev[2 * i], .right = prev[2 * i + 1] }
                    else
                        null,
                    node_values,
                );
            }
            return out;
        }
    };
}

test "prover vcs: decommit and verify roundtrip" {
    const Hasher = @import("../../core/vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProver(Hasher);
    const Verifier = @import("../../core/vcs/verifier.zig").MerkleVerifier(Hasher);
    const alloc = std.testing.allocator;

    const columns = [_][]const M31{
        &[_]M31{
            M31.fromCanonical(1),
            M31.fromCanonical(2),
            M31.fromCanonical(3),
            M31.fromCanonical(4),
            M31.fromCanonical(5),
            M31.fromCanonical(6),
            M31.fromCanonical(7),
            M31.fromCanonical(8),
        },
        &[_]M31{
            M31.fromCanonical(9),
            M31.fromCanonical(10),
            M31.fromCanonical(11),
            M31.fromCanonical(12),
        },
        &[_]M31{
            M31.fromCanonical(13),
            M31.fromCanonical(14),
            M31.fromCanonical(15),
            M31.fromCanonical(16),
            M31.fromCanonical(17),
            M31.fromCanonical(18),
            M31.fromCanonical(19),
            M31.fromCanonical(20),
        },
    };

    var prover = try Prover.commit(alloc, columns[0..]);
    defer prover.deinit(alloc);

    const queries = [_]vcs_verifier.LogSizeQueries{
        .{ .log_size = 3, .queries = &[_]usize{ 1, 6 } },
        .{ .log_size = 2, .queries = &[_]usize{2} },
    };
    var decommitment = try prover.decommit(alloc, queries[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    var column_log_sizes = [_]u32{ 3, 2, 3 };
    var verifier = try Verifier.init(alloc, prover.root(), column_log_sizes[0..]);
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        queries[0..],
        decommitment.queried_values,
        decommitment.decommitment.decommitment,
    );
}

test "prover vcs: invalid witness fails verification" {
    const Hasher = @import("../../core/vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProver(Hasher);
    const Verifier = @import("../../core/vcs/verifier.zig").MerkleVerifier(Hasher);
    const alloc = std.testing.allocator;

    const columns = [_][]const M31{
        &[_]M31{
            M31.fromCanonical(1),
            M31.fromCanonical(2),
            M31.fromCanonical(3),
            M31.fromCanonical(4),
        },
    };

    var prover = try Prover.commit(alloc, columns[0..]);
    defer prover.deinit(alloc);

    const queries = [_]vcs_verifier.LogSizeQueries{
        .{ .log_size = 2, .queries = &[_]usize{1} },
    };
    var decommitment = try prover.decommit(alloc, queries[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    decommitment.decommitment.decommitment.hash_witness[0][0] ^= 1;

    var verifier = try Verifier.init(alloc, prover.root(), &[_]u32{2});
    defer verifier.deinit(alloc);

    try std.testing.expectError(
        vcs_verifier.MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            queries[0..],
            decommitment.queried_values,
            decommitment.decommitment.decommitment,
        ),
    );
}
