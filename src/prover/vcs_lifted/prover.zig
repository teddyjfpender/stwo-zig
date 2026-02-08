const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const lifted_merkle_hasher = @import("../../core/vcs_lifted/merkle_hasher.zig");
const vcs_lifted_verifier = @import("../../core/vcs_lifted/verifier.zig");

const M31 = m31.M31;

pub fn MerkleProverLifted(comptime H: type) type {
    comptime lifted_merkle_hasher.assertMerkleHasherLifted(H);
    return struct {
        /// Merkle layers from root to largest layer.
        layers: [][]H.Hash,

        const Self = @This();
        const NodeValue = vcs_lifted_verifier.MerkleDecommitmentLiftedAux(H).NodeValue;
        const ExtendedDecommitment = vcs_lifted_verifier.ExtendedMerkleDecommitmentLifted(H);
        const Decommitment = vcs_lifted_verifier.MerkleDecommitmentLifted(H);

        pub const DecommitmentResult = struct {
            queried_values: [][]M31,
            decommitment: ExtendedDecommitment,

            pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
                for (self.queried_values) |column| allocator.free(column);
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
            const sorted = try sortColumnsByLogSizeAsc(allocator, columns);
            defer allocator.free(sorted);

            var layers_bottom_up = std.ArrayList([]H.Hash).empty;
            defer layers_bottom_up.deinit(allocator);
            errdefer {
                for (layers_bottom_up.items) |layer| allocator.free(layer);
            }

            const leaves = try buildLeaves(allocator, sorted);
            try layers_bottom_up.append(allocator, leaves);

            if (leaves.len > 1) {
                std.debug.assert(std.math.isPowerOfTwo(leaves.len));
                const max_log_size = std.math.log2_int(usize, leaves.len);
                var i: usize = 0;
                while (i < max_log_size) : (i += 1) {
                    const next_layer = try buildNextLayer(
                        allocator,
                        layers_bottom_up.items[layers_bottom_up.items.len - 1],
                    );
                    try layers_bottom_up.append(allocator, next_layer);
                }
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
            query_positions: []const usize,
            columns: []const []const M31,
        ) !DecommitmentResult {
            const max_log_size_u32: u32 = @intCast(self.layers.len - 1);

            const queried_values = try allocator.alloc([]M31, columns.len);
            var queried_values_initialized: usize = 0;
            errdefer {
                for (queried_values[0..queried_values_initialized]) |column| allocator.free(column);
                allocator.free(queried_values);
            }

            for (columns, 0..) |column, i| {
                if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
                    return error.InvalidColumnSize;
                }
                const log_size: u32 = @intCast(std.math.log2_int(usize, column.len));
                if (log_size > max_log_size_u32) return error.InvalidColumnSize;
                const shift = max_log_size_u32 - log_size;
                const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);

                queried_values[i] = try allocator.alloc(M31, query_positions.len);
                queried_values_initialized += 1;
                for (query_positions, 0..) |position, j| {
                    const column_index = ((position >> shift_amt) << 1) + (position & 1);
                    queried_values[i][j] = column[column_index];
                }
            }

            var hash_witness = std.ArrayList(H.Hash).empty;
            defer hash_witness.deinit(allocator);

            var all_node_values = std.ArrayList([]NodeValue).empty;
            defer {
                for (all_node_values.items) |layer| allocator.free(layer);
                all_node_values.deinit(allocator);
            }

            var prev_layer_queries = std.ArrayList(usize).empty;
            defer prev_layer_queries.deinit(allocator);
            for (query_positions, 0..) |position, i| {
                if (i == 0 or query_positions[i - 1] != position) {
                    try prev_layer_queries.append(allocator, position);
                }
            }

            var layer_log_size: i64 = @intCast(self.layers.len);
            layer_log_size -= 2;
            while (layer_log_size >= 0) : (layer_log_size -= 1) {
                const prev_layer_hashes = self.layers[@intCast(layer_log_size + 1)];

                var curr_layer_queries = std.ArrayList(usize).empty;
                defer curr_layer_queries.deinit(allocator);

                var all_node_values_for_layer = std.ArrayList(NodeValue).empty;
                defer all_node_values_for_layer.deinit(allocator);

                var p: usize = 0;
                while (p < prev_layer_queries.items.len) {
                    const first = prev_layer_queries.items[p];
                    var chunk_len: usize = 1;
                    if (p + 1 < prev_layer_queries.items.len and
                        ((first ^ 1) == prev_layer_queries.items[p + 1]))
                    {
                        chunk_len = 2;
                    }

                    if (chunk_len == 1) {
                        try hash_witness.append(allocator, prev_layer_hashes[first ^ 1]);
                    }

                    const curr_index = first >> 1;
                    try curr_layer_queries.append(allocator, curr_index);
                    try all_node_values_for_layer.append(allocator, .{
                        .index = 2 * curr_index,
                        .hash = prev_layer_hashes[2 * curr_index],
                    });
                    try all_node_values_for_layer.append(allocator, .{
                        .index = 2 * curr_index + 1,
                        .hash = prev_layer_hashes[2 * curr_index + 1],
                    });
                    p += chunk_len;
                }

                prev_layer_queries.clearRetainingCapacity();
                try prev_layer_queries.appendSlice(allocator, curr_layer_queries.items);

                try all_node_values.append(allocator, try all_node_values_for_layer.toOwnedSlice(allocator));
            }

            const hash_witness_owned = try hash_witness.toOwnedSlice(allocator);
            errdefer allocator.free(hash_witness_owned);

            const all_node_values_owned = try all_node_values.toOwnedSlice(allocator);
            errdefer {
                for (all_node_values_owned) |layer| allocator.free(layer);
                allocator.free(all_node_values_owned);
            }

            return .{
                .queried_values = queried_values,
                .decommitment = .{
                    .decommitment = Decommitment{
                        .hash_witness = hash_witness_owned,
                    },
                    .aux = .{
                        .all_node_values = all_node_values_owned,
                    },
                },
            };
        }

        const ColumnRef = struct {
            values: []const M31,
            log_size: u32,
            original_index: usize,
        };

        fn sortColumnsByLogSizeAsc(
            allocator: std.mem.Allocator,
            columns: []const []const M31,
        ) ![]ColumnRef {
            const out = try allocator.alloc(ColumnRef, columns.len);
            for (columns, 0..) |column, i| {
                if (!std.math.isPowerOfTwo(column.len) or column.len < 2) {
                    return error.InvalidColumnSize;
                }
                out[i] = .{
                    .values = column,
                    .log_size = @intCast(std.math.log2_int(usize, column.len)),
                    .original_index = i,
                };
            }
            std.sort.heap(ColumnRef, out, {}, lessByLogSizeAscStable);
            return out;
        }

        fn lessByLogSizeAscStable(_: void, lhs: ColumnRef, rhs: ColumnRef) bool {
            if (lhs.log_size == rhs.log_size) return lhs.original_index < rhs.original_index;
            return lhs.log_size < rhs.log_size;
        }

        fn buildLeaves(
            allocator: std.mem.Allocator,
            sorted_columns: []const ColumnRef,
        ) ![]H.Hash {
            var seed_hasher = H.defaultWithInitialState();
            if (sorted_columns.len == 0) {
                const layer = try allocator.alloc(H.Hash, 1);
                layer[0] = seed_hasher.finalize();
                return layer;
            }

            if (sorted_columns[0].values.len == 1) return error.InvalidColumnSize;

            var prev_layer = try allocator.alloc(H, 2);
            prev_layer[0] = seed_hasher;
            prev_layer[1] = seed_hasher;

            var prev_layer_log_size: u32 = 1;
            var group_start: usize = 0;
            while (group_start < sorted_columns.len) {
                const log_size = sorted_columns[group_start].log_size;
                var group_end = group_start + 1;
                while (group_end < sorted_columns.len and
                    sorted_columns[group_end].log_size == log_size)
                {
                    group_end += 1;
                }

                const log_ratio = log_size - prev_layer_log_size;
                const layer_size = @as(usize, 1) << @intCast(log_size);
                const shift_amt: std.math.Log2Int(usize) = @intCast(log_ratio + 1);
                const expanded = try allocator.alloc(H, layer_size);
                for (0..layer_size) |idx| {
                    const src_idx = ((idx >> shift_amt) << 1) + (idx & 1);
                    expanded[idx] = prev_layer[src_idx];
                }
                allocator.free(prev_layer);
                prev_layer = expanded;

                for (sorted_columns[group_start..group_end]) |column| {
                    var idx: usize = 0;
                    while (idx < layer_size) : (idx += 1) {
                        const value = [_]M31{column.values[idx]};
                        prev_layer[idx].updateLeaf(value[0..]);
                    }
                }

                prev_layer_log_size = log_size;
                group_start = group_end;
            }

            const out = try allocator.alloc(H.Hash, prev_layer.len);
            for (prev_layer, 0..) |*hasher, i| out[i] = hasher.finalize();
            allocator.free(prev_layer);
            return out;
        }

        fn buildNextLayer(
            allocator: std.mem.Allocator,
            prev_layer: []const H.Hash,
        ) ![]H.Hash {
            std.debug.assert(prev_layer.len > 1 and std.math.isPowerOfTwo(prev_layer.len));
            const out = try allocator.alloc(H.Hash, prev_layer.len >> 1);
            for (0..out.len) |i| {
                out[i] = H.hashChildren(.{
                    .left = prev_layer[2 * i],
                    .right = prev_layer[2 * i + 1],
                });
            }
            return out;
        }
    };
}

test "prover vcs_lifted: decommit and verify roundtrip" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("../../core/vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);
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

    const query_positions = [_]usize{ 1, 6, 6 };
    var decommitment = try prover.decommit(alloc, query_positions[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
    defer alloc.free(queried_values);
    for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

    var verifier = try Verifier.init(alloc, prover.root(), &[_]u32{ 3, 2, 3 });
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        query_positions[0..],
        queried_values,
        decommitment.decommitment.decommitment,
    );
}

test "prover vcs_lifted: invalid witness fails verification" {
    const Hasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("../../core/vcs_lifted/verifier.zig").MerkleVerifierLifted(Hasher);
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

    const query_positions = [_]usize{1};
    var decommitment = try prover.decommit(alloc, query_positions[0..], columns[0..]);
    defer decommitment.deinit(alloc);

    decommitment.decommitment.decommitment.hash_witness[0][0] ^= 1;

    const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
    defer alloc.free(queried_values);
    for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

    var verifier = try Verifier.init(alloc, prover.root(), &[_]u32{2});
    defer verifier.deinit(alloc);
    try std.testing.expectError(
        vcs_lifted_verifier.MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            query_positions[0..],
            queried_values,
            decommitment.decommitment.decommitment,
        ),
    );
}

test "prover vcs_lifted: empty columns root matches mixed-degree prover" {
    const LiftedHasher = @import("../../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const MixedHasher = @import("../../core/vcs/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = MerkleProverLifted(LiftedHasher);
    const MixedProver = @import("../vcs/prover.zig").MerkleProver(MixedHasher);
    const alloc = std.testing.allocator;

    const no_columns = [_][]const M31{};
    var lifted = try LiftedProver.commit(alloc, no_columns[0..]);
    defer lifted.deinit(alloc);
    var mixed = try MixedProver.commit(alloc, no_columns[0..]);
    defer mixed.deinit(alloc);

    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&lifted.root()), std.mem.asBytes(&mixed.root())));
}
