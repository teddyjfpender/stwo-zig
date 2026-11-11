const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_hash = @import("hash.zig");
const vcs_merkle_hasher = @import("merkle_hasher.zig");
const vcs_utils = @import("utils.zig");

const M31 = m31.M31;

pub const MerkleVerificationError = error{
    WitnessTooShort,
    WitnessTooLong,
    TooManyQueriedValues,
    TooFewQueriedValues,
    RootMismatch,
};

pub const LogSizeQueries = struct {
    log_size: u32,
    queries: []const usize,
};

pub fn MerkleDecommitment(comptime H: type) type {
    return struct {
        hash_witness: []H.Hash,
        column_witness: []M31,

        const Self = @This();

        pub fn empty(allocator: std.mem.Allocator) !Self {
            return .{
                .hash_witness = try allocator.alloc(H.Hash, 0),
                .column_witness = try allocator.alloc(M31, 0),
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.hash_witness);
            allocator.free(self.column_witness);
            self.* = undefined;
        }
    };
}

pub fn MerkleDecommitmentAux(comptime H: type) type {
    return struct {
        all_node_values: [][]NodeValue,

        pub const NodeValue = struct {
            index: usize,
            hash: H.Hash,
        };

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.all_node_values) |layer| allocator.free(layer);
            allocator.free(self.all_node_values);
            self.* = undefined;
        }
    };
}

pub fn ExtendedMerkleDecommitment(comptime H: type) type {
    return struct {
        decommitment: MerkleDecommitment(H),
        aux: MerkleDecommitmentAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.decommitment.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn MerkleVerifier(comptime H: type) type {
    comptime vcs_merkle_hasher.assertMerkleHasher(H);
    return struct {
        root: H.Hash,
        column_log_sizes: []u32,

        const Self = @This();
        const Pair = struct {
            idx: usize,
            hash: H.Hash,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            root: H.Hash,
            column_log_sizes: []const u32,
        ) !Self {
            return .{
                .root = root,
                .column_log_sizes = try allocator.dupe(u32, column_log_sizes),
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.column_log_sizes);
            self.* = undefined;
        }

        pub fn verify(
            self: Self,
            allocator: std.mem.Allocator,
            queries_per_log_size: []const LogSizeQueries,
            queried_values: []const M31,
            decommitment: MerkleDecommitment(H),
        ) (std.mem.Allocator.Error || MerkleVerificationError)!void {
            const max_log_size_opt = maxLogSize(self.column_log_sizes);
            if (max_log_size_opt == null) return;
            const max_log_size = max_log_size_opt.?;

            var queried_at: usize = 0;
            var hash_witness_at: usize = 0;
            var column_witness_at: usize = 0;

            var last_layer_hashes = try allocator.alloc(Pair, 0);
            defer allocator.free(last_layer_hashes);

            var layer_log_size: i64 = @intCast(max_log_size);
            while (layer_log_size >= 0) : (layer_log_size -= 1) {
                const layer_size_u32: u32 = @intCast(layer_log_size);
                const n_columns_in_layer = countColumnsAtLogSize(self.column_log_sizes, layer_size_u32);

                var layer_total_queries = std.ArrayList(Pair).empty;
                defer layer_total_queries.deinit(allocator);

                const layer_queries = queriesForLogSize(queries_per_log_size, layer_size_u32);

                const prev_queries = try allocator.alloc(usize, last_layer_hashes.len);
                defer allocator.free(prev_queries);
                for (last_layer_hashes, 0..) |pair, i| prev_queries[i] = pair.idx;

                var prev_queries_at: usize = 0;
                var prev_hashes_at: usize = 0;
                var layer_queries_at: usize = 0;

                while (vcs_utils.nextDecommitmentNode(
                    prev_queries,
                    prev_queries_at,
                    layer_queries,
                    layer_queries_at,
                )) |node_index| {
                    while (prev_queries_at < prev_queries.len and
                        (prev_queries[prev_queries_at] / 2) == node_index)
                    {
                        prev_queries_at += 1;
                    }

                    var has_children = false;
                    var left_hash: H.Hash = undefined;
                    var right_hash: H.Hash = undefined;
                    if (last_layer_hashes.len > 0) {
                        const left_index = node_index * 2;
                        const right_index = left_index + 1;

                        if (prev_hashes_at < last_layer_hashes.len and
                            last_layer_hashes[prev_hashes_at].idx == left_index)
                        {
                            left_hash = last_layer_hashes[prev_hashes_at].hash;
                            prev_hashes_at += 1;
                        } else {
                            if (hash_witness_at >= decommitment.hash_witness.len) {
                                return MerkleVerificationError.WitnessTooShort;
                            }
                            left_hash = decommitment.hash_witness[hash_witness_at];
                            hash_witness_at += 1;
                        }

                        if (prev_hashes_at < last_layer_hashes.len and
                            last_layer_hashes[prev_hashes_at].idx == right_index)
                        {
                            right_hash = last_layer_hashes[prev_hashes_at].hash;
                            prev_hashes_at += 1;
                        } else {
                            if (hash_witness_at >= decommitment.hash_witness.len) {
                                return MerkleVerificationError.WitnessTooShort;
                            }
                            right_hash = decommitment.hash_witness[hash_witness_at];
                            hash_witness_at += 1;
                        }
                        has_children = true;
                    }

                    const is_queried_node = layer_queries_at < layer_queries.len and
                        layer_queries[layer_queries_at] == node_index;
                    if (is_queried_node) {
                        layer_queries_at += 1;
                    }

                    const node_values = try allocator.alloc(M31, n_columns_in_layer);
                    defer allocator.free(node_values);
                    if (is_queried_node) {
                        if (queried_at + n_columns_in_layer > queried_values.len) {
                            return MerkleVerificationError.TooFewQueriedValues;
                        }
                        @memcpy(
                            node_values,
                            queried_values[queried_at .. queried_at + n_columns_in_layer],
                        );
                        queried_at += n_columns_in_layer;
                    } else {
                        if (column_witness_at + n_columns_in_layer > decommitment.column_witness.len) {
                            return MerkleVerificationError.WitnessTooShort;
                        }
                        @memcpy(
                            node_values,
                            decommitment.column_witness[column_witness_at .. column_witness_at + n_columns_in_layer],
                        );
                        column_witness_at += n_columns_in_layer;
                    }

                    try layer_total_queries.append(allocator, .{
                        .idx = node_index,
                        .hash = H.hashNode(
                            if (has_children)
                                .{ .left = left_hash, .right = right_hash }
                            else
                                null,
                            node_values,
                        ),
                    });
                }

                const next_last_layer = try layer_total_queries.toOwnedSlice(allocator);
                allocator.free(last_layer_hashes);
                last_layer_hashes = next_last_layer;
            }

            if (hash_witness_at != decommitment.hash_witness.len) {
                return MerkleVerificationError.WitnessTooLong;
            }
            if (column_witness_at != decommitment.column_witness.len) {
                return MerkleVerificationError.WitnessTooLong;
            }
            if (queried_at != queried_values.len) {
                return MerkleVerificationError.TooManyQueriedValues;
            }
            if (last_layer_hashes.len != 1) {
                return MerkleVerificationError.RootMismatch;
            }
            if (!vcs_hash.eql(last_layer_hashes[0].hash, self.root)) {
                return MerkleVerificationError.RootMismatch;
            }
        }
    };
}

fn countColumnsAtLogSize(column_log_sizes: []const u32, log_size: u32) usize {
    var count: usize = 0;
    for (column_log_sizes) |size| {
        if (size == log_size) count += 1;
    }
    return count;
}

fn queriesForLogSize(queries_per_log_size: []const LogSizeQueries, log_size: u32) []const usize {
    for (queries_per_log_size) |entry| {
        if (entry.log_size == log_size) return entry.queries;
    }
    return &[_]usize{};
}

fn maxLogSize(values: []const u32) ?u32 {
    if (values.len == 0) return null;
    var max_value = values[0];
    for (values[1..]) |value| max_value = @max(max_value, value);
    return max_value;
}

test "vcs verifier: verifies simple decommitment" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    const Verifier = MerkleVerifier(Hasher);
    const Decommitment = MerkleDecommitment(Hasher);
    const alloc = std.testing.allocator;

    // Two columns of size 4 (log_size=2), one value per node from each column.
    const rows = [_][2]M31{
        .{ M31.fromCanonical(9), M31.fromCanonical(19) },
        .{ M31.fromCanonical(10), M31.fromCanonical(20) },
        .{ M31.fromCanonical(29), M31.fromCanonical(39) },
        .{ M31.fromCanonical(30), M31.fromCanonical(40) },
    };
    var leaf_hashes: [4]Hasher.Hash = undefined;
    for (rows, 0..) |row, i| {
        leaf_hashes[i] = Hasher.hashNode(null, row[0..]);
    }
    const parent0 = Hasher.hashNode(.{ .left = leaf_hashes[0], .right = leaf_hashes[1] }, &[_]M31{});
    const parent1 = Hasher.hashNode(.{ .left = leaf_hashes[2], .right = leaf_hashes[3] }, &[_]M31{});
    const root = Hasher.hashNode(.{ .left = parent0, .right = parent1 }, &[_]M31{});

    var verifier = try Verifier.init(alloc, root, &[_]u32{ 2, 2 });
    defer verifier.deinit(alloc);

    const queries = [_]LogSizeQueries{
        .{ .log_size = 2, .queries = &[_]usize{ 1, 3 } },
    };
    const queried_values = [_]M31{
        rows[1][0], rows[1][1],
        rows[3][0], rows[3][1],
    };

    var decommitment = Decommitment{
        .hash_witness = try alloc.dupe(Hasher.Hash, &[_]Hasher.Hash{
            leaf_hashes[0],
            leaf_hashes[2],
        }),
        .column_witness = try alloc.alloc(M31, 0),
    };
    defer decommitment.deinit(alloc);

    try verifier.verify(alloc, queries[0..], queried_values[0..], decommitment);
}

test "vcs verifier: detects root mismatch" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    const Verifier = MerkleVerifier(Hasher);
    const Decommitment = MerkleDecommitment(Hasher);
    const alloc = std.testing.allocator;

    var verifier = try Verifier.init(alloc, [_]u8{7} ** 32, &[_]u32{1});
    defer verifier.deinit(alloc);

    var decommitment = Decommitment{
        .hash_witness = try alloc.alloc(Hasher.Hash, 0),
        .column_witness = try alloc.alloc(M31, 0),
    };
    defer decommitment.deinit(alloc);

    try std.testing.expectError(
        MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            &[_]LogSizeQueries{},
            &[_]M31{},
            decommitment,
        ),
    );
}
