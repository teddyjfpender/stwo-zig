const std = @import("std");
const m31 = @import("../fields/m31.zig");
const vcs_hash = @import("../vcs/hash.zig");
const lifted_merkle_hasher = @import("merkle_hasher.zig");

const M31 = m31.M31;

pub const MerkleVerificationError = error{
    WitnessTooShort,
    WitnessTooLong,
    RootMismatch,
};

pub fn MerkleDecommitmentLifted(comptime H: type) type {
    return struct {
        hash_witness: []H.Hash,

        const Self = @This();

        pub fn empty(allocator: std.mem.Allocator) !Self {
            return .{ .hash_witness = try allocator.alloc(H.Hash, 0) };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.hash_witness);
            self.* = undefined;
        }
    };
}

pub fn MerkleDecommitmentLiftedAux(comptime H: type) type {
    return struct {
        all_node_values: [][]NodeValue,

        pub const NodeValue = struct {
            index: usize,
            hash: H.Hash,
        };

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.all_node_values) |layer_values| allocator.free(layer_values);
            allocator.free(self.all_node_values);
            self.* = undefined;
        }
    };
}

pub fn ExtendedMerkleDecommitmentLifted(comptime H: type) type {
    return struct {
        decommitment: MerkleDecommitmentLifted(H),
        aux: MerkleDecommitmentLiftedAux(H),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.decommitment.deinit(allocator);
            self.aux.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn MerkleVerifierLifted(comptime H: type) type {
    comptime lifted_merkle_hasher.assertMerkleHasherLifted(H);
    return struct {
        root: H.Hash,
        column_log_sizes: []u32,

        const Self = @This();
        const Decommitment = MerkleDecommitmentLifted(H);

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

        /// `queried_values` is indexed by column, then query index.
        pub fn verify(
            self: Self,
            allocator: std.mem.Allocator,
            query_positions: []const usize,
            queried_values: []const []const M31,
            decommitment: Decommitment,
        ) MerkleVerificationError!void {
            if (self.column_log_sizes.len == 0) return;

            // If duplicate queries appear, all columns should agree on their values.
            var i: usize = 1;
            while (i < query_positions.len) : (i += 1) {
                if (query_positions[i - 1] != query_positions[i]) continue;
                for (queried_values) |col| {
                    std.debug.assert(col[i - 1].eql(col[i]));
                }
            }

            // Sort columns by log size.
            const n_cols = queried_values.len;
            const col_indices = try allocator.alloc(usize, n_cols);
            defer allocator.free(col_indices);
            for (col_indices, 0..) |*idx, j| idx.* = j;
            std.sort.heap(usize, col_indices, self.column_log_sizes, lessByLogSize);

            // Deduplicate values per sorted column by query positions.
            var dedup_cols = try allocator.alloc([]M31, n_cols);
            defer {
                for (dedup_cols) |col| allocator.free(col);
                allocator.free(dedup_cols);
            }
            for (col_indices, 0..) |col_idx, j| {
                const col = queried_values[col_idx];
                var dedup = std.ArrayList(M31).init(allocator);
                defer dedup.deinit();
                var k: usize = 0;
                while (k < query_positions.len and k < col.len) : (k += 1) {
                    if (k == 0 or query_positions[k] != query_positions[k - 1]) {
                        try dedup.append(col[k]);
                    }
                }
                dedup_cols[j] = try dedup.toOwnedSlice();
            }

            const Pair = struct { idx: usize, hash: H.Hash };
            var prev_layer = std.ArrayList(Pair).init(allocator);
            defer prev_layer.deinit();

            var col_pos = try allocator.alloc(usize, n_cols);
            defer allocator.free(col_pos);
            @memset(col_pos, 0);

            for (query_positions) |pos| {
                var row = std.ArrayList(M31).init(allocator);
                defer row.deinit();
                for (dedup_cols, 0..) |col, col_i| {
                    if (col_pos[col_i] >= col.len) return MerkleVerificationError.WitnessTooShort;
                    try row.append(col[col_pos[col_i]]);
                    col_pos[col_i] += 1;
                }
                var hasher = H.defaultWithInitialState();
                hasher.updateLeaf(row.items);
                try prev_layer.append(.{ .idx = pos, .hash = hasher.finalize() });
            }

            // Verify all dedup values were consumed.
            for (dedup_cols, 0..) |col, col_i| {
                if (col_pos[col_i] != col.len) return MerkleVerificationError.WitnessTooLong;
            }

            var witness_idx: usize = 0;
            const max_log_size = maxLogSize(self.column_log_sizes);
            var layer: u32 = 0;
            while (layer < max_log_size) : (layer += 1) {
                var curr = std.ArrayList(Pair).init(allocator);
                defer curr.deinit();

                var p: usize = 0;
                while (p < prev_layer.items.len) {
                    const first = prev_layer.items[p];
                    var chunk_len: usize = 1;
                    var children: struct { left: H.Hash, right: H.Hash } = undefined;
                    if (p + 1 < prev_layer.items.len and (first.idx ^ 1) == prev_layer.items[p + 1].idx) {
                        const second = prev_layer.items[p + 1];
                        children = .{ .left = first.hash, .right = second.hash };
                        chunk_len = 2;
                    } else {
                        if (witness_idx >= decommitment.hash_witness.len) {
                            return MerkleVerificationError.WitnessTooShort;
                        }
                        const witness = decommitment.hash_witness[witness_idx];
                        witness_idx += 1;
                        children = if ((first.idx & 1) == 0)
                            .{ .left = first.hash, .right = witness }
                        else
                            .{ .left = witness, .right = first.hash };
                    }
                    try curr.append(.{
                        .idx = first.idx >> 1,
                        .hash = H.hashChildren(children),
                    });
                    p += chunk_len;
                }

                prev_layer.clearRetainingCapacity();
                try prev_layer.appendSlice(curr.items);
            }

            if (witness_idx != decommitment.hash_witness.len) {
                return MerkleVerificationError.WitnessTooLong;
            }
            if (prev_layer.items.len != 1) return MerkleVerificationError.RootMismatch;
            if (!vcs_hash.eql(prev_layer.items[0].hash, self.root)) {
                return MerkleVerificationError.RootMismatch;
            }
        }
    };
}

fn lessByLogSize(log_sizes: []const u32, lhs: usize, rhs: usize) bool {
    return log_sizes[lhs] < log_sizes[rhs];
}

fn maxLogSize(values: []const u32) u32 {
    var max_value: u32 = 0;
    for (values) |v| max_value = @max(max_value, v);
    return max_value;
}

test "vcs_lifted verifier: verifies simple proof" {
    const Hasher = @import("blake2_merkle.zig").Blake2sMerkleHasher;
    const Decommitment = MerkleDecommitmentLifted(Hasher);
    const Verifier = MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const query_positions = [_]usize{ 1, 3 };
    const queried_values = [_][]const M31{
        &[_]M31{ M31.fromCanonical(10), M31.fromCanonical(30) },
        &[_]M31{ M31.fromCanonical(20), M31.fromCanonical(40) },
    };

    // Build leaf hashes.
    var row0 = [_]M31{ queried_values[0][0], queried_values[1][0] };
    var row1 = [_]M31{ queried_values[0][1], queried_values[1][1] };
    var h0s = Hasher.defaultWithInitialState();
    h0s.updateLeaf(row0[0..]);
    const h0 = h0s.finalize();
    var h1s = Hasher.defaultWithInitialState();
    h1s.updateLeaf(row1[0..]);
    const h1 = h1s.finalize();

    // Sibling witnesses for positions 1 and 3.
    var leaf0s = Hasher.defaultWithInitialState();
    leaf0s.updateLeaf(&[_]M31{ M31.fromCanonical(9), M31.fromCanonical(19) });
    const leaf0 = leaf0s.finalize();
    var leaf2s = Hasher.defaultWithInitialState();
    leaf2s.updateLeaf(&[_]M31{ M31.fromCanonical(29), M31.fromCanonical(39) });
    const leaf2 = leaf2s.finalize();

    const parent0 = Hasher.hashChildren(.{ .left = leaf0, .right = h0 });
    const parent1 = Hasher.hashChildren(.{ .left = leaf2, .right = h1 });
    const root = Hasher.hashChildren(.{ .left = parent0, .right = parent1 });

    var verifier = try Verifier.init(alloc, root, &[_]u32{ 2, 2 });
    defer verifier.deinit(alloc);

    var decommitment = Decommitment{ .hash_witness = try alloc.dupe(Hasher.Hash, &[_]Hasher.Hash{ leaf0, leaf2 }) };
    defer decommitment.deinit(alloc);

    try verifier.verify(alloc, query_positions[0..], queried_values[0..], decommitment);
}
