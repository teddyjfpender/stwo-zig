//! Lifted Merkle protocol and compatibility tests.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const vcs_lifted_verifier = @import("stwo_core").vcs_lifted.verifier;
const prover_mod = @import("stwo_prover_engine").vcs_lifted.prover;

const M31 = m31.M31;
const MerkleProverLifted = prover_mod.MerkleProverLifted;

test "prover vcs_lifted: decommit and verify roundtrip" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("stwo_core").vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
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

    const query_positions = [_]usize{ 1, 6 };
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
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Prover = MerkleProverLifted(Hasher);
    const Verifier = @import("stwo_core").vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
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
    const LiftedHasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MixedHasher = @import("stwo_core").vcs.blake2_merkle.Blake2sMerkleHasher;
    const LiftedProver = MerkleProverLifted(LiftedHasher);
    const MixedProver = @import("stwo_prover_engine").vcs.prover.MerkleProver(MixedHasher);
    const alloc = std.testing.allocator;

    const no_columns = [_][]const M31{};
    var lifted = try LiftedProver.commit(alloc, no_columns[0..]);
    defer lifted.deinit(alloc);
    var mixed = try MixedProver.commit(alloc, no_columns[0..]);
    defer mixed.deinit(alloc);

    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&lifted.root()), std.mem.asBytes(&mixed.root())));
}

test "prover vcs_lifted: packed leaf hashing matches legacy per-value path" {
    const lifted_blake2 = @import("stwo_core").vcs_lifted.blake2_merkle;
    const BaseHasher = lifted_blake2.Blake2sMerkleHasher;
    const PackedProver = MerkleProverLifted(BaseHasher);
    const LegacyLeafHasher = struct {
        inner: BaseHasher,
        pub const Hash = BaseHasher.Hash;
        pub const NodeSeed = BaseHasher.NodeSeed;

        pub fn defaultWithInitialState() @This() {
            return .{ .inner = BaseHasher.defaultWithInitialState() };
        }

        pub fn hashChildren(children: struct { left: Hash, right: Hash }) Hash {
            return BaseHasher.hashChildren(.{
                .left = children.left,
                .right = children.right,
            });
        }

        pub fn nodeSeed() NodeSeed {
            return BaseHasher.nodeSeed();
        }

        pub fn hashChildrenWithSeed(seed: NodeSeed, children: struct { left: Hash, right: Hash }) Hash {
            return BaseHasher.hashChildrenWithSeed(seed, .{
                .left = children.left,
                .right = children.right,
            });
        }

        pub fn updateLeaf(self: *@This(), column_values: []const M31) void {
            self.inner.updateLeaf(column_values);
        }

        pub fn finalize(self: *@This()) Hash {
            return self.inner.finalize();
        }
    };
    const LegacyProver = MerkleProverLifted(LegacyLeafHasher);
    const alloc = std.testing.allocator;
    const large_column_count: usize = 258;
    const small_column_count: usize = 2;
    const total_columns = large_column_count + small_column_count;
    const large_len: usize = 1 << 9;
    const small_len: usize = 1 << 8;

    const columns_storage = try alloc.alloc([]M31, total_columns);
    defer {
        for (columns_storage) |column| alloc.free(column);
        alloc.free(columns_storage);
    }

    const columns = try alloc.alloc([]const M31, total_columns);
    defer alloc.free(columns);

    for (0..large_column_count) |col_idx| {
        const values = try alloc.alloc(M31, large_len);
        columns_storage[col_idx] = values;
        columns[col_idx] = values;
        for (values, 0..) |*value, row_idx| {
            const seed = ((@as(u64, @intCast(col_idx + 1)) * 1009) +
                (@as(u64, @intCast(row_idx + 3)) * 37) +
                @as(u64, @intCast((col_idx ^ row_idx) + 11)));
            value.* = M31.fromU64(seed);
        }
    }
    for (0..small_column_count) |offset| {
        const col_idx = large_column_count + offset;
        const values = try alloc.alloc(M31, small_len);
        columns_storage[col_idx] = values;
        columns[col_idx] = values;
        for (values, 0..) |*value, row_idx| {
            const seed = ((@as(u64, @intCast(col_idx + 5)) * 1223) +
                (@as(u64, @intCast(row_idx + 7)) * 19) +
                @as(u64, @intCast((col_idx * 3) + row_idx)));
            value.* = M31.fromU64(seed);
        }
    }

    var packed_prover = try PackedProver.commit(alloc, columns);
    defer packed_prover.deinit(alloc);
    var legacy = try LegacyProver.commit(alloc, columns);
    defer legacy.deinit(alloc);

    const packed_root = packed_prover.root();
    const legacy_root = legacy.root();
    try std.testing.expectEqualSlices(u8, packed_root[0..], legacy_root[0..]);

    const query_positions = [_]usize{ 3, 255, 510 };
    var packed_decommitment = try packed_prover.decommit(alloc, query_positions[0..], columns);
    defer packed_decommitment.deinit(alloc);
    var legacy_decommitment = try legacy.decommit(alloc, query_positions[0..], columns);
    defer legacy_decommitment.deinit(alloc);

    try std.testing.expectEqual(packed_decommitment.queried_values.len, legacy_decommitment.queried_values.len);
    for (packed_decommitment.queried_values, legacy_decommitment.queried_values) |packed_column, legacy_column| {
        try std.testing.expectEqual(packed_column.len, legacy_column.len);
        for (packed_column, legacy_column) |packed_value, legacy_value| {
            try std.testing.expect(packed_value.eql(legacy_value));
        }
    }

    const packed_hash_witness = packed_decommitment.decommitment.decommitment.hash_witness;
    const legacy_hash_witness = legacy_decommitment.decommitment.decommitment.hash_witness;
    try std.testing.expectEqual(packed_hash_witness.len, legacy_hash_witness.len);
    for (packed_hash_witness, legacy_hash_witness) |packed_hash, legacy_hash| {
        try std.testing.expectEqualSlices(u8, packed_hash[0..], legacy_hash[0..]);
    }

    const packed_layers = packed_decommitment.decommitment.aux.all_node_values;
    const legacy_layers = legacy_decommitment.decommitment.aux.all_node_values;
    try std.testing.expectEqual(packed_layers.len, legacy_layers.len);
    for (packed_layers, legacy_layers) |packed_layer, legacy_layer| {
        try std.testing.expectEqual(packed_layer.len, legacy_layer.len);
        for (packed_layer, legacy_layer) |packed_node, legacy_node| {
            try std.testing.expectEqual(packed_node.index, legacy_node.index);
            try std.testing.expectEqualSlices(u8, packed_node.hash[0..], legacy_node.hash[0..]);
        }
    }
}
