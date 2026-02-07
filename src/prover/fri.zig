const std = @import("std");
const core_fri = @import("../core/fri.zig");
const m31 = @import("../core/fields/m31.zig");
const qm31 = @import("../core/fields/qm31.zig");
const vcs_lifted_verifier = @import("../core/vcs_lifted/verifier.zig");
const secure_column = @import("secure_column.zig");
const vcs_lifted_prover = @import("vcs_lifted/prover.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const FriDecommitError = error{
    QueryOutOfRange,
    FoldStepTooLarge,
};

pub const ValueEntry = struct {
    position: usize,
    value: QM31,
};

pub const DecommitmentPositionsResult = struct {
    decommitment_positions: []usize,
    witness_evals: []QM31,
    value_map: []ValueEntry,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        allocator.free(self.decommitment_positions);
        allocator.free(self.witness_evals);
        allocator.free(self.value_map);
        self.* = undefined;
    }
};

pub fn LayerDecommitResult(comptime H: type) type {
    return struct {
        decommitment_positions: []usize,
        proof: core_fri.FriLayerProof(H),
        value_map: []ValueEntry,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.decommitment_positions);
            self.proof.deinit(allocator);
            allocator.free(self.value_map);
            self.* = undefined;
        }
    };
}

/// Produces an extended FRI layer proof (proof + aux) for one layer decommitment.
pub fn decommitLayerExtended(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!core_fri.ExtendedFriLayerProof(H) {
    const column_values = try column.toVec(allocator);
    defer allocator.free(column_values);

    const helper = try computeDecommitmentPositionsAndWitnessEvals(
        allocator,
        column_values,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    const IndexedValue = core_fri.FriLayerProofAux(H).IndexedValue;
    const indexed_values = try allocator.alloc(IndexedValue, helper.value_map.len);
    errdefer allocator.free(indexed_values);
    for (helper.value_map, 0..) |entry, i| {
        indexed_values[i] = .{
            .index = entry.position,
            .value = entry.value,
        };
    }
    const all_values = try allocator.alloc([]IndexedValue, 1);
    errdefer {
        allocator.free(indexed_values);
        allocator.free(all_values);
    }
    all_values[0] = indexed_values;

    const column_refs = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    const merkle_decommit = try merkle_tree.decommit(
        allocator,
        helper.decommitment_positions,
        column_refs[0..],
    );
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
    }

    allocator.free(helper.decommitment_positions);
    allocator.free(helper.value_map);
    return .{
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .aux = .{
            .all_values = all_values,
            .decommitment = merkle_decommit.decommitment.aux,
        },
    };
}

/// Returns Merkle decommitment positions and witness evals needed for one FRI layer decommitment.
///
/// `query_positions` are expected in sorted ascending order.
pub fn computeDecommitmentPositionsAndWitnessEvals(
    allocator: std.mem.Allocator,
    column: []const QM31,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!DecommitmentPositionsResult {
    if (fold_step >= @bitSizeOf(usize)) return FriDecommitError.FoldStepTooLarge;

    var decommitment_positions = std.ArrayList(usize).init(allocator);
    defer decommitment_positions.deinit();
    var witness_evals = std.ArrayList(QM31).init(allocator);
    defer witness_evals.deinit();
    var value_map = std.ArrayList(ValueEntry).init(allocator);
    defer value_map.deinit();

    const subset_len = @as(usize, 1) << @intCast(fold_step);

    var subset_start_idx: usize = 0;
    while (subset_start_idx < query_positions.len) {
        const subset_key = query_positions[subset_start_idx] >> @intCast(fold_step);
        var subset_end_idx = subset_start_idx + 1;
        while (subset_end_idx < query_positions.len and
            (query_positions[subset_end_idx] >> @intCast(fold_step)) == subset_key)
        {
            subset_end_idx += 1;
        }

        const subset_queries = query_positions[subset_start_idx..subset_end_idx];
        const subset_start = subset_key << @intCast(fold_step);
        var subset_query_at: usize = 0;

        var position = subset_start;
        while (position < subset_start + subset_len) : (position += 1) {
            if (position >= column.len) return FriDecommitError.QueryOutOfRange;

            try decommitment_positions.append(position);
            const eval = column[position];
            try value_map.append(.{
                .position = position,
                .value = eval,
            });

            if (subset_query_at < subset_queries.len and subset_queries[subset_query_at] == position) {
                subset_query_at += 1;
            } else {
                try witness_evals.append(eval);
            }
        }

        subset_start_idx = subset_end_idx;
    }

    return .{
        .decommitment_positions = try decommitment_positions.toOwnedSlice(),
        .witness_evals = try witness_evals.toOwnedSlice(),
        .value_map = try value_map.toOwnedSlice(),
    };
}

/// Produces a FRI layer decommitment proof for `query_positions`.
pub fn decommitLayer(
    comptime H: type,
    allocator: std.mem.Allocator,
    merkle_tree: vcs_lifted_prover.MerkleProverLifted(H),
    column: secure_column.SecureColumnByCoords,
    query_positions: []const usize,
    fold_step: u32,
) (std.mem.Allocator.Error || FriDecommitError)!LayerDecommitResult(H) {
    const column_values = try column.toVec(allocator);
    defer allocator.free(column_values);

    const helper = try computeDecommitmentPositionsAndWitnessEvals(
        allocator,
        column_values,
        query_positions,
        fold_step,
    );
    errdefer {
        allocator.free(helper.decommitment_positions);
        allocator.free(helper.witness_evals);
        allocator.free(helper.value_map);
    }

    const column_refs = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle_decommit = try merkle_tree.decommit(
        allocator,
        helper.decommitment_positions,
        column_refs[0..],
    );
    defer {
        for (merkle_decommit.queried_values) |col| allocator.free(col);
        allocator.free(merkle_decommit.queried_values);
        merkle_decommit.decommitment.aux.deinit(allocator);
    }

    return .{
        .decommitment_positions = helper.decommitment_positions,
        .proof = .{
            .fri_witness = helper.witness_evals,
            .decommitment = merkle_decommit.decommitment.decommitment,
            .commitment = merkle_tree.root(),
        },
        .value_map = helper.value_map,
    };
}

test "prover fri: decommitment positions and witness evals" {
    const alloc = std.testing.allocator;

    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
        QM31.fromBase(.fromCanonical(5)),
        QM31.fromBase(.fromCanonical(6)),
        QM31.fromBase(.fromCanonical(7)),
        QM31.fromBase(.fromCanonical(8)),
    };
    const queries = [_]usize{ 1, 3, 6 };

    var result = try computeDecommitmentPositionsAndWitnessEvals(
        alloc,
        column[0..],
        queries[0..],
        1,
    );
    defer result.deinit(alloc);

    try std.testing.expectEqualSlices(usize, &[_]usize{ 0, 1, 2, 3, 6, 7 }, result.decommitment_positions);
    try std.testing.expectEqual(@as(usize, 3), result.witness_evals.len);
    try std.testing.expect(result.witness_evals[0].eql(column[0]));
    try std.testing.expect(result.witness_evals[1].eql(column[2]));
    try std.testing.expect(result.witness_evals[2].eql(column[7]));

    try std.testing.expectEqual(@as(usize, 6), result.value_map.len);
    for (result.value_map, 0..) |entry, i| {
        try std.testing.expectEqual(result.decommitment_positions[i], entry.position);
        try std.testing.expect(entry.value.eql(column[entry.position]));
    }
}

test "prover fri: query out of range fails" {
    const column = [_]QM31{
        QM31.fromBase(.fromCanonical(1)),
        QM31.fromBase(.fromCanonical(2)),
        QM31.fromBase(.fromCanonical(3)),
        QM31.fromBase(.fromCanonical(4)),
    };
    const queries = [_]usize{7};
    try std.testing.expectError(
        FriDecommitError.QueryOutOfRange,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            0,
        ),
    );
}

test "prover fri: fold step too large fails" {
    const column = [_]QM31{QM31.fromBase(.fromCanonical(1))};
    const queries = [_]usize{0};
    try std.testing.expectError(
        FriDecommitError.FoldStepTooLarge,
        computeDecommitmentPositionsAndWitnessEvals(
            std.testing.allocator,
            column[0..],
            queries[0..],
            @bitSizeOf(usize),
        ),
    );
}

test "prover fri: layer decommit extended contains proof and aux values" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{1};
    var extended = try decommitLayerExtended(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer extended.deinit(alloc);

    try std.testing.expect(std.mem.eql(
        u8,
        std.mem.asBytes(&extended.proof.commitment),
        std.mem.asBytes(&merkle.root()),
    ));
    try std.testing.expectEqual(@as(usize, 1), extended.aux.all_values.len);
    try std.testing.expectEqual(@as(usize, 2), extended.aux.all_values[0].len);
    try std.testing.expectEqual(@as(usize, 0), extended.aux.all_values[0][0].index);
    try std.testing.expect(extended.aux.all_values[0][0].value.eql(values[0]));
    try std.testing.expectEqual(@as(usize, 1), extended.aux.all_values[0][1].index);
    try std.testing.expect(extended.aux.all_values[0][1].value.eql(values[1]));
}

test "prover fri: layer decommit extended query out of range fails" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{7};
    try std.testing.expectError(
        FriDecommitError.QueryOutOfRange,
        decommitLayerExtended(
            Hasher,
            alloc,
            merkle,
            column,
            query_positions[0..],
            1,
        ),
    );
}

test "prover fri: layer decommit verifies with lifted merkle verifier" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const LiftedVerifier = vcs_lifted_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
        QM31.fromU32Unchecked(25, 26, 27, 28),
        QM31.fromU32Unchecked(29, 30, 31, 32),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{ 1, 3, 6 };
    var decommit = try decommitLayer(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer decommit.deinit(alloc);

    const queried_values = try alloc.alloc([]const M31, qm31.SECURE_EXTENSION_DEGREE);
    defer alloc.free(queried_values);
    const queried_values_owned = try alloc.alloc([]M31, qm31.SECURE_EXTENSION_DEGREE);
    defer {
        for (queried_values_owned) |col_vals| alloc.free(col_vals);
        alloc.free(queried_values_owned);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        queried_values_owned[coord] = try alloc.alloc(M31, decommit.value_map.len);
        for (decommit.value_map, 0..) |entry, i| {
            const coords = entry.value.toM31Array();
            queried_values_owned[coord][i] = coords[coord];
        }
        queried_values[coord] = queried_values_owned[coord];
    }

    const log_size = @as(u32, @intCast(std.math.log2_int(usize, values.len)));
    const repeated_sizes = [_]u32{ log_size, log_size, log_size, log_size };
    var verifier = try LiftedVerifier.init(alloc, merkle.root(), repeated_sizes[0..]);
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        decommit.decommitment_positions,
        queried_values,
        decommit.proof.decommitment,
    );
}

test "prover fri: layer decommit corrupted witness fails" {
    const Hasher = @import("../core/vcs_lifted/blake2_merkle.zig").Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const LiftedVerifier = vcs_lifted_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    const coord_columns = [_][]const M31{
        column.columns[0],
        column.columns[1],
        column.columns[2],
        column.columns[3],
    };
    var merkle = try LiftedProver.commit(alloc, coord_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{1};
    var decommit = try decommitLayer(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        1,
    );
    defer decommit.deinit(alloc);

    decommit.proof.decommitment.hash_witness[0][0] ^= 1;

    const queried_values = try alloc.alloc([]const M31, qm31.SECURE_EXTENSION_DEGREE);
    defer alloc.free(queried_values);
    const queried_values_owned = try alloc.alloc([]M31, qm31.SECURE_EXTENSION_DEGREE);
    defer {
        for (queried_values_owned) |col_vals| alloc.free(col_vals);
        alloc.free(queried_values_owned);
    }

    for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
        queried_values_owned[coord] = try alloc.alloc(M31, decommit.value_map.len);
        for (decommit.value_map, 0..) |entry, i| {
            const coords = entry.value.toM31Array();
            queried_values_owned[coord][i] = coords[coord];
        }
        queried_values[coord] = queried_values_owned[coord];
    }

    const log_size = @as(u32, @intCast(std.math.log2_int(usize, values.len)));
    const repeated_sizes = [_]u32{ log_size, log_size, log_size, log_size };
    var verifier = try LiftedVerifier.init(alloc, merkle.root(), repeated_sizes[0..]);
    defer verifier.deinit(alloc);

    try std.testing.expectError(
        vcs_lifted_verifier.MerkleVerificationError.RootMismatch,
        verifier.verify(
            alloc,
            decommit.decommitment_positions,
            queried_values,
            decommit.proof.decommitment,
        ),
    );
}
