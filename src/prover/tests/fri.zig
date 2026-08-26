//! Backend-independent FRI decommitment tests.

const std = @import("std");
const fri = @import("stwo_prover_engine").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const secure_column = @import("stwo_prover_engine").secure_column;
const vcs_lifted_prover = @import("stwo_prover_engine").vcs_lifted.prover;
const vcs_lifted_verifier = @import("stwo_core").vcs_lifted.verifier;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FriDecommitError = fri.FriDecommitError;
const computeDecommitmentPositionsAndWitnessEvals = fri.computeDecommitmentPositionsAndWitnessEvals;
const decommitLayer = fri.decommitLayer;
const decommitLayerExtended = fri.decommitLayerExtended;

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
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
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

test "prover fri: four-fold layer commits and decommits packed STWO leaves" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const LiftedProver = vcs_lifted_prover.MerkleProverLifted(Hasher);
    const LiftedVerifier = vcs_lifted_verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;

    var values: [16]QM31 = undefined;
    for (&values, 0..) |*value, i| {
        const base: u32 = @intCast(i * qm31.SECURE_EXTENSION_DEGREE + 1);
        value.* = QM31.fromU32Unchecked(base, base + 1, base + 2, base + 3);
    }
    var column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer column.deinit(alloc);

    var packed_storage: [16][4]M31 = undefined;
    for (0..4) |leaf| {
        inline for (0..4) |offset| {
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                packed_storage[offset * qm31.SECURE_EXTENSION_DEGREE + coordinate][leaf] =
                    column.columns[coordinate][leaf * 4 + offset];
            }
        }
    }
    var packed_columns: [16][]const M31 = undefined;
    for (&packed_columns, &packed_storage) |*out, *storage| out.* = storage[0..];

    var merkle = try LiftedProver.commit(alloc, packed_columns[0..]);
    defer merkle.deinit(alloc);

    const query_positions = [_]usize{ 1, 14 };
    var extended = try decommitLayerExtended(
        Hasher,
        alloc,
        merkle,
        column,
        query_positions[0..],
        4,
    );
    defer extended.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 14), extended.proof.fri_witness.len);
    try std.testing.expectEqual(@as(usize, 16), extended.aux.all_values[0].len);
    const packed_positions = [_]usize{ 0, 1, 2, 3 };
    const repeated_sizes = [_]u32{2} ** 16;
    var verifier = try LiftedVerifier.init(alloc, merkle.root(), repeated_sizes[0..]);
    defer verifier.deinit(alloc);
    try verifier.verify(
        alloc,
        packed_positions[0..],
        packed_columns[0..],
        extended.proof.decommitment,
    );
}

test "prover fri: layer decommit extended query out of range fails" {
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
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
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
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
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
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
