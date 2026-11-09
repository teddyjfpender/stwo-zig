//! Proof sizing, line interpolation, and VCS oracle vectors.

const std = @import("std");
const circle_mod = @import("stwo_core").circle;
const fri_mod = @import("stwo_core").fri;
const pcs_mod = @import("stwo_core").pcs;
const proof_mod = @import("stwo_core").proof;
const quotients_mod = @import("stwo_core").pcs.quotients;
const line_mod = @import("stwo_core").poly.line;
const vcs_verifier_mod = @import("stwo_core").vcs.verifier;
const prover_line_mod = @import("stwo_prover_engine").line;
const vcs_prover_mod = @import("stwo_prover_engine").vcs.prover;
const vcs_lifted_prover_mod = @import("stwo_prover_engine").vcs_lifted.prover;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;
const fixtures = @import("fixtures.zig");

const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const parseVectors = fixtures.parseVectors;
const m31From = fixtures.m31From;
const qm31From = fixtures.qm31From;
const encodeQM31 = fixtures.encodeQM31;
const circleQM31From = fixtures.circleQM31From;
const decodeQueriedValuesTree = fixtures.decodeQueriedValuesTree;
const decodeQm31Tree = fixtures.decodeQm31Tree;
const decodeQm31Slice = fixtures.decodeQm31Slice;
const expectedVcsError = fixtures.expectedVcsError;
const expectedVcsLiftedError = fixtures.expectedVcsLiftedError;

test "field vectors: proof extract oods parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.proof_extract_oods.len > 0);
    for (parsed.value.proof_extract_oods) |v| {
        const composition_tree = try alloc.alloc([]QM31, v.composition_values.len);
        var initialized: usize = 0;
        errdefer {
            for (composition_tree[0..initialized]) |col| alloc.free(col);
            alloc.free(composition_tree);
        }
        for (v.composition_values, 0..) |value, i| {
            composition_tree[i] = try alloc.alloc(QM31, 1);
            composition_tree[i][0] = qm31From(value);
            initialized += 1;
        }

        const sampled_values = quotients_mod.TreeVec([][]QM31).initOwned(
            try alloc.dupe([][]QM31, &[_][][]QM31{composition_tree}),
        );
        var proof = proof_mod.StarkProof(Hasher){
            .commitment_scheme_proof = .{
                .config = pcs_mod.PcsConfig.default(),
                .commitments = quotients_mod.TreeVec(Hasher.Hash).initOwned(
                    try alloc.alloc(Hasher.Hash, 0),
                ),
                .sampled_values = sampled_values,
                .decommitments = quotients_mod.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(
                    try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), 0),
                ),
                .queried_values = quotients_mod.TreeVec([][]M31).initOwned(
                    try alloc.alloc([][]M31, 0),
                ),
                .proof_of_work = 0,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = try alloc.alloc(QM31, 0),
                        .decommitment = .{ .hash_witness = try alloc.alloc(Hasher.Hash, 0) },
                        .commitment = [_]u8{0} ** 32,
                    },
                    .inner_layers = try alloc.alloc(fri_mod.FriLayerProof(Hasher), 0),
                    .last_layer_poly = line_mod.LinePoly.initOwned(
                        try alloc.dupe(QM31, &[_]QM31{QM31.one()}),
                    ),
                },
            },
        };
        defer proof.deinit(alloc);

        const extracted = proof.extractCompositionOodsEval(
            circleQM31From(v.oods_point),
            v.composition_log_size,
        ) orelse unreachable;
        try std.testing.expectEqualSlices(u32, v.expected[0..], encodeQM31(extracted)[0..]);
    }
}

test "field vectors: proof size breakdown parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const vcs_verifier = @import("stwo_core").vcs_lifted.verifier;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.proof_sizes.len > 0);
    for (parsed.value.proof_sizes) |v| {
        var sampled_values = try decodeQm31Tree(alloc, v.sampled_values);
        var queried_values = try decodeQueriedValuesTree(alloc, v.queried_values);
        var sampled_values_moved = false;
        var queried_values_moved = false;
        defer if (!sampled_values_moved) sampled_values.deinitDeep(alloc);
        defer if (!queried_values_moved) queried_values.deinitDeep(alloc);

        var commitments = pcs_mod.TreeVec(Hasher.Hash).initOwned(
            try alloc.dupe(Hasher.Hash, v.commitments),
        );
        var commitments_moved = false;
        defer if (!commitments_moved) commitments.deinit(alloc);

        const decommitments_vec = try alloc.alloc(vcs_verifier.MerkleDecommitmentLifted(Hasher), v.decommitments.len);
        errdefer alloc.free(decommitments_vec);
        var decommitments_initialized: usize = 0;
        errdefer {
            for (decommitments_vec[0..decommitments_initialized]) |*decommitment| decommitment.deinit(alloc);
        }
        for (v.decommitments, 0..) |witness, i| {
            decommitments_vec[i] = .{ .hash_witness = try alloc.dupe(Hasher.Hash, witness) };
            decommitments_initialized += 1;
        }
        var decommitments = pcs_mod.TreeVec(vcs_verifier.MerkleDecommitmentLifted(Hasher)).initOwned(decommitments_vec);
        var decommitments_moved = false;
        defer if (!decommitments_moved) {
            for (decommitments.items) |*decommitment| decommitment.deinit(alloc);
            decommitments.deinit(alloc);
        };

        const first_layer_witness = try decodeQm31Slice(alloc, v.first_layer_witness);
        errdefer alloc.free(first_layer_witness);
        const first_layer_decommitment = vcs_verifier.MerkleDecommitmentLifted(Hasher){
            .hash_witness = try alloc.dupe(Hasher.Hash, v.first_layer_decommitment),
        };
        errdefer {
            var tmp = first_layer_decommitment;
            tmp.deinit(alloc);
        }

        const inner_layers = try alloc.alloc(fri_mod.FriLayerProof(Hasher), v.inner_layers.len);
        errdefer alloc.free(inner_layers);
        var inner_layers_initialized: usize = 0;
        errdefer {
            for (inner_layers[0..inner_layers_initialized]) |*layer| layer.deinit(alloc);
        }
        for (v.inner_layers, 0..) |inner, i| {
            inner_layers[i] = .{
                .fri_witness = try decodeQm31Slice(alloc, inner.fri_witness),
                .decommitment = .{ .hash_witness = try alloc.dupe(Hasher.Hash, inner.decommitment) },
                .commitment = inner.commitment,
            };
            inner_layers_initialized += 1;
        }

        const last_layer_poly_coeffs = try decodeQm31Slice(alloc, v.last_layer_poly);
        errdefer alloc.free(last_layer_poly_coeffs);

        sampled_values_moved = true;
        queried_values_moved = true;
        commitments_moved = true;
        decommitments_moved = true;
        var proof = proof_mod.StarkProof(Hasher){
            .commitment_scheme_proof = .{
                .config = pcs_mod.PcsConfig.default(),
                .commitments = commitments,
                .sampled_values = sampled_values,
                .decommitments = decommitments,
                .queried_values = queried_values,
                .proof_of_work = v.proof_of_work,
                .fri_proof = .{
                    .first_layer = .{
                        .fri_witness = first_layer_witness,
                        .decommitment = first_layer_decommitment,
                        .commitment = v.first_layer_commitment,
                    },
                    .inner_layers = inner_layers,
                    .last_layer_poly = line_mod.LinePoly.initOwned(last_layer_poly_coeffs),
                },
            },
        };
        defer proof.deinit(alloc);

        const actual = proof.sizeBreakdownEstimate();
        try std.testing.expectEqual(v.expected_breakdown.oods_samples, actual.oods_samples);
        try std.testing.expectEqual(v.expected_breakdown.queries_values, actual.queries_values);
        try std.testing.expectEqual(v.expected_breakdown.fri_samples, actual.fri_samples);
        try std.testing.expectEqual(v.expected_breakdown.fri_decommitments, actual.fri_decommitments);
        try std.testing.expectEqual(v.expected_breakdown.trace_decommitments, actual.trace_decommitments);
    }
}

test "field vectors: prover line interpolation parity" {
    const alloc = std.testing.allocator;
    const LineEvaluation = prover_line_mod.LineEvaluation;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.meta.schema_version >= 1);
    try std.testing.expect(parsed.value.prover_line.len > 0);
    for (parsed.value.prover_line) |v| {
        const domain = try line_mod.LineDomain.init(circle_mod.Coset.halfOdds(v.line_log_size));

        const values = try alloc.alloc(QM31, v.values.len);
        for (v.values, 0..) |value, i| values[i] = qm31From(value);

        var eval = try LineEvaluation.initOwned(domain, values);
        var poly = try eval.interpolate(alloc);
        defer poly.deinit(alloc);

        const coeffs_bit_reversed = poly.coefficients();
        try std.testing.expectEqual(v.coeffs_bit_reversed.len, coeffs_bit_reversed.len);
        for (v.coeffs_bit_reversed, 0..) |expected, i| {
            try std.testing.expect(coeffs_bit_reversed[i].eql(qm31From(expected)));
        }

        const coeffs_ordered = poly.intoOrderedCoefficients();
        try std.testing.expectEqual(v.coeffs_ordered.len, coeffs_ordered.len);
        for (v.coeffs_ordered, 0..) |expected, i| {
            try std.testing.expect(coeffs_ordered[i].eql(qm31From(expected)));
        }

        if (v.values.len > 0) {
            const mutated_values = try alloc.alloc(QM31, v.values.len);
            for (v.values, 0..) |value, i| mutated_values[i] = qm31From(value);
            mutated_values[0] = mutated_values[0].add(QM31.one());

            var mutated_eval = try LineEvaluation.initOwned(domain, mutated_values);
            var mutated_poly = try mutated_eval.interpolate(alloc);
            defer mutated_poly.deinit(alloc);

            var differs = false;
            for (mutated_poly.coefficients(), 0..) |actual, i| {
                if (!actual.eql(qm31From(v.coeffs_bit_reversed[i]))) {
                    differs = true;
                    break;
                }
            }
            try std.testing.expect(differs);
        }
    }
}

test "field vectors: vcs verifier parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs.blake2_merkle.Blake2sMerkleHasher;
    const Verifier = vcs_verifier_mod.MerkleVerifier(Hasher);
    const Decommitment = vcs_verifier_mod.MerkleDecommitment(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_verifier.len > 0);
    for (parsed.value.vcs_verifier) |v| {
        var verifier = try Verifier.init(alloc, v.root, v.column_log_sizes);
        defer verifier.deinit(alloc);

        const queries = try alloc.alloc(vcs_verifier_mod.LogSizeQueries, v.queries_per_log_size.len);
        defer alloc.free(queries);
        for (v.queries_per_log_size, 0..) |entry, i| {
            queries[i] = .{
                .log_size = entry.log_size,
                .queries = entry.queries,
            };
        }

        const queried_values = try alloc.alloc(M31, v.queried_values.len);
        defer alloc.free(queried_values);
        for (v.queried_values, 0..) |value, i| queried_values[i] = m31From(value);

        var decommitment = Decommitment{
            .hash_witness = try alloc.dupe(Hasher.Hash, v.hash_witness),
            .column_witness = try alloc.alloc(M31, v.column_witness.len),
        };
        for (v.column_witness, 0..) |value, i| decommitment.column_witness[i] = m31From(value);
        defer decommitment.deinit(alloc);

        if (std.mem.eql(u8, v.expected, "ok")) {
            try verifier.verify(alloc, queries, queried_values, decommitment);
        } else {
            try std.testing.expectError(
                expectedVcsError(v.expected),
                verifier.verify(alloc, queries, queried_values, decommitment),
            );
        }
    }
}

test "field vectors: vcs prover parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs.blake2_merkle.Blake2sMerkleHasher;
    const Prover = vcs_prover_mod.MerkleProver(Hasher);
    const Verifier = vcs_verifier_mod.MerkleVerifier(Hasher);
    const LogSizeQueries = vcs_verifier_mod.LogSizeQueries;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_prover.len > 0);
    for (parsed.value.vcs_prover) |v| {
        const columns = try alloc.alloc([]const M31, v.columns.len);
        defer alloc.free(columns);

        const owned_columns = try alloc.alloc([]M31, v.columns.len);
        defer {
            for (owned_columns) |col| alloc.free(col);
            alloc.free(owned_columns);
        }

        for (v.columns, 0..) |column, i| {
            owned_columns[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| owned_columns[i][j] = m31From(value);
            columns[i] = owned_columns[i];
        }

        var prover = try Prover.commit(alloc, columns);
        defer prover.deinit(alloc);

        try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&prover.root()), std.mem.asBytes(&v.root)));

        const queries = try alloc.alloc(LogSizeQueries, v.queries_per_log_size.len);
        defer alloc.free(queries);
        for (v.queries_per_log_size, 0..) |entry, i| {
            queries[i] = .{
                .log_size = entry.log_size,
                .queries = entry.queries,
            };
        }

        var decommitment = try prover.decommit(alloc, queries, columns);
        defer decommitment.deinit(alloc);

        try std.testing.expectEqual(v.queried_values.len, decommitment.queried_values.len);
        for (v.queried_values, 0..) |value, i| {
            try std.testing.expect(m31From(value).eql(decommitment.queried_values[i]));
        }

        try std.testing.expectEqual(
            v.hash_witness.len,
            decommitment.decommitment.decommitment.hash_witness.len,
        );
        for (v.hash_witness, 0..) |hash, i| {
            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&hash),
                std.mem.asBytes(&decommitment.decommitment.decommitment.hash_witness[i]),
            ));
        }

        try std.testing.expectEqual(
            v.column_witness.len,
            decommitment.decommitment.decommitment.column_witness.len,
        );
        for (v.column_witness, 0..) |value, i| {
            try std.testing.expect(m31From(value).eql(
                decommitment.decommitment.decommitment.column_witness[i],
            ));
        }

        var verifier = try Verifier.init(alloc, prover.root(), v.column_log_sizes);
        defer verifier.deinit(alloc);
        try verifier.verify(
            alloc,
            queries,
            decommitment.queried_values,
            decommitment.decommitment.decommitment,
        );
    }
}

test "field vectors: vcs lifted verifier parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Verifier = @import("stwo_core").vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
    const Decommitment = @import("stwo_core").vcs_lifted.verifier.MerkleDecommitmentLifted(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.vcs_lifted_verifier.len > 0);
    for (parsed.value.vcs_lifted_verifier) |v| {
        var verifier = try Verifier.init(alloc, v.root, v.column_log_sizes);
        defer verifier.deinit(alloc);

        const queried_values = try alloc.alloc([]const M31, v.queried_values.len);
        defer alloc.free(queried_values);

        const queried_values_owned = try alloc.alloc([]M31, v.queried_values.len);
        defer {
            for (queried_values_owned) |col| alloc.free(col);
            alloc.free(queried_values_owned);
        }

        for (v.queried_values, 0..) |column, i| {
            queried_values_owned[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| queried_values_owned[i][j] = m31From(value);
            queried_values[i] = queried_values_owned[i];
        }

        var decommitment = Decommitment{
            .hash_witness = try alloc.dupe(Hasher.Hash, v.hash_witness),
        };
        defer decommitment.deinit(alloc);

        if (std.mem.eql(u8, v.expected, "ok")) {
            try verifier.verify(
                alloc,
                v.query_positions,
                queried_values,
                decommitment,
            );
        } else {
            try std.testing.expectError(
                expectedVcsLiftedError(v.expected),
                verifier.verify(
                    alloc,
                    v.query_positions,
                    queried_values,
                    decommitment,
                ),
            );
        }
    }
}

test "field vectors: vcs lifted prover parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Prover = vcs_lifted_prover_mod.MerkleProverLifted(Hasher);
    const Verifier = @import("stwo_core").vcs_lifted.verifier.MerkleVerifierLifted(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 64), Hasher.domainPrefixBytes());
    try std.testing.expect(parsed.value.vcs_lifted_prover.len > 0);
    for (parsed.value.vcs_lifted_prover) |v| {
        const columns = try alloc.alloc([]const M31, v.columns.len);
        defer alloc.free(columns);

        const owned_columns = try alloc.alloc([]M31, v.columns.len);
        defer {
            for (owned_columns) |col| alloc.free(col);
            alloc.free(owned_columns);
        }

        for (v.columns, 0..) |column, i| {
            owned_columns[i] = try alloc.alloc(M31, column.len);
            for (column, 0..) |value, j| owned_columns[i][j] = m31From(value);
            columns[i] = owned_columns[i];
        }

        var prover = try Prover.commit(alloc, columns);
        defer prover.deinit(alloc);

        try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&prover.root()), std.mem.asBytes(&v.root)));

        var decommitment = try prover.decommit(alloc, v.query_positions, columns);
        defer decommitment.deinit(alloc);

        try std.testing.expectEqual(v.queried_values.len, decommitment.queried_values.len);
        for (v.queried_values, 0..) |column, i| {
            try std.testing.expectEqual(column.len, decommitment.queried_values[i].len);
            for (column, 0..) |value, j| {
                try std.testing.expect(m31From(value).eql(decommitment.queried_values[i][j]));
            }
        }

        try std.testing.expectEqual(
            v.hash_witness.len,
            decommitment.decommitment.decommitment.hash_witness.len,
        );
        for (v.hash_witness, 0..) |hash, i| {
            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&hash),
                std.mem.asBytes(&decommitment.decommitment.decommitment.hash_witness[i]),
            ));
        }

        const queried_values = try alloc.alloc([]const M31, decommitment.queried_values.len);
        defer alloc.free(queried_values);
        for (decommitment.queried_values, 0..) |column, i| queried_values[i] = column;

        var verifier = try Verifier.init(alloc, prover.root(), v.column_log_sizes);
        defer verifier.deinit(alloc);
        try verifier.verify(
            alloc,
            v.query_positions,
            queried_values,
            decommitment.decommitment.decommitment,
        );
    }
}
