//! PCS quotient and FRI oracle vectors.

const std = @import("std");
const circle_mod = @import("stwo_core").circle;
const constraints_mod = @import("stwo_core").constraints;
const fri_mod = @import("stwo_core").fri;
const pcs_utils_mod = @import("stwo_core").pcs.utils;
const quotients_mod = @import("stwo_core").pcs.quotients;
const canonic_mod = @import("stwo_core").poly.circle.canonic;
const line_mod = @import("stwo_core").poly.line;
const utils_mod = @import("stwo_core").utils;
const prover_fri_mod = @import("stwo_prover_engine").fri;
const prover_secure_column_mod = @import("stwo_prover_engine").secure_column;
const vcs_lifted_prover_mod = @import("stwo_prover_engine").vcs_lifted.prover;
const m31_mod = @import("stwo_core").fields.m31;
const qm31_mod = @import("stwo_core").fields.qm31;
const fixtures = @import("fixtures.zig");

const CirclePointQM31 = circle_mod.CirclePointQM31;
const M31 = m31_mod.M31;
const QM31 = qm31_mod.QM31;
const SampleWithRandomness = quotients_mod.SampleWithRandomness;
const NumeratorData = quotients_mod.NumeratorData;
const ColumnSampleBatch = quotients_mod.ColumnSampleBatch;
const LineCoeffs = constraints_mod.LineCoeffs;
const parseVectors = fixtures.parseVectors;
const qm31From = fixtures.qm31From;
const encodeCM31 = fixtures.encodeCM31;
const encodeQM31 = fixtures.encodeQM31;
const circleQM31From = fixtures.circleQM31From;
const sampleWithRandomnessFrom = fixtures.sampleWithRandomnessFrom;
const decodeColumnLogSizes = fixtures.decodeColumnLogSizes;
const decodeSamplesTree = fixtures.decodeSamplesTree;
const splitPointSamplesTree = fixtures.splitPointSamplesTree;
const decodeQueriedValuesTree = fixtures.decodeQueriedValuesTree;
const expectedFriDecommitError = fixtures.expectedFriDecommitError;

test "field vectors: pcs quotients parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.pcs_quotients.len > 0);
    for (parsed.value.pcs_quotients) |v| {
        var column_log_sizes = try decodeColumnLogSizes(alloc, v.column_log_sizes);
        defer column_log_sizes.deinitDeep(alloc);
        var samples = try decodeSamplesTree(alloc, v.samples);
        defer samples.deinitDeep(alloc);
        var split_samples = try splitPointSamplesTree(alloc, samples);
        defer split_samples.deinit(alloc);
        var queried_values = try decodeQueriedValuesTree(alloc, v.queried_values);
        defer queried_values.deinitDeep(alloc);
        const random_coeff = qm31From(v.random_coeff);

        var samples_with_randomness = try quotients_mod.buildSamplesWithRandomnessAndPeriodicity(
            alloc,
            split_samples.points,
            split_samples.values,
            column_log_sizes,
            v.lifting_log_size,
            random_coeff,
        );
        defer samples_with_randomness.deinitDeep(alloc);

        try std.testing.expectEqual(v.samples_with_randomness.len, samples_with_randomness.items.len);
        for (v.samples_with_randomness, 0..) |expected_tree, tree_idx| {
            try std.testing.expectEqual(expected_tree.len, samples_with_randomness.items[tree_idx].len);
            for (expected_tree, 0..) |expected_col, col_idx| {
                try std.testing.expectEqual(expected_col.len, samples_with_randomness.items[tree_idx][col_idx].len);
                for (expected_col, 0..) |expected_sample, sample_idx| {
                    const actual = samples_with_randomness.items[tree_idx][col_idx][sample_idx];
                    const decoded_expected = sampleWithRandomnessFrom(expected_sample);
                    try std.testing.expect(actual.point.eql(decoded_expected.point));
                    try std.testing.expect(actual.value.eql(decoded_expected.value));
                    try std.testing.expect(actual.random_coeff.eql(decoded_expected.random_coeff));
                }
            }
        }

        var flat_samples = std.ArrayList([]const SampleWithRandomness).empty;
        defer flat_samples.deinit(alloc);
        for (samples_with_randomness.items) |tree| {
            for (tree) |col| try flat_samples.append(alloc, col);
        }

        const sample_batches = try ColumnSampleBatch.newVec(alloc, flat_samples.items);
        defer ColumnSampleBatch.deinitSlice(alloc, sample_batches);

        try std.testing.expectEqual(v.sample_batches.len, sample_batches.len);
        for (v.sample_batches, 0..) |expected_batch, batch_idx| {
            const actual_batch = sample_batches[batch_idx];
            try std.testing.expect(actual_batch.point.eql(circleQM31From(expected_batch.point)));
            try std.testing.expectEqual(expected_batch.cols_vals_randpows.len, actual_batch.cols_vals_randpows.len);
            for (expected_batch.cols_vals_randpows, 0..) |expected_num, num_idx| {
                const actual_num: NumeratorData = actual_batch.cols_vals_randpows[num_idx];
                try std.testing.expectEqual(expected_num.column_index, actual_num.column_index);
                try std.testing.expect(actual_num.sample_value.eql(qm31From(expected_num.sample_value)));
                try std.testing.expect(actual_num.random_coeff.eql(qm31From(expected_num.random_coeff)));
            }
        }

        var q_consts = try quotients_mod.quotientConstants(alloc, sample_batches);
        defer q_consts.deinit(alloc);

        try std.testing.expectEqual(v.line_coeffs.len, q_consts.line_coeffs.len);
        for (v.line_coeffs, 0..) |expected_batch_coeffs, batch_idx| {
            try std.testing.expectEqual(expected_batch_coeffs.len, q_consts.line_coeffs[batch_idx].len);
            for (expected_batch_coeffs, 0..) |expected_coeff, coeff_idx| {
                const actual: LineCoeffs = q_consts.line_coeffs[batch_idx][coeff_idx];
                try std.testing.expect(actual.a.eql(qm31From(expected_coeff.a)));
                try std.testing.expect(actual.b.eql(qm31From(expected_coeff.b)));
                try std.testing.expect(actual.c.eql(qm31From(expected_coeff.c)));
            }
        }

        var queried_values_flat = std.ArrayList([]const M31).empty;
        defer queried_values_flat.deinit(alloc);
        for (queried_values.items) |tree| {
            for (tree) |col| try queried_values_flat.append(alloc, col);
        }

        const row_values = try alloc.alloc(M31, queried_values_flat.items.len);
        defer alloc.free(row_values);
        const sample_points = try alloc.alloc(CirclePointQM31, sample_batches.len);
        defer alloc.free(sample_points);
        for (sample_batches, 0..) |batch, i| sample_points[i] = batch.point;

        const domain = canonic_mod.CanonicCoset.new(v.lifting_log_size).circleDomain();
        try std.testing.expectEqual(v.query_positions.len, v.denominator_inverses.len);
        try std.testing.expectEqual(v.query_positions.len, v.partial_numerators.len);
        try std.testing.expectEqual(v.query_positions.len, v.row_quotients.len);
        try std.testing.expectEqual(v.query_positions.len, v.fri_answers.len);

        for (v.query_positions, 0..) |position, row_idx| {
            for (queried_values_flat.items, 0..) |column, col_idx| {
                row_values[col_idx] = column[row_idx];
            }
            const domain_point = domain.at(utils_mod.bitReverseIndex(position, v.lifting_log_size));

            const den_inv = try quotients_mod.denominatorInverses(alloc, sample_points, domain_point);
            defer alloc.free(den_inv);
            try std.testing.expectEqual(v.denominator_inverses[row_idx].len, den_inv.len);
            for (v.denominator_inverses[row_idx], 0..) |expected_inv, i| {
                const encoded_inv = encodeCM31(den_inv[i]);
                try std.testing.expectEqualSlices(u32, expected_inv[0..], encoded_inv[0..]);
            }

            try std.testing.expectEqual(v.partial_numerators[row_idx].len, sample_batches.len);
            for (sample_batches, 0..) |batch, batch_idx| {
                const partial = try quotients_mod.accumulateRowPartialNumerators(
                    &batch,
                    row_values,
                    q_consts.line_coeffs[batch_idx],
                );
                try std.testing.expectEqualSlices(
                    u32,
                    v.partial_numerators[row_idx][batch_idx][0..],
                    encodeQM31(partial)[0..],
                );
            }

            const row_quot = try quotients_mod.accumulateRowQuotients(
                alloc,
                sample_batches,
                row_values,
                &q_consts,
                domain_point,
            );
            try std.testing.expectEqualSlices(u32, v.row_quotients[row_idx][0..], encodeQM31(row_quot)[0..]);
        }

        const fri_answers = try quotients_mod.friAnswers(
            alloc,
            column_log_sizes,
            split_samples.points,
            split_samples.values,
            random_coeff,
            v.query_positions,
            queried_values,
            v.lifting_log_size,
        );
        defer alloc.free(fri_answers);
        for (v.fri_answers, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(fri_answers[i])[0..]);
        }
    }
}

test "field vectors: pcs preprocessed query positions parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.pcs_preprocessed_queries.len > 0);
    for (parsed.value.pcs_preprocessed_queries) |v| {
        const actual = try pcs_utils_mod.preparePreprocessedQueryPositions(
            alloc,
            v.query_positions,
            v.max_log_size,
            v.pp_max_log_size,
        );
        defer alloc.free(actual);
        try std.testing.expectEqualSlices(usize, v.expected, actual);
    }
}

test "field vectors: fri fold parity" {
    const alloc = std.testing.allocator;
    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fri_folds.len > 0);
    for (parsed.value.fri_folds) |v| {
        const line_domain = try line_mod.LineDomain.init(circle_mod.Coset.halfOdds(v.line_log_size));
        const line_eval = try alloc.alloc(QM31, v.line_eval.len);
        defer alloc.free(line_eval);
        for (v.line_eval, 0..) |value, i| line_eval[i] = qm31From(value);

        const folded_line = try fri_mod.foldLine(alloc, line_eval, line_domain, qm31From(v.alpha));
        defer alloc.free(folded_line.values);
        try std.testing.expectEqual(v.fold_line_values.len, folded_line.values.len);
        for (v.fold_line_values, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(folded_line.values[i])[0..]);
        }

        const circle_domain = canonic_mod.CanonicCoset.new(v.circle_log_size).circleDomain();
        const circle_eval = try alloc.alloc(QM31, v.circle_eval.len);
        defer alloc.free(circle_eval);
        for (v.circle_eval, 0..) |value, i| circle_eval[i] = qm31From(value);

        const folded_circle = try alloc.alloc(QM31, v.fold_circle_values.len);
        defer alloc.free(folded_circle);
        @memset(folded_circle, QM31.zero());
        try fri_mod.foldCircleIntoLine(folded_circle, circle_eval, circle_domain, qm31From(v.alpha));
        try std.testing.expectEqual(v.fold_circle_values.len, folded_circle.len);
        for (v.fold_circle_values, 0..) |expected, i| {
            try std.testing.expectEqualSlices(u32, expected[0..], encodeQM31(folded_circle[i])[0..]);
        }
    }
}

test "field vectors: fri decommit parity" {
    const alloc = std.testing.allocator;

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fri_decommit.len > 0);
    for (parsed.value.fri_decommit) |v| {
        const column = try alloc.alloc(QM31, v.column.len);
        defer alloc.free(column);
        for (v.column, 0..) |value, i| column[i] = qm31From(value);

        if (std.mem.eql(u8, v.expected, "ok")) {
            var result = try prover_fri_mod.computeDecommitmentPositionsAndWitnessEvals(
                alloc,
                column,
                v.query_positions,
                v.fold_step,
            );
            defer result.deinit(alloc);

            try std.testing.expectEqualSlices(usize, v.decommitment_positions, result.decommitment_positions);
            try std.testing.expectEqual(v.witness_evals.len, result.witness_evals.len);
            for (v.witness_evals, 0..) |expected, i| {
                try std.testing.expect(result.witness_evals[i].eql(qm31From(expected)));
            }
            try std.testing.expectEqual(v.value_map_positions.len, result.value_map.len);
            for (result.value_map, 0..) |entry, i| {
                try std.testing.expectEqual(v.value_map_positions[i], entry.position);
                try std.testing.expect(entry.value.eql(qm31From(v.value_map_values[i])));
            }
        } else {
            try std.testing.expectError(
                expectedFriDecommitError(v.expected),
                prover_fri_mod.computeDecommitmentPositionsAndWitnessEvals(
                    alloc,
                    column,
                    v.query_positions,
                    v.fold_step,
                ),
            );
        }
    }
}

test "field vectors: fri layer decommit parity" {
    const alloc = std.testing.allocator;
    const Hasher = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Prover = vcs_lifted_prover_mod.MerkleProverLifted(Hasher);

    var parsed = try parseVectors(alloc);
    defer parsed.deinit();

    try std.testing.expect(parsed.value.fri_layer_decommit.len > 0);
    for (parsed.value.fri_layer_decommit) |v| {
        const column = try alloc.alloc(QM31, v.column.len);
        defer alloc.free(column);
        for (v.column, 0..) |value, i| column[i] = qm31From(value);

        var secure_column = try prover_secure_column_mod.SecureColumnByCoords.fromSecureSlice(alloc, column);
        defer secure_column.deinit(alloc);

        const coord_columns = [_][]const M31{
            secure_column.columns[0],
            secure_column.columns[1],
            secure_column.columns[2],
            secure_column.columns[3],
        };
        var merkle = try Prover.commit(alloc, coord_columns[0..]);
        defer merkle.deinit(alloc);

        const root = merkle.root();
        try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&v.commitment), std.mem.asBytes(&root)));

        if (std.mem.eql(u8, v.expected, "ok")) {
            var result = try prover_fri_mod.decommitLayer(
                Hasher,
                alloc,
                merkle,
                secure_column,
                v.query_positions,
                v.fold_step,
            );
            defer result.deinit(alloc);

            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&v.commitment),
                std.mem.asBytes(&result.proof.commitment),
            ));
            try std.testing.expectEqualSlices(
                usize,
                v.decommitment_positions,
                result.decommitment_positions,
            );

            try std.testing.expectEqual(v.fri_witness.len, result.proof.fri_witness.len);
            for (v.fri_witness, 0..) |expected, i| {
                try std.testing.expect(result.proof.fri_witness[i].eql(qm31From(expected)));
            }

            try std.testing.expectEqual(v.hash_witness.len, result.proof.decommitment.hash_witness.len);
            for (v.hash_witness, 0..) |expected, i| {
                try std.testing.expect(std.mem.eql(
                    u8,
                    std.mem.asBytes(&expected),
                    std.mem.asBytes(&result.proof.decommitment.hash_witness[i]),
                ));
            }

            try std.testing.expectEqual(v.value_map_positions.len, result.value_map.len);
            for (result.value_map, 0..) |entry, i| {
                try std.testing.expectEqual(v.value_map_positions[i], entry.position);
                try std.testing.expect(entry.value.eql(qm31From(v.value_map_values[i])));
            }

            var extended = try prover_fri_mod.decommitLayerExtended(
                Hasher,
                alloc,
                merkle,
                secure_column,
                v.query_positions,
                v.fold_step,
            );
            defer extended.deinit(alloc);

            try std.testing.expect(std.mem.eql(
                u8,
                std.mem.asBytes(&v.commitment),
                std.mem.asBytes(&extended.proof.commitment),
            ));
            try std.testing.expectEqual(v.fri_witness.len, extended.proof.fri_witness.len);
            for (v.fri_witness, 0..) |expected, i| {
                try std.testing.expect(extended.proof.fri_witness[i].eql(qm31From(expected)));
            }
            try std.testing.expectEqual(v.hash_witness.len, extended.proof.decommitment.hash_witness.len);
            for (v.hash_witness, 0..) |expected, i| {
                try std.testing.expect(std.mem.eql(
                    u8,
                    std.mem.asBytes(&expected),
                    std.mem.asBytes(&extended.proof.decommitment.hash_witness[i]),
                ));
            }
            try std.testing.expectEqual(@as(usize, 1), extended.aux.all_values.len);
            try std.testing.expectEqual(v.value_map_positions.len, extended.aux.all_values[0].len);
            for (extended.aux.all_values[0], 0..) |indexed, i| {
                try std.testing.expectEqual(v.value_map_positions[i], indexed.index);
                try std.testing.expect(indexed.value.eql(qm31From(v.value_map_values[i])));
            }
        } else {
            try std.testing.expectError(
                expectedFriDecommitError(v.expected),
                prover_fri_mod.decommitLayer(
                    Hasher,
                    alloc,
                    merkle,
                    secure_column,
                    v.query_positions,
                    v.fold_step,
                ),
            );
            try std.testing.expectError(
                expectedFriDecommitError(v.expected),
                prover_fri_mod.decommitLayerExtended(
                    Hasher,
                    alloc,
                    merkle,
                    secure_column,
                    v.query_positions,
                    v.fold_step,
                ),
            );
        }
    }
}
