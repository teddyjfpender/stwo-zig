//! Independent scalar replay of one accepted CAS05 relation. This test never
//! calls the prover's pairedHeight or either verifier fold helper to compute
//! its expected words. It is finite validation, not a Zig semantics theorem.

const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_sparse_cascade_experimental;
const M31 = core.fields.m31.M31;
const CM31 = core.fields.cm31.CM31;
const QM31 = core.fields.qm31.QM31;
const Channel = core.channel.blake2s.Blake2sChannel;
const canonic = core.poly.circle.canonic;
const LineDomain = core.poly.line.LineDomain;
const LinePoly = core.poly.line.LinePoly;
const sparse = core.pcs.transposed_merkle_sparse;

fn scalarPair(left: QM31, right: QM31, coordinate: M31, alpha: QM31) !QM31 {
    const sum = left.add(right);
    const difference = left.sub(right);
    return sum.add(alpha.mul(difference.mulM31(try coordinate.inv())));
}

fn scalarBatch(
    columns: []const []const M31,
    claims: []const QM31,
    point: core.circle.CirclePointQM31,
    challenge: QM31,
    p: core.circle.CirclePointM31,
    row: usize,
) !QM31 {
    const conjugate = point.complexConjugate();
    const denominator = point.x.c0.sub(CM31.fromBase(p.x)).mul(point.y.c1)
        .sub(point.y.c0.sub(CM31.fromBase(p.y)).mul(point.x.c1));
    const inverse = try denominator.inv();
    var weight = QM31.one();
    var result = QM31.zero();
    for (columns, claims) |column, claim| {
        const word = column[row];
        // Interpolate the OOD claim and its complex conjugate directly at
        // this row's y. The native path uses cross-multiplied line
        // coefficients; these divisions are intentionally independent.
        const slope = claim.complexConjugate().sub(claim);
        const y_span = conjugate.y.sub(point.y);
        const interpolation = claim.add(try slope.mul(
            QM31.fromBase(p.y).sub(point.y),
        ).div(y_span));
        const residual = QM31.fromBase(word).sub(interpolation).mul(y_span);
        result = result.add(weight.mul(QM31.fromBase(word)));
        weight = weight.mul(challenge);
        result = result.add(weight.mul(residual.mulCM31(inverse)));
        weight = weight.mul(challenge);
    }
    return result;
}

fn openedWord(opening: core.pcs.paired_sparse_cascade_experimental.LineOpening, at: usize) QM31 {
    return QM31.fromM31Array(.{
        opening.queried_coordinates[0][at], opening.queried_coordinates[1][at],
        opening.queried_coordinates[2][at], opening.queried_coordinates[3][at],
    });
}

test "CAS05 accepted nonconstant four-height proof refines independent scalar relation" {
    const allocator = std.testing.allocator;
    const k: u32 = 7;
    const height_count: usize = 4;
    var xs: [height_count][128]M31 = undefined;
    var ys: [height_count][128]M31 = undefined;
    var columns: [height_count][2][]const M31 = undefined;
    var groups: [height_count][]const []const M31 = undefined;
    for (0..height_count) |height| {
        const log_size = k - @as(u32, @intCast(height));
        const size = @as(usize, 1) << @intCast(log_size);
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        for (0..size) |row| {
            const p = domain.at(core.utils.bitReverseIndex(row, log_size));
            xs[height][row] = p.x;
            ys[height][row] = p.y;
        }
        columns[height] = .{ xs[height][0..size], ys[height][0..size] };
        groups[height] = &columns[height];
    }
    const input = host.Input{
        .source_columns = &groups,
        .log_blowup = 2,
        .n_queries = 13,
    };
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, input, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    const statement = core.pcs.paired_sparse_cascade_experimental.ExpectedStatement{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    };
    const encoded = try core.pcs.paired_sparse_cascade_wire.encode(allocator, proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try core.pcs.paired_sparse_cascade_wire.verifyAgainstStatement(
        allocator,
        encoded,
        &verifier_channel,
        statement,
    );
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    var extractor_channel = Channel{};
    var accepted = try core.pcs.paired_sparse_cascade_wire.verifyAndExtractRelation(
        allocator,
        encoded,
        &extractor_channel,
        statement,
    );
    defer accepted.deinit();
    try std.testing.expectEqualSlices(u8, &verifier_channel.digest, &extractor_channel.digest);
    // The byte decoder has already freed its temporary proof. This check
    // runs on the extractor's owned relation for every sampled query/height.
    try accepted.check(allocator);
    const original_forwarded = accepted.forwarded[0][0];
    accepted.forwarded[0][0] = original_forwarded.add(QM31.one());
    if (accepted.check(allocator)) |_| return error.MutatedForwardedValueAccepted else |_| {}
    accepted.forwarded[0][0] = original_forwarded;
    const original_alpha = accepted.alphas[0];
    accepted.alphas[0] = original_alpha.add(QM31.one());
    if (accepted.check(allocator)) |_| return error.MutatedFoldChallengeAccepted else |_| {}
    accepted.alphas[0] = original_alpha;
    const original_source = accepted.source.values[0][0];
    accepted.source.values[0][0] = original_source.add(M31.one());
    if (accepted.check(allocator)) |_| return error.MutatedSourceRowAccepted else |_| {}
    accepted.source.values[0][0] = original_source;
    const original_line = accepted.line_pairs[0][0];
    accepted.line_pairs[0][0] = original_line.add(QM31.one());
    if (accepted.check(allocator)) |_| return error.MutatedLineRowAccepted else |_| {}
    accepted.line_pairs[0][0] = original_line;
    const original_terminal = accepted.terminal_ordered_coeffs[0];
    accepted.terminal_ordered_coeffs[0] = original_terminal.add(QM31.one());
    if (accepted.check(allocator)) |_| return error.MutatedTerminalAccepted else |_| {}
    accepted.terminal_ordered_coeffs[0] = original_terminal;
    const original_raw = accepted.raw_queries[0];
    accepted.raw_queries[0] = @as(usize, 1) << k;
    if (accepted.check(allocator)) |_| return error.OutOfRangeQueryAccepted else |_| {}
    accepted.raw_queries[0] = original_raw;
    try accepted.check(allocator);
    var wrong_statement = statement;
    wrong_statement.source_root[0] ^= 1;
    var rejected_channel = Channel{};
    const initial_digest = rejected_channel.digest;
    try std.testing.expectError(
        error.UnexpectedSparseStatement,
        core.pcs.paired_sparse_cascade_wire.verifyAndExtractRelation(
            allocator,
            encoded,
            &rejected_channel,
            wrong_statement,
        ),
    );
    try std.testing.expectEqualSlices(u8, &initial_digest, &rejected_channel.digest);
    var invalid_line_channel = Channel{};
    var invalid_line = try host.proveWithInvalidLineForTest(allocator, input, &invalid_line_channel);
    defer invalid_line.deinit();
    const invalid_line_wire = try core.pcs.paired_sparse_cascade_wire.encode(allocator, invalid_line.proof);
    defer allocator.free(invalid_line_wire);
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        core.pcs.paired_sparse_cascade_wire.verifyAndExtractRelation(
            allocator,
            invalid_line_wire,
            &rejected_channel,
            .{
                .profile = invalid_line.proof.profile,
                .source_root = invalid_line.proof.source_root,
                .claims = invalid_line.proof.claims,
            },
        ),
    );
    try std.testing.expectEqualSlices(u8, &initial_digest, &rejected_channel.digest);
    var invalid_terminal_channel = Channel{};
    var invalid_terminal = try host.proveWithInvalidTerminalForTest(
        allocator,
        input,
        &invalid_terminal_channel,
    );
    defer invalid_terminal.deinit();
    const invalid_terminal_wire = try core.pcs.paired_sparse_cascade_wire.encode(
        allocator,
        invalid_terminal.proof,
    );
    defer allocator.free(invalid_terminal_wire);
    try std.testing.expectError(
        error.TerminalFoldMismatch,
        core.pcs.paired_sparse_cascade_wire.verifyAndExtractRelation(
            allocator,
            invalid_terminal_wire,
            &rejected_channel,
            .{
                .profile = invalid_terminal.proof.profile,
                .source_root = invalid_terminal.proof.source_root,
                .claims = invalid_terminal.proof.claims,
            },
        ),
    );
    try std.testing.expectEqualSlices(u8, &initial_digest, &rejected_channel.digest);

    // Replay only transcript custody and XDM04 authentication. The expected
    // quotient and fold words below come from the independent scalar formulas.
    var replay = Channel{};
    core.pcs.paired_sparse_cascade_experimental.bindVersion(&replay);
    const point = try core.pcs.paired_cascade_experimental.drawOodPoint(
        &replay,
        proof.profile,
        proof.source_root,
    );
    try std.testing.expect(point.eql(proof.sampled_point));
    const batch_challenge = core.pcs.paired_cascade_experimental.drawBatchAfterOod(
        &replay,
        proof.claims,
    );
    var alphas: [height_count]QM31 = undefined;
    for (&alphas, 0..) |*alpha, step| {
        alpha.* = replay.drawSecureFelt();
        if (step < proof.line_openings.len)
            core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
                &replay,
                proof.line_openings[step].root,
            );
    }
    replay.mixFelts(proof.terminal_ordered_coeffs);
    const raw = try core.queries.drawQueries(&replay, allocator, k, proof.profile.source.query_count);
    defer allocator.free(raw);
    var opened = try sparse.verifyAndCollect(
        allocator,
        proof.source_wire,
        proof.profile.source,
        proof.source_root,
        raw,
    );
    defer opened.deinit();
    var native_answers = try core.pcs.transposed_paired_sparse.fromVerifiedOpenings(
        allocator,
        opened,
        raw,
        point,
        proof.claims,
        batch_challenge,
    );
    defer native_answers.deinit();
    for (raw, 0..) |position, query| {
        for (0..height_count) |height| {
            const base = sparse.pairBase(position, height);
            for (0..2) |side| for (0..2) |column| {
                try std.testing.expect(groups[height][column][base + side].eql(
                    opened.at(height, query, side, column),
                ));
            };
        }
    }

    var batches: [height_count][]QM31 = undefined;
    var built: usize = 0;
    var saw_quotient_contribution = false;
    defer for (batches[0..built]) |batch| allocator.free(batch);
    for (0..height_count) |height| {
        const log_size = k - @as(u32, @intCast(height));
        const size = @as(usize, 1) << @intCast(log_size);
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        batches[height] = try allocator.alloc(QM31, size);
        built += 1;
        for (batches[height], 0..) |*word, row| {
            const p = domain.at(core.utils.bitReverseIndex(row, log_size));
            word.* = try scalarBatch(
                groups[height],
                proof.claims[height],
                point,
                batch_challenge,
                p,
                row,
            );
            const original_only = QM31.fromBase(groups[height][0][row]).add(
                batch_challenge.square().mul(QM31.fromBase(groups[height][1][row])),
            );
            if (!word.eql(original_only)) saw_quotient_contribution = true;
        }
        for (raw, 0..) |position, query| {
            const base = sparse.pairBase(position, height);
            for (0..2) |side| {
                try std.testing.expect(batches[height][base + side].eql(
                    native_answers.values[height][query * 2 + side],
                ));
            }
        }
    }
    try std.testing.expect(saw_quotient_contribution);

    const two = QM31.fromBase(M31.fromCanonical(2));
    const half = try two.inv();
    var scale = QM31.one();
    var current: []QM31 = &.{};
    for (0..height_count) |step| {
        const circle_log = k - @as(u32, @intCast(step));
        const output_len = batches[step].len / 2;
        const next = try allocator.alloc(QM31, output_len);
        const domain = canonic.CanonicCoset.new(circle_log).circleDomain();
        const previous_domain = if (step == 0) undefined else LineDomain.fromCircleDomain(canonic.CanonicCoset.new(circle_log + 1).circleDomain());
        for (next, 0..) |*word, row| {
            const base = row * 2;
            const y = domain.at(core.utils.bitReverseIndex(base, circle_log)).y;
            const inserted = try scalarPair(
                batches[step][base],
                batches[step][base + 1],
                y,
                alphas[step],
            );
            word.* = if (step == 0) inserted else blk: {
                const x = previous_domain.at(core.utils.bitReverseIndex(base, circle_log));
                const carried = try scalarPair(current[base], current[base + 1], x, alphas[step]);
                break :blk carried.add(alphas[step].square().mul(inserted));
            };
            // Eq. 68 uses normalized butterflies. A native layer has scale
            // 2^step, so both its carried pair and newly inserted pair are
            // divided by that scale before the paper's 1/2 butterfly.
            const normalized_inserted = try scalarPair(
                try batches[step][base].div(scale),
                try batches[step][base + 1].div(scale),
                y,
                alphas[step],
            );
            const normalized = if (step == 0) half.mul(normalized_inserted) else blk: {
                const x = previous_domain.at(core.utils.bitReverseIndex(base, circle_log));
                const normalized_carried = try scalarPair(
                    try current[base].div(scale),
                    try current[base + 1].div(scale),
                    x,
                    alphas[step],
                );
                break :blk half.mul(normalized_carried)
                    .add(alphas[step].square().mul(half.mul(normalized_inserted)));
            };
            try std.testing.expect(word.eql(two.mul(scale).mul(normalized)));
        }
        if (step + 1 < height_count) {
            const opening = proof.line_openings[step];
            for (raw, 0..) |position, query| {
                const base = sparse.pairBase(position, step + 1);
                for (0..2) |side|
                    try std.testing.expect(next[base + side].eql(
                        openedWord(opening, query * 2 + side),
                    ));
            }
        } else {
            const coefficients = try allocator.dupe(QM31, proof.terminal_ordered_coeffs);
            var polynomial = LinePoly.fromOrderedCoefficients(coefficients);
            defer polynomial.deinit(allocator);
            const terminal_domain = LineDomain.fromCircleDomain(domain);
            for (next, 0..) |actual, row| {
                const x = terminal_domain.at(core.utils.bitReverseIndex(row, terminal_domain.logSize()));
                const claimed = try polynomial.evalAtPoint(allocator, QM31.fromBase(x));
                try std.testing.expect(actual.eql(claimed));
            }
        }
        if (step != 0) allocator.free(current);
        current = next;
        scale = scale.mul(two);
    }
    allocator.free(current);
}

test "CAS05 accepted relation extractor checks every one of eight heights" {
    const allocator = std.testing.allocator;
    const k: u32 = 10;
    const height_count: usize = 8;
    var xs: [height_count][1024]M31 = undefined;
    var columns: [height_count][1][]const M31 = undefined;
    var groups: [height_count][]const []const M31 = undefined;
    for (0..height_count) |height| {
        const log_size = k - @as(u32, @intCast(height));
        const size = @as(usize, 1) << @intCast(log_size);
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        for (0..size) |row|
            xs[height][row] = domain.at(core.utils.bitReverseIndex(row, log_size)).x;
        columns[height] = .{xs[height][0..size]};
        groups[height] = &columns[height];
    }
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, .{
        .source_columns = &groups,
        .log_blowup = 1,
        .n_queries = 4,
    }, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    const encoded = try core.pcs.paired_sparse_cascade_wire.encode(allocator, proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    var accepted = try core.pcs.paired_sparse_cascade_wire.verifyAndExtractRelation(
        allocator,
        encoded,
        &verifier_channel,
        .{
            .profile = proof.profile,
            .source_root = proof.source_root,
            .claims = proof.claims,
        },
    );
    defer accepted.deinit();
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(height_count, accepted.forwarded.len);
    try std.testing.expectEqual(@as(usize, 2), accepted.terminal_ordered_coeffs.len);
    try accepted.check(allocator);
    const middle = accepted.forwarded[4][0];
    accepted.forwarded[4][0] = middle.add(QM31.one());
    if (accepted.check(allocator)) |_| return error.MiddleFoldMutationAccepted else |_| {}
}
