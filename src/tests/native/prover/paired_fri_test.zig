//! Experimental paired and multi-height FRI integration tests.

const std = @import("std");
const fri = @import("stwo_prover_engine").fri;
const core_fri = @import("stwo_core").fri;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const secure_column = @import("stwo_prover_engine").secure_column;

test {
    _ = @import("paired_fri_relation_bridge_test.zig");
}

const M31 = m31.M31;
const QM31 = qm31.QM31;
const FriProver = fri.FriProver;

test "three-height one-root cascade authenticates every insertion and rolls back" {
    const core = @import("stwo_core");
    const cascade = core.pcs.paired_cascade_experimental;
    const host = @import("stwo_prover_engine").pcs.paired_cascade_experimental;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var x0: [32]M31 = undefined;
    var x1: [16]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 5)).x;
    for (&x1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 4)).x;
    const third = [_]M31{M31.fromCanonical(7)} ** 8;
    const h0 = [_][]const M31{&x0};
    const h1 = [_][]const M31{&x1};
    const h2 = [_][]const M31{&third};
    const heights = [_][]const []const M31{ &h0, &h1, &h2 };
    const cascade_input = host.Input{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 5,
    };
    var prover_channel = Channel{};
    var owned = try host.prove(alloc, cascade_input, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    const statement = cascade.ExpectedStatement{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    };
    var verifier_channel = Channel{};
    try cascade.verifyAgainstStatement(alloc, proof, &verifier_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    const outer = core.pcs.paired_cascade_wire;
    const encoded = try outer.encode(alloc, proof);
    defer alloc.free(encoded);
    try std.testing.expectError(
        error.UnsupportedProofFormat,
        core.pcs.paired_two_height_v2_wire.decode(alloc, encoded),
    );
    var decoded = try outer.decode(alloc, encoded);
    defer decoded.deinit();
    var wire_channel = Channel{};
    try outer.verifyAgainstStatement(alloc, encoded, &wire_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &wire_channel.digest);
    const reencoded = try outer.encode(alloc, decoded.proof);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    try std.testing.expectEqual(@as(usize, 1236), encoded.len);
    var wire_rejected = Channel{};
    const wire_initial = wire_rejected.digest;
    try std.testing.expectError(error.TruncatedCascadeProof, outer.verifyAgainstStatement(alloc, encoded[0 .. encoded.len - 1], &wire_rejected, statement));
    try std.testing.expectError(error.TruncatedCascadeProof, outer.verifyAgainstStatement(alloc, encoded[0..15], &wire_rejected, statement));
    const trailing = try alloc.alloc(u8, encoded.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, trailing, &wire_rejected, statement));
    const mutated = try alloc.dupe(u8, encoded);
    defer alloc.free(mutated);
    mutated[8] = 5;
    try std.testing.expectError(error.UnsupportedProofVersion, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    mutated[8] = outer.VERSION;
    mutated[10] = 1;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    mutated[10] = 0;
    const point_at = 32 + 2 * proof.profile.source.height_count + 32;
    @memset(mutated[point_at..][0..4], 0xff);
    try std.testing.expectError(error.NonCanonicalM31, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    @memcpy(mutated[point_at..][0..4], encoded[point_at..][0..4]);
    const inner_at = std.mem.indexOf(u8, mutated, core.pcs.transposed_merkle_cascade.MAGIC).?;
    mutated[inner_at + 8] = 4;
    try std.testing.expectError(error.UnsupportedProofVersion, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    mutated[inner_at + 8] = 3;
    const first_inner_felt = inner_at + 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 +
        2 * proof.profile.source.height_count + 32 + 4;
    @memset(mutated[first_inner_felt..][0..4], 0xff);
    try std.testing.expectError(error.NonCanonicalM31, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    @memcpy(mutated[first_inner_felt..][0..4], encoded[first_inner_felt..][0..4]);
    const line_count_at = inner_at + proof.source_wire.len;
    mutated[line_count_at] = 0;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    mutated[line_count_at] = @intCast(proof.line_openings.len);
    const root_at = 32 + 2 * proof.profile.source.height_count;
    mutated[root_at] ^= 1;
    try std.testing.expectError(error.UnexpectedCascadeRoot, outer.verifyAgainstStatement(alloc, mutated, &wire_rejected, statement));
    mutated[root_at] ^= 1;
    try std.testing.expectEqualSlices(u8, &wire_initial, &wire_rejected.digest);
    var wire_wrong_root = statement;
    wire_wrong_root.source_root[0] ^= 1;
    try std.testing.expectError(error.UnexpectedCascadeStatement, outer.verifyAgainstStatement(alloc, encoded, &wire_rejected, wire_wrong_root));
    var wire_wrong_shape = statement;
    wire_wrong_shape.profile.source.columns[0] += 1;
    try std.testing.expectError(error.UnexpectedCascadeStatement, outer.verifyAgainstStatement(alloc, encoded, &wire_rejected, wire_wrong_shape));
    try std.testing.expectEqualSlices(u8, &wire_initial, &wire_rejected.digest);
    var prefixed = Channel{};
    prefixed.mixU64(0x5052_4546_4958_3034);
    const prefixed_digest = prefixed.digest;
    try std.testing.expectError(error.UnsampledOodPoint, outer.verifyAgainstStatement(alloc, encoded, &prefixed, statement));
    try std.testing.expectEqualSlices(u8, &prefixed_digest, &prefixed.digest);
    var replay = Channel{};
    cascade.bindVersion(&replay);
    const sampled = try cascade.drawOodPoint(&replay, proof.profile, proof.source_root);
    try std.testing.expect(sampled.eql(proof.sampled_point));
    const lambda = cascade.drawBatchAfterOod(&replay, proof.claims);
    for (proof.line_openings) |opening| {
        _ = replay.drawSecureFelt();
        core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&replay, opening.root);
    }
    _ = replay.drawSecureFelt();
    replay.mixFelts(proof.terminal_ordered_coeffs);
    const raw = try core.queries.drawQueries(&replay, alloc, 5, 5);
    defer alloc.free(raw);
    var opened = try core.pcs.transposed_merkle_cascade.verifyAndCollect(
        alloc,
        proof.source_wire,
        proof.profile.source,
        proof.source_root,
        raw,
    );
    defer opened.deinit();
    var paired = try core.pcs.transposed_paired_cascade.fromVerifiedOpenings(
        alloc,
        opened,
        raw,
        sampled,
        proof.claims,
        lambda,
    );
    defer paired.deinit();
    const old_host = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
    for (heights, 0..) |columns, height| {
        const log_size = 5 - @as(u32, @intCast(height));
        const domain = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
        const reference = try old_host.pairedHeight(
            alloc,
            domain,
            columns,
            proof.claims[height],
            sampled,
            .{ .batch = lambda },
        );
        defer alloc.free(reference);
        const width = proof.profile.source.width(height);
        for (raw, 0..) |position, query| {
            const base = (position & ~(proof.profile.source.width(0) - 1)) >> @intCast(height);
            for (0..width) |j|
                try std.testing.expect(reference[base + j].eql(paired.values[height][query * width + j]));
        }
    }
    try std.testing.expectEqual(@as(usize, 2), proof.line_openings.len);
    try std.testing.expectEqual(@as(usize, 1), proof.terminal_ordered_coeffs.len);
    var wrong_root = statement;
    wrong_root.source_root[0] ^= 1;
    var rejected = Channel{};
    const initial = rejected.digest;
    try std.testing.expectError(error.UnexpectedCascadeStatement, cascade.verifyAgainstStatement(alloc, proof, &rejected, wrong_root));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_claims = try alloc.dupe(QM31, proof.claims[1]);
    defer alloc.free(wrong_claims);
    wrong_claims[0] = wrong_claims[0].add(QM31.one());
    var claims = [_][]const QM31{ proof.claims[0], wrong_claims, proof.claims[2] };
    var wrong_statement = statement;
    wrong_statement.claims = &claims;
    try std.testing.expectError(error.UnexpectedCascadeStatement, cascade.verifyAgainstStatement(alloc, proof, &rejected, wrong_statement));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_point = proof;
    wrong_point.sampled_point = core.circle.CirclePointQM31.zero();
    try std.testing.expectError(error.UnsampledOodPoint, cascade.verifyAgainstStatement(alloc, wrong_point, &rejected, statement));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_source = proof;
    const changed_source = try alloc.dupe(u8, proof.source_wire);
    defer alloc.free(changed_source);
    const xdm_header_len = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 +
        2 * proof.profile.source.height_count + 32;
    changed_source[xdm_header_len + 4] ^= 1;
    wrong_source.source_wire = changed_source;
    if (cascade.verifyAgainstStatement(alloc, wrong_source, &rejected, statement)) |_| {
        return error.ExpectedProofRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    const changed_version = try alloc.dupe(u8, proof.source_wire);
    defer alloc.free(changed_version);
    changed_version[8] = 4;
    wrong_source.source_wire = changed_version;
    try std.testing.expectError(error.UnsupportedProofVersion, cascade.verifyAgainstStatement(alloc, wrong_source, &rejected, statement));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_line = proof;
    var line_openings = try alloc.dupe(cascade.LineOpening, proof.line_openings);
    defer alloc.free(line_openings);
    const changed = try alloc.dupe(M31, line_openings[1].queried_coordinates[0]);
    defer alloc.free(changed);
    changed[0] = changed[0].add(M31.one());
    line_openings[1].queried_coordinates[0] = changed;
    wrong_line.line_openings = line_openings;
    try std.testing.expectError(error.DuplicateQueryMismatch, cascade.verifyAgainstStatement(alloc, wrong_line, &rejected, statement));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    const wrong_line_wire = try outer.encode(alloc, wrong_line);
    defer alloc.free(wrong_line_wire);
    try std.testing.expectError(error.DuplicateQueryMismatch, outer.verifyAgainstStatement(alloc, wrong_line_wire, &wire_rejected, statement));
    try std.testing.expectEqualSlices(u8, &wire_initial, &wire_rejected.digest);
    var wrong_terminal = proof;
    const terminal = try alloc.dupe(QM31, proof.terminal_ordered_coeffs);
    defer alloc.free(terminal);
    terminal[0] = terminal[0].add(QM31.one());
    wrong_terminal.terminal_ordered_coeffs = terminal;
    if (cascade.verifyAgainstStatement(alloc, wrong_terminal, &rejected, statement)) |_| {
        return error.ExpectedProofRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var forged_channel = Channel{};
    var forged = try host.proveWithInvalidTerminalForTest(alloc, cascade_input, &forged_channel);
    defer forged.deinit();
    const forged_statement = cascade.ExpectedStatement{
        .profile = forged.proof.profile,
        .source_root = forged.proof.source_root,
        .claims = forged.proof.claims,
    };
    const forged_wire = try outer.encode(alloc, forged.proof);
    defer alloc.free(forged_wire);
    try std.testing.expectError(error.TerminalFoldMismatch, outer.verifyAgainstStatement(alloc, forged_wire, &wire_rejected, forged_statement));
    try std.testing.expectEqualSlices(u8, &wire_initial, &wire_rejected.digest);
    try std.testing.expectEqual(@as(usize, 434), proof.source_wire.len);
    try std.testing.expectEqual(@as(usize, 1), proof.line_openings[0].hash_witness.len);
    try std.testing.expectEqual(@as(usize, 1), proof.line_openings[1].hash_witness.len);
}

fn normalizedPairReference(even: QM31, odd: QM31, coordinate: M31, alpha: QM31) !QM31 {
    const inverse_two = try M31.fromCanonical(2).inv();
    return even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try coordinate.inv())))
        .mulM31(inverse_two);
}

test "native cascade normalization has a height-dependent inserted batch scale" {
    const cascade = @import("stwo_core").pcs.paired_cascade_experimental;
    // Let C_i be the native layer and P_i=C_i/2^i. The native insertion at
    // height i corresponds to F(P_i)+alpha^2*2^-i*F(H_i), where F is the
    // published normalized inverse butterfly. Check i=1,2,3 independently.
    var factor = M31.fromCanonical(2);
    var normalized_previous = QM31.fromBase(M31.fromCanonical(5));
    var native_previous = normalized_previous.mulM31(factor);
    for (1..4) |height| {
        const other = QM31.fromBase(M31.fromCanonical(@intCast(8 + height)));
        const inserted_even = QM31.fromBase(M31.fromCanonical(@intCast(15 + height)));
        const inserted_odd = QM31.fromBase(M31.fromCanonical(@intCast(3 + height)));
        const alpha = QM31.fromBase(M31.fromCanonical(@intCast(7 + height)));
        const x = M31.fromCanonical(@intCast(2 + height));
        const y = M31.fromCanonical(@intCast(4 + height));
        const native_next = try cascade.foldInsertedPair(
            native_previous,
            other.mulM31(factor),
            x,
            inserted_even,
            inserted_odd,
            y,
            alpha,
        );
        const previous_term = try normalizedPairReference(normalized_previous, other, x, alpha);
        const inserted_term = try normalizedPairReference(inserted_even, inserted_odd, y, alpha);
        const normalized_next = previous_term.add(
            alpha.square().mul(inserted_term).mulM31(try factor.inv()),
        );
        const next_factor = factor.add(factor);
        try std.testing.expect(native_next.eql(normalized_next.mulM31(next_factor)));
        try std.testing.expect(!normalized_next.eql(previous_term.add(alpha.square().mul(inserted_term))));
        factor = next_factor;
        native_previous = native_next;
        normalized_previous = normalized_next;
    }
}

test "three-height sparse two-row cascade verifies one-root source and line paths" {
    const core = @import("stwo_core");
    const sparse_cascade = core.pcs.paired_sparse_cascade_experimental;
    const host = @import("stwo_prover_engine").pcs.paired_sparse_cascade_experimental;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var x0: [32]M31 = undefined;
    var x1: [16]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 5)).x;
    for (&x1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 4)).x;
    const third = [_]M31{M31.fromCanonical(7)} ** 8;
    const h0 = [_][]const M31{&x0};
    const h1 = [_][]const M31{&x1};
    const h2 = [_][]const M31{&third};
    const heights = [_][]const []const M31{ &h0, &h1, &h2 };
    var prover_channel = Channel{};
    var owned = try host.prove(alloc, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 5,
    }, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    const statement = sparse_cascade.ExpectedStatement{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    };
    var verifier_channel = Channel{};
    try sparse_cascade.verifyAgainstStatement(alloc, proof, &verifier_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    for (proof.line_openings) |opening|
        for (opening.queried_coordinates) |column|
            try std.testing.expectEqual(@as(usize, 10), column.len);
    const outer = core.pcs.paired_sparse_cascade_wire;
    const encoded = try outer.encode(alloc, proof);
    defer alloc.free(encoded);
    try std.testing.expectError(error.UnsupportedProofFormat, core.pcs.paired_cascade_wire.decode(alloc, encoded));
    var decoded = try outer.decode(alloc, encoded);
    defer decoded.deinit();
    const reencoded = try outer.encode(alloc, decoded.proof);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    var wire_channel = Channel{};
    try outer.verifyAgainstStatement(alloc, encoded, &wire_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &wire_channel.digest);
    var replay = Channel{};
    sparse_cascade.bindVersion(&replay);
    const sampled = try core.pcs.paired_cascade_experimental.drawOodPoint(&replay, proof.profile, proof.source_root);
    try std.testing.expect(sampled.eql(proof.sampled_point));
    const lambda = core.pcs.paired_cascade_experimental.drawBatchAfterOod(&replay, proof.claims);
    for (proof.line_openings) |opening| {
        _ = replay.drawSecureFelt();
        core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&replay, opening.root);
    }
    _ = replay.drawSecureFelt();
    replay.mixFelts(proof.terminal_ordered_coeffs);
    const raw = try core.queries.drawQueries(&replay, alloc, 5, 5);
    defer alloc.free(raw);
    var opened = try core.pcs.transposed_merkle_sparse.verifyAndCollect(
        alloc,
        proof.source_wire,
        proof.profile.source,
        proof.source_root,
        raw,
    );
    defer opened.deinit();
    var sparse_answers = try core.pcs.transposed_paired_sparse.fromVerifiedOpenings(
        alloc,
        opened,
        raw,
        sampled,
        proof.claims,
        lambda,
    );
    defer sparse_answers.deinit();
    const paired_reference = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
    for (heights, 0..) |columns, height| {
        const log_size = 5 - @as(u32, @intCast(height));
        const domain = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
        const reference = try paired_reference.pairedHeight(
            alloc,
            domain,
            columns,
            proof.claims[height],
            sampled,
            .{ .batch = lambda },
        );
        defer alloc.free(reference);
        for (raw, 0..) |position, query| {
            const base = core.pcs.transposed_merkle_sparse.pairBase(position, height);
            for (0..2) |j|
                try std.testing.expect(reference[base + j].eql(sparse_answers.values[height][query * 2 + j]));
        }
    }
    try std.testing.expectEqual(@as(usize, 1428), encoded.len);
    try std.testing.expectEqual(@as(usize, 722), proof.source_wire.len);
    var rejected = Channel{};
    const initial = rejected.digest;
    try std.testing.expectError(error.TruncatedCascadeProof, outer.verifyAgainstStatement(alloc, encoded[0 .. encoded.len - 1], &rejected, statement));
    const trailing = try alloc.alloc(u8, encoded.len + 1);
    defer alloc.free(trailing);
    @memcpy(trailing[0..encoded.len], encoded);
    trailing[encoded.len] = 0;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, trailing, &rejected, statement));
    const changed = try alloc.dupe(u8, encoded);
    defer alloc.free(changed);
    changed[8] = 4;
    try std.testing.expectError(error.UnsupportedProofVersion, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[8] = 5;
    changed[10] = 1;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[10] = 0;
    const inner_at = std.mem.indexOf(u8, changed, core.pcs.transposed_merkle_sparse.MAGIC).?;
    changed[inner_at + 8] = 3;
    try std.testing.expectError(error.UnsupportedProofVersion, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[inner_at + 8] = 4;
    const point_at = 32 + 2 * proof.profile.source.height_count + 32;
    @memset(changed[point_at..][0..4], 0xff);
    try std.testing.expectError(error.NonCanonicalM31, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    @memcpy(changed[point_at..][0..4], encoded[point_at..][0..4]);
    const inner_first_felt = inner_at + 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 +
        2 * proof.profile.source.height_count + 32 + 4;
    @memset(changed[inner_first_felt..][0..4], 0xff);
    try std.testing.expectError(error.NonCanonicalM31, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    @memcpy(changed[inner_first_felt..][0..4], encoded[inner_first_felt..][0..4]);
    changed[inner_first_felt - 4] ^= 1;
    try std.testing.expectError(error.UnexpectedSparseQuery, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[inner_first_felt - 4] ^= 1;
    const line_count_at = inner_at + proof.source_wire.len;
    changed[line_count_at] = 0;
    try std.testing.expectError(error.InvalidCascadeProof, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[line_count_at] = @intCast(proof.line_openings.len);
    const root_at = 32 + 2 * proof.profile.source.height_count;
    changed[root_at] ^= 1;
    try std.testing.expectError(error.UnexpectedSparseRoot, outer.verifyAgainstStatement(alloc, changed, &rejected, statement));
    changed[root_at] ^= 1;
    changed[inner_at + proof.source_wire.len - 1] ^= 1;
    if (outer.verifyAgainstStatement(alloc, changed, &rejected, statement)) |_| {
        return error.ExpectedSourceWitnessRejection;
    } else |_| {}
    changed[inner_at + proof.source_wire.len - 1] ^= 1;
    const first_line_value = line_count_at + 4 + 32 + 4;
    changed[first_line_value] ^= 1;
    if (outer.verifyAgainstStatement(alloc, changed, &rejected, statement)) |_| {
        return error.ExpectedLineOpeningRejection;
    } else |_| {}
    changed[first_line_value] ^= 1;
    var wrong_statement = statement;
    wrong_statement.source_root[0] ^= 1;
    try std.testing.expectError(error.UnexpectedSparseStatement, outer.verifyAgainstStatement(alloc, encoded, &rejected, wrong_statement));
    wrong_statement = statement;
    wrong_statement.profile.source.columns[0] += 1;
    try std.testing.expectError(error.UnexpectedSparseStatement, outer.verifyAgainstStatement(alloc, encoded, &rejected, wrong_statement));
    const wrong_claim = try alloc.dupe(QM31, proof.claims[0]);
    defer alloc.free(wrong_claim);
    wrong_claim[0] = wrong_claim[0].add(QM31.one());
    var claim_rows = [_][]const QM31{ wrong_claim, proof.claims[1], proof.claims[2] };
    wrong_statement = statement;
    wrong_statement.claims = &claim_rows;
    try std.testing.expectError(error.UnexpectedSparseStatement, outer.verifyAgainstStatement(alloc, encoded, &rejected, wrong_statement));
    var prefixed = Channel{};
    prefixed.mixU64(0x5350_4152_5345_3035);
    const prefixed_digest = prefixed.digest;
    try std.testing.expectError(error.UnsampledOodPoint, outer.verifyAgainstStatement(alloc, encoded, &prefixed, statement));
    try std.testing.expectEqualSlices(u8, &prefixed_digest, &prefixed.digest);
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var line_channel = Channel{};
    var false_line = try host.proveWithInvalidLineForTest(alloc, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 5,
    }, &line_channel);
    defer false_line.deinit();
    const false_line_wire = try outer.encode(alloc, false_line.proof);
    defer alloc.free(false_line_wire);
    try std.testing.expectError(error.IntermediateFoldMismatch, outer.verifyAgainstStatement(alloc, false_line_wire, &rejected, .{
        .profile = false_line.proof.profile,
        .source_root = false_line.proof.source_root,
        .claims = false_line.proof.claims,
    }));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var adversarial_channel = Channel{};
    var adversarial = try host.proveWithInvalidTerminalForTest(alloc, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 5,
    }, &adversarial_channel);
    defer adversarial.deinit();
    const false_wire = try outer.encode(alloc, adversarial.proof);
    defer alloc.free(false_wire);
    try std.testing.expectError(error.TerminalFoldMismatch, outer.verifyAgainstStatement(alloc, false_wire, &rejected, .{
        .profile = adversarial.proof.profile,
        .source_root = adversarial.proof.source_root,
        .claims = adversarial.proof.claims,
    }));
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
}

test "four-height sparse cascade has a complete canonical wire" {
    const core = @import("stwo_core");
    const host = @import("stwo_prover_engine").pcs.paired_sparse_cascade_experimental;
    const outer = core.pcs.paired_sparse_cascade_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(6).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var x0: [64]M31 = undefined;
    var x1: [32]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 6)).x;
    for (&x1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 5)).x;
    const third = [_]M31{M31.fromCanonical(7)} ** 16;
    const fourth = [_]M31{M31.fromCanonical(11)} ** 8;
    const h0 = [_][]const M31{&x0};
    const h1 = [_][]const M31{&x1};
    const h2 = [_][]const M31{&third};
    const h3 = [_][]const M31{&fourth};
    const heights = [_][]const []const M31{ &h0, &h1, &h2, &h3 };
    var prover_channel = Channel{};
    var owned = try host.prove(alloc, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 3,
    }, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    const encoded = try outer.encode(alloc, proof);
    defer alloc.free(encoded);
    var verifier_channel = Channel{};
    try outer.verifyAgainstStatement(alloc, encoded, &verifier_channel, .{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    });
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(@as(usize, 1488), encoded.len);
    try std.testing.expectEqual(@as(usize, 628), proof.source_wire.len);
    try std.testing.expectEqual(@as(usize, 3), proof.line_openings.len);
    for (proof.line_openings) |opening|
        for (opening.queried_coordinates) |column|
            try std.testing.expectEqual(@as(usize, 6), column.len);
}

test "generic cascade checks four adjacent heights under one transposed root" {
    const core = @import("stwo_core");
    const cascade = core.pcs.paired_cascade_experimental;
    const host = @import("stwo_prover_engine").pcs.paired_cascade_experimental;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(6).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var x0: [64]M31 = undefined;
    var x1: [32]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 6)).x;
    for (&x1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 5)).x;
    const third = [_]M31{M31.fromCanonical(7)} ** 16;
    const fourth = [_]M31{M31.fromCanonical(11)} ** 8;
    const h0 = [_][]const M31{&x0};
    const h1 = [_][]const M31{&x1};
    const h2 = [_][]const M31{&third};
    const h3 = [_][]const M31{&fourth};
    const heights = [_][]const []const M31{ &h0, &h1, &h2, &h3 };
    var prover_channel = Channel{};
    var owned = try host.prove(alloc, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 3,
    }, &prover_channel);
    defer owned.deinit();
    const proof = owned.proof;
    var verifier_channel = Channel{};
    try cascade.verifyAgainstStatement(alloc, proof, &verifier_channel, .{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    });
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(@as(usize, 3), proof.line_openings.len);
    try std.testing.expectEqual(@as(usize, 1), proof.terminal_ordered_coeffs.len);
    try std.testing.expectEqual(@as(usize, 572), proof.source_wire.len);
    for (proof.line_openings) |line_opening|
        try std.testing.expectEqual(@as(usize, 2), line_opening.hash_witness.len);
    const outer = core.pcs.paired_cascade_wire;
    const encoded = try outer.encode(alloc, proof);
    defer alloc.free(encoded);
    var wire_channel = Channel{};
    try outer.verifyAgainstStatement(alloc, encoded, &wire_channel, .{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .claims = proof.claims,
    });
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &wire_channel.digest);
    try std.testing.expectEqual(@as(usize, 1752), encoded.len);
}

test "XDM03 authenticates three adjacent source heights under one root" {
    const core = @import("stwo_core");
    const xdm = core.pcs.transposed_merkle_cascade;
    const host = @import("stwo_prover_engine").pcs.transposed_cascade_experimental;
    const alloc = std.testing.allocator;
    const first = [_]M31{M31.fromCanonical(3)} ** 32;
    const second = [_]M31{M31.fromCanonical(5)} ** 16;
    const third = [_]M31{M31.fromCanonical(7)} ** 8;
    const h0 = [_][]const M31{&first};
    const h1 = [_][]const M31{&second};
    const h2 = [_][]const M31{&third};
    const heights = [_][]const []const M31{ &h0, &h1, &h2 };
    var tree = try host.Commitment.commit(alloc, &heights);
    defer tree.deinit();
    const raw = [_]usize{ 1, 9, 1 };
    const encoded = try tree.encodeOpenings(alloc, &raw);
    defer alloc.free(encoded);
    var profile = tree.profile;
    profile.query_count = raw.len;
    var opened = try xdm.verifyAndCollect(alloc, encoded, profile, tree.root(), &raw);
    defer opened.deinit();
    for (0..raw.len) |query| {
        for (0..8) |row| try std.testing.expectEqual(first[0], opened.at(0, query, row, 0));
        for (0..4) |row| try std.testing.expectEqual(second[0], opened.at(1, query, row, 0));
        for (0..2) |row| try std.testing.expectEqual(third[0], opened.at(2, query, row, 0));
    }
    var bad_root = tree.root();
    bad_root[0] ^= 1;
    try std.testing.expectError(
        error.UnexpectedCascadeRoot,
        xdm.verifyAndCollect(alloc, encoded, profile, bad_root, &raw),
    );
    const wrong_raw = [_]usize{ 1, 8, 1 };
    try std.testing.expectError(
        error.UnexpectedCascadeQuery,
        xdm.verifyAndCollect(alloc, encoded, profile, tree.root(), &wrong_raw),
    );
    var oversized = xdm.Profile{
        .largest_log_size = 16,
        .height_count = 8,
        .columns = [_]u16{64} ** xdm.MAX_HEIGHTS,
        .query_count = 1 << 14,
    };
    try std.testing.expectError(error.InvalidCascadeProfile, oversized.validate());
    oversized.query_count = 1;
    try oversized.validate();
    const changed = try alloc.dupe(u8, encoded);
    defer alloc.free(changed);
    const header = try xdm.inspectHeader(encoded);
    try std.testing.expect(std.meta.eql(profile, header.profile));
    const first_felt_at = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 + 2 * profile.height_count + 32 + 4;
    changed[first_felt_at] ^= 1;
    try std.testing.expectError(
        error.DuplicateProjectedValue,
        xdm.verifyAndCollect(alloc, changed, profile, tree.root(), &raw),
    );
}

test "XDM04 authenticates sparse pairs and preserves duplicate raw queries" {
    const core = @import("stwo_core");
    const sparse = core.pcs.transposed_merkle_sparse;
    const host = @import("stwo_prover_engine").pcs.transposed_cascade_experimental;
    const alloc = std.testing.allocator;
    var first: [32]M31 = undefined;
    var second: [16]M31 = undefined;
    var third: [8]M31 = undefined;
    for (&first, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row + 1));
    for (&second, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row + 41));
    for (&third, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row + 71));
    const h0 = [_][]const M31{&first};
    const h1 = [_][]const M31{&second};
    const h2 = [_][]const M31{&third};
    const heights = [_][]const []const M31{ &h0, &h1, &h2 };
    var tree = try host.Commitment.commit(alloc, &heights);
    defer tree.deinit();
    const raw = [_]usize{ 5, 5, 23 };
    const encoded = try tree.encodeSparseOpenings(alloc, &raw);
    defer alloc.free(encoded);
    const profile = sparse.Profile{
        .largest_log_size = tree.profile.largest_log_size,
        .height_count = tree.profile.height_count,
        .columns = tree.profile.columns,
        .query_count = raw.len,
    };
    try sparse.validateEncoding(encoded, profile, tree.root());
    var opened = try sparse.verifyAndCollect(alloc, encoded, profile, tree.root(), &raw);
    defer opened.deinit();
    for (raw, 0..) |position, query| {
        for (0..3) |height| {
            const base = sparse.pairBase(position, height);
            const source = heights[height][0];
            for (0..2) |j|
                try std.testing.expectEqual(source[base + j], opened.at(height, query, j, 0));
        }
    }
    const wrong_raw = [_]usize{ 5, 7, 23 };
    try std.testing.expectError(error.UnexpectedSparseQuery, sparse.verifyAndCollect(alloc, encoded, profile, tree.root(), &wrong_raw));
    var wrong_root = tree.root();
    wrong_root[0] ^= 1;
    try std.testing.expectError(error.UnexpectedSparseRoot, sparse.verifyAndCollect(alloc, encoded, profile, wrong_root, &raw));
    const changed = try alloc.dupe(u8, encoded);
    defer alloc.free(changed);
    const header_len = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 + 2 * profile.height_count + 32;
    const per_query = 4 + 3 * 2 * 4;
    changed[header_len + per_query + 4] ^= 1;
    try std.testing.expectError(error.DuplicateProjectedValue, sparse.verifyAndCollect(alloc, changed, profile, tree.root(), &raw));
    const overlap_cases = [_][4]usize{
        .{ 0, 1, 2, 3 }, .{ 4, 5, 6, 7 }, .{ 5, 7, 13, 15 }, .{ 0, 0, 0, 0 },
    };
    for (overlap_cases) |case| {
        const bytes = try tree.encodeSparseOpenings(alloc, &case);
        defer alloc.free(bytes);
        var case_profile = profile;
        case_profile.query_count = case.len;
        var verified = try sparse.verifyAndCollect(alloc, bytes, case_profile, tree.root(), &case);
        defer verified.deinit();
        for (case, 0..) |position, query|
            for (0..3) |height| {
                const base = sparse.pairBase(position, height);
                for (0..2) |j|
                    try std.testing.expectEqual(heights[height][0][base + j], verified.at(height, query, j, 0));
            };
    }
}

test "XDM04 verifies a log-22 sparse path without a dense prover tree" {
    const core = @import("stwo_core");
    const sparse = core.pcs.transposed_merkle_sparse;
    const tree = core.pcs.transposed_merkle_cascade;
    const alloc = std.testing.allocator;
    const profile = sparse.Profile{
        .largest_log_size = 22,
        .height_count = 2,
        .columns = .{ 1, 1, 0, 0, 0, 0, 0, 0 },
        .query_count = 1,
    };
    try profile.validate();
    const wide = sparse.Profile{
        .largest_log_size = 22,
        .height_count = 8,
        .columns = [_]u16{1} ** tree.MAX_HEIGHTS,
        .query_count = 1024,
    };
    try wide.validate(); // full-fiber XDM03 rejected this geometry.
    var over_budget = wide;
    over_budget.columns = [_]u16{64} ** tree.MAX_HEIGHTS;
    over_budget.query_count = 1 << 14;
    try std.testing.expectError(error.InvalidCascadeProfile, over_budget.validate());
    var too_tall = wide;
    too_tall.largest_log_size = sparse.MAX_LOG_SIZE + 1;
    try std.testing.expectError(error.InvalidCascadeProfile, too_tall.validate());

    const Hash = tree.Hash;
    const first = [_]M31{M31.fromCanonical(1)};
    const second = [_]M31{M31.fromCanonical(2)};
    const third = [_]M31{M31.fromCanonical(3)};
    const fourth = [_]M31{M31.fromCanonical(4)};
    var witness: [42]Hash = undefined;
    for (&witness, 0..) |*hash, i| hash.* = [_]u8{@intCast(i + 1)} ** 32;
    const leaf4 = tree.hashLeaf(&first);
    const leaf5 = tree.hashLeaf(&second);
    var left = tree.hashInserted(leaf4, witness[0], &third);
    var right = tree.hashInserted(leaf5, witness[1], &fourth);
    // At level 21 the known inserted nodes occupy indices 2 and 3.
    // Their upper siblings at 0 and 1 precede the 20 ordinary levels.
    left = tree.hashUpper(witness[2], left);
    right = tree.hashUpper(witness[3], right);
    var at: usize = 4;
    while (at < witness.len) : (at += 2) {
        left = tree.hashUpper(left, witness[at]);
        right = tree.hashUpper(right, witness[at + 1]);
    }
    const root = tree.hashUpper(left, right);

    var bytes = std.ArrayList(u8).empty;
    defer bytes.deinit(alloc);
    const w = bytes.writer(alloc);
    try w.writeAll(sparse.MAGIC);
    try w.writeInt(u16, sparse.VERSION, .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, 0, .little);
    try w.writeInt(u32, profile.largest_log_size, .little);
    try w.writeInt(u16, @intCast(profile.height_count), .little);
    try w.writeInt(u16, 0, .little);
    try w.writeInt(u32, @intCast(profile.query_count), .little);
    for (profile.columns[0..profile.height_count]) |count| try w.writeInt(u16, count, .little);
    try w.writeAll(&root);
    try w.writeInt(u32, 5, .little);
    for ([_]u32{ 1, 2, 3, 4 }) |value| try w.writeInt(u32, value, .little);
    try w.writeInt(u32, witness.len, .little);
    for (witness) |hash| try w.writeAll(&hash);
    std.mem.writeInt(u32, bytes.items[12..16], @intCast(bytes.items.len), .little);
    try sparse.validateEncoding(bytes.items, profile, root);
    var opened = try sparse.verifyAndCollect(alloc, bytes.items, profile, root, &.{5});
    defer opened.deinit();
    try std.testing.expectEqual(@as(u32, 1), opened.at(0, 0, 0, 0).toU32());
    try std.testing.expectEqual(@as(u32, 2), opened.at(0, 0, 1, 0).toU32());
    try std.testing.expectEqual(@as(u32, 3), opened.at(1, 0, 0, 0).toU32());
    try std.testing.expectEqual(@as(u32, 4), opened.at(1, 0, 1, 0).toU32());
    for ([_]usize{ 0, 1, 5, (1 << 21) + 7, (1 << 22) - 1 }) |raw| {
        var point = core.poly.circle.canonic.CanonicCoset.new(22).circleDomain()
            .at(core.utils.bitReverseIndex(raw, 22));
        for (0..8) |height| {
            const log_size: u32 = 22 - @as(u32, @intCast(height));
            const row = sparse.pairBase(raw, height) | (raw & 1);
            const expected = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain()
                .at(core.utils.bitReverseIndex(row, log_size));
            try std.testing.expect(point.eql(expected));
            point = point.double();
        }
    }
}

test "sparse pair schedule matches circle doubling and line fold positions" {
    const core = @import("stwo_core");
    const sparse = core.pcs.transposed_merkle_sparse;
    const k: u32 = 6;
    const largest = core.poly.circle.canonic.CanonicCoset.new(k).circleDomain();
    for (0..64) |raw| {
        var point = largest.at(core.utils.bitReverseIndex(raw, k));
        for (0..4) |height| {
            const log_size = k - @as(u32, @intCast(height));
            const base = sparse.pairBase(raw, height);
            try std.testing.expectEqual(2 * (raw >> @intCast(height + 1)), base);
            const projected_row = base | (raw & 1);
            const expected = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain()
                .at(core.utils.bitReverseIndex(projected_row, log_size));
            try std.testing.expect(point.eql(expected));
            if (height < 3) {
                const next_base = sparse.pairBase(raw, height + 1);
                const output = base / 2;
                try std.testing.expectEqual(next_base + ((raw >> @intCast(height + 1)) & 1), output);
            }
            point = point.double();
        }
    }
    for (0..4) |height| {
        const shift: std.math.Log2Int(usize) = @intCast(height);
        const domain_size: usize = @as(usize, 64) >> shift;
        for (0..domain_size) |projected_row| {
            var count: usize = 0;
            for (0..64) |raw|
                if ((sparse.pairBase(raw, height) | (raw & 1)) == projected_row) {
                    count += 1;
                };
            try std.testing.expectEqual(@as(usize, 1) << shift, count);
        }
    }
}

test "P2F02 one-root paired proof binds statement and rolls back late failures" {
    const core = @import("stwo_core");
    const host = @import("stwo_prover_engine").pcs.paired_two_height_v2_experimental;
    const wire = core.pcs.paired_two_height_v2_wire;
    const old_wire = core.pcs.paired_two_height_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var x0: [32]M31 = undefined;
    var x1: [16]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 5)).x;
    for (&x1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 4)).x;
    const c0 = [_]M31{M31.fromCanonical(7)} ** 32;
    const c1 = [_]M31{M31.fromCanonical(11)} ** 16;
    const first = [_][]const M31{ &x0, &c0 };
    const second = [_][]const M31{ &x1, &c1 };
    const input = host.Input{
        .largest_log_size = 5,
        .log_blowup = 2,
        .n_queries = 5,
        .first_columns = &first,
        .second_columns = &second,
    };
    var prover_channel = Channel{};
    const encoded = try host.prove(alloc, input, &prover_channel);
    defer alloc.free(encoded);
    var decoded = try wire.decode(alloc, encoded);
    defer decoded.deinit();
    const proof = decoded.proof;
    const statement = wire.ExpectedStatement{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .large_claims = proof.large_claims,
        .small_claims = proof.small_claims,
    };
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(alloc, encoded, &verifier_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectError(error.UnsupportedProofFormat, old_wire.decode(alloc, encoded));
    var wrong_root = statement;
    wrong_root.source_root[0] ^= 1;
    var rejected = Channel{};
    const initial = rejected.digest;
    try std.testing.expectError(
        error.UnexpectedPairedStatement,
        wire.verifyAgainstStatement(alloc, encoded, &rejected, wrong_root),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_profile = statement;
    wrong_profile.profile.n_queries += 1;
    try std.testing.expectError(
        error.UnexpectedPairedStatement,
        wire.verifyAgainstStatement(alloc, encoded, &rejected, wrong_profile),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_claims = try alloc.dupe(QM31, proof.large_claims);
    defer alloc.free(wrong_claims);
    wrong_claims[0] = wrong_claims[0].add(QM31.one());
    var wrong_statement = statement;
    wrong_statement.large_claims = wrong_claims;
    try std.testing.expectError(
        error.UnexpectedPairedStatement,
        wire.verifyAgainstStatement(alloc, encoded, &rejected, wrong_statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_outer = try alloc.dupe(u8, encoded);
    defer alloc.free(wrong_outer);
    wrong_outer[8] = 3;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        wire.verifyAgainstStatement(alloc, wrong_outer, &rejected, statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_inner = try alloc.dupe(u8, encoded);
    defer alloc.free(wrong_inner);
    const inner_at = std.mem.indexOf(u8, wrong_inner, core.pcs.transposed_merkle.MAGIC).?;
    wrong_inner[inner_at + 8] = 3;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        wire.verifyAgainstStatement(alloc, wrong_inner, &rejected, statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_point_proof = proof;
    wrong_point_proof.sampled_point = core.circle.CirclePointQM31.zero();
    const wrong_point = try wire.encode(alloc, wrong_point_proof);
    defer alloc.free(wrong_point);
    try std.testing.expectError(
        error.UnsampledOodPoint,
        wire.verifyAgainstStatement(alloc, wrong_point, &rejected, statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_terminal_proof = proof;
    const changed_terminal = try alloc.dupe(QM31, proof.terminal_ordered_coeffs);
    defer alloc.free(changed_terminal);
    changed_terminal[0] = changed_terminal[0].add(QM31.one());
    wrong_terminal_proof.terminal_ordered_coeffs = changed_terminal;
    const wrong_terminal = try wire.encode(alloc, wrong_terminal_proof);
    defer alloc.free(wrong_terminal);
    if (wire.verifyAgainstStatement(alloc, wrong_terminal, &rejected, statement)) |_| {
        return error.ExpectedProofRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_source = try alloc.dupe(u8, encoded);
    defer alloc.free(wrong_source);
    const xdm_at = std.mem.indexOf(u8, wrong_source, core.pcs.transposed_merkle.MAGIC).?;
    wrong_source[xdm_at + 64] ^= 1; // first opened source felt
    try std.testing.expectError(
        error.RootMismatch,
        wire.verifyAgainstStatement(alloc, wrong_source, &rejected, statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    var wrong_line_proof = proof;
    var line_columns = proof.intermediate.queried_coordinates;
    const changed_column = try alloc.dupe(M31, line_columns[0]);
    defer alloc.free(changed_column);
    changed_column[0] = changed_column[0].add(M31.one());
    line_columns[0] = changed_column;
    wrong_line_proof.intermediate.queried_coordinates = line_columns;
    const wrong_line = try wire.encode(alloc, wrong_line_proof);
    defer alloc.free(wrong_line);
    try std.testing.expectError(
        error.RootMismatch,
        wire.verifyAgainstStatement(alloc, wrong_line, &rejected, statement),
    );
    try std.testing.expectEqualSlices(u8, &initial, &rejected.digest);
    const old_prover = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
    var old_channel = Channel{};
    const old_encoded = try old_prover.prove(alloc, input, &old_channel);
    defer alloc.free(old_encoded);
    try std.testing.expectEqual(@as(usize, 1012), encoded.len);
    try std.testing.expectEqual(@as(usize, 1180), old_encoded.len);
}

fn checkP2F02Geometry(
    comptime log_size: u32,
    n_queries: usize,
    expected_v2_bytes: usize,
    expected_v1_bytes: usize,
) !void {
    const core = @import("stwo_core");
    const host = @import("stwo_prover_engine").pcs.paired_two_height_v2_experimental;
    const old_host = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
    const wire = core.pcs.paired_two_height_v2_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const size = @as(usize, 1) << @intCast(log_size);
    const d0 = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
    var x0: [size]M31 = undefined;
    var x1: [size / 2]M31 = undefined;
    for (&x0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, log_size)).x;
    for (&x1) |*value| value.* = M31.fromCanonical(11);
    const first = [_][]const M31{&x0};
    const second = [_][]const M31{&x1};
    const input = host.Input{
        .largest_log_size = log_size,
        .log_blowup = 2,
        .n_queries = n_queries,
        .first_columns = &first,
        .second_columns = &second,
    };
    var prover_channel = Channel{};
    const encoded = try host.prove(alloc, input, &prover_channel);
    defer alloc.free(encoded);
    var decoded = try wire.decode(alloc, encoded);
    defer decoded.deinit();
    const proof = decoded.proof;
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(alloc, encoded, &verifier_channel, .{
        .profile = proof.profile,
        .source_root = proof.source_root,
        .large_claims = proof.large_claims,
        .small_claims = proof.small_claims,
    });
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    var old_channel = Channel{};
    const old_encoded = try old_host.prove(alloc, input, &old_channel);
    defer alloc.free(old_encoded);
    try std.testing.expectEqual(expected_v2_bytes, encoded.len);
    try std.testing.expectEqual(expected_v1_bytes, old_encoded.len);
}

test "P2F02 roundtrips at adjacent 16/8 and 64/32 heights" {
    try checkP2F02Geometry(4, 4, 592, 748);
    try checkP2F02Geometry(6, 7, 1300, 1180);
}

test "experimental paired source and native quotient roundtrip through FRI" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Prover = FriProver(CpuBackend, Hasher, MerkleChannel);
    const Verifier = core_fri.FriVerifier(Hasher, MerkleChannel);
    const TreeVec = core.pcs.TreeVec;
    const alloc = std.testing.allocator;

    const shape = paired.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 1,
    };
    const config = try core_fri.FriConfig.init(0, 1, 4);
    const domain = core.poly.circle.canonic.CanonicCoset.new(shape.log_domain_size).circleDomain();
    var original: [8]M31 = undefined;
    var all_positions: [8]usize = undefined;
    for (&original, &all_positions, 0..) |*value, *position, row| {
        position.* = row;
        value.* = domain.at(core.utils.bitReverseIndex(row, shape.log_domain_size)).x;
    }

    const sample_point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    var column_logs = [_]u32{shape.log_domain_size};
    var logs_tree = [_][]u32{column_logs[0..]};
    var point_column = [_]core.circle.CirclePointQM31{sample_point};
    var points_tree = [_][]core.circle.CirclePointQM31{point_column[0..]};
    var points = [_][][]core.circle.CirclePointQM31{points_tree[0..]};
    var value_column = [_]QM31{sample_point.x};
    var values_tree = [_][]QM31{value_column[0..]};
    var sampled_values = [_][][]QM31{values_tree[0..]};
    var original_tree = [_][]M31{original[0..]};
    var original_queried = [_][][]M31{original_tree[0..]};
    const deep_randomness = QM31.fromBase(M31.fromCanonical(17));
    const all_quotient = try core.pcs.quotients.friAnswers(
        alloc,
        TreeVec([]u32).initOwned(logs_tree[0..]),
        TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        TreeVec([][]QM31).initOwned(sampled_values[0..]),
        deep_randomness,
        all_positions[0..],
        TreeVec([][]M31).initOwned(original_queried[0..]),
        shape.log_domain_size,
    );
    defer alloc.free(all_quotient);
    var nonzero_quotient = false;
    for (all_quotient) |value| {
        nonzero_quotient = nonzero_quotient or !value.eql(QM31.zero());
    }
    try std.testing.expect(nonzero_quotient);

    const source_columns = [_][]const M31{original[0..]};
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    var source_tree = try SourceProver.commit(alloc, &source_columns);
    defer source_tree.deinit(alloc);
    const source_root = source_tree.root();

    var prover_channel = Channel{};
    MerkleChannel.mixRoot(&prover_channel, source_root);
    prover_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
    const prover_challenges = try paired.drawChallenges(&prover_channel, shape);
    const quotient_columns = [_][]const QM31{all_quotient};
    const paired_values = try paired.foldColumns(
        alloc,
        &source_columns,
        &quotient_columns,
        shape,
        prover_challenges,
    );
    defer alloc.free(paired_values);
    const column = try secure_column.SecureColumnByCoords.fromSecureSlice(alloc, paired_values);
    var prover = try Prover.commit(alloc, &prover_channel, config, domain, column);
    var decommit_result = try prover.decommit(alloc, &prover_channel);
    defer decommit_result.deinit(alloc);

    var verifier_channel = Channel{};
    MerkleChannel.mixRoot(&verifier_channel, source_root);
    verifier_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
    const verifier_challenges = try paired.drawChallenges(&verifier_channel, shape);
    try std.testing.expect(prover_challenges.batch.eql(verifier_challenges.batch));
    var verifier = try Verifier.commit(
        alloc,
        &verifier_channel,
        config,
        decommit_result.fri_proof.proof,
        core_fri.CirclePolyDegreeBound.init(shape.log_degree_bound),
    );
    defer verifier.deinit(alloc);
    const positions = try verifier.sampleQueryPositions(alloc, &verifier_channel);
    defer alloc.free(positions);
    try std.testing.expectEqualSlices(usize, decommit_result.query_positions, positions);

    var source_opening = try source_tree.decommit(alloc, positions, &source_columns);
    defer source_opening.deinit(alloc);
    const queried_original = source_opening.queried_values[0];
    var queried_original_tree = [_][]M31{queried_original};
    var queried_original_all = [_][][]M31{queried_original_tree[0..]};
    const queried_quotient = try core.pcs.quotients.friAnswers(
        alloc,
        TreeVec([]u32).initOwned(logs_tree[0..]),
        TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        TreeVec([][]QM31).initOwned(sampled_values[0..]),
        deep_randomness,
        positions,
        TreeVec([][]M31).initOwned(queried_original_all[0..]),
        shape.log_domain_size,
    );
    defer alloc.free(queried_quotient);
    const answers = try alloc.alloc(QM31, positions.len);
    defer alloc.free(answers);
    for (answers, queried_original, queried_quotient) |*answer, source, quotient| {
        answer.* = try paired.foldRow(&[_]M31{source}, &[_]QM31{quotient}, shape, verifier_challenges);
    }
    for (answers, positions) |answer, position| {
        try std.testing.expect(answer.eql(paired_values[position]));
    }
    const SourceVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
    var source_verifier = try SourceVerifier.init(alloc, source_root, &[_]u32{shape.log_domain_size});
    defer source_verifier.deinit(alloc);
    const authenticated_sources = [_][]const M31{queried_original};
    const authenticated_answers = try core.pcs.paired_authenticated.authenticatedAnswers(
        Hasher,
        alloc,
        source_verifier,
        positions,
        &authenticated_sources,
        source_opening.decommitment.decommitment,
        &[_]core.circle.CirclePointQM31{sample_point},
        &[_]QM31{sample_point.x},
        shape,
        verifier_challenges,
    );
    defer alloc.free(authenticated_answers);
    try std.testing.expectEqualSlices(QM31, answers, authenticated_answers);
    try verifier.decommit(alloc, authenticated_answers);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // A changed authenticated source is refused before a paired answer exists.
    const corrupted_source = try alloc.dupe(M31, queried_original);
    defer alloc.free(corrupted_source);
    corrupted_source[0] = corrupted_source[0].add(M31.one());
    const corrupted_sources = [_][]const M31{corrupted_source};
    try std.testing.expectError(
        error.RootMismatch,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            source_verifier,
            positions,
            &corrupted_sources,
            source_opening.decommitment.decommitment,
            &[_]core.circle.CirclePointQM31{sample_point},
            &[_]QM31{sample_point.x},
            shape,
            verifier_challenges,
        ),
    );

    // A changed paired answer must fail the same first-layer authentication.
    var bad_channel = Channel{};
    MerkleChannel.mixRoot(&bad_channel, source_root);
    bad_channel.mixFelts(&[_]QM31{ sample_point.x, sample_point.y, sample_point.x });
    _ = try paired.drawChallenges(&bad_channel, shape);
    var bad_verifier = try Verifier.commit(
        alloc,
        &bad_channel,
        config,
        decommit_result.fri_proof.proof,
        core_fri.CirclePolyDegreeBound.init(shape.log_degree_bound),
    );
    defer bad_verifier.deinit(alloc);
    const bad_positions = try bad_verifier.sampleQueryPositions(alloc, &bad_channel);
    defer alloc.free(bad_positions);
    const bad_answers = try alloc.dupe(QM31, answers);
    defer alloc.free(bad_answers);
    bad_answers[0] = bad_answers[0].add(QM31.one());
    if (bad_verifier.decommit(alloc, bad_answers)) |_| {
        return error.ExpectedPairedAnswerRejection;
    } else |err| {
        try std.testing.expect(err != error.OutOfMemory);
    }
}

test "paired ensemble binds shape and includes each source exactly once" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const shape = paired.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 2,
    };
    var channel = Channel{};
    const challenges = try paired.drawChallenges(&channel, shape);
    const source0 = [_]M31{M31.fromCanonical(3)} ** 8;
    const source1 = [_]M31{M31.fromCanonical(5)} ** 8;
    const quotient0 = [_]QM31{QM31.fromBase(M31.fromCanonical(7))} ** 8;
    const quotient1 = [_]QM31{QM31.fromBase(M31.fromCanonical(11))} ** 8;
    const columns = [_][]const M31{ &source0, &source1 };
    const quotients = [_][]const QM31{ &quotient0, &quotient1 };
    const folded = try paired.foldColumns(alloc, &columns, &quotients, shape, challenges);
    defer alloc.free(folded);
    const expected = try paired.foldRow(
        &[_]M31{ source0[0], source1[0] },
        &[_]QM31{ quotient0[0], quotient1[0] },
        shape,
        challenges,
    );
    const lambda = challenges.batch;
    const manual = QM31.fromBase(source0[0])
        .add(lambda.mul(quotient0[0]))
        .add(lambda.square().mul(QM31.fromBase(source1[0])))
        .add(lambda.square().mul(lambda).mul(quotient1[0]));
    try std.testing.expect(expected.eql(manual));
    for (folded) |value| try std.testing.expect(value.eql(expected));
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldRow(&[_]M31{source0[0]}, &[_]QM31{quotient0[0]}, shape, challenges),
    );
    try std.testing.expectError(
        error.InvalidPairedShape,
        paired.foldColumns(alloc, columns[0..1], &quotients, shape, challenges),
    );

    var changed_channel = Channel{};
    _ = try paired.drawChallenges(&changed_channel, .{
        .log_domain_size = 4,
        .log_degree_bound = 2,
        .original_column_count = 2,
    });
    try std.testing.expect(!std.mem.eql(u8, &channel.digest, &changed_channel.digest));
}

test "paired authenticated bridge binds both source columns and their order" {
    const core = @import("stwo_core");
    const paired = core.pcs.paired_ensemble;
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const SourceVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher);
    const alloc = std.testing.allocator;
    const shape = paired.Shape{ .log_domain_size = 3, .log_degree_bound = 2, .original_column_count = 2 };
    const original0 = [_]M31{M31.fromCanonical(3)} ** 8;
    const original1 = [_]M31{M31.fromCanonical(5)} ** 8;
    const source_columns = [_][]const M31{ &original0, &original1 };
    var source_tree = try SourceProver.commit(alloc, &source_columns);
    defer source_tree.deinit(alloc);
    const positions = [_]usize{ 0, 3, 7 };
    var source_opening = try source_tree.decommit(alloc, &positions, &source_columns);
    defer source_opening.deinit(alloc);
    var source_verifier = try SourceVerifier.init(alloc, source_tree.root(), &[_]u32{ 3, 3 });
    defer source_verifier.deinit(alloc);
    const query_columns = [_][]const M31{
        source_opening.queried_values[0],
        source_opening.queried_values[1],
    };
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const points = [_]core.circle.CirclePointQM31{ point, point };
    const claims = [_]QM31{
        QM31.fromBase(original0[0]),
        QM31.fromBase(original1[0]),
    };
    var channel = Channel{};
    MerkleChannel.mixRoot(&channel, source_tree.root());
    channel.mixFelts(&[_]QM31{ point.x, point.y, claims[0], claims[1] });
    const challenges = try paired.drawChallenges(&channel, shape);
    const answers = try core.pcs.paired_authenticated.authenticatedAnswers(
        Hasher,
        alloc,
        source_verifier,
        &positions,
        &query_columns,
        source_opening.decommitment.decommitment,
        &points,
        &claims,
        shape,
        challenges,
    );
    defer alloc.free(answers);
    for (answers, source_opening.queried_values[0], source_opening.queried_values[1]) |answer, f0, f1| {
        const expected = try paired.foldRow(
            &[_]M31{ f0, f1 },
            &[_]QM31{ QM31.zero(), QM31.zero() },
            shape,
            challenges,
        );
        try std.testing.expect(answer.eql(expected));
    }

    const swapped = [_][]const M31{
        source_opening.queried_values[1],
        source_opening.queried_values[0],
    };
    try std.testing.expectError(
        error.RootMismatch,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            source_verifier,
            &positions,
            &swapped,
            source_opening.decommitment.decommitment,
            &points,
            &claims,
            shape,
            challenges,
        ),
    );
    var wrong_height = try SourceVerifier.init(alloc, source_tree.root(), &[_]u32{ 3, 2 });
    defer wrong_height.deinit(alloc);
    try std.testing.expectError(
        error.InvalidPairedShape,
        core.pcs.paired_authenticated.authenticatedAnswers(
            Hasher,
            alloc,
            wrong_height,
            &positions,
            &query_columns,
            source_opening.decommitment.decommitment,
            &points,
            &claims,
            shape,
            challenges,
        ),
    );
}

fn manualNativeEq68Row(
    previous_even: QM31,
    previous_odd: QM31,
    x: M31,
    inserted_even: QM31,
    inserted_odd: QM31,
    y: M31,
    alpha: QM31,
) !QM31 {
    // Native inverse butterflies omit division by two. This is the row-level
    // Eq. 68 relation in the existing FRI evaluation convention.
    const previous_fold = previous_even.add(previous_odd).add(
        alpha.mul(previous_even.sub(previous_odd).mulM31(try x.inv())),
    );
    const inserted_fold = inserted_even.add(inserted_odd).add(
        alpha.mul(inserted_even.sub(inserted_odd).mulM31(try y.inv())),
    );
    return previous_fold.add(alpha.square().mul(inserted_fold));
}

test "experimental multi-domain insertion matches native relation at two smaller heights" {
    const core = @import("stwo_core");
    const insert = core_fri.multidomain_insertion.insertCircleBatch;
    const alloc = std.testing.allocator;
    const h0_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const h1_domain = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const h2_domain = core.poly.circle.canonic.CanonicCoset.new(2).circleDomain();
    const g0_domain = core.poly.line.LineDomain.fromCircleDomain(h0_domain);
    var h0: [16]QM31 = undefined;
    var h1: [8]QM31 = undefined;
    var h2: [4]QM31 = undefined;
    for (&h0, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(3 * i + 5)));
    for (&h1, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(5 * i + 7)));
    for (&h2, 0..) |*value, i| value.* = QM31.fromBase(M31.fromCanonical(@intCast(7 * i + 11)));
    const alpha0 = QM31.fromU32Unchecked(2, 3, 0, 1);
    const alpha1 = QM31.fromU32Unchecked(5, 0, 7, 1);
    const alpha2 = QM31.fromU32Unchecked(11, 3, 2, 0);

    // First height has no previous line layer. The following two heights
    // insert into a previously folded line word.
    var g0 = [_]QM31{QM31.zero()} ** 8;
    var circle_workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer circle_workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        &h0,
        h0_domain,
        alpha0,
        &circle_workspace,
    );

    const g1 = try insert(alloc, &g0, g0_domain, &h1, h1_domain, alpha1);
    defer alloc.free(g1.values);
    try std.testing.expect(g1.domain.coset().eql(h1_domain.half_coset));
    for (g1.values, 0..) |actual, i| {
        const x = g0_domain.at(core.utils.bitReverseIndex(i * 2, g0_domain.logSize()));
        const y = h1_domain.at(core.utils.bitReverseIndex(i * 2, h1_domain.logSize())).y;
        const expected = try manualNativeEq68Row(
            g0[2 * i],
            g0[2 * i + 1],
            x,
            h1[2 * i],
            h1[2 * i + 1],
            y,
            alpha1,
        );
        try std.testing.expect(actual.eql(expected));
    }

    const g2 = try insert(alloc, g1.values, g1.domain, &h2, h2_domain, alpha2);
    defer alloc.free(g2.values);
    try std.testing.expect(g2.domain.coset().eql(h2_domain.half_coset));
    for (g2.values, 0..) |actual, i| {
        const x = g1.domain.at(core.utils.bitReverseIndex(i * 2, g1.domain.logSize()));
        const y = h2_domain.at(core.utils.bitReverseIndex(i * 2, h2_domain.logSize())).y;
        const expected = try manualNativeEq68Row(
            g1.values[2 * i],
            g1.values[2 * i + 1],
            x,
            h2[2 * i],
            h2[2 * i + 1],
            y,
            alpha2,
        );
        try std.testing.expect(actual.eql(expected));
    }

    // The insertion kernel may not coerce a wrong height or an unrelated
    // equal-sized circle coset into this cascade.
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, &g0, g0_domain, &h2, h2_domain, alpha1),
    );
    const shifted = h1_domain.shift(h1_domain.half_coset.step_size);
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, &g0, g0_domain, &h1, shifted, alpha1),
    );
    try std.testing.expectError(
        error.InvalidInsertionGeometry,
        insert(alloc, g0[0..7], g0_domain, &h1, h1_domain, alpha1),
    );
}

test "experimental multi-domain insertion preserves an explicit low-degree cascade" {
    const core = @import("stwo_core");
    const insert = core_fri.multidomain_insertion.insertCircleBatch;
    const alloc = std.testing.allocator;
    const h0_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const h1_domain = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const h2_domain = core.poly.circle.canonic.CanonicCoset.new(2).circleDomain();
    const g0_domain = core.poly.line.LineDomain.fromCircleDomain(h0_domain);
    var h0: [16]QM31 = undefined;
    var h1: [8]QM31 = undefined;
    const c = QM31.fromBase(M31.fromCanonical(9));
    const h2 = [_]QM31{c} ** 4;
    for (&h0, 0..) |*value, row| {
        value.* = QM31.fromBase(h0_domain.at(core.utils.bitReverseIndex(row, 4)).x);
    }
    for (&h1, 0..) |*value, row| {
        value.* = QM31.fromBase(h1_domain.at(core.utils.bitReverseIndex(row, 3)).x);
    }
    const alpha0 = QM31.fromBase(M31.fromCanonical(3));
    const alpha1 = QM31.fromBase(M31.fromCanonical(5));
    const alpha2 = QM31.fromBase(M31.fromCanonical(7));

    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        &h0,
        h0_domain,
        alpha0,
        &workspace,
    );
    for (g0, 0..) |value, row| {
        const x = g0_domain.at(core.utils.bitReverseIndex(row, g0_domain.logSize()));
        try std.testing.expect(value.eql(QM31.fromBase(x).mulM31(M31.fromCanonical(2))));
    }

    const g1 = try insert(alloc, &g0, g0_domain, &h1, h1_domain, alpha1);
    defer alloc.free(g1.values);
    const g2 = try insert(alloc, g1.values, g1.domain, &h2, h2_domain, alpha2);
    defer alloc.free(g2.values);

    // Native butterflies are unnormalized: x circle-folds to 2x, then line
    // folds to 4*alpha. The second line fold and constant insertion give a
    // constant expression despite the two distinct source heights.
    const expected = QM31.fromBase(M31.fromCanonical(8)).mul(alpha1)
        .add(QM31.fromBase(M31.fromCanonical(4)).mul(alpha1.square()).mul(alpha2))
        .add(QM31.fromBase(M31.fromCanonical(2)).mul(alpha2.square()).mul(c));
    for (g2.values) |value| try std.testing.expect(value.eql(expected));
}

test "experimental versioned multi-height source openings authenticate before insertion" {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const projection = core.pcs.paired_projection;
    const Hasher = envelope_mod.Hasher;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const shape0 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 4,
        .log_degree_bound = 3,
        .original_column_count = 1,
    };
    const shape1 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 1,
    };
    var f0: [16]M31 = undefined;
    var f1: [8]M31 = undefined;
    var queries: [16]usize = undefined;
    for (&f0, &queries, 0..) |*value, *query, row| {
        query.* = row;
        value.* = d0.at(core.utils.bitReverseIndex(row, 4)).x;
    }
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 3)).x;
    const projected = try projection.projectPositions(alloc, &queries, 4, 3);
    defer alloc.free(projected);
    try std.testing.expectError(
        error.QueryPositionOutOfRange,
        projection.projectPositions(alloc, &[_]usize{16}, 4, 3),
    );
    try std.testing.expectError(
        error.InvalidProjectionGeometry,
        projection.projectPositions(alloc, &queries, 4, 5),
    );
    for (queries, projected) |large, small| {
        const large_point = d0.at(core.utils.bitReverseIndex(large, 4));
        const small_point = d1.at(core.utils.bitReverseIndex(small, 3));
        try std.testing.expect(large_point.double().eql(small_point));
    }

    const columns0 = [_][]const M31{&f0};
    const columns1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &columns0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &columns1);
    defer tree1.deinit(alloc);
    var opened0 = try tree0.decommit(alloc, &queries, &columns0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected, &columns1);
    defer opened1.deinit(alloc);

    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const points = [_]core.circle.CirclePointQM31{point};
    const claims = [_]QM31{point.x};
    const queried0 = [_][]const M31{opened0.queried_values[0]};
    const queried1 = [_][]const M31{opened1.queried_values[0]};
    const heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried0,
            .hash_witness = opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried1,
            .hash_witness = opened1.decommitment.decommitment.hash_witness,
        },
    };
    const source_envelope = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = queries.len,
        .heights = &heights,
    };
    const encoded = try envelope_mod.encode(alloc, source_envelope);
    defer alloc.free(encoded);
    const expected_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = queries.len,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    };
    var verifier_channel = Channel{};
    var prepared = try envelope_mod.decodeAndBind(alloc, encoded, &verifier_channel, expected_profile);
    defer prepared.deinit();
    const proof = prepared.decoded.envelope;
    try std.testing.expectEqual(@as(usize, 2), proof.heights.len);
    const reencoded = try envelope_mod.encode(alloc, proof);
    defer alloc.free(reencoded);
    try std.testing.expectEqualSlices(u8, encoded, reencoded);
    var prover_channel = Channel{};
    const prover_challenges = try envelope_mod.drawChallenges(&prover_channel, source_envelope);
    const challenges = prepared.challenges;
    try std.testing.expect(prover_challenges.batch.eql(challenges.batch));

    const answers0 = try envelope_mod.authenticatedHeightAnswers(alloc, proof, 0, &queries, challenges);
    defer alloc.free(answers0);
    const answers1 = try envelope_mod.authenticatedHeightAnswers(alloc, proof, 1, &queries, challenges);
    defer alloc.free(answers1);
    var dense1: [8]QM31 = undefined;
    var seen = [_]bool{false} ** 8;
    for (projected, answers1) |position, answer| {
        if (seen[position]) {
            try std.testing.expect(dense1[position].eql(answer));
        } else {
            dense1[position] = answer;
            seen[position] = true;
        }
    }
    for (seen) |value| try std.testing.expect(value);

    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    const alpha0 = QM31.fromBase(M31.fromCanonical(3));
    const alpha1 = QM31.fromBase(M31.fromCanonical(5));
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        answers0,
        d0,
        alpha0,
        &workspace,
    );
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        core.poly.line.LineDomain.fromCircleDomain(d0),
        &dense1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    try std.testing.expectEqual(@as(usize, 4), g1.values.len);

    const changed = try alloc.dupe(M31, proof.heights[1].queried_sources[0]);
    defer alloc.free(changed);
    changed[0] = changed[0].add(M31.one());
    const changed_columns = [_][]const M31{changed};
    var changed_heights = [_]envelope_mod.HeightOpening{ proof.heights[0], proof.heights[1] };
    changed_heights[1].queried_sources = &changed_columns;
    const changed_proof = envelope_mod.Envelope{
        .largest_log_size = proof.largest_log_size,
        .query_count = proof.query_count,
        .heights = &changed_heights,
    };
    try std.testing.expectError(
        error.DuplicateQueryMismatch,
        envelope_mod.authenticatedHeightAnswers(alloc, changed_proof, 1, &queries, challenges),
    );

    const altered_wire = try alloc.dupe(u8, encoded);
    defer alloc.free(altered_wire);
    altered_wire[8] = 2;
    var rejected_channel = Channel{};
    const digest_before = rejected_channel.digest;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        envelope_mod.decodeAndBind(alloc, altered_wire, &rejected_channel, expected_profile),
    );
    try std.testing.expectEqualSlices(u8, &digest_before, &rejected_channel.digest);
    const wrong_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = queries.len,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape0 },
    };
    try std.testing.expectError(
        error.UnexpectedPairedProfile,
        envelope_mod.decodeAndBind(alloc, encoded, &rejected_channel, wrong_profile),
    );
    try std.testing.expectEqualSlices(u8, &digest_before, &rejected_channel.digest);
    @memcpy(altered_wire[0..8], "STWOPRW1");
    try std.testing.expectError(error.LegacyProofRequiresLegacyVerifier, envelope_mod.decode(alloc, altered_wire));
    @memcpy(altered_wire, encoded);
    std.mem.writeInt(u32, altered_wire[72..76], m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, envelope_mod.decode(alloc, altered_wire));
    const extended_wire = try alloc.alloc(u8, encoded.len + 1);
    defer alloc.free(extended_wire);
    @memcpy(extended_wire[0..encoded.len], encoded);
    extended_wire[encoded.len] = 0;
    try std.testing.expectError(error.InvalidPairedEnvelope, envelope_mod.decode(alloc, extended_wire));
}

fn pairedFullBatchForTest(
    allocator: std.mem.Allocator,
    source: []const M31,
    log_domain_size: u32,
    point: @import("stwo_core").circle.CirclePointQM31,
    claim: QM31,
    challenges: @import("stwo_core").pcs.paired_ensemble.Challenges,
) ![]QM31 {
    const core = @import("stwo_core");
    const shape = core.pcs.paired_ensemble.Shape{
        .log_domain_size = log_domain_size,
        .log_degree_bound = log_domain_size - 1,
        .original_column_count = 1,
    };
    const positions = try allocator.alloc(usize, source.len);
    defer allocator.free(positions);
    for (positions, 0..) |*position, i| position.* = i;
    var log_column = [_]u32{log_domain_size};
    var log_tree = [_][]u32{log_column[0..]};
    var point_column = [_]core.circle.CirclePointQM31{point};
    var point_tree = [_][]core.circle.CirclePointQM31{point_column[0..]};
    var points = [_][][]core.circle.CirclePointQM31{point_tree[0..]};
    var claim_column = [_]QM31{claim};
    var claim_tree = [_][]QM31{claim_column[0..]};
    var claims = [_][][]QM31{claim_tree[0..]};
    var source_tree = [_][]M31{@constCast(source)};
    var queried = [_][][]M31{source_tree[0..]};
    const quotient = try core.pcs.quotients.friAnswers(
        allocator,
        core.pcs.TreeVec([]u32).initOwned(log_tree[0..]),
        core.pcs.TreeVec([][]core.circle.CirclePointQM31).initOwned(points[0..]),
        core.pcs.TreeVec([][]QM31).initOwned(claims[0..]),
        QM31.one(),
        positions,
        core.pcs.TreeVec([][]M31).initOwned(queried[0..]),
        log_domain_size,
    );
    defer allocator.free(quotient);
    return core.pcs.paired_ensemble.foldColumns(
        allocator,
        &[_][]const M31{source},
        &[_][]const QM31{quotient},
        shape,
        challenges,
    );
}

fn directTwoPointQuotient(
    point: @import("stwo_core").circle.CirclePointQM31,
    claim: QM31,
    domain_point: @import("stwo_core").circle.CirclePointM31,
    value: M31,
) !QM31 {
    // This is the scalar geometric definition, independent of friAnswers'
    // sample batching, line-coefficient cache, and row accumulation.
    const CM31 = @import("stwo_core").fields.cm31.CM31;
    const conjugate = point.complexConjugate();
    const delta_y = conjugate.y.sub(point.y);
    const line_value = claim.add(try claim.complexConjugate().sub(claim)
        .mul(QM31.fromBase(domain_point.y).sub(point.y)).div(delta_y));
    const denominator = point.x.c0.sub(CM31.fromBase(domain_point.x)).mul(point.y.c1)
        .sub(point.y.c0.sub(CM31.fromBase(domain_point.y)).mul(point.x.c1));
    return QM31.fromBase(value).sub(line_value).mul(delta_y)
        .mulCM31(try denominator.inv());
}

fn directLagrangeLine(
    values: []const QM31,
    domain: @import("stwo_core").poly.line.LineDomain,
    x: QM31,
) !QM31 {
    const core = @import("stwo_core");
    var result = QM31.zero();
    for (values, 0..) |value, i| {
        const xi = QM31.fromBase(domain.at(core.utils.bitReverseIndex(i, domain.logSize())));
        var numerator = QM31.one();
        var denominator = QM31.one();
        for (values, 0..) |_, j| {
            if (j == i) continue;
            const xj = QM31.fromBase(domain.at(core.utils.bitReverseIndex(j, domain.logSize())));
            numerator = numerator.mul(x.sub(xj));
            denominator = denominator.mul(xi.sub(xj));
        }
        result = result.add(value.mul(try numerator.div(denominator)));
    }
    return result;
}

fn checkHonestAdjacentHeights(comptime largest_log: u32, n_queries: usize) !void {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const two_height = core.pcs.paired_two_height_fri;
    const wire = core.pcs.paired_two_height_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Hasher = envelope_mod.Hasher;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const LineEvaluation = @import("stwo_prover_engine").line.LineEvaluation;
    const alloc = std.testing.allocator;
    const smaller_log = largest_log - 1;
    const larger_len = @as(usize, 1) << largest_log;
    const smaller_len = larger_len / 2;
    const terminal_len = smaller_len / 4;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(largest_log).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(smaller_log).circleDomain();
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(d0);
    const terminal_domain = core.poly.line.LineDomain.fromCircleDomain(d1);
    const shape0 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = largest_log,
        .log_degree_bound = largest_log - 1,
        .original_column_count = 1,
    };
    const shape1 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = smaller_log,
        .log_degree_bound = smaller_log - 1,
        .original_column_count = 1,
    };
    var f0: [larger_len]M31 = undefined;
    var f1: [smaller_len]M31 = undefined;
    for (&f0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, largest_log)).x;
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, smaller_log)).x;
    const columns0 = [_][]const M31{&f0};
    const columns1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &columns0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &columns1);
    defer tree1.deinit(alloc);

    var points = [_]core.circle.CirclePointQM31{core.circle.CirclePointQM31.zero()};
    var claims = [_]QM31{QM31.zero()};
    const dummy_values = try alloc.alloc(M31, 4 * n_queries);
    defer alloc.free(dummy_values);
    @memset(dummy_values, M31.zero());
    var empty_witness: [0]Hasher.Hash = .{};
    const dummy_columns = [_][]const M31{dummy_values};
    const header_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
    };
    const header = envelope_mod.Envelope{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &header_heights,
    };
    // Force two otherwise astronomically rare transcript draws. Both map to
    // C(CM31), where the conjugate-line denominator is zero. Rejection must
    // leave the caller's transcript untouched, including after root binding.
    const ChosenSeedChannel = struct {
        digest: [32]u8 = [_]u8{0} ** 32,
        draws: usize = 0,
        seed: QM31,
        const Self = @This();
        pub fn digestBytes(self: Self) [32]u8 {
            return self.digest;
        }
        pub fn updateDigest(self: *Self, digest: [32]u8) void {
            self.digest = digest;
        }
        pub fn mixU64(self: *Self, _: u64) void {
            self.draws += 1;
        }
        pub fn drawSecureFelt(self: *Self) QM31 {
            self.draws += 1;
            return self.seed;
        }
    };
    for ([_]QM31{
        QM31.fromBase(M31.fromCanonical(7)),
        QM31.fromM31(M31.fromCanonical(7), M31.fromCanonical(11), M31.zero(), M31.zero()),
    }) |seed| {
        var channel = ChosenSeedChannel{ .seed = seed };
        const original = channel;
        try std.testing.expectError(
            error.DegenerateOodPoint,
            wire.drawOodPointFromRoots(&channel, header),
        );
        try std.testing.expectEqualSlices(u8, &original.digest, &channel.digest);
        try std.testing.expectEqual(original.draws, channel.draws);
    }
    var prover_channel = Channel{};
    wire.bindVersion(&prover_channel);
    const sample_point = try wire.drawOodPointFromRoots(&prover_channel, header);
    points[0] = sample_point;
    claims[0] = sample_point.x;
    const challenges = try wire.drawBatchAfterOod(&prover_channel, header, sample_point);
    const changed_claims = [_]QM31{claims[0].add(QM31.one())};
    var changed_claim_heights = header_heights;
    for (&changed_claim_heights) |*height| height.sample_values = &changed_claims;
    const changed_claim_header = envelope_mod.Envelope{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &changed_claim_heights,
    };
    var changed_claim_channel = Channel{};
    wire.bindVersion(&changed_claim_channel);
    const changed_claim_point = try wire.drawOodPointFromRoots(
        &changed_claim_channel,
        changed_claim_header,
    );
    try std.testing.expect(changed_claim_point.eql(sample_point));
    const changed_challenges = try wire.drawBatchAfterOod(
        &changed_claim_channel,
        changed_claim_header,
        changed_claim_point,
    );
    try std.testing.expect(!changed_challenges.batch.eql(challenges.batch));
    const alpha0 = prover_channel.drawSecureFelt();
    const batch0 = try pairedFullBatchForTest(alloc, &f0, largest_log, sample_point, claims[0], challenges);
    defer alloc.free(batch0);
    const batch1 = try pairedFullBatchForTest(alloc, &f1, smaller_log, sample_point, claims[0], challenges);
    defer alloc.free(batch1);
    for (batch0, f0, 0..) |actual, x, row| {
        const p = d0.at(core.utils.bitReverseIndex(row, largest_log));
        const quotient = try directTwoPointQuotient(sample_point, claims[0], p, x);
        const expected = QM31.fromBase(x).add(challenges.batch.mul(quotient));
        try std.testing.expect(actual.eql(expected));
    }
    for (batch1, f1, 0..) |actual, x, row| {
        const p = d1.at(core.utils.bitReverseIndex(row, smaller_log));
        const quotient = try directTwoPointQuotient(sample_point, claims[0], p, x);
        const expected = QM31.fromBase(x).add(challenges.batch.mul(quotient));
        try std.testing.expect(actual.eql(expected));
    }

    var g0: [smaller_len]QM31 = [_]QM31{QM31.zero()} ** smaller_len;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, smaller_len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(
        alloc,
        &g0,
        batch0,
        d0,
        alpha0,
        &workspace,
    );
    for (g0, 0..) |actual, row| {
        const y = d0.at(core.utils.bitReverseIndex(2 * row, largest_log)).y;
        const even = batch0[2 * row];
        const odd = batch0[2 * row + 1];
        const expected = even.add(odd).add(alpha0.mul(even.sub(odd).mulM31(try y.inv())));
        try std.testing.expect(actual.eql(expected));
    }
    var line_coordinates: [4][smaller_len]M31 = undefined;
    for (g0, 0..) |value, row| {
        for (value.toM31Array(), 0..) |coordinate, part| {
            line_coordinates[part][row] = coordinate;
        }
    }
    const line_columns = [_][]const M31{
        &line_coordinates[0], &line_coordinates[1],
        &line_coordinates[2], &line_coordinates[3],
    };
    var line_tree = try SourceProver.commit(alloc, &line_columns);
    defer line_tree.deinit(alloc);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&prover_channel, line_tree.root());
    const alpha1 = prover_channel.drawSecureFelt();
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        line_domain,
        batch1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    for (g1.values, 0..) |actual, row| {
        const x = line_domain.at(core.utils.bitReverseIndex(2 * row, line_domain.logSize()));
        const y = d1.at(core.utils.bitReverseIndex(2 * row, smaller_log)).y;
        const expected = try manualNativeEq68Row(
            g0[2 * row],
            g0[2 * row + 1],
            x,
            batch1[2 * row],
            batch1[2 * row + 1],
            y,
            alpha1,
        );
        try std.testing.expect(actual.eql(expected));
    }
    var g1_evaluation = try LineEvaluation.initBorrowed(g1.domain, g1.values);
    var g1_poly = try g1_evaluation.interpolate(alloc);
    defer g1_poly.deinit(alloc);
    const ordered_coeffs = g1_poly.intoOrderedCoefficients();
    for (ordered_coeffs[terminal_len..]) |coefficient| try std.testing.expect(coefficient.isZero());
    const terminal_coeffs = ordered_coeffs[0..terminal_len];
    const terminal_copy = try alloc.dupe(QM31, terminal_coeffs);
    var terminal_poly = core.poly.line.LinePoly.fromOrderedCoefficients(terminal_copy);
    defer terminal_poly.deinit(alloc);
    for (g1.values, 0..) |actual, row| {
        const x = terminal_domain.at(core.utils.bitReverseIndex(row, terminal_domain.logSize()));
        try std.testing.expect(actual.eql(try terminal_poly.evalAtPoint(alloc, QM31.fromBase(x))));
    }
    const independent_ood_eval = try directLagrangeLine(g1.values, terminal_domain, sample_point.x);
    try std.testing.expect(independent_ood_eval.eql(try terminal_poly.evalAtPoint(alloc, sample_point.x)));
    prover_channel.mixFelts(terminal_coeffs);
    var schedule = try two_height.sampleQuerySchedule(
        alloc,
        &prover_channel,
        largest_log,
        n_queries,
    );
    defer schedule.deinit(alloc);
    const projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        schedule.source_positions,
        largest_log,
        smaller_log,
    );
    defer alloc.free(projected);
    for (schedule.source_positions, projected) |large_row, small_row| {
        const large_point = d0.at(core.utils.bitReverseIndex(large_row, largest_log));
        const small_point = d1.at(core.utils.bitReverseIndex(small_row, smaller_log));
        try std.testing.expect(large_point.double().eql(small_point));
    }
    var opened0 = try tree0.decommit(alloc, schedule.source_positions, &columns0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected, &columns1);
    defer opened1.deinit(alloc);
    var opened_line = try line_tree.decommit(alloc, schedule.line_positions, &line_columns);
    defer opened_line.deinit(alloc);
    const queried0 = [_][]const M31{opened0.queried_values[0]};
    const queried1 = [_][]const M31{opened1.queried_values[0]};
    const heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried0,
            .hash_witness = opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried1,
            .hash_witness = opened1.decommitment.decommitment.hash_witness,
        },
    };
    const source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &heights,
    });
    defer alloc.free(source_wire);
    const outer_wire = try wire.encode(alloc, .{
        .source_wire = source_wire,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                opened_line.queried_values[0], opened_line.queried_values[1],
                opened_line.queried_values[2], opened_line.queried_values[3],
            },
            .hash_witness = opened_line.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(outer_wire);
    var generated_channel = Channel{};
    const generated_wire = try @import("stwo_prover_engine").pcs.paired_two_height_experimental.prove(
        alloc,
        .{
            .largest_log_size = largest_log,
            .log_blowup = 1,
            .n_queries = n_queries,
            .first_columns = &columns0,
            .second_columns = &columns1,
        },
        &generated_channel,
    );
    defer alloc.free(generated_wire);
    try std.testing.expectEqualSlices(u8, outer_wire, generated_wire);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &generated_channel.digest);
    var verifier_channel = Channel{};
    try wire.verify(alloc, outer_wire, &verifier_channel, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    }, n_queries);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // Keep both honest commitments, change only the claimed OOD value, and
    // open the honest trees afresh at the changed transcript's queries.
    // Authentication succeeds; the algebraic first fold must reject.
    _ = changed_claim_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &changed_claim_channel,
        line_tree.root(),
    );
    _ = changed_claim_channel.drawSecureFelt();
    changed_claim_channel.mixFelts(terminal_coeffs);
    var changed_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &changed_claim_channel,
        largest_log,
        n_queries,
    );
    defer changed_schedule.deinit(alloc);
    const changed_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        changed_schedule.source_positions,
        largest_log,
        smaller_log,
    );
    defer alloc.free(changed_projected);
    var changed_opened0 = try tree0.decommit(
        alloc,
        changed_schedule.source_positions,
        &columns0,
    );
    defer changed_opened0.deinit(alloc);
    var changed_opened1 = try tree1.decommit(
        alloc,
        changed_projected,
        &columns1,
    );
    defer changed_opened1.deinit(alloc);
    var changed_opened_line = try line_tree.decommit(
        alloc,
        changed_schedule.line_positions,
        &line_columns,
    );
    defer changed_opened_line.deinit(alloc);
    const changed_columns0 = [_][]const M31{changed_opened0.queried_values[0]};
    const changed_columns1 = [_][]const M31{changed_opened1.queried_values[0]};
    const changed_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &changed_claims,
            .queried_sources = &changed_columns0,
            .hash_witness = changed_opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &changed_claims,
            .queried_sources = &changed_columns1,
            .hash_witness = changed_opened1.decommitment.decommitment.hash_witness,
        },
    };
    const changed_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = largest_log,
        .query_count = @intCast(4 * n_queries),
        .heights = &changed_heights,
    });
    defer alloc.free(changed_source_wire);
    const changed_outer_wire = try wire.encode(alloc, .{
        .source_wire = changed_source_wire,
        .intermediate = .{
            .root = line_tree.root(),
            .queried_coordinates = .{
                changed_opened_line.queried_values[0], changed_opened_line.queried_values[1],
                changed_opened_line.queried_values[2], changed_opened_line.queried_values[3],
            },
            .hash_witness = changed_opened_line.decommitment.decommitment.hash_witness,
        },
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_outer_wire);
    var changed_verifier_channel = Channel{};
    const changed_verifier_before = changed_verifier_channel.digest;
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        wire.verify(alloc, changed_outer_wire, &changed_verifier_channel, .{
            .largest_log_size = largest_log,
            .query_count = @intCast(4 * n_queries),
            .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
        }, n_queries),
    );
    try std.testing.expectEqualSlices(
        u8,
        &changed_verifier_before,
        &changed_verifier_channel.digest,
    );
}

test "experimental paired FRI works at parameterized adjacent heights" {
    try checkHonestAdjacentHeights(4, 4);
    try checkHonestAdjacentHeights(5, 5);
    try checkHonestAdjacentHeights(6, 7);
}

test "paired query trace follows the published circle-squaring projection" {
    const core = @import("stwo_core");
    const canonic = core.poly.circle.canonic;
    const two_height = core.pcs.paired_two_height_fri;
    const projection = core.pcs.paired_projection;
    const alloc = std.testing.allocator;
    for ([_]u32{ 4, 5, 6 }) |large_log| {
        const large = canonic.CanonicCoset.new(large_log).circleDomain();
        const small = canonic.CanonicCoset.new(large_log - 1).circleDomain();
        for (0..large.size()) |raw| {
            const trace = try two_height.queryTrace(raw, large_log);
            const expected_projection = try projection.projectPositions(
                alloc,
                &[_]usize{raw},
                large_log,
                large_log - 1,
            );
            defer alloc.free(expected_projection);
            try std.testing.expectEqual(expected_projection[0], trace.projected_circle_row);
            try std.testing.expect(raw >= trace.source_bundle_base);
            try std.testing.expect(raw < trace.source_bundle_base + 4);
            try std.testing.expectEqual(trace.terminal_row, trace.line_bundle_base >> 1);
            const p0 = large.at(core.utils.bitReverseIndex(raw, large_log));
            const p1 = small.at(core.utils.bitReverseIndex(trace.projected_circle_row, large_log - 1));
            try std.testing.expect(p0.double().eql(p1));
        }
    }
    // An ordinary right shift of native bit-reversed row 2 selects the wrong
    // smaller-domain point: it removes the y-sign bit instead of bit 1.
    const large = canonic.CanonicCoset.new(4).circleDomain();
    const small = canonic.CanonicCoset.new(3).circleDomain();
    const p0 = large.at(core.utils.bitReverseIndex(2, 4));
    const wrongly_shifted = small.at(core.utils.bitReverseIndex(1, 3));
    try std.testing.expect(!p0.double().eql(wrongly_shifted));
    try std.testing.expectError(error.QueryPositionOutOfRange, two_height.queryTrace(16, 4));
    try std.testing.expectError(error.InvalidTwoHeightProfile, two_height.queryTrace(0, 2));
}

test "versioned transposed two-height source and line commitments authenticate" {
    const core = @import("stwo_core");
    const xdm = core.pcs.transposed_merkle;
    const Tree = @import("stwo_prover_engine").pcs.transposed_source_experimental.Commitment;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher);
    const SourceVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher);
    const alloc = std.testing.allocator;
    for ([_]u32{ 4, 5, 6 }) |log_size| {
        const size = @as(usize, 1) << @intCast(log_size);
        const large = try alloc.alloc(M31, size);
        defer alloc.free(large);
        const small = try alloc.alloc(M31, size / 2);
        defer alloc.free(small);
        const line = try alloc.alloc(M31, size / 2);
        defer alloc.free(line);
        for (large, 0..) |*value, row| value.* = M31.fromCanonical(@intCast(row + 1));
        for (small, line, 0..) |*value, *line_value, row| {
            value.* = M31.fromCanonical(@intCast(row + 19));
            line_value.* = M31.fromCanonical(@intCast(row + 31));
        }
        const large_columns = [_][]const M31{large};
        const small_columns = [_][]const M31{small};
        var tree = try Tree.commit(alloc, &large_columns, &small_columns);
        defer tree.deinit();
        const raw = [_]usize{ 2, 2, size - 3 };
        const encoded = try tree.encodeOpenings(alloc, &raw);
        defer alloc.free(encoded);
        var old_large = try SourceProver.commit(alloc, &large_columns);
        defer old_large.deinit(alloc);
        var old_small = try SourceProver.commit(alloc, &small_columns);
        defer old_small.deinit(alloc);
        var large_rows: [12]usize = undefined;
        for (raw, 0..) |query, qi| {
            const base = query & ~@as(usize, 3);
            for (0..4) |j| large_rows[4 * qi + j] = base + j;
        }
        const small_rows = try core.pcs.paired_projection.projectPositions(alloc, &large_rows, log_size, log_size - 1);
        defer alloc.free(small_rows);
        var old_large_open = try old_large.decommit(alloc, &large_rows, &large_columns);
        defer old_large_open.deinit(alloc);
        var old_small_open = try old_small.decommit(alloc, small_rows, &small_columns);
        defer old_small_open.deinit(alloc);
        const separate_hashes = old_large_open.decommitment.decommitment.hash_witness.len +
            old_small_open.decommitment.decommitment.hash_witness.len;
        const witness_count_offset = 60 + raw.len * 28;
        const shared_hashes: usize = std.mem.readInt(u32, &encoded[witness_count_offset..][0..4].*, .little);
        try std.testing.expectEqual(separate_hashes, shared_hashes);
        try std.testing.expectEqual(witness_count_offset + 4 + 32 * shared_hashes, encoded.len);
        const profile = xdm.Profile{
            .log_size = log_size,
            .large_columns = 1,
            .small_columns = 1,
            .query_count = raw.len,
        };
        try xdm.verifyWire(alloc, encoded, profile, tree.root(), &raw);
        var authenticated = try xdm.verifyAndCollect(alloc, encoded, profile, tree.root(), &raw);
        defer authenticated.deinit();
        const sample_point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
        const batch = QM31.fromBase(M31.fromCanonical(7));
        const large_claim = [_]QM31{sample_point.x};
        const small_claim = [_]QM31{sample_point.y};
        var answers = try core.pcs.transposed_paired_answers.fromVerifiedOpenings(
            alloc,
            authenticated,
            &raw,
            sample_point,
            &large_claim,
            &small_claim,
            batch,
        );
        defer answers.deinit();
        const full_large = try pairedFullBatchForTest(alloc, large, log_size, sample_point, large_claim[0], .{ .batch = batch });
        defer alloc.free(full_large);
        const full_small = try pairedFullBatchForTest(alloc, small, log_size - 1, sample_point, small_claim[0], .{ .batch = batch });
        defer alloc.free(full_small);
        for (raw, 0..) |query, qi| {
            const large_base = query & ~@as(usize, 3);
            const small_base = (query >> 2) << 1;
            for (0..4) |j| {
                try std.testing.expectEqual(large[large_base + j], authenticated.largeAt(qi, j, 0));
                try std.testing.expect(answers.large[4 * qi + j].eql(full_large[large_base + j]));
            }
            for (0..2) |j| {
                try std.testing.expectEqual(small[small_base + j], authenticated.smallAt(qi, j, 0));
                try std.testing.expect(answers.small[2 * qi + j].eql(full_small[small_base + j]));
            }
        }
        // The next FRI round commits its line separately, after its fold
        // challenge. It must still authenticate its line queries normally.
        const line_columns = [_][]const M31{line};
        var line_tree = try SourceProver.commit(alloc, &line_columns);
        defer line_tree.deinit(alloc);
        const line_rows = [_]usize{ 1, 1, size / 2 - 2 };
        var line_opening = try line_tree.decommit(alloc, &line_rows, &line_columns);
        defer line_opening.deinit(alloc);
        var line_verifier = try SourceVerifier.init(alloc, line_tree.root(), &[_]u32{log_size - 1});
        defer line_verifier.deinit(alloc);
        const line_values = [_][]const M31{line_opening.queried_values[0]};
        try line_verifier.verify(alloc, &line_rows, &line_values, .{
            .hash_witness = line_opening.decommitment.decommitment.hash_witness,
        });
        const wrong_raw = [_]usize{ 3, 2, size - 3 };
        try std.testing.expectError(error.UnexpectedCrossDomainQuery, xdm.verifyWire(alloc, encoded, profile, tree.root(), &wrong_raw));
        var wrong_root = tree.root();
        wrong_root[0] ^= 1;
        try std.testing.expectError(error.UnexpectedCrossDomainRoot, xdm.verifyWire(alloc, encoded, profile, wrong_root, &raw));
        const changed = try alloc.dupe(u8, encoded);
        defer alloc.free(changed);
        changed[64] ^= 1; // first large value
        try std.testing.expectError(error.DuplicateProjectedValue, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[120] ^= 1; // unique last-query large value
        try std.testing.expectError(error.RootMismatch, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[136] ^= 1; // unique last-query inserted smaller-height value
        try std.testing.expectError(error.RootMismatch, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[witness_count_offset + 4] ^= 1; // first shared authentication sibling
        try std.testing.expectError(error.RootMismatch, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        std.mem.writeInt(u32, changed[witness_count_offset..][0..4], @intCast(shared_hashes - 1), .little);
        try std.testing.expectError(error.WitnessTooShort, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        std.mem.writeInt(u32, changed[witness_count_offset..][0..4], @intCast(shared_hashes + 1), .little);
        try std.testing.expectError(error.TruncatedCrossDomainProof, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[108] ^= 1; // duplicate projected small value in repeated query
        try std.testing.expectError(error.DuplicateProjectedValue, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        std.mem.writeInt(u32, changed[64..68], m31.Modulus, .little);
        try std.testing.expectError(error.NonCanonicalM31, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[8] = 3;
        try std.testing.expectError(error.UnsupportedProofVersion, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[10] = 1;
        try std.testing.expectError(error.InvalidCrossDomainProof, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        @memcpy(changed, encoded);
        changed[0] ^= 1;
        try std.testing.expectError(error.UnsupportedProofFormat, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
        try std.testing.expectError(error.InvalidCrossDomainProof, xdm.verifyWire(alloc, encoded[0 .. encoded.len - 1], profile, tree.root(), &raw));
        const truncated = try alloc.dupe(u8, encoded[0 .. encoded.len - 1]);
        defer alloc.free(truncated);
        std.mem.writeInt(u32, truncated[12..16], @intCast(truncated.len), .little);
        try std.testing.expectError(error.TruncatedCrossDomainProof, xdm.verifyWire(alloc, truncated, profile, tree.root(), &raw));
        const extended = try alloc.alloc(u8, encoded.len + 1);
        defer alloc.free(extended);
        @memcpy(extended[0..encoded.len], encoded);
        extended[encoded.len] = 0;
        try std.testing.expectError(error.InvalidCrossDomainProof, xdm.verifyWire(alloc, extended, profile, tree.root(), &raw));
        // The shared multiproof uses the same number of witness hashes as
        // the existing two-tree compressed multiproofs on these query sets,
        // while binding one root instead of two. Values and header framing
        // are measured separately below in the design brief.
    }
}

test "transposed source openings preserve multi-column paired order" {
    const core = @import("stwo_core");
    const xdm = core.pcs.transposed_merkle;
    const Tree = @import("stwo_prover_engine").pcs.transposed_source_experimental.Commitment;
    const alloc = std.testing.allocator;
    var large0: [16]M31 = undefined;
    var large1: [16]M31 = undefined;
    var small0: [8]M31 = undefined;
    var small1: [8]M31 = undefined;
    for (&large0, &large1, 0..) |*a, *b, i| {
        a.* = M31.fromCanonical(@intCast(i + 1));
        b.* = M31.fromCanonical(@intCast(i * i + 3));
    }
    for (&small0, &small1, 0..) |*a, *b, i| {
        a.* = M31.fromCanonical(@intCast(i + 19));
        b.* = M31.fromCanonical(@intCast(2 * i + 7));
    }
    const large_cols = [_][]const M31{ &large0, &large1 };
    const small_cols = [_][]const M31{ &small0, &small1 };
    var tree = try Tree.commit(alloc, &large_cols, &small_cols);
    defer tree.deinit();
    const raw = [_]usize{ 3, 9 };
    const encoded = try tree.encodeOpenings(alloc, &raw);
    defer alloc.free(encoded);
    const profile = xdm.Profile{ .log_size = 4, .large_columns = 2, .small_columns = 2, .query_count = raw.len };
    var authenticated = try xdm.verifyAndCollect(alloc, encoded, profile, tree.root(), &raw);
    defer authenticated.deinit();
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    const batch = QM31.fromBase(M31.fromCanonical(7));
    const large_claims = [_]QM31{ point.x, point.y };
    const small_claims = [_]QM31{ point.y, point.x };
    var answers = try core.pcs.transposed_paired_answers.fromVerifiedOpenings(
        alloc,
        authenticated,
        &raw,
        point,
        &large_claims,
        &small_claims,
        batch,
    );
    defer answers.deinit();
    const l0 = try pairedFullBatchForTest(alloc, &large0, 4, point, large_claims[0], .{ .batch = batch });
    defer alloc.free(l0);
    const l1 = try pairedFullBatchForTest(alloc, &large1, 4, point, large_claims[1], .{ .batch = batch });
    defer alloc.free(l1);
    const s0 = try pairedFullBatchForTest(alloc, &small0, 3, point, small_claims[0], .{ .batch = batch });
    defer alloc.free(s0);
    const s1 = try pairedFullBatchForTest(alloc, &small1, 3, point, small_claims[1], .{ .batch = batch });
    defer alloc.free(s1);
    for (raw, 0..) |query, qi| {
        const large_base = query & ~@as(usize, 3);
        const small_base = (query >> 2) << 1;
        for (0..4) |j| {
            const expected = l0[large_base + j].add(batch.square().mul(l1[large_base + j]));
            try std.testing.expect(expected.eql(answers.large[4 * qi + j]));
        }
        for (0..2) |j| {
            const expected = s0[small_base + j].add(batch.square().mul(s1[small_base + j]));
            try std.testing.expect(expected.eql(answers.small[2 * qi + j]));
        }
    }
    const changed = try alloc.dupe(u8, encoded);
    defer alloc.free(changed);
    changed[68] ^= 1; // second column at the first opened leaf
    try std.testing.expectError(error.RootMismatch, xdm.verifyWire(alloc, changed, profile, tree.root(), &raw));
}

test "experimental paired prover handles two source pairs and rejects invalid inputs" {
    const core = @import("stwo_core");
    const prover = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
    const wire = core.pcs.paired_two_height_wire;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const alloc = std.testing.allocator;
    const first_domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    const second_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var first_x: [32]M31 = undefined;
    var second_x: [16]M31 = undefined;
    for (&first_x, 0..) |*value, row| {
        value.* = first_domain.at(core.utils.bitReverseIndex(row, 5)).x;
    }
    for (&second_x, 0..) |*value, row| {
        value.* = second_domain.at(core.utils.bitReverseIndex(row, 4)).x;
    }
    const first_constant = [_]M31{M31.fromCanonical(7)} ** 32;
    const second_constant = [_]M31{M31.fromCanonical(11)} ** 16;
    const first_columns = [_][]const M31{ &first_x, &first_constant };
    const second_columns = [_][]const M31{ &second_x, &second_constant };
    const input = prover.Input{
        .largest_log_size = 5,
        .log_blowup = 2,
        .n_queries = 5,
        .first_columns = &first_columns,
        .second_columns = &second_columns,
    };
    var proving_channel = Channel{};
    const encoded = try prover.prove(alloc, input, &proving_channel);
    defer alloc.free(encoded);
    const shapes = try input.shapes();
    var verifying_channel = Channel{};
    try wire.verify(alloc, encoded, &verifying_channel, .{
        .largest_log_size = 5,
        .query_count = 20,
        .shapes = &shapes,
    }, 5);
    try std.testing.expectEqualSlices(u8, &proving_channel.digest, &verifying_channel.digest);
    var decoded = try wire.decode(alloc, encoded);
    defer decoded.deinit();
    const first = decoded.source.envelope.heights[0];
    const second = decoded.source.envelope.heights[1];
    try std.testing.expectEqual(@as(usize, 2), first.sample_values.len);
    try std.testing.expectEqual(@as(usize, 2), second.sample_values.len);
    try std.testing.expect(first.sample_values[0].eql(first.sample_points[0].x));
    try std.testing.expect(second.sample_values[0].eql(second.sample_points[0].x));
    try std.testing.expect(first.sample_values[1].eql(QM31.fromBase(M31.fromCanonical(7))));
    try std.testing.expect(second.sample_values[1].eql(QM31.fromBase(M31.fromCanonical(11))));
    var repeated_channel = Channel{};
    const repeated = try prover.prove(alloc, input, &repeated_channel);
    defer alloc.free(repeated);
    try std.testing.expectEqualSlices(u8, encoded, repeated);
    try std.testing.expectEqualSlices(u8, &proving_channel.digest, &repeated_channel.digest);
    var prefixed_prover_channel = Channel{};
    prefixed_prover_channel.mixU64(0x5345_4544_4544_5032);
    const prefixed_wire = try prover.prove(alloc, input, &prefixed_prover_channel);
    defer alloc.free(prefixed_wire);
    var prefixed_verifier_channel = Channel{};
    prefixed_verifier_channel.mixU64(0x5345_4544_4544_5032);
    try wire.verify(alloc, prefixed_wire, &prefixed_verifier_channel, .{
        .largest_log_size = 5,
        .query_count = 20,
        .shapes = &shapes,
    }, 5);
    try std.testing.expectEqualSlices(
        u8,
        &prefixed_prover_channel.digest,
        &prefixed_verifier_channel.digest,
    );

    const short_columns = [_][]const M31{ first_x[0..31], &first_constant };
    var rejected_channel = Channel{};
    const untouched = rejected_channel.digest;
    var malformed = input;
    malformed.first_columns = &short_columns;
    try std.testing.expectError(
        error.InvalidPairedProverInput,
        prover.prove(alloc, malformed, &rejected_channel),
    );
    try std.testing.expectEqualSlices(u8, &untouched, &rejected_channel.digest);
    var high_degree = first_x;
    high_degree[0] = high_degree[0].add(M31.one());
    const high_degree_columns = [_][]const M31{ &high_degree, &first_constant };
    malformed = input;
    malformed.first_columns = &high_degree_columns;
    try std.testing.expectError(
        error.SourceDegreeExceeded,
        prover.prove(alloc, malformed, &rejected_channel),
    );
    try std.testing.expectEqualSlices(u8, &untouched, &rejected_channel.digest);
}

test "experimental sampled two-height FRI authenticates intermediate and checks both folds" {
    const core = @import("stwo_core");
    const envelope_mod = core.pcs.paired_envelope;
    const two_height = core.pcs.paired_two_height_fri;
    const Channel = core.channel.blake2s.Blake2sChannel;
    const Hasher = envelope_mod.Hasher;
    const SourceProver = @import("stwo_prover_engine").vcs_lifted.prover.MerkleProverLifted(Hasher);
    const LineEvaluation = @import("stwo_prover_engine").line.LineEvaluation;
    const alloc = std.testing.allocator;
    const d0 = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const d1 = core.poly.circle.canonic.CanonicCoset.new(3).circleDomain();
    const shape0 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 4,
        .log_degree_bound = 3,
        .original_column_count = 1,
    };
    const shape1 = core.pcs.paired_ensemble.Shape{
        .log_domain_size = 3,
        .log_degree_bound = 2,
        .original_column_count = 1,
    };
    var f0: [16]M31 = undefined;
    var f1: [8]M31 = undefined;
    for (&f0, 0..) |*value, row| value.* = d0.at(core.utils.bitReverseIndex(row, 4)).x;
    for (&f1, 0..) |*value, row| value.* = d1.at(core.utils.bitReverseIndex(row, 3)).x;
    const sources0 = [_][]const M31{&f0};
    const sources1 = [_][]const M31{&f1};
    var tree0 = try SourceProver.commit(alloc, &sources0);
    defer tree0.deinit(alloc);
    var tree1 = try SourceProver.commit(alloc, &sources1);
    defer tree1.deinit(alloc);
    var points = [_]core.circle.CirclePointQM31{core.circle.CirclePointQM31.zero()};
    var claims = [_]QM31{QM31.zero()};
    const n_queries: usize = 4;
    var dummy_values = [_]M31{M31.zero()} ** (4 * n_queries);
    var empty_witness: [0]Hasher.Hash = .{};
    const dummy_columns = [_][]const M31{&dummy_values};
    const header_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &dummy_columns,
            .hash_witness = &empty_witness,
        },
    };
    const header = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &header_heights,
    };
    var prover_channel = Channel{};
    core.pcs.paired_two_height_wire.bindVersion(&prover_channel);
    const sample_point = try core.pcs.paired_two_height_wire.drawOodPointFromRoots(
        &prover_channel,
        header,
    );
    points[0] = sample_point;
    claims[0] = sample_point.x;
    const batch_challenges = try core.pcs.paired_two_height_wire.drawBatchAfterOod(
        &prover_channel,
        header,
        sample_point,
    );
    var source_only_channel = Channel{};
    const source_only_challenges = try envelope_mod.drawChallenges(&source_only_channel, header);
    try std.testing.expect(!batch_challenges.batch.eql(source_only_challenges.batch));
    const alpha0 = prover_channel.drawSecureFelt();
    const batch0 = try pairedFullBatchForTest(alloc, &f0, 4, sample_point, sample_point.x, batch_challenges);
    defer alloc.free(batch0);
    const batch1 = try pairedFullBatchForTest(alloc, &f1, 3, sample_point, sample_point.x, batch_challenges);
    defer alloc.free(batch1);
    var g0 = [_]QM31{QM31.zero()} ** 8;
    var workspace = try core_fri.folding.FoldCircleWorkspace.init(alloc, g0.len);
    defer workspace.deinit(alloc);
    try core_fri.folding.foldCircleIntoLineWithWorkspace(alloc, &g0, batch0, d0, alpha0, &workspace);
    var g0_coordinates: [4][8]M31 = undefined;
    for (g0, 0..) |value, row| {
        const parts = value.toM31Array();
        for (0..4) |part| g0_coordinates[part][row] = parts[part];
    }
    const g0_columns = [_][]const M31{
        &g0_coordinates[0], &g0_coordinates[1], &g0_coordinates[2], &g0_coordinates[3],
    };
    var g0_tree = try SourceProver.commit(alloc, &g0_columns);
    defer g0_tree.deinit(alloc);
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(&prover_channel, g0_tree.root());
    const alpha1 = prover_channel.drawSecureFelt();
    const g1 = try core_fri.multidomain_insertion.insertCircleBatch(
        alloc,
        &g0,
        core.poly.line.LineDomain.fromCircleDomain(d0),
        batch1,
        d1,
        alpha1,
    );
    defer alloc.free(g1.values);
    var g1_evaluation = try LineEvaluation.initBorrowed(g1.domain, g1.values);
    var g1_poly = try g1_evaluation.interpolate(alloc);
    defer g1_poly.deinit(alloc);
    const ordered_coeffs = g1_poly.intoOrderedCoefficients();
    for (ordered_coeffs[2..]) |coefficient| try std.testing.expect(coefficient.isZero());
    const terminal_coeffs = ordered_coeffs[0..2];
    prover_channel.mixFelts(terminal_coeffs);
    var schedule = try two_height.sampleQuerySchedule(alloc, &prover_channel, 4, n_queries);
    defer schedule.deinit(alloc);

    const projected1 = try core.pcs.paired_projection.projectPositions(
        alloc,
        schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(projected1);
    var opened0 = try tree0.decommit(alloc, schedule.source_positions, &sources0);
    defer opened0.deinit(alloc);
    var opened1 = try tree1.decommit(alloc, projected1, &sources1);
    defer opened1.deinit(alloc);
    var opened_g0 = try g0_tree.decommit(alloc, schedule.line_positions, &g0_columns);
    defer opened_g0.deinit(alloc);
    const queried0 = [_][]const M31{opened0.queried_values[0]};
    const queried1 = [_][]const M31{opened1.queried_values[0]};
    const heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried0,
            .hash_witness = opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &queried1,
            .hash_witness = opened1.decommitment.decommitment.hash_witness,
        },
    };
    const source_envelope = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &heights,
    };
    const encoded = try envelope_mod.encode(alloc, source_envelope);
    defer alloc.free(encoded);
    const expected_profile = envelope_mod.ExpectedProfile{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .shapes = &[_]core.pcs.paired_ensemble.Shape{ shape0, shape1 },
    };
    var verifier_channel = Channel{};
    var prepared = try core.pcs.paired_two_height_wire.bindSourceEnvelope(
        alloc,
        encoded,
        &verifier_channel,
        expected_profile,
    );
    defer prepared.deinit();
    const intermediate = two_height.IntermediateOpening{
        .root = g0_tree.root(),
        .queried_coordinates = .{
            opened_g0.queried_values[0], opened_g0.queried_values[1],
            opened_g0.queried_values[2], opened_g0.queried_values[3],
        },
        .hash_witness = opened_g0.decommitment.decommitment.hash_witness,
    };
    const two_height_wire = core.pcs.paired_two_height_wire;
    const complete_wire = try two_height_wire.encode(alloc, .{
        .source_wire = encoded,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(complete_wire);
    var wire_channel = Channel{};
    try two_height_wire.verify(
        alloc,
        complete_wire,
        &wire_channel,
        expected_profile,
        n_queries,
    );
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &wire_channel.digest);
    const expected_roots = [_]envelope_mod.Hash{ tree0.root(), tree1.root() };
    const expected_claims = [_][]const QM31{ &claims, &claims };
    const statement = two_height_wire.ExpectedStatement{
        .profile = expected_profile,
        .source_roots = &expected_roots,
        .sample_values = &expected_claims,
    };
    var statement_channel = Channel{};
    try two_height_wire.verifyAgainstStatement(
        alloc,
        complete_wire,
        &statement_channel,
        statement,
        n_queries,
    );
    try std.testing.expectEqualSlices(u8, &wire_channel.digest, &statement_channel.digest);
    var wrong_roots = expected_roots;
    wrong_roots[0][0] ^= 1;
    var rejected_statement_channel = Channel{};
    const statement_digest_before = rejected_statement_channel.digest;
    try std.testing.expectError(
        error.UnexpectedPairedStatement,
        two_height_wire.verifyAgainstStatement(alloc, complete_wire, &rejected_statement_channel, .{
            .profile = expected_profile,
            .source_roots = &wrong_roots,
            .sample_values = &expected_claims,
        }, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &statement_digest_before, &rejected_statement_channel.digest);
    const wrong_claim = [_]QM31{claims[0].add(QM31.one())};
    const wrong_claims = [_][]const QM31{ &wrong_claim, &claims };
    try std.testing.expectError(
        error.UnexpectedPairedStatement,
        two_height_wire.verifyAgainstStatement(alloc, complete_wire, &rejected_statement_channel, .{
            .profile = expected_profile,
            .source_roots = &expected_roots,
            .sample_values = &wrong_claims,
        }, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &statement_digest_before, &rejected_statement_channel.digest);
    const wrong_version_wire = try alloc.dupe(u8, complete_wire);
    defer alloc.free(wrong_version_wire);
    wrong_version_wire[8] = 2;
    var untouched_channel = Channel{};
    const untouched_digest = untouched_channel.digest;
    try std.testing.expectError(
        error.UnsupportedProofVersion,
        two_height_wire.verify(
            alloc,
            wrong_version_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const other_point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13);
    try std.testing.expect(!other_point.eql(sample_point));
    const altered_points = [_]core.circle.CirclePointQM31{other_point};
    var altered_heights = heights;
    altered_heights[0].sample_points = &altered_points;
    const altered_source = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &altered_heights,
    });
    defer alloc.free(altered_source);
    const altered_wire = try two_height_wire.encode(alloc, .{
        .source_wire = altered_source,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(altered_wire);
    try std.testing.expectError(
        error.UnsampledOodPoint,
        two_height_wire.verify(alloc, altered_wire, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const changed_source_values = try alloc.dupe(M31, queried0[0]);
    defer alloc.free(changed_source_values);
    for (schedule.source_positions, 0..) |position, index| {
        if (position == schedule.source_positions[0]) {
            changed_source_values[index] = changed_source_values[index].add(M31.one());
        }
    }
    const changed_source_columns = [_][]const M31{changed_source_values};
    var changed_source_heights = heights;
    changed_source_heights[0].queried_sources = &changed_source_columns;
    const changed_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &changed_source_heights,
    });
    defer alloc.free(changed_source_wire);
    const changed_source_proof = try two_height_wire.encode(alloc, .{
        .source_wire = changed_source_wire,
        .intermediate = intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_source_proof);
    var changed_source_channel = Channel{};
    try std.testing.expectError(
        error.RootMismatch,
        two_height_wire.verify(
            alloc,
            changed_source_proof,
            &changed_source_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &changed_source_channel.digest);
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.encode(alloc, .{
            .source_wire = encoded,
            .intermediate = intermediate,
            .terminal_ordered_coeffs = &[_]QM31{ terminal_coeffs[0], terminal_coeffs[1], QM31.one() },
        }),
    );
    try std.testing.expectError(
        error.UnsupportedProofFormat,
        two_height_wire.verify(alloc, encoded, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const extended_wire = try alloc.alloc(u8, complete_wire.len + 1);
    defer alloc.free(extended_wire);
    @memcpy(extended_wire[0..complete_wire.len], complete_wire);
    extended_wire[complete_wire.len] = 0;
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.verify(alloc, extended_wire, &untouched_channel, expected_profile, n_queries),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const noncanonical_wire = try alloc.dupe(u8, complete_wire);
    defer alloc.free(noncanonical_wire);
    const terminal_offset = 20 + encoded.len + 32 + 4;
    std.mem.writeInt(u32, noncanonical_wire[terminal_offset..][0..4], m31.Modulus, .little);
    try std.testing.expectError(
        error.NonCanonicalM31,
        two_height_wire.verify(
            alloc,
            noncanonical_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    const high_degree_wire = try alloc.alloc(u8, complete_wire.len + @sizeOf(QM31));
    defer alloc.free(high_degree_wire);
    @memcpy(high_degree_wire[0 .. terminal_offset + 2 * @sizeOf(QM31)], complete_wire[0 .. terminal_offset + 2 * @sizeOf(QM31)]);
    @memset(high_degree_wire[terminal_offset + 2 * @sizeOf(QM31) ..][0..@sizeOf(QM31)], 0);
    @memcpy(high_degree_wire[terminal_offset + 3 * @sizeOf(QM31) ..], complete_wire[terminal_offset + 2 * @sizeOf(QM31) ..]);
    std.mem.writeInt(u32, high_degree_wire[12..16], @intCast(high_degree_wire.len), .little);
    std.mem.writeInt(u32, high_degree_wire[terminal_offset - 4 ..][0..4], 3, .little);
    try std.testing.expectError(
        error.InvalidPairedProof,
        two_height_wire.verify(
            alloc,
            high_degree_wire,
            &untouched_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &untouched_channel.digest);
    try two_height.verifyAfterSourceBinding(
        alloc,
        &verifier_channel,
        &prepared,
        intermediate,
        terminal_coeffs,
        n_queries,
    );
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);

    // A changed intermediate line word must fail its own commitment check
    // before either fold relation is considered.
    const changed_coordinate = try alloc.dupe(M31, intermediate.queried_coordinates[0]);
    defer alloc.free(changed_coordinate);
    for (changed_coordinate) |*value| value.* = value.*.add(M31.one());
    var changed_intermediate = intermediate;
    changed_intermediate.queried_coordinates[0] = changed_coordinate;
    var rejected_channel = Channel{};
    var rejected_prepared = try two_height_wire.bindSourceEnvelope(
        alloc,
        encoded,
        &rejected_channel,
        expected_profile,
    );
    defer rejected_prepared.deinit();
    try std.testing.expectError(
        error.RootMismatch,
        two_height.verifyAfterSourceBinding(
            alloc,
            &rejected_channel,
            &rejected_prepared,
            changed_intermediate,
            terminal_coeffs,
            n_queries,
        ),
    );
    const changed_line_wire = try two_height_wire.encode(alloc, .{
        .source_wire = encoded,
        .intermediate = changed_intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(changed_line_wire);
    var changed_line_channel = Channel{};
    try std.testing.expectError(
        error.RootMismatch,
        two_height_wire.verify(
            alloc,
            changed_line_wire,
            &changed_line_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &changed_line_channel.digest);

    // A prover can commit to a different, internally consistent line tree.
    // Merkle authentication then succeeds, but the sampled source-to-line
    // relation must still reject the forged fold.
    var forged_coordinates = g0_coordinates;
    for (&forged_coordinates[0]) |*value| value.* = value.*.add(M31.one());
    const forged_columns = [_][]const M31{
        &forged_coordinates[0], &forged_coordinates[1],
        &forged_coordinates[2], &forged_coordinates[3],
    };
    var forged_tree = try SourceProver.commit(alloc, &forged_columns);
    defer forged_tree.deinit(alloc);
    var forged_prover_channel = Channel{};
    two_height_wire.bindVersion(&forged_prover_channel);
    const forged_sample = try two_height_wire.drawOodPointFromRoots(&forged_prover_channel, header);
    try std.testing.expect(forged_sample.eql(sample_point));
    _ = try two_height_wire.drawBatchAfterOod(&forged_prover_channel, header, forged_sample);
    _ = forged_prover_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &forged_prover_channel,
        forged_tree.root(),
    );
    _ = forged_prover_channel.drawSecureFelt();
    forged_prover_channel.mixFelts(terminal_coeffs);
    var forged_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &forged_prover_channel,
        4,
        n_queries,
    );
    defer forged_schedule.deinit(alloc);
    const forged_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        forged_schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(forged_projected);
    var forged_opened0 = try tree0.decommit(
        alloc,
        forged_schedule.source_positions,
        &sources0,
    );
    defer forged_opened0.deinit(alloc);
    var forged_opened1 = try tree1.decommit(
        alloc,
        forged_projected,
        &sources1,
    );
    defer forged_opened1.deinit(alloc);
    var forged_opened_line = try forged_tree.decommit(
        alloc,
        forged_schedule.line_positions,
        &forged_columns,
    );
    defer forged_opened_line.deinit(alloc);
    const forged_source0 = [_][]const M31{forged_opened0.queried_values[0]};
    const forged_source1 = [_][]const M31{forged_opened1.queried_values[0]};
    const forged_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &forged_source0,
            .hash_witness = forged_opened0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &forged_source1,
            .hash_witness = forged_opened1.decommitment.decommitment.hash_witness,
        },
    };
    const forged_envelope = envelope_mod.Envelope{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &forged_heights,
    };
    const forged_wire = try envelope_mod.encode(alloc, forged_envelope);
    defer alloc.free(forged_wire);
    var forged_verifier_channel = Channel{};
    var forged_prepared = try two_height_wire.bindSourceEnvelope(
        alloc,
        forged_wire,
        &forged_verifier_channel,
        expected_profile,
    );
    defer forged_prepared.deinit();
    const forged_intermediate = two_height.IntermediateOpening{
        .root = forged_tree.root(),
        .queried_coordinates = .{
            forged_opened_line.queried_values[0], forged_opened_line.queried_values[1],
            forged_opened_line.queried_values[2], forged_opened_line.queried_values[3],
        },
        .hash_witness = forged_opened_line.decommitment.decommitment.hash_witness,
    };
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        two_height.verifyAfterSourceBinding(
            alloc,
            &forged_verifier_channel,
            &forged_prepared,
            forged_intermediate,
            terminal_coeffs,
            n_queries,
        ),
    );
    const forged_line_wire = try two_height_wire.encode(alloc, .{
        .source_wire = forged_wire,
        .intermediate = forged_intermediate,
        .terminal_ordered_coeffs = terminal_coeffs,
    });
    defer alloc.free(forged_line_wire);
    var forged_line_channel = Channel{};
    try std.testing.expectError(
        error.IntermediateFoldMismatch,
        two_height_wire.verify(
            alloc,
            forged_line_wire,
            &forged_line_channel,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &forged_line_channel.digest);

    // An adversary can publish a different short terminal polynomial and
    // re-open both honest trees at the resulting Fiat-Shamir queries. Its
    // source and line Merkle proofs are then valid, but the second fold must
    // disagree with that polynomial.
    const wrong_terminal = [_]QM31{ terminal_coeffs[0].add(QM31.one()), terminal_coeffs[1] };
    var wrong_terminal_channel = Channel{};
    two_height_wire.bindVersion(&wrong_terminal_channel);
    const wrong_sample = try two_height_wire.drawOodPointFromRoots(&wrong_terminal_channel, header);
    try std.testing.expect(wrong_sample.eql(sample_point));
    _ = try two_height_wire.drawBatchAfterOod(&wrong_terminal_channel, header, wrong_sample);
    _ = wrong_terminal_channel.drawSecureFelt();
    core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel.mixRoot(
        &wrong_terminal_channel,
        g0_tree.root(),
    );
    _ = wrong_terminal_channel.drawSecureFelt();
    wrong_terminal_channel.mixFelts(&wrong_terminal);
    var wrong_terminal_schedule = try two_height.sampleQuerySchedule(
        alloc,
        &wrong_terminal_channel,
        4,
        n_queries,
    );
    defer wrong_terminal_schedule.deinit(alloc);
    const wrong_projected = try core.pcs.paired_projection.projectPositions(
        alloc,
        wrong_terminal_schedule.source_positions,
        4,
        3,
    );
    defer alloc.free(wrong_projected);
    var wrong_source0 = try tree0.decommit(
        alloc,
        wrong_terminal_schedule.source_positions,
        &sources0,
    );
    defer wrong_source0.deinit(alloc);
    var wrong_source1 = try tree1.decommit(alloc, wrong_projected, &sources1);
    defer wrong_source1.deinit(alloc);
    var wrong_line = try g0_tree.decommit(
        alloc,
        wrong_terminal_schedule.line_positions,
        &g0_columns,
    );
    defer wrong_line.deinit(alloc);
    const wrong_columns0 = [_][]const M31{wrong_source0.queried_values[0]};
    const wrong_columns1 = [_][]const M31{wrong_source1.queried_values[0]};
    const wrong_heights = [_]envelope_mod.HeightOpening{
        .{
            .shape = shape0,
            .source_root = tree0.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &wrong_columns0,
            .hash_witness = wrong_source0.decommitment.decommitment.hash_witness,
        },
        .{
            .shape = shape1,
            .source_root = tree1.root(),
            .sample_points = &points,
            .sample_values = &claims,
            .queried_sources = &wrong_columns1,
            .hash_witness = wrong_source1.decommitment.decommitment.hash_witness,
        },
    };
    const wrong_source_wire = try envelope_mod.encode(alloc, .{
        .largest_log_size = 4,
        .query_count = 4 * n_queries,
        .heights = &wrong_heights,
    });
    defer alloc.free(wrong_source_wire);
    const wrong_intermediate = two_height.IntermediateOpening{
        .root = g0_tree.root(),
        .queried_coordinates = .{
            wrong_line.queried_values[0], wrong_line.queried_values[1],
            wrong_line.queried_values[2], wrong_line.queried_values[3],
        },
        .hash_witness = wrong_line.decommitment.decommitment.hash_witness,
    };
    const wrong_terminal_wire = try two_height_wire.encode(alloc, .{
        .source_wire = wrong_source_wire,
        .intermediate = wrong_intermediate,
        .terminal_ordered_coeffs = &wrong_terminal,
    });
    defer alloc.free(wrong_terminal_wire);
    var wrong_terminal_verifier = Channel{};
    try std.testing.expectError(
        error.TerminalFoldMismatch,
        two_height_wire.verify(
            alloc,
            wrong_terminal_wire,
            &wrong_terminal_verifier,
            expected_profile,
            n_queries,
        ),
    );
    try std.testing.expectEqualSlices(u8, &untouched_digest, &wrong_terminal_verifier.digest);
}
