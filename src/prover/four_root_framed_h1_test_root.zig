//! Candidate CAS12 join: four plain source roots, framed challenges, exact
//! raw queries, and two independent H1 degree checks. No production selector.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Bcs = core.channel.framed_bcs_v2.FramedBcsChannelV2;
const Binding = core.channel.framed_bcs_v2.StatementBinding;
const source_host = prover.pcs.four_root_pair_openings_experimental;
const wire = core.pcs.four_root_pair_wire_experimental;
const h1 = core.pcs.four_root_independent_h1_experimental;
const dual = core.pcs.paired_independent_h1_experimental;
const LineEvaluation = prover.line.LineEvaluation;

fn firstQM31(limbs: [8]u32) QM31 {
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

fn drawFirst(channel: *Bcs) !QM31 {
    try channel.beginChallengeDraw();
    const limbs = try channel.drawChallengeQM31Limbs();
    try channel.endChallengeDraw();
    return firstQM31(limbs);
}

fn absorbValues(channel: *Bcs, values: []const QM31) !void {
    const allocator = std.testing.allocator;
    const limbs = try allocator.alloc(u32, 4 * values.len);
    defer allocator.free(limbs);
    for (values, 0..) |value, i| {
        for (value.toM31Array(), 0..) |word, j| limbs[4 * i + j] = word.v;
    }
    try channel.mixField(limbs);
}

test "CAS12 framed four-root H1 joins raw queries to both degree tracks" {
    const alloc = std.testing.allocator;
    const k: u32 = 5;
    const domain = core.poly.circle.canonic.CanonicCoset.new(k).circleDomain();
    var fixed: [32]M31 = undefined;
    var main: [32]M31 = undefined;
    var interaction: [32]M31 = undefined;
    var composition_words: [8][32]M31 = undefined;
    var composition: [8][]const M31 = undefined;
    for (0..32) |row| {
        const x = domain.at(core.utils.bitReverseIndex(row, k)).x;
        fixed[row] = x.add(M31.fromCanonical(7));
        main[row] = M31.fromCanonical(11);
        interaction[row] = x.add(M31.fromCanonical(13));
        for (&composition_words, 0..) |*column, i|
            column[row] = x.add(M31.fromCanonical(@intCast(20 + i)));
    }
    for (&composition_words, &composition) |*words, *column|
        column.* = words[0..];
    const fixed_columns = [_][]const M31{&fixed};
    const main_columns = [_][]const M31{&main};
    const interaction_columns = [_][]const M31{&interaction};
    const columns = [4][]const []const M31{
        &fixed_columns, &main_columns, &interaction_columns, &composition,
    };
    const all_columns = [11][]const M31{
        &fixed,         &main,          &interaction,
        composition[0], composition[1], composition[2],
        composition[3], composition[4], composition[5],
        composition[6], composition[7],
    };

    // Source commitments do not depend on post-FRI query positions. This
    // initial one-pair proof exists only to materialize the four roots before
    // drawing challenges; the actual opening proof is built after queries.
    const provisional_raw = [_]usize{1};
    var preliminary = try source_host.prove(alloc, .{
        .columns = columns,
        .lifting_log_size = k,
        .raw_queries = &provisional_raw,
    });
    defer preliminary.deinit();
    const roots = preliminary.expected.roots;
    const digest = [_]u8{0x42} ** 32;
    var channel = Bcs.init(Binding{
        .key_digest = digest,
        .circuit_digest = [_]u8{0x43} ** 32,
        .fri_config_digest = [_]u8{0x44} ** 32,
        .source_tree_descriptors = [_][32]u8{
            [_]u8{0x10} ** 32, [_]u8{0x11} ** 32,
            [_]u8{0x12} ** 32, [_]u8{0x13} ** 32,
        },
        .line_profile_digest = [_]u8{0x45} ** 32,
    });
    try channel.mixRoot(roots[0]); // fixed
    try channel.mixRoot([_]u8{0x46} ** 32); // circuit identity
    try channel.mixField(&.{ 0, 0, 0, 0 }); // public output
    try channel.mixRoot(roots[1]); // main
    _ = try channel.beginPow(0); // interaction barrier
    try channel.acceptPowNonce(0);
    _ = try drawFirst(&channel); // lookup pair, unused in this H1 polynomial control
    try channel.mixField(&.{ 0, 0, 0, 0 }); // interaction claim
    try channel.mixRoot(roots[2]); // interaction
    _ = try drawFirst(&channel); // composition gamma
    try channel.mixRoot(roots[3]); // composition
    const ood_seed = try drawFirst(&channel);
    const point = try core.circle.secureFieldPointFromRandomSeedChecked(ood_seed);
    var claims: [11]QM31 = undefined;
    var claim_arena = std.heap.ArenaAllocator.init(alloc);
    defer claim_arena.deinit();
    try prover.pcs.paired_two_height_experimental.evaluateClaims(
        claim_arena.allocator(),
        domain,
        &all_columns,
        point,
        &claims,
    );
    try absorbValues(&channel, &claims); // sampled values
    const batch = try drawFirst(&channel);
    const alpha = try drawFirst(&channel);

    var context = try dual.RowContext.init(alloc, point, &claims, batch);
    defer context.deinit();
    var batches: [2][32]QM31 = undefined;
    for (0..32) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, k));
        const words = try context.dense(&all_columns, row, p);
        for (0..2) |track| batches[track][row] = words[track];
    }
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(domain);
    var terminal: [2][]QM31 = undefined;
    var terminals_built: usize = 0;
    defer for (terminal[0..terminals_built]) |coefficients| alloc.free(coefficients);
    const bound: usize = 4; // k=5, log_blowup=2, one circle fold
    for (0..2) |track| {
        var folded = [_]QM31{QM31.zero()} ** 16;
        var workspace = try core.fri.folding.FoldCircleWorkspace.init(alloc, 16);
        defer workspace.deinit(alloc);
        try core.fri.folding.foldCircleIntoLineWithWorkspace(
            alloc,
            &folded,
            &batches[track],
            domain,
            alpha,
            &workspace,
        );
        var evaluation = try LineEvaluation.initBorrowed(line_domain, &folded);
        var polynomial = try evaluation.interpolate(alloc);
        defer polynomial.deinit(alloc);
        const coefficients = polynomial.intoOrderedCoefficients();
        for (coefficients[bound..]) |coefficient|
            try std.testing.expect(coefficient.isZero());
        terminal[track] = try alloc.dupe(QM31, coefficients[0..bound]);
        terminals_built += 1;
        try absorbValues(&channel, terminal[track]); // each terminal track
    }
    _ = try channel.beginPow(0); // final PCS barrier
    try channel.acceptPowNonce(0);
    var query_channel = try channel.beginQueries();
    try std.testing.expectEqual(@as(u64, 22), query_channel.event);
    var sampled = try core.uniform_queries_v1.drawUniformQueriesV1(
        &query_channel,
        alloc,
        k,
        16,
        2,
    );
    defer sampled.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 2), sampled.blocks_consumed);
    try std.testing.expectEqual(@as(u64, 0), sampled.words_rejected);
    try std.testing.expectEqual(@as(usize, 16), sampled.raw.len);

    var opened = try source_host.prove(alloc, .{
        .columns = columns,
        .lifting_log_size = k,
        .raw_queries = sampled.raw,
    });
    defer opened.deinit();
    for (roots, opened.expected.roots) |before, after|
        try std.testing.expectEqualSlices(u8, &before, &after);
    const encoded = try wire.encode(alloc, opened.expected, opened.openings);
    defer alloc.free(encoded);
    try h1.verify(alloc, .{
        .source = opened.expected,
        .point = point,
        .claims = .{ claims[0..1], claims[1..2], claims[2..3], claims[3..11] },
        .batch_challenge = batch,
        .fold_challenge = alpha,
        .log_blowup = 2,
    }, .{ .source_wire = encoded, .terminals = .{ terminal[0], terminal[1] } });
}
