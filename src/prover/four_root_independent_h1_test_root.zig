//! Honest H1 local degree join over four plain source roots. All 16 source
//! pairs are opened, so this small control checks every first-fold row.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const source_host = prover.pcs.four_root_pair_openings_experimental;
const wire = core.pcs.four_root_pair_wire_experimental;
const h1 = core.pcs.four_root_independent_h1_experimental;
const dual = core.pcs.paired_independent_h1_experimental;
const LineEvaluation = prover.line.LineEvaluation;

test "CAS11 H1 four roots and eight composition columns drive both terminal tracks" {
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
    const all_columns = [11][]const M31{
        &fixed,         &main,          &interaction,
        composition[0], composition[1], composition[2],
        composition[3], composition[4], composition[5],
        composition[6], composition[7],
    };
    var raw: [16]usize = undefined;
    for (&raw, 0..) |*position, i| position.* = 2 * i + 1;
    var source_proof = try source_host.prove(alloc, .{
        .columns = .{
            &fixed_columns, &main_columns, &interaction_columns,
            &composition,
        },
        .lifting_log_size = k,
        .raw_queries = &raw,
    });
    defer source_proof.deinit();
    const encoded = try wire.encode(alloc, source_proof.expected, source_proof.openings);
    defer alloc.free(encoded);

    const point = try core.circle.secureFieldPointFromRandomSeedChecked(QM31.fromU32Unchecked(1, 2, 3, 4));
    var claims: [11]QM31 = undefined;
    var claim_arena = std.heap.ArenaAllocator.init(alloc);
    defer claim_arena.deinit();
    try prover.pcs.paired_two_height_experimental.evaluateClaims(claim_arena.allocator(), domain, &all_columns, point, &claims);
    const batch = QM31.fromU32Unchecked(7, 0, 0, 0);
    const alpha = QM31.fromU32Unchecked(9, 0, 0, 0);
    const statement = h1.Statement{
        .source = source_proof.expected,
        .point = point,
        .claims = .{
            claims[0..1], claims[1..2], claims[2..3], claims[3..11],
        },
        .batch_challenge = batch,
        .fold_challenge = alpha,
        .log_blowup = 2,
    };
    const bound = try h1.terminalLength(statement);
    try std.testing.expectEqual(@as(usize, 4), bound);
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
    for (0..2) |track| {
        var folded = [_]QM31{QM31.zero()} ** 16;
        var workspace = try core.fri.folding.FoldCircleWorkspace.init(alloc, 16);
        defer workspace.deinit(alloc);
        try core.fri.folding.foldCircleIntoLineWithWorkspace(alloc, &folded, &batches[track], domain, alpha, &workspace);
        var evaluation = try LineEvaluation.initBorrowed(line_domain, &folded);
        var polynomial = try evaluation.interpolate(alloc);
        defer polynomial.deinit(alloc);
        const coefficients = polynomial.intoOrderedCoefficients();
        for (coefficients[bound..]) |coefficient|
            try std.testing.expect(coefficient.isZero());
        terminal[track] = try alloc.dupe(QM31, coefficients[0..bound]);
    }
    defer for (terminal) |coefficients| alloc.free(coefficients);
    try h1.verify(alloc, statement, .{
        .source_wire = encoded,
        .terminals = .{ terminal[0], terminal[1] },
    });
    try std.testing.expect(!terminal[0][0].eql(terminal[1][0]));
}
