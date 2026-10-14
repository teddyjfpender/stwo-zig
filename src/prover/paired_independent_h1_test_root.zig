//! Focused tests for experimental independent original and own-quotient FRI.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_independent_h1_experimental;
const LineEvaluation = @import("stwo_prover_engine").line.LineEvaluation;
const dual = core.pcs.paired_independent_h1_experimental;
const wire = core.pcs.paired_independent_h1_wire;
const M31 = core.fields.m31.M31;
const Channel = core.channel.blake2s.Blake2sChannel;

test "H1 authentic source drives two distinct terminal degree checks" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var x: [32]M31 = undefined;
    for (&x, 0..) |*value, row|
        value.* = domain.at(core.utils.bitReverseIndex(row, 5)).x.add(M31.fromCanonical(7));
    const constant = [_]M31{M31.fromCanonical(11)} ** 32;
    const columns = [_][]const M31{ &x, &constant };
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, .{ .columns = &columns, .log_blowup = 2, .query_count = 16 }, &prover_channel);
    defer owned.deinit();
    const statement = dual.ExpectedStatement{
        .profile = owned.proof.profile,
        .source_root = owned.proof.source_root,
        .claims = owned.proof.claims,
    };
    const encoded = try wire.encode(allocator, owned.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(allocator, encoded, &verifier_channel, statement);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqualSlices(u8, wire.MAGIC, encoded[0..wire.MAGIC.len]);
    try std.testing.expectEqual(@as(usize, 4), owned.proof.original_terminal.len);
    try std.testing.expectEqual(@as(usize, 4), owned.proof.quotient_terminal.len);
    // The source original is nonconstant and the conjugate quotient is
    // separately represented in the second terminal, not a single blend.
    try std.testing.expect(!owned.proof.original_terminal[0].eql(owned.proof.quotient_terminal[0]));
}

test "local source-degree preflight refuses an overdegree column" {
    const allocator = std.testing.allocator;
    var values = [_]M31{M31.zero()} ** 32;
    values[0] = M31.one();
    const columns = [_][]const M31{&values};
    var channel = Channel{};
    try std.testing.expectError(error.SourceDegreeExceeded, host.prove(
        allocator,
        .{ .columns = &columns, .log_blowup = 2, .query_count = 3 },
        &channel,
    ));
    const zero = Channel{};
    try std.testing.expectEqualSlices(u8, &zero.digest, &channel.digest);
}

test "a wrong constant claim leaves the original track low degree but makes its own quotient high degree" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    const values = [_]M31{M31.fromCanonical(7)} ** 32;
    const columns = [_][]const M31{&values};
    var prover_channel = Channel{};
    var honest = try host.prove(allocator, .{ .columns = &columns, .log_blowup = 2, .query_count = 3 }, &prover_channel);
    defer honest.deinit();
    const wrong_claim = [_]core.fields.qm31.QM31{honest.proof.claims[0][0].add(core.fields.qm31.QM31.one())};
    var context = try dual.RowContext.init(allocator, honest.proof.sampled_point, &wrong_claim, core.fields.qm31.QM31.one());
    defer context.deinit();
    const originals = try allocator.alloc(core.fields.qm31.QM31, 32);
    defer allocator.free(originals);
    const quotients = try allocator.alloc(core.fields.qm31.QM31, 32);
    defer allocator.free(quotients);
    for (0..32) |row| {
        const point = domain.at(core.utils.bitReverseIndex(row, 5));
        const word = try context.dense(&columns, row, point);
        originals[row] = word[0];
        quotients[row] = word[1];
    }
    const alpha = core.fields.qm31.QM31.fromBase(M31.fromCanonical(13));
    const original_line = try allocator.alloc(core.fields.qm31.QM31, 16);
    defer allocator.free(original_line);
    const quotient_line = try allocator.alloc(core.fields.qm31.QM31, 16);
    defer allocator.free(quotient_line);
    @memset(original_line, core.fields.qm31.QM31.zero());
    @memset(quotient_line, core.fields.qm31.QM31.zero());
    var workspace = try core.fri.folding.FoldCircleWorkspace.init(allocator, 16);
    defer workspace.deinit(allocator);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(allocator, original_line, originals, domain, alpha, &workspace);
    try core.fri.folding.foldCircleIntoLineWithWorkspace(allocator, quotient_line, quotients, domain, alpha, &workspace);
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(domain);
    var original_evaluation = try LineEvaluation.initBorrowed(line_domain, original_line);
    var original_poly = try original_evaluation.interpolate(allocator);
    defer original_poly.deinit(allocator);
    var quotient_evaluation = try LineEvaluation.initBorrowed(line_domain, quotient_line);
    var quotient_poly = try quotient_evaluation.interpolate(allocator);
    defer quotient_poly.deinit(allocator);
    const bound = honest.proof.profile.terminalLength();
    for (original_poly.intoOrderedCoefficients()[bound..]) |coefficient|
        try std.testing.expect(coefficient.isZero());
    var quotient_exceeds = false;
    for (quotient_poly.intoOrderedCoefficients()[bound..]) |coefficient|
        quotient_exceeds = quotient_exceeds or !coefficient.isZero();
    try std.testing.expect(quotient_exceeds);
}
