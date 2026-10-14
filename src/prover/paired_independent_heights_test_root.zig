//! Focused CAS09 two-track sparse-height native proof regression.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_independent_heights_experimental;
const cascade = core.pcs.paired_independent_heights_experimental;
const wire = core.pcs.paired_independent_heights_wire;
const dual_rows = core.pcs.paired_independent_h1_experimental;
const old_host = @import("stwo_prover_engine").pcs.paired_two_height_experimental;
const M31 = core.fields.m31.M31;
const Channel = core.channel.blake2s.Blake2sChannel;

test "CAS09 gapped H4 authenticates both original and own-quotient fold tracks" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(6).circleDomain();
    var top: [64]M31 = undefined;
    for (&top, 0..) |*value, row|
        value.* = domain.at(core.utils.bitReverseIndex(row, 6)).x.add(M31.fromCanonical(3));
    const h2_values = [_]M31{M31.fromCanonical(5)} ** 16;
    const h3_values = [_]M31{M31.fromCanonical(7)} ** 8;
    const h0 = [_][]const M31{&top};
    const h1 = [_][]const M31{};
    const h2 = [_][]const M31{&h2_values};
    const h3 = [_][]const M31{&h3_values};
    const heights = [_][]const []const M31{ &h0, &h1, &h2, &h3 };
    var prover_channel = Channel{};
    var proof = try host.prove(allocator, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 8,
    }, &prover_channel);
    defer proof.deinit();
    const encoded = try wire.encode(allocator, proof.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(allocator, encoded, &verifier_channel, .{
        .profile = proof.proof.profile,
        .source_root = proof.proof.source_root,
        .claims = proof.proof.claims,
    });
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqualSlices(u8, wire.MAGIC, encoded[0..wire.MAGIC.len]);
    try std.testing.expectEqual(@as(usize, 3), proof.proof.line_openings.len);
    try std.testing.expectEqual(@as(usize, 1), proof.proof.terminals[0].len);
    try std.testing.expectEqual(@as(usize, 1), proof.proof.terminals[1].len);
}

test "CAS09 H1 uses two terminal tracks without intermediate roots" {
    const allocator = std.testing.allocator;
    const constant = [_]M31{M31.fromCanonical(7)} ** 32;
    const h0 = [_][]const M31{&constant};
    const heights = [_][]const []const M31{&h0};
    var prover_channel = Channel{};
    var proof = try host.prove(allocator, .{
        .source_columns = &heights,
        .log_blowup = 2,
        .n_queries = 4,
    }, &prover_channel);
    defer proof.deinit();
    const encoded = try wire.encode(allocator, proof.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(allocator, encoded, &verifier_channel, .{
        .profile = proof.proof.profile,
        .source_root = proof.proof.source_root,
        .claims = proof.proof.claims,
    });
    try std.testing.expectEqual(@as(usize, 0), proof.proof.line_openings.len);
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
}

test "two separate row tracks reconstruct the legacy paired-column order" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var x: [32]M31 = undefined;
    for (&x, 0..) |*value, row|
        value.* = domain.at(core.utils.bitReverseIndex(row, 5)).x.add(M31.fromCanonical(3));
    const constant = [_]M31{M31.fromCanonical(11)} ** 32;
    const columns = [_][]const M31{ &x, &constant };
    const h0 = [_][]const []const M31{&columns};
    var channel = Channel{};
    var proof = try host.prove(allocator, .{ .source_columns = &h0, .log_blowup = 2, .n_queries = 4 }, &channel);
    defer proof.deinit();
    const lambda = core.fields.qm31.QM31.fromBase(M31.fromCanonical(13));
    var rows = try dual_rows.RowContext.init(allocator, proof.proof.sampled_point, proof.proof.claims[0], lambda.square());
    defer rows.deinit();
    const combined = try old_host.pairedHeight(
        allocator,
        domain,
        &columns,
        proof.proof.claims[0],
        proof.proof.sampled_point,
        .{ .batch = lambda },
    );
    defer allocator.free(combined);
    for (combined, 0..) |word, row| {
        const point = domain.at(core.utils.bitReverseIndex(row, 5));
        const separate = try rows.dense(&columns, row, point);
        try std.testing.expect(word.eql(separate[0].add(lambda.mul(separate[1]))));
    }
}
