//! Focused CAS07 candidate prover/verifier geometry and hostile checks.
const std = @import("std");
const core = @import("stwo_core");
const host = @import("stwo_prover_engine").pcs.paired_sparse_cascade_heights_experimental;
const cascade = core.pcs.paired_sparse_cascade_heights_experimental;
const wire = core.pcs.paired_sparse_cascade_heights_wire;
const old_wire = core.pcs.paired_sparse_cascade_wire;
const source = core.pcs.transposed_merkle_sparse_heights_experimental;
const source_host = @import("stwo_prover_engine").pcs.transposed_sparse_heights_experimental;
const prelude = core.pcs.s31_cas05_prelude_experimental;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Channel = core.channel.blake2s.Blake2sChannel;

fn statement(proof: cascade.Proof) cascade.ExpectedStatement {
    return .{ .profile = proof.profile, .source_root = proof.source_root, .claims = proof.claims };
}

test "CAS07 H=1 proves and verifies, with terminal and format failures" {
    const allocator = std.testing.allocator;
    const top_values = [_]M31{M31.fromCanonical(7)} ** 32;
    const h0 = [_][]const M31{&top_values};
    const heights = [_][]const []const M31{&h0};
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 3 };
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, input, &prover_channel);
    defer owned.deinit();
    const encoded = try wire.encode(allocator, owned.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(allocator, encoded, &verifier_channel, statement(owned.proof));
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectError(error.UnsupportedProofFormat, old_wire.decode(allocator, encoded));

    var bad = try allocator.dupe(u8, encoded);
    defer allocator.free(bad);
    bad[8] = 6;
    try std.testing.expectError(error.UnsupportedProofVersion, wire.decode(allocator, bad));
    bad[8] = 7;
    var wrong_statement = statement(owned.proof);
    wrong_statement.source_root[0] ^= 1;
    var rejected = Channel{};
    try std.testing.expectError(error.UnexpectedSparseStatement, wire.verifyAgainstStatement(
        allocator,
        encoded,
        &rejected,
        wrong_statement,
    ));
    const initial = Channel{};
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);

    var fake_channel = Channel{};
    var fake = try host.proveWithInvalidTerminalForTest(allocator, input, &fake_channel);
    defer fake.deinit();
    const fake_bytes = try wire.encode(allocator, fake.proof);
    defer allocator.free(fake_bytes);
    try std.testing.expectError(error.TerminalFoldMismatch, wire.verifyAgainstStatement(
        allocator,
        fake_bytes,
        &rejected,
        statement(fake.proof),
    ));
}

test "CAS07 H=1 verifies a nonconstant circle polynomial at sampled source pairs" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(5).circleDomain();
    var values: [32]M31 = undefined;
    for (&values, 0..) |*value, row| {
        const point = domain.at(core.utils.bitReverseIndex(row, 5));
        value.* = point.x.add(M31.fromCanonical(7));
    }
    const h0 = [_][]const M31{&values};
    const heights = [_][]const []const M31{&h0};
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 32 };
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, input, &prover_channel);
    defer owned.deinit();
    var verifier_channel = Channel{};
    try cascade.verifyAgainstStatement(allocator, owned.proof, &verifier_channel, statement(owned.proof));
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(@as(usize, 0), owned.proof.line_openings.len);
    try std.testing.expectEqual(@as(usize, 4), owned.proof.terminal_ordered_coeffs.len);
}

test "an absent CAS07 height folds the preceding line without an inserted term" {
    const allocator = std.testing.allocator;
    const line_domain = core.poly.line.LineDomain.fromCircleDomain(
        core.poly.circle.canonic.CanonicCoset.new(5).circleDomain(),
    );
    const inserted_domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    var previous: [16]QM31 = undefined;
    for (&previous, 0..) |*value, row|
        value.* = QM31.fromBase(M31.fromCanonical(@intCast(3 * row * row + row + 11)));
    const zero = [_]QM31{QM31.zero()} ** 16;
    const alpha = QM31.fromBase(M31.fromCanonical(137));
    const folded = try core.fri.multidomain_insertion.insertCircleBatch(
        allocator,
        &previous,
        line_domain,
        &zero,
        inserted_domain,
        alpha,
    );
    defer allocator.free(folded.values);
    try std.testing.expectEqual(@as(usize, 8), folded.values.len);
    for (folded.values, 0..) |actual, row| {
        const x = line_domain.at(core.utils.bitReverseIndex(row, 3));
        const even = previous[2 * row];
        const odd = previous[2 * row + 1];
        const expected = even.add(odd).add(alpha.mul(even.sub(odd).mulM31(try x.inv())));
        try std.testing.expect(actual.eql(expected));
    }
}

test "CAS07 gapped H=4 proves and verifies, with forged line rejected" {
    const allocator = std.testing.allocator;
    const top_values = [_]M31{M31.fromCanonical(3)} ** 64;
    const h2_values = [_]M31{M31.fromCanonical(5)} ** 16;
    const h3_values = [_]M31{M31.fromCanonical(7)} ** 8;
    const h0 = [_][]const M31{&top_values};
    const h1 = [_][]const M31{};
    const h2 = [_][]const M31{&h2_values};
    const h3 = [_][]const M31{&h3_values};
    const heights = [_][]const []const M31{ &h0, &h1, &h2, &h3 };
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 3 };
    var prover_channel = Channel{};
    var owned = try host.prove(allocator, input, &prover_channel);
    defer owned.deinit();
    const encoded = try wire.encode(allocator, owned.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstStatement(allocator, encoded, &verifier_channel, statement(owned.proof));
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(@as(u16, 0), owned.proof.profile.source.columns[1]);

    var fake_channel = Channel{};
    var fake = try host.proveWithInvalidLineForTest(allocator, input, &fake_channel);
    defer fake.deinit();
    const fake_bytes = try wire.encode(allocator, fake.proof);
    defer allocator.free(fake_bytes);
    var rejected = Channel{};
    try std.testing.expectError(error.IntermediateFoldMismatch, wire.verifyAgainstStatement(
        allocator,
        fake_bytes,
        &rejected,
        statement(fake.proof),
    ));
}

test "CAS07 profile admits current Gate heights and bounds source residency" {
    var counts = [_]u16{0} ** source.MAX_HEIGHTS;
    counts[0] = 51; // log 20
    counts[2] = 8; // log 18
    counts[4] = 15; // log 16
    counts[6] = 8; // log 14
    counts[11] = 28; // log 9
    counts[12] = 8; // log 8
    counts[16] = 193; // log 4
    const profile = cascade.Profile{ .source = .{
        .largest_log_size = 20,
        .height_count = 17,
        .columns = counts,
        .query_count = 32,
    }, .log_blowup = 2 };
    try profile.validate();
    try std.testing.expectEqual(@as(usize, 2), profile.terminalLength());
    const source_words: usize = 56_708_112;
    const source_tree_bytes = try source_host.Commitment.estimatedHostBytes(20, source_words);
    try std.testing.expectEqual(@as(usize, 293_941_280), source_tree_bytes);
    try std.testing.expect(source_tree_bytes < source_host.Commitment.MAX_RESIDENT_BYTES);
    // This bound excludes paired batches, FRI line trees, source copies,
    // allocation overhead, and proof serialization; it is not a prover cap.
    counts[16] = 257;
    try std.testing.expectError(error.InvalidCascadeProfile, (cascade.Profile{ .source = .{
        .largest_log_size = 20,
        .height_count = 17,
        .columns = counts,
        .query_count = 32,
    }, .log_blowup = 2 }).validate());
}

test "CAS07 candidate S31 prelude binds key words and roster before source profile" {
    const allocator = std.testing.allocator;
    const values = [_]M31{M31.fromCanonical(13)} ** 32;
    const h0 = [_][]const M31{&values};
    const heights = [_][]const []const M31{&h0};
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 2 };
    const binding = prelude.Binding{
        .installed_key_sha256 = [_]u8{0x11} ** 32,
        .public_words = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .source_air_roster_sha256 = [_]u8{0x22} ** 32,
    };
    var prover_channel = Channel{};
    var owned = try host.proveForS31Statement(allocator, input, &prover_channel, binding);
    defer owned.deinit();
    const encoded = try wire.encode(allocator, owned.proof);
    defer allocator.free(encoded);
    var verifier_channel = Channel{};
    try wire.verifyAgainstS31Statement(allocator, encoded, &verifier_channel, binding, statement(owned.proof));
    try std.testing.expectEqualSlices(u8, &prover_channel.digest, &verifier_channel.digest);
    var changed = binding;
    changed.source_air_roster_sha256[0] ^= 1;
    var rejected = Channel{};
    try std.testing.expectError(error.UnsampledOodPoint, wire.verifyAgainstS31Statement(allocator, encoded, &rejected, changed, statement(owned.proof)));
    const initial = Channel{};
    try std.testing.expectEqualSlices(u8, &initial.digest, &rejected.digest);
}

test "CAS07 full Gate roster nonconstant pilot" {
    var input_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer input_arena.deinit();
    const a = input_arena.allocator();
    const counts = [_]usize{ 51, 0, 8, 0, 15, 0, 8, 0, 0, 0, 0, 28, 8, 0, 0, 0, 193 };
    var heights: [17][]const []const M31 = undefined;
    for (counts, 0..) |count, i| {
        const columns = try a.alloc([]const M31, count);
        if (count > 0) {
            const log_size: u32 = @intCast(20 - i);
            const values = try a.alloc(M31, @as(usize, 1) << @intCast(log_size));
            const domain = core.poly.circle.canonic.CanonicCoset.new(log_size).circleDomain();
            for (values, 0..) |*value, row| {
                const point = domain.at(core.utils.bitReverseIndex(row, log_size));
                value.* = point.x.add(M31.fromCanonical(@intCast(i + 1)));
            }
            for (columns) |*column| column.* = values;
        }
        heights[i] = columns;
    }
    const input = host.Input{ .source_columns = &heights, .log_blowup = 2, .n_queries = 232 };
    var channel = Channel{};
    var timer = try std.time.Timer.start();
    var owned = try host.prove(std.testing.allocator, input, &channel);
    defer owned.deinit();
    const proving_ns = timer.read();
    const bytes = try wire.encode(std.testing.allocator, owned.proof);
    defer std.testing.allocator.free(bytes);
    var verify_channel = Channel{};
    const verifying_start = timer.read();
    try wire.verifyAgainstStatement(std.testing.allocator, bytes, &verify_channel, statement(owned.proof));
    const verifying_ns = timer.read() - verifying_start;
    try std.testing.expectEqualSlices(u8, &channel.digest, &verify_channel.digest);
    std.debug.print("GATE_PILOT proving_ns={d} verifying_ns={d} proof_bytes={d}\n", .{ proving_ns, verifying_ns, bytes.len });
}
