//! Focused wide PCS authority gates; complete prover integration is separate.
const std = @import("std");
const core = @import("mod.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const P = core.pcs.ForField(O);
const F = P.quotients;
const a = std.testing.allocator;
fn element(seed: u32) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 31);
    return O.fromM31Array(c);
}
fn eval(point: core.circle.CirclePoint(O), x_scale: u32) O {
    return point.x.mulM31(M.fromCanonical(x_scale)).add(point.y.mulM31(M.fromCanonical(3))).add(O.fromBase(M.fromCanonical(5)));
}

test "wide PCS: dense partial evaluations match independent eight-basis reconstruction" {
    var values: [8]O = undefined;
    var expected = O.zero();
    for (&values, 0..) |*value, i| {
        value.* = element(@intCast(i * 97 + 11));
        var coords = [_]M{M.zero()} ** 8;
        coords[i] = M.one();
        expected = expected.add(value.mul(O.fromM31Array(coords)));
    }
    try std.testing.expect(O.fromPartialEvals(values).eql(expected));
}

test "wide PCS: row and packed denominator plans preserve DEEP line quotients" {
    const points = [_]core.circle.CirclePoint(O){
        try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, element(7)),
        try core.circle.secureFieldPointFromRandomSeedCheckedFor(O, element(101)),
    };
    var data0 = [_]F.NumeratorData{.{ .column_index = 0, .sample_value = eval(points[0], 1), .random_coeff = element(11) }};
    var data1 = [_]F.NumeratorData{.{ .column_index = 1, .sample_value = eval(points[1], 2), .random_coeff = element(113) }};
    const batches = [_]F.ColumnSampleBatch{ .{ .point = points[0], .cols_vals_randpows = &data0 }, .{ .point = points[1], .cols_vals_randpows = &data1 } };
    var constants = try F.quotientConstants(a, &batches);
    defer constants.deinit(a);
    var workspace = try F.RowQuotientWorkspace.init(a, &batches);
    defer workspace.deinit(a);
    var domain: [32]core.circle.CirclePointM31 = undefined;
    var it = core.circle.Coset.halfOdds(5).iter();
    for (&domain) |*p| p.* = it.next().?;
    var denominators: [64]Q = undefined;
    var inverses: [64]Q = undefined;
    try workspace.prepareDenominatorInversesForRowsBatchMajor(&domain, &denominators, &inverses);
    const generator = O{ .c0 = Q.zero(), .c1 = Q.one() };
    const expected = generator.add(generator).mul(element(11).add(element(113).mulM31(M.fromCanonical(2))));
    for (domain, 0..) |p, i| {
        const values = [_]M{ p.x.add(p.y.mul(M.fromCanonical(3))).add(M.fromCanonical(5)), p.x.mul(M.fromCanonical(2)).add(p.y.mul(M.fromCanonical(3))).add(M.fromCanonical(5)) };
        const got = try F.accumulateRowQuotientsWithWorkspace(&batches, &values, &constants, p, &workspace);
        try std.testing.expect(got.eql(expected));
        inline for (0..2) |b| {
            const scalar = core.constraints.quadraticLineDenominator(O, points[b], p);
            try std.testing.expect(denominators[b * domain.len + i].eql(scalar));
            try std.testing.expect(scalar.mul(inverses[b * domain.len + i]).eql(Q.one()));
        }
    }
}

test "wide PCS: point poles fail closed and configuration binds all eight coordinates" {
    const pole = O.fromInner(Q.fromU32Unchecked(0, 1, 0, 0));
    try std.testing.expectError(error.DivisionByZero, core.circle.secureFieldPointFromRandomSeedCheckedFor(O, pole));
    try std.testing.expectError(error.DivisionByZero, core.circle.secureFieldPointFromRandomSeedCheckedFor(O, pole.neg()));
    var actual = core.channel.raw_mod_m31.Om31Channel.init();
    var reference = actual;
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 128) };
    config.mixInto(&actual);
    reference.mixFelts(&.{O.fromM31Array(.{ M.fromCanonical(26), M.one(), M.fromCanonical(128), M.zero(), M.zero(), M.zero(), M.zero(), M.zero() })});
    try std.testing.expectEqualSlices(u8, &actual.digestBytes(), &reference.digestBytes());
}

test "wide PCS: complete native verifier rejects an absent preprocessed tree" {
    const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
    const Channel = core.channel.raw_mod_m31.Om31Channel;
    const MC = struct {
        pub fn mixRoot(ch: *Channel, root: H.Hash) void {
            core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&ch.inner, root);
        }
    };
    var scheme = try P.verifier.CommitmentSchemeVerifier(H, MC).init(a, core.pcs.PcsConfig.default());
    defer scheme.deinit(a);
    const Layer = core.fri.ForField(O).FriLayerProof(H);
    const proof = core.proof.ForField(O).StarkProof(H){ .commitment_scheme_proof = .{
        .config = core.pcs.PcsConfig.default(),
        .commitments = P.TreeVec(H.Hash).initOwned(try a.alloc(H.Hash, 0)),
        .sampled_values = P.TreeVec([][]O).initOwned(try a.alloc([][]O, 0)),
        .decommitments = P.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H)).initOwned(try a.alloc(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H), 0)),
        .queried_values = P.TreeVec([][]M).initOwned(try a.alloc([][]M, 0)),
        .proof_of_work = 0,
        .fri_proof = .{ .first_layer = .{ .fri_witness = try a.alloc(O, 0), .decommitment = .{ .hash_witness = try a.alloc(H.Hash, 0) }, .commitment = @splat(0) }, .inner_layers = try a.alloc(Layer, 0), .last_layer_poly = core.poly.line.LinePolyFor(O).initOwned(try a.dupe(O, &.{O.one()})) },
    } };
    var channel = Channel.init();
    try std.testing.expectError(error.InvalidPreprocessedTree, core.verifier.ForField(O).verify(H, MC, a, &.{}, &channel, &scheme, proof));
}

test "wide PCS: raw-mod proof-of-work preserves the tagged digest and draw counter" {
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    channel.mixU32s(&.{ 17, 29, 41 });
    _ = channel.drawSecureFelt();
    const before = channel.inner.n_draws;
    const digest = channel.digestBytes();
    const nonce = channel.grindWithWorkerCount(8, 1);
    try std.testing.expect(channel.verifyPowNonce(8, nonce));
    try std.testing.expectEqual(nonce, channel.inner.grindWithWorkerCount(8, 1));
    try std.testing.expectEqual(before, channel.inner.n_draws);
    try std.testing.expectEqualSlices(u8, &digest, &channel.digestBytes());
    var invalid: u64 = 0;
    while (channel.inner.verifyPowNonce(8, invalid)) : (invalid += 1) {}
    try std.testing.expect(!channel.verifyPowNonce(8, invalid));
}
