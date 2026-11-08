//! A literal constant-polynomial PCS fixture; no STARK/FRI prover or guest runs.
const std = @import("std");
const core = @import("stwo_core");
const Suite = core.proof_suites.Blake3;
const H = Suite.Hasher;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const TreeVec = core.pcs.TreeVec;
const Proof = core.pcs.CommitmentSchemeProof(H);
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(H, Suite.MerkleChannel);
const Capture = core.pcs.verifier.VerifiedProofCapture(H);
const challenges = core.pcs.verifier.ProofCaptureChallenges{ .composition_randomness = Q.fromU32Unchecked(1, 2, 3, 4), .oods_seed = Q.fromU32Unchecked(5, 6, 7, 8) };

fn matrix(comptime T: type, a: std.mem.Allocator, values: []const T) !TreeVec([][]T) {
    const column = try a.dupe(T, values);
    errdefer a.free(column);
    const tree = try a.dupe([]T, &.{column});
    errdefer a.free(tree);
    return TreeVec([][]T).initOwned(try a.dupe([][]T, &.{tree}));
}
fn leaf(values: []const M) H.Hash {
    var hash = H.defaultWithInitialState();
    hash.updateLeaf(values);
    return hash.finalize();
}
fn node(hash: H.Hash) H.Hash {
    return H.hashChildren(.{ .left = hash, .right = hash });
}
/// Exact multiproof for a four-leaf constant tree, in bottom-up Merkle order.
fn witness(a: std.mem.Allocator, selected_in: [4]bool, leaf_hash: H.Hash) ![]H.Hash {
    var selected = selected_in;
    var hashes: [3]H.Hash = undefined;
    var count: usize = 0;
    var width: usize = 4;
    var hash = leaf_hash;
    while (width > 1) : (width /= 2) {
        for (0..width / 2) |pair| {
            const left = selected[2 * pair];
            const right = selected[2 * pair + 1];
            if (left != right) {
                hashes[count] = hash;
                count += 1;
            }
            selected[pair] = left or right;
        }
        hash = node(hash);
    }
    return a.dupe(H.Hash, hashes[0..count]);
}
fn fixture(a: std.mem.Allocator) !Proof {
    // The committed column is constant seven. Its opening quotient and every
    // FRI evaluation are zero; those values are written literally, not proved.
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 7) };
    const trace_leaf = leaf(&.{M.fromCanonical(7)});
    const trace_root = node(node(trace_leaf));
    const fri_leaf = leaf(&.{ M.zero(), M.zero(), M.zero(), M.zero() });
    const fri_root = node(node(fri_leaf));
    var channel = Suite.Channel{};
    Suite.MerkleChannel.mixRoot(&channel, trace_root);
    channel.mixFelts(&.{Q.fromBase(M.fromCanonical(7))});
    _ = channel.drawSecureFelt(); // DEEP randomness.
    Suite.MerkleChannel.mixRoot(&channel, fri_root);
    _ = channel.drawSecureFelt(); // First-layer fold challenge.
    channel.mixFelts(&.{Q.zero()});
    channel.mixU64(0);
    const raw = try core.queries.drawQueries(&channel, a, 2, config.fri_config.n_queries);
    defer a.free(raw);
    var queries = try core.queries.Queries.init(a, raw, 2);
    defer queries.deinit(a);
    var selected: [4]bool = @splat(false);
    var values: [4]M = @splat(M.fromCanonical(7));
    for (queries.positions) |position| selected[position] = true;
    var samples = try matrix(Q, a, &.{Q.fromBase(M.fromCanonical(7))});
    errdefer samples.deinitDeep(a);
    var queried = try matrix(M, a, values[0..queries.positions.len]);
    errdefer queried.deinitDeep(a);
    const roots = try a.dupe(H.Hash, &.{trace_root});
    errdefer a.free(roots);
    const trace_witness = try witness(a, selected, trace_leaf);
    errdefer a.free(trace_witness);
    const decommitments = try a.dupe(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H), &.{.{ .hash_witness = trace_witness }});
    errdefer a.free(decommitments);
    var expanded: [4]bool = @splat(false);
    var missing: usize = 0;
    for (0..2) |pair| {
        if (!selected[2 * pair] and !selected[2 * pair + 1]) continue;
        expanded[2 * pair] = true;
        expanded[2 * pair + 1] = true;
        if (!selected[2 * pair]) missing += 1;
        if (!selected[2 * pair + 1]) missing += 1;
    }
    const fri_values = try a.alloc(Q, missing);
    errdefer a.free(fri_values);
    @memset(fri_values, Q.zero());
    const fri_witness = try witness(a, expanded, fri_leaf);
    errdefer a.free(fri_witness);
    const inner = try a.alloc(core.fri.FriLayerProof(H), 0);
    errdefer a.free(inner);
    const last = try a.dupe(Q, &.{Q.zero()});
    return .{
        .config = config,
        .commitments = TreeVec(H.Hash).initOwned(roots),
        .sampled_values = samples,
        .queried_values = queried,
        .decommitments = TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(H)).initOwned(decommitments),
        .proof_of_work = 0,
        .fri_proof = .{ .first_layer = .{ .fri_witness = fri_values, .decommitment = .{ .hash_witness = fri_witness }, .commitment = fri_root }, .inner_layers = inner, .last_layer_poly = core.poly.line.LinePoly.initOwned(last) },
    };
}
fn digest(proof: *const Proof) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(std.mem.sliceAsBytes(proof.commitments.items));
    for (proof.sampled_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (proof.queried_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (proof.decommitments.items) |d| hash.update(std.mem.sliceAsBytes(d.hash_witness));
    hash.update(std.mem.sliceAsBytes(proof.fri_proof.first_layer.fri_witness));
    hash.update(std.mem.sliceAsBytes(proof.fri_proof.first_layer.decommitment.hash_witness));
    hash.update(std.mem.sliceAsBytes(proof.fri_proof.last_layer_poly.coefficients()));
    return hash.finalResult();
}
fn points(a: std.mem.Allocator) !TreeVec([][]Point) {
    return matrix(Point, a, &.{core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17)});
}
fn channelFor(proof: *const Proof) Suite.Channel {
    var channel = Suite.Channel{};
    Suite.MerkleChannel.mixRoot(&channel, proof.commitments.items[0]);
    return channel;
}
fn assertSuccess(a: std.mem.Allocator, verifier: *const Verifier, proof: *const Proof) !void {
    const before = digest(proof);
    var channel = channelFor(proof);
    var publication: [@sizeOf(Capture)]u8 align(@alignOf(Capture)) = @splat(0x7b);
    verifier.verifyValuesWithBorrowedProofCapture(a, try points(a), proof, &channel, challenges, @ptrCast(&publication)) catch |err| {
        try std.testing.expectEqualDeep(before, digest(proof));
        for (publication) |byte| try std.testing.expectEqual(@as(u8, 0x7b), byte);
        return err;
    };
    const capture: *Capture = @ptrCast(&publication);
    defer capture.deinit(a);
    try std.testing.expectEqualDeep(before, digest(proof));
    try std.testing.expectEqual(@as(usize, 7), capture.queries.raw.len);
    try std.testing.expect(capture.queries.raw.len > capture.queries.unique.len);
    try std.testing.expectEqual(@as(u32, 2), capture.trace_paths[0].path_depth);
    try std.testing.expectEqual(@as(usize, 1), capture.fri.layers.len);
    try std.testing.expectEqual(@as(u32, 1), capture.fri.layers[0].path_depth);
    for (capture.queried_values) |value| try std.testing.expect(value.eql(M.fromCanonical(7)));
    for (capture.deep_answers) |value| try std.testing.expect(value.eql(Q.zero()));
}
test "borrowed proof capture successful constant PCS remains immutable through every allocation failure" {
    const a = std.testing.allocator;
    var proof = try fixture(a);
    defer proof.deinit(a);
    var verifier = try Verifier.init(a, proof.config);
    defer verifier.deinit(a);
    var channel = Suite.Channel{};
    try verifier.commit(a, proof.commitments.items[0], &.{1}, &channel);
    try assertSuccess(a, &verifier, &proof);
    try std.testing.checkAllAllocationFailures(a, assertSuccess, .{ &verifier, &proof });
}
test "borrowed proof capture matches owned verification and outlives poisoned original vectors" {
    const a = std.testing.allocator;
    var proof = try fixture(a);
    var proof_live = true;
    defer if (proof_live) proof.deinit(a);
    var verifier = try Verifier.init(a, proof.config);
    defer verifier.deinit(a);
    var setup = Suite.Channel{};
    try verifier.commit(a, proof.commitments.items[0], &.{1}, &setup);
    var channel = channelFor(&proof);
    var borrowed: Capture = undefined;
    try verifier.verifyValuesWithBorrowedProofCapture(a, try points(a), &proof, &channel, challenges, &borrowed);
    defer borrowed.deinit(a);
    var owned_proof = try fixture(a);
    var owned_live = true;
    defer if (owned_live) owned_proof.deinit(a);
    const owned_points = try points(a);
    var owned_channel = channelFor(&owned_proof);
    var owned: Capture = undefined;
    owned_live = false; // Existing entry point consumes this entire proof.
    try verifier.verifyValuesWithProofCapture(a, owned_points, owned_proof, &owned_channel, challenges, &owned);
    defer owned.deinit(a);
    try std.testing.expectEqualDeep(owned, borrowed);
    try std.testing.expectEqualDeep(owned_channel, channel);
    // Poison all input payloads while still allocated, then free the original.
    @memset(proof.commitments.items, @splat(0xa5));
    for (proof.sampled_values.items) |tree| for (tree) |values| @memset(values, Q.one());
    for (proof.queried_values.items) |tree| for (tree) |values| @memset(values, M.one());
    for (proof.decommitments.items) |d| @memset(d.hash_witness, @splat(0xa5));
    @memset(proof.fri_proof.first_layer.fri_witness, Q.one());
    @memset(proof.fri_proof.first_layer.decommitment.hash_witness, @splat(0xa5));
    @memset(proof.fri_proof.last_layer_poly.coefficientsMut(), Q.one());
    proof.deinit(a);
    proof_live = false;
    try std.testing.expectEqualDeep(owned, borrowed);
}

fn foldedScratch(a: std.mem.Allocator) !void {
    var values: [8]Q = @splat(Q.zero());
    var subsets = [_][]Q{ &values, &values };
    var positions = [_]usize{ 0, 8 };
    // Borrowed literal evaluations drive the genuine workspace and successive
    // folds, covering teardown on failures beyond the one-layer PCS fixture.
    const sparse = core.fri.SparseEvaluation{ .subset_evals = &subsets, .subset_domain_initial_indexes = &positions };
    const line_domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(4));
    const line_values = try sparse.foldLineSubsetsN(a, Q.one(), line_domain, 3);
    defer a.free(line_values);
    const circle_values = try sparse.foldCircleSubsets(a, Q.one(), core.poly.circle.CanonicCoset.new(4).circleDomain(), 3);
    defer a.free(circle_values);
    for (line_values) |value| try std.testing.expect(value.eql(Q.zero()));
    for (circle_values) |value| try std.testing.expect(value.eql(Q.zero()));
}
test "borrowed proof capture FRI multi-fold scratch releases every allocation failure" {
    try foldedScratch(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, foldedScratch, .{});
}
