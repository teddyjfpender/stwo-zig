//! Immutable producer inputs and transactional owned capture, without proving.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePointQM31;
const TreeVec = core.pcs.TreeVec;
const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
const Capture = core.verifier.ProofCapture(suite.Hasher);

fn matrix(comptime T: type, a: std.mem.Allocator, value: T) !TreeVec([][]T) {
    const column = try a.dupe(T, &.{value});
    errdefer a.free(column);
    const tree = try a.dupe([]T, &.{column});
    errdefer a.free(tree);
    return TreeVec([][]T).initOwned(try a.dupe([][]T, &.{tree}));
}
fn fixture(a: std.mem.Allocator) !suite.Proof {
    var samples = try matrix(Q, a, Q.fromU32Unchecked(1, 2, 3, 4));
    errdefer samples.deinitDeep(a);
    var queried = try matrix(M, a, M.fromCanonical(5));
    errdefer queried.deinitDeep(a);
    const roots = try a.dupe(suite.Hasher.Hash, &.{@splat(1)});
    errdefer a.free(roots);
    const witness = try a.dupe(suite.Hasher.Hash, &.{@splat(2)});
    errdefer a.free(witness);
    const decommitments = try a.dupe(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher), &.{.{ .hash_witness = witness }});
    errdefer a.free(decommitments);
    const fri_values = try a.dupe(Q, &.{Q.one()});
    errdefer a.free(fri_values);
    const fri_hashes = try a.dupe(suite.Hasher.Hash, &.{@splat(3)});
    errdefer a.free(fri_hashes);
    const inner = try a.alloc(core.fri.FriLayerProof(suite.Hasher), 0);
    errdefer a.free(inner);
    const last = try a.dupe(Q, &.{Q.one()});
    errdefer a.free(last);
    return .{
        .commitment_scheme_proof = .{
            // Unsupported PoW rejects deterministically after FRI construction;
            // there is no nonce search and no successful proof assertion here.
            .config = .{ .pow_bits = 33, .fri_config = try core.fri.FriConfig.init(0, 1, 2) },
            .commitments = TreeVec(suite.Hasher.Hash).initOwned(roots),
            .sampled_values = samples,
            .queried_values = queried,
            .decommitments = TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLifted(suite.Hasher)).initOwned(decommitments),
            .proof_of_work = 0,
            .fri_proof = .{ .first_layer = .{ .fri_witness = fri_values, .decommitment = .{ .hash_witness = fri_hashes }, .commitment = @splat(4) }, .inner_layers = inner, .last_layer_poly = core.poly.line.LinePoly.initOwned(last) },
        },
    };
}
fn digest(proof: *const suite.Proof) [32]u8 {
    const p = &proof.commitment_scheme_proof;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(std.mem.sliceAsBytes(p.commitments.items));
    for (p.sampled_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (p.queried_values.items) |tree| for (tree) |values| hash.update(std.mem.sliceAsBytes(values));
    for (p.decommitments.items) |d| hash.update(std.mem.sliceAsBytes(d.hash_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.first_layer.fri_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.first_layer.decommitment.hash_witness));
    hash.update(std.mem.sliceAsBytes(p.fri_proof.last_layer_poly.coefficients()));
    return hash.finalResult();
}
fn assertPcsFailure(a: std.mem.Allocator, verifier: *const Verifier, proof: *const suite.Proof) !void {
    const before = digest(proof);
    const points = try matrix(Point, a, core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17));
    var channel = suite.Channel{};
    var publication: [@sizeOf(Capture)]u8 align(@alignOf(Capture)) = @splat(0x5a);
    const result = verifier.verifyValuesWithBorrowedProofCapture(a, points, &proof.commitment_scheme_proof, &channel, .{ .composition_randomness = Q.one(), .oods_seed = Q.one() }, @ptrCast(&publication));
    try std.testing.expectEqualDeep(before, digest(proof));
    for (publication) |byte| try std.testing.expectEqual(@as(u8, 0x5a), byte);
    if (result) |_| return error.AcceptedInvalidBorrowedProof else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(error.ProofOfWork, err);
    }
}
test "borrowed proof capture preserves original PCS vectors on late rejection and every allocation failure" {
    const a = std.testing.allocator;
    var proof = try fixture(a);
    defer proof.deinit(a);
    var verifier = try Verifier.init(a, proof.commitment_scheme_proof.config);
    defer verifier.deinit(a);
    var channel = suite.Channel{};
    try verifier.commit(a, @splat(1), &.{1}, &channel);
    try assertPcsFailure(a, &verifier, &proof);
    try assertPcsFailure(a, &verifier, &proof);
    // Temporary verifier allocations belong to the fault allocator; every
    // original proof vector remains owned by a different live allocator.
    try std.testing.checkAllAllocationFailures(a, assertPcsFailure, .{ &verifier, &proof });
}
test "borrowed proof capture preserves STARK input and publication on early rejection" {
    const a = std.testing.allocator;
    var proof = try fixture(a);
    defer proof.deinit(a);
    const before = digest(&proof);
    var verifier = try Verifier.init(a, proof.commitment_scheme_proof.config);
    defer verifier.deinit(a);
    var channel = suite.Channel{};
    var publication: [@sizeOf(Capture)]u8 align(@alignOf(Capture)) = @splat(0x6b);
    try std.testing.expectError(error.InvalidPreprocessedTree, core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{}, &channel, &verifier, &proof, @ptrCast(&publication)));
    try std.testing.expectEqualDeep(before, digest(&proof));
    for (publication) |byte| try std.testing.expectEqual(@as(u8, 0x6b), byte);
}
