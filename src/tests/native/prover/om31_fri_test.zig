//! Native eight-coordinate FRI commitment, openings and fresh core verification.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const F = core.fri.ForField(O);
const PF = engine.fri.ForField(O);
const Backend = @import("stwo_cpu_backend").Om31FriBackend;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const C = core.channel.raw_mod_m31.Om31Channel;
const MC = struct {
    pub fn mixRoot(c: *C, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&c.inner, root);
    }
};
const Prover = PF.FriProver(Backend, H, MC);
const Verifier = F.FriVerifier(H, MC);
const A = std.testing.allocator;
fn value(seed: u32) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 37);
    return O.fromM31Array(coordinates);
}
fn check(a: std.mem.Allocator, proof: F.FriProof(H), config: F.FriConfig, log: u32, values: []const O) !void {
    return checkChannel(a, proof, config, log, values, false);
}
fn checkChannel(a: std.mem.Allocator, proof: F.FriProof(H), config: F.FriConfig, log: u32, values: []const O, altered_channel: bool) !void {
    var channel = C.init();
    if (altered_channel) channel.mixU32s(&.{0xdeadbeef});
    var verifier = try Verifier.commit(a, &channel, config, proof, F.CirclePolyDegreeBound.init(log - config.log_blowup_factor));
    defer verifier.deinit(a);
    const positions = try verifier.sampleQueryPositions(a, &channel);
    defer a.free(positions);
    const answers = try a.alloc(O, positions.len);
    defer a.free(answers);
    for (positions, 0..) |p, i| answers[i] = values[p];
    try verifier.decommit(a, answers);
}
fn exercise(a: std.mem.Allocator, fold_step: u32) !void {
    const log: u32 = 7;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var config = try F.FriConfig.init(0, 1, 16);
    config.fold_step = fold_step;
    const values = try a.alloc(O, domain.size());
    defer a.free(values);
    // A nonzero value in every tower coordinate, not an embedded QM31 fixture.
    for (values, 0..) |*v, i| {
        const point = domain.at(core.utils.bitReverseIndex(i, log));
        v.* = value(13).add(value(29).mulM31(point.x)).add(value(71).mulM31(point.y));
    }
    const column = try engine.secure_column.SecureColumnByCoordsFor(O).fromSecureSlice(a, values);
    var channel = C.init();
    var prover = try Prover.commit(a, &channel, config, domain, column);
    var result = try prover.decommit(a, &channel);
    defer result.deinit(a);
    try check(a, result.fri_proof.proof, config, log, values);
}
test "OM31 FRI actual commit decommit and fresh verification with fold1 and fold4" {
    try exercise(A, 1);
    try exercise(A, 4);
}
test "OM31 FRI public Q facade retains original concrete types" {
    try std.testing.expect(engine.fri.FriProver == engine.fri.ForField(core.fields.qm31.QM31).FriProver);
    try std.testing.expect(engine.secure_column.SecureColumnByCoords == engine.secure_column.SecureColumnByCoordsFor(core.fields.qm31.QM31));
}

fn exerciseFailure(a: std.mem.Allocator) !void {
    try exercise(a, 4);
}
test "OM31 FRI allocation failures release owned planes trees and proofs" {
    try std.testing.checkAllAllocationFailures(A, exerciseFailure, .{});
}
fn expectRejected(result: anyerror!void) !void {
    result catch |err| switch (err) {
        error.InvalidNumFriLayers, error.FirstLayerEvaluationsInvalid, error.FirstLayerCommitmentInvalid, error.InnerLayerCommitmentInvalid, error.InnerLayerEvaluationsInvalid, error.LastLayerDegreeInvalid, error.LastLayerEvaluationsInvalid => return,
        else => return err,
    };
    return error.ExpectedRejection;
}
test "OM31 FRI rejects high-coordinate leaf challenge terminal and shape mutations" {
    const log: u32 = 7;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    var config = try F.FriConfig.init(0, 1, 16);
    config.fold_step = 4;
    const values = try A.alloc(O, domain.size());
    defer A.free(values);
    for (values, 0..) |*v, i| {
        const p = domain.at(core.utils.bitReverseIndex(i, log));
        v.* = value(13).add(value(29).mulM31(p.x)).add(value(71).mulM31(p.y));
    }
    const column = try engine.secure_column.SecureColumnByCoordsFor(O).fromSecureSlice(A, values);
    var channel = C.init();
    var prover = try Prover.commit(A, &channel, config, domain, column);
    var result = try prover.decommit(A, &channel);
    defer result.deinit(A);
    const proof = &result.fri_proof.proof;
    try check(A, proof.*, config, log, values);
    const leaf = &proof.first_layer.fri_witness[0];
    leaf.* = leaf.add(O.basis());
    try expectRejected(check(A, proof.*, config, log, values));
    leaf.* = leaf.sub(O.basis());
    try expectRejected(checkChannel(A, proof.*, config, log, values, true));
    const coefficient = &proof.last_layer_poly.coeffs[0];
    coefficient.* = coefficient.add(O.basis());
    try expectRejected(check(A, proof.*, config, log, values));
    coefficient.* = coefficient.sub(O.basis());
    const original = proof.inner_layers;
    proof.inner_layers = original[0..0];
    try expectRejected(check(A, proof.*, config, log, values));
    proof.inner_layers = original;
    try check(A, proof.*, config, log, values);
}

test {
    _ = @import("fri_test.zig");
}
