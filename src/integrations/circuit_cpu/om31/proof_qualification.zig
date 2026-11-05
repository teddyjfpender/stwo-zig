//! Actual native-OM31 circuit proof, independent receiver and physical mutations.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const Prove = @import("prove.zig");
fn rejected(a: std.mem.Allocator, key: *const Prove.Authority, p: *Prove.Produced) !void {
    var capture = Prove.verify(a, key, p.outputs, p.claims, &p.proof.proof) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    capture.deinit(a);
    return error.ExpectedOm31CircuitRejection;
}
test "om31 outer actual q108 P20 circuit proof fresh receiver and mutations" {
    const a = std.testing.allocator;
    var ctx = try circuit.builder.Context(P.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(P.Q.fromU32Unchecked(3, 1, 2, 4));
    const y = try ctx.guess(P.Q.fromU32Unchecked(7, 2, 3, 5));
    const out = try ctx.mul(x, y);
    try ctx.setOutputs(&.{out});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(P.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var key = try Prove.Authority.init(a, &pp);
    defer key.deinit();
    var device_key = try Prove.Authority.initForDeviceProver(a, &pp, key.fixedRoot());
    defer device_key.deinit();
    try std.testing.expectEqual(key.identity, device_key.identity);
    try std.testing.expectEqual(key.fixed_logs, device_key.fixed_logs);
    try std.testing.expect(device_key.fixed == null and device_key.device_fixed);
    try std.testing.expectError(error.Om31CircuitDeviceFixedRequiresDeviceProver, Prove.prove(a, &device_key, ctx.values()));
    var timer = try std.time.Timer.start();
    var proof = try Prove.prove(a, &key, ctx.values());
    defer proof.deinit();
    const prove_ns = timer.lap();
    var capture = try Prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
    defer capture.deinit(a);
    const verify_ns = timer.lap();
    var device_capture = try Prove.verify(a, &device_key, proof.outputs, proof.claims, &proof.proof.proof);
    defer device_capture.deinit(a);
    var wrong_root = key.fixedRoot();
    wrong_root[0] ^= 1;
    var wrong_key = try Prove.Authority.initForDeviceProver(a, &pp, wrong_root);
    defer wrong_key.deinit();
    try rejected(a, &wrong_key, &proof);

    try std.testing.expectEqual(@as(u32, 108), proof.proof.proof.commitment_scheme_proof.config.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 20), proof.proof.proof.commitment_scheme_proof.config.pow_bits);
    proof.claims.eq = proof.claims.eq.add(P.O.basis());
    try rejected(a, &key, &proof);
    proof.claims.eq = proof.claims.eq.sub(P.O.basis());
    proof.outputs[0] = proof.outputs[0].add(P.Q.one());
    try rejected(a, &key, &proof);
    proof.outputs[0] = proof.outputs[0].sub(P.Q.one());
    const pcs = &proof.proof.proof.commitment_scheme_proof;
    pcs.commitments.items[0][0] ^= 1;
    try rejected(a, &key, &proof);
    pcs.commitments.items[0][0] ^= 1;
    const saved = pcs.sampled_values.items[2][0][0];
    pcs.sampled_values.items[2][0][0] = saved.add(P.O.basis());
    try rejected(a, &key, &proof);
    pcs.sampled_values.items[2][0][0] = saved;
    pcs.config.fri_config.n_queries = 70;
    try rejected(a, &key, &proof);
    pcs.config.fri_config.n_queries = 108;
    std.debug.print("OM31_CIRCUIT_PROOF fresh_accepted=true q=108 p=20 full_octic_air=true prove_ns={} verify_ns={} physical_mutants=5\n", .{ prove_ns, verify_ns });
}

// New profiles use the existing real PCS producer and verifier. This gate is
// deliberately a small circuit, not an Ethereum or compression timing claim.
test "om31 grinding26 actual proof fresh authority and cross profile wire rejection" {
    const a = std.testing.allocator;
    const saved = P.active();
    defer P.selectForTesting(saved);
    P.selectForTesting(.m7_outer_diet_k4_cap3_r1_b2_q102_p26_fold4_v1);
    var ctx = try circuit.builder.Context(P.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(P.Q.fromU32Unchecked(3, 1, 2, 4));
    const out = try ctx.mul(x, x);
    try ctx.setOutputs(&.{out});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(P.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var key = try Prove.Authority.init(a, &pp);
    defer key.deinit();
    var proof = try Prove.prove(a, &key, ctx.values());
    defer proof.deinit();
    var receiver = try Prove.Authority.init(a, &pp);
    defer receiver.deinit();
    var capture = try Prove.verify(a, &receiver, proof.outputs, proof.claims, &proof.proof.proof);
    defer capture.deinit(a);
    const Wire = @import("wire.zig");
    const encoded = try Wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
    defer a.free(encoded);
    var decoded = try Wire.decode(a, receiver.identity, pp.n_outputs, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(u32, 102), decoded.proof.commitment_scheme_proof.config.fri_config.n_queries);
    try std.testing.expectEqual(@as(u32, 26), decoded.proof.commitment_scheme_proof.config.pow_bits);
    P.selectForTesting(.m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1);
    try std.testing.expectError(error.Om31CircuitWireProfile, Wire.decode(a, receiver.identity, pp.n_outputs, encoded));
    try std.testing.expectError(error.InvalidOm31CircuitProof, Prove.verify(a, &receiver, proof.outputs, proof.claims, &proof.proof.proof));
    std.debug.print("OM31_GRIND26 q=102 p=26 real_pcs=true fresh_authority=true old_profile_rejected=true bytes={d}\n", .{encoded.len});
}
