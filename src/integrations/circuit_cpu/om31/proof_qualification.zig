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
    var timer = try std.time.Timer.start();
    var proof = try Prove.prove(a, &key, ctx.values());
    defer proof.deinit();
    const prove_ns = timer.lap();
    var capture = try Prove.verify(a, &key, proof.outputs, proof.claims, &proof.proof.proof);
    defer capture.deinit(a);
    const verify_ns = timer.lap();
    const Wire = @import("wire.zig");
    const encoded = try Wire.encode(a, key.identity, proof.outputs, proof.claims, &proof.proof.proof);
    defer a.free(encoded);
    var decoded = try Wire.decode(a, key.identity, key.pp.n_outputs, encoded);
    defer decoded.deinit();
    var received = try Prove.verify(a, &key, decoded.outputs, decoded.claims, &decoded.proof);
    defer received.deinit(a);
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
