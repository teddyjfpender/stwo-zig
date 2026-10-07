//! End-to-end proof that a circuit's private wires equal a chip's endpoints.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const native = @import("native_verifier.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const chip = cpu.repeated_step_chip;
const Boundary = circuit.common.direct_arithmetic.PrivateBoundary;

const Fixture = struct {
    ctx: circuit.builder.Context(QM31),
    boundary: Boundary,
    initial: [4]M31,
    final: [4]M31,

    fn deinit(self: *Fixture) void {
        self.ctx.deinit();
    }
};

fn fixture(allocator: std.mem.Allocator) !Fixture {
    var ctx = try circuit.builder.Context(QM31).init(allocator, 8);
    errdefer ctx.deinit();
    const initial = [4]M31{ M31.fromCanonical(3), M31.fromCanonical(5), M31.fromCanonical(7), M31.fromCanonical(11) };
    const final = try chip.direct(initial, M31.fromCanonical(13), 16);
    var x: [4]Var = undefined;
    var y: [4]Var = undefined;
    var outputs: [8]Var = undefined;
    for (0..4) |lane| {
        x[lane] = try ctx.guessM31(QM31.fromBase(initial[lane]));
        y[lane] = try ctx.guessM31(QM31.fromBase(final[lane]));
        outputs[lane] = try ctx.add(x[lane], y[lane]);
        outputs[4 + lane] = try ctx.mul(x[lane], y[lane]);
    }
    const boundary = Boundary{
        .input = .{ x[0].idx, x[1].idx, x[2].idx, x[3].idx },
        .output = .{ y[0].idx, y[1].idx, y[2].idx, y[3].idx },
    };
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    try circuit.common.finalize.padToTargets(QM31, &ctx, .{
        .eq = 0,
        .qm31_ops = circuit.common.finalize.paddedSize(ctx.circuit.nQm31OpsRows()),
        .triple_xor = 0,
        .m31_to_u32 = 0,
        .blake_g_gate = 0,
    });
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expect((try ctx.circuit.firstYieldViolation(allocator)) == null);
    return .{ .ctx = ctx, .boundary = boundary, .initial = initial, .final = final };
}

test "one native proof binds private circuit wires to repeated-step chip endpoints" {
    const allocator = std.testing.allocator;
    var item = try fixture(allocator);
    defer item.deinit();
    var duplicate = item.boundary;
    duplicate.output[0] = duplicate.input[0];
    try std.testing.expectError(error.InvalidPrivateBoundary, circuit.common.direct_arithmetic.Circuit.fromBuilderCircuitWithPrivateBoundary(allocator, &item.ctx.circuit, duplicate));
    var pp = try circuit.common.direct_arithmetic.Circuit.fromBuilderCircuitWithPrivateBoundary(allocator, &item.ctx.circuit, item.boundary);
    defer pp.deinit(allocator);
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    var pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), @as(u32, 4)));
    pcs.preprocessed_lifting_log_size = pp.traceLogSize() + fri.log_blowup_factor;
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("s31-private-bridge-test-v1", &source_digest, .{});
    const request = cpu.prove.ChipRequest{
        .source_digest = source_digest,
        .rounds = 16,
        .constant = M31.fromCanonical(13),
        .initial = item.initial,
        .final = item.final,
    };
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    const root = try pp.preprocessedRoot(allocator, fri.log_blowup_factor);
    var timer = try std.time.Timer.start();
    var proof = try cpu.direct_arithmetic.prove(allocator, item.ctx.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .chip_request = request,
        .private_boundary = item.boundary,
    });
    const prove_ns = timer.read();
    defer proof.deinit();
    try std.testing.expect(proof.bridge_claimed_sum != null);
    var public_words: [8]u32 = undefined;
    for (proof.output_values, &public_words) |word, *out| {
        const limbs = word.toM31Array();
        try std.testing.expect(limbs[1].isZero() and limbs[2].isZero() and limbs[3].isZero());
        out.* = limbs[0].toU32();
    }
    const bytes = try native.serializeDirectPrivate(allocator, &proof);
    defer allocator.free(bytes);
    const layout = pp.layout();
    const spec = native.HybridSpec{ .source_digest = source_digest, .rounds = 16, .constant = request.constant };
    timer.reset();
    try native.verifyDirectPrivate(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, public_words, bytes, source_digest, spec, item.boundary);
    const verify_ns = timer.read();
    std.debug.print("private bridge diagnostic: circuit_rows={d}, chip_rows=16, bridge_rows=16, bridge_main=8, bridge_interaction=20, proof_bytes={d}, prove_ms={d}, verify_ms={d}\n", .{
        @as(usize, 1) << @intCast(pp.traceLogSize()), bytes.len, prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms,
    });

    var changed_words = public_words;
    changed_words[0] +%= 1;
    try std.testing.expectError(error.InvalidInteractionNonce, native.verifyDirectPrivate(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, changed_words, bytes, source_digest, spec, item.boundary));
    var changed_boundary = item.boundary;
    changed_boundary.input[0] = 12345;
    try std.testing.expectError(error.InvalidCircuitHash, native.verifyDirectPrivate(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, public_words, bytes, source_digest, spec, changed_boundary));
    try std.testing.expectError(error.InvalidNativeProof, native.verifyDirect(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, public_words, bytes, source_digest, spec));
    const altered_bytes = try allocator.dupe(u8, bytes);
    defer allocator.free(altered_bytes);
    // The third claimed sum is the bridge LogUp claim, after two 16-byte sums.
    altered_bytes[DIRECT_PRIVATE_HEADER_SUM_OFFSET] ^= 1;
    try std.testing.expectError(error.InvalidPrivateBoundaryLookupSum, native.verifyDirectPrivate(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, public_words, altered_bytes, source_digest, spec, item.boundary));
    altered_bytes[DIRECT_PRIVATE_HEADER_SUM_OFFSET] ^= 1;
    altered_bytes[altered_bytes.len - 1] ^= 1;
    if (native.verifyDirectPrivate(allocator, &layout, &bundle, pcs, root, proof.circuit_hash, public_words, altered_bytes, source_digest, spec, item.boundary)) |_| {
        return error.TamperedProofAccepted;
    } else |_| {}

    var wrong = request;
    wrong.initial[0] = wrong.initial[0].add(M31.one());
    wrong.final = try chip.direct(wrong.initial, wrong.constant, wrong.rounds);
    try std.testing.expectError(error.InvalidPrivateBoundaryLookupSum, cpu.direct_arithmetic.prove(allocator, item.ctx.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .chip_request = wrong,
        .private_boundary = item.boundary,
    }));
}

const DIRECT_PRIVATE_HEADER_SUM_OFFSET: usize = "S31NAT5P".len + 8 + 2 * 16;
