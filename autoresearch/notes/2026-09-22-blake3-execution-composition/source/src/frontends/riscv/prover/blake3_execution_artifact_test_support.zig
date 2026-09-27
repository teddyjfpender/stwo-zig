//! Artifact/admission attacks exercised against the real runner proof.
const std = @import("std");
const core = @import("stwo_core");
const codec = @import("blake3_execution_codec.zig");
pub fn check(comptime Api: type, a: std.mem.Allocator, prepared: *Api.PreparedVerifier, expected: [32]u8, raw: []const u8, digest: [32]u8) !void {
    const changed = try a.dupe(u8, raw);
    defer a.free(changed);
    changed[12] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, codec.decode(a, changed, prepared, expected));
    changed[12] ^= 1;
    changed[8] ^= 1;
    try std.testing.expectError(error.InvalidExecutionArtifactVersion, codec.decode(a, changed, prepared, expected));
    changed[8] ^= 1;
    std.mem.writeInt(u32, changed[codec.HEADER_BYTES..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.InvalidInteractionClaim, codec.decode(a, changed, prepared, expected));
    @memcpy(changed, raw);
    std.mem.writeInt(u32, changed[44..48], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.InvalidInteractionClaim, codec.decode(a, changed, prepared, expected));
    try std.testing.expectError(error.InvalidExecutionArtifactLength, codec.decode(a, raw[0 .. raw.len - 1], prepared, expected));
    try std.testing.expectError(error.TruncatedExecutionArtifact, codec.decode(a, raw[0..8], prepared, expected));
    var wrong_pin = expected;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, codec.decode(a, raw, prepared, wrong_pin));
    prepared.key.preprocessed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedExecutionKey, prepared.validate(expected));
    prepared.key.preprocessed_root[0] ^= 1;
    prepared.config.fri_config.n_queries += 1;
    try std.testing.expectError(error.UntrustedExecutionKey, prepared.validate(expected));
    prepared.config.fri_config.n_queries -= 1;
    prepared.shape.final_pc += 4;
    try std.testing.expectError(error.InvalidStatement, prepared.validate(expected));
    prepared.shape.final_pc -= 4;
    var bad_root = try codec.decode(a, raw, prepared, expected);
    bad_root.stark.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlake3Preprocessing, Api.verifyPreparedOwned(a, bad_root, prepared, expected));
    const bad_claim = try codec.decode(a, raw, prepared, expected);
    bad_claim.native_claims.opcode_claims[0][0] = bad_claim.native_claims.opcode_claims[0][0].add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.UnclosedExecutionRelations, Api.verifyPreparedOwned(a, bad_claim, prepared, expected));
    const retained = prepared.hashes.?;
    // Two independent decoded proofs reuse the same prepared verifier. No
    // witness/fixed trace buffers are retained or reconstructed on this path.
    for (0..2) |iteration| {
        const proof = try codec.decode(a, raw, prepared, expected);
        if (iteration == 0) {
            const actual = try Api.verifyPreparedOwned(a, proof, prepared, expected);
            try std.testing.expectEqualSlices(u8, &digest, &actual);
        } else {
            var capture = try Api.verifyPreparedCaptureOwned(a, proof, prepared, expected);
            defer capture.deinit();
            try capture.validate(prepared, expected);
            try std.testing.expectEqualSlices(u8, &digest, &capture.final_channel.digestBytes());
            capture.proof.sampled_values[0] = capture.proof.sampled_values[0].add(core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidExecutionCapture, capture.validate(prepared, expected));
            capture.proof.sampled_values[0] = capture.proof.sampled_values[0].sub(core.fields.qm31.QM31.one());
            var replay = try @import("../recursion/air/blake3_execution_transcript.zig").planReplay(a, prepared, &capture, expected, 2);
            defer replay.deinit();
            try std.testing.expectEqualSlices(u8, &digest, &replay.end.digestBytes());
            const counts = try replay.hashCounts();
            try std.testing.expect(counts.g > 0 and counts.xor > 0);
            var composition = try @import("../recursion/air/blake3_execution_composition.zig").prepare(a, prepared, &capture, expected);
            defer composition.deinit();
            try composition.validate(a, prepared, &capture, expected);
            try std.testing.expectEqual(@as(usize, 2), composition.circuit.outputs.len);
            var deep = try @import("../recursion/air/blake3_execution_deep.zig").prepare(a, prepared, &capture, expected);
            defer deep.deinit();
            var fri = try @import("../recursion/air/blake3_native_fri.zig").prepareCaptured(a, &capture.proof, prepared.config, &deep, 2, 3);
            defer fri.deinit();
            const sample_links = @import("../recursion/air/blake3_execution_sample_links.zig");
            var links = try sample_links.prepare(a, &composition, &deep, 1, 2, 0);
            defer links.deinit();
            try std.testing.expect(links.packs.len > 0);
            try std.testing.expectEqual(capture.proof.sampled_values.len * 4, links.sources.len);
            var current_first = false;
            var previous_first = false;
            for (deep.graph.profile().sample_layouts) |layout| {
                current_first = current_first or layout == .current_previous;
                previous_first = previous_first or layout == .previous_current;
            }
            try std.testing.expect(current_first and previous_first);
            const challenge_mod = @import("../recursion/air/blake3_execution_challenges.zig");
            var challenges = try challenge_mod.prepare(a, &composition, &replay, &deep, &fri, .{ 1, 2, 3 }, 4);
            defer challenges.deinit();
            try std.testing.expect(challenges.packs.len > 0);
            const payload_mod = @import("../recursion/air/blake3_execution_payloads.zig");
            var payloads = try payload_mod.prepare(a, &composition, &replay, &deep, 1, 2, 5);
            defer payloads.deinit();
            try std.testing.expectEqual(capture.proof.sampled_values.len + payloads.claim_packs.len, payloads.encoded.len);
            // The payloads add one secure encoder consumer to each sample.
            for (links.sources, payloads.samples.sources) |original, encoded| try std.testing.expectEqual(original[3].v + 1, encoded[3].v);
            const claim_index = capture.proof.sampled_values.len;
            composition.inputs[claim_index] = composition.inputs[claim_index].add(core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidExecutionPayload, payload_mod.prepare(a, &composition, &replay, &deep, 1, 2, 5));
            composition.inputs[claim_index] = composition.inputs[claim_index].sub(core.fields.qm31.QM31.one());
            const exported = replay.plan.fixed.draw_outputs[0];
            replay.operations[exported.operation].secure.values[0] = replay.operations[exported.operation].secure.values[0].add(core.fields.m31.M31.one());
            try std.testing.expectError(error.InvalidExecutionChallenge, challenge_mod.prepare(a, &composition, &replay, &deep, &fri, .{ 1, 2, 3 }, 4));
            replay.operations[exported.operation].secure.values[0] = replay.operations[exported.operation].secure.values[0].sub(core.fields.m31.M31.one());

            composition.inputs[0] = composition.inputs[0].add(core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidExecutionSampleLink, sample_links.prepare(a, &composition, &deep, 1, 2, 0));
            composition.inputs[0] = composition.inputs[0].sub(core.fields.qm31.QM31.one());

            const scratch = try a.alloc(core.fields.qm31.QM31, composition.values.len);
            defer a.free(scratch);
            // Alter the split composition evaluation and a detailed claim:
            // each must fail the graph equations, independently of receipt seals.
            for ([_]usize{ capture.proof.sampled_values.len - 1, capture.proof.sampled_values.len }) |index| {
                composition.inputs[index] = composition.inputs[index].add(core.fields.qm31.QM31.one());
                try std.testing.expectError(error.UnsatisfiedCircuit, composition.circuit.evaluateInto(composition.inputs, scratch));
                composition.inputs[index] = composition.inputs[index].sub(core.fields.qm31.QM31.one());
            }
            composition.inputs[0] = composition.inputs[0].add(core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidExecutionComposition, composition.validate(a, prepared, &capture, expected));
            composition.inputs[0] = composition.inputs[0].sub(core.fields.qm31.QM31.one());
        }
        try std.testing.expectEqual(retained, prepared.hashes.?);
        try std.testing.expectEqual(@as(usize, 0), retained.columns[0].items.len);
        try std.testing.expectEqual(@as(usize, 0), retained.columns[1].items.len);
    }
}
