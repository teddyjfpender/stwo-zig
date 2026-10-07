//! Two private Bitcoin headers share one SHA AIR, two caller AIRs, and one FRI proof.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("../../language/relation.zig");
const compiler = @import("../../language/relation_compiler.zig");
const joint = @import("../proving/sha_joint_batch2_prover.zig");
const native = @import("../verification/sha_joint_batch2_native_verifier.zig");
const profile = @import("../config/sha_joint_batch2_profile.zig");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

test "two private linked Bitcoin headers are proved by one circuit and six SHA calls" {
    const a = std.testing.allocator;
    const source = @embedFile("../../examples/bitcoin_header_pair.s31.json");
    var program = try relation.parseProgram(a, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(a, @embedFile("../../examples/bitcoin_header_pair.valid.json"));
    defer assignment.deinit();
    var value_maps = compiler.Maps{};
    defer value_maps.deinit(a);
    var values = try compiler.compileShaChipWithSpans(QM31, a, program.value, assignment.value, &value_maps);
    defer values.deinit();
    var topology_maps = compiler.Maps{};
    defer topology_maps.deinit(a);
    var topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, a, program.value, null, &topology_maps);
    defer topology.deinit();
    try std.testing.expectEqual(@as(usize, 2), value_maps.sha_boundaries.items.len);
    try std.testing.expectEqual(@as(usize, 2), topology_maps.sha_boundaries.items.len);
    var addresses: [profile.header_count][profile.gate_address_count]u32 = undefined;
    for (&addresses, 0..) |*group, index| {
        group.* = value_maps.sha_boundaries.items[index].addresses;
        try std.testing.expectEqualDeep(group.*, topology_maps.sha_boundaries.items[index].addresses);
    }
    const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&topology.circuit));
    const targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(QM31, &values, targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, targets);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(try values.isCircuitValid());
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundaryPair(a, &topology.circuit, .{
        .first = .{ .addresses = addresses[0] },
        .second = .{ .addresses = addresses[1] },
    });
    defer pp.deinit(a);
    var headers: [profile.header_count][80]u8 = undefined;
    for (program.value.inputs, &headers) |input, *header| {
        const words = try relation.inputValues(a, assignment.value, input);
        defer a.free(words);
        for (words, 0..) |word, i|
            std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    }
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), 18));
    const key = try native.deriveKey(a, source_digest, &pp, @intCast(values.circuit.n_vars), addresses, pcs);
    const public_words = try relation.claimedWords(a, program.value, assignment.value);
    var public_outputs: [8]QM31 = undefined;
    for (public_words, 0..) |word, i| public_outputs[i] = QM31.fromM31(
        M31.fromCanonical(word & 0xffff),
        M31.fromCanonical(word >> 16),
        M31.zero(),
        M31.zero(),
    );
    var bundle = try cpu.air.parse(a, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var metrics = joint.Metrics{};
    var timer = try std.time.Timer.start();
    var proof = try joint.prove(a, values.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .gate_addresses = addresses,
        .headers = headers,
        .metrics = &metrics,
    });
    defer proof.deinit();
    const prove_ns = timer.read();
    const bytes = try joint.serialize(a, &proof);
    defer a.free(bytes);
    try std.testing.expectEqual(@as(usize, 14), proof.claimed_sums.len);
    try std.testing.expectEqualDeep(key.preprocessed_root, proof.preprocessed_root);
    try std.testing.expectEqualDeep(try key.profile.keyDigest(key.preprocessed_root), proof.key_digest);
    try std.testing.expectEqualSlices(QM31, &public_outputs, proof.output_values);
    const admission = key.admission(&public_outputs);
    timer.reset();
    try native.verify(a, admission, bytes);
    const verify_ns = timer.read();
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &proof_digest, .{});
    std.debug.print("S31_SHA_BATCH2 proved=true verified=true prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_ms={d} columns={d}/{d}/{d} proof_sha256={s} key_digest={s}\n", .{
        prove_ns / std.time.ns_per_ms,           verify_ns / std.time.ns_per_ms,           bytes.len,
        metrics.fri_pow_ns / std.time.ns_per_ms, metrics.fixed_columns,                    metrics.main_columns,
        metrics.interaction_columns,             std.fmt.bytesToHex(proof_digest, .lower), std.fmt.bytesToHex(proof.key_digest, .lower),
    });

    var altered_public = public_outputs;
    altered_public[0] = altered_public[0].add(QM31.one());
    var changed = admission;
    changed.public_outputs = &altered_public;
    if (native.verify(a, changed, bytes)) |_| return error.ChangedPublicOutputAccepted else |_| {}
    changed = admission;
    changed.profile.gate_addresses[1][0] = changed.profile.gate_addresses[0][0];
    if (native.verify(a, changed, bytes)) |_| return error.ChangedSecondBoundaryAccepted else |_| {}
    const corrupt = try a.dupe(u8, bytes);
    defer a.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    if (native.verify(a, admission, corrupt)) |_| return error.CorruptBatchProofAccepted else |_| {}
    const base_request = joint.Request{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .gate_addresses = addresses,
        .headers = headers,
    };
    var invalid = base_request;
    invalid.test_mutation = .header_and_sha_input;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
    invalid.test_mutation = .digest_and_sha_output;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
    invalid.test_mutation = .second_header_and_sha_input;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
    invalid.test_mutation = .second_digest_and_sha_output;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
    invalid = base_request;
    invalid.headers[0][0] ^= 1;
    try std.testing.expectError(error.InvalidJoinedShaGateLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
    invalid = base_request;
    invalid.headers[1][0] ^= 1;
    try std.testing.expectError(error.InvalidJoinedShaGateLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, invalid));
}
