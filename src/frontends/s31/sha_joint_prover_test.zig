//! Focused compile and one-proof test root for the S31 SHA joint prover.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const relation = @import("relation.zig");
const compiler = @import("relation_compiler.zig");
const joint = @import("sha_joint_prover.zig");
const native = @import("sha_joint_native_verifier.zig");
const joint_profile = @import("sha_joint_profile.zig");

test "joint SHA prover exposes one sealed proof object" {
    try std.testing.expect(@hasDecl(joint, "prove"));
    try std.testing.expect(@hasField(joint.Proof, "stark_proof"));
    _ = &joint.prove;
}

test "one private Bitcoin header is proved by the joined circuit and SHA AIR" {
    const a = std.testing.allocator;
    const source = @embedFile("examples/bitcoin_header_pow.s31.json");
    var program = try relation.parseProgram(a, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(a, @embedFile("examples/bitcoin_header_pow.valid.json"));
    defer assignment.deinit();
    var value_maps = compiler.Maps{};
    defer value_maps.deinit(a);
    var values = try compiler.compileShaChipWithSpans(core.fields.qm31.QM31, a, program.value, assignment.value, &value_maps);
    defer values.deinit();
    var topology_maps = compiler.Maps{};
    defer topology_maps.deinit(a);
    var topology = try compiler.compileShaChipWithSpans(circuit.builder.NoValue, a, program.value, null, &topology_maps);
    defer topology.deinit();
    const addresses = value_maps.sha_boundaries.items[0].addresses;
    try std.testing.expectEqualSlices(u32, &addresses, &topology_maps.sha_boundaries.items[0].addresses);
    const raw = circuit.common.finalize.rawComponentSizes(.fromBuilder(&topology.circuit));
    const targets: circuit.common.finalize.ComponentSizes = .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    };
    try circuit.common.finalize.padToTargets(core.fields.qm31.QM31, &values, targets);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, targets);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    var pp = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(a, &topology.circuit, .{ .addresses = addresses });
    defer pp.deinit(a);
    const words = try relation.inputValues(a, assignment.value, program.value.inputs[0]);
    defer a.free(words);
    var header: [80]u8 = undefined;
    for (words, 0..) |word, i|
        std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word.toU32()), .little);
    var source_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &source_digest, .{});
    const fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, @max(pp.traceLogSize(), 18));
    const expected_profile = try joint_profile.Profile.canonical(source_digest, .{
        std.math.log2_int(usize, targets.eq),
        std.math.log2_int(usize, targets.qm31_ops),
        std.math.log2_int(usize, targets.m31_to_u32),
        16,
    }, @intCast(values.circuit.n_vars), addresses, pcs);
    const key = try native.deriveKey(a, source_digest, &pp, @intCast(values.circuit.n_vars), addresses, pcs);
    try std.testing.expectEqualDeep(expected_profile, key.profile);
    const public_words = try relation.claimedWords(a, program.value, assignment.value);
    var public_outputs: [8]core.fields.qm31.QM31 = undefined;
    // The S31 Bytes32 output ABI is one QM31 with two u16 limbs per word.
    for (public_words, 0..) |word, i|
        public_outputs[i] = core.fields.qm31.QM31.fromM31(
            core.fields.m31.M31.fromCanonical(word & 0xffff),
            core.fields.m31.M31.fromCanonical(word >> 16),
            core.fields.m31.M31.zero(),
            core.fields.m31.M31.zero(),
        );
    var bundle = try cpu.air.parse(a, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var metrics = joint.Metrics{};
    var timer = try std.time.Timer.start();
    var proof = try joint.prove(a, values.values(), &pp, &bundle, pcs, .{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .gate_addresses = addresses,
        .header = header,
        .metrics = &metrics,
    });
    defer proof.deinit();
    const prove_ns = timer.read();
    const bytes = try joint.serialize(a, &proof);
    defer a.free(bytes);
    try std.testing.expectEqualDeep(expected_profile, proof.profile);
    try std.testing.expectEqualDeep(key.preprocessed_root, proof.preprocessed_root);
    try std.testing.expectEqualDeep(try key.profile.keyDigest(key.preprocessed_root), proof.key_digest);
    try std.testing.expectEqualSlices(core.fields.qm31.QM31, &public_outputs, proof.output_values);
    const admission = key.admission(&public_outputs);
    timer.reset();
    try native.verify(a, admission, bytes);
    const verify_ns = timer.read();
    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &proof_digest, .{});
    std.debug.print("S31_SHA_JOINT proved=true verified=true prove_ms={d} verify_ms={d} proof_bytes={d} claims={d} proof_sha256={x}\n", .{ prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, bytes.len, proof.claimed_sums.len, proof_digest });
    std.debug.print("S31_SHA_JOINT_STAGES setup_ms={d} fixed_commit_ms={d} main_witness_ms={d} main_commit_ms={d} interaction_witness_ms={d} interaction_commit_ms={d} bind_ms={d} fri_ms={d} fri_pow_ms={d} columns={d}/{d}/{d} table_nonzero={any}\n", .{
        metrics.setup_ns / std.time.ns_per_ms,
        metrics.fixed_commit_ns / std.time.ns_per_ms,
        metrics.main_witness_ns / std.time.ns_per_ms,
        metrics.main_commit_ns / std.time.ns_per_ms,
        metrics.interaction_witness_ns / std.time.ns_per_ms,
        metrics.interaction_commit_ns / std.time.ns_per_ms,
        metrics.component_bind_ns / std.time.ns_per_ms,
        metrics.fri_ns / std.time.ns_per_ms,
        metrics.fri_pow_ns / std.time.ns_per_ms,
        metrics.fixed_columns,
        metrics.main_columns,
        metrics.interaction_columns,
        metrics.table_nonzero_rows,
    });
    try std.testing.expectEqual(@as(usize, 12), proof.claimed_sums.len);

    var altered_public = try a.dupe(core.fields.qm31.QM31, proof.output_values);
    defer a.free(altered_public);
    altered_public[0] = altered_public[0].add(core.fields.qm31.QM31.one());
    var changed_admission = admission;
    changed_admission.public_outputs = altered_public;
    if (native.verify(a, changed_admission, bytes)) |_| return error.ChangedPublicOutputAccepted else |_| {}
    changed_admission = admission;
    changed_admission.public_outputs = public_outputs[0..7];
    try std.testing.expectError(error.InvalidShaJointPublicOutputCount, native.verify(a, changed_admission, bytes));
    var noncanonical_public = public_outputs;
    noncanonical_public[0].c1.a = core.fields.m31.M31.one();
    changed_admission = admission;
    changed_admission.public_outputs = &noncanonical_public;
    if (native.verify(a, changed_admission, bytes)) |_| return error.NoncanonicalPublicOutputAccepted else |_| {}
    changed_admission = admission;
    changed_admission.preprocessed_root[0] ^= 1;
    if (native.verify(a, changed_admission, bytes)) |_| return error.ChangedPreprocessedRootAccepted else |_| {}
    changed_admission = admission;
    changed_admission.profile.source_digest[0] ^= 1;
    if (native.verify(a, changed_admission, bytes)) |_| return error.ChangedSourceAccepted else |_| {}
    changed_admission = admission;
    var unused_address: u32 = 3;
    while (unused_address < key.profile.n_vars) : (unused_address += 1) {
        var used = false;
        for (addresses) |address| used = used or address == unused_address;
        if (!used) break;
    }
    try std.testing.expect(unused_address < key.profile.n_vars);
    changed_admission.profile.gate_addresses[0] = unused_address;
    try std.testing.expectError(error.WrongShaJointVerificationKey, native.verify(a, changed_admission, bytes));
    var changed_layout = key.layout;
    changed_layout.entries[0].log_size += 1;
    changed_admission = admission;
    changed_admission.layout = &changed_layout;
    if (native.verify(a, changed_admission, bytes)) |_| return error.ChangedLayoutAccepted else |_| {}
    const altered_bytes = try a.dupe(u8, bytes);
    defer a.free(altered_bytes);
    altered_bytes[altered_bytes.len - 1] ^= 1;
    if (native.verify(a, admission, altered_bytes)) |_| return error.ChangedProofAccepted else |_| {}
    const official_air = @embedFile("s31_air_programs");
    const altered_air = try a.dupe(u8, official_air);
    defer a.free(altered_air);
    altered_air[0] ^= 1;
    try std.testing.expectError(error.InvalidShaJointCircuitAir, native.validateOfficialBundleDigest(altered_air));

    const base_request = joint.Request{
        .source_digest = source_digest,
        .n_vars = @intCast(values.circuit.n_vars),
        .gate_addresses = addresses,
        .header = header,
    };
    var altered_request = base_request;
    altered_request.test_mutation = .header_and_sha_input;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, altered_request));
    altered_request = base_request;
    altered_request.test_mutation = .digest_and_sha_output;
    try std.testing.expectError(error.InvalidJoinedShaWireLookupSum, joint.prove(a, values.values(), &pp, &bundle, pcs, altered_request));
}
