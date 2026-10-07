//! Opt-in integration proof: a generic checkpoint anchor is verified inside
//! one Bitcoin header fold whose SHA256d is a private, joined AIR witness.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const circuit_wire = @import("stwo_circuit_recursion_wire").circuit_serialize;
const s31 = @import("stwo_s31_prototype");
const anchor = @import("../../bitcoin/fold/bitcoin_chain_anchor.zig");
const fold = @import("../../bitcoin/fold/bitcoin_chain_fold.zig");
const generic_native = @import("../../runtime/native_verifier.zig");
const sealed = @import("../../bitcoin/verification/bitcoin_fused_chain_verifier.zig");
const fused_profile = s31.sha_fused_fold_profile;
const fused_prover = s31.sha_fused_fold_prover;
const fused_native = s31.sha_fused_fold_native_verifier;
const fused_shape = s31.sha_fused_fold_shape;
const fused_transcript = s31.sha_fused_fold_recursive_transcript;
const pp_guard = s31.bitcoin_fold_preprocessed_guard;

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const checkpoint = [8]u32{ 93892305, 397617766, 1762064199, 2128125525, 211345822, 958247097, 595994426, 1074837273 };
const child_rows: circuit.common.finalize.ComponentSizes = .{
    .eq = 32768,
    .qm31_ops = 2097152,
    .m31_to_u32 = 262144,
    .triple_xor = 131072,
    .blake_g_gate = 2097152,
};

fn boundaryAddresses(wires: s31.bitcoin_fold_step.ShaBoundaryWires) [56]u32 {
    var result: [56]u32 = undefined;
    for (wires.header, 0..) |wire, i| result[i] = wire.idx;
    for (wires.digest, 0..) |wire, i| result[40 + i] = wire.idx;
    return result;
}

fn sha256dHeader(words: [40]u32, header: *[80]u8) [32]u8 {
    for (words, 0..) |word, i| std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(word), .little);
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(header, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    return second;
}

fn digestRoot(hash: [32]u8) [8]u32 {
    var limbs: [16]M31 = undefined;
    for (&limbs, 0..) |*limb, i| limb.* = M31.fromCanonical(std.mem.readInt(u16, hash[2 * i ..][0..2], .little));
    const root = s31.poseidon2.leafWords(&limbs);
    var words: [8]u32 = undefined;
    for (root, &words) |limb, *word| word.* = limb.toU32();
    return words;
}

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return words;
}

fn packedWords(words: [8]u32) [8]QM31 {
    var result: [8]QM31 = undefined;
    for (words, &result) |word, *slot| slot.* = circuit.builder.ivalue.packU32(QM31, word);
    return result;
}

fn m31Words(comptime n: usize, words: [n]u32) [n]QM31 {
    var result: [n]QM31 = undefined;
    for (words, &result) |word, *slot| slot.* = QM31.fromBase(M31.fromCanonical(word));
    return result;
}

fn digestLimbs(hash: [32]u8) [16]QM31 {
    var result: [16]QM31 = undefined;
    for (&result, 0..) |*slot, i| slot.* = QM31.fromBase(M31.fromCanonical(std.mem.readInt(u16, hash[2 * i ..][0..2], .little)));
    return result;
}

test "checkpoint anchor and fused SHA fold step zero share one native proof" {
    const allocator = std.heap.page_allocator;
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();

    // First produce and independently verify the generic child. Only the
    // accepted verifier capture is converted into a recursive witness.
    var anchor_topology = try anchor.build(circuit.builder.NoValue, allocator, checkpoint, child_rows);
    defer anchor_topology.deinit();
    var anchor_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_topology.circuit);
    defer anchor_pp.deinit(allocator);
    const anchor_layout = anchor_pp.layout();
    const child_fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const child_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(child_fri, anchor_layout.traceLogSize());
    const anchor_root = try anchor_pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);
    const anchor_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&anchor_layout),
        child_pcs.fri_config.log_blowup_factor,
        anchor_root,
    );
    var anchor_values = try anchor.build(QM31, allocator, checkpoint, child_rows);
    defer anchor_values.deinit();
    try std.testing.expect(try anchor_values.isCircuitValid());
    var anchor_value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_values.circuit);
    defer anchor_value_pp.deinit(allocator);
    try pp_guard.requireExact(&anchor_pp, &anchor_value_pp);
    anchor_values.circuit.deinit(allocator);
    anchor_values.circuit = .{};
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE anchor_prove\n", .{});
    var anchor_timer = try std.time.Timer.start();
    var anchor_proof = try cpu.Internal.prove(allocator, anchor_values.values(), &anchor_pp, &bundle, child_pcs, .{ .evaluations_only = true }, {});
    defer anchor_proof.deinit();
    const anchor_prove_ns = anchor_timer.read();
    const anchor_bytes = try generic_native.serialize(allocator, &anchor_proof);
    defer allocator.free(anchor_bytes);
    var captured = try generic_native.verifyAndCapture(allocator, &anchor_layout, &bundle, child_pcs, anchor_root, anchor_hash, checkpoint, anchor_bytes);
    defer captured.deinit();
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE anchor_verified\n", .{});

    // Derive the outer key solely from value-free topology and canonical
    // fixed columns. The SHA address order is part of its verifier ABI.
    var no_boundary: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
    var topology = try fold.fusedTopology(allocator, @embedFile("s31_air_projection"), anchor_layout, child_pcs, anchor_root, checkpoint, 0, &no_boundary);
    defer topology.deinit();
    const addresses = boundaryAddresses(no_boundary);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, child_rows);
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &topology.circuit, .{ .addresses = addresses });
    defer pp.deinit(allocator);
    const statement = s31.sha_fused_private_join_profile.PublicStatement{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = addresses, .first_call_id = 1 },
    };
    const production_outer = std.posix.getenv("S31_FUSED_FOLD_PRODUCTION") != null;
    const outer_fri = try core.pcs.config_v2.FriConfigV2.init(
        if (production_outer) 26 else 0,
        0,
        1,
        if (production_outer) 70 else 12,
        1,
    );
    const outer_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(outer_fri, @max(pp.layout().traceLogSize(), 8));
    const source_digest = fused_profile.trustedFoldSourceDigest();
    const n_vars: u32 = @intCast(topology.circuit.n_vars);
    const key = try fused_native.deriveKey(allocator, source_digest, &pp, n_vars, statement, outer_pcs);
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE key_derived\n", .{});

    const Fixture = struct { private_inputs: struct { prior_hash: [16]u32, child: [40]u32 } };
    var fixture = try std.json.parseFromSlice(Fixture, allocator, @embedFile("s31_bitcoin_fixture"), .{ .ignore_unknown_fields = true });
    defer fixture.deinit();
    var header: [80]u8 = undefined;
    const hash = sha256dHeader(fixture.value.private_inputs.child, &header);
    const root = digestRoot(hash);
    const times = s31.bitcoin_fold_digest.initialTimes();
    const timestamp = fixture.value.private_inputs.child[34] | (fixture.value.private_inputs.child[35] << 16);
    const expected_words = try s31.bitcoin_fold_digest.statementDigest(key.fixed_root, 0, checkpoint, root, s31.bitcoin_fold_digest.advanceTimes(times, timestamp));
    const expected_outputs = packedWords(expected_words);
    var prior_times: [11]QM31 = undefined;
    for (times, &prior_times) |word, *slot| slot.* = circuit.builder.ivalue.packU32(QM31, word);
    var projection = try circuit.air_eval.projection.parse(allocator, @embedFile("s31_air_projection"));
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    const child_config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = child_pcs,
        .preprocessed_column_log_sizes = anchor_layout,
    };
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const child_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &captured.proof, captured.config);
    var value_boundary: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
    var values = try fold.buildFusedCircuit(
        QM31,
        allocator,
        &table,
        &child_config,
        anchor_root,
        checkpoint,
        circuit.builder.blake.hashValue(QM31, wordsFromBytes(key.fixed_root)),
        m31Words(8, checkpoint),
        prior_times,
        m31Words(16, fixture.value.private_inputs.prior_hash),
        m31Words(40, fixture.value.private_inputs.child),
        digestLimbs(hash),
        0,
        &child_values,
        circuit.stark_verifier.verify.NoStages{},
        &value_boundary,
    );
    defer values.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqualDeep(addresses, boundaryAddresses(value_boundary));
    try circuit.common.finalize.padToTargets(QM31, &values, child_rows);
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(n_vars, values.circuit.n_vars);
    var value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &values.circuit, .{ .addresses = boundaryAddresses(value_boundary) });
    defer value_pp.deinit(allocator);
    try pp_guard.requireExact(&pp, &value_pp);
    try std.testing.expectEqualDeep(addresses, value_pp.sha_boundary.?.addresses);
    const value_root = try value_pp.preprocessedRoot(allocator, outer_pcs.fri_config.log_blowup_factor);
    const topology_root = try pp.preprocessedRoot(allocator, outer_pcs.fri_config.log_blowup_factor);
    try std.testing.expectEqualDeep(topology_root, value_root);
    const value_key = try fused_native.deriveKey(allocator, source_digest, &value_pp, n_vars, statement, outer_pcs);
    try std.testing.expectEqualDeep(key.fixed_root, value_key.fixed_root);
    try std.testing.expectEqualDeep(key.digest, value_key.digest);
    values.circuit.deinit(allocator);
    values.circuit = .{};
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE value_topology_matched\n", .{});

    // A caller cannot substitute a different private digest while keeping
    // the same SHA witness: the Gate lookup must close in this proof.
    const altered_values = try allocator.dupe(QM31, values.values());
    defer allocator.free(altered_values);
    const digest_address: usize = @intCast(addresses[40]);
    const digest_word = std.mem.readInt(u16, hash[0..2], .little);
    altered_values[digest_address] = QM31.fromBase(M31.fromCanonical(if (digest_word == 65535) 65534 else @as(u32, digest_word) + 1));
    if (fused_prover.prove(allocator, altered_values, &pp, &bundle, outer_pcs, .{
        .source_digest = source_digest,
        .n_vars = n_vars,
        .statement = statement,
        .header = header,
    })) |unexpected| {
        var accepted = unexpected;
        accepted.deinit();
        return error.ChangedFusedFoldDigestAccepted;
    } else |err| try std.testing.expectEqual(error.InvalidFusedFoldGateClosure, err);
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE digest_negative_rejected\n", .{});

    var metrics = fused_prover.Metrics{};
    var timer = try std.time.Timer.start();
    std.debug.print("S31_SHA_FUSED_FOLD_STAGE joined_prove\n", .{});
    var proof = try fused_prover.prove(allocator, values.values(), &pp, &bundle, outer_pcs, .{
        .source_digest = source_digest,
        .n_vars = n_vars,
        .statement = statement,
        .header = header,
        .metrics = &metrics,
    });
    defer proof.deinit();
    const prove_ns = timer.read();
    try std.testing.expectEqualDeep(key.fixed_root, proof.key.fixed_root);
    try std.testing.expectEqualSlices(QM31, &expected_outputs, proof.outputs);
    const bytes = try fused_prover.serialize(allocator, &proof);
    defer allocator.free(bytes);
    timer.reset();
    try fused_native.verifyBytes(allocator, .{ .key = key, .public_outputs = &expected_outputs }, bytes);
    const verify_ns = timer.read();
    try fused_transcript.expectAcceptedProofPrefix(
        key,
        proof.outputs,
        proof.stark.proof.commitment_scheme_proof.commitments.items,
        proof.nonce,
        &proof.claims,
    );
    // The native proof has 21 components and split-two composition. Its SHA
    // state and schedule columns open five shifted rows each; the current
    // recursive wire format accepts only one trace opening per column.
    const sampled = proof.stark.proof.commitment_scheme_proof.sampled_values.items;
    try std.testing.expectEqual(@as(usize, 4), sampled.len);
    try std.testing.expect(!fused_shape.supports_recursive_proof_transport);
    try std.testing.expectEqual(@as(usize, 21), fused_shape.component_shapes.len);
    try std.testing.expectEqual(@as(usize, 17), proof.claims.len);
    try std.testing.expectEqual(@as(usize, 16), sampled[3].len);
    const fused_main = fused_shape.fusedMainOffset();
    try std.testing.expectEqual(@as(usize, 5), sampled[1][fused_main].len);
    try std.testing.expectEqual(@as(usize, 1), sampled[1][fused_main + 64].len);
    try std.testing.expectEqual(@as(usize, 5), sampled[1][fused_main + 76].len);
    const joined_shape = try fused_shape.proofShape(key);
    var transported = try cpu.verifier_proof.fromStarkProof(
        allocator,
        &proof.stark,
        joined_shape,
        &proof.claims,
        proof.nonce,
        0,
    );
    defer transported.deinit();
    const wire_bytes = try transported.serialize(allocator);
    defer allocator.free(wire_bytes);
    try std.testing.expectEqual(joined_shape.serializedLen(), wire_bytes.len);
    var decoded = try circuit_wire.deserializeProof(allocator, wire_bytes, joined_shape);
    defer decoded.deinit();
    try std.testing.expectEqual(wire_bytes.len, decoded.consumed);
    try std.testing.expectEqualSlices(QM31, transported.proof.claimed_sums, decoded.proof.claimed_sums);
    try std.testing.expectEqualSlices(QM31, transported.proof.trace_at_oods, decoded.proof.trace_at_oods);
    for ([_]usize{ fused_main, fused_main + 64, fused_main + 76 }) |column| {
        const range = joined_shape.traceMaskRange(column);
        try std.testing.expectEqualSlices(QM31, sampled[1][column], decoded.proof.trace_at_oods[range.start..range.end]);
    }
    for ([_]usize{ fused_profile.interaction_width + 4, fused_profile.interaction_width + 12 }) |column| {
        try std.testing.expectEqual(@as(usize, 2), sampled[2][column].len);
        try std.testing.expectEqualDeep(sampled[2][column][0], decoded.proof.interaction_at_oods[column].at_prev.?);
        try std.testing.expectEqualDeep(sampled[2][column][1], decoded.proof.interaction_at_oods[column].at_oods);
    }
    if (production_outer) {
        // Reuse the production-parameter proof to test the application-facing
        // sealed boundary. Its key and Gate addresses are rebuilt independently.
        const sealed_key_bytes = try sealed.generateKeyJson(allocator, sealed.genesis_display_hash);
        defer allocator.free(sealed_key_bytes);
        const sealed_key = try sealed.validateKey(allocator, sealed_key_bytes, @import("../../bitcoin/verification/bitcoin_chain_verifier.zig").sha256(sealed_key_bytes));
        try std.testing.expectEqualDeep(key.fixed_root, sealed_key.material.fused_key.fixed_root);
        try std.testing.expectEqualDeep(key.digest, sealed_key.material.fused_key.digest);
        var display_hash = hash;
        std.mem.reverse(u8, &display_hash);
        const display_hex = std.fmt.bytesToHex(display_hash, .lower);
        const sealed_statement = try sealed.generateStatementJson(allocator, sealed_key, &display_hex, timestamp);
        defer allocator.free(sealed_statement);
        const sealed_outputs = try sealed.validateStatement(allocator, sealed_key, sealed_statement);
        try std.testing.expectEqualSlices(QM31, &expected_outputs, &sealed_outputs);
        try sealed.verifyProof(allocator, sealed_key, sealed_statement, bytes);
        var parsed_sealed = try std.json.parseFromSlice(sealed.Statement, allocator, sealed_statement, .{ .ignore_unknown_fields = false });
        defer parsed_sealed.deinit();
        parsed_sealed.value.current_block_timestamp += 1;
        const changed_sealed = try std.json.Stringify.valueAlloc(allocator, parsed_sealed.value, .{});
        defer allocator.free(changed_sealed);
        try std.testing.expectError(error.InvalidFusedBitcoinTimestamps, sealed.verifyProof(allocator, sealed_key, changed_sealed, bytes));
        parsed_sealed.value.last_timestamps[0] += 1;
        const consistent_changed_time = try std.json.Stringify.valueAlloc(allocator, parsed_sealed.value, .{});
        defer allocator.free(consistent_changed_time);
        try std.testing.expectError(error.InvalidFusedBitcoinStatement, sealed.verifyProof(allocator, sealed_key, consistent_changed_time, bytes));
    }
    std.debug.print("S31_SHA_FUSED_FOLD anchor_bytes={d} anchor_prove_ms={d} proof_bytes={d} prove_ms={d} verify_ms={d} components={d} columns={d}/{d}/{d} child_pow={d} child_queries={d} child_fold={d} outer_pow={d} outer_queries={d} outer_fold={d} anchor_root={s} circuit_root={s} joined_fixed_root={s}\n", .{
        anchor_bytes.len,                           anchor_prove_ns / std.time.ns_per_ms,        bytes.len,             prove_ns / std.time.ns_per_ms,
        verify_ns / std.time.ns_per_ms,             fused_profile.component_count,               metrics.fixed_columns, metrics.main_columns,
        metrics.interaction_columns,                child_fri.pow_bits,                          child_fri.n_queries,   child_fri.fold_step,
        outer_fri.pow_bits,                         outer_fri.n_queries,                         outer_fri.fold_step,   &std.fmt.bytesToHex(anchor_root, .lower),
        &std.fmt.bytesToHex(topology_root, .lower), &std.fmt.bytesToHex(key.fixed_root, .lower),
    });
    std.debug.print("S31_SHA_FUSED_FOLD_STAGES fixed_ms={d} composition_eval_ms={d} composition_interpolate_ms={d} composition_commit_ms={d} fri_quotient_ms={d} fri_decommit_ms={d}\n", .{
        metrics.fixed_commit_ns / std.time.ns_per_ms,
        metrics.composition_eval_ns / std.time.ns_per_ms,
        metrics.composition_interpolate_ns / std.time.ns_per_ms,
        metrics.composition_commit_ns / std.time.ns_per_ms,
        metrics.fri_quotient_commit_ns / std.time.ns_per_ms,
        metrics.fri_decommit_ns / std.time.ns_per_ms,
    });

    var changed_words = expected_words;
    changed_words[0] ^= 1;
    const changed_outputs = packedWords(changed_words);
    if (fused_native.verifyBytes(allocator, .{ .key = key, .public_outputs = &changed_outputs }, bytes)) |_| return error.ChangedFusedFoldOutputAccepted else |_| {}
    var changed_key = key;
    changed_key.source_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedFusedFoldSourceDigest, fused_native.verifyBytes(allocator, .{ .key = changed_key, .public_outputs = &expected_outputs }, bytes));
    var reordered = statement;
    std.mem.swap(u32, &reordered.config.gate_addresses[0], &reordered.config.gate_addresses[1]);
    try std.testing.expectError(error.InvalidFusedFoldTopology, fused_native.deriveKey(allocator, source_digest, &pp, n_vars, reordered, outer_pcs));
    var changed_header = header;
    changed_header[0] ^= 1;
    if (fused_prover.prove(allocator, values.values(), &pp, &bundle, outer_pcs, .{
        .source_digest = source_digest,
        .n_vars = n_vars,
        .statement = statement,
        .header = changed_header,
    })) |unexpected| {
        var accepted = unexpected;
        accepted.deinit();
        return error.ChangedFusedFoldHeaderAccepted;
    } else |err| try std.testing.expectEqual(error.InvalidFusedFoldGateClosure, err);
}
