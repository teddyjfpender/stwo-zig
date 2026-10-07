//! Matched one-step Bitcoin fold comparison. One independently
//! verified production child anchor is shared by the generic and fused-SHA
//! outer proofs. The default outer FRI0/12 is diagnostic; set
//! S31_FOLD_MATCHED_PRODUCTION=1 for matching production FRI26/70 proofs.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const prover = @import("stwo_prover_engine");
const s31 = @import("stwo_s31_prototype");
const anchor = @import("../../bitcoin/fold/bitcoin_chain_anchor.zig");
const fold = @import("../../bitcoin/fold/bitcoin_chain_fold.zig");
const generic_native = @import("../../runtime/native_verifier.zig");
const fused_profile = s31.sha_fused_fold_profile;
const fused_prover = s31.sha_fused_fold_prover;
const fused_native = s31.sha_fused_fold_native_verifier;
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

fn m31Words(comptime n: usize, words: [n]u32) [n]QM31 {
    var out: [n]QM31 = undefined;
    for (words, &out) |word, *slot| slot.* = QM31.fromBase(M31.fromCanonical(word));
    return out;
}

fn packedWords(words: [8]u32) [8]QM31 {
    var out: [8]QM31 = undefined;
    for (words, &out) |word, *slot| slot.* = circuit.builder.ivalue.packU32(QM31, word);
    return out;
}

fn wordsFromBytes(bytes: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*slot, i| slot.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return out;
}

fn sha256d(words: [40]u32, header: *[80]u8) [32]u8 {
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
    var out: [8]u32 = undefined;
    for (root, &out) |word, *slot| slot.* = word.toU32();
    return out;
}

fn digestLimbs(hash: [32]u8) [16]QM31 {
    var out: [16]QM31 = undefined;
    for (&out, 0..) |*slot, i| slot.* = QM31.fromBase(M31.fromCanonical(std.mem.readInt(u16, hash[2 * i ..][0..2], .little)));
    return out;
}

fn addresses(wires: s31.bitcoin_fold_step.ShaBoundaryWires) [56]u32 {
    var out: [56]u32 = undefined;
    for (wires.header, 0..) |wire, i| out[i] = wire.idx;
    for (wires.digest, 0..) |wire, i| out[40 + i] = wire.idx;
    return out;
}

fn stageNs(nodes: []const prover.stage_profile.StageNode, id: []const u8) u64 {
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, id)) return @intFromFloat(node.seconds * std.time.ns_per_s);
        if (node.children) |children| {
            const child = stageNs(children, id);
            if (child != 0) return child;
        }
    }
    return 0;
}

test "matched generic and joined SHA fold step zero" {
    const allocator = std.heap.page_allocator;
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    const child_fri = try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4);
    const production_outer = std.posix.getenv("S31_FOLD_MATCHED_PRODUCTION") != null;
    const outer_fri = try core.pcs.config_v2.FriConfigV2.init(
        if (production_outer) 26 else 0,
        0,
        1,
        if (production_outer) 70 else 12,
        1,
    );

    var anchor_topology = try anchor.build(circuit.builder.NoValue, allocator, checkpoint, child_rows);
    defer anchor_topology.deinit();
    var anchor_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_topology.circuit);
    defer anchor_pp.deinit(allocator);
    const child_layout = anchor_pp.layout();
    const child_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(child_fri, child_layout.traceLogSize());
    const anchor_root = try anchor_pp.preprocessedRoot(allocator, child_pcs.fri_config.log_blowup_factor);
    const anchor_hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&child_layout),
        child_pcs.fri_config.log_blowup_factor,
        anchor_root,
    );
    var anchor_values = try anchor.build(QM31, allocator, checkpoint, child_rows);
    defer anchor_values.deinit();
    var anchor_value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &anchor_values.circuit);
    defer anchor_value_pp.deinit(allocator);
    try pp_guard.requireExact(&anchor_pp, &anchor_value_pp);
    anchor_values.circuit.deinit(allocator);
    anchor_values.circuit = .{};
    var child_proof = try cpu.Internal.prove(allocator, anchor_values.values(), &anchor_pp, &bundle, child_pcs, .{ .evaluations_only = true }, {});
    defer child_proof.deinit();
    const child_bytes = try generic_native.serialize(allocator, &child_proof);
    defer allocator.free(child_bytes);
    var child_capture = try generic_native.verifyAndCapture(allocator, &child_layout, &bundle, child_pcs, anchor_root, anchor_hash, checkpoint, child_bytes);
    defer child_capture.deinit();
    std.debug.print("S31_FOLD_MATCHED_SETUP child_pow=26 child_queries=70 child_fold=4 outer_pow={d} outer_queries={d} outer_fold=1 fixed_policy=cold outer_security={s}\n", .{
        outer_fri.pow_bits,
        outer_fri.n_queries,
        if (production_outer) "production_parameters" else "test_only",
    });

    const Fixture = struct { private_inputs: struct { prior_hash: [16]u32, child: [40]u32 } };
    var fixture = try std.json.parseFromSlice(Fixture, allocator, @embedFile("s31_bitcoin_fixture"), .{ .ignore_unknown_fields = true });
    defer fixture.deinit();
    var header: [80]u8 = undefined;
    const digest = sha256d(fixture.value.private_inputs.child, &header);
    const new_root = digestRoot(digest);
    const timestamp = fixture.value.private_inputs.child[34] | (fixture.value.private_inputs.child[35] << 16);
    const next_times = s31.bitcoin_fold_digest.advanceTimes(s31.bitcoin_fold_digest.initialTimes(), timestamp);
    var prior_times: [11]QM31 = undefined;
    for (s31.bitcoin_fold_digest.initialTimes(), &prior_times) |word, *slot| slot.* = circuit.builder.ivalue.packU32(QM31, word);
    var projection = try circuit.air_eval.projection.parse(allocator, @embedFile("s31_air_projection"));
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(allocator, &projection);
    defer table.deinit();
    const child_config: circuit.statements.circuit_statement.CircuitConfig = .{
        .config = child_pcs,
        .preprocessed_column_log_sizes = child_layout,
    };
    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const child_values = try cpu.verifier_proof.circuitVerifierValues(scratch.allocator(), &child_capture.proof, child_capture.config);

    var timer = try std.time.Timer.start();
    // Free the first proof and circuit before timing the second one. The
    // child proof, parsed witness, and AIR bundle remain shared setup.
    {
        // Generic fold: SHA256d remains in the ordinary full circuit.
        var generic_topology = try fold.topology(allocator, @embedFile("s31_air_projection"), child_layout, child_pcs, anchor_root, checkpoint, 0);
        defer generic_topology.deinit();
        try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &generic_topology, child_rows);
        var generic_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &generic_topology.circuit);
        defer generic_pp.deinit(allocator);
        const generic_layout = generic_pp.layout();
        const generic_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(outer_fri, generic_layout.traceLogSize());
        const generic_root = try generic_pp.preprocessedRoot(allocator, generic_pcs.fri_config.log_blowup_factor);
        const generic_hash = try circuit.common.circuit_hash.hostCircuitHash(
            try circuit.common.component_list.circuitComponentLogSizes(&generic_layout),
            generic_pcs.fri_config.log_blowup_factor,
            generic_root,
        );
        var generic_values = try fold.buildCircuit(
            QM31,
            allocator,
            &table,
            &child_config,
            anchor_root,
            checkpoint,
            circuit.builder.blake.hashValue(QM31, wordsFromBytes(generic_root)),
            m31Words(8, checkpoint),
            prior_times,
            m31Words(16, fixture.value.private_inputs.prior_hash),
            m31Words(40, fixture.value.private_inputs.child),
            0,
            &child_values,
            circuit.stark_verifier.verify.NoStages{},
        );
        defer generic_values.deinit();
        try std.testing.expect(try generic_values.isCircuitValid());
        try circuit.common.finalize.padToTargets(QM31, &generic_values, child_rows);
        var generic_value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &generic_values.circuit);
        defer generic_value_pp.deinit(allocator);
        try pp_guard.requireExact(&generic_pp, &generic_value_pp);
        generic_values.circuit.deinit(allocator);
        generic_values.circuit = .{};
        const generic_expected = try s31.bitcoin_fold_digest.statementDigest(generic_root, 0, checkpoint, new_root, next_times);
        var generic_recorder = prover.stage_profile.Recorder.initWithOptions(allocator, "generic_fold", "prove", .{ .capture_tasks = false });
        defer generic_recorder.deinit();
        timer.reset();
        var generic_proof = try cpu.Internal.prove(allocator, generic_values.values(), &generic_pp, &bundle, generic_pcs, .{ .evaluations_only = true, .recorder = &generic_recorder }, {});
        defer generic_proof.deinit();
        const generic_prove_ns = timer.read();
        try std.testing.expectEqualSlices(QM31, &packedWords(generic_expected), generic_proof.output_values);
        const generic_bytes = try generic_native.serialize(allocator, &generic_proof);
        defer allocator.free(generic_bytes);
        timer.reset();
        try generic_native.verify(allocator, &generic_layout, &bundle, generic_pcs, generic_root, generic_hash, generic_expected, generic_bytes);
        const generic_verify_ns = timer.read();
        var generic_stages = try generic_recorder.snapshot(allocator);
        defer generic_stages.deinit(allocator);
        std.debug.print("S31_FOLD_MATCHED profile=generic prove_ns={d} verify_ns={d} proof_bytes={d} witness_ns={d} fixed_ns={d} main_commit_ns={d} interaction_ns={d} interaction_commit_ns={d} composition_eval_ns={d} composition_interpolate_ns={d} composition_commit_ns={d} fri_quotient_ns={d} fri_decommit_ns={d}\n", .{
            generic_prove_ns,
            generic_verify_ns,
            generic_bytes.len,
            stageNs(generic_stages.stages, "circuit_base_witness"),
            stageNs(generic_stages.stages, "circuit_commit_preprocessed"),
            stageNs(generic_stages.stages, "circuit_commit_base"),
            stageNs(generic_stages.stages, "circuit_interaction_witness"),
            stageNs(generic_stages.stages, "circuit_commit_interaction"),
            stageNs(generic_stages.stages, "composition_evaluation"),
            stageNs(generic_stages.stages, "composition_interpolate_and_split"),
            stageNs(generic_stages.stages, "composition_commit"),
            stageNs(generic_stages.stages, "fri_quotient_build_and_commit"),
            stageNs(generic_stages.stages, "fri_decommit"),
        });
    }

    // Joined fold: the identical header/digest witness is constrained by the
    // SHA AIR and Gate/word buses under a separately derived full-circuit key.
    var boundary_wires: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
    var fused_topology = try fold.fusedTopology(allocator, @embedFile("s31_air_projection"), child_layout, child_pcs, anchor_root, checkpoint, 0, &boundary_wires);
    defer fused_topology.deinit();
    const gate_addresses = addresses(boundary_wires);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &fused_topology, child_rows);
    var fused_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &fused_topology.circuit, .{ .addresses = gate_addresses });
    defer fused_pp.deinit(allocator);
    const fused_layout = fused_pp.layout();
    const fused_pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(outer_fri, @max(fused_layout.traceLogSize(), 8));
    const source_digest = fused_profile.trustedFoldSourceDigest();
    const statement = s31.sha_fused_private_join_profile.PublicStatement{
        .digest_visibility = .private,
        .config = .{ .gate_addresses = gate_addresses, .first_call_id = 1 },
    };
    const fused_key = try fused_native.deriveKey(allocator, source_digest, &fused_pp, fused_topology.circuit.n_vars, statement, fused_pcs);
    const fused_expected = try s31.bitcoin_fold_digest.statementDigest(fused_key.fixed_root, 0, checkpoint, new_root, next_times);
    const fused_expected_values = packedWords(fused_expected);
    var value_boundary: s31.bitcoin_fold_step.ShaBoundaryWires = undefined;
    var fused_values = try fold.buildFusedCircuit(
        QM31,
        allocator,
        &table,
        &child_config,
        anchor_root,
        checkpoint,
        circuit.builder.blake.hashValue(QM31, wordsFromBytes(fused_key.fixed_root)),
        m31Words(8, checkpoint),
        prior_times,
        m31Words(16, fixture.value.private_inputs.prior_hash),
        m31Words(40, fixture.value.private_inputs.child),
        digestLimbs(digest),
        0,
        &child_values,
        circuit.stark_verifier.verify.NoStages{},
        &value_boundary,
    );
    defer fused_values.deinit();
    try std.testing.expect(try fused_values.isCircuitValid());
    try std.testing.expectEqualDeep(gate_addresses, addresses(value_boundary));
    try circuit.common.finalize.padToTargets(QM31, &fused_values, child_rows);
    var fused_value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuitWithShaBoundary(allocator, &fused_values.circuit, .{ .addresses = gate_addresses });
    defer fused_value_pp.deinit(allocator);
    try pp_guard.requireExact(&fused_pp, &fused_value_pp);
    fused_values.circuit.deinit(allocator);
    fused_values.circuit = .{};
    var fused_metrics = fused_prover.Metrics{};
    timer.reset();
    var fused_proof = try fused_prover.prove(allocator, fused_values.values(), &fused_pp, &bundle, fused_pcs, .{
        .source_digest = source_digest,
        .n_vars = fused_topology.circuit.n_vars,
        .statement = statement,
        .header = header,
        .metrics = &fused_metrics,
    });
    defer fused_proof.deinit();
    const fused_prove_ns = timer.read();
    try std.testing.expectEqualSlices(QM31, &fused_expected_values, fused_proof.outputs);
    const fused_bytes = try fused_prover.serialize(allocator, &fused_proof);
    defer allocator.free(fused_bytes);
    timer.reset();
    try fused_native.verifyBytes(allocator, .{ .key = fused_key, .public_outputs = &fused_expected_values }, fused_bytes);
    const fused_verify_ns = timer.read();
    std.debug.print("S31_FOLD_MATCHED profile=fused_sha prove_ns={d} verify_ns={d} proof_bytes={d} witness_ns={d} fixed_ns={d} main_commit_ns={d} interaction_ns={d} interaction_commit_ns={d} composition_eval_ns={d} composition_interpolate_ns={d} composition_commit_ns={d} fri_quotient_ns={d} fri_decommit_ns={d}\n", .{
        fused_prove_ns,
        fused_verify_ns,
        fused_bytes.len,
        fused_metrics.witness_ns,
        fused_metrics.fixed_commit_ns,
        fused_metrics.main_commit_ns,
        fused_metrics.interaction_ns,
        fused_metrics.interaction_commit_ns,
        fused_metrics.composition_eval_ns,
        fused_metrics.composition_interpolate_ns,
        fused_metrics.composition_commit_ns,
        fused_metrics.fri_quotient_commit_ns,
        fused_metrics.fri_decommit_ns,
    });
}
