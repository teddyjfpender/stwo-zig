//! Real recursive-parent capture and consuming arithmetic regression. The
//! retained parent is verified; this gate does not prove its next consumer.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("recursive_segment_v2_detached_parent_verifier.zig");
const command = @import("recursive_segment_v2_detached_parent_command.zig");
const protocol = @import("recursive_segment_v2_detached_parent_protocol.zig");
const cohort = @import("recursive_segment_v2_detached_parent_cohort.zig");
const composition = @import("recursive_segment_v2_detached_composition.zig");
const v3 = recursion.recursion_air_composition_circuit_v3;
const QM31 = core.fields.qm31.QM31;

test "detached parent capture replays genuine sparse cohort after input destruction" {
    const allocator = std.testing.allocator;
    var key: *command.OwnedKeyV1 = undefined;
    var expected: verifier.ExpectedV1 = undefined;
    var claims: verifier.ClaimsV1 = undefined;
    var capture: verifier.ProofCapture = undefined;
    var result: verifier.RecordingResultV1 = undefined;
    var channel = recursion.recording_poseidon_channel_v4.Channel.init(allocator);
    defer channel.deinit();
    {
        var input_arena = std.heap.ArenaAllocator.init(allocator);
        defer input_arena.deinit();
        const a = input_arena.allocator();
        const directory = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_BUNDLE");
        const pin_hex = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_KEY_SHA256");
        const expected_path = try std.process.getEnvVarOwned(a, "STWO_DETACHED_PARENT_EXPECTED_ROOT");
        var pin: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&pin, pin_hex);
        var dir = try std.fs.cwd().openDir(directory, .{});
        defer dir.close();
        key = try command.OwnedKeyV1.admit(allocator, try dir.readFileAlloc(a, "key.json", command.MAX_KEY_BYTES), pin);
        errdefer key.deinit();
        expected = try command.decodeExpected(a, try std.fs.cwd().readFileAlloc(a, expected_path, command.MAX_INPUT_BYTES));
        const envelope = try command.decodeClaims(a, try dir.readFileAlloc(a, "claims.json", command.MAX_INPUT_BYTES));
        claims = envelope.claims;
        const proof = try dir.readFileAlloc(a, "proof.bin", envelope.proof_bytes);
        try std.testing.expectEqual(envelope.proof_bytes, proof.len);
        try std.testing.expectEqual(envelope.proof_sha256, command.hash(proof));
        const terminal = try verifier.verify(allocator, key.key(), &expected, claims, proof);
        result = try verifier.verifyWithCaptureRecording(allocator, key.key(), &expected, claims, proof, &channel, &capture);
        errdefer capture.deinit(allocator);
        try std.testing.expectEqual(terminal, result.terminal);
        try std.testing.expectError(error.SegmentDetachedRecordingNotFresh,
            verifier.verifyWithCaptureRecording(allocator, key.key(), &expected, claims, proof, &channel, &capture));
        @memset(proof, 0); // No borrowed input survives the arena destruction.
    }
    defer key.deinit();
    defer capture.deinit(allocator);
    var execution = try channel.finish();
    defer execution.deinit();
    try std.testing.expectEqual(result.terminal, recursion.protocol.transcriptId(execution.final_digest, execution.final_draw_count));
    try @import("recursive_detached_recording_draws.zig").validate(&execution, &capture, &result.relations, key.key().pcs_config.fri_config.n_queries);
    var layout = try v3.capture_layout_v3.CaptureLayoutV3.initAuthenticatedBinaryWithProviderRow(allocator, .detached_segment_parent_v1, 34, &key.key().manifest, &capture);
    defer layout.deinit();
    const profile = v3.InputProfileV3{ .sampled_value_count = layout.sampled_value_count };
    const components = try cohort.OwnedComponentsV1.init(allocator, &key.key().manifest, key.key().parameters, &result.relations, claims);
    defer components.deinit();
    var program = try composition.recordDetached(.binary_node, allocator, &key.key().manifest, &layout, profile, components);
    defer program.circuit.deinit();
    defer allocator.free(program.bindings);
    const inputs = try allocator.alloc(QM31, try recursion.air.composition_circuit.recursionInputCount(profile.graphProfile()));
    defer allocator.free(inputs);
    var claim_inputs: [v3.COMPOSITION_CLAIM_INPUT_COUNT]QM31 = undefined;
    try v3.writeClaimInputs(.binary_node, &claims.values, &claims.poseidon_partials, &claim_inputs);
    try v3.writeInputsFromValidatedProfile(profile, .{
        .parent_binary_selector = true, .proof_kind = .binary_node,
        .statement_words = expected[0..recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS], .sampled_values = capture.sampled_values,
        .claim_inputs = &claim_inputs, .public_wire_boundary = try protocol.publicBoundary(&expected, &result.relations),
        .relations = &result.relations, .composition_randomness = capture.composition_randomness, .oods_seed = capture.oods_seed,
    }, inputs);
    const scratch = try allocator.alloc(QM31, program.circuit.nodes.len);
    defer allocator.free(scratch);
    try program.circuit.evaluateInto(inputs, scratch);
    var mutations: usize = 0;
    for (program.bindings, 0..) |binding, index| {
        const mutate = switch (binding.source) {
            .claimed_sum => |coordinate| coordinate.word_index == 0,
            .sampled_value => |coordinate| coordinate.item_index == layout.offsets[v3.capture_layout_v3.COMPOSITION_TREE_INDEX][0],
            else => false,
        };
        if (!mutate) continue;
        const saved = inputs[index];
        defer inputs[index] = saved;
        inputs[index] = saved.add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, program.circuit.evaluateInto(inputs, scratch));
        mutations += 1;
    }
    try std.testing.expectEqual(@as(usize, 45), mutations);
    var pcs = try recursion.captured_fri.Owned.init(allocator, .{
        .log_blowup_factor = key.key().pcs_config.fri_config.log_blowup_factor,
        .log_last_layer_degree_bound = key.key().pcs_config.fri_config.log_last_layer_degree_bound,
        .interaction_pow_bits = 0, .pcs_pow_bits = key.key().pcs_config.pow_bits,
        .claimed_sum_count = @intCast(claims.values.len),
    }, &capture);
    defer pcs.deinit();
    std.debug.print("DETACHED_PARENT_CAPTURE active_rows={d} physical_claims={d} sampled_values={d} graph_nodes={d} rejected_claims_and_samples={d} input_destroyed=true parent_verified=true consumer_proof_created=false\n", .{ key.key().manifest.roster_count, claims.values.len, capture.sampled_values.len, program.circuit.nodes.len, mutations });
}
