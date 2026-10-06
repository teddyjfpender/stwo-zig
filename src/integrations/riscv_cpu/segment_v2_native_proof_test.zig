//! Native CPU proof evidence for authenticated resumable V2 segments.

const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_api = @import("stwo_prover_api");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const M31 = stwo_core.fields.m31.M31;
const pcs_core = stwo_core.pcs;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const io_binding = frontend.recursion.segment_public_io_binding_v1;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const verified_link_v3 = frontend.recursion.segment_leaf_local_verified_link_v3;
const span = frontend.recursion.span_statement;
const Engine = prover.ProverEngineForBackend(CpuBackend);

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 1,
    },
};

test "native V2 proves and independently verifies real nonfinal and final segments" {
    try nativeSegments(Engine, "blake2s-default");
}
test "BLAKE3 V2 segment proofs verify nonfinal capture and final completion" {
    try nativeSegments(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1");
}
test "native BLAKE3 arithmetic fusion census" {
    try nativeSegmentsMode(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1", true);
}
fn nativeSegments(comptime ProofEngine: type, comptime suite_name: []const u8) !void {
    return nativeSegmentsMode(ProofEngine, suite_name, false);
}
fn nativeSegmentsMode(comptime ProofEngine: type, comptime suite_name: []const u8, comptime audit_only: bool) !void {
    const allocator = std.testing.allocator;
    std.debug.print("\nV2_NATIVE_PROOF_SUITE suite={s} queries={d} pow_bits={d}\n", .{ suite_name, test_config.fri_config.n_queries, test_config.pow_bits });
    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-segment-v2-poseidon-witness",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    // This repository-owned ELF carries exact __text_start/__text_len symbols,
    // so every segment commits the same complete declared program rather than
    // a segment-local fetch subset.  No CUSTOM-0 call is retired here.
    const elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );

    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    const left_result = &left_profile.base;
    var right_profile = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_profile.deinit();
    const right_result = &right_profile.base;

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        left_result.execution_trace.rows.items,
        left_result.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const expected_io = io_binding.Expected{
        .input_start = left_result.input_start,
        .input = left_result.input.?,
        .output_len_addr = right_result.output_len_addr,
        .output_data_addr = right_result.output_data_addr,
        .output = right_result.output orelse &.{},
    };
    try io_binding.validateRunner(left_result, expected_io);
    try io_binding.validateRunner(right_result, expected_io);
    const public_input = try io_binding.inputDigest(expected_io);
    const public_output = try io_binding.outputDigest(expected_io);
    const zero_io: span.Digest = .{0} ** 8;
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        zero_io,
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        zero_io,
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        zero_io,
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const left_span = try leafStatement(
        job,
        left_result,
        initial_state,
        shared_state,
        try span.EdgeClaim.present(public_input),
        span.EdgeClaim.absent(),
    );
    const right_span = try leafStatement(
        job,
        right_result,
        shared_state,
        final_state,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(public_output),
    );
    const session_id = digest("native-v2-session");
    const left_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        left_span,
        left_result,
    );
    const right_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        right_span,
        right_result,
    );
    try segment_v2.requireAdjacentSources(&left_source, &right_source);

    const left_words = try encode(allocator, &left_source);
    defer allocator.free(left_words);
    const right_words = try encode(allocator, &right_source);
    defer allocator.free(right_words);
    const left_public = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        left_words,
    );
    const right_public = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        right_words,
    );
    _ = try frontend.air.public_data_v2.PublicDataV2.authenticateAdjacent(
        &left_public,
        &right_public,
    );

    // Keep deterministic ingress mutations before the first expensive proof.
    // The authenticated wire owns this rejection; the V2 statement envelope
    // subsequently consumes only a validated `PublicDataV2`.
    const saved_word = left_words[segment_v2.fixed_layout.position_id];
    left_words[segment_v2.fixed_layout.position_id] = M31.fromCanonical(
        saved_word.toU32() ^ 1,
    );
    try std.testing.expectError(error.DigestMismatch, left_public.validate());
    left_words[segment_v2.fixed_layout.position_id] = saved_word;
    try left_public.validate();

    var left_prove_timer = try std.time.Timer.start();
    var left_output = try prover.proveRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        test_config,
        left_result,
        &recorder,
        left_public,
    );
    const left_prove_ns = left_prove_timer.read();
    const left_proof_size = left_output.proof.sizeEstimate();
    var left_proof_moved = false;
    defer if (left_proof_moved)
        left_output.deinitAfterProofMoved(allocator)
    else
        left_output.deinit(allocator);
    try left_output.statement.validateSegmentResult(left_result);
    try std.testing.expect(!(try left_output.statement.metadata()).is_final);
    const work = recorder.workCaptureRecorder() orelse unreachable;
    const poseidon_site = @intFromEnum(
        prover_api.work_profile.Site.sparse_memory_and_guest_poseidon_witness,
    );
    try std.testing.expectEqual(@as(u64, 1), work.planned_sites[poseidon_site]);
    try std.testing.expectEqual(@as(u64, 1), work.completed_sites[poseidon_site]);
    const work_snapshot = try recorder.workSnapshot();
    try work_snapshot.validate();

    // Preserve a real proof for the failure-atomic mutation gate without
    // proving twice: canonical postcard decoding owns an independent copy.
    var proof_bytes: std.ArrayList(u8) = .empty;
    defer proof_bytes.deinit(allocator);
    try postcard.serializeProof(
        ProofEngine.Hasher,
        proof_bytes.writer(allocator),
        left_output.proof,
    );
    if (comptime ProofEngine.Hasher != prover.Hasher) {
        var wrong_stream = std.io.fixedBufferStream(proof_bytes.items);
        const wrong_suite_proof = try postcard.deserializeProof(prover.Hasher, allocator, wrong_stream.reader());
        try std.testing.expectError(error.InvalidPreprocessedCommitment, prover.verifyRiscVSegmentV2WithEngine(Engine, allocator, test_config, left_output.statement, wrong_suite_proof, left_output.interaction_claim));
    }
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var mutated_proof = try postcard.deserializeProof(
        ProofEngine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var mutated_proof_moved = false;
    defer if (!mutated_proof_moved) mutated_proof.deinit(allocator);
    try std.testing.expectEqual(proof_bytes.items.len, proof_stream.pos);

    var bad_version = left_output.statement;
    bad_version.format_version +%= 1;
    var capture_sentinel: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
    @memset(std.mem.asBytes(&capture_sentinel), 0xa5);
    var before: [@sizeOf(@TypeOf(capture_sentinel))]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&capture_sentinel));
    var rejected_channel = ProofEngine.Channel{};
    mutated_proof_moved = true;
    try std.testing.expectError(
        error.InvalidStatement,
        prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
            ProofEngine,
            allocator,
            test_config,
            bad_version,
            mutated_proof,
            left_output.interaction_claim,
            &rejected_channel,
            &capture_sentinel,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&capture_sentinel),
    );

    var left_capture: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
    var left_channel = ProofEngine.Channel{};
    left_proof_moved = true;
    var left_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        ProofEngine,
        allocator,
        test_config,
        left_output.statement,
        left_output.proof,
        left_output.interaction_claim,
        &left_channel,
        &left_capture,
    );
    const left_verify_ns = left_verify_timer.read();
    defer left_capture.deinit(allocator);
    try left_capture.validate();
    const left_io_coverage = try io_binding.validateVerifiedCapture(ProofEngine, &left_capture, expected_io);
    try std.testing.expect(left_io_coverage.input and !left_io_coverage.output);
    try std.testing.expectError(error.IncompleteIoCoverage, io_binding.requireComplete(&.{left_io_coverage}));
    var changed_expected_io = expected_io;
    changed_expected_io.input = &.{1};
    try std.testing.expectError(
        error.InputDigestMismatch,
        io_binding.validateVerifiedCapture(ProofEngine, &left_capture, changed_expected_io),
    );
    try std.testing.expectEqual(left_public.wireId(), left_capture.receipt.wire_id);
    try std.testing.expectEqual(
        left_output.statement.authority_id,
        left_capture.receipt.authority_id,
    );
    try std.testing.expect(!left_capture.receipt.is_final);
    try std.testing.expect(
        left_capture.public_data.canonical_words.ptr != left_words.ptr,
    );
    if (comptime ProofEngine.Hasher != prover.Hasher) {
        const adapter = frontend.recursion.air.blake3_native_transcript;
        const coordinator = frontend.recursion.blake3_native_parent_preparation;
        const state = try coordinator.State.initRowOracle(ProofEngine, allocator, &left_output.statement, left_output.interaction_claim, &left_capture, test_config, 3);
        defer state.deinit();
        const prepared = &state.prepared;
        const transcript_counts = state.hash_layout.transcript;
        const path_counts = state.hash_layout.paths;
        try std.testing.expectEqual(prepared.live.g_rows.len + state.paths.live.g_rows.len, state.hash_layout.total.g);
        try std.testing.expectEqual(prepared.live.xor_rows.len + state.paths.live.xor_rows.len, state.hash_layout.total.xor);
        var invalid_layout = state.hash_layout;
        invalid_layout.logs[0] += 1;
        try std.testing.expectError(error.InvalidNativeHashLayout, invalid_layout.validateEmitted(transcript_counts, path_counts));
        invalid_layout = state.hash_layout;
        invalid_layout.paths.g += 1;
        try std.testing.expectError(error.InvalidNativeHashLayout, invalid_layout.validateEmitted(transcript_counts, path_counts));
        var invalid_geometry = left_capture.proof;
        invalid_geometry.trace_paths = invalid_geometry.trace_paths[0..3];
        try std.testing.expectError(error.InvalidNativeHashLayout, @TypeOf(state.hash_layout).init(allocator, transcript_counts, &invalid_geometry));
        std.debug.print("V2_BLAKE3_HASH_LAYOUT transcript_g={d} path_g={d} total_g={d} total_xor={d} logs={d},{d} verified_against_emission=true\n", .{ transcript_counts.g, path_counts.g, state.hash_layout.total.g, state.hash_layout.total.xor, state.hash_layout.logs[0], state.hash_layout.logs[1] });

        try std.testing.expectEqualSlices(u8, &left_channel.digestBytes(), &prepared.end.digestBytes());
        try std.testing.expectEqual(left_channel.n_draws, prepared.end.n_draws);
        try std.testing.expect(prepared.claim_payloads.len > 0);
        var pairs: usize = 0;
        for (prepared.live.draw_outputs) |output| if (output.role == .riscv_relation) {
            pairs += 1;
        };
        try std.testing.expectEqual(frontend.air.relation_challenges.DRAW_COUNT / 2, pairs);
        const composition = &state.composition;
        const native_links = frontend.recursion.air.blake3_native_challenge_links;
        const links = try native_links.prepare(allocator, composition, prepared.live.draw_outputs, 1500);
        try std.testing.expectEqual(@as(usize, 104), links.links.len);
        try std.testing.expectError(error.InvalidNativeChallengeLink, native_links.schedule(&composition.circuit, prepared.live.draw_outputs[1..]));
        const duplicate_outputs = try allocator.alloc(@TypeOf(prepared.live.draw_outputs[0]), prepared.live.draw_outputs.len + 1);
        defer allocator.free(duplicate_outputs);
        @memcpy(duplicate_outputs[0..prepared.live.draw_outputs.len], prepared.live.draw_outputs);
        duplicate_outputs[prepared.live.draw_outputs.len] = prepared.live.draw_outputs[0];
        try std.testing.expectError(error.InvalidNativeChallengeLink, native_links.schedule(&composition.circuit, duplicate_outputs));
        // Compare routed values directly with the canonical transcript draws.
        var matched: usize = 0;
        for (prepared.live.draw_outputs) |output| {
            if (output.role != .riscv_relation and output.role != .composition and output.role != .oods) continue;
            const draw = prepared.operations[output.operation].secure;
            for (0..output.words) |coordinate| {
                for (links.links, links.rows, links.fixed) |link, row, fixed| {
                    if (link.source.circuit != output.source.circuit or link.source.first_wire != output.source.first_wire + coordinate) continue;
                    try std.testing.expectEqual(draw.values[coordinate], row[0]);
                    try std.testing.expect(fixed[0].isZero());
                    try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
                    matched += 1;
                }
            }
        }
        try std.testing.expectEqual(links.links.len, matched);
        const reordered = duplicate_outputs[0..prepared.live.draw_outputs.len];
        std.mem.reverse(@TypeOf(reordered[0]), reordered);
        try std.testing.expectEqualDeep(links.links, try native_links.schedule(&composition.circuit, reordered));
        @memcpy(reordered, prepared.live.draw_outputs);
        reordered[1].source = reordered[0].source;
        try std.testing.expectError(error.InvalidNativeChallengeLink, native_links.schedule(&composition.circuit, reordered));
        std.debug.print("V2_BLAKE3_NATIVE_COMPOSITION nodes={d} challenge_links={d} outputs={d}\n", .{ composition.circuit.nodes.len, links.links.len, composition.circuit.outputs.len });
        const payload_links = frontend.recursion.air.blake3_native_payload_links;
        const payloads = &state.payloads;
        try std.testing.expectEqual(@as(usize, composition.circuit.input_profile.sampled_value_count) + frontend.air.transcript.claims.COMPONENT_COUNT, payloads.encoded.len);
        for (payloads.encoded, payloads.fixed_encoded) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[24..], fixed[24..]);
        for (payloads.scalars, payloads.fixed_scalars) |row, fixed| {
            try std.testing.expect(fixed[0].isZero());
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        }
        for (payloads.packing, payloads.fixed_packing) |row, fixed| {
            for (fixed[0..4]) |word| try std.testing.expect(word.isZero());
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[4..], fixed[4..]);
        }
        {
            const saved = prepared.live.payload_reads;
            defer prepared.live.payload_reads = saved;
            prepared.live.payload_reads = saved[1..];
            try std.testing.expectError(error.InvalidNativePayloadLink, payload_links.prepare(allocator, composition, prepared, 1500));
        }
        var changed_payload_checked = false;
        for (prepared.operations) |*op| {
            if (op.* != .routed_felts or !std.meta.eql(op.routed_felts.source, prepared.claim_payloads[0].source)) continue;
            const saved = op.routed_felts.values;
            defer op.routed_felts.values = saved;
            const changed = [_]stwo_core.fields.qm31.QM31{saved[0].add(stwo_core.fields.qm31.QM31.one())};
            op.routed_felts.values = &changed;
            try std.testing.expectError(error.InvalidNativePayloadLink, payload_links.prepare(allocator, composition, prepared, 1500));
            changed_payload_checked = true;
            break;
        }
        try std.testing.expect(changed_payload_checked);
        std.debug.print("V2_BLAKE3_NATIVE_PAYLOADS secure_values={d} scalar_routes={d}\n", .{ payloads.encoded.len, payloads.scalars.len });
        const deep = &state.deep;
        const shared_samples = &state.shared_samples;
        try std.testing.expectEqual(@as(usize, composition.circuit.input_profile.sampled_value_count) * 4, shared_samples.destinations.len);
        const claim_scalars = frontend.air.transcript.claims.COMPONENT_COUNT * 4;
        try std.testing.expectEqualDeep(payloads.scalars[0..claim_scalars], shared_samples.sources[0..claim_scalars]);
        for (shared_samples.sources[claim_scalars..], payloads.scalars[claim_scalars..]) |shared, original_source| {
            try std.testing.expectEqual(original_source[3].v + 1, shared[3].v);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, original_source[0..3], shared[0..3]);
        }
        for (shared_samples.destinations, shared_samples.fixed_destinations) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        {
            const index = frontend.air.transcript.claims.COMPONENT_COUNT;
            const saved = payloads.nodes[index];
            defer payloads.nodes[index] = saved;
            payloads.nodes[index] = payloads.nodes[index + 1];
            try std.testing.expectError(error.InvalidNativeSampleLink, frontend.recursion.air.blake3_native_sample_links.prepare(allocator, composition, payloads, deep, 1500, 1502));
        }
        const samples_changed = try allocator.dupe(stwo_core.fields.qm31.QM31, deep.inputs.inputs.sampled_values);
        defer allocator.free(samples_changed);
        samples_changed[0] = samples_changed[0].add(stwo_core.fields.qm31.QM31.one());
        var wrong_deep = deep.inputs.inputs;
        wrong_deep.sampled_values = samples_changed;
        try std.testing.expectError(error.UnsatisfiedCircuit, deep.graph.evaluate(allocator, wrong_deep));
        std.debug.print("V2_BLAKE3_NATIVE_DEEP nodes={d} outputs={d} shared_sample_scalars={d}\n", .{ deep.graph.nodes.len, deep.graph.outputs.len, shared_samples.destinations.len });
        const fri = &state.fri;
        try std.testing.expectEqual(test_config.fri_config.n_queries * 4, fri.sources.len);
        for (fri.sources, fri.fixed_sources, fri.destinations, fri.fixed_destinations) |source, fixed_source, destination, fixed_destination| {
            try std.testing.expectEqual(source[0], destination[0]);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, source[1..], fixed_source[1..]);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, destination[1..], fixed_destination[1..]);
        }
        const wrong_answers = try allocator.dupe(stwo_core.fields.qm31.QM31, fri.inputs.inputs.deep_answers);
        defer allocator.free(wrong_answers);
        wrong_answers[0] = wrong_answers[0].add(stwo_core.fields.qm31.QM31.one());
        var wrong_fri = fri.inputs.inputs;
        wrong_fri.deep_answers = wrong_answers;
        try std.testing.expectError(error.UnsatisfiedCircuit, fri.graph.evaluate(allocator, wrong_fri));
        const wrong_coefficients = try allocator.dupe(stwo_core.fields.qm31.QM31, fri.inputs.inputs.last_layer_coefficients);
        defer allocator.free(wrong_coefficients);
        wrong_coefficients[0] = wrong_coefficients[0].add(stwo_core.fields.qm31.QM31.one());
        wrong_fri = fri.inputs.inputs;
        wrong_fri.last_layer_coefficients = wrong_coefficients;
        try std.testing.expectError(error.UnsatisfiedCircuit, fri.graph.evaluate(allocator, wrong_fri));
        std.debug.print("V2_BLAKE3_NATIVE_FRI nodes={d} outputs={d} answer_routes={d}\n", .{ fri.graph.nodes.len, fri.graph.outputs.len, fri.sources.len });
        const pcs_challenges = frontend.recursion.air.blake3_native_pcs_challenges;
        const joined_challenges = &state.joined_challenges;
        try std.testing.expectEqual(8 + 4 * fri.inputs.inputs.fri_alphas.len, joined_challenges.rows.len);
        for (joined_challenges.rows, joined_challenges.fixed) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        for (0..4) |word| try std.testing.expectEqual(links.rows[native_links.COUNT - 4 + word][3].v + 1, joined_challenges.composition.rows[native_links.COUNT - 4 + word][3].v);
        {
            const saved = prepared.live.draw_outputs;
            defer prepared.live.draw_outputs = saved;
            prepared.live.draw_outputs = saved[0 .. saved.len - 1];
            try std.testing.expectError(error.InvalidNativePcsChallenge, pcs_challenges.prepare(allocator, composition, prepared, deep, fri, .{ 1500, 1502, 1504 }));
        }
        var checked_draw_mutation = false;
        for (prepared.operations) |*op| {
            if (op.* != .secure or op.secure.output == null or op.secure.output.? != .deep) continue;
            const saved = op.secure.values[0];
            defer op.secure.values[0] = saved;
            op.secure.values[0] = saved.add(stwo_core.fields.m31.M31.one());
            try std.testing.expectError(error.InvalidNativePcsChallenge, pcs_challenges.prepare(allocator, composition, prepared, deep, fri, .{ 1500, 1502, 1504 }));
            checked_draw_mutation = true;
            break;
        }
        try std.testing.expect(checked_draw_mutation);
        std.debug.print("V2_BLAKE3_NATIVE_PCS_CHALLENGES routes={d} oods_shared=4\n", .{joined_challenges.rows.len});
        const terminal_encoding = frontend.recursion.air.blake3_native_terminal_encoding;
        const terminal_rows = &state.terminal_rows;
        try std.testing.expectEqual(fri.inputs.inputs.last_layer_coefficients.len, terminal_rows.rows.len);
        for (terminal_rows.rows, fri.inputs.inputs.last_layer_coefficients) |row, coefficient| {
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, &coefficient.toM31Array(), row.encoded[0..4]);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row.encoded[24..], row.fixed_encoded[24..]);
        }
        {
            const saved = prepared.live.payload_reads;
            defer prepared.live.payload_reads = saved;
            prepared.live.payload_reads = saved[0 .. saved.len - 1];
            try std.testing.expectError(error.InvalidNativeTerminalEncoding, terminal_encoding.prepare(allocator, prepared, fri, 1504));
        }
        var checked_terminal_mutation = false;
        for (prepared.operations) |*op| {
            if (op.* != .routed_felts or !std.meta.eql(op.routed_felts.source, adapter.TERMINAL_SOURCE)) continue;
            const saved = op.routed_felts.values;
            const changed = try allocator.dupe(stwo_core.fields.qm31.QM31, saved);
            defer allocator.free(changed);
            defer op.routed_felts.values = saved;
            changed[0] = changed[0].add(stwo_core.fields.qm31.QM31.one());
            op.routed_felts.values = changed;
            try std.testing.expectError(error.InvalidNativeTerminalEncoding, terminal_encoding.prepare(allocator, prepared, fri, 1504));
            checked_terminal_mutation = true;
            break;
        }
        try std.testing.expect(checked_terminal_mutation);
        std.debug.print("V2_BLAKE3_NATIVE_TERMINAL encoded_coefficients={d}\n", .{terminal_rows.rows.len});
        const native_queries = frontend.recursion.air.blake3_native_queries;
        const query_rows = &state.query_rows;
        try std.testing.expectEqual(test_config.fri_config.n_queries, query_rows.encoded.len);
        for (query_rows.rows, query_rows.fixed) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        for (query_rows.encoded, left_capture.proof.queries.raw) |row, position| try std.testing.expectEqual(position, row[0].v);
        {
            const saved = prepared.live.query_outputs;
            defer prepared.live.query_outputs = saved;
            prepared.live.query_outputs = saved[1..];
            try std.testing.expectError(error.InvalidNativeQueryLink, native_queries.prepare(allocator, prepared, deep, fri));
        }
        var query_mutation_checked = false;
        for (prepared.operations) |*op| {
            if (op.* != .queries) continue;
            const saved = op.queries.values;
            const changed = try allocator.dupe(u32, saved);
            defer allocator.free(changed);
            defer op.queries.values = saved;
            changed[0] ^= 1;
            op.queries.values = changed;
            try std.testing.expectError(error.InvalidNativeQueryLink, native_queries.prepare(allocator, prepared, deep, fri));
            query_mutation_checked = true;
            break;
        }
        try std.testing.expect(query_mutation_checked);
        std.debug.print("V2_BLAKE3_NATIVE_QUERIES queries={d} scalar_rows={d}\n", .{ query_rows.encoded.len, query_rows.rows.len });
        const native_paths = frontend.recursion.air.blake3_stark_paths;
        const paths = &state.paths;
        try native_queries.applyPathReads(allocator, query_rows, deep, paths.inputs.projection.bit_reads);
        const admitted_rows = try allocator.dupe(@TypeOf(query_rows.rows[0]), query_rows.rows);
        defer allocator.free(admitted_rows);
        try native_queries.applyPathReads(allocator, query_rows, deep, paths.inputs.projection.bit_reads);
        try std.testing.expectEqualDeep(admitted_rows, query_rows.rows);
        const saved_reads = try allocator.alloc([31]u32, query_rows.links.queries.len);
        defer allocator.free(saved_reads);
        for (query_rows.links.queries, saved_reads) |query, *saved| saved.* = query.path_uses;
        {
            const columns_support = frontend.recursion.air.blake3_native_parent_test_support.hash_columns;
            var columns_arena = std.heap.ArenaAllocator.init(allocator);
            defer columns_arena.deinit();
            const out = try columns_support.allocate(columns_arena.allocator(), paths.live.g_rows.len, paths.live.xor_rows.len);
            {
                var repeated_paths = try native_paths.prepareMainColumns(allocator, &left_capture.proof, &deep.graph, &fri.graph, &query_rows.links, out);
                defer repeated_paths.deinit();
                try std.testing.expect(repeated_paths.hash_metadata != null);
                try columns_support.expectReceipts(paths.live, repeated_paths.live);
                try columns_support.expectReceipts(paths.fixed, repeated_paths.fixed);
                try columns_support.expectFixedMetadata(paths.fixed, repeated_paths.fixed_hash_metadata.?);
                try std.testing.expectEqualDeep(paths.inputs.sources, repeated_paths.inputs.sources);
                for (query_rows.links.queries, saved_reads) |query, saved| try std.testing.expectEqualDeep(saved, query.path_uses);
            }
            try columns_support.expectRows(out, paths.live, paths.fixed);
            columns_support.poison(out);
            var bad = out;
            bad.xor_rows.columns[0] = bad.xor_rows.columns[0][1..];
            try std.testing.expectError(error.InvalidBlake3WitnessDestination, native_paths.prepareMainColumns(allocator, &left_capture.proof, &deep.graph, &fri.graph, &query_rows.links, bad));
            try columns_support.expectPoison(out);
            const sibling = &left_capture.proof.trace_paths[0].siblings[0];
            sibling[31] ^= 0x80;
            defer sibling[31] ^= 0x80;
            try std.testing.expectError(error.InvalidStarkPathRoot, native_paths.prepareMainColumns(allocator, &left_capture.proof, &deep.graph, &fri.graph, &query_rows.links, out));
            for (query_rows.links.queries, saved_reads) |query, saved| try std.testing.expectEqualDeep(saved, query.path_uses);
        }
        {
            const sibling = &left_capture.proof.trace_paths[0].siblings[0];
            sibling[31] ^= 0x80;
            defer sibling[31] ^= 0x80;
            try std.testing.expectError(error.InvalidStarkPathRoot, native_paths.prepare(allocator, &left_capture.proof, &deep.graph, &fri.graph, &query_rows.links));
        }
        for (query_rows.links.queries, saved_reads) |query, saved| try std.testing.expectEqualDeep(saved, query.path_uses);
        std.debug.print("V2_BLAKE3_NATIVE_PATHS g_rows={d} select_rows={d} opening_sources={d}\n", .{ paths.live.g_rows.len, paths.live.select_rows.len, paths.inputs.sources.len });
        const native_openings = frontend.recursion.air.blake3_native_openings;
        const opening_rows = &state.opening_rows;
        try std.testing.expectEqual(paths.inputs.sources.len, opening_rows.rows.len);
        for (opening_rows.rows, opening_rows.fixed, paths.inputs.sources) |row, fixed, source| {
            try std.testing.expectEqual(source.value, row[0]);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        }
        {
            const saved = paths.inputs.sources;
            defer paths.inputs.sources = saved;
            paths.inputs.sources = saved[1..];
            try std.testing.expectError(error.InvalidNativeOpeningSource, native_openings.prepare(allocator, paths, deep, fri));
        }
        {
            const saved = paths.inputs.sources[0];
            defer paths.inputs.sources[0] = saved;
            paths.inputs.sources[0] = paths.inputs.sources[1];
            try std.testing.expectError(error.InvalidNativeOpeningSource, native_openings.prepare(allocator, paths, deep, fri));
            paths.inputs.sources[0] = saved;
            paths.inputs.sources[0].value = saved.value.add(stwo_core.fields.m31.M31.one());
            try std.testing.expectError(error.InvalidNativeOpeningSource, native_openings.prepare(allocator, paths, deep, fri));
        }
        std.debug.print("V2_BLAKE3_NATIVE_OPENINGS scalar_producers={d}\n", .{opening_rows.rows.len});
        const root_nonce = frontend.recursion.air.blake3_native_root_nonce;
        const root_words = &state.root_words;
        try std.testing.expectEqual((left_capture.proof.commitments.len + left_capture.proof.fri.layers.len - 1) * 8 + 4, root_words.words.len);
        for (root_words.words, root_words.fixed_words) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[4..], fixed[4..]);
        {
            const saved = prepared.live.root_reads;
            defer prepared.live.root_reads = saved;
            prepared.live.root_reads = saved[1..];
            try std.testing.expectError(error.InvalidNativeRootNonce, root_nonce.prepare(ProofEngine, allocator, &left_output.statement, &left_capture, test_config, left_output.interaction_claim.interaction_pow, prepared));
        }
        var root_checked = false;
        var nonce_checked = false;
        for (prepared.operations) |*op| {
            if (op.* == .routed_root and !root_checked) {
                op.routed_root.value[31] ^= 0x80;
                defer op.routed_root.value[31] ^= 0x80;
                try std.testing.expectError(error.InvalidNativeRootNonce, root_nonce.prepare(ProofEngine, allocator, &left_output.statement, &left_capture, test_config, left_output.interaction_claim.interaction_pow, prepared));
                root_checked = true;
            } else if (op.* == .routed_integer and !nonce_checked) {
                op.routed_integer.value ^= 1;
                defer op.routed_integer.value ^= 1;
                try std.testing.expectError(error.InvalidNativeRootNonce, root_nonce.prepare(ProofEngine, allocator, &left_output.statement, &left_capture, test_config, left_output.interaction_claim.interaction_pow, prepared));
                nonce_checked = true;
            }
        }
        try std.testing.expect(root_checked and nonce_checked);
        std.debug.print("V2_BLAKE3_NATIVE_ROOT_NONCE private_words={d} key_words={d}\n", .{ root_words.words.len, root_words.key.len });
        const public_boundary = &state.public_boundary;
        try public_boundary.graph.validate();
        try std.testing.expect(try public_boundary.circuit.outputsAreZero(public_boundary.evaluation.values));
        var public_sum_mutated = false;
        for (public_boundary.bindings, 0..) |binding, index| {
            if (binding != .published_sum_word) continue;
            const saved = public_boundary.inputs[index];
            defer public_boundary.inputs[index] = saved;
            public_boundary.inputs[index] = saved.add(stwo_core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidNativePublicBoundary, public_boundary.evaluate(allocator, public_boundary.inputs));
            public_sum_mutated = true;
            break;
        }
        try std.testing.expect(public_sum_mutated);
        std.debug.print("V2_BLAKE3_NATIVE_PUBLIC_BOUNDARY nodes={d} inputs={d} outputs={d}\n", .{ public_boundary.graph.nodes.len, public_boundary.inputs.len, public_boundary.graph.outputs.len });
        const public_links = frontend.recursion.air.blake3_native_public_links;
        const public_join = &state.public_join;
        try std.testing.expectEqual(@as(usize, 4), public_join.graph.outputs.len);
        for (public_join.destinations, public_join.fixed_destinations) |row, fixed| try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
        var wrong_total = public_join.inputs;
        wrong_total[0] = wrong_total[0].add(stwo_core.fields.qm31.QM31.one());
        try std.testing.expectError(error.InvalidNativePublicLink, public_join.evaluate(allocator, &wrong_total));
        for (public_join.composition.rows[0..32], joined_challenges.composition.rows[0..32]) |row, original_row| try std.testing.expectEqual(original_row[3].v + 1, row[3].v);
        try std.testing.expectEqualDeep(joined_challenges.composition.rows[32..], public_join.composition.rows[32..]);
        {
            const saved = joined_challenges.composition.links[0];
            defer joined_challenges.composition.links[0] = saved;
            joined_challenges.composition.links[0].node = joined_challenges.composition.links[1].node;
            try std.testing.expectError(error.InvalidNativePublicLink, public_links.prepare(allocator, composition, public_boundary, joined_challenges, payloads));
        }
        {
            const saved = public_boundary.evaluation.values[0];
            defer public_boundary.evaluation.values[0] = saved;
            public_boundary.evaluation.values[0] = saved.add(stwo_core.fields.qm31.QM31.one());
            try std.testing.expectError(error.InvalidNativePublicBoundary, public_boundary.validate(allocator));
        }
        std.debug.print("V2_BLAKE3_NATIVE_PUBLIC_LINKS challenges={d} aggregate_inputs={d} zero_outputs={d}\n", .{ public_join.challenge_rows.len, public_join.inputs.len, public_join.graph.outputs.len });
        const public_sources = frontend.recursion.air.blake3_native_public_sources;
        const public_inputs = &state.public_inputs;
        try std.testing.expectEqual(public_boundary.inputs.len, public_inputs.rows.len + public_inputs.sums.len + public_join.challenge_rows.len + public_join.total_sources.len);
        for (public_inputs.rows, public_inputs.fixed_rows) |row, fixed| {
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[4..], fixed[4..]);
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[0..4], row[8..12]);
        }
        for (public_inputs.sums, public_inputs.fixed_sums) |row, fixed| {
            try std.testing.expectEqualSlices(stwo_core.fields.m31.M31, row[1..], fixed[1..]);
            try std.testing.expectEqual(@as(u32, 0), fixed[0].v);
        }
        {
            const index = public_inputs.statement_operation;
            const saved = prepared.operations[index];
            defer prepared.operations[index] = saved;
            const changed = try allocator.dupe(u32, saved.words);
            defer allocator.free(changed);
            changed[0] ^= 1;
            prepared.operations[index] = .{ .words = changed };
            try std.testing.expectError(error.InvalidNativePublicSource, public_sources.prepare(allocator, &left_output.statement, test_config, prepared, public_boundary));
        }
        std.debug.print("V2_BLAKE3_NATIVE_PUBLIC_SOURCES public_rows={d} private_sum_rows={d} covered_inputs={d}\n", .{ public_inputs.rows.len, public_inputs.sums.len, public_boundary.inputs.len });
        const parent_rows = frontend.recursion.air.blake3_native_parent_rows;
        const parent_sources = state.sources();
        {
            const saved_row = opening_rows.rows[1];
            const saved_fixed = opening_rows.fixed[1];
            defer opening_rows.rows[1] = saved_row;
            defer opening_rows.fixed[1] = saved_fixed;
            opening_rows.rows[1] = opening_rows.rows[0];
            opening_rows.fixed[1] = opening_rows.fixed[0];
            try std.testing.expectError(error.DuplicateNativeParentInput, parent_rows.prepare(allocator, parent_sources));
        }
        {
            const saved_rows = opening_rows.rows;
            const saved_fixed = opening_rows.fixed;
            defer opening_rows.rows = saved_rows;
            defer opening_rows.fixed = saved_fixed;
            opening_rows.rows = opening_rows.rows[1..];
            opening_rows.fixed = opening_rows.fixed[1..];
            try std.testing.expectError(error.MissingNativeParentInput, parent_rows.prepare(allocator, parent_sources));
        }
        if (audit_only) {
            try parent_rows.fusionCensus(allocator, state.sources());
            var census_rows = try parent_rows.prepareCensus(allocator, state.sources());
            defer census_rows.deinit();
            return;
        }
        var expected_parent = try state.finish();
        defer expected_parent.deinit();
        {
            const direct = try coordinator.State.init(ProofEngine, allocator, &left_output.statement, left_output.interaction_claim, &left_capture, test_config, 3);
            var owns_direct = true;
            defer if (owns_direct) direct.deinit();
            try std.testing.expect(direct.prepared.live.hash_metadata != null);
            try std.testing.expect(direct.paths.hash_metadata != null);
            const first_column = direct.hash_columns.?.main[0][0].values.ptr;
            const metadata = &direct.prepared.live.hash_metadata.?.g_rows[0][0];
            const saved = metadata.*;
            metadata.* = saved.add(stwo_core.fields.m31.M31.one());
            try std.testing.expectError(error.InvalidNativeParentRows, direct.finish());
            metadata.* = saved;
            try std.testing.expectEqual(first_column, direct.hash_columns.?.main[0][0].values.ptr);
            var adopted = try direct.finish();
            defer adopted.deinit();
            try std.testing.expectEqual(first_column, adopted.rows.main[0][0].values.ptr);
            try std.testing.expectEqual(@as(usize, 0), direct.hash_columns.?.main[0].len);
            try std.testing.expectError(error.InvalidNativeHashColumns, direct.finish());
            direct.deinit();
            owns_direct = false;
            inline for (parent_rows.Airs, 0..) |_, i| {
                try std.testing.expectEqualDeep(expected_parent.rows.main[i], adopted.rows.main[i]);
                try std.testing.expectEqualDeep(expected_parent.rows.fixed[i], adopted.rows.fixed[i]);
            }
        }
        for ([_]usize{ 1, 64 * 1024 * 1024 }) |rejected_limit| {
            try std.testing.expectError(error.PreparationHostBudgetExceeded, coordinator.prepareBounded(ProofEngine, allocator, &left_output.statement, left_output.interaction_claim, &left_capture, test_config, 3, rejected_limit));
        }
        const queued_byte_limit = 512 * 1024 * 1024;
        var handoff = try coordinator.Handoff.init(allocator, 1, queued_byte_limit);
        defer handoff.deinit();
        const PreparationWorker = struct {
            queue: *coordinator.Handoff,
            failure: ?anyerror = null,
            fn run(self: *@This(), a: std.mem.Allocator, statement: *const @TypeOf(left_output.statement), claim: @TypeOf(left_output.interaction_claim), capture: *const @TypeOf(left_capture)) void {
                defer self.queue.close();
                coordinator.prepareAndSend(ProofEngine, a, statement, claim, capture, test_config, 3, 512 * 1024 * 1024, self.queue) catch |err| {
                    self.failure = err;
                };
            }
        };
        var preparation_worker = PreparationWorker{ .queue = &handoff };
        const preparation_thread = try std.Thread.spawn(.{}, PreparationWorker.run, .{ &preparation_worker, allocator, &left_output.statement, left_output.interaction_claim, &left_capture });
        // receive transfers the arena-backed owner across the thread boundary.
        // Join before observing the worker error or releasing capture inputs.
        const received_parent = handoff.receive();
        preparation_thread.join();
        if (preparation_worker.failure) |err| return err;
        var parent = received_parent orelse return error.MissingPreparedParent;
        defer parent.deinit();
        try std.testing.expect(handoff.receive() == null);
        {
            const expected = &expected_parent;
            try std.testing.expectEqualDeep(expected.context, parent.context);
            inline for (parent_rows.Airs, 0..) |_, i| {
                try std.testing.expectEqualDeep(expected.rows.main[i], parent.rows.main[i]);
                try std.testing.expectEqualDeep(expected.rows.fixed[i], parent.rows.fixed[i]);
            }
        }
        const preparation_budget = parent.allocation_budget.?.snapshot();
        try std.testing.expect(preparation_budget.live_bytes <= preparation_budget.limit);
        try std.testing.expect(preparation_budget.peak_live_bytes <= preparation_budget.limit);
        std.debug.print("V2_BLAKE3_NATIVE_PARENT_HANDOFF slots=1 queue_limit_bytes={d} retained_bytes={d} preparation_peak_bytes={d} preparation_limit_bytes={d}\n", .{ queued_byte_limit, try parent.retainedBytes(), preparation_budget.peak_live_bytes, preparation_budget.limit });
        std.debug.print("V2_BLAKE3_NATIVE_PARENT_PREPARATION canonical=true hash_columns_emitted_directly=true row_oracle_parity=true intermediates_released=true bounded_thread_handoff=true inputs={d}\n", .{parent.rows.input_count});
        const execution_policy = @import("./recursive_pipeline_worker_execution_policy_v2.zig");
        const host = try execution_policy.HostExecutionAuthorityV2.detect(16 * 1024 * 1024 * 1024);
        const pipeline_policy = try execution_policy.PolicyV2.init(host, .{ .total_cpu_tokens = 3, .cpu_tokens_per_node = 3, .proof_worker_count = 2, .maximum_parallel_nodes = 1, .total_rss_bytes = 12 * 1024 * 1024 * 1024, .rss_bytes_per_node = 12 * 1024 * 1024 * 1024 });
        const pipeline = frontend.recursion.blake3_native_parent_pipeline;
        const parent_job = pipeline.Job(ProofEngine){ .statement = &left_output.statement, .claim = left_output.interaction_claim, .capture = &left_capture, .config = test_config, .capacity = 3 };
        try frontend.recursion.air.blake3_native_parent_test_support.ForBackend(CpuBackend).check(ProofEngine, allocator, &parent.rows, parent.context, &pipeline_policy, &.{ parent_job, parent_job });
        const original = left_output.interaction_claim.opcode_claims[0][0];
        left_output.interaction_claim.opcode_claims[0][0] = original.add(stwo_core.fields.qm31.QM31.one());
        defer left_output.interaction_claim.opcode_claims[0][0] = original;
        try std.testing.expectError(error.InvalidBlake3PcsTranscript, adapter.prepare(ProofEngine, allocator, &left_output.statement, left_output.interaction_claim, &left_capture, test_config, 3));
        std.debug.print("V2_BLAKE3_NATIVE_TRANSCRIPT operations={d} relation_pairs={d} draws={d} plan={s}\n", .{ prepared.operations.len, pairs, prepared.end.n_draws, std.fmt.bytesToHex(prepared.plan.id, .lower) });
    }
    try left_capture.vm_air.validate();
    try left_capture.public_data.data.validate();
    const captured_relations = frontend.air.relation_challenges.Relations
        .fromDrawSequence(&left_capture.vm_air.relation_draws);
    try left_capture.native_public_sums.validateAgainst(
        &left_capture.public_data.data,
        &captured_relations,
    );
    const saved_sums_identity = left_capture.native_public_sums.identity[0];
    left_capture.native_public_sums.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidNativePublicSums,
        left_capture.native_public_sums.validateAgainst(
            &left_capture.public_data.data,
            &captured_relations,
        ),
    );
    left_capture.native_public_sums.identity[0] = saved_sums_identity;
    try left_capture.validate();
    const saved_receipt_identity = left_capture.receipt.identity[0];
    left_capture.receipt.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidVerifiedReceipt,
        left_capture.validate(),
    );
    left_capture.receipt.identity[0] = saved_receipt_identity;
    try left_capture.validate();

    var right_prove_timer = try std.time.Timer.start();
    var right_output = try prover.proveRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        test_config,
        right_result,
        null,
        right_public,
    );
    const right_prove_ns = right_prove_timer.read();
    const right_proof_size = right_output.proof.sizeEstimate();
    var right_proof_moved = false;
    defer if (right_proof_moved)
        right_output.deinitAfterProofMoved(allocator)
    else
        right_output.deinit(allocator);
    try right_output.statement.validateSegmentResult(right_result);
    // A resumed V2 segment authenticates its nonzero origin through the
    // statement. A self-consistent local trace range cannot replace it.
    const trace = &right_profile.base.execution_trace;
    const saved_origin = trace.clock_origin;
    const saved_last = trace.last_retirement_clock;
    try std.testing.expect(saved_origin > 0);
    try trace.bindExtractedClockRange(0, @intCast(right_result.cycle_count), 0);
    try std.testing.expectError(
        error.SegmentResultMismatch,
        right_output.statement.validateSegmentResult(right_result),
    );
    try trace.bindExtractedClockRange(saved_origin, saved_last, 0);
    const saved_first_row_clock = trace.rows.items[0].clk;
    trace.rows.items[0].clk = 1;
    try std.testing.expectError(
        error.SegmentResultMismatch,
        right_output.statement.validateSegmentResult(right_result),
    );
    trace.rows.items[0].clk = saved_first_row_clock;
    try right_output.statement.validateSegmentResult(right_result);
    const right_metadata = try right_output.statement.metadata();
    try std.testing.expect(right_metadata.is_final);
    try std.testing.expect(right_metadata.completion != null);
    right_proof_moved = true;
    var right_verify_timer = try std.time.Timer.start();
    var right_capture: prover.VerifiedSegmentV2CaptureForEngine(ProofEngine) = undefined;
    var right_channel = ProofEngine.Channel{};
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        ProofEngine,
        allocator,
        test_config,
        right_output.statement,
        right_output.proof,
        right_output.interaction_claim,
        &right_channel,
        &right_capture,
    );
    defer right_capture.deinit(allocator);
    const right_io_coverage = try io_binding.validateVerifiedCapture(ProofEngine, &right_capture, expected_io);
    try std.testing.expect(!right_io_coverage.input and right_io_coverage.output);
    var changed_final_io = expected_io;
    changed_final_io.output = &.{1};
    try std.testing.expectError(
        error.OutputDigestMismatch,
        io_binding.validateVerifiedCapture(ProofEngine, &right_capture, changed_final_io),
    );
    try io_binding.requireComplete(&.{ left_io_coverage, right_io_coverage });
    const right_verify_ns = right_verify_timer.read();

    std.debug.print(
        "\nV2_NATIVE_PROOF nonfinal cycles={d} proof_estimate={d} " ++
            "wire_bytes={d} prove_ms={d:.3} verify_capture_ms={d:.3}\n",
        .{
            left_result.cycle_count,
            left_proof_size,
            proof_bytes.items.len,
            milliseconds(left_prove_ns),
            milliseconds(left_verify_ns),
        },
    );
    printDigest("nonfinal_wire_id", left_capture.receipt.wire_id);
    printDigest("nonfinal_authority_id", left_capture.receipt.authority_id);
    printDigest(
        "nonfinal_relation_context_id",
        left_capture.native_public_sums.relation_context_id,
    );
    printDigest("nonfinal_native_sums_id", left_capture.native_public_sums.identity);
    std.debug.print(
        "V2_NATIVE_PROOF final cycles={d} proof_estimate={d} " ++
            "prove_ms={d:.3} verify_ms={d:.3}\n",
        .{
            right_result.cycle_count,
            right_proof_size,
            milliseconds(right_prove_ns),
            milliseconds(right_verify_ns),
        },
    );
    printDigest("final_wire_id", right_public.wireId());
    printDigest("final_authority_id", right_output.statement.authority_id);
}

test "native V2 proves a rebased leaf-local V3 segment without widening the AIR" {
    const allocator = std.testing.allocator;
    const elf = frontend.testing.guest_precompile_test_elf.build(
        false,
        .self_loop,
    );
    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_profile = try session.startSegment(1);
    defer left_profile.deinit();
    var right_profile = try session.resumeSegment(
        left_profile.base.continuation.?,
        16,
    );
    defer right_profile.deinit();
    const left_result = &left_profile.base;
    const right_result = &right_profile.base;

    const right_global = try @import("recursive_segment_v3_native_test_fixture.zig").rightGlobal(
        allocator,
        left_result,
        right_result,
    );
    var projection = try projection_v3.ProjectionV3.init(&right_global);
    const local_source = try projection.sourceV2(
        &right_global,
        digest("native-local-v3-session"),
    );
    const words = try encode(allocator, &local_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );
    const global_metadata = try right_global.metadata();
    const local_metadata = try public_data.metadata();
    try std.testing.expect(global_metadata.global_cycle_start > 0);
    try std.testing.expectEqual(@as(u32, 0), local_metadata.global_cycle_start);
    try std.testing.expectEqual(
        global_metadata.local_cycle_count,
        local_metadata.global_cycle_end,
    );

    var output = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        &projection.local_result,
        null,
        public_data,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);
    try output.statement.validateSegmentResult(&projection.local_result);
    try std.testing.expectError(
        error.ClockFrameMismatch,
        output.statement.validateSegmentResult(right_result),
    );
    var capture: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.proof,
        output.interaction_claim,
        &verify_channel,
        &capture,
    );
    defer capture.deinit(allocator);
    try capture.validate();
    const link = try verified_link_v3.VerifiedLinkV3.fromVerifiedCapture(
        Engine,
        &global_metadata,
        &capture,
    );
    try link.validateAgainst(
        &global_metadata,
        &capture.public_data.data,
        &capture.receipt,
    );
    var forged_link = link;
    forged_link.global_cycle_start += 1;
    try std.testing.expectError(
        error.InvalidVerifiedLink,
        forged_link.validateAgainst(
            &global_metadata,
            &capture.public_data.data,
            &capture.receipt,
        ),
    );
    // Reuse the same immutable cold-wire admission in the real global link.
    // Unleased public values keep their full authentication behavior.
    const Public = frontend.air.public_data_v2.PublicDataV2;
    const owned_words = try allocator.dupe(M31, capture.public_data.data.words());
    var counters = Public.ValidationCountersV2{};
    var lease = Public.OwnedValidatedLeaseV2.adoptCold(allocator, owned_words, &counters) catch |err| {
        allocator.free(owned_words);
        return err;
    };
    defer lease.deinit();
    const leased_link = try verified_link_v3.VerifiedLinkV3.fromVerifiedCapture(Engine, &global_metadata, &capture);
    try std.testing.expectEqualDeep(link, leased_link);
    const before = counters.snapshot();
    for (0..8) |_| try leased_link.validateAgainst(&global_metadata, lease.data(), &capture.receipt);
    const after = counters.snapshot();
    // Each link validation checks local data, receipt metadata and the actual
    // projected view through the existing owner. A raw-wire bypass loses the
    // third reuse and repeats sparse root authentication instead.
    try std.testing.expectEqual(before.cached_view_reuses + 24, after.cached_view_reuses);
    try std.testing.expectEqual(@as(u64, 1), after.legacy_full_authentications);
    var substituted = lease.data().*;
    substituted.canonical_words = capture.public_data.data.words();
    try std.testing.expectError(error.SourceMutation, leased_link.validateAgainst(&global_metadata, &substituted, &capture.receipt));
    substituted = lease.data().*;
    substituted.authenticated_wire_id[0] ^= 1;
    try std.testing.expectError(error.SourceMutation, leased_link.validateAgainst(&global_metadata, &substituted, &capture.receipt));
    try projection.validateAgainst(&right_global);

    // The reusable ingress must perform the same real prove, serialization,
    // producer destruction, fresh verification and global-position join.
    const PoseidonEngine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
    var admitted = try @import("recursive_segment_v3_native_ingress.zig").proveAndVerify(
        PoseidonEngine,
        allocator,
        &right_global,
        test_config,
        digest("native-local-v3-session"),
    );
    defer admitted.deinit();
    try admitted.validate();
    try std.testing.expect(admitted.proof_bytes.len != 0);
    try std.testing.expectEqualDeep(global_metadata, admitted.global_metadata);
    try std.testing.expectEqualDeep(link.global_metadata_id, admitted.link.global_metadata_id);
    var shifted = admitted.global_metadata;
    shifted.global_cycle_start += 1;
    try std.testing.expectError(
        error.GlobalPositionMismatch,
        admitted.link.validateAgainst(&shifted, &admitted.capture.public_data.data, &admitted.capture.receipt),
    );
    var wrong_entry = admitted.global_metadata;
    wrong_entry.entry.snapshot_id[0] ^= 1;
    try std.testing.expectError(
        error.LocalBoundaryMismatch,
        admitted.link.validateAgainst(&wrong_entry, &admitted.capture.public_data.data, &admitted.capture.receipt),
    );
    var wrong_exit = admitted.global_metadata;
    wrong_exit.exit.snapshot_id[0] ^= 1;
    try std.testing.expectError(
        error.LocalBoundaryMismatch,
        admitted.link.validateAgainst(&wrong_exit, &admitted.capture.public_data.data, &admitted.capture.receipt),
    );
    var wrong_clocks = admitted.global_metadata;
    wrong_clocks.exit.memory_clock_id[0] ^= 1;
    try std.testing.expectError(
        error.LocalBoundaryMismatch,
        admitted.link.validateAgainst(&wrong_clocks, &admitted.capture.public_data.data, &admitted.capture.receipt),
    );

    // The real native capture can feed the existing 39-component V2 outer
    // transaction. The resulting stage is deliberately not a V3 root.
    const recursion = frontend.recursion;
    var profile = try recursion.captured_fri.Owned.init(
        allocator,
        recursion.captured_fri.ProfileConfig.fromPcs(test_config),
        &admitted.capture.proof,
    );
    defer profile.deinit();
    var tree_heights: [recursion.fixed_profile.TREE_COUNT]u32 = undefined;
    @memcpy(&tree_heights, profile.trace_tree_heights);
    const shape = try recursion.transcript_shape.derive(
        profile.circuit.profile(),
        tree_heights,
        .{
            .sampled_value_count = profile.sampled_value_count,
            .queried_values_per_query = profile.queried_values_per_query,
            .claimed_sum_count = profile.claimed_sum_count,
            .interaction_pow_bits = profile.interaction_pow_bits,
            .pcs_pow_bits = profile.pcs_pow_bits,
        },
    );
    const schedule = recursion.air.verifier_schedule;
    var vm_plan = try schedule.Plan.initShape(allocator, try schedule.vmProgramSpec(0, 0), shape);
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(allocator, schedule.RECURSION_PROGRAM_SPEC_V1, shape);
    defer recursion_plan.deinit();
    const keys = try recursion.segment_leaf_authority_v2.VerifierKeyAuthorityV2.init(
        digest("recursive-v3-local-segment-vk"),
        digest("recursive-v3-local-parent-vk"),
    );
    const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
    var prepared = try leaf_outer.PreparedNativeV2LeafOuter.init(
        allocator,
        allocator,
        &admitted.capture,
        test_config,
        admitted.interaction_pow,
        keys,
        recursion.air.universal_challenges.UniversalRelations.dummy(),
        .{ .vm = &vm_plan, .recursion = &recursion_plan },
    );
    admitted.capture_owned = false;
    defer prepared.deinit();
    const outer_stage = @import("recursive_segment_v3_outer_stage.zig");
    var stage = try outer_stage.proveAndVerifyPrepared(
        allocator,
        &prepared,
        &admitted.global_metadata,
        &admitted.link,
        .{ .worker_count = 1 },
    );
    defer stage.deinit(allocator);
    try stage.manifest.validateAgainst(
        &admitted.global_metadata,
        &admitted.link,
        &prepared.capture.public_data.data,
        &prepared.capture.receipt,
        &stage.publication,
    );
    try std.testing.expectError(error.V3WrapperProofUnavailable, stage.requireRecursiveV3Publication());
    var forged_manifest = stage.manifest;
    forged_manifest.outer_publication_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidV3StageManifest,
        forged_manifest.validateAgainst(
            &admitted.global_metadata,
            &admitted.link,
            &prepared.capture.public_data.data,
            &prepared.capture.receipt,
            &stage.publication,
        ),
    );

    // The two field preimages now come from the separately verified native
    // child and 39-row outer proof, then enter pinned typed-adapter geometry.
    // Their AIR/LogUp rows still need one new V3 STARK transaction.
    const outer_cohort = @import("recursive_segment_v2_outer_cohort.zig");
    var cohort = try outer_cohort.Cohort.init(allocator, &prepared);
    defer cohort.deinit();
    var fields = try recursion.segment_leaf_wrapper_field_witness_v3.BundleV3.init(
        allocator,
        &prepared,
        &stage.capture,
        &stage.publication,
        &stage.recursive_witness,
        cohort.manifest(),
    );
    defer fields.deinit();
    const field_manifest = try recursion.air.segment_leaf_wrapper_field_manifest_v3.Manifest.build(
        allocator,
        &fields.native,
        &fields.provider,
    );
    try field_manifest.validateAgainst(allocator, &fields.native, &fields.provider);
    try std.testing.expectEqualDeep(fields.native.program.digest, field_manifest.program_input.digest);
    try std.testing.expectEqualDeep(fields.provider.authority.digest, field_manifest.provider_input.digest);
    try std.testing.expectError(error.V3WrapperProofUnavailable, field_manifest.requireCompleteWrapperProof());

    // A separate versioned outer transaction proves the same genuine leaf
    // cohort under q193/PCS-PoW16/fold4 and verifies its 10-bit interaction
    // nonce before reconstructing relation challenges. Its artifact is not a
    // legacy V2 publication and cannot yet stand in for the 49-row wrapper.
    const strong_outer = recursion.segment_outer_transaction_v3.ForBackend(CpuBackend);
    const StrongKernel = strong_outer.EngineKernel(outer_cohort.Cohort);
    var strong = try StrongKernel.proveAndVerify(allocator, &prepared);
    defer strong.deinit(allocator);
    try strong.receipt.validate();
    try strong.artifact.validateEncoding();
    try std.testing.expect(strong.artifact.proof_bytes.len != 0);
    try std.testing.expect(strong.receipt.producer_peak_bytes > 0);
    var wrong_query = strong.artifact;
    wrong_query.query_count = 3;
    var rejected_capture: strong_outer.Capture = undefined;
    try std.testing.expectError(
        error.InvalidV3OuterArtifact,
        StrongKernel.verifyArtifact(allocator, &prepared, &wrong_query, &rejected_capture),
    );
    var wrong_profile = strong.artifact;
    wrong_profile.profile_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidV3OuterProfile,
        StrongKernel.verifyArtifact(allocator, &prepared, &wrong_profile, &rejected_capture),
    );
    var wrong_nonce = strong.artifact;
    var rejected = false;
    for (0..64) |_| {
        wrong_nonce.interaction_pow_nonce +%= 1;
        StrongKernel.verifyArtifact(allocator, &prepared, &wrong_nonce, &rejected_capture) catch |err| {
            if (err == error.InvalidV3OuterInteractionPow) {
                rejected = true;
                break;
            }
            continue;
        };
        rejected_capture.deinit(allocator);
    }
    try std.testing.expect(rejected);
}

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    if (result.global_first_cycle == 0) return error.InvalidGlobalCycle;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            input,
            output,
        ),
    );
}

fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4e56_3250); // "NV2P"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn printDigest(label: []const u8, value: channel.Digest) void {
    std.debug.print("  {s}=", .{label});
    for (value) |word| std.debug.print("{x:0>8}", .{word});
    std.debug.print("\n", .{});
}
