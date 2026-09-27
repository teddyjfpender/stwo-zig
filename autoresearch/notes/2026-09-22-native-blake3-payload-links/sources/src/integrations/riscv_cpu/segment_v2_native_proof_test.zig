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
fn nativeSegments(comptime ProofEngine: type, comptime suite_name: []const u8) !void {
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

    const public_input = digest("native-v2-input");
    const public_output = digest("native-v2-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        digest("native-v2-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        digest("native-v2-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        digest("native-v2-io-exit"),
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
        var prepared = try adapter.prepare(ProofEngine, allocator, &left_output.statement, left_output.interaction_claim, &left_capture, test_config, 3);
        defer prepared.deinit();
        try std.testing.expectEqualSlices(u8, &left_channel.digestBytes(), &prepared.end.digestBytes());
        try std.testing.expectEqual(left_channel.n_draws, prepared.end.n_draws);
        try std.testing.expect(prepared.claim_payloads.len > 0);
        var pairs: usize = 0;
        for (prepared.live.draw_outputs) |output| if (output.role == .riscv_relation) {
            pairs += 1;
        };
        try std.testing.expectEqual(frontend.air.relation_challenges.DRAW_COUNT / 2, pairs);
        var composition = try frontend.recursion.vm_air_composition_prepared_v2.prepare(allocator, &left_capture, test_config);
        defer composition.deinit();
        const native_links = frontend.recursion.air.blake3_native_challenge_links;
        const links = try native_links.prepare(allocator, &composition, prepared.live.draw_outputs, 1500);
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
        var payloads = try payload_links.prepare(allocator, &composition, &prepared, 1500);
        defer payloads.deinit();
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
            try std.testing.expectError(error.InvalidNativePayloadLink, payload_links.prepare(allocator, &composition, &prepared, 1500));
        }
        var changed_payload_checked = false;
        for (prepared.operations) |*op| {
            if (op.* != .routed_felts or !std.meta.eql(op.routed_felts.source, prepared.claim_payloads[0].source)) continue;
            const saved = op.routed_felts.values;
            defer op.routed_felts.values = saved;
            const changed = [_]stwo_core.fields.qm31.QM31{saved[0].add(stwo_core.fields.qm31.QM31.one())};
            op.routed_felts.values = &changed;
            try std.testing.expectError(error.InvalidNativePayloadLink, payload_links.prepare(allocator, &composition, &prepared, 1500));
            changed_payload_checked = true;
            break;
        }
        try std.testing.expect(changed_payload_checked);
        std.debug.print("V2_BLAKE3_NATIVE_PAYLOADS secure_values={d} scalar_routes={d}\n", .{ payloads.encoded.len, payloads.scalars.len });
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
    try prover.verifyRiscVSegmentV2WithEngine(
        ProofEngine,
        allocator,
        test_config,
        right_output.statement,
        right_output.proof,
        right_output.interaction_claim,
    );
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

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        right_result.execution_trace.rows.items,
        right_result.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
    const public_input = digest("native-local-v3-input");
    const public_output = digest("native-local-v3-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .initial_word).id,
        digest("native-local-v3-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotIdentity(left_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotIdentity(right_result.rw_memory.words, .final_word).id,
        digest("native-local-v3-io-exit"),
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
    const right_global_statement = try leafStatement(
        job,
        right_result,
        shared_state,
        final_state,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(public_output),
    );
    const right_global = try global_v3.SourceV3.fromSegmentResult(
        right_global_statement,
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
    const link = try verified_link_v3.VerifiedLinkV3.init(
        &global_metadata,
        &capture.public_data.data,
        &capture.receipt,
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
    const leased_link = try verified_link_v3.VerifiedLinkV3.init(&global_metadata, lease.data(), &capture.receipt);
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
