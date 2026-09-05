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
    const allocator = std.testing.allocator;
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
        digest("native-v2-rw-entry"),
        digest("native-v2-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        digest("native-v2-rw-shared"),
        digest("native-v2-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        digest("native-v2-rw-exit"),
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
        Engine,
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
        prover.Hasher,
        proof_bytes.writer(allocator),
        left_output.proof,
    );
    var proof_stream = std.io.fixedBufferStream(proof_bytes.items);
    var mutated_proof = try postcard.deserializeProof(
        prover.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var mutated_proof_moved = false;
    defer if (!mutated_proof_moved) mutated_proof.deinit(allocator);
    try std.testing.expectEqual(proof_bytes.items.len, proof_stream.pos);

    var bad_version = left_output.statement;
    bad_version.format_version +%= 1;
    var capture_sentinel: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    @memset(std.mem.asBytes(&capture_sentinel), 0xa5);
    var before: [@sizeOf(@TypeOf(capture_sentinel))]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&capture_sentinel));
    var rejected_channel = Engine.Channel{};
    mutated_proof_moved = true;
    try std.testing.expectError(
        error.InvalidStatement,
        prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
            Engine,
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

    var left_capture: prover.VerifiedSegmentV2CaptureForEngine(Engine) = undefined;
    var left_channel = Engine.Channel{};
    left_proof_moved = true;
    var left_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngineUsingChannelAndCapture(
        Engine,
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
        Engine,
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
    const right_metadata = try right_output.statement.metadata();
    try std.testing.expect(right_metadata.is_final);
    try std.testing.expect(right_metadata.completion != null);
    right_proof_moved = true;
    var right_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngine(
        Engine,
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
        digest("native-local-v3-rw-entry"),
        digest("native-local-v3-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        digest("native-local-v3-rw-shared"),
        digest("native-local-v3-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        digest("native-local-v3-rw-exit"),
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
