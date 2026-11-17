//! Native CPU proof evidence for authenticated resumable V2 segments.

const std = @import("std");
const milliseconds = @import("segment_native_proof_receipts.zig").milliseconds;
const printDigest = @import("segment_native_proof_receipts.zig").printDigest;
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

const support = @import("segment_native_proof_support.zig");
const test_config = support.test_config;
const leafStatement = support.leafStatement;
const machineState = support.machineState;
const encode = support.encode;
const digest = support.digest;
const scalarDigest = support.scalarDigest;

test "native V2 proves and independently verifies real nonfinal and final segments" {
    try nativeSegments(Engine, "blake2s-default");
}
test "BLAKE3 V2 segment proofs verify nonfinal capture and final completion" {
    try nativeSegments(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1");
}
test "native BLAKE3 arithmetic fusion census" {
    try nativeSegmentsMode(frontend.recursion.engine.Blake3ProverEngineForBackend(CpuBackend), "blake3.experimental.v1", true);
}
const nativeSegmentsMode = @import("segment_native_proof_cases.zig").nativeSegmentsMode;

fn nativeSegments(comptime ProofEngine: type, comptime suite_name: []const u8) !void {
    return nativeSegmentsMode(ProofEngine, suite_name, false);
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
