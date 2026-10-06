//! Real-proof acceptance for the authenticated degree-aware lookup protocol.
//!
//! This gate holds execution and public statement constant, proves both the
//! compatibility and selected physical layouts, independently verifies each,
//! and requires reciprocal cross-protocol rejection. Timings are attribution
//! evidence from one deliberately tiny proof, not a throughput claim.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const test_backend = @import("lookup_v2_test_backend");

const M31 = stwo_core.fields.m31.M31;
const pcs_core = stwo_core.pcs;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const span = frontend.recursion.span_statement;
const physical = frontend.air.lookup_physical_manifest_v2;
const Engine = test_backend.Engine;

/// Development-security profile: one query and no proof of work make this a
/// fast protocol/geometry gate, never production security evidence.
const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 1,
    },
};

test "authenticated lookup V2 proves, independently verifies, and rejects compatibility replay" {
    const allocator = std.testing.allocator;
    try test_backend.initialize(allocator);
    defer test_backend.shutdown();
    const elf = frontend.testing.guest_precompile_test_elf.buildAllFamilies();

    var session = try runner.Poseidon2ExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var execution_profile = try session.startSegment(64);
    defer execution_profile.deinit();
    const execution = &execution_profile.base;
    try std.testing.expect(execution.continuation == null);

    var program = try frontend.air.program.commitment.buildDeclared(
        allocator,
        execution.execution_trace.rows.items,
        execution.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const public_input = digest("lookup-v2-input");
    const public_output = digest("lookup-v2-output");
    const initial_state = try machineState(
        execution.entry_cpu,
        digest("lookup-v2-rw-entry"),
        digest("lookup-v2-io-entry"),
    );
    const final_state = try machineState(
        execution.exit_cpu,
        digest("lookup-v2-rw-exit"),
        digest("lookup-v2-io-exit"),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial_state,
            final_state,
            public_input,
            public_output,
            @intCast(execution.cycle_count),
        ),
        1,
    );
    const execution_span = try leafStatement(
        job,
        execution,
        initial_state,
        final_state,
        try span.EdgeClaim.present(public_input),
        try span.EdgeClaim.present(public_output),
    );
    const source = try segment_v2.SourceV2.fromSegmentResult(
        digest("lookup-v2-session"),
        execution_span,
        execution,
    );
    const words = try encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    const manifest = physical.Manifest.native();
    try manifest.validate();
    try manifest.auditAgainstCompiler(allocator);
    const preflight = try prover.inspectRiscVSegmentLookupV2FullCohort(
        allocator,
        execution,
        public_data,
    );
    const preflight_activation = preflight.activation;
    try std.testing.expectEqual(@as(u32, 17), preflight_activation.component_count);
    try std.testing.expectEqual(@as(u32, 644), preflight_activation.opcode_main_columns);
    try std.testing.expectEqual(@as(u32, 548), preflight_activation.opcode_interaction_columns);
    try std.testing.expectEqual(@as(u32, 137), preflight_activation.detailed_claim_count);
    try std.testing.expectEqual(
        @as(u32, 620),
        preflight.compatibility_opcode_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 68),
        preflight.infrastructure_interaction_columns,
    );
    try std.testing.expectEqual(
        preflight.compatibility_opcode_interaction_columns +
            preflight.infrastructure_interaction_columns,
        preflight.compatibility_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(usize, preflight_activation.opcode_interaction_columns) +
            @as(usize, preflight.infrastructure_interaction_columns),
        preflight.selected_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(usize, 72),
        @as(usize, preflight.compatibility_interaction_columns) -
            preflight.selected_interaction_columns,
    );

    var compatibility_prove_timer = try std.time.Timer.start();
    var compatibility = try prover.proveRiscVSegmentLookupV1CompatibilityWithEngine(
        Engine,
        allocator,
        test_config,
        execution,
        null,
        public_data,
    );
    const compatibility_prove_ns = compatibility_prove_timer.read();
    var compatibility_proof_moved = false;
    defer if (compatibility_proof_moved)
        compatibility.deinitAfterProofMoved(allocator)
    else
        compatibility.deinit(allocator);

    var selected_prove_timer = try std.time.Timer.start();
    var selected = try prover.proveRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        execution,
        null,
        public_data,
    );
    const selected_prove_ns = selected_prove_timer.read();
    var selected_proof_moved = false;
    defer if (selected_proof_moved)
        selected.deinitAfterProofMoved(allocator)
    else
        selected.deinit(allocator);

    try compatibility.statement.validateSegmentResult(execution);
    try selected.statement.validateSegmentResult(execution);
    try std.testing.expectEqualDeep(
        compatibility.statement.authority_id,
        selected.statement.authority_id,
    );
    const activation = try physical.AuthenticatedStatement.init(
        &selected.statement.core,
        &manifest,
    );
    try activation.validateAgainst(&selected.statement.core, &manifest);
    try std.testing.expectEqualDeep(preflight_activation, activation);
    try std.testing.expectEqual(@as(u32, 17), activation.component_count);
    try std.testing.expectEqual(@as(u32, 644), activation.opcode_main_columns);
    try std.testing.expectEqual(@as(u32, 548), activation.opcode_interaction_columns);
    try std.testing.expectEqual(@as(u32, 137), activation.detailed_claim_count);
    const compatibility_columns = selected.statement.core.nInteractionColumns();
    const selected_columns = try activation.totalInteractionColumns(
        &selected.statement.core,
        &manifest,
    );
    try std.testing.expectEqual(
        preflight.compatibility_interaction_columns,
        compatibility_columns,
    );
    try std.testing.expectEqual(preflight.selected_interaction_columns, selected_columns);

    var compatibility_bytes: std.ArrayList(u8) = .empty;
    defer compatibility_bytes.deinit(allocator);
    try postcard.serializeProof(
        prover.Hasher,
        compatibility_bytes.writer(allocator),
        compatibility.proof,
    );
    var selected_bytes: std.ArrayList(u8) = .empty;
    defer selected_bytes.deinit(allocator);
    try postcard.serializeProof(
        prover.Hasher,
        selected_bytes.writer(allocator),
        selected.proof,
    );

    // Both directions must fail. This pins the activation tag and physical
    // Tree-2 shape as protocol identity, rather than treating V2 as a local
    // prover optimization that a compatibility verifier might accept.
    var selected_stream = std.io.fixedBufferStream(selected_bytes.items);
    const selected_as_compatibility = try postcard.deserializeProof(
        prover.Hasher,
        allocator,
        selected_stream.reader(),
    );
    try std.testing.expectEqual(selected_bytes.items.len, selected_stream.pos);
    if (prover.verifyRiscVSegmentLookupV1CompatibilityWithEngine(
        Engine,
        allocator,
        test_config,
        selected.statement,
        selected_as_compatibility,
        selected.interaction_claim,
    )) |_| {
        return error.ExpectedCrossProtocolRejection;
    } else |_| {}

    var compatibility_stream = std.io.fixedBufferStream(
        compatibility_bytes.items,
    );
    const compatibility_as_selected = try postcard.deserializeProof(
        prover.Hasher,
        allocator,
        compatibility_stream.reader(),
    );
    try std.testing.expectEqual(
        compatibility_bytes.items.len,
        compatibility_stream.pos,
    );
    if (prover.verifyRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        compatibility.statement,
        compatibility_as_selected,
        compatibility.interaction_claim,
    )) |_| {
        return error.ExpectedCrossProtocolRejection;
    } else |_| {}

    compatibility_proof_moved = true;
    var compatibility_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentLookupV1CompatibilityWithEngine(
        Engine,
        allocator,
        test_config,
        compatibility.statement,
        compatibility.proof,
        compatibility.interaction_claim,
    );
    const compatibility_verify_ns = compatibility_verify_timer.read();

    selected_proof_moved = true;
    var selected_verify_timer = try std.time.Timer.start();
    try prover.verifyRiscVSegmentV2WithEngine(
        Engine,
        allocator,
        test_config,
        selected.statement,
        selected.proof,
        selected.interaction_claim,
    );
    const selected_verify_ns = selected_verify_timer.read();

    std.debug.print(
        "\nA014_LOOKUP_V2_PROOF cycles={d} compatibility_columns={d} " ++
            "selected_columns={d} saved_columns={d} compatibility_bytes={d} " ++
            "selected_bytes={d} compatibility_prove_ms={d:.3} " ++
            "selected_prove_ms={d:.3} compatibility_verify_ms={d:.3} " ++
            "selected_verify_ms={d:.3}\n",
        .{
            execution.cycle_count,
            compatibility_columns,
            selected_columns,
            @as(usize, compatibility_columns) - selected_columns,
            compatibility_bytes.items.len,
            selected_bytes.items.len,
            milliseconds(compatibility_prove_ns),
            milliseconds(selected_prove_ns),
            milliseconds(compatibility_verify_ns),
            milliseconds(selected_verify_ns),
        },
    );
    printDigest("manifest_identity", manifest.identity);
    printDigest("statement_identity", activation.statement_identity);
    printDigest("activation_identity", activation.activation_identity);
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
    return channel.hashBytes(label, 0x4c56_3250); // "LV2P"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn printDigest(label: []const u8, value: [32]u8) void {
    std.debug.print("  {s}=", .{label});
    for (value) |word| std.debug.print("{x:0>2}", .{word});
    std.debug.print("\n", .{});
}
