//! A-013 production exit for generated RISC-V composition.
//!
//! The reference arm deliberately declines only the optional backend
//! composition capability. Every commitment, Fiat--Shamir draw, FRI fold,
//! opening, and verifier remains the ordinary CPU implementation. The
//! generated arm is the production CPU path, which admits adjacent semantic
//! and lookup programs exported from the frontend's canonical typed builder.
//!
//! Exact proof bytes and terminal transcript state are normative equivalence
//! evidence. The two elapsed times are one-process attribution diagnostics,
//! not benchmark results.

const std = @import("std");
const stwo_core = @import("stwo_core");
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
const span = frontend.recursion.span_statement;

/// Exact CPU reference backend with only the optional composition accelerator
/// disabled. Every declaration below is a direct alias, so there is no second
/// implementation whose behavior could drift from `CpuBackend`.
const ReferenceCpuBackend = struct {
    pub const capabilities = CpuBackend.capabilities;
    pub const combined_commit_min_columns =
        CpuBackend.combined_commit_min_columns;
    pub const combined_commit_max_columns =
        CpuBackend.combined_commit_max_columns;
    pub const combined_base_in_place = CpuBackend.combined_base_in_place;
    pub const reuses_constant_merkle_parents =
        CpuBackend.reuses_constant_merkle_parents;
    pub const lazy_merkle_reuses_constant_parents =
        CpuBackend.lazy_merkle_reuses_constant_parents;
    pub const combinedCircleLdeSkippedForwardLayers =
        CpuBackend.combinedCircleLdeSkippedForwardLayers;
    pub const warmup = CpuBackend.warmup;
    pub const riscvCompositionTelemetrySnapshot =
        CpuBackend.riscvCompositionTelemetrySnapshot;
    pub const interpolateSecureComposition =
        CpuBackend.interpolateSecureComposition;
    pub const ColumnType = CpuBackend.ColumnType;
    pub const batchInverse = CpuBackend.batchInverse;
    pub const interpolateAndEvaluateCircleBuffers =
        CpuBackend.interpolateAndEvaluateCircleBuffers;
    pub const foldCircleIntoLine = CpuBackend.foldCircleIntoLine;
    pub const foldLine = CpuBackend.foldLine;
    pub const foldLineN = CpuBackend.foldLineN;
    pub const MerkleTree = CpuBackend.MerkleTree;
    pub const commitMerkle = CpuBackend.commitMerkle;
    pub const commitLazyMerkle = CpuBackend.commitLazyMerkle;
};

comptime {
    // A new CPU backend operation must be inherited deliberately. This keeps
    // the reference arm exact as the production backend evolves instead of
    // silently falling onto a second generic implementation.
    for (@typeInfo(CpuBackend).@"struct".decls) |declaration| {
        if (std.mem.eql(
            u8,
            declaration.name,
            "computeCompositionEvaluation",
        ) or std.mem.eql(
            u8,
            declaration.name,
            "computeCompositionEvaluationWithExecution",
        )) continue;
        if (!@hasDecl(ReferenceCpuBackend, declaration.name)) {
            @compileError(std.fmt.comptimePrint(
                "A-013 reference backend is missing CpuBackend declaration '{s}'",
                .{declaration.name},
            ));
        }
    }
    if (@hasDecl(ReferenceCpuBackend, "computeCompositionEvaluation") or
        @hasDecl(ReferenceCpuBackend, "computeCompositionEvaluationWithExecution"))
    {
        @compileError("A-013 reference backend must decline composition");
    }
}

const ReferenceEngine = prover.ProverEngineForBackend(ReferenceCpuBackend);
const GeneratedEngine = prover.ProverEngineForBackend(CpuBackend);

/// Development-security profile: this is a protocol-equivalence gate, not a
/// production-security or throughput measurement.
const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 1,
        .fold_step = 1,
    },
};

test "A-013 generated full-cohort composition is proof-byte and transcript exact" {
    const allocator = std.testing.allocator;
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

    const public_input = digest("a013-generated-input");
    const public_output = digest("a013-generated-output");
    const initial_state = try machineState(
        execution.entry_cpu,
        digest("a013-generated-rw-entry"),
        digest("a013-generated-io-entry"),
    );
    const final_state = try machineState(
        execution.exit_cpu,
        digest("a013-generated-rw-exit"),
        digest("a013-generated-io-exit"),
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
        digest("a013-generated-session"),
        execution_span,
        execution,
    );
    const words = try encode(allocator, &source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    const execution_options = prover.ExecutionOptionsV2{
        .cpu = .{
            .worker_count = 1,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        },
    };

    var reference_channel = ReferenceEngine.Channel{};
    var reference_timer = try std.time.Timer.start();
    var reference = try prover.proveRiscVSegmentV2WithEngineUsingChannelAndExecution(
        ReferenceEngine,
        allocator,
        test_config,
        execution,
        null,
        public_data,
        &reference_channel,
        execution_options,
    );
    const reference_ns = reference_timer.read();
    var reference_proof_moved = false;
    defer if (reference_proof_moved)
        reference.deinitAfterProofMoved(allocator)
    else
        reference.deinit(allocator);

    const telemetry_before = CpuBackend.riscvCompositionTelemetrySnapshot();
    var generated_channel = GeneratedEngine.Channel{};
    var generated_timer = try std.time.Timer.start();
    var generated = try prover.proveRiscVSegmentV2WithEngineUsingChannelAndExecution(
        GeneratedEngine,
        allocator,
        test_config,
        execution,
        null,
        public_data,
        &generated_channel,
        execution_options,
    );
    const generated_ns = generated_timer.read();
    const telemetry = CpuBackend.riscvCompositionTelemetrySnapshot().delta(
        telemetry_before,
    );
    var generated_proof_moved = false;
    defer if (generated_proof_moved)
        generated.deinitAfterProofMoved(allocator)
    else
        generated.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 1), telemetry.admissions);
    try std.testing.expectEqual(@as(u64, 17), telemetry.eligible_pairs);
    try std.testing.expectEqual(@as(u64, 0), telemetry.declines);
    try std.testing.expectEqual(@as(u32, 17), reference.statement.core.n_components);
    try std.testing.expectEqual(
        @as(u32, 688),
        reference.statement.core.nInteractionColumns(),
    );
    try std.testing.expectEqualDeep(reference.statement, generated.statement);
    try std.testing.expectEqualDeep(
        reference.interaction_claim.*,
        generated.interaction_claim.*,
    );
    try std.testing.expectEqualSlices(
        u8,
        &reference_channel.digestBytes(),
        &generated_channel.digestBytes(),
    );

    var reference_bytes: std.ArrayList(u8) = .empty;
    defer reference_bytes.deinit(allocator);
    try postcard.serializeProof(
        prover.Hasher,
        reference_bytes.writer(allocator),
        reference.proof,
    );
    var generated_bytes: std.ArrayList(u8) = .empty;
    defer generated_bytes.deinit(allocator);
    try postcard.serializeProof(
        prover.Hasher,
        generated_bytes.writer(allocator),
        generated.proof,
    );
    try std.testing.expectEqualSlices(
        u8,
        reference_bytes.items,
        generated_bytes.items,
    );

    // Verification is deliberately performed by the ordinary production
    // engine. Neither proof can rely on the reference arm's backend wrapper.
    reference_proof_moved = true;
    var reference_verify_channel = GeneratedEngine.Channel{};
    try prover.verifyRiscVSegmentV2WithEngineUsingChannel(
        GeneratedEngine,
        allocator,
        test_config,
        reference.statement,
        reference.proof,
        reference.interaction_claim,
        &reference_verify_channel,
    );
    generated_proof_moved = true;
    var generated_verify_channel = GeneratedEngine.Channel{};
    try prover.verifyRiscVSegmentV2WithEngineUsingChannel(
        GeneratedEngine,
        allocator,
        test_config,
        generated.statement,
        generated.proof,
        generated.interaction_claim,
        &generated_verify_channel,
    );
    try std.testing.expectEqualSlices(
        u8,
        &reference_channel.digestBytes(),
        &reference_verify_channel.digestBytes(),
    );
    try std.testing.expectEqualSlices(
        u8,
        &generated_channel.digestBytes(),
        &generated_verify_channel.digestBytes(),
    );

    var proof_digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(generated_bytes.items, &proof_digest, .{});
    std.debug.print(
        "\nA013_GENERATED_COMPOSITION cycles={d} families={d} " ++
            "interaction_columns={d} proof_bytes={d} eligible_pairs={d} " ++
            "fallback_components={d} reference_prove_ms={d:.3} " ++
            "generated_prove_ms={d:.3}\n",
        .{
            execution.cycle_count,
            reference.statement.core.n_components,
            reference.statement.core.nInteractionColumns(),
            generated_bytes.items.len,
            telemetry.eligible_pairs,
            telemetry.fallback_components,
            milliseconds(reference_ns),
            milliseconds(generated_ns),
        },
    );
    printDigest("proof_sha256", proof_digest);
    printDigest("transcript_digest", generated_channel.digestBytes());
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
    return channel.hashBytes(label, 0x4130_3133); // "A013"
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
