//! Joined base + Keccak-f + successful signer-recovery CPU proof gate.

const std = @import("std");
const stwo_core = @import("stwo_core");
const pcs_core = @import("stwo_core").pcs;
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");

const prover = frontend.prover_mod;
const public_data_mod = frontend.air.public_data;
const M31 = stwo_core.fields.m31.M31;
const channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const span = frontend.recursion.span_statement;
const Engine = prover.ProverEngineForBackend(CpuBackend);
const RecursiveEngine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const segment_artifact =
    prover.guest_precompile.ethereum_segment_proof_artifact;
const poseidon_segment_artifact =
    prover.guest_precompile.ethereum_segment_poseidon2_proof_artifact;
const proof_security = @import("recursive_temporal_proof_security_v1.zig");
const segment_admission_test = @import(
    "ethereum_segment_v2_admission_test_support.zig",
);
const segment_transcript_extension_test = @import(
    "ethereum_segment_transcript_extension_test.zig",
);

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

test "Ethereum base Keccak and signer recovery prove and independently verify on CPU" {
    const allocator = std.testing.allocator;
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
    const completion_offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
        return error.MissingCompletionInstruction;
    std.mem.writeInt(u32, elf[completion_offset..][0..4], 0x0000_006f, .little);
    try proveAndVerify(allocator, &elf, 1, 1, 8, true);
}

test "Ethereum zero-family segment preserves fourteen slots and independently verifies" {
    const allocator = std.testing.allocator;
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    replaceInstruction(
        &elf,
        frontend.testing.guest_precompile_test_elf.ethereum_instructions[2],
        0x0000_0013,
    );
    replaceInstruction(
        &elf,
        frontend.testing.guest_precompile_test_elf.ethereum_instructions[4],
        0x0000_0013,
    );
    replaceInstruction(&elf, 0x0000_0073, 0x0000_006f);
    try proveAndVerify(allocator, &elf, 0, 0, 1, false);
}

test "Ethereum nonfinal SegmentV2 zero-extension leaf proves and verifies" {
    try proveSegmentV2(1, 0, 0);
}

test "Ethereum nonfinal SegmentV2 signer leaf proves and verifies" {
    try proveSegmentV2(3, 0, 1);
}

test "Ethereum SegmentV3 capture seals count-sensitive extension sidecars" {
    try proveSegmentV2(3, 0, 1);
}

test "Ethereum SegmentV2 extended transcript binds dynamic provider shard count" {
    try segment_transcript_extension_test.run();
}

test "Ethereum Poseidon2 SegmentV3 artifact verifies full dynamic capture" {
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
    const completion_offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
        return error.MissingCompletionInstruction;
    std.mem.writeInt(u32, elf[completion_offset..][0..4], 0x0000_006f, .little);
    try proveSegmentV2ElfWithSuite(&elf, 3, 0, 1, .recursive_poseidon2);
}

const SegmentArtifactSuite = enum { native_blake2s, recursive_poseidon2 };

fn proveSegmentV2(
    first_budget: usize,
    expected_keccak: usize,
    expected_signer: usize,
) !void {
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
    const completion_offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
        return error.MissingCompletionInstruction;
    std.mem.writeInt(u32, elf[completion_offset..][0..4], 0x0000_006f, .little);
    return proveSegmentV2Elf(
        &elf,
        first_budget,
        expected_keccak,
        expected_signer,
    );
}

fn proveSegmentV2Elf(
    elf: []const u8,
    first_budget: usize,
    expected_keccak: usize,
    expected_signer: usize,
) !void {
    return proveSegmentV2ElfWithSuite(
        elf,
        first_budget,
        expected_keccak,
        expected_signer,
        .native_blake2s,
    );
}

fn proveSegmentV2ElfWithSuite(
    elf: []const u8,
    first_budget: usize,
    expected_keccak: usize,
    expected_signer: usize,
    comptime suite: SegmentArtifactSuite,
) !void {
    const allocator = std.testing.allocator;
    const ProvingEngine = if (suite == .native_blake2s)
        Engine
    else
        RecursiveEngine;
    const config = if (suite == .native_blake2s)
        test_config
    else
        protocol.PCS_CONFIG;
    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer session.deinit();
    var first = try session.startSegment(first_budget);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 32);
    defer second.deinit();
    try std.testing.expect(!first.base.isComplete());
    try std.testing.expect(second.base.isComplete());
    try std.testing.expectEqual(expected_keccak, first.keccakf_calls.len());
    try std.testing.expectEqual(expected_signer, first.signer_recovery_calls.len());

    var program = try frontend.air.program.commitment
        .buildDeclaredForProfileSources(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            first.base.execution_trace.rows.items,
            first.keccakf_execution_rows.rows(),
            first.signer_recovery_execution_rows.rows(),
        },
        first.base.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);
    const input_digest = digest("ethereum-segment-input");
    const output_digest = digest("ethereum-segment-output");
    const initial = try machineState(
        first.base.entry_cpu,
        digest("ethereum-segment-rw-entry"),
        digest("ethereum-segment-io-entry"),
    );
    const shared = try machineState(
        first.base.exit_cpu,
        digest("ethereum-segment-rw-shared"),
        digest("ethereum-segment-io-shared"),
    );
    const final = try machineState(
        second.base.exit_cpu,
        digest("ethereum-segment-rw-exit"),
        digest("ethereum-segment-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(first.base.cycle_count),
        @intCast(second.base.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial,
            final,
            input_digest,
            output_digest,
            total_cycles,
        ),
        2,
    );
    const global_statement = try leafStatement(
        job,
        &first.base,
        initial,
        shared,
        try span.EdgeClaim.present(input_digest),
        span.EdgeClaim.absent(),
    );
    const global_source = try global_v3.SourceV3.fromSegmentResult(
        global_statement,
        &first.base,
    );
    const global_metadata = try global_source.metadata();
    var projection = try projection_v3.ProjectionV3.init(&global_source);
    const local_source = try projection.sourceV2(
        &global_source,
        digest("ethereum-segment-session"),
    );
    const words = try encodeSegment(allocator, &local_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    var output = try prover.proveEthereumSegmentWithEngine(
        ProvingEngine,
        allocator,
        config,
        &projection.local_result,
        &first.keccakf_calls,
        &first.keccakf_execution_rows,
        &first.signer_recovery_calls,
        &first.signer_recovery_execution_rows,
        null,
        public_data,
    );
    defer output.deinit(allocator);
    try output.statement.validateSegmentResult(&projection.local_result);
    try std.testing.expect(!(try output.statement.metadata()).is_final);
    try std.testing.expectEqual(@as(usize, 14), output.extension.components.len);
    try segment_admission_test.assertBoundaries(
        allocator,
        &output,
        &local_source,
        words,
    );

    if (suite == .native_blake2s) {
        const artifact = try segment_artifact.encodeAlloc(allocator, .{
            .pcs_config = config,
            .statement = &output.statement,
            .extension = &output.extension,
            .global = &global_metadata,
            .base_claim = output.base_claim,
            .extension_claim = &output.extension_claim,
            .proof = &output.proof,
        });
        defer allocator.free(artifact);
        try rejectMutatedSegmentIdentity(allocator, artifact);
        var decoded = try segment_artifact.decodeAllocForConfig(
            allocator,
            artifact,
            config,
            .{},
        );
        var proof_moved = false;
        defer if (proof_moved)
            decoded.deinitAfterProofMoved(allocator)
        else
            decoded.deinit(allocator);
        try verifySegmentArtifactCapture(
            ProvingEngine,
            allocator,
            config,
            &decoded,
            &global_metadata,
            &proof_moved,
        );
    } else {
        const security = proof_security.ProofSecurityV1
            .ethereumSegmentV3Poseidon2();
        try security.validate();
        const preflight_shape = try poseidon_segment_artifact.proofPreflightShape(
            allocator,
            &output.statement,
            &output.extension,
            .{},
        );
        try std.testing.expectEqual(
            @TypeOf(preflight_shape.hash_encoding).canonical_m31_words,
            preflight_shape.hash_encoding,
        );
        const artifact = try poseidon_segment_artifact.encodeAlloc(allocator, .{
            .security_identity_sha256 = security.identity,
            .statement = &output.statement,
            .extension = &output.extension,
            .global = &global_metadata,
            .base_claim = output.base_claim,
            .extension_claim = &output.extension_claim,
            .proof = &output.proof,
        });
        defer allocator.free(artifact);
        try rejectNonCanonicalPoseidonClockFrame(
            allocator,
            artifact,
            security.identity,
        );
        try rejectMutatedPoseidonSegmentArtifact(
            allocator,
            artifact,
            security.identity,
        );
        var decoded = try poseidon_segment_artifact.decodeAlloc(
            allocator,
            artifact,
            security.identity,
            .{},
        );
        var proof_moved = false;
        defer if (proof_moved)
            decoded.deinitAfterProofMoved(allocator)
        else
            decoded.deinit(allocator);
        try verifySegmentArtifactCapture(
            ProvingEngine,
            allocator,
            config,
            &decoded,
            &global_metadata,
            &proof_moved,
        );
    }
}

fn rejectNonCanonicalPoseidonClockFrame(
    allocator: std.mem.Allocator,
    artifact: []const u8,
    security_identity: [32]u8,
) !void {
    const mutated = try allocator.dupe(u8, artifact);
    defer allocator.free(mutated);
    const statement_length = std.mem.readInt(
        u32,
        mutated[poseidon_segment_artifact.HeaderOffset.statement_length..][0..4],
        .little,
    );
    const clock_frame_offset = poseidon_segment_artifact.header_size +
        statement_length + poseidon_segment_artifact.ExtensionOffset.metadata_clock_frame;
    if (clock_frame_offset + @sizeOf(u16) > mutated.len)
        return error.InvalidTestArtifact;
    // The low byte remains the honest leaf-local tag. A non-zero high byte
    // proves the decoder consumes and validates the full canonical u16 wire.
    mutated[clock_frame_offset + 1] = 1;
    try std.testing.expectError(
        error.InvalidEnumTag,
        poseidon_segment_artifact.decodeAlloc(
            allocator,
            mutated,
            security_identity,
            .{},
        ),
    );
}

fn verifySegmentArtifactCapture(
    comptime ProvingEngine: type,
    allocator: std.mem.Allocator,
    config: pcs_core.PcsConfig,
    decoded: anytype,
    expected_global: *const global_v3.MetadataV3,
    proof_moved: *bool,
) !void {
    try std.testing.expect(std.meta.eql(decoded.global, expected_global.*));
    var capture: prover.VerifiedEthereumSegmentV3CaptureForEngine(ProvingEngine) =
        undefined;
    proof_moved.* = true;
    try prover.verifyEthereumSegmentWithEngineAndEthereumV3Capture(
        ProvingEngine,
        allocator,
        config,
        decoded.statement,
        decoded.extension,
        decoded.proof,
        decoded.base_claim,
        &decoded.extension_claim,
        &decoded.global,
        &capture,
    );
    defer capture.deinit(allocator);
    try capture.validate();
    try capture.verified_link.validateAgainst(
        expected_global,
        &capture.base.public_data.data,
        &capture.base.receipt,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(2 * capture.core_statement.core.n_components +
            capture.core_statement.core.n_infra + 14)),
        capture.extension_context.full_component_count,
    );
    try rejectStoredSidecarMutation(&capture);
}

fn rejectStoredSidecarMutation(capture: anytype) !void {
    var mutated = capture.extension_context;
    mutated.statement_sha256[0] ^= 1;
    try std.testing.expectError(
        error.EthereumContextMismatch,
        mutated.validateAgainst(
            &capture.core_statement,
            &capture.extension_statement,
            &capture.extension_claim,
            &capture.base.vm_air,
        ),
    );
    mutated = capture.extension_context;
    mutated.claim_sha256[0] ^= 1;
    try std.testing.expectError(
        error.EthereumContextMismatch,
        mutated.validateAgainst(
            &capture.core_statement,
            &capture.extension_statement,
            &capture.extension_claim,
            &capture.base.vm_air,
        ),
    );
}

fn expectPairedCountHashesDiffer(
    core: *const frontend.air.statement.RiscVStatement,
    extension: *const frontend.air.guest_precompile.ethereum_statement.Statement,
    extension_claim: *const prover.guest_precompile.ethereum_types.ExtensionClaim,
) !void {
    const statement_mod = frontend.air.guest_precompile.ethereum_statement;
    const shapes = statement_mod.SecpShapes{
        .product_base = shape(extension.components[3]),
        .product_scalar = shape(extension.components[4]),
        .linear_base = shape(extension.components[5]),
        .linear_scalar = shape(extension.components[6]),
        .point = shape(extension.components[7]),
        .split = shape(extension.components[8]),
        .scalar = shape(extension.components[9]),
        .table = shape(extension.components[10]),
        .recovery = shape(extension.components[11]),
        .byte = shape(extension.components[12]),
        .recovery_caller = shape(extension.components[13]),
    };
    const paired_statement = try statement_mod.Statement.canonical(
        core,
        2,
        extension.counts.signer_calls,
        shapes,
    );
    var paired_claim = extension_claim.*;
    paired_claim.keccak_shard.call_count = 2;
    try paired_claim.validate(&paired_statement);
    try std.testing.expect(std.meta.eql(
        extension.components[0],
        paired_statement.components[0],
    ));
    const context = frontend.recursion.ethereum_leaf_context_v1;
    const original_statement_sha = context.statementSha256(extension);
    const paired_statement_sha = context.statementSha256(&paired_statement);
    const original_claim_sha = context.claimSha256(extension_claim);
    const paired_claim_sha = context.claimSha256(&paired_claim);
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_statement_sha,
        &paired_statement_sha,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_claim_sha,
        &paired_claim_sha,
    ));
}

fn shape(
    descriptor: frontend.air.guest_precompile.ethereum_statement.Descriptor,
) frontend.air.guest_precompile.ethereum_statement.Shape {
    return .{ .log_size = descriptor.log_size, .n_rows = descriptor.n_rows };
}

fn rejectMutatedSegmentIdentity(
    allocator: std.mem.Allocator,
    artifact: []const u8,
) !void {
    const mutated = try allocator.dupe(u8, artifact);
    defer allocator.free(mutated);
    const statement_length = std.mem.readInt(
        u32,
        mutated[segment_artifact.HeaderOffset.statement_length..][0..4],
        .little,
    );
    const extension_length = std.mem.readInt(
        u32,
        mutated[segment_artifact.HeaderOffset.extension_length..][0..4],
        .little,
    );
    const identity_start = segment_artifact.header_size +
        statement_length + extension_length;
    const identity_length = std.mem.readInt(
        u32,
        mutated[segment_artifact.HeaderOffset.identity_length..][0..4],
        .little,
    );
    if (identity_length == 0 or identity_start + identity_length > mutated.len)
        return error.InvalidTestArtifact;
    mutated[identity_start + identity_length - 1] ^= 1;
    try std.testing.expectError(
        error.IdentityMismatch,
        segment_artifact.decodeAllocForConfig(
            allocator,
            mutated,
            test_config,
            .{},
        ),
    );
}

fn rejectMutatedPoseidonSegmentArtifact(
    allocator: std.mem.Allocator,
    artifact: []const u8,
    security_identity: [32]u8,
) !void {
    const mutated_hasher = try allocator.dupe(u8, artifact);
    defer allocator.free(mutated_hasher);
    std.mem.writeInt(
        u16,
        mutated_hasher[poseidon_segment_artifact.HeaderOffset.hasher..][0..2],
        1,
        .little,
    );
    try std.testing.expectError(
        error.UnsupportedProofHasher,
        poseidon_segment_artifact.decodeAlloc(
            allocator,
            mutated_hasher,
            security_identity,
            .{},
        ),
    );

    var wrong_security = security_identity;
    wrong_security[0] ^= 1;
    try std.testing.expectError(
        error.IdentityMismatch,
        poseidon_segment_artifact.decodeAlloc(
            allocator,
            artifact,
            wrong_security,
            .{},
        ),
    );

    const mutated_identity = try allocator.dupe(u8, artifact);
    defer allocator.free(mutated_identity);
    const statement_length = std.mem.readInt(
        u32,
        mutated_identity[poseidon_segment_artifact.HeaderOffset.statement_length..][0..4],
        .little,
    );
    const extension_length = std.mem.readInt(
        u32,
        mutated_identity[poseidon_segment_artifact.HeaderOffset.extension_length..][0..4],
        .little,
    );
    const identity_length = std.mem.readInt(
        u32,
        mutated_identity[poseidon_segment_artifact.HeaderOffset.identity_length..][0..4],
        .little,
    );
    const identity_start = poseidon_segment_artifact.header_size +
        statement_length + extension_length;
    if (identity_length == 0 or
        identity_start + identity_length > mutated_identity.len)
    {
        return error.InvalidTestArtifact;
    }
    mutated_identity[identity_start + identity_length - 1] ^= 1;
    try std.testing.expectError(
        error.IdentityMismatch,
        poseidon_segment_artifact.decodeAlloc(
            allocator,
            mutated_identity,
            security_identity,
            .{},
        ),
    );
}

fn proveAndVerify(
    allocator: std.mem.Allocator,
    elf: []const u8,
    expected_keccak: usize,
    expected_signer: usize,
    workers: usize,
    report_timing: bool,
) !void {
    var total_timer = try std.time.Timer.start();

    var execution_timer = try std.time.Timer.start();
    var run = try frontend.runner.runEthereumExtension(allocator, elf, 16);
    const execution_ns = execution_timer.read();
    defer run.deinit();
    try std.testing.expectEqual(frontend.runner.CompletionReason.self_loop, run.base.completion_reason);
    // The canonical self-loop is committed as the public completion fetch but
    // is deliberately not retired; three core rows plus two external rows
    // therefore own the clock range [1, 5].
    try std.testing.expectEqual(@as(usize, 5), run.base.step_count);
    try std.testing.expectEqual(expected_keccak, run.keccakf_calls.len());
    try std.testing.expectEqual(expected_signer, run.signer_recovery_calls.len());

    const input_words = try public_data_mod.packInputWords(allocator, run.base.input);
    defer allocator.free(input_words);
    const output_words = try allocator.alloc(
        public_data_mod.OutputWord,
        run.base.output_words.len,
    );
    defer allocator.free(output_words);
    for (output_words, run.base.output_words) |*destination, source| {
        destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
    }
    const public_data = public_data_mod.PublicData{
        .initial_pc = run.base.initial_pc,
        .final_pc = run.base.final_pc,
        .clock = @intCast(run.base.step_count),
        .initial_regs = run.base.initial_regs,
        .final_regs = run.base.final_regs,
        .reg_last_clock = run.base.state_chain_tracker.reg_last_clk,
        .program_root = null,
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = try public_data_mod.completionFromRun(run.base),
        .io_entries = .{
            .input_start = run.base.input_start,
            .input_len = @intCast(run.base.input.len),
            .input_words = input_words,
            .output_len = run.base.output_len,
            .output_len_addr = run.base.output_len_addr,
            .output_data_addr = run.base.output_data_addr,
            .output_words = output_words,
        },
    };

    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "ReleaseFast",
        "ethereum-leaf-smoke-n8",
        .{ .capture_tasks = true },
    );
    defer recorder.deinit();

    var proof_timer = try std.time.Timer.start();
    var output = try prover.proveEthereumWithEngineUsingExecution(
        Engine,
        allocator,
        test_config,
        &run.base.execution_trace,
        &run.keccakf_calls,
        &run.keccakf_execution_rows,
        &run.signer_recovery_calls,
        &run.signer_recovery_execution_rows,
        &run.base.state_chain_tracker,
        &run.base.rw_memory,
        &recorder,
        public_data,
        .{ .cpu = .{
            .worker_count = workers,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .strict,
        } },
    );
    const proof_ns = proof_timer.read();
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    try output.extension.validate(&output.statement);
    try output.extension_claim.validate(&output.extension);
    if (expected_keccak == 1) try expectPairedCountHashesDiffer(
        &output.statement,
        &output.extension,
        &output.extension_claim,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(expected_keccak + expected_signer)),
        output.extension.counts.external_retirements,
    );
    try std.testing.expectEqual(
        @as(usize, 14),
        output.extension.components.len,
    );
    if (expected_keccak == 0) {
        try std.testing.expectEqual(@as(u32, 0), output.extension.components[0].n_rows);
    }
    if (expected_signer == 0) {
        for (output.extension.components[3..12]) |descriptor|
            try std.testing.expectEqual(@as(u32, 0), descriptor.n_rows);
        try std.testing.expectEqual(@as(u32, 256), output.extension.components[12].n_rows);
        try std.testing.expectEqual(@as(u32, 0), output.extension.components[13].n_rows);
    }
    try std.testing.expectEqual(@as(usize, 4), output.proof.commitment_scheme_proof.commitments.items.len);

    proof_moved = true;
    var verify_timer = try std.time.Timer.start();
    try prover.verifyEthereumWithEngine(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.extension,
        output.proof,
        output.base_claim,
        &output.extension_claim,
    );
    const verify_ns = verify_timer.read();

    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expect(profile.stages.len >= 6);
    if (report_timing) {
        std.debug.print(
            "ETHEREUM_LEAF_TIMING execution_ns={d} prove_ns={d} verify_ns={d} total_ns={d}\n",
            .{ execution_ns, proof_ns, verify_ns, total_timer.read() },
        );
        printStages(profile.stages, 0);
    }
}

fn replaceInstruction(elf: []u8, old: u32, new: u32) void {
    const bytes = std.mem.toBytes(old);
    const offset = std.mem.indexOf(u8, elf, &bytes) orelse unreachable;
    std.mem.writeInt(u32, elf[offset..][0..4], new, .little);
}

fn leafStatement(
    job: span.JobContext,
    result: *const frontend.runner.SegmentResult,
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
    cpu: frontend.runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw_memory, public_io_state);
}

fn encodeSegment(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4554_4833); // "ETH3"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn printStages(stages: []const prover_api.stage_profile.StageNode, depth: usize) void {
    for (stages) |stage| {
        std.debug.print(
            "ETHEREUM_LEAF_STAGE depth={d} id={s} seconds={d:.9}\n",
            .{ depth, stage.id, stage.seconds },
        );
        if (stage.children) |children| printStages(children, depth + 1);
    }
}
