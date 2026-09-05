//! Focused instantiation of the opt-in Ethereum SegmentV2 transcript hook.
//!
//! This test authority is deliberately not a product omission descriptor. It
//! binds the two committed Stage-A roots and a runtime provider-shard count so
//! the generic hook is compiled and exercised without predicting the separate
//! ProjectedNativeV2 transport owned by the integration layer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const pcs_core = stwo_core.pcs;
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;
const frontend = @import("stwo_riscv_frontend");
const support = @import("ethereum_block_leaf_support.zig");

const prover = frontend.prover_mod;
const M31 = stwo_core.fields.m31.M31;
const global_channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const span = frontend.recursion.span_statement;
const Engine = support.RecursiveEngine;
const ethereum_transcript = prover.guest_precompile.ethereum_transcript;
const provider_protocol = prover.ethereum_native_provider_omit_protocol_v1;
const provider_authority = prover.memory_provider_shard_authority;
const provider_harness = frontend.testing.narrow_memory_provider_proof_harness;
const provider_omit_proof =
    frontend.testing.narrow_memory_provider_ethereum_omit_proof_v1;
const degree5_omit_proof =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

pub fn run() !void {
    const allocator = std.testing.allocator;
    var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
    const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
    const completion_offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
        return error.MissingCompletionInstruction;
    std.mem.writeInt(u32, elf[completion_offset..][0..4], 0x0000_006f, .little);

    var session = try frontend.runner.EthereumExecutionSession.init(
        allocator,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
    );
    defer session.deinit();
    var first = try session.startSegment(1);
    defer first.deinit();
    var second = try session.resumeSegment(first.base.continuation.?, 32);
    defer second.deinit();
    try std.testing.expect(!first.base.isComplete());
    try std.testing.expect(second.base.isComplete());

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
    const input_digest = digest("ethereum-extension-input");
    const output_digest = digest("ethereum-extension-output");
    const initial = try machineState(
        first.base.entry_cpu,
        digest("ethereum-extension-rw-entry"),
        digest("ethereum-extension-io-entry"),
    );
    const shared = try machineState(
        first.base.exit_cpu,
        digest("ethereum-extension-rw-shared"),
        digest("ethereum-extension-io-shared"),
    );
    const final = try machineState(
        second.base.exit_cpu,
        digest("ethereum-extension-rw-exit"),
        digest("ethereum-extension-io-exit"),
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
        digest("ethereum-extension-session"),
    );
    const words = try encodeSegment(allocator, &local_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    try runNativeProviderOmission(
        allocator,
        &projection.local_result,
        &first.keccakf_calls,
        &first.keccakf_execution_rows,
        &first.signer_recovery_calls,
        &first.signer_recovery_execution_rows,
        public_data,
    );

    const extension = TestTranscriptExtension(Engine){
        // Segment 27 requires sixteen log20 provider shards. Keeping this a
        // runtime value proves the hook is not specialized to segment 0's ten.
        .provider_shard_count = 16,
    };
    var prove_channel = Engine.Channel{};
    var output = try prover
        .proveEthereumSegmentWithEngineUsingChannelAndExecutionAndTranscriptExtension(
        Engine,
        allocator,
        test_config,
        &projection.local_result,
        &first.keccakf_calls,
        &first.keccakf_execution_rows,
        &first.signer_recovery_calls,
        &first.signer_recovery_execution_rows,
        null,
        public_data,
        &prove_channel,
        prover.guest_precompile.ethereum_segment_orchestration.sequential_execution,
        extension,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);
    try output.statement.validateSegmentResult(&projection.local_result);
    try std.testing.expectEqual(
        @as(usize, 4),
        output.proof.commitment_scheme_proof.commitments.items.len,
    );

    var capture: prover.VerifiedEthereumSegmentV3CaptureForEngine(Engine) =
        undefined;
    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try prover
        .verifyEthereumSegmentWithEngineAndEthereumV3CaptureUsingChannelAndTranscriptExtension(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.extension,
        output.proof,
        output.base_claim,
        &output.extension_claim,
        &global_metadata,
        &verify_channel,
        extension,
        &capture,
    );
    defer capture.deinit(allocator);
    try capture.validate();
}

fn runNativeProviderOmission(
    allocator: std.mem.Allocator,
    result: *const frontend.runner.SegmentResult,
    keccak_calls: anytype,
    keccak_rows: anytype,
    recovery_calls: anytype,
    recovery_rows: anytype,
    public_data: frontend.air.public_data_v2.PublicDataV2,
) !void {
    var call_authority = try prover.buildEthereumSegmentProviderCallAuthorityV1(
        allocator,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        public_data,
    );
    defer call_authority.deinit();
    const call_count: u64 = @intCast(call_authority.calls.len);
    const max_log = @max(
        @as(u32, 4),
        std.math.log2_int_ceil(u64, call_count),
    );
    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0xa7} ** 32,
        call_authority.calls,
        shard_planner.Request{
            .logical_row_count = call_count,
            .column_count = provider_authority.main_column_count,
            .min_shard_log_size = 4,
            .max_shard_log_size = max_log,
            .log_blowup_factor = test_config.fri_config.log_blowup_factor,
            .retention_policy = .always,
            .host_byte_budget = 1024 * 1024 * 1024,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);
    const degree5_program = try degree5_omit_proof.VerifierProgramAuthorityV2
        .coldCompile(allocator);
    const degree5_execution = degree5_omit_proof.ExecutionProfileV1.n4(
        degree5_program.base,
    );

    const provider_roots = try allocator.alloc(
        provider_harness.StageACommitment(Engine),
        plan.shards.len,
    );
    defer allocator.free(provider_roots);
    for (provider_roots, 0..) |*roots, index| {
        roots.* = try degree5_omit_proof.commitStageAV1(
            Engine,
            allocator,
            support.recursive_pcs_config,
            degree5_program,
            &plan,
            call_authority.calls,
            @intCast(index),
        );
    }
    var owned_provider_stage_a = try provider_protocol
        .ProviderStageAManifestV1(Engine).createFromRoots(
        allocator,
        &plan,
        call_authority.calls,
        provider_roots,
    );
    defer owned_provider_stage_a.deinit(allocator);
    const provider_stage_a = owned_provider_stage_a.manifest;

    var prove_extension = try provider_protocol.Extension(Engine).init(
        &plan,
        call_authority.calls,
        &provider_stage_a,
    );
    var prove_channel = Engine.Channel{};
    var output = try prover
        .proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission(
        Engine,
        allocator,
        support.recursive_pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        null,
        public_data,
        &prove_channel,
        prover.guest_precompile.ethereum_segment_orchestration.sequential_execution,
        &prove_extension,
    );
    var output_proof_moved = false;
    defer if (output_proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);
    const projection = try prove_extension.providerProjection();
    try std.testing.expectEqual(
        output.statement.core.n_infra - 1,
        output.base_claim.n_infra,
    );
    try std.testing.expectEqual(
        output.statement.core.nMainColumns() - projection.tree1ColumnsRemoved(),
        projection.projected_native.core.nMainColumns(),
    );
    try std.testing.expect(prove_extension.prover_residual != null);

    // The omitted arm deliberately stops at the prove output and never hands
    // the projected core to the ordinary SegmentV2 artifact codec: that codec
    // re-runs `ethereum_proof_admission.validateV2`, whose geometry check
    // requires the very `.poseidon2` descriptor this projection removes, so a
    // projected core has no canonical SegmentV2 envelope today. The projection
    // seal below is the authority that replaces it.
    try std.testing.expect(projection.omitted_descriptor.kind == .poseidon2);
    try std.testing.expectEqual(
        provider_authority.main_column_count,
        projection.omitted_descriptor.n_columns,
    );
    try projection.validateSealAndFull(&output.statement, &output.extension);

    var verify_extension = try provider_protocol.Extension(Engine)
        .initForFreshVerify(
        &plan,
        call_authority.calls,
        &provider_stage_a,
        prove_extension.shared_relation orelse
            return error.MissingEthereumProviderSharedAuthority,
    );
    var verify_channel = Engine.Channel{};
    output_proof_moved = true;
    try prover.verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission(
        Engine,
        allocator,
        support.recursive_pcs_config,
        output.statement,
        output.extension,
        output.proof,
        output.base_claim,
        &output.extension_claim,
        &verify_channel,
        &verify_extension,
    );
    try std.testing.expect(verify_extension.fresh_verifier_residual != null);
    try std.testing.expect(
        prove_extension.prover_residual.?.eql(
            verify_extension.fresh_verifier_residual.?,
        ),
    );
    const shared = verify_extension.shared_relation orelse
        return error.MissingEthereumProviderSharedAuthority;
    const fresh_core = verify_extension.fresh_core orelse
        return error.MissingEthereumProviderFreshCore;
    const verified_projection = try verify_extension.providerProjection();
    try std.testing.expectEqualSlices(
        u8,
        &projection.identity,
        &verified_projection.identity,
    );
    try verified_projection.validateSealAndFull(
        &output.statement,
        &output.extension,
    );
    var lookup_manifest = frontend.air.lookup_physical_manifest_v2
        .Manifest.native();
    const authenticated = try frontend.air.lookup_physical_manifest_v2
        .AuthenticatedStatement.init(
        &output.statement.core,
        &lookup_manifest,
    );
    const provider_source = provider_omit_proof.Source(Engine){
        .native = &output.statement,
        .extension = &output.extension,
        .lookup_manifest = &lookup_manifest,
        .authenticated_lookup = &authenticated,
        .projection = verified_projection,
        .plan = &plan,
        .calls = call_authority.calls,
        .provider_stage_a = &provider_stage_a,
        .shared = shared,
    };
    const fresh_providers = try allocator.alloc(
        degree5_omit_proof.FreshDegree5ProviderClaimV1,
        plan.shards.len,
    );
    defer allocator.free(fresh_providers);
    for (fresh_providers, 0..) |*fresh, index| {
        const provider_output = try degree5_omit_proof.proveProviderV1(
            Engine,
            allocator,
            support.recursive_pcs_config,
            degree5_program,
            degree5_execution,
            provider_source,
            @intCast(index),
        );
        fresh.* = try degree5_omit_proof.verifyProviderFreshV1(
            Engine,
            allocator,
            support.recursive_pcs_config,
            degree5_program,
            degree5_execution,
            provider_source,
            provider_output.statement,
            provider_output.proof,
        );
    }
    const closed = try degree5_omit_proof.closeFreshClaimsV1(
        Engine,
        allocator,
        degree5_program,
        degree5_execution,
        provider_source,
        fresh_core,
        fresh_providers,
    );
    const closure = closed.closure;
    try closure.validate();
    try closed.strategy.validate();
    try std.testing.expect(closure.closed_sum.isZero());
    try std.testing.expect(closed.strategy.shared_core_zero_sum_verified);
    try std.testing.expectEqual(
        degree5_program.air_program_identity,
        closed.strategy.air_program_identity,
    );
    try std.testing.expect(!closure.production_eligible);
    try std.testing.expect(!closure.recursive_admissible);

    var mutated_stage_a = provider_stage_a;
    mutated_stage_a.identity[0] ^= 1;
    try std.testing.expectError(
        error.EthereumProviderStageAManifestIdentityMismatch,
        provider_protocol.Extension(Engine).init(
            &plan,
            call_authority.calls,
            &mutated_stage_a,
        ),
    );
}

fn TestTranscriptExtension(comptime ProvingEngine: type) type {
    return struct {
        provider_shard_count: u32,

        const Self = @This();
        const Frame = struct {
            provider_shard_count: u32,
            tree0_root: ProvingEngine.Hasher.Hash,
            tree1_root: ProvingEngine.Hasher.Hash,

            pub fn mixInto(self: @This(), transcript_channel: anytype) void {
                transcript_channel.mixU32s(&.{
                    0x4757_5453, // "STWG"
                    0x5845_5445, // "ETEX"
                    1,
                    self.provider_shard_count,
                });
                ProvingEngine.MerkleChannel.mixRoot(
                    transcript_channel,
                    self.tree0_root,
                );
                ProvingEngine.MerkleChannel.mixRoot(
                    transcript_channel,
                    self.tree1_root,
                );
            }
        };

        pub fn prepareProjectedCore(
            self: Self,
            native_statement: anytype,
            extension_statement: anytype,
            lookup_manifest: anytype,
            authenticated_lookup: anytype,
            workspace_core: anytype,
            full_geometry: anytype,
        ) !void {
            if (self.provider_shard_count == 0)
                return error.InvalidTestProviderShardCount;
            // Product integration replaces `workspace_core` here. The test
            // authority keeps it unchanged while forcing this precommit hook
            // to compile and run before Stage-A allocation.
            _ = native_statement;
            _ = extension_statement;
            _ = lookup_manifest;
            _ = authenticated_lookup;
            _ = workspace_core;
            _ = full_geometry;
        }

        pub fn drawChallenges(
            self: Self,
            allocator: std.mem.Allocator,
            scheme: *ProvingEngine.Scheme,
            transcript_channel: *ProvingEngine.Channel,
            native_statement: anytype,
            core: anytype,
            extension_statement: anytype,
            lookup_manifest: anytype,
            authenticated_lookup: anytype,
            recorder: anytype,
        ) !ethereum_transcript.Prefix {
            if (self.provider_shard_count == 0)
                return error.InvalidTestProviderShardCount;
            _ = native_statement;
            _ = extension_statement;
            _ = lookup_manifest;
            _ = authenticated_lookup;
            _ = recorder;
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 2) return error.InvalidTestStageATreeCount;
            return ethereum_transcript.proveToRelationsWithExtension(
                allocator,
                transcript_channel,
                core,
                Frame{
                    .provider_shard_count = self.provider_shard_count,
                    .tree0_root = roots.items[0],
                    .tree1_root = roots.items[1],
                },
            );
        }

        pub fn verifyRelations(
            self: Self,
            allocator: std.mem.Allocator,
            pcs_config: pcs_core.PcsConfig,
            transcript_channel: *ProvingEngine.Channel,
            native_statement: anytype,
            core: anytype,
            extension_statement: anytype,
            lookup_manifest: anytype,
            authenticated_lookup: anytype,
            interaction_pow: u64,
            tree0_root: ProvingEngine.Hasher.Hash,
            tree1_root: ProvingEngine.Hasher.Hash,
        ) !ethereum_transcript.Relations {
            if (self.provider_shard_count == 0)
                return error.InvalidTestProviderShardCount;
            _ = pcs_config;
            _ = native_statement;
            _ = extension_statement;
            _ = lookup_manifest;
            _ = authenticated_lookup;
            return ethereum_transcript.verifyToRelationsWithExtension(
                allocator,
                transcript_channel,
                core,
                interaction_pow,
                Frame{
                    .provider_shard_count = self.provider_shard_count,
                    .tree0_root = tree0_root,
                    .tree1_root = tree1_root,
                },
            );
        }
    };
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
    return global_channel.hashBytes(label, 0x4554_4833); // "ETH3"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** global_channel.RATE;
    result[0] = value;
    return result;
}
