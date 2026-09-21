//! Genuine two-leaf ingress into the secure Ethereum H1 parent.
//!
//! Both children are first proved under the selected Poseidon2 SegmentV3
//! policy and independently verified into live `VerifiedPoseidonV4` captures.
//! The parent proof then crosses canonical retained bytes, destruction,
//! decode, and a second cold verification. Nothing here activates production.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const prover_engine = @import("stwo_prover_engine");

const leaf_support = @import("ethereum_block_leaf_support.zig");
const ingress =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const h1_manifest =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const h1_cohort =
    @import("recursive_temporal_ethereum_poseidon_h1_proof_cohort_v1.zig");
const parent_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");
const parent_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const node_public =
    @import("recursive_temporal_node_public_authority_v2.zig");
const leaf_descriptor =
    @import("recursive_temporal_ethereum_leaf_descriptor_v1.zig");
const node_profile = @import("recursive_temporal_node_profile_v1.zig");
const proof_security =
    @import("recursive_temporal_proof_security_v1.zig");
const child_transcript =
    @import("recursive_temporal_child_transcript_authority_v1.zig");
const provider_bridge =
    @import("recursive_temporal_incremental_provider_authority_v1.zig");

const recursion = frontend.recursion;
const prover = leaf_support.prover;
const RecursiveEngine = leaf_support.RecursiveEngine;
const span = recursion.span_statement;
const channel = recursion.poseidon2_channel;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const projection_v3 = recursion.segment_leaf_local_projection_v3;
const source_wire = leaf_support.source_wire;
const native_provider = prover.memory_provider_shard_authority;
const poseidon_air = frontend.air.memory_commitment.poseidon2_air;
const residency = prover_engine.pcs.residency_shard_plan;
const QM31 = core.fields.qm31.QM31;

const ParentKernel = parent_engine.EngineKernelForManifest(
    h1_cohort.DefaultCohortV1,
    h1_manifest,
    .ethereum_poseidon_h1_v1,
);

test "Ethereum Poseidon h1 two verified leaves retain secure q193 cold proof" {
    const allocator = std.testing.allocator;
    var fixture = try FixtureV1.init(allocator);
    defer fixture.deinit();
    const inputs = fixture.authorityInputs();
    const session = try parent_artifact.SessionV1.initFromFreshEthereumH1(
        &fixture.fresh,
    );

    var result = try ParentKernel.proveAndColdVerify(
        allocator,
        inputs,
        session,
        .{ .worker_count = 1 },
    );
    const retained = try result.artifact.encodeCanonicalAlloc(allocator);
    defer allocator.free(retained);
    const expected_statement = result.fresh.statement;
    const expected_receipt = result.receipt;
    result.deinit();

    var decoded = try parent_artifact.OwnedArtifactV1.decodeCanonical(
        allocator,
        retained,
    );
    defer decoded.deinit();
    var cold = try ParentKernel.verifyCold(
        allocator,
        inputs,
        &session,
        &decoded,
    );
    defer cold.deinit();

    try std.testing.expectEqualDeep(expected_statement, cold.statement);
    try std.testing.expectEqualDeep(decoded.statement, cold.statement);
    try expected_receipt.validate();
    try std.testing.expectEqual(@as(u32, 193), expected_receipt.fri_query_count);
    try std.testing.expectEqual(@as(u32, 16), expected_receipt.pcs_pow_bits);
    try std.testing.expectEqual(@as(u32, 4), expected_receipt.fri_fold_step);
    try std.testing.expectEqual(
        parent_engine.TranscriptFlavorV1.ethereum_poseidon_h1_v1,
        expected_receipt.transcript_flavor,
    );
    try std.testing.expect(!parent_engine.PRODUCTION_ACTIVATION);
}

const FixtureV1 = struct {
    allocator: std.mem.Allocator,
    left: LeafV1,
    right: LeafV1,
    profile: node_profile.NodeProfileV1,
    fresh: ingress.FreshIngressV1,

    fn init(allocator: std.mem.Allocator) !FixtureV1 {
        var elf = frontend.testing.guest_precompile_test_elf.buildEthereum();
        const ecall = std.mem.toBytes(@as(u32, 0x0000_0073));
        const completion_offset = std.mem.lastIndexOf(u8, &elf, &ecall) orelse
            return error.MissingCompletionInstruction;
        std.mem.writeInt(
            u32,
            elf[completion_offset..][0..4],
            0x0000_006f,
            .little,
        );
        var execution = try frontend.runner.EthereumExecutionSession.init(
            allocator,
            &elf,
            .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
        );
        defer execution.deinit();
        var first = try execution.startSegment(1);
        defer first.deinit();
        var second = try execution.resumeSegment(first.base.continuation.?, 32);
        defer second.deinit();
        if (first.base.isComplete() or !second.base.isComplete())
            return error.InvalidH1ExecutionFixture;

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
        const input_digest = digest("h1-secure-parent-input");
        const output_digest = digest("h1-secure-parent-output");
        const initial = try machineState(
            first.base.entry_cpu,
            digest("h1-secure-parent-rw-entry"),
            digest("h1-secure-parent-io-entry"),
        );
        const middle = try machineState(
            first.base.exit_cpu,
            digest("h1-secure-parent-rw-middle"),
            digest("h1-secure-parent-io-middle"),
        );
        const final = try machineState(
            second.base.exit_cpu,
            digest("h1-secure-parent-rw-exit"),
            digest("h1-secure-parent-io-exit"),
        );
        const total_cycles = try std.math.add(
            u64,
            @intCast(first.base.cycle_count),
            @intCast(second.base.cycle_count),
        );
        const job = try span.JobContext.init(
            try span.CompleteExecution.init(
                recursion.protocol.PROTOCOL_ID_WORDS,
                scalarDigest(program.tree.root),
                initial,
                final,
                input_digest,
                output_digest,
                total_cycles,
            ),
            2,
        );
        const left_statement = try leafStatement(
            job,
            &first.base,
            initial,
            middle,
            try span.EdgeClaim.present(input_digest),
            span.EdgeClaim.absent(),
        );
        const right_statement = try leafStatement(
            job,
            &second.base,
            middle,
            final,
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(output_digest),
        );
        var left = try LeafV1.init(
            allocator,
            &first,
            left_statement,
            31,
        );
        errdefer left.deinit(allocator);
        var right = try LeafV1.init(
            allocator,
            &second,
            right_statement,
            71,
        );
        errdefer right.deinit(allocator);
        const profile = try secureProfile();
        const fresh = try ingress.mintFromFreshVerifier(allocator, .{
            .profile = &profile,
            .left = left.input(),
            .right = right.input(),
        });
        return .{
            .allocator = allocator,
            .left = left,
            .right = right,
            .profile = profile,
            .fresh = fresh,
        };
    }

    fn deinit(self: *FixtureV1) void {
        self.right.deinit(self.allocator);
        self.left.deinit(self.allocator);
        self.* = undefined;
    }

    fn mintInput(self: *FixtureV1) ingress.FreshMintInputV1 {
        return .{
            .profile = &self.profile,
            .left = self.left.input(),
            .right = self.right.input(),
        };
    }

    fn authorityInputs(
        self: *FixtureV1,
    ) h1_cohort.DefaultCohortV1.AuthorityInputs {
        return .{ .verifier_minted = .{
            .fresh = &self.fresh,
            .input = self.mintInput(),
        } };
    }
};

const LeafV1 = struct {
    source: source_wire.Source,
    verified: leaf_support.VerifiedPoseidonV4,
    node: node_public.EthereumLeafAuthorityV2,

    fn init(
        allocator: std.mem.Allocator,
        segment: *const frontend.runner.EthereumSegmentResult,
        statement: span.SpanStatement,
        seed: u32,
    ) !LeafV1 {
        const global_source = try global_v3.SourceV3.fromSegmentResult(
            statement,
            &segment.base,
        );
        const metadata = try global_source.metadata();
        var projection = try projection_v3.ProjectionV3.init(&global_source);
        const local_source = try projection.sourceV2(
            &global_source,
            digest("h1-secure-parent-leaf-session"),
        );
        const public = try leaf_support.encodeLocalPublicData(
            allocator,
            &local_source,
        );
        defer allocator.free(public.words);
        var output = try prover.proveEthereumSegmentWithEngine(
            RecursiveEngine,
            allocator,
            leaf_support.recursive_pcs_config,
            &projection.local_result,
            &segment.keccakf_calls,
            &segment.keccakf_execution_rows,
            &segment.signer_recovery_calls,
            &segment.signer_recovery_execution_rows,
            null,
            public.value,
        );
        defer output.deinit(allocator);
        const encoded = try leaf_support.recursive_artifact.encodeAllocWithLimits(
            allocator,
            .{
                .security_identity_sha256 = leaf_support.recursive_security_identity,
                .statement = &output.statement,
                .extension = &output.extension,
                .global = &metadata,
                .base_claim = output.base_claim,
                .extension_claim = &output.extension_claim,
                .proof = &output.proof,
            },
            leaf_support.artifact_limits,
        );
        defer allocator.free(encoded);
        const source = source_wire.Source{
            .journal_record_sha256 = sha(seed),
            .metadata = metadata,
        };
        var verified = try leaf_support.verifyPoseidonArtifactWithCapture(
            allocator,
            encoded,
            &source,
        );
        errdefer verified.deinit(allocator);
        var provider = try ProviderFixtureV1.init(
            allocator,
            metadata,
            verified.leaf_descriptor,
            seed + 100,
        );
        defer provider.deinit();
        const node = try node_public.EthereumLeafAuthorityV2
            .initFromFreshVerifier(
            verified.leaf_descriptor,
            metadata,
            provider.input(),
        );
        return .{
            .source = source,
            .verified = verified,
            .node = node,
        };
    }

    fn deinit(self: *LeafV1, allocator: std.mem.Allocator) void {
        self.verified.deinit(allocator);
        self.* = undefined;
    }

    fn input(self: *LeafV1) ingress.FreshLeafInputV1 {
        return .{
            .verified = &self.verified,
            .source = &self.source,
            .descriptor = &self.verified.leaf_descriptor,
            .node_public = &self.node,
        };
    }
};

const ProviderFixtureV1 = struct {
    allocator: std.mem.Allocator,
    calls: [16]poseidon_air.Call,
    provider_plan: native_provider.ProviderShardPlanV1,
    residency_request: residency.Request,
    residency_plan: residency.Plan,
    relation: native_provider.PoseidonRelationContextV1,
    core_claim: native_provider.CorePoseidonClaimV1,
    shard_claims: [1]native_provider.ProviderShardClaimV1,
    shard_artifacts: [1]provider_bridge.ShardArtifactV1,
    entry_continuation_root: u32,
    exit_continuation_root: u32,
    core_proof_artifact_sha256: [32]u8,
    core_proof_capture_sha256: [32]u8,
    core_capture_identity: [32]u8,

    fn init(
        allocator: std.mem.Allocator,
        metadata: global_v3.MetadataV3,
        descriptor: leaf_descriptor.DescriptorV1,
        seed: u32,
    ) !ProviderFixtureV1 {
        var calls: [16]poseidon_air.Call = undefined;
        for (&calls, 0..) |*call, index| call.* =
            poseidon_air.Call.narrowWithOutput(
                @intCast(index + 1),
                @intCast(index + 2),
                @intCast(index + 3),
            );
        const request = residency.Request{
            .logical_row_count = calls.len,
            .column_count = native_provider.main_column_count,
            .min_shard_log_size = 4,
            .max_shard_log_size = 4,
            .log_blowup_factor = 1,
            .retention_policy = .never,
            .host_byte_budget = 1 << 30,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        };
        var provider_plan = try native_provider.ProviderShardPlanV1.create(
            allocator,
            sha(seed),
            &calls,
            request,
        );
        errdefer provider_plan.deinit(allocator);
        if (provider_plan.shard_count != 1)
            return error.InvalidH1ProviderFixture;
        const relation = try native_provider.PoseidonRelationContextV1
            .canonical(
            provider_plan.session,
            QM31.fromU32Unchecked(11, 12, 13, 14),
            QM31.fromU32Unchecked(21, 22, 23, 24),
        );
        const shard_claim = native_provider.ProviderShardClaimV1{
            .plan_identity = provider_plan.identity,
            .descriptor_identity = provider_plan.shards[0].identity,
            .shard_index = 0,
            .relation_context_identity = relation.identity,
            .claims = .{ .sums = .{
                QM31.fromU32Unchecked(1, 0, 0, 0),
                QM31.zero(),
            } },
        };
        const core_claim = native_provider.CorePoseidonClaimV1{
            .plan_identity = provider_plan.identity,
            .relation_context_identity = relation.identity,
            .claim = shard_claim.claims.total().neg(),
        };
        const shard_artifact = try provider_bridge.ShardArtifactV1
            .initFromFreshVerifier(.{
            .ordinal = 0,
            .proof_artifact_sha256 = sha(seed + 1),
            .proof_root_sha256 = sha(seed + 2),
            .proof_capture_sha256 = sha(seed + 3),
            .capture_identity = sha(seed + 4),
            .air_program_identity = sha(seed + 5),
            .verifier_program_authority = sha(seed + 6),
            .protocol_profile_sha256 = sha(seed + 7),
            .preprocessed_commitment_root = scalarDigest(seed + 8),
        }, shard_claim);
        return .{
            .allocator = allocator,
            .calls = calls,
            .provider_plan = provider_plan,
            .residency_request = request,
            .residency_plan = try residency.create(request),
            .relation = relation,
            .core_claim = core_claim,
            .shard_claims = .{shard_claim},
            .shard_artifacts = .{shard_artifact},
            .entry_continuation_root = metadata.entry.continuation_root,
            .exit_continuation_root = metadata.exit.continuation_root,
            .core_proof_artifact_sha256 = descriptor.proof_artifact_sha256,
            .core_proof_capture_sha256 = descriptor.program.proof_capture_sha256,
            .core_capture_identity = descriptor.program.capture_identity,
        };
    }

    fn deinit(self: *ProviderFixtureV1) void {
        self.provider_plan.deinit(self.allocator);
        self.* = undefined;
    }

    fn input(self: *ProviderFixtureV1) provider_bridge.CompilerInputV1 {
        return .{
            .entry_continuation_root = self.entry_continuation_root,
            .exit_continuation_root = self.exit_continuation_root,
            .core_proof_artifact_sha256 = self.core_proof_artifact_sha256,
            .core_proof_capture_sha256 = self.core_proof_capture_sha256,
            .core_capture_identity = self.core_capture_identity,
            .residency_request = self.residency_request,
            .residency_plan = self.residency_plan,
            .provider_plan = &self.provider_plan,
            .calls = &self.calls,
            .relation = self.relation,
            .core_claim = self.core_claim,
            .shard_claims = &self.shard_claims,
            .shard_artifacts = &self.shard_artifacts,
        };
    }
};

fn secureProfile() !node_profile.NodeProfileV1 {
    return node_profile.NodeProfileV1.initWithManifests(
        .real_parent_h1,
        1,
        digest("h1-secure-parent-vk"),
        digest("h1-secure-parent-next-vk"),
        sha(901),
        try h1_manifest.contractIdentity(),
        digest("h1-secure-parent-air"),
        digest("h1-secure-parent-profile"),
        proof_security.ProofSecurityV1.ethereumSegmentV3Poseidon2(),
        proof_security.ProofSecurityV1.recursiveParentSecure(),
        child_transcript.DescriptorV1.temporalParentV3(),
    );
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

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4831_5350); // "H1SP"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn sha(seed: u32) [32]u8 {
    var result = [_]u8{0} ** 32;
    std.mem.writeInt(u32, result[0..4], seed, .little);
    result[4] = 1;
    return result;
}
