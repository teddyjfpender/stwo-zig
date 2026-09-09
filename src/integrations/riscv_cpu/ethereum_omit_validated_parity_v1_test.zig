//! Proving parity between the validated and unvalidated omission routes.
//!
//! Every `...Validated` sibling on the Ethereum provider-omission path swaps
//! one `ProviderShardPlanV1.validate(calls)` corpus rehash for an O(1)
//! pointer-closed readmission of an already minted
//! `OwnedValidatedPlanCallAuthorityV1`. The graft is meant to be strictly a
//! validation change, so this gate runs the *same* fixture through both routes
//! and requires that nothing observable moves:
//!
//! - identical Stage-A commitment roots and Stage-A manifest identity,
//! - identical omitted-core prove output (proof bytes, statement authority id,
//!   extension claim, prover residual, projection identity),
//! - identical `SharedRelationAuthorityV1`,
//! - identical fresh-verify residual and fresh-core residual,
//! - identical degree-five shard statements and shard proof bytes,
//! - identical fresh shard claims and aggregate closure identity,
//! - one full corpus validation per side (the token is minted once and every
//!   later readmission is a pointer check).
//!
//! Deliberately *not* compared: any encoded artifact. A projected core has no
//! canonical SegmentV2 envelope -- the ordinary codec re-runs
//! `ethereum_proof_admission.validateV2`, whose geometry check requires the
//! very `.poseidon2` descriptor this projection removes. The comparison stops
//! at the prove outputs and the closure, which is exactly where the identity
//! claim lives.
//!
//! The cheap fixture PCS config (`pow_bits = 0`, three queries) is used on
//! purpose: the graft is transcript- and config-agnostic, and both arms share
//! one config, so a divergence would show up at any query count.

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

/// One arm's observable prove output, reduced to values that can be compared
/// without touching an encoder.
const ArmSummary = struct {
    proof_digest: [32]u8,
    statement_authority_id: global_channel.Digest,
    n_infra: usize,
    projected_main_columns: usize,
    projection_identity: provider_authority.Digest,
    shared: provider_protocol.SharedRelationAuthorityV1(Engine),
    fresh_core: provider_protocol.FreshCoreResidualV1,
    prover_residual: stwo_core.fields.qm31.QM31,
    fresh_verifier_residual: stwo_core.fields.qm31.QM31,
    shard_statements: []degree5_omit_proof.ProviderStatementV1,
    shard_proof_digests: [][32]u8,
    fresh_shards: []degree5_omit_proof.FreshDegree5ProviderClaimV1,
    closure: provider_protocol.VerifiedJointClosureV1,
    strategy: degree5_omit_proof.FreshStrategyV1,
    /// The validated arm's token receipt. `null` on the unvalidated arm, which
    /// mints no token and so has nothing to account for.
    work_receipt: ?provider_authority.OwnedValidatedPlanCallAuthorityV1
        .WorkReceiptV1,

    fn deinit(self: *ArmSummary, allocator: std.mem.Allocator) void {
        allocator.free(self.shard_statements);
        allocator.free(self.shard_proof_digests);
        allocator.free(self.fresh_shards);
        self.* = undefined;
    }
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

    const initial = try machineState(
        first.base.entry_cpu,
        digest("omit-parity-rw-entry"),
        digest("omit-parity-io-entry"),
    );
    const shared_state = try machineState(
        first.base.exit_cpu,
        digest("omit-parity-rw-shared"),
        digest("omit-parity-io-shared"),
    );
    const final = try machineState(
        second.base.exit_cpu,
        digest("omit-parity-rw-exit"),
        digest("omit-parity-io-exit"),
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
            digest("omit-parity-input"),
            digest("omit-parity-output"),
            total_cycles,
        ),
        2,
    );
    const global_statement = try leafStatement(
        job,
        &first.base,
        initial,
        shared_state,
        try span.EdgeClaim.present(digest("omit-parity-input")),
        span.EdgeClaim.absent(),
    );
    const global_source = try global_v3.SourceV3.fromSegmentResult(
        global_statement,
        &first.base,
    );
    var projection = try projection_v3.ProjectionV3.init(&global_source);
    const local_source = try projection.sourceV2(
        &global_source,
        digest("omit-parity-session"),
    );
    const words = try encodeSegment(allocator, &local_source);
    defer allocator.free(words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        words,
    );

    // One corpus, one plan, one Stage-A program: the only difference between
    // the two arms below is whether the corpus is readmitted by rehash or by
    // the O(1) token.
    var call_authority = try prover.buildEthereumSegmentProviderCallAuthorityV1(
        allocator,
        &projection.local_result,
        &first.keccakf_calls,
        &first.keccakf_execution_rows,
        &first.signer_recovery_calls,
        &first.signer_recovery_execution_rows,
        public_data,
    );
    defer call_authority.deinit();
    const call_count: u64 = @intCast(call_authority.calls.len);
    const max_log = @max(@as(u32, 4), std.math.log2_int_ceil(u64, call_count));
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

    var token = try provider_authority.OwnedValidatedPlanCallAuthorityV1.init(
        allocator,
        &plan,
        call_authority.calls,
    );
    defer token.deinit();
    const minted = token.workReceipt();
    try minted.validate();
    try std.testing.expectEqual(@as(u64, 1), minted.full_corpus_validations);

    var plain = try proveArm(
        allocator,
        &projection.local_result,
        &first,
        public_data,
        &plan,
        call_authority.calls,
        null,
    );
    defer plain.deinit(allocator);
    var fast = try proveArm(
        allocator,
        &projection.local_result,
        &first,
        public_data,
        &plan,
        call_authority.calls,
        &token,
    );
    defer fast.deinit(allocator);

    // The validated arm pays for exactly one full corpus hash -- the mint --
    // and every readmission after it is a pointer check. The unvalidated arm
    // mints nothing, so it carries no receipt; its cost is the per-shard,
    // per-side rehash this graft removes. The counter must actually have
    // moved: a silent fallback to the slow path would leave it where the mint
    // left it.
    try std.testing.expect(plain.work_receipt == null);
    const receipt = fast.work_receipt orelse
        return error.MissingValidatedProviderWorkReceipt;
    try receipt.validate();
    try std.testing.expectEqual(@as(u64, 1), receipt.full_corpus_validations);
    try std.testing.expect(
        receipt.fast_pointer_checks > minted.fast_pointer_checks,
    );

    try expectArmParity(&plain, &fast);
}

/// Runs one complete omission arm. `validated` selects the route: `null` keeps
/// the historical rehash, a token takes the O(1) readmission everywhere.
fn proveArm(
    allocator: std.mem.Allocator,
    result: *const frontend.runner.SegmentResult,
    segment: anytype,
    public_data: frontend.air.public_data_v2.PublicDataV2,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const frontend.air.memory_commitment.poseidon2_air.Call,
    validated: ?*const provider_authority.OwnedValidatedPlanCallAuthorityV1,
) !ArmSummary {
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
        roots.* = if (validated) |token|
            try degree5_omit_proof.commitStageAValidatedV1(
                Engine,
                allocator,
                test_config,
                degree5_program,
                plan,
                calls,
                token,
                @intCast(index),
            )
        else
            try degree5_omit_proof.commitStageAV1(
                Engine,
                allocator,
                test_config,
                degree5_program,
                plan,
                calls,
                @intCast(index),
            );
    }
    var owned_stage_a = if (validated) |token|
        try provider_protocol.ProviderStageAManifestV1(Engine)
            .createFromRootsValidated(
            allocator,
            plan,
            calls,
            token,
            provider_roots,
        )
    else
        try provider_protocol.ProviderStageAManifestV1(Engine).createFromRoots(
            allocator,
            plan,
            calls,
            provider_roots,
        );
    defer owned_stage_a.deinit(allocator);
    const provider_stage_a = owned_stage_a.manifest;

    var prove_extension = if (validated) |token|
        try provider_protocol.Extension(Engine).initValidated(
            plan,
            calls,
            token,
            &provider_stage_a,
        )
    else
        try provider_protocol.Extension(Engine).init(
            plan,
            calls,
            &provider_stage_a,
        );
    var prove_channel = Engine.Channel{};
    var output = try prover
        .proveEthereumSegmentWithEngineUsingChannelAndExecutionAndNativeProviderOmission(
        Engine,
        allocator,
        test_config,
        result,
        &segment.keccakf_calls,
        &segment.keccakf_execution_rows,
        &segment.signer_recovery_calls,
        &segment.signer_recovery_execution_rows,
        null,
        public_data,
        &prove_channel,
        prover.guest_precompile.ethereum_segment_orchestration.sequential_execution,
        &prove_extension,
    );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    const core_projection = try prove_extension.providerProjection();
    try core_projection.validateSealAndFull(&output.statement, &output.extension);
    const proof_digest = proofDigest(Engine, output.proof);

    var verify_extension = if (validated) |token|
        try provider_protocol.Extension(Engine).initForFreshVerifyValidated(
            plan,
            calls,
            token,
            &provider_stage_a,
            prove_extension.shared_relation orelse
                return error.MissingEthereumProviderSharedAuthority,
        )
    else
        try provider_protocol.Extension(Engine).initForFreshVerify(
            plan,
            calls,
            &provider_stage_a,
            prove_extension.shared_relation orelse
                return error.MissingEthereumProviderSharedAuthority,
        );
    var verify_channel = Engine.Channel{};
    proof_moved = true;
    try prover.verifyEthereumSegmentWithEngineUsingChannelAndNativeProviderOmission(
        Engine,
        allocator,
        test_config,
        output.statement,
        output.extension,
        output.proof,
        output.base_claim,
        &output.extension_claim,
        &verify_channel,
        &verify_extension,
    );

    const shared = verify_extension.shared_relation orelse
        return error.MissingEthereumProviderSharedAuthority;
    const fresh_core = verify_extension.fresh_core orelse
        return error.MissingEthereumProviderFreshCore;
    const verified_projection = try verify_extension.providerProjection();
    var lookup_manifest = frontend.air.lookup_physical_manifest_v2
        .Manifest.native();
    const authenticated = try frontend.air.lookup_physical_manifest_v2
        .AuthenticatedStatement.init(&output.statement.core, &lookup_manifest);
    const source = provider_omit_proof.Source(Engine){
        .native = &output.statement,
        .extension = &output.extension,
        .lookup_manifest = &lookup_manifest,
        .authenticated_lookup = &authenticated,
        .projection = verified_projection,
        .plan = plan,
        .calls = calls,
        .provider_stage_a = &provider_stage_a,
        .shared = shared,
        .validated_calls = validated,
    };
    try source.validate();

    const shard_statements = try allocator.alloc(
        degree5_omit_proof.ProviderStatementV1,
        plan.shards.len,
    );
    errdefer allocator.free(shard_statements);
    const shard_proof_digests = try allocator.alloc([32]u8, plan.shards.len);
    errdefer allocator.free(shard_proof_digests);
    const fresh_shards = try allocator.alloc(
        degree5_omit_proof.FreshDegree5ProviderClaimV1,
        plan.shards.len,
    );
    errdefer allocator.free(fresh_shards);
    for (fresh_shards, shard_statements, shard_proof_digests, 0..) |
        *fresh,
        *statement_out,
        *digest_out,
        index,
    | {
        const shard_output = try degree5_omit_proof.proveProviderV1(
            Engine,
            allocator,
            test_config,
            degree5_program,
            degree5_execution,
            source,
            @intCast(index),
        );
        statement_out.* = shard_output.statement;
        digest_out.* = proofDigest(Engine, shard_output.proof);
        fresh.* = try degree5_omit_proof.verifyProviderFreshV1(
            Engine,
            allocator,
            test_config,
            degree5_program,
            degree5_execution,
            source,
            shard_output.statement,
            shard_output.proof,
        );
    }
    const closed = try degree5_omit_proof.closeFreshClaimsV1(
        Engine,
        allocator,
        degree5_program,
        degree5_execution,
        source,
        fresh_core,
        fresh_shards,
    );
    try closed.closure.validate();
    try closed.strategy.validate();

    return .{
        .proof_digest = proof_digest,
        .statement_authority_id = output.statement.authority_id,
        .n_infra = output.base_claim.n_infra,
        .projected_main_columns = core_projection.projected_native.core
            .nMainColumns(),
        .projection_identity = core_projection.identity,
        .shared = shared,
        .fresh_core = fresh_core,
        .prover_residual = prove_extension.prover_residual orelse
            return error.MissingEthereumProviderProverResidual,
        .fresh_verifier_residual = verify_extension.fresh_verifier_residual orelse
            return error.MissingEthereumProviderFreshResidual,
        .shard_statements = shard_statements,
        .shard_proof_digests = shard_proof_digests,
        .fresh_shards = fresh_shards,
        .closure = closed.closure,
        .strategy = closed.strategy,
        .work_receipt = if (validated) |token| token.workReceipt() else null,
    };
}

fn expectArmParity(plain: *const ArmSummary, fast: *const ArmSummary) !void {
    try std.testing.expectEqualSlices(
        u8,
        &plain.proof_digest,
        &fast.proof_digest,
    );
    try std.testing.expectEqualSlices(
        u32,
        &plain.statement_authority_id,
        &fast.statement_authority_id,
    );
    try std.testing.expectEqual(plain.n_infra, fast.n_infra);
    try std.testing.expectEqual(
        plain.projected_main_columns,
        fast.projected_main_columns,
    );
    try std.testing.expectEqualSlices(
        u8,
        &plain.projection_identity,
        &fast.projection_identity,
    );
    try std.testing.expect(std.meta.eql(plain.shared, fast.shared));
    try std.testing.expect(std.meta.eql(plain.fresh_core, fast.fresh_core));
    try std.testing.expect(plain.prover_residual.eql(fast.prover_residual));
    try std.testing.expect(
        plain.fresh_verifier_residual.eql(fast.fresh_verifier_residual),
    );
    try std.testing.expectEqual(
        plain.shard_statements.len,
        fast.shard_statements.len,
    );
    try std.testing.expect(plain.shard_statements.len > 0);
    for (
        plain.shard_statements,
        fast.shard_statements,
        plain.shard_proof_digests,
        fast.shard_proof_digests,
        plain.fresh_shards,
        fast.fresh_shards,
    ) |
        left_statement,
        right_statement,
        left_digest,
        right_digest,
        left_fresh,
        right_fresh,
    | {
        try std.testing.expect(std.meta.eql(left_statement, right_statement));
        try std.testing.expectEqualSlices(u8, &left_digest, &right_digest);
        try std.testing.expect(std.meta.eql(left_fresh, right_fresh));
    }
    try std.testing.expect(std.meta.eql(plain.closure, fast.closure));
    try std.testing.expect(std.meta.eql(plain.strategy, fast.strategy));
    try std.testing.expect(plain.closure.closed_sum.isZero());
}

/// A total, order-sensitive digest of every byte a Stark proof carries.
///
/// The omitted core has no canonical artifact envelope, so this stands in for
/// "the proof bytes": two proofs share a digest only if every commitment,
/// sampled value, decommitment hash, queried value, proof-of-work nonce, and
/// FRI witness matches position for position.
fn proofDigest(
    comptime ProvingEngine: type,
    proof: stwo_core.proof.StarkProof(ProvingEngine.Hasher),
) [32]u8 {
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    const scheme = proof.commitment_scheme_proof;
    mixUsize(&hasher, scheme.config.pow_bits);
    mixUsize(&hasher, scheme.config.fri_config.log_blowup_factor);
    mixUsize(&hasher, scheme.config.fri_config.log_last_layer_degree_bound);
    mixUsize(&hasher, scheme.config.fri_config.n_queries);
    mixUsize(&hasher, scheme.proof_of_work);

    mixUsize(&hasher, scheme.commitments.items.len);
    for (scheme.commitments.items) |commitment| mixHash(&hasher, commitment);

    mixUsize(&hasher, scheme.sampled_values.items.len);
    for (scheme.sampled_values.items) |tree| {
        mixUsize(&hasher, tree.len);
        for (tree) |column| {
            mixUsize(&hasher, column.len);
            for (column) |value| mixQm31(&hasher, value);
        }
    }

    mixUsize(&hasher, scheme.decommitments.items.len);
    for (scheme.decommitments.items) |decommitment|
        mixDecommitment(&hasher, decommitment);

    mixUsize(&hasher, scheme.queried_values.items.len);
    for (scheme.queried_values.items) |tree| {
        mixUsize(&hasher, tree.len);
        for (tree) |column| {
            mixUsize(&hasher, column.len);
            for (column) |value| mixUsize(&hasher, value.v);
        }
    }

    mixLayer(&hasher, scheme.fri_proof.first_layer);
    mixUsize(&hasher, scheme.fri_proof.inner_layers.len);
    for (scheme.fri_proof.inner_layers) |layer| mixLayer(&hasher, layer);
    mixUsize(&hasher, scheme.fri_proof.last_layer_poly.log_size);
    mixUsize(&hasher, scheme.fri_proof.last_layer_poly.coeffs.len);
    for (scheme.fri_proof.last_layer_poly.coeffs) |value|
        mixQm31(&hasher, value);

    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

fn mixLayer(hasher: anytype, layer: anytype) void {
    mixHash(hasher, layer.commitment);
    mixUsize(hasher, layer.fri_witness.len);
    for (layer.fri_witness) |value| mixQm31(hasher, value);
    mixDecommitment(hasher, layer.decommitment);
}

fn mixDecommitment(hasher: anytype, decommitment: anytype) void {
    mixUsize(hasher, decommitment.hash_witness.len);
    for (decommitment.hash_witness) |value| mixHash(hasher, value);
}

fn mixHash(hasher: anytype, value: anytype) void {
    hasher.update(std.mem.asBytes(&value));
}

fn mixQm31(hasher: anytype, value: stwo_core.fields.qm31.QM31) void {
    for (value.toM31Array()) |limb| mixUsize(hasher, limb.v);
}

fn mixUsize(hasher: anytype, value: anytype) void {
    var buffer: [8]u8 = undefined;
    std.mem.writeInt(u64, &buffer, @intCast(value), .little);
    hasher.update(&buffer);
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
