//! Terminal nonproduction proof gate for the combined Ethereum candidate.
//!
//! A real combined session supplies the base/Keccak/recovery/bulk/SWAP tapes.
//! The leaf proof is postcarded, every producer-owned proof allocation is
//! destroyed, and a cold decoder feeds the independent candidate verifier.
//! The same fresh transcript authority then proves and closes every degree-5
//! provider shard. No digest or constructor substitutes for either proof.

const std = @import("std");
const stwo_core = @import("stwo_core");
const shard_planner = @import("stwo_prover_engine").pcs.residency_shard_plan;
const frontend = @import("stwo_riscv_frontend");
const support = @import("ethereum_block_leaf_support.zig");
const provider_batch_execution =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const provider_prepared_batch =
    @import("ethereum_candidate_degree5_provider_prepared_batch_v1.zig");
const provider_proof_batch =
    @import("ethereum_candidate_degree5_provider_proof_batch_v1.zig");

const prover = frontend.prover_mod;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const global_channel = frontend.recursion.poseidon2_channel;
const protocol = frontend.recursion.protocol;
const segment_v2 = frontend.recursion.segment_statement_v2;
const global_v3 = frontend.recursion.segment_leaf_local_authority_v3;
const projection_v3 = frontend.recursion.segment_leaf_local_projection_v3;
const span = frontend.recursion.span_statement;
const Engine = support.RecursiveEngine;
const candidate = prover.guest_precompile;
const candidate_orchestration =
    candidate.ethereum_candidate_leaf_orchestration_v1;
const candidate_artifact = candidate.ethereum_candidate_leaf_proof_artifact_v1;
const candidate_verifier = candidate.ethereum_candidate_leaf_verifier_v1;
const candidate_tree = candidate.ethereum_candidate_leaf_tree_v1;
const candidate_profile = candidate.ethereum_candidate_leaf_profile_v1;
const native_provider_omit = candidate.native_provider_omit_v1;
const candidate_protocol =
    frontend.testing.narrow_memory_provider_ethereum_candidate_protocol_v1;
const candidate_provider =
    frontend.testing.narrow_memory_provider_degree5_ethereum_candidate_v1;
const provider_protocol = prover.ethereum_native_provider_omit_protocol_v1;
const provider_authority = prover.memory_provider_shard_authority;
const bulk_harness = frontend.testing.bulk_memcpy_proof_harness_v1;
const bulk_trace = frontend.testing.bulk_memcpy_proof_trace_v1;
const bulk_component = frontend.testing.bulk_memcpy_proof_component_v1;
const bulk_relations = frontend.testing.bulk_memcpy_relations_v1;
const swap_trace = frontend.testing.stack_swap_proof_trace_v1;
const lookup_v2 = frontend.air.lookup_physical_manifest_v2;

test "combined candidate leaf postcards, cold verifies, and closes degree-five providers" {
    const allocator = std.testing.allocator;
    try bulk_harness.exerciseRetainedLdeParityForTest(allocator);
    const elf = frontend.testing.guest_precompile_test_elf
        .buildEthereumCombinedCandidate();
    const authority = try authorityForElf(&elf);
    const CandidateSession = frontend.testing
        .EthereumCombinedCandidateExecutionSessionV1();
    var session = try CandidateSession.initCandidate(
        allocator,
        &elf,
        .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local },
        authority,
    );
    defer session.deinit();
    var segment = try session.startSegment(24);
    defer segment.deinit();
    try segment.validateAgainst(authority, 0);
    try std.testing.expect(segment.ethereum.base.isComplete());
    try std.testing.expectEqual(@as(usize, 1), segment.bulk_memcpy.records().len);
    try std.testing.expectEqual(@as(usize, 1), segment.stack_swap.records().len);

    var bulk = try bulk_trace.generate(allocator, &segment.bulk_memcpy);
    defer bulk.deinit();
    var swap = try swap_trace.generate(allocator, &segment.stack_swap);
    defer swap.deinit();
    const candidate_witness = candidate_tree.CandidateWitness{
        .bulk_memcpy_tape = &segment.bulk_memcpy,
        .stack_swap_tape = &segment.stack_swap,
        .bulk_memcpy_trace = &bulk,
        .stack_swap_trace = &swap,
    };

    const decoder = try frontend.testing.ethereum_candidate_combined_decode_v1
        .DeclaredDecodeAuthority.init(authority);
    var program = try frontend.air.program.commitment
        .buildDeclaredWithDecodeAuthoritySources(
        allocator,
        decoder,
        .{
            segment.ethereum.base.execution_trace.rows.items,
            segment.ethereum.keccakf_execution_rows.rows(),
            segment.ethereum.signer_recovery_execution_rows.rows(),
            segment.bulk_memcpy.rows(),
            segment.stack_swap.rows(),
        },
        segment.ethereum.base.rw_memory.program_words,
        null,
    );
    defer program.deinit(allocator);

    const public_input = digest("candidate-leaf-input");
    const public_output = digest("candidate-leaf-output");
    const initial = try machineState(
        segment.ethereum.base.entry_cpu,
        digest("candidate-leaf-rw-entry"),
        digest("candidate-leaf-io-entry"),
    );
    const final = try machineState(
        segment.ethereum.base.exit_cpu,
        digest("candidate-leaf-rw-exit"),
        digest("candidate-leaf-io-exit"),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(program.tree.root),
            initial,
            final,
            public_input,
            public_output,
            @intCast(segment.ethereum.base.cycle_count),
        ),
        1,
    );
    const global_statement = try leafStatement(
        job,
        &segment.ethereum.base,
        initial,
        final,
        try span.EdgeClaim.present(public_input),
        try span.EdgeClaim.present(public_output),
    );
    const global_source = try global_v3.SourceV3.fromSegmentResult(
        global_statement,
        &segment.ethereum.base,
    );
    const global_metadata = try global_source.metadata();
    var projection = try projection_v3.ProjectionV3.init(&global_source);
    const local_source = try projection.sourceV2(
        &global_source,
        digest("candidate-leaf-session"),
    );
    const public_words = try encodeSegment(allocator, &local_source);
    defer allocator.free(public_words);
    const public_data = try frontend.air.public_data_v2.PublicDataV2.authenticate(
        public_words,
    );

    var wrong_local = projection.local_result;
    wrong_local.clock_frame = .leaf_local;
    try std.testing.expectError(
        error.ClockFrameMismatch,
        combinedLocalView(&segment, &wrong_local),
    );
    const local_candidate = try combinedLocalView(
        &segment,
        &projection.local_result,
    );
    var call_diagnostic: ?candidate_orchestration
        .ProviderCallAuthorityDiagnosticV1 = null;
    var call_authority = candidate_orchestration
        .buildProviderCallAuthorityDiagnosedV1(
        allocator,
        &local_candidate,
        authority,
        public_data,
        &call_diagnostic,
    ) catch |err| {
        const observed = call_diagnostic orelse
            return error.MissingCandidateProviderCallDiagnostic;
        std.debug.print(
            "candidate-provider-call phase={s} cause={s}\n",
            .{ @tagName(observed.phase), @errorName(observed.cause) },
        );
        return err;
    };
    defer call_authority.deinit();
    const call_count: u64 = @intCast(call_authority.calls.len);
    const provider_log = @max(
        @as(u32, 4),
        std.math.log2_int_ceil(u64, call_count),
    );
    var plan = try provider_authority.ProviderShardPlanV1.create(
        allocator,
        [_]u8{0xc5} ** 32,
        call_authority.calls,
        shard_planner.Request{
            .logical_row_count = call_count,
            .column_count = provider_authority.main_column_count,
            .min_shard_log_size = 4,
            .max_shard_log_size = provider_log,
            .log_blowup_factor = support.recursive_pcs_config.fri_config.log_blowup_factor,
            .retention_policy = .always,
            .host_byte_budget = 1024 * 1024 * 1024,
            .reserved_host_bytes = 0,
            .requested_parallel_shards = 1,
        },
    );
    defer plan.deinit(allocator);
    const degree5_program = try candidate_provider.VerifierProgramAuthorityV2
        .coldCompile(allocator);
    const provider_host = try provider_batch_execution.HostCapacityV1.init(
        4,
        1024 * 1024 * 1024,
    );
    const provider_execution = try provider_batch_execution.AuthorityV1
        .initAgainstPlan(provider_host, &plan, .{
        .concurrent_owners = 1,
        .engine_workers_per_owner = 1,
        .total_host_byte_budget = 1024 * 1024 * 1024,
        .controller_reserve_bytes = 64 * 1024 * 1024,
    });
    const degree5_execution = try provider_execution.executionProfile(
        degree5_program,
    );
    var prepared_stage_a = try provider_prepared_batch.prepareParallel(
        Engine,
        allocator,
        support.recursive_pcs_config,
        degree5_program,
        &plan,
        call_authority.calls,
        &provider_execution,
    );
    defer prepared_stage_a.deinit();
    var owned_stage_a = try provider_protocol.ProviderStageAManifestV1(Engine)
        .createFromRoots(
        allocator,
        &plan,
        call_authority.calls,
        prepared_stage_a.roots(),
    );
    defer owned_stage_a.deinit(allocator);
    const stage_a = owned_stage_a.manifest;

    var transcript_extension = try candidate_protocol.Extension(Engine)
        .initDerivedForProver(
        &plan,
        call_authority.calls,
        &stage_a,
        authority,
        @intCast(segment.bulk_memcpy.records().len),
        @intCast(segment.bulk_memcpy.wordRows().len),
        @intCast(segment.stack_swap.records().len),
    );
    const execution_authority = candidate_orchestration
        .MatchedAbExecutionAuthority.canonical();
    var prove_channel = Engine.Channel{};
    var prove_diagnostic: ?candidate_orchestration.CandidateProveDiagnosticV1 =
        null;
    var output = candidate_orchestration
        .proveWithEngineUsingChannelAndMatchedAbExecutionDiagnosed(
        Engine,
        allocator,
        support.recursive_pcs_config,
        &projection.local_result,
        &segment.ethereum.keccakf_calls,
        &segment.ethereum.keccakf_execution_rows,
        &segment.ethereum.signer_recovery_calls,
        &segment.ethereum.signer_recovery_execution_rows,
        candidate_witness,
        authority,
        null,
        public_data,
        &prove_channel,
        execution_authority,
        .{ .concurrent_owners = 1, .engine_workers_per_owner = 4 },
        &transcript_extension,
        &prove_diagnostic,
    ) catch |err| {
        const observed = prove_diagnostic orelse
            return error.MissingCandidateProveDiagnostic;
        std.debug.print(
            "candidate-leaf-prove phase={s} cause={s}",
            .{ @tagName(observed.phase), @errorName(observed.cause) },
        );
        if (observed.engine) |engine| {
            std.debug.print(
                " engine_phase={s} engine_cause={s}",
                .{ @tagName(engine.phase), @errorName(engine.cause) },
            );
            if (engine.composition_subphase) |subphase| {
                std.debug.print(
                    " engine_composition_subphase={s}",
                    .{@tagName(subphase)},
                );
            }
            if (engine.evaluation) |evaluation| {
                std.debug.print(
                    " engine_evaluation_stage={s}" ++
                        " component={any} tree={any} column={any}" ++
                        " actual={any} expected={any}",
                    .{
                        @tagName(evaluation.stage),
                        evaluation.component_index,
                        evaluation.tree_index,
                        evaluation.column_index,
                        evaluation.actual,
                        evaluation.expected,
                    },
                );
            }
        }
        std.debug.print("\n", .{});
        return err;
    };
    var output_live = true;
    defer if (output_live) output.deinit(allocator);
    const expected_shared = output.shared_relation;
    const projected = try diagnosePostProve(
        "provider_projection",
        transcript_extension.providerProjection(),
    );
    const encoded = try diagnosePostProve(
        "artifact_encode",
        candidate_artifact.encodeAlloc(
            Engine,
            allocator,
            .{
                .pcs_config = support.recursive_pcs_config,
                .security_identity_sha256 = support.recursive_security_identity,
                .full_statement = &output.statement,
                .projected_statement = &projected.projected_native,
                .extension = &output.extension,
                .global = &global_metadata,
                .profile = &output.profile,
                .base_claim = output.base_claim,
                .interaction_claims = &output.interaction_claims,
                .proof = &output.proof,
            },
            support.artifact_limits,
        ),
    );
    defer allocator.free(encoded);

    // The verifier must receive no producer-owned proof or claim allocation.
    output.deinit(allocator);
    output_live = false;
    var decoded = try diagnosePostProve(
        "artifact_decode",
        candidate_artifact.decodeAlloc(
            Engine,
            allocator,
            encoded,
            support.recursive_pcs_config,
            support.recursive_security_identity,
            support.artifact_limits,
        ),
    );
    var decoded_proof_moved = false;
    defer if (decoded_proof_moved)
        decoded.deinitAfterProofMoved(allocator)
    else
        decoded.deinit(allocator);

    var capture: candidate_verifier.FreshVerifiedCandidateLeafCaptureV1(
        Engine,
    ) = undefined;
    decoded_proof_moved = true;
    try diagnosePostProve(
        "fresh_verify",
        candidate_verifier.verifyWithEngineAndCapture(
            Engine,
            allocator,
            support.recursive_pcs_config,
            decoded.full_statement,
            decoded.extension,
            decoded.proof,
            decoded.base_claim,
            &decoded.interaction_claims,
            &decoded.profile,
            &plan,
            call_authority.calls,
            &stage_a,
            expected_shared,
            &capture,
        ),
    );
    defer capture.deinit(allocator);
    try diagnosePostProve("capture_validate", capture.validate());
    try diagnosePostProve(
        "profile_mutations",
        assertProfileMutationsRejected(
            &capture,
            &plan,
            call_authority.calls,
        ),
    );
    try diagnosePreProviderCancellation(
        &capture,
        call_authority.calls,
        provider_log,
        segment.bulk_memcpy.wordRows(),
    );

    var manifest = lookup_v2.Manifest.native();
    const authenticated = try diagnosePostProve(
        "authenticated_lookup",
        lookup_v2.AuthenticatedStatement.init(
            &capture.full_statement.core,
            &manifest,
        ),
    );
    const provider_source = candidate_provider.Source(Engine){
        .native = &capture.full_statement,
        .extension = &capture.extension_statement,
        .lookup_manifest = &manifest,
        .authenticated_lookup = &authenticated,
        .projection = &capture.projection,
        .profile = &capture.profile,
        .plan = &plan,
        .calls = call_authority.calls,
        .provider_stage_a = &stage_a,
        .shared = capture.provider_shared_authority,
    };
    const fresh_core = try diagnosePostProve(
        "fresh_core_capture",
        candidate_provider.FreshCandidateCoreResidualV1
            .captureAfterFreshCandidateVerification(
            provider_source,
            capture.fresh_core,
            capture.interaction_claims.candidate,
        ),
    );
    var provider_proofs = try provider_proof_batch.provePreparedParallel(
        Engine,
        allocator,
        support.recursive_pcs_config,
        degree5_program,
        degree5_execution,
        provider_source,
        &prepared_stage_a,
        &provider_execution,
    );
    defer provider_proofs.deinit();
    var fresh_provider_batch = try provider_proof_batch.verifyFreshParallel(
        Engine,
        allocator,
        support.recursive_pcs_config,
        degree5_program,
        degree5_execution,
        provider_source,
        &provider_proofs,
        &provider_execution,
    );
    defer fresh_provider_batch.deinit();
    const fresh_providers = fresh_provider_batch.claims;
    const closed = try diagnoseJointClose(
        expected_shared,
        provider_source,
        fresh_core,
        fresh_providers,
        candidate_provider.closeFreshClaimsV2(
            Engine,
            allocator,
            degree5_program,
            degree5_execution,
            provider_source,
            fresh_core,
            fresh_providers,
        ),
    );
    try diagnosePostProve(
        "closure_validate",
        closed.closure.validateAgainst(
            provider_source,
            fresh_core,
            fresh_providers,
        ),
    );
    try diagnosePostProve(
        "strategy_validate",
        closed.strategy.validateAgainst(provider_source, closed.closure),
    );
    try std.testing.expect(closed.closure.ordinary.closed_sum.isZero());
    try std.testing.expect(!closed.closure.production_eligible);
    try std.testing.expect(!closed.closure.recursive_admissible);
}

fn diagnosePreProviderCancellation(
    capture: anytype,
    calls: []const poseidon2_air.Call,
    provider_log: u32,
    bulk_word_rows: anytype,
) !void {
    const provider_claim = try poseidonClaimsFromCalls(
        calls,
        provider_log,
        &capture.relations.ethereum.base,
    );

    const public_boundary = capture.projected_base.native_public_sums.total;
    var projected_base = QM31.zero();
    for (capture.projected_base.vm_air.canonical_claims) |claim|
        projected_base = projected_base.add(claim);
    const ethereum = capture.interaction_claims.ethereum.componentSum();
    const candidate_claims = capture.interaction_claims.candidate;
    const candidate_total = candidate_claims.componentSum();
    const ordinary = public_boundary.add(projected_base).add(ethereum);
    const recomposed_core = ordinary.add(candidate_total);
    const provider = provider_claim.total();
    const closed = recomposed_core.add(provider);
    const replayed_bulk_word_batches = try replayedBulkWordBatches(
        bulk_word_rows,
        &capture.relations.bulk_memcpy,
    );
    for (
        replayed_bulk_word_batches,
        candidate_claims.bulk_memcpy_words.batch_sums,
    ) |replayed, captured| {
        if (!replayed.eql(captured))
            return error.BulkMemcpyWordClaimReplayMismatch;
    }
    if (!recomposed_core.eql(capture.fresh_core.poseidon2_residual) or
        !closed.isZero())
    {
        std.debug.print(
            "candidate-leaf-cancellation-decomposition" ++
                " public={any} projected_base={any} ethereum={any}\n" ++
                "  ordinary={any} candidate={any} core={any}" ++
                " captured_core={any}\n" ++
                "  provider_batch0={any} provider_batch1={any}" ++
                " provider_direct={any} closed={any}\n",
            .{
                qm31Words(public_boundary),
                qm31Words(projected_base),
                qm31Words(ethereum),
                qm31Words(ordinary),
                qm31Words(candidate_total),
                qm31Words(recomposed_core),
                qm31Words(capture.fresh_core.poseidon2_residual),
                qm31Words(provider_claim.sums[0]),
                qm31Words(provider_claim.sums[1]),
                qm31Words(provider),
                qm31Words(closed),
            },
        );
        printCandidateClaim(
            "bulk_caller",
            candidate_claims.bulk_memcpy_caller,
        );
        printCandidateClaim(
            "bulk_words",
            candidate_claims.bulk_memcpy_words,
        );
        printCandidateClaim(
            "swap_caller",
            candidate_claims.stack_swap_caller,
        );
        printCandidateClaim(
            "swap_words",
            candidate_claims.stack_swap_words,
        );
        if (!recomposed_core.eql(capture.fresh_core.poseidon2_residual))
            return error.CandidateLeafResidualDecompositionMismatch;
        return error.PoseidonRelationNotClosed;
    }
}

fn replayedBulkWordBatches(
    rows: anytype,
    relations: *const bulk_relations.Relations,
) ![bulk_component.Word.batch_count]QM31 {
    var sums = [_]QM31{QM31.zero()} ** bulk_component.Word.batch_count;
    for (rows) |row| {
        const main = row.encode();
        const pairs = bulk_component.wordRowPairs(M31, &main, relations);
        const events = try row.memoryEvents();
        if (!pairs[0].d1.eql(memoryDenominator(events[0].request, relations)) or
            !pairs[0].d2.eql(memoryDenominator(events[1].emit, relations)) or
            !pairs[1].d1.eql(memoryDenominator(events[2].request, relations)) or
            !pairs[1].d2.eql(memoryDenominator(events[3].emit, relations)))
        {
            return error.BulkMemcpyWordAddressRelationMismatch;
        }
        for (pairs, 0..) |pair, index| sums[index] = sums[index].add(
            try rowPairValue(pair),
        );
    }
    return sums;
}

fn memoryDenominator(
    event: frontend.testing.bulk_memcpy_word_candidate_v1.MemoryTuple,
    relations: *const bulk_relations.Relations,
) QM31 {
    return bulk_relations.combine(
        M31,
        relations.base.memory_access,
        [7]M31{
            M31.fromCanonical(event.address_space),
            M31.fromCanonical(event.address),
            M31.fromCanonical(event.clock),
            M31.fromCanonical(event.bytes[0]),
            M31.fromCanonical(event.bytes[1]),
            M31.fromCanonical(event.bytes[2]),
            M31.fromCanonical(event.bytes[3]),
        },
    );
}

fn rowPairValue(pair: anytype) !QM31 {
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(denominator.inv() catch return error.ZeroDenominator);
}

fn poseidonClaimsFromCalls(
    calls: []const poseidon2_air.Call,
    log_size: u32,
    relations: anytype,
) !poseidon2_air.Claims {
    if (log_size >= @bitSizeOf(usize) or
        calls.len > (@as(usize, 1) << @intCast(log_size)))
    {
        return error.InvalidTraceShape;
    }
    var result = poseidon2_air.Claims{
        .sums = [_]QM31{QM31.zero()} ** poseidon2_air.N_SUMS,
    };
    for (calls) |call| {
        const pairs = poseidon2_air.rowPairsFromCall(call, relations);
        for (pairs, 0..) |pair, index| {
            result.sums[index] = result.sums[index].add(try rowPairValue(pair));
        }
    }
    return result;
}

fn printCandidateClaim(comptime label: []const u8, claim: anytype) void {
    std.debug.print(
        "  candidate_component={s} component_sum={any}" ++
            " log_size={d} rows={d}\n",
        .{ label, qm31Words(claim.component_sum), claim.log_size, claim.n_rows },
    );
    for (claim.batch_sums, 0..) |sum, index| {
        std.debug.print(
            "    batch[{d}]={any}\n",
            .{ index, qm31Words(sum) },
        );
    }
}

fn diagnoseJointClose(
    expected_shared: anytype,
    source: anytype,
    core: anytype,
    providers: anytype,
    result: anytype,
) @TypeOf(result) {
    return result catch |err| {
        var provider_sum = QM31.zero();
        std.debug.print(
            "candidate-leaf-post-prove stage=joint_close cause={s}\n" ++
                "  expected_shared={any} source_shared={any}\n" ++
                "  expected_relation={any} source_relation={any}\n" ++
                "  plan={any} call_list={any} shards={d} providers={d}\n" ++
                "  core={any}\n",
            .{
                @errorName(err),
                expected_shared.identity,
                source.shared.identity,
                expected_shared.relation_context.identity,
                source.shared.relation_context.identity,
                source.plan.identity,
                source.plan.call_list_commitment,
                source.plan.shards.len,
                providers.len,
                qm31Words(core.ordinary.poseidon2_residual),
            },
        );
        for (providers, 0..) |provider, index| {
            if (index >= source.plan.shards.len) break;
            const descriptor = source.plan.shards[index];
            const native = provider.provider.provider.native_claim;
            const claim = native.claims.total();
            provider_sum = provider_sum.add(claim);
            std.debug.print(
                "  shard[{d}] claim_index={d} descriptor={any}" ++
                    " first_call={d} call_count={d} claim={any}\n",
                .{
                    index,
                    native.shard_index,
                    descriptor.identity,
                    descriptor.first_call,
                    descriptor.call_count,
                    qm31Words(claim),
                },
            );
        }
        std.debug.print(
            "  provider={any} closed={any} candidate_components={any}\n",
            .{
                qm31Words(provider_sum),
                qm31Words(core.ordinary.poseidon2_residual.add(provider_sum)),
                qm31Words(core.candidate_claims.componentSum()),
            },
        );
        return err;
    };
}

fn qm31Words(value: QM31) [4]u32 {
    const limbs = value.toM31Array();
    return .{ limbs[0].v, limbs[1].v, limbs[2].v, limbs[3].v };
}

fn diagnosePostProve(comptime stage: []const u8, result: anytype) @TypeOf(result) {
    return result catch |err| {
        std.debug.print(
            "candidate-leaf-post-prove stage={s} cause={s}\n",
            .{ stage, @errorName(err) },
        );
        return err;
    };
}

fn diagnosePostProveIndexed(
    comptime stage: []const u8,
    index: usize,
    result: anytype,
) @TypeOf(result) {
    return result catch |err| {
        std.debug.print(
            "candidate-leaf-post-prove stage={s} index={d} cause={s}\n",
            .{ stage, index, @errorName(err) },
        );
        return err;
    };
}

fn assertProfileMutationsRejected(
    capture: anytype,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: anytype,
) !void {
    var manifest = lookup_v2.Manifest.native();
    const authenticated = try lookup_v2.AuthenticatedStatement.init(
        &capture.projection.projected_native.core,
        &manifest,
    );
    const base_columns: u32 = @intCast(
        try authenticated.totalInteractionColumns(
            &capture.projection.projected_native.core,
            &manifest,
        ),
    );
    const profile: candidate_profile.Profile = capture.profile;
    const candidate_retirements = try std.math.add(
        u32,
        profile.bulk_memcpy_call_count,
        profile.stack_swap_call_count,
    );
    try std.testing.expectEqual(
        candidate_retirements,
        capture.admission.candidate_retirements,
    );
    try std.testing.expectEqual(
        try std.math.add(
            u32,
            capture.extension_statement.counts.external_retirements,
            candidate_retirements,
        ),
        capture.admission.total_external_retirements,
    );
    try std.testing.expectEqual(
        capture.admission.total_external_retirements,
        capture.admission.retirementSupplementV2().rows,
    );
    var wrong_supplement = capture.admission.retirementSupplementV2();
    wrong_supplement.rows -= 1;
    try expectRejected(
        capture.projection.validateAgainstWithRetirementSupplementV2(
            &capture.full_statement,
            &capture.extension_statement,
            .proof,
            wrong_supplement,
            &manifest,
            &authenticated,
            plan,
            calls,
            try native_provider_omit.deriveFullGeometry(
                &capture.full_statement,
            ),
        ),
    );
    var changed_admission = capture.admission;
    changed_admission.total_external_retirements -= 1;
    try expectRejected(changed_admission.validateAgainst(
        &capture.projection.projected_native.core,
        &capture.extension_statement,
        base_columns,
        &profile,
    ));
    try expectRejected(profile.validate(
        &capture.projection.projected_native.core,
        &capture.extension_statement,
        base_columns + 1,
    ));

    var changed_extension = capture.extension_statement;
    changed_extension.components[0].main_columns += 1;
    try expectRejected(profile.validate(
        &capture.projection.projected_native.core,
        &changed_extension,
        base_columns,
    ));
    changed_extension = capture.extension_statement;
    std.mem.swap(
        @TypeOf(changed_extension.components[0]),
        &changed_extension.components[0],
        &changed_extension.components[1],
    );
    try expectRejected(profile.validate(
        &capture.projection.projected_native.core,
        &changed_extension,
        base_columns,
    ));

    var changed = profile;
    changed.authority.guest_elf_sha256[0] ^= 1;
    try expectRejected(changed.validate(
        &capture.projection.projected_native.core,
        &capture.extension_statement,
        base_columns,
    ));
    inline for (.{
        "bulk_memcpy_call_count",
        "bulk_memcpy_word_row_count",
        "stack_swap_call_count",
    }) |field| {
        changed = profile;
        @field(changed, field) += 1;
        try expectRejected(changed.validate(
            &capture.projection.projected_native.core,
            &capture.extension_statement,
            base_columns,
        ));
    }
    changed = profile;
    changed.placements.stack_swap_words.main_offset += 1;
    try expectRejected(changed.validate(
        &capture.projection.projected_native.core,
        &capture.extension_statement,
        base_columns,
    ));
    changed = profile;
    changed.components[0].composition_log_split = 1;
    try expectRejected(changed.validate(
        &capture.projection.projected_native.core,
        &capture.extension_statement,
        base_columns,
    ));

    var changed_projected_core = capture.projection.projected_native.core;
    changed_projected_core.infra_descs[0].n_columns += 1;
    try expectRejected(profile.validate(
        &changed_projected_core,
        &capture.extension_statement,
        base_columns,
    ));
}

fn expectRejected(result: anytype) !void {
    if (result) |_| return error.ExpectedCandidateProfileMutationRejection else |_| {}
}

fn authorityForElf(elf: []const u8) !frontend.testing
    .ethereum_candidate_combined_authority_v1.Authority {
    var identity: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &identity, .{});
    return frontend.testing.ethereum_candidate_combined_authority_v1.Authority
        .create(identity);
}

/// Borrowed proof-frame view: execution custody remains leaf-local, while the
/// existing SegmentV2 prover consumes the canonical global-continuous local
/// projection. The returned value must never be deinitialized.
fn combinedLocalView(
    segment: *const frontend.testing.ethereum_candidate_combined_result_v1.SegmentResult,
    local_base: *const frontend.runner.SegmentResult,
) !frontend.testing.ethereum_candidate_combined_result_v1.SegmentResult {
    if (segment.ethereum.base.clock_frame != .leaf_local or
        local_base.clock_frame != .global_continuous)
    {
        return error.ClockFrameMismatch;
    }
    var result = segment.*;
    result.ethereum.base = local_base.*;
    return result;
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
    return global_channel.hashBytes(label, 0x434c_4631); // "CLF1"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** global_channel.RATE;
    result[0] = value;
    return result;
}

comptime {
    if (candidate_orchestration.production_active or
        candidate_verifier.production_active or candidate_profile.production_active or
        candidate_provider.production_active)
    {
        @compileError("candidate leaf proof fixture became production-active");
    }
}
