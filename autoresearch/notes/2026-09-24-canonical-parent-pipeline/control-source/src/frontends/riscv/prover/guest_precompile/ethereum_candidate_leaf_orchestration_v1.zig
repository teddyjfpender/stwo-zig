//! Candidate-only joined Ethereum leaf prover.
//!
//! This sibling preserves the ordinary SegmentV2 orchestration byte-for-byte
//! and appends the admitted bulk-memcpy and U256-SWAP components to all three
//! trees. The native Poseidon provider is physically omitted; its residual is
//! only a pending claim until the separately proven degree-five provider set
//! closes under the same candidate transcript authority.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;

const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const bulk_trace = @import("../../air/guest_precompile/bulk_memcpy_trace_v1.zig");
const swap_trace = @import("../../air/guest_precompile/stack_swap_trace_v1.zig");
const combined_authority =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod =
    @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod =
    @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const runner_result = @import("../../runner/result.zig");
const combined_result =
    @import("../../runner/ethereum_candidate_combined_result_v1.zig");
const commitment_witness = @import("../commitment_witness.zig");
const base_orchestration = @import("../orchestration.zig");
const proof_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const candidate_protocol =
    @import("../memory_provider_shards/ethereum_candidate_omit_protocol_v1.zig");
const candidate_decode = @import("ethereum_candidate_combined_decode_v1.zig");
const candidate_admission = @import("ethereum_candidate_leaf_admission_v1.zig");
const candidate_integration = @import("ethereum_candidate_leaf_integration_v1.zig");
const matched_ab_execution =
    @import("ethereum_leaf_matched_ab_execution_profile_v1.zig");
const candidate_profile = @import("ethereum_candidate_leaf_profile_v1.zig");
const candidate_tree = @import("ethereum_candidate_leaf_tree_v1.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_orchestration = @import("ethereum_orchestration.zig");
const ethereum_segment_geometry = @import("ethereum_segment_geometry.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_witness = @import("ethereum_witness.zig");

pub const production_active = false;
pub const ExecutionOptions = ethereum_orchestration.ExecutionOptions;
pub const MatchedAbExecutionAuthority = matched_ab_execution.Authority;
pub const MatchedAbProviderExecutionRequest =
    matched_ab_execution.ProviderExecutionRequest;
pub const sequential_execution = ethereum_orchestration.sequential_execution;
pub const ProviderCallAuthorityV1 =
    ethereum_segment_geometry.ProviderCallAuthorityV1;

/// Deterministic, diagnostic-only stage marker for the candidate provider-call
/// authority transaction. The ordinary entrypoint preserves its exact error
/// surface; focused integration gates may opt into this out-of-band marker to
/// localize a collapsed `InvalidStatement` without weakening admission.
pub const ProviderCallAuthorityPhaseV1 = enum {
    result_authority,
    non_empty_trace,
    workspace,
    public_data,
    clock_authority,
    decoder,
    commitment_witness,
    statement_geometry,
    statement_result,
    ethereum_witness,
    ethereum_statement,
    proof_admission,
    detach_calls,
    non_empty_calls,
};

pub const ProviderCallAuthorityDiagnosticV1 = struct {
    phase: ProviderCallAuthorityPhaseV1,
    cause: anyerror,
};

/// Failure-only phase marker for the candidate leaf prover transaction. The
/// diagnostic is not transcript data and never replaces the original error.
pub const CandidateProvePhaseV1 = enum {
    execution_authority,
    statement_admission,
    tree0_root,
    tree1,
    relation_draw,
    tree2_claims,
    residual,
    assembly,
    engine_prove,
    finalization,
};

pub const CandidateProveDiagnosticV1 = struct {
    phase: CandidateProvePhaseV1,
    cause: anyerror,
    engine: ?prover_api.ProveDiagnostic = null,
};

/// Rebuilds the exact candidate base witness with the combined decoder and
/// all five execution sources, then detaches only its ordered native Poseidon
/// calls. The ordinary three-source/default-decoder helper cannot be used for
/// this program root.
pub fn buildProviderCallAuthorityV1(
    allocator: std.mem.Allocator,
    result: *const combined_result.SegmentResult,
    authority: combined_authority.Authority,
    public_data: public_data_v2.PublicDataV2,
) !ProviderCallAuthorityV1 {
    return buildProviderCallAuthorityInternalV1(
        allocator,
        result,
        authority,
        public_data,
        null,
    );
}

/// Diagnostic twin of `buildProviderCallAuthorityV1`. It executes the same
/// transaction and returns the same error; `diagnostic_out` is populated only
/// on failure with the exact stage that returned it.
pub fn buildProviderCallAuthorityDiagnosedV1(
    allocator: std.mem.Allocator,
    result: *const combined_result.SegmentResult,
    authority: combined_authority.Authority,
    public_data: public_data_v2.PublicDataV2,
    diagnostic_out: *?ProviderCallAuthorityDiagnosticV1,
) !ProviderCallAuthorityV1 {
    diagnostic_out.* = null;
    return buildProviderCallAuthorityInternalV1(
        allocator,
        result,
        authority,
        public_data,
        diagnostic_out,
    );
}

fn buildProviderCallAuthorityInternalV1(
    allocator: std.mem.Allocator,
    result: *const combined_result.SegmentResult,
    authority: combined_authority.Authority,
    public_data: public_data_v2.PublicDataV2,
    diagnostic_out: ?*?ProviderCallAuthorityDiagnosticV1,
) !ProviderCallAuthorityV1 {
    var phase: ProviderCallAuthorityPhaseV1 = .result_authority;
    errdefer |err| {
        if (diagnostic_out) |out| out.* = .{
            .phase = phase,
            .cause = err,
        };
    }

    try result.validateAgainst(authority, 0);
    phase = .non_empty_trace;
    if (result.ethereum.base.execution_trace.step_count == 0)
        return error.EmptyTrace;

    phase = .workspace;
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);
    phase = .public_data;
    const core_public = statement_v2.canonicalCorePublicData(&public_data) catch
        return error.InvalidStatement;
    phase = .clock_authority;
    const external_count = try validateClockAuthorityCounts(
        &result.ethereum.base,
        result.ethereum.keccakf_calls.len(),
        result.ethereum.keccakf_execution_rows.rows().len,
        result.ethereum.signer_recovery_calls.len(),
        result.ethereum.signer_recovery_execution_rows.rows().len,
        result.bulk_memcpy.records().len,
        result.stack_swap.records().len,
        core_public.clock,
    );
    phase = .decoder;
    const decoder = try candidate_decode.DeclaredDecodeAuthority.init(authority);
    phase = .commitment_witness;
    var base_witness = try commitment_witness.CommitmentWitness
        .buildExternalDecodeAuthorityV2(
        allocator,
        decoder,
        .{
            result.ethereum.base.execution_trace.rows.items,
            result.ethereum.keccakf_execution_rows.rows(),
            result.ethereum.signer_recovery_execution_rows.rows(),
            result.bulk_memcpy.rows(),
            result.stack_swap.rows(),
        },
        &result.ethereum.base.rw_memory,
        &public_data,
    );
    defer base_witness.deinit(allocator);
    phase = .statement_geometry;
    const built = try @import("../statement_geometry.zig").buildExternalV2(
        allocator,
        workspace,
        &result.ethereum.base.execution_trace,
        &base_witness,
        &result.ethereum.base.state_chain_tracker,
        public_data,
        external_count,
        .proof,
    );
    phase = .statement_result;
    try built.statement.validateSegmentResult(&result.ethereum.base);

    phase = .ethereum_witness;
    var witness = try ethereum_witness.Witness.init(
        allocator,
        result.ethereum.keccakf_calls.records(),
        result.ethereum.keccakf_execution_rows.rows(),
        result.ethereum.signer_recovery_calls.records(),
        result.ethereum.signer_recovery_execution_rows.rows(),
        core_public.clock,
    );
    defer witness.deinit();
    phase = .ethereum_statement;
    const extension = try statement_mod.Statement.canonicalV2(
        &built.statement,
        @intCast(result.ethereum.keccakf_calls.len()),
        @intCast(result.ethereum.signer_recovery_calls.len()),
        witness.shapes(),
    );
    phase = .proof_admission;
    _ = try validatePreprojectionAdmissionV1(
        &built.statement,
        &extension,
        authority,
        result.bulk_memcpy.records().len,
        result.bulk_memcpy.wordRows().len,
        result.stack_swap.records().len,
    );

    phase = .detach_calls;
    const calls = try base_witness.poseidon_calls.toOwnedSlice(allocator);
    base_witness.poseidon_calls = .{};
    phase = .non_empty_calls;
    if (calls.len == 0) {
        allocator.free(calls);
        return error.EmptyProviderCallAuthority;
    }
    return .{
        .allocator = allocator,
        .calls = calls,
        .public_data_wire_id = public_data.wireId(),
    };
}

pub fn ProveOutputForEngine(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        extension: statement_mod.Statement,
        profile: candidate_profile.Profile,
        proof: base_types.ProofForEngine(Engine),
        base_claim: *base_types.RiscVInteractionClaim,
        interaction_claims: candidate_tree.InteractionClaims,
        shared_relation: candidate_protocol.SharedRelationAuthorityV1(Engine),

        const Self = @This();

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            allocator.destroy(self.base_claim);
            self.* = undefined;
        }

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            allocator.destroy(self.base_claim);
            self.* = undefined;
        }
    };
}

/// Opt-in candidate entrypoint paired with the unoptimized baseline's exact
/// physical execution authority. Provider owner admission is separately
/// checked through `MatchedAbExecutionAuthority.validateProviderExecution`.
pub fn proveWithEngineUsingChannelAndMatchedAbExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    candidate: candidate_tree.CandidateWitness,
    authority: combined_authority.Authority,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution_authority: MatchedAbExecutionAuthority,
    provider_execution: matched_ab_execution.ProviderExecutionRequest,
    transcript_extension: *candidate_protocol.Extension(Engine),
) !ProveOutputForEngine(Engine) {
    try execution_authority.validateProviderExecution(provider_execution);
    return proveWithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        candidate,
        authority,
        recorder,
        public_data,
        channel,
        .{ .cpu = try execution_authority.leafCpuRequest() },
        transcript_extension,
    );
}

/// Diagnostic twin of the matched A/B entrypoint. It preserves the exact
/// execution authority checks and original returned error while recording the
/// first candidate prover phase that failed.
pub fn proveWithEngineUsingChannelAndMatchedAbExecutionDiagnosed(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    candidate: candidate_tree.CandidateWitness,
    authority: combined_authority.Authority,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution_authority: MatchedAbExecutionAuthority,
    provider_execution: matched_ab_execution.ProviderExecutionRequest,
    transcript_extension: *candidate_protocol.Extension(Engine),
    diagnostic_out: *?CandidateProveDiagnosticV1,
) !ProveOutputForEngine(Engine) {
    diagnostic_out.* = null;
    execution_authority.validateProviderExecution(provider_execution) catch |err| {
        diagnostic_out.* = .{
            .phase = .execution_authority,
            .cause = err,
        };
        return err;
    };
    const cpu = execution_authority.leafCpuRequest() catch |err| {
        diagnostic_out.* = .{
            .phase = .execution_authority,
            .cause = err,
        };
        return err;
    };
    return proveWithEngineUsingChannelAndExecutionDiagnosed(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        candidate,
        authority,
        recorder,
        public_data,
        channel,
        .{ .cpu = cpu },
        transcript_extension,
        diagnostic_out,
    );
}

pub fn proveWithEngineUsingChannelAndExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    candidate: candidate_tree.CandidateWitness,
    authority: combined_authority.Authority,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    transcript_extension: *candidate_protocol.Extension(Engine),
) !ProveOutputForEngine(Engine) {
    return proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        candidate,
        authority,
        recorder,
        public_data,
        channel,
        execution,
        transcript_extension,
        null,
    );
}

/// Diagnostic twin of `proveWithEngineUsingChannelAndExecution`. The proof
/// transaction and returned error are unchanged; the out-parameter is set only
/// when the transaction fails.
pub fn proveWithEngineUsingChannelAndExecutionDiagnosed(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    candidate: candidate_tree.CandidateWitness,
    authority: combined_authority.Authority,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    transcript_extension: *candidate_protocol.Extension(Engine),
    diagnostic_out: *?CandidateProveDiagnosticV1,
) !ProveOutputForEngine(Engine) {
    diagnostic_out.* = null;
    return proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        candidate,
        authority,
        recorder,
        public_data,
        channel,
        execution,
        transcript_extension,
        diagnostic_out,
    );
}

fn proveWithEngineUsingChannelAndExecutionInternal(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    candidate: candidate_tree.CandidateWitness,
    authority: combined_authority.Authority,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    transcript_extension: *candidate_protocol.Extension(Engine),
    diagnostic_out: ?*?CandidateProveDiagnosticV1,
) !ProveOutputForEngine(Engine) {
    var phase: CandidateProvePhaseV1 = .execution_authority;
    var engine_diagnostic: ?prover_api.ProveDiagnostic = null;
    errdefer |err| {
        if (diagnostic_out) |out| {
            if (out.* == null) out.* = .{
                .phase = phase,
                .cause = err,
                .engine = if (phase == .engine_prove)
                    engine_diagnostic
                else
                    null,
            };
        }
    }

    comptime prover_api.assertProverEngine(Engine);
    if (execution.cpu.contention_policy != .strict)
        return error.NonStrictExecutionPolicy;
    if (result.execution_trace.step_count == 0)
        return error.EmptyTrace;
    try authority.validate();
    try candidate.bulk_memcpy_tape.validate();
    try candidate.stack_swap_tape.validate();

    var execution_pool: base_orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    phase = .statement_admission;
    const core_public = statement_v2.canonicalCorePublicData(&public_data) catch
        return error.InvalidStatement;
    const external_count = try validateClockAuthority(
        result,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        candidate,
        core_public.clock,
    );
    const decoder = try candidate_decode.DeclaredDecodeAuthority.init(authority);
    var base_witness = try commitment_witness.CommitmentWitness
        .buildExternalDecodeAuthorityV2(
        allocator,
        decoder,
        .{
            result.execution_trace.rows.items,
            keccak_rows.rows(),
            recovery_rows.rows(),
            candidate.bulk_memcpy_tape.rows(),
            candidate.stack_swap_tape.rows(),
        },
        &result.rw_memory,
        &public_data,
    );
    defer base_witness.deinit(allocator);
    const built = try @import("../statement_geometry.zig").buildExternalV2(
        allocator,
        workspace,
        &result.execution_trace,
        &base_witness,
        &result.state_chain_tracker,
        public_data,
        external_count,
        .proof,
    );
    const native_statement = built.statement;
    const core = &workspace.statement;
    try native_statement.validateSegmentResult(result);

    var witness = try ethereum_witness.Witness.init(
        allocator,
        keccak_calls.records(),
        keccak_rows.rows(),
        recovery_calls.records(),
        recovery_rows.rows(),
        core_public.clock,
    );
    defer witness.deinit();
    const extension = try statement_mod.Statement.canonicalV2(
        &native_statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        witness.shapes(),
    );
    _ = try validatePreprojectionAdmissionV1(
        &native_statement,
        &extension,
        authority,
        candidate.bulk_memcpy_tape.records().len,
        candidate.bulk_memcpy_tape.wordRows().len,
        candidate.stack_swap_tape.records().len,
    );

    var manifest = lookup_physical_v2.Manifest.native();
    var authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        core,
        &manifest,
    );
    try transcript_extension.prepareProjectedCore(
        &native_statement,
        &extension,
        &manifest,
        &authenticated,
        core,
        built.base,
    );
    const projection = try transcript_extension.providerProjection();
    try projection.validateSealAndFull(&native_statement, &extension);
    if (!std.meta.eql(core.*, projection.projected_native.core))
        return error.ProjectedCoreInstallMismatch;
    const profile = try transcript_extension.profileValue();
    if (!std.meta.eql(profile.authority, authority))
        return error.EthereumCandidateLeafAuthorityMismatch;
    try candidate.validate(profile);

    phase = .tree0_root;
    var tree_logs = try candidate_tree.logSizes(
        allocator,
        core,
        &extension,
        &manifest,
        &authenticated,
        profile,
    );
    defer tree_logs.deinit(allocator);
    _ = try @import("ethereum_segment_orchestration.zig").requireTree1Residency(
        tree_logs.tree1,
        pcs_config.fri_config.log_blowup_factor,
        execution.cpu.host_byte_budget,
    );

    pcs_config.mixInto(channel);
    try statement_v2.mixIntoNativeTranscript(&public_data, channel);
    authenticated.mixInto(channel);
    try extension.mixIntoV2(&native_statement, channel);

    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);

    const tree0 = try candidate_tree.mixAndGenerateTree0(
        allocator,
        channel,
        projection,
        &native_statement,
        &extension,
        &manifest,
        &authenticated,
        profile,
        candidate,
    );
    var tree0_moved = false;
    errdefer if (!tree0_moved) freeColumns(allocator, tree0);
    tree0_moved = true;
    try Engine.commit(&scheme, allocator, tree0, recorder, channel);

    phase = .tree1;
    var retained = try candidate_tree.commitTree1(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        &result.execution_trace,
        &base_witness,
        built.base,
        &result.state_chain_tracker,
        &witness,
        keccak_calls.records(),
        recovery_calls.records(),
        &native_statement,
        &extension,
        projection,
        &manifest,
        &authenticated,
        profile,
        candidate,
    );
    defer retained.deinit(allocator, workspace);

    phase = .relation_draw;
    const prefix = try transcript_extension.drawChallenges(
        allocator,
        &scheme,
        channel,
        &native_statement,
        core,
        &extension,
        &manifest,
        &authenticated,
        recorder,
    );

    phase = .tree2_claims;
    const base_claim = try allocator.create(base_types.RiscVInteractionClaim);
    var claim_owned = true;
    defer if (claim_owned) allocator.destroy(base_claim);

    var serial_pool: work_pool.WorkPool = undefined;
    var serial_pool_live = false;
    defer if (serial_pool_live) serial_pool.deinit();
    const pool = execution_pool.get() orelse blk: {
        try serial_pool.initInPlaceWithOptions(.{ .worker_count = 1 });
        serial_pool_live = true;
        break :blk &serial_pool;
    };
    const interaction_claims = try candidate_tree.generateAndCommitTree2(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        &base_witness,
        built.base,
        &retained.lookup_source,
        &prefix,
        &witness,
        pool,
        base_claim,
        &manifest,
        &authenticated,
        &native_statement,
        &extension,
        projection,
        profile,
        candidate,
    );
    try interaction_claims.validate(&extension, profile);

    phase = .residual;
    const residual = try candidate_integration.residualWithoutNativePoseidonV2(
        projection,
        &native_statement,
        &extension,
        .proof,
        &manifest,
        &authenticated,
        transcript_extension.providerPlan(),
        transcript_extension.providerCalls(),
        built.base,
        &prefix.relations,
        base_claim,
        &interaction_claims.ethereum,
        profile,
        interaction_claims.candidate,
    );
    try transcript_extension.recordProverResidual(residual);

    phase = .assembly;
    const n_main = core.nMainColumns();
    const n_interaction = try authenticated.totalInteractionColumns(
        core,
        &manifest,
    );
    const base_components = try proof_finalize.assembleAuthenticatedLookupV2(
        workspace,
        &prefix.relations.ethereum.base,
        base_claim,
        n_main,
        n_interaction,
        &manifest,
        &authenticated,
    );
    const assembly = try candidate_integration.Assembly(.prover)
        .createWithoutNativePoseidonAuthenticatedLookupV2(
        allocator,
        projection,
        &native_statement,
        &extension,
        &prefix.relations,
        base_components,
        &interaction_claims.ethereum,
        interaction_claims.candidate,
        &manifest,
        &authenticated,
        profile,
    );
    defer assembly.destroy(allocator);

    phase = .engine_prove;
    scheme_owned = false;
    const prove_options: prover_api.ProveOptions = .{
        .recorder = recorder,
        .cpu_composition_execution = execution.cpu,
    };
    var extended_proof = blk: {
        if (comptime @hasDecl(Engine, "proveDiagnosed")) {
            if (diagnostic_out != null) {
                break :blk try Engine.proveDiagnosed(
                    allocator,
                    assembly.active(),
                    channel,
                    scheme,
                    prove_options,
                    &engine_diagnostic,
                );
            }
        }
        break :blk try Engine.prove(
            allocator,
            assembly.active(),
            channel,
            scheme,
            prove_options,
        );
    };

    phase = .finalization;
    const proof = extended_proof.proof;
    extended_proof.aux.deinit(allocator);
    work_pool.recordProofPublicationForTest(execution_pool.get());
    const shared_relation = transcript_extension.shared_relation orelse
        return error.MissingEthereumCandidateSharedAuthority;
    claim_owned = false;
    return .{
        .statement = native_statement,
        .extension = extension,
        .profile = profile.*,
        .proof = proof,
        .base_claim = base_claim,
        .interaction_claims = interaction_claims,
        .shared_relation = shared_relation,
    };
}

fn validateClockAuthority(
    result: *const runner_result.SegmentResult,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    candidate: candidate_tree.CandidateWitness,
    public_clock: u32,
) !u32 {
    return validateClockAuthorityCounts(
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        candidate.bulk_memcpy_tape.records().len,
        candidate.stack_swap_tape.records().len,
        public_clock,
    );
}

/// Before provider omission exists, validate the full candidate retirement
/// supplement against the full core. The projected Profile is reconstructed
/// later and must yield the identical Admission before transcript mutation.
fn validatePreprojectionAdmissionV1(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const statement_mod.Statement,
    authority: combined_authority.Authority,
    bulk_memcpy_calls: usize,
    bulk_memcpy_word_rows: usize,
    stack_swap_calls: usize,
) !candidate_admission.Admission {
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &native.core,
        &manifest,
    );
    const base_interaction_columns = std.math.cast(
        u32,
        try authenticated.totalInteractionColumns(&native.core, &manifest),
    ) orelse return error.EthereumCandidateLeafGeometryOverflow;
    const profile = try candidate_profile.Profile.create(
        &native.core,
        extension,
        base_interaction_columns,
        authority,
        std.math.cast(u32, bulk_memcpy_calls) orelse
            return error.EthereumCandidateLeafGeometryOverflow,
        std.math.cast(u32, bulk_memcpy_word_rows) orelse
            return error.EthereumCandidateLeafGeometryOverflow,
        std.math.cast(u32, stack_swap_calls) orelse
            return error.EthereumCandidateLeafGeometryOverflow,
    );
    return candidate_admission.validateV2(
        native,
        extension,
        base_interaction_columns,
        &profile,
        .proof,
    );
}

fn validateClockAuthorityCounts(
    result: *const runner_result.SegmentResult,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    bulk_memcpy_calls: usize,
    stack_swap_calls: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return base_types.ProverError.InvalidStatement;
    const candidate_calls = std.math.add(
        usize,
        bulk_memcpy_calls,
        stack_swap_calls,
    ) catch return base_types.ProverError.InvalidStatement;
    const ethereum_calls = std.math.add(
        usize,
        keccak_calls,
        recovery_calls,
    ) catch return base_types.ProverError.InvalidStatement;
    const external = std.math.add(
        usize,
        ethereum_calls,
        candidate_calls,
    ) catch return base_types.ProverError.InvalidStatement;
    const total = std.math.add(
        usize,
        result.execution_trace.step_count,
        external,
    ) catch return base_types.ProverError.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock or
        result.execution_trace.recordedExternalSteps() != external)
    {
        return base_types.ProverError.InvalidStatement;
    }
    result.execution_trace.validateClockRange(
        0,
        public_clock,
        external,
    ) catch return base_types.ProverError.InvalidStatement;
    return std.math.cast(u32, external) orelse
        return base_types.ProverError.InvalidStatement;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

comptime {
    if (production_active or candidate_profile.production_active or
        candidate_protocol.production_active or candidate_tree.production_active)
    {
        @compileError("candidate Ethereum leaf orchestration became active");
    }
    _ = bulk_trace.Bundle;
    _ = swap_trace.Bundle;
}
