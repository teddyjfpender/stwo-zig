//! Joined base + Ethereum proving for one authenticated SegmentV2 leaf.
//!
//! Complete-execution Ethereum proofs retain their V1 transaction. This
//! append-only path consumes a caller-validated local SegmentV2 projection,
//! binds the selected physical lookup authority, and appends the same fourteen
//! Keccak/secp components to all three trace trees.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;
const lookup_physical_v2 = @import("../../air/lang/lookup_physical_manifest_v2.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const proof_admission = @import("../../air/guest_precompile/ethereum_proof_admission.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const runner_result = @import("../../runner/result.zig");
const commitment_witness = @import("../commitment_witness.zig");
const base_orchestration = @import("../orchestration.zig");
const proof_finalize = @import("../proof_finalize.zig");
const proof_workspace = @import("../proof_workspace.zig");
const statement_geometry = @import("../statement_geometry.zig");
const base_types = @import("../types.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const ethereum_assembly = @import("ethereum_assembly.zig");
const ethereum_cancellation = @import("ethereum_cancellation.zig");
const ethereum_interaction = @import("ethereum_interaction.zig");
const matched_ab_execution =
    @import("ethereum_leaf_matched_ab_execution_profile_v1.zig");
const ethereum_main = @import("ethereum_main.zig");
const ethereum_orchestration = @import("ethereum_orchestration.zig");
const ethereum_preprocessed = @import("ethereum_preprocessed.zig");
const ethereum_segment_geometry = @import("ethereum_segment_geometry.zig");
const ethereum_transcript = @import("ethereum_transcript.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_witness = @import("ethereum_witness.zig");

pub const ExecutionOptions = ethereum_orchestration.ExecutionOptions;
pub const MatchedAbExecutionAuthority = matched_ab_execution.Authority;
pub const ProveDiagnostic = prover_api.ProveDiagnostic;
pub const ProvePhase = prover_api.ProvePhase;
pub const CompositionSubphase = prover_api.CompositionSubphase;
pub const PoseidonCandidateProfile = ethereum_segment_geometry.PoseidonCandidateProfile;
pub const PoseidonCandidateGeometry = ethereum_segment_geometry.PoseidonCandidateGeometry;
pub const PoseidonCandidateResidencyEstimate = ethereum_segment_geometry.PoseidonCandidateResidencyEstimate;
pub const sequential_execution = ethereum_orchestration.sequential_execution;
pub const tree1_coefficient_retention_policy =
    ethereum_segment_geometry.tree1_coefficient_retention_policy;
pub const GeometrySnapshot = ethereum_segment_geometry.GeometrySnapshot;
pub const ProviderCallAuthorityV1 = ethereum_segment_geometry.ProviderCallAuthorityV1;
pub const ProgramInventoryV1 = ethereum_segment_geometry.ProgramInventoryV1;
pub const ExecutionInventoryV1 = ethereum_segment_geometry.ExecutionInventoryV1;
pub const CountedGeometryV1 = ethereum_segment_geometry.CountedGeometryV1;
pub const LegacyPoseidonSpan = ethereum_segment_geometry.LegacyPoseidonSpan;
pub const CandidateEstimate = ethereum_segment_geometry.CandidateEstimate;
pub const RemovedPoseidonColumns = ethereum_segment_geometry.RemovedPoseidonColumns;
pub const requireTree1Residency = ethereum_segment_geometry.requireTree1Residency;
pub const inspectPreEngineGeometry = ethereum_segment_geometry.inspectPreEngineGeometry;
pub const inspectPreEngineGeometryFromCountedInventoryV1 =
    ethereum_segment_geometry.inspectPreEngineGeometryFromCountedInventoryV1;
pub const buildProviderCallAuthorityV1 =
    ethereum_segment_geometry.buildProviderCallAuthorityV1;
pub const testing = ethereum_segment_geometry.testing;

pub fn proveWithEngine(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    return proveWithEngineUsingExecution(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        recorder,
        public_data,
        sequential_execution,
    );
}

pub fn proveWithEngineUsingExecution(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    execution: ExecutionOptions,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    var channel = Engine.Channel{};
    return proveWithEngineUsingChannelAndExecution(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        recorder,
        public_data,
        &channel,
        execution,
    );
}

pub fn proveWithEngineUsingExecutionDiagnosed(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    execution: ExecutionOptions,
    diagnostic: *?ProveDiagnostic,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    diagnostic.* = null;
    var diagnostic_phase: ProvePhase = .execution_authority;
    var diagnostic_subphase: ?CompositionSubphase = null;
    var channel = Engine.Channel{};
    return proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        recorder,
        public_data,
        &channel,
        execution,
        diagnostic,
        &diagnostic_phase,
        &diagnostic_subphase,
    ) catch |err| {
        ProveDiagnostic.recordFirstAt(
            diagnostic,
            diagnostic_phase,
            diagnostic_subphase,
            err,
        );
        return err;
    };
}

/// Opt-in unoptimized-baseline entrypoint for a matched candidate A/B run.
/// The ordinary eight-worker product default remains unchanged.
pub fn proveWithEngineUsingMatchedAbExecutionDiagnosed(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    execution_authority: MatchedAbExecutionAuthority,
    diagnostic: *?ProveDiagnostic,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    return proveWithEngineUsingExecutionDiagnosed(
        Engine,
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        recorder,
        public_data,
        .{ .cpu = try execution_authority.leafCpuRequest() },
        diagnostic,
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
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    var ignored_phase: ProvePhase = .execution_authority;
    var ignored_subphase: ?CompositionSubphase = null;
    return proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        false,
        false,
        @as(void, {}),
        allocator,
        pcs_config,
        result,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        recorder,
        public_data,
        channel,
        execution,
        null,
        &ignored_phase,
        &ignored_subphase,
    );
}

pub fn proveWithEngineUsingChannelAndExecutionInternal(
    comptime Engine: type,
    comptime use_transcript_extension: bool,
    comptime omit_native_provider: bool,
    transcript_extension: anytype,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    result: *const runner_result.SegmentResult,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    recorder: ?*stage_profile.Recorder,
    public_data: public_data_v2.PublicDataV2,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    diagnostic: ?*?ProveDiagnostic,
    diagnostic_phase: *ProvePhase,
    diagnostic_subphase: *?CompositionSubphase,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    comptime prover_api.assertProverEngine(Engine);
    comptime if (omit_native_provider and !use_transcript_extension)
        @compileError("native provider omission requires a transcript extension");
    if (execution.cpu.contention_policy != .strict)
        return error.NonStrictExecutionPolicy;
    if (result.execution_trace.step_count == 0)
        return base_types.ProverError.EmptyTrace;

    var execution_pool: base_orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();
    const workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer workspace.destroy(allocator);

    diagnostic_phase.* = .statement_admission;
    const core_public = statement_v2.canonicalCorePublicData(&public_data) catch
        return base_types.ProverError.InvalidStatement;
    const external_count = try validateClockAuthority(
        &result.execution_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );
    diagnostic_phase.* = .base_witness;
    var base_witness = try commitment_witness.CommitmentWitness
        .buildExternalProfileV2(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        .{
            result.execution_trace.rows.items,
            keccak_rows.rows(),
            recovery_rows.rows(),
        },
        &result.rw_memory,
        &public_data,
    );
    defer base_witness.deinit(allocator);
    const built = try statement_geometry.buildExternalV2(
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

    diagnostic_phase.* = .extension_witness;
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
    try proof_admission.validateV2(&native_statement, &extension, .proof);

    // The opt-in projected-native route must remove the provider before any
    // Tree1 sizing or commitment allocation. The callback receives only
    // already-admitted full authorities and may transactionally replace the
    // workspace core; the ordinary route preserves its prior construction
    // order and never instantiates this branch.
    var manifest: lookup_physical_v2.Manifest = undefined;
    var authenticated: lookup_physical_v2.AuthenticatedStatement = undefined;
    if (comptime use_transcript_extension) {
        manifest = lookup_physical_v2.Manifest.native();
        authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
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
        if (comptime omit_native_provider) {
            const projection: *const native_provider_omit.ProjectionV1 =
                try transcript_extension.providerProjection();
            try projection.validateSealAndFull(&native_statement, &extension);
            if (!std.meta.eql(core.*, projection.projected_native.core))
                return error.ProjectedCoreInstallMismatch;
        }
    }

    diagnostic_phase.* = .tree1;
    const tree1_column_log_sizes = try ethereum_main.logSizes(
        allocator,
        core,
        &extension,
    );
    defer allocator.free(tree1_column_log_sizes);
    _ = try requireTree1Residency(
        tree1_column_log_sizes,
        pcs_config.fri_config.log_blowup_factor,
        execution.cpu.host_byte_budget,
    );

    diagnostic_phase.* = .statement_admission;
    if (comptime !use_transcript_extension) {
        manifest = lookup_physical_v2.Manifest.native();
        authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
            core,
            &manifest,
        );
    }
    pcs_config.mixInto(channel);
    try statement_v2.mixIntoNativeTranscript(&public_data, channel);
    authenticated.mixInto(channel);
    try extension.mixIntoV2(&native_statement, channel);

    diagnostic_phase.* = .tree0;
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    if (comptime omit_native_provider)
        scheme.setCoefficientRetentionPolicy(.never);

    const tree0 = if (comptime omit_native_provider)
        try ethereum_preprocessed.generateWithoutNativePoseidonV2(
            allocator,
            try transcript_extension.providerProjection(),
            &native_statement,
            &extension,
        )
    else
        try ethereum_preprocessed.generate(allocator, core, &extension);
    var tree0_moved = false;
    errdefer if (!tree0_moved) freeColumns(allocator, tree0);
    tree0_moved = true;
    try Engine.commit(&scheme, allocator, tree0, recorder, channel);

    diagnostic_phase.* = .tree1;
    var retained = if (comptime omit_native_provider)
        try ethereum_main.commitWithoutNativePoseidon(
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
            try transcript_extension.providerProjection(),
        )
    else
        try ethereum_main.commit(
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
        );
    defer retained.deinit(allocator, workspace);

    diagnostic_phase.* = .tree2;
    const prefix = if (comptime use_transcript_extension)
        try transcript_extension.drawChallenges(
            allocator,
            &scheme,
            channel,
            &native_statement,
            core,
            &extension,
            &manifest,
            &authenticated,
            recorder,
        )
    else
        try ethereum_transcript.proveToRelations(
            allocator,
            channel,
            core,
        );
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
    const extension_claim = if (comptime omit_native_provider)
        try ethereum_interaction
            .generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2(
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
            try transcript_extension.providerProjection(),
        )
    else
        try ethereum_interaction.generateAndCommitAuthenticatedLookupV2(
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
        );
    try extension_claim.validate(&extension);
    if (comptime omit_native_provider) {
        const residual = try ethereum_cancellation.residualWithoutNativePoseidonV2(
            try transcript_extension.providerProjection(),
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
            &extension_claim,
        );
        // Diagnostic only. The cold verifier recomputes the residual after the
        // projected STARK succeeds and is the only authority admitted later.
        try transcript_extension.recordProverResidual(residual);
    } else {
        try ethereum_cancellation.verifyV2(
            &native_statement,
            &manifest,
            &authenticated,
            &prefix.relations,
            base_claim,
            &extension_claim,
        );
    }

    diagnostic_phase.* = .composition;
    diagnostic_subphase.* = .assembly;
    const n_main = core.nMainColumns();
    const n_interaction = try authenticated.totalInteractionColumns(core, &manifest);
    const base_components = try proof_finalize.assembleAuthenticatedLookupV2(
        workspace,
        &prefix.relations.base,
        base_claim,
        n_main,
        n_interaction,
        &manifest,
        &authenticated,
    );
    const assembly = if (comptime omit_native_provider)
        try ethereum_assembly.Assembly(.prover)
            .createWithoutNativePoseidonAuthenticatedLookupV2(
            allocator,
            try transcript_extension.providerProjection(),
            &native_statement,
            &extension,
            &prefix.relations,
            base_components,
            &extension_claim,
            &manifest,
            &authenticated,
        )
    else
        try ethereum_assembly.Assembly(.prover).createAuthenticatedLookupV2(
            allocator,
            &native_statement,
            &extension,
            &prefix.relations,
            base_components,
            &extension_claim,
            &manifest,
            &authenticated,
        );
    defer assembly.destroy(allocator);

    scheme_owned = false;
    const prove_options: prover_api.ProveOptions = .{
        .recorder = recorder,
        .cpu_composition_execution = execution.cpu,
    };
    var extended_proof = blk: {
        if (comptime @hasDecl(Engine, "proveDiagnosed")) {
            if (diagnostic) |output| break :blk try Engine.proveDiagnosed(
                allocator,
                assembly.active(),
                channel,
                scheme,
                prove_options,
                output,
            );
        }
        break :blk try Engine.prove(
            allocator,
            assembly.active(),
            channel,
            scheme,
            prove_options,
        );
    };
    diagnostic_phase.* = .capture;
    diagnostic_subphase.* = null;
    const proof = extended_proof.proof;
    extended_proof.aux.deinit(allocator);
    work_pool.recordProofPublicationForTest(execution_pool.get());
    claim_owned = false;
    return .{
        .statement = native_statement,
        .extension = extension,
        .proof = proof,
        .base_claim = base_claim,
        .extension_claim = extension_claim,
    };
}

fn validateClockAuthority(
    trace: *const @import("../../runner/trace.zig").Trace,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return base_types.ProverError.InvalidStatement;
    const external = std.math.add(usize, keccak_calls, recovery_calls) catch
        return base_types.ProverError.InvalidStatement;
    const total = std.math.add(usize, trace.step_count, external) catch
        return base_types.ProverError.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock or
        trace.recordedExternalSteps() != external)
    {
        return base_types.ProverError.InvalidStatement;
    }
    trace.validateClockRange(0, public_clock, external) catch
        return base_types.ProverError.InvalidStatement;
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
