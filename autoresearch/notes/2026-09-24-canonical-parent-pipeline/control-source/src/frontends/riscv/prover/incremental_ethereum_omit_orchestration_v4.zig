//! Omitted-provider V4 orchestration and cold verifier for the incremental
//! Ethereum leaf (Step 4 of the leaf route flip).
//!
//! This file is the additive twin of `incremental_ethereum_orchestration_v3`
//! and `incremental_ethereum_verifier_v3`: the native 445-column `poseidon2`
//! infrastructure component leaves Trees 0/1/2, and the same provider calls are
//! proved elsewhere as degree-five shards under the one relation draw this
//! transcript performs. Neither native file is touched; the small private
//! helpers they own (`validateClockAuthority`, `BridgeClaimMix`/
//! `mixBridgeClaim`, `freeColumns`, `prefixColumns`, `verifyPreprocessedRoot`,
//! `incrementalRoots`) are duplicated below rather than exported, so the native
//! leaf path stays byte-identical.
//!
//! Exact transcript order on the core channel (producer and cold verifier are
//! byte-identical up to the relation draw; every shard replays [1]-[6]):
//!
//!   1. `AuthorityV4.mixPreTree0(FULL statement, role-aware public)`
//!   2. `IncrementalOmissionFrameV4.mixInto` (projection identity, pin
//!      identity, PROJECTED bridge geometry)
//!   3. Tree 0 root
//!   4. Tree 1 root
//!   5. `AuthorityV4.mixPostTree1(FULL statement, role-aware public)`
//!   6. `Extension.drawChallenges` == `proveToRelationsWithExtension`
//!      (`mixMainClaim(projected core)`, provider `Frame`, 16-bit grind,
//!      `mixU64(nonce)`, `Relations.draw`)
//!   7. `mixInteractionClaimV2(projected core)` then the bridge claim
//!   8. Tree 2 root
//!   9. Composition, FRI -- unchanged
//!
//! Steps 1 and 2 live in `mixRoutePreTree0` so the producer, the cold verifier
//! and the Step-5 shard adapter cannot drift from one another.
//!
//! Nothing here activates production: the omitted core mints a
//! `FreshCoreResidualV1` (whose `production_eligible`/`recursive_admissible`
//! are both false) and never a `FreshVerifiedCaptureV4`, whose `validate`
//! re-derives the bridge placement from the FULL statement and would reject a
//! projected core by construction.

const std = @import("std");
const core_verifier = @import("stwo_core").verifier;
const pcs_core = @import("stwo_core").pcs;
const pcs_verifier = @import("stwo_core").pcs.verifier;
const prover_pcs = @import("stwo_prover_engine").pcs;
const m31 = @import("stwo_core").fields.m31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_api = @import("stwo_prover_api");
const stage_profile = prover_api.stage_profile;
const work_pool = @import("stwo_prover_engine").work_pool;

const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const statement = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const public_data_v1 = @import("../air/public_data.zig");
const incremental_public = @import("../air/incremental_public_logup_v4.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const state_chain = @import("../runner/state_chain.zig");
const trace_mod = @import("../runner/trace.zig");
const keccak_calls_mod =
    @import("../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod =
    @import("../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod =
    @import("../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod =
    @import("../runner/guest_precompile/secp256k1_recover_v1.zig");

const incremental_bridge = @import("incremental_bridge_external_v3.zig");
const incremental_witness = @import("incremental_commitment_witness_v3.zig");
const orchestration = @import("orchestration.zig");
const native_orchestration =
    @import("incremental_ethereum_orchestration_v3.zig");
const route = @import("incremental_ethereum_omit_protocol_v4.zig");
const proof_finalize = @import("proof_finalize.zig");
const proof_workspace = @import("proof_workspace.zig");
const proof_admission =
    @import("../air/guest_precompile/ethereum_proof_admission.zig");
const ethereum_assembly = @import("guest_precompile/ethereum_assembly.zig");
const ethereum_interaction = @import("guest_precompile/ethereum_interaction.zig");
const ethereum_main = @import("guest_precompile/ethereum_main.zig");
const ethereum_preprocessed =
    @import("guest_precompile/ethereum_preprocessed.zig");
const ethereum_transcript = @import("guest_precompile/ethereum_transcript.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const external_tree = @import("guest_precompile/external_profile_tree.zig");
const segment_orchestration =
    @import("guest_precompile/ethereum_segment_orchestration.zig");
const base_verifier = @import("verifier.zig");
const types = @import("types.zig");

const omit_protocol =
    @import("memory_provider_shards/ethereum_omit_protocol_v1.zig");
const omission =
    @import("memory_provider_shards/native_provider_omit_v1.zig");
const provider_authority = @import("memory_provider_shards/authority.zig");

pub const RESEARCH_ONLY = true;
pub const PRODUCTION_ACTIVE = false;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const FORMAT_VERSION: u16 = 4;
pub const COMMITMENT_TREE_COUNT: usize = 4;

pub const Digest = route.Digest;
pub const ExecutionOptions = native_orchestration.ExecutionOptions;
pub const PreparedProofInputsV4 = native_orchestration.PreparedProofInputsV4;
pub const InteractionClaimsV4 = native_orchestration.InteractionClaimsV4;
pub const IncrementalOmissionFrameV4 = route.IncrementalOmissionFrameV4;
pub const LeafOmissionAuthorityV4 = route.LeafOmissionAuthorityV4;
pub const ProviderOmissionPinsV1 = route.ProviderOmissionPinsV1;

/// Opt-in knobs of the route. Everything that could move proof identity is a
/// comptime pin in `ProviderOmissionPinsV1`; only diagnostics live here.
pub const OmittedRouteOptionsV1 = struct {
    /// G7. `verifyMerkleAndPoseidonCancellation` regenerates a full Poseidon
    /// interaction table serially, and on this route the fresh shard closure
    /// is the authoritative check, so it is off unless a caller asks for the
    /// diagnostic explicitly.
    diagnostic_cancellation: bool = false,
};

/// Projected committed prefix and the bridge placement it implies. The
/// producer computes it once before Tree 0; the cold verifier recomputes it
/// from the decoded statement and compares.
pub const ProjectedRouteGeometryV4 = struct {
    prefix: incremental_bridge.PrefixColumnsV3,
    bridge: incremental_bridge.GeometryV3,
};

/// The omission section of STWIOL01, reduced to exactly the fields this
/// verifier readmits. Step 8's envelope owns the encoding; the shape and
/// `validateAgainst` contract live here next to the code that enforces them.
pub const DecodedOmissionV1 = struct {
    format: u32 = route.FORMAT_VERSION,
    pins_identity: Digest,
    projection_identity: Digest,
    plan_identity: Digest,
    manifest_identity: Digest,
    shared_identity: Digest,
    relation_context_identity: Digest,
    interaction_pow: u64,
    projected_bridge_geometry: incremental_bridge.GeometryV3,
    frame_identity: Digest,
    leaf_omission_identity: Digest,

    /// Self-consistency only: the pin set is comptime, so a decoded section
    /// claiming another one is refused before any statement is consulted.
    pub fn validate(self: *const DecodedOmissionV1) !void {
        if (self.format != route.FORMAT_VERSION)
            return error.InvalidIncrementalOmittedEthereumOmissionSection;
        if (!std.mem.eql(
            u8,
            &self.pins_identity,
            &ProviderOmissionPinsV1.identity(),
        )) return error.ProviderOmissionPinDriftV4;
        for ([_]Digest{
            self.projection_identity,
            self.plan_identity,
            self.manifest_identity,
            self.shared_identity,
            self.relation_context_identity,
            self.frame_identity,
            self.leaf_omission_identity,
        }) |digest| {
            var aggregate: u8 = 0;
            for (digest) |byte| aggregate |= byte;
            if (aggregate == 0)
                return error.InvalidIncrementalOmittedEthereumOmissionSection;
        }
    }

    /// Fail-closed readmission against the live authorities the verifier
    /// rebuilt for itself. `plan` must be the plan rebuilt from the pins and
    /// the call list, never one recovered from the decoded bytes.
    pub fn validateAgainst(
        self: *const DecodedOmissionV1,
        projection: *const omission.ProjectionV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        provider_stage_a: anytype,
        shared: anytype,
        projected_bridge: *const incremental_bridge.GeometryV3,
        frame: *const IncrementalOmissionFrameV4,
        leaf_omission: *const LeafOmissionAuthorityV4,
    ) !void {
        return self.validateAgainstBindings(
            .{
                .projection_identity = projection.identity,
                .plan_identity = plan.identity,
                .manifest_identity = provider_stage_a.identity,
                .shared_identity = shared.identity,
                .relation_context_identity = shared.relation_context.identity,
                .interaction_pow = shared.interaction_pow,
            },
            projected_bridge,
            frame,
            leaf_omission,
        );
    }

    /// Digest-level core of `validateAgainst`, split out so the whole
    /// comparison matrix is reachable without minting a projection, a plan and
    /// an engine-typed Stage-A manifest.
    pub fn validateAgainstBindings(
        self: *const DecodedOmissionV1,
        bindings: OmissionBindingsV1,
        projected_bridge: *const incremental_bridge.GeometryV3,
        frame: *const IncrementalOmissionFrameV4,
        leaf_omission: *const LeafOmissionAuthorityV4,
    ) !void {
        try self.validate();
        try frame.validate();
        try leaf_omission.validate();
        if (!std.mem.eql(
            u8,
            &self.projection_identity,
            &bindings.projection_identity,
        ) or !std.mem.eql(
            u8,
            &self.plan_identity,
            &bindings.plan_identity,
        ) or !std.mem.eql(
            u8,
            &self.manifest_identity,
            &bindings.manifest_identity,
        ) or !std.mem.eql(
            u8,
            &self.shared_identity,
            &bindings.shared_identity,
        ) or !std.mem.eql(
            u8,
            &self.relation_context_identity,
            &bindings.relation_context_identity,
        ) or self.interaction_pow != bindings.interaction_pow or
            !std.mem.eql(u8, &self.frame_identity, &frame.identity) or
            !std.mem.eql(
                u8,
                &self.leaf_omission_identity,
                &leaf_omission.identity,
            ))
        {
            return error.InvalidIncrementalOmittedEthereumOmissionSection;
        }
        if (!std.meta.eql(
            self.projected_bridge_geometry,
            projected_bridge.*,
        )) return error.IncrementalOmittedEthereumBridgeGeometryMismatch;
        if (!std.meta.eql(
            frame.projected_bridge_geometry,
            projected_bridge.*,
        )) return error.IncrementalOmittedEthereumBridgeGeometryMismatch;
    }
};

/// The six live identities `DecodedOmissionV1` is readmitted against.
pub const OmissionBindingsV1 = struct {
    projection_identity: Digest,
    plan_identity: Digest,
    manifest_identity: Digest,
    shared_identity: Digest,
    relation_context_identity: Digest,
    interaction_pow: u64,
};

pub fn ProveOutputV4Omitted(comptime Engine: type) type {
    return struct {
        /// FULL statement: the public statement of this leaf never becomes the
        /// projected one, because ordinary admission requires the omitted
        /// descriptor and can never accept a projected core.
        statement: statement_v2.RiscVStatementV2,
        extension: ethereum_statement.Statement,
        /// FULL-prefix bridge geometry, exactly as the profile pins it.
        bridge_geometry: incremental_bridge.GeometryV3,
        /// Projected-prefix bridge geometry: what the proved components used.
        projected_bridge_geometry: incremental_bridge.GeometryV3,
        projection: omission.ProjectionV1,
        frame_v4: IncrementalOmissionFrameV4,
        leaf_omission: LeafOmissionAuthorityV4,
        shared_relation: omit_protocol.SharedRelationAuthorityV1(Engine),
        prover_residual: QM31,
        proof: types.ProofForEngine(Engine),
        claims: InteractionClaimsV4,
        public_boundary_identity_sha256: [32]u8,
        profile_identity_sha256: [32]u8,
        /// Channel checkpoint immediately after `Relations.draw`. The G6
        /// parity test compares it against the adapter replay and the cold
        /// verifier; nothing in the proof depends on it.
        transcript_after_relations_digest: [8]u32,
        transcript_after_relations_draw_count: u32,

        const Self = @This();

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.claims.deinit(allocator);
            self.* = undefined;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.claims.deinit(allocator);
            self.* = undefined;
        }
    };
}

pub fn FreshOmittedCoreV4(comptime Engine: type) type {
    return struct {
        fresh_core: omit_protocol.FreshCoreResidualV1,
        shared: omit_protocol.SharedRelationAuthorityV1(Engine),
        relations: ethereum_transcript.Relations,
        leaf_omission: LeafOmissionAuthorityV4,
        transcript_after_relations_digest: [8]u32,
        transcript_final_digest: [8]u32,
        draw_count: u32,
    };
}

// ---------------------------------------------------------------------------
// Shared route geometry and transcript prefix
// ---------------------------------------------------------------------------

/// Projected prefix and bridge placement for an already-installed projection.
/// The prover calls it once before Tree 0; the verifier calls it again from the
/// decoded statement. Both go through `route.projectedBridgeGeometryFromPrefix`,
/// which fails closed unless exactly (2, 445, 8) columns left.
pub fn projectedRouteGeometry(
    full_bridge: *const incremental_bridge.GeometryV3,
    projected_core: *const statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !ProjectedRouteGeometryV4 {
    const prefix = try route.projectedPrefixColumns(
        projected_core,
        extension,
        authenticated,
        manifest,
    );
    return .{
        .prefix = prefix,
        .bridge = try route.projectedBridgeGeometryFromPrefix(
            full_bridge,
            prefix,
        ),
    };
}

/// Placement-only sibling, callable without a statement. Kept public so the
/// arithmetic that both sides depend on has a unit-testable seam.
pub fn projectedRouteGeometryFromPrefix(
    full_bridge: *const incremental_bridge.GeometryV3,
    projected_prefix: incremental_bridge.PrefixColumnsV3,
) !ProjectedRouteGeometryV4 {
    return .{
        .prefix = projected_prefix,
        .bridge = try route.projectedBridgeGeometryFromPrefix(
            full_bridge,
            projected_prefix,
        ),
    };
}

/// Transcript steps [1] and [2]: the unchanged full-statement profile prefix,
/// then the pre-Tree0 omission frame. Producer, cold verifier and the shard
/// adapter all call exactly this, so the single Fiat-Shamir order cannot drift
/// between the three sides.
pub fn mixRoutePreTree0(
    profile: anytype,
    native: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data_v1.PublicData,
    frame: *const IncrementalOmissionFrameV4,
    channel: anytype,
) !void {
    try frame.validate();
    try profile.mixPreTree0(native, role_aware_public, channel);
    frame.mixInto(channel);
}

/// The per-shard non-portability digest of this leaf.
pub fn leafOmissionAuthority(
    profile_identity_sha256: [32]u8,
    frame: *const IncrementalOmissionFrameV4,
    shared_identity: Digest,
    full_statement_authority_id: route.AuthorityId,
) !LeafOmissionAuthorityV4 {
    try frame.validate();
    return LeafOmissionAuthorityV4.canonical(
        profile_identity_sha256,
        frame.identity,
        shared_identity,
        full_statement_authority_id,
    );
}

// ---------------------------------------------------------------------------
// Admission prologue (copied from the native prepared entry, split only so the
// engine-independent half has a unit-testable seam; the order is unchanged)
// ---------------------------------------------------------------------------

/// First three refusals of `provePreparedWithEngineUsingChannel`, verbatim:
/// a non-strict CPU contention policy, an empty execution trace, and a PCS
/// config that is not the profile's. None of them touches the statement, so
/// they run before the proof execution pool exists.
pub fn admitOmittedExecutionAndTrace(
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    profile: anytype,
    execution: ExecutionOptions,
) !void {
    if (execution.cpu) |cpu| {
        if (cpu.contention_policy != .strict)
            return error.NonStrictExecutionPolicy;
    }
    if (exec_trace.step_count == 0) return error.EmptyTrace;
    if (!std.meta.eql(pcs_config, try profile.pcsConfig()))
        return error.IncrementalEthereumPcsMismatch;
}

/// Remainder of the native prepared prologue, verbatim: prepared-statement
/// closure, shared public authority, optional statement admission, clock
/// authority, canonical extension closure, and full-statement V2 admission.
/// The statement handed to `proof_admission.validateV2` is always the FULL
/// one -- a projected core cannot pass `validateGeometry` by construction.
pub fn admitPreparedOmittedStatement(
    exec_trace: *const trace_mod.Trace,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data_v1.PublicData,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    prepared: PreparedProofInputsV4,
    execution: ExecutionOptions,
) !void {
    const external_count = std.math.add(
        usize,
        keccak_calls.len(),
        recovery_calls.len(),
    ) catch return error.InvalidStatement;
    const external_retirements = std.math.cast(u32, external_count) orelse
        return error.InvalidStatement;
    if (!std.meta.eql(prepared.geometry.statement, expected_statement.*) or
        !std.meta.eql(
            prepared.workspace.statement,
            expected_statement.core,
        ) or prepared.extension.counts.external_retirements !=
        external_retirements)
    {
        return error.IncrementalEthereumPreparedStatementMismatch;
    }
    try incremental_public.validateSharedAuthority(
        &expected_statement.public_data,
        role_aware_public,
    );
    if (execution.statement_admission) |admission|
        try admission.admit(expected_statement);
    const core_public = try statement_v2.canonicalCorePublicData(
        &expected_statement.public_data,
    );
    _ = try validateClockAuthority(
        exec_trace,
        keccak_calls.len(),
        keccak_rows.rows().len,
        recovery_calls.len(),
        recovery_rows.rows().len,
        core_public.clock,
    );
    const canonical_extension = try ethereum_statement.Statement.canonicalV2(
        expected_statement,
        @intCast(keccak_calls.len()),
        @intCast(recovery_calls.len()),
        prepared.ethereum_witness.shapes(),
    );
    if (!std.meta.eql(canonical_extension, prepared.extension.*))
        return error.IncrementalEthereumPreparedExtensionMismatch;
    try proof_admission.validateV2(
        expected_statement,
        prepared.extension,
        .proof,
    );
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// One omitted-provider core proof over an already prepared transaction.
///
/// `extension` must already carry its O(1) validated plan/call authority (G1):
/// without it every readmission on this path re-hashes 6.67M calls and the
/// first Metal timing measures rehashing rather than proving, so a missing
/// token is a refusal, not a slow path.
pub fn provePreparedOmittedProviderWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    exec_trace: *const trace_mod.Trace,
    opt_chain: ?*const state_chain.StateChainTracker,
    full_witness: *const incremental_witness.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data_v1.PublicData,
    keccak_calls: *const keccak_calls_mod.Frozen,
    keccak_rows: *const keccak_rows_mod.FrozenExecutionRows,
    recovery_calls: *const recovery_calls_mod.Frozen,
    recovery_rows: *const recovery_rows_mod.FrozenExecutionRows,
    prepared: PreparedProofInputsV4,
    profile: anytype,
    recorder: ?*stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: ExecutionOptions,
    extension: *omit_protocol.Extension(Engine),
    options: OmittedRouteOptionsV1,
) !ProveOutputV4Omitted(Engine) {
    comptime types.assertProverEngine(Engine);

    // ---- 1. Admission prologue, copied from the native prepared entry ------
    try admitOmittedExecutionAndTrace(
        pcs_config,
        exec_trace,
        profile,
        execution,
    );

    var execution_pool: orchestration.ProofExecutionPool = .{};
    try execution_pool.initInPlace(allocator, execution.cpu);
    defer execution_pool.deinit();

    try admitPreparedOmittedStatement(
        exec_trace,
        expected_statement,
        role_aware_public,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        prepared,
        execution,
    );

    const workspace = prepared.workspace;
    const built = prepared.geometry;
    const ext_statement = prepared.extension;
    const witness = prepared.ethereum_witness;

    // ---- 2. Manifest and authenticated statement over the FULL core -------
    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &workspace.statement,
        &manifest,
    );
    try profile.validateAgainstStatement(
        &built.statement,
        ext_statement,
        role_aware_public,
    );
    const bridge_geometry = profile.bridge_geometry;
    try bridge_geometry.validateAfterPrefix(try prefixColumns(
        &built.statement,
        ext_statement,
        &authenticated,
        &manifest,
    ));
    const bridge_rows = full_witness.boundary.bridgeRows();
    if (bridge_rows.len != @as(usize, bridge_geometry.n_rows))
        return error.IncrementalBridgeGeometryMismatch;

    // ---- 3. Install the projected core, restoring it on every exit --------
    const validated = extension.validated orelse
        return error.MissingValidatedProviderPlanCallAuthorityV4;
    const full_core = workspace.statement;
    try extension.prepareProjectedCoreValidated(
        &built.statement,
        ext_statement,
        &manifest,
        &authenticated,
        validated,
        &workspace.statement,
        built.base,
    );
    // `PreparedProofTransactionV4.validateBorrowed` requires
    // `geometry.statement.core == workspace.statement`, so the projected core
    // is a strictly scoped substitution.
    defer workspace.statement = full_core;
    const projection = try extension.providerProjection();
    if (!std.meta.eql(
        workspace.statement,
        projection.projected_native.core,
    )) return error.IncrementalOmittedEthereumProjectedCoreMismatch;
    const projected_core = &workspace.statement;

    // ---- 4. Projected bridge placement and the pre-Tree0 frame ------------
    const projected = try projectedRouteGeometry(
        &bridge_geometry,
        projected_core,
        ext_statement,
        &authenticated,
        &manifest,
    );
    const frame_v4 = try IncrementalOmissionFrameV4.canonical(
        projection,
        bridge_geometry.n_rows,
        projected.prefix,
    );
    try frame_v4.validateAgainst(projection, projected.prefix);

    // ---- 5. Transcript [1] and [2] ---------------------------------------
    try mixRoutePreTree0(
        profile,
        &built.statement,
        role_aware_public,
        &frame_v4,
        channel,
    );

    // ---- 6. Tree 0: projected preprocessed + Ethereum + bridge -----------
    var scheme = try Engine.init(allocator, pcs_config);
    var scheme_owned = true;
    defer if (scheme_owned) Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);

    // The bridge trace types read only `log_size`/`n_rows`, which the
    // projection leaves untouched; only the placement moves.
    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        &bridge_geometry,
    );
    defer bridge_tree0.deinit();
    const tree0_blocks = [_]external_tree.BorrowedBlock{bridge_tree0.block()};
    const tree0 = try ethereum_preprocessed
        .generateWithoutNativePoseidonV2WithExternalBlocks(
        allocator,
        projection,
        &built.statement,
        ext_statement,
        &tree0_blocks,
    );
    var tree0_moved = false;
    errdefer if (!tree0_moved) freeColumns(allocator, tree0);
    tree0_moved = true;
    try Engine.commit(&scheme, allocator, tree0, recorder, channel);

    // ---- 7. Tree 1: projected infra (no 445-column table) ----------------
    var bridge_tree1 = try incremental_bridge.MainTraceV3.init(
        allocator,
        bridge_rows,
        &bridge_geometry,
    );
    defer bridge_tree1.deinit();
    const tree1_blocks = [_]external_tree.BorrowedBlock{bridge_tree1.block()};
    const tree1_logs = try ethereum_main.logSizesWithExternalBlocks(
        allocator,
        projected_core,
        ext_statement,
        &tree1_blocks,
    );
    defer allocator.free(tree1_logs);
    _ = try segment_orchestration.requireTree1Residency(
        tree1_logs,
        pcs_config.fri_config.log_blowup_factor,
        if (execution.cpu) |cpu|
            cpu.host_byte_budget
        else
            std.math.maxInt(usize),
    );
    var retained = try ethereum_main
        .commitWithoutNativePoseidonWithExternalBlocks(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        exec_trace,
        &full_witness.base,
        built.base,
        opt_chain,
        witness,
        keccak_calls.records(),
        recovery_calls.records(),
        projection,
        &tree1_blocks,
        // The bridge issues no fixed-table lookups (G5).
        null,
    );
    defer retained.deinit(allocator, workspace);

    // ---- 8. Transcript [5] and the single relation draw [6] --------------
    try profile.mixPostTree1(
        &built.statement,
        role_aware_public,
        channel,
    );
    // A no-op unless the engine deferred its first tree. The route requires
    // both roots to be absorbed at [3] and [4], i.e. before `mixPostTree1`;
    // an engine that actually deferred one to this point would produce a
    // transcript the Step-5 shard adapter cannot replay, so the disagreement
    // surfaces as a failed shard verification, never as a silent divergence.
    try Engine.flushPendingCommit(&scheme, allocator, channel);
    const prefix = try extension.drawChallenges(
        allocator,
        &scheme,
        channel,
        &built.statement,
        projected_core,
        ext_statement,
        &manifest,
        &authenticated,
        recorder,
    );
    const transcript_after_relations_digest = channel.digestWords();
    const transcript_after_relations_draw_count = channel.n_draws;
    const shared_relation = extension.shared_relation orelse
        return error.MissingIncrementalOmittedEthereumSharedAuthority;
    const leaf_omission = try leafOmissionAuthority(
        profile.identity_sha256,
        &frame_v4,
        shared_relation.identity,
        built.statement.authority_id,
    );

    // ---- 9. Optional serial cancellation diagnostic (G7, default off) ----
    if (options.diagnostic_cancellation) {
        try full_witness.boundary.verifyMerkleAndPoseidonCancellation(
            &prefix.relations.base,
        );
    }

    // ---- 10. Tree 2: projected interaction + Ethereum + bridge -----------
    var bridge_tree2 = try incremental_bridge.InteractionTraceV3.init(
        allocator,
        bridge_rows,
        full_witness.boundary.roots().entry,
        full_witness.boundary.roots().exit,
        &prefix.relations.base,
        &bridge_geometry,
    );
    defer bridge_tree2.deinit();
    const bridge_claim = bridge_tree2.claim();
    var bridge_columns = bridge_tree2.ownedColumns();

    const base_claim = try allocator.create(statement.RiscVInteractionClaim);
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
    const extension_claim = try ethereum_interaction
        .generateAndCommitWithoutNativePoseidonAuthenticatedLookupV2WithExternal(
        Engine,
        allocator,
        workspace,
        &scheme,
        channel,
        recorder,
        &full_witness.base,
        built.base,
        &retained.lookup_source,
        &prefix,
        witness,
        pool,
        base_claim,
        &manifest,
        &authenticated,
        projection,
        &bridge_columns,
        BridgeClaimMix{ .claim = bridge_claim },
        mixBridgeClaim,
    );
    try extension_claim.validate(ext_statement);

    // ---- 11. Residual (diagnostic; the shard closure is authoritative) ---
    try projection.validateAgainstValidated(
        &built.statement,
        ext_statement,
        .proof,
        &manifest,
        &authenticated,
        extension.plan,
        extension.calls,
        validated,
        built.base,
    );
    const canonical = try authenticated.canonicalInteractionClaim(
        projected_core,
        &manifest,
        base_claim,
    );
    const public_boundary = try incremental_public.sum(
        &built.statement.public_data,
        role_aware_public,
        &prefix.relations.base,
    );
    const residual = route.residualIncrementalV4(
        public_boundary,
        canonical.view().total(),
        &extension_claim,
        bridge_claim,
    );
    try extension.recordProverResidual(residual);

    // ---- 12. Assembly over the PROJECTED core and bridge placement -------
    const base_components = try proof_finalize
        .assembleAuthenticatedLookupV2WithIncrementalBoundaryV3(
        workspace,
        &prefix.relations.base,
        base_claim,
        projected_core.nMainColumns(),
        try authenticated.totalInteractionColumns(projected_core, &manifest),
        &manifest,
        &authenticated,
    );
    const ethereum_components = try ethereum_assembly.Assembly(.prover)
        .createWithoutNativePoseidonAuthenticatedLookupV2(
        allocator,
        projection,
        &built.statement,
        ext_statement,
        &prefix.relations,
        base_components,
        &extension_claim,
        &manifest,
        &authenticated,
    );
    defer ethereum_components.destroy(allocator);
    const roots = full_witness.boundary.roots();
    const assembly = try incremental_bridge.Assembly(.prover).create(
        allocator,
        ethereum_components.active(),
        &projected.bridge,
        roots.entry,
        roots.exit,
        &prefix.relations.base,
        bridge_claim,
    );
    defer assembly.destroy(allocator);

    // ---- 13. Prove -------------------------------------------------------
    scheme_owned = false;
    var extended = try Engine.prove(
        allocator,
        assembly.active(),
        channel,
        scheme,
        .{
            .recorder = recorder,
            .cpu_composition_execution = execution.cpu,
        },
    );
    const proof = extended.proof;
    extended.aux.deinit(allocator);
    work_pool.recordProofPublicationForTest(execution_pool.get());
    claim_owned = false;
    return .{
        .statement = built.statement,
        .extension = ext_statement.*,
        .bridge_geometry = bridge_geometry,
        .projected_bridge_geometry = projected.bridge,
        .projection = projection.*,
        .frame_v4 = frame_v4,
        .leaf_omission = leaf_omission,
        .shared_relation = shared_relation,
        .prover_residual = residual,
        .proof = proof,
        .claims = .{
            .base = base_claim,
            .ethereum = extension_claim,
            .bridge = bridge_claim,
        },
        .public_boundary_identity_sha256 = incremental_public
            .publicBoundaryIdentity(
            &built.statement.public_data,
            role_aware_public,
        ),
        .profile_identity_sha256 = profile.identity_sha256,
        .transcript_after_relations_digest = transcript_after_relations_digest,
        .transcript_after_relations_draw_count = transcript_after_relations_draw_count,
    };
}

// ---------------------------------------------------------------------------
// Cold verifier
// ---------------------------------------------------------------------------

/// Cold verifier for one omitted-provider core. Consumes `proof_in` on every
/// path and mints only a `FreshCoreResidualV1` -- never a
/// `FreshVerifiedCaptureV4`, whose `validate` re-derives the bridge placement
/// from the FULL statement and would reject this proof's projected placement.
///
/// `extension` must already have run `prepareProjectedVerifierCore` (or a
/// validated sibling) and must carry the expected shared relation authority so
/// that a mismatched draw is refused inside `verifyRelations`.
pub fn verifyOmittedProviderWithEngineUsingChannel(
    comptime Engine: type,
    comptime Profile: type,
    allocator: std.mem.Allocator,
    statement_value: *const statement_v2.RiscVStatementV2,
    extension_statement: *const ethereum_statement.Statement,
    role_aware_public: *const public_data_v1.PublicData,
    profile: *const Profile,
    proof_in: types.ProofForEngine(Engine),
    base_claim: *const statement.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
    decoded_omission: DecodedOmissionV1,
    channel: *Engine.Channel,
    extension: *omit_protocol.Extension(Engine),
) !FreshOmittedCoreV4(Engine) {
    var proof = proof_in;
    var proof_moved = false;
    defer if (!proof_moved) proof.deinit(allocator);
    if (proof.commitment_scheme_proof.commitments.items.len !=
        COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalEthereumProofShape;
    }
    try statement_value.validate();
    try extension_statement.validateV2(statement_value);
    try extension_claim.validate(extension_statement);
    try incremental_public.validateSharedAuthority(
        &statement_value.public_data,
        role_aware_public,
    );
    try profile.validateAgainstStatement(
        statement_value,
        extension_statement,
        role_aware_public,
    );
    const pcs_config = try profile.pcsConfig();
    if (!std.meta.eql(
        pcs_config,
        proof.commitment_scheme_proof.config,
    )) return error.InvalidIncrementalEthereumProofShape;

    var manifest = lookup_physical_v2.Manifest.native();
    const authenticated = try lookup_physical_v2.AuthenticatedStatement.init(
        &statement_value.core,
        &manifest,
    );
    try profile.bridge_geometry.validateAfterPrefix(try prefixColumns(
        statement_value,
        extension_statement,
        &authenticated,
        &manifest,
    ));

    // G1 on the verify side too: without the O(1) authority every readmission
    // below re-hashes the whole call corpus.
    if (extension.validated == null)
        return error.MissingValidatedProviderPlanCallAuthorityV4;
    // The caller must have named the draw it expects, so a re-drawn transcript
    // is refused inside `verifyRelations` rather than only by the decoded
    // omission section further down.
    if (extension.expected_shared_relation == null)
        return error.MissingExpectedEthereumProviderSharedAuthorityV4;
    if (!extension.projection_ready)
        return error.ProjectionNotPrepared;
    const projection = try extension.providerProjection();
    try projection.validateSealAndFull(statement_value, extension_statement);
    const projected_core = &projection.projected_native.core;
    // The claim is counted against the PROJECTED core: one infrastructure
    // component fewer than the full statement the profile was minted over.
    if (base_claim.n_infra != projected_core.n_infra or
        base_claim.n_components != projected_core.n_components)
    {
        return error.InvalidIncrementalOmittedEthereumClaimStructure;
    }

    const projected = try projectedRouteGeometry(
        &profile.bridge_geometry,
        projected_core,
        extension_statement,
        &authenticated,
        &manifest,
    );
    if (!std.meta.eql(
        projected.bridge,
        decoded_omission.projected_bridge_geometry,
    )) return error.IncrementalOmittedEthereumBridgeGeometryMismatch;
    const frame_v4 = try IncrementalOmissionFrameV4.canonical(
        projection,
        profile.bridge_geometry.n_rows,
        projected.prefix,
    );
    try frame_v4.validateAgainst(projection, projected.prefix);
    if (!std.mem.eql(
        u8,
        &frame_v4.identity,
        &decoded_omission.frame_identity,
    )) return error.InvalidIncrementalOmittedEthereumOmissionSection;

    // Tree shapes are the PROJECTED ones; the bridge blocks keep their rows.
    var bridge_tree0 = try incremental_bridge.PreprocessedTraceV3.init(
        allocator,
        &profile.bridge_geometry,
    );
    defer bridge_tree0.deinit();
    const tree0_blocks = [_]external_tree.BorrowedBlock{bridge_tree0.block()};
    const tree0_columns = try ethereum_preprocessed
        .generateWithoutNativePoseidonV2WithExternalBlocks(
        allocator,
        projection,
        statement_value,
        extension_statement,
        &tree0_blocks,
    );
    try verifyPreprocessedRoot(
        Engine,
        allocator,
        pcs_config,
        tree0_columns,
        proof.commitment_scheme_proof.commitments.items[0],
    );

    const empty_main = [_][]const m31.M31{&.{}} **
        incremental_bridge.MAIN_COLUMNS;
    const main_shape = external_tree.BorrowedBlock{
        .log_size = profile.bridge_geometry.log_size,
        .columns = &empty_main,
    };
    const empty_interaction = [_][]const m31.M31{&.{}} **
        incremental_bridge.INTERACTION_COLUMNS;
    const interaction_shape = external_tree.BorrowedBlock{
        .log_size = profile.bridge_geometry.log_size,
        .columns = &empty_interaction,
    };
    const tree0_logs = try ethereum_preprocessed.logSizesWithExternalBlocks(
        allocator,
        projected_core,
        extension_statement,
        &tree0_blocks,
    );
    defer allocator.free(tree0_logs);
    const tree1_logs = try ethereum_main.logSizesWithExternalBlocks(
        allocator,
        projected_core,
        extension_statement,
        &.{main_shape},
    );
    defer allocator.free(tree1_logs);
    const tree2_prefix = try ethereum_interaction.logSizesAuthenticatedLookupV2(
        allocator,
        projected_core,
        extension_statement,
        &manifest,
        &authenticated,
    );
    defer allocator.free(tree2_prefix);
    const tree2_logs = try external_tree.appendLogSizes(
        allocator,
        tree2_prefix,
        &.{interaction_shape},
    );
    defer allocator.free(tree2_logs);

    // Transcript [1] and [2].
    try mixRoutePreTree0(
        profile,
        statement_value,
        role_aware_public,
        &frame_v4,
        channel,
    );
    var scheme = try pcs_verifier.CommitmentSchemeVerifier(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
    ).init(allocator, pcs_config);
    defer scheme.deinit(allocator);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[0],
        tree0_logs,
        channel,
    );
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[1],
        tree1_logs,
        channel,
    );

    // Transcript [5] and the shared draw [6]. `verifyRelations` re-verifies the
    // 16-bit interaction PoW and rejects a shared-authority mismatch.
    try profile.mixPostTree1(statement_value, role_aware_public, channel);
    const relations = try extension.verifyRelations(
        allocator,
        pcs_config,
        channel,
        statement_value,
        projected_core,
        extension_statement,
        &manifest,
        &authenticated,
        base_claim.interaction_pow,
        proof.commitment_scheme_proof.commitments.items[0],
        proof.commitment_scheme_proof.commitments.items[1],
    );
    const transcript_after_relations_digest = channel.digestWords();
    const draw_count_after_relations = channel.n_draws;
    const shared = extension.shared_relation orelse
        return error.MissingIncrementalOmittedEthereumSharedAuthority;
    const leaf_omission = try leafOmissionAuthority(
        profile.identity_sha256,
        &frame_v4,
        shared.identity,
        statement_value.authority_id,
    );
    if (!std.mem.eql(
        u8,
        &leaf_omission.identity,
        &decoded_omission.leaf_omission_identity,
    )) return error.InvalidIncrementalOmittedEthereumOmissionSection;
    try decoded_omission.validateAgainst(
        projection,
        extension.plan,
        extension.provider_stage_a,
        shared,
        &projected.bridge,
        &frame_v4,
        &leaf_omission,
    );

    // Transcript [7] and Tree 2 [8].
    try ethereum_transcript.mixInteractionClaimV2(
        channel,
        projected_core,
        &manifest,
        &authenticated,
        base_claim,
        extension_claim,
    );
    incremental_bridge.mixClaim(channel, bridge_claim);
    try scheme.commit(
        allocator,
        proof.commitment_scheme_proof.commitments.items[2],
        tree2_logs,
        channel,
    );

    const canonical = try authenticated.canonicalInteractionClaim(
        projected_core,
        &manifest,
        base_claim,
    );
    const public_sums = try incremental_public.VerifiedPublicSumsV4.init(
        &statement_value.public_data,
        role_aware_public,
        &relations.base,
    );
    // The native Poseidon2 claim is absent, so global cancellation does not
    // close here: this residual is exactly what the shard closure must supply.
    const fresh_residual = route.residualIncrementalV4(
        public_sums.total,
        canonical.view().total(),
        extension_claim,
        bridge_claim,
    );

    const workspace = try proof_workspace.VerificationWorkspace.create(
        allocator,
    );
    defer workspace.destroy(allocator);
    workspace.canonical = canonical;
    const base_components = try base_verifier
        .assembleComponentsAuthenticatedLookupV2WithIncrementalBoundaryV3(
        workspace,
        projected_core,
        base_claim,
        &relations.base,
        projected_core.nMainColumns(),
        try authenticated.totalInteractionColumns(projected_core, &manifest),
        &manifest,
        &authenticated,
    );
    const ethereum_components = try ethereum_assembly.Assembly(.verifier)
        .createWithoutNativePoseidonAuthenticatedLookupV2(
        allocator,
        projection,
        statement_value,
        extension_statement,
        &relations,
        base_components,
        extension_claim,
        &manifest,
        &authenticated,
    );
    defer ethereum_components.destroy(allocator);
    const roots = try incrementalRoots(statement_value);
    const assembly = try incremental_bridge.Assembly(.verifier).create(
        allocator,
        ethereum_components.active(),
        &projected.bridge,
        roots.entry,
        roots.exit,
        &relations.base,
        bridge_claim,
    );
    defer assembly.destroy(allocator);

    // `core_verifier.verify` consumes `proof` on every path, so the commitment
    // identity has to be taken while the proof is still alive.
    const commitments_identity = extension.proofCommitmentsIdentity(
        proof.commitment_scheme_proof.commitments.items,
    );
    proof_moved = true;
    try core_verifier.verify(
        types.HasherForEngine(Engine),
        Engine.MerkleChannel,
        allocator,
        assembly.active(),
        channel,
        &scheme,
        proof,
    );
    const transcript_final_digest = channel.digestWords();
    const draw_count = channel.n_draws;
    try validateTranscriptCheckpoint(transcript_final_digest, draw_count);
    try validateTranscriptCheckpoint(
        transcript_after_relations_digest,
        draw_count_after_relations,
    );

    try extension.recordFreshVerifierAuthority(
        fresh_residual,
        commitments_identity,
    );
    const fresh_core = extension.fresh_core orelse
        return error.MissingIncrementalOmittedEthereumFreshCore;
    try fresh_core.validate();
    return .{
        .fresh_core = fresh_core,
        .shared = shared,
        .relations = relations,
        .leaf_omission = leaf_omission,
        .transcript_after_relations_digest = transcript_after_relations_digest,
        .transcript_final_digest = transcript_final_digest,
        .draw_count = draw_count,
    };
}

// ---------------------------------------------------------------------------
// Helpers duplicated from the native V4 files (never exported from them)
// ---------------------------------------------------------------------------

const BridgeClaimMix = struct { claim: QM31 };

fn mixBridgeClaim(
    context: BridgeClaimMix,
    channel: anytype,
    _: *const statement.RiscVInteractionClaim,
    _: *const ethereum_types.ExtensionClaim,
) !void {
    incremental_bridge.mixClaim(channel, context.claim);
}

fn validateClockAuthority(
    trace: *const trace_mod.Trace,
    keccak_calls: usize,
    keccak_rows: usize,
    recovery_calls: usize,
    recovery_rows: usize,
    public_clock: u32,
) !u32 {
    if (keccak_calls != keccak_rows or recovery_calls != recovery_rows)
        return error.InvalidStatement;
    const external = std.math.add(usize, keccak_calls, recovery_calls) catch
        return error.InvalidStatement;
    const total = std.math.add(usize, trace.step_count, external) catch
        return error.InvalidStatement;
    if (std.math.cast(u32, total) != public_clock or
        trace.recordedExternalSteps() != external)
    {
        return error.InvalidStatement;
    }
    trace.validateClockRange(0, public_clock, external) catch
        return error.InvalidStatement;
    return std.math.cast(u32, external) orelse error.InvalidStatement;
}

/// FULL-statement committed prefix before the bridge. The projected sibling is
/// `route.projectedPrefixColumns`.
fn prefixColumns(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !incremental_bridge.PrefixColumnsV3 {
    var result = incremental_bridge.PrefixColumnsV3{
        .preprocessed = native.core.nPreprocessedColumns(),
        .main = native.core.nMainColumns(),
        .interaction = @intCast(
            try authenticated.totalInteractionColumns(&native.core, manifest),
        ),
    };
    for (extension.components) |descriptor| {
        result.preprocessed = try add(
            result.preprocessed,
            descriptor.preprocessed_columns,
        );
        result.main = try add(result.main, descriptor.main_columns);
        result.interaction = try add(
            result.interaction,
            descriptor.interaction_columns,
        );
    }
    try result.validate();
    return result;
}

fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    columns: []prover_pcs.ColumnEvaluation,
    expected: Engine.Hasher.Hash,
) !void {
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    scheme.setCoefficientRetentionPolicy(.never);
    var channel = Engine.Channel{};
    moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);
    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], expected))
        return error.InvalidIncrementalEthereumPreprocessedRoot;
}

fn incrementalRoots(
    native: *const statement_v2.RiscVStatementV2,
) !struct { entry: u32, exit: u32 } {
    return .{
        .entry = native.core.public_data.initial_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
        .exit = native.core.public_data.final_rw_root orelse
            return error.InvalidIncrementalEthereumStatement,
    };
}

fn validateTranscriptCheckpoint(digest: [8]u32, draw_count: u32) !void {
    if (draw_count >= m31.Modulus)
        return error.InvalidIncrementalOmittedEthereumTranscript;
    var aggregate: u32 = 0;
    for (digest) |word| {
        if (word >= m31.Modulus)
            return error.InvalidIncrementalOmittedEthereumTranscript;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidIncrementalOmittedEthereumTranscript;
}

fn add(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.IncrementalEthereumLeafGeometryOverflow;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

comptime {
    if (PRODUCTION_ACTIVE or ACTIVATES_PRODUCTION_PROOF or
        FORMAT_VERSION != 4 or COMMITMENT_TREE_COUNT != 4)
    {
        @compileError("omitted-provider incremental Ethereum route activated");
    }
    if (route.ACTIVATES_PRODUCTION_PROOF or
        omit_protocol.ACTIVATES_PRODUCTION_PROOF or
        omission.ACTIVATES_PRODUCTION_PROOF)
    {
        @compileError("omitted-provider protocol activated under this route");
    }
    if (!omit_protocol.OMIT_RECOMPUTE_CORE_IMPLEMENTED or
        !omit_protocol.FRESH_PROVIDER_CLOSURE_REQUIRED)
    {
        @compileError(
            "the omitted core route requires the fresh provider closure",
        );
    }
}
