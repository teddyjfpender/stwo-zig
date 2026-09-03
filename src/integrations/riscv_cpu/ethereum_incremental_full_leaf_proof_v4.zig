//! Integration owner for the full Ethereum + incremental-memory V4 leaf.
//!
//! STWIMT04 is coldly reconstructed once. The same boundary witness first
//! determines the joined profile geometry and is then moved into the complete
//! external-profile commitment witness. Proof and verification remain owned
//! by the frontend; this module supplies no digest-only admission path.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const artifact_v4 = @import("ethereum_incremental_boundary_artifact_v4.zig");
const boundary_v4 = @import("ethereum_incremental_boundary_authority_v4.zig");
const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const orchestration =
    frontend.testing.incremental_ethereum_orchestration_v4_internal;
const verifier = frontend.testing.incremental_ethereum_verifier_v4_internal;

const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const runner = frontend.runner;
const prover = frontend.prover_mod;
const witness_v3 = prover.incremental_commitment_witness_v3;

pub const FORMAT_VERSION: u16 = 4;
pub const PRODUCTION_ACTIVE = false;
pub const Profile = profile_mod.AuthorityV4;

pub fn FreshVerifiedCaptureV4(comptime Engine: type) type {
    comptime requireRecursiveEngine(Engine);
    return verifier.FreshVerifiedCaptureV4(Engine, Profile);
}

/// Owns the one cold reconstruction and the one full commitment witness used
/// by statement derivation, profile minting, and proof generation.
pub const PreparedWitnessV4 = struct {
    cold: artifact_v4.ColdReconstructionV4,
    full: witness_v3.FullWitnessV3,

    pub fn deinit(self: *PreparedWitnessV4, allocator: std.mem.Allocator) void {
        self.full.deinit(allocator);
        self.cold.deinit();
        self.* = undefined;
    }

    pub fn mintProfile(
        self: *const PreparedWitnessV4,
        artifact: *const artifact_v4.OwnedArtifactV4,
        public_authority: boundary_v4.SegmentPublicAuthorityV4,
        native: *const statement_v2.RiscVStatementV2,
        ethereum: *const ethereum_statement.Statement,
    ) !Profile {
        return profile_mod.mintFromColdReconstruction(
            native,
            ethereum,
            public_authority,
            artifact,
            &self.cold,
            &self.full.boundary,
        );
    }
};

/// Consumes only cold-authenticated V4 transport plus exact live execution
/// sources. `execution_sources` must be the statement-ordered tuple
/// `{base rows, Keccak rows, recovery rows}` from one Ethereum session.
pub fn prepareFullWitnessFromColdArtifact(
    allocator: std.mem.Allocator,
    execution_sources: anytype,
    opt_memory: ?*const runner.memory_state.Snapshot,
    completion: public_data.Completion,
    artifact: *const artifact_v4.OwnedArtifactV4,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    limits: artifact_v4.Limits,
) !PreparedWitnessV4 {
    var cold = try artifact_v4.coldReconstruct(
        allocator,
        artifact,
        segment_public_wire,
        public_authority,
        limits,
    );
    var cold_owned = true;
    errdefer if (cold_owned) cold.deinit();
    var boundary = try profile_mod.deriveBoundaryWitness(
        allocator,
        artifact,
        public_authority,
        &cold,
    );
    var boundary_owned = true;
    errdefer if (boundary_owned) boundary.deinit();
    const full = try witness_v3.buildFullExternalProfileFromBoundary(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        execution_sources,
        opt_memory,
        completion,
        &boundary,
    );
    boundary_owned = false;
    cold_owned = false;
    return .{ .cold = cold, .full = full };
}

/// Prepared-program sibling of `prepareFullWitnessFromColdArtifact`.
///
/// Cold transport reconstruction and incremental-boundary ownership are
/// unchanged. The extra argument is a process-local, token-validated borrow
/// of immutable program commitment material; only leaf fetch multiplicities
/// are rebuilt. No proof, transcript, or verifier state is shared.
pub fn prepareFullWitnessFromColdArtifactPreparedProgram(
    allocator: std.mem.Allocator,
    execution_sources: anytype,
    opt_memory: ?*const runner.memory_state.Snapshot,
    completion: public_data.Completion,
    prepared_program: anytype,
    artifact: *const artifact_v4.OwnedArtifactV4,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v4.SegmentPublicAuthorityV4,
    limits: artifact_v4.Limits,
) !PreparedWitnessV4 {
    try prepared_program.validate();
    var cold = try artifact_v4.coldReconstruct(
        allocator,
        artifact,
        segment_public_wire,
        public_authority,
        limits,
    );
    var cold_owned = true;
    errdefer if (cold_owned) cold.deinit();
    var boundary = try profile_mod.deriveBoundaryWitness(
        allocator,
        artifact,
        public_authority,
        &cold,
    );
    var boundary_owned = true;
    errdefer if (boundary_owned) boundary.deinit();
    const full = try witness_v3
        .buildFullExternalProfileFromBoundaryPreparedProgram(
        allocator,
        .rv32im_zkvm_ethereum_v1,
        execution_sources,
        opt_memory,
        completion,
        prepared_program,
        &boundary,
    );
    boundary_owned = false;
    cold_owned = false;
    return .{ .cold = cold, .full = full };
}

pub fn prepareStatement(
    allocator: std.mem.Allocator,
    exec_trace: *const runner.trace.Trace,
    opt_chain: ?*const runner.state_chain.StateChainTracker,
    prepared: *const PreparedWitnessV4,
    public_wire: public_data_v2.PublicDataV2,
    external_retirements: u32,
) !statement_v2.RiscVStatementV2 {
    return orchestration.prepareStatement(
        allocator,
        exec_trace,
        opt_chain,
        &prepared.full,
        public_wire,
        external_retirements,
    );
}

pub fn proveWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    exec_trace: *const runner.trace.Trace,
    opt_chain: ?*const runner.state_chain.StateChainTracker,
    prepared: *const PreparedWitnessV4,
    expected_statement: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data.PublicData,
    keccak_calls: *const runner.guest_precompile.keccakf_call_buffer.Frozen,
    keccak_rows: *const runner.guest_precompile.keccakf_v1.FrozenExecutionRows,
    recovery_calls: *const runner.guest_precompile.secp256k1_recover_call_buffer.Frozen,
    recovery_rows: *const runner.guest_precompile.secp256k1_recover_v1.FrozenExecutionRows,
    profile: *const Profile,
    recorder: ?*@import("stwo_prover_api").stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: orchestration.ExecutionOptions,
) !orchestration.ProveOutputV4(Engine) {
    comptime requireRecursiveEngine(Engine);
    return orchestration.proveWithEngineUsingChannel(
        Engine,
        allocator,
        try profile.pcsConfig(),
        exec_trace,
        opt_chain,
        &prepared.full,
        expected_statement,
        role_aware_public,
        keccak_calls,
        keccak_rows,
        recovery_calls,
        recovery_rows,
        profile,
        recorder,
        channel,
        execution,
    );
}

/// Consumes `proof` on every path and returns only a verifier-owned PCS/FRI
/// capture after the full base + Ethereum + bridge AIR transaction closes.
pub fn verifyWithEngineUsingChannelAndCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data.PublicData,
    profile: *const Profile,
    proof: prover.ProofForEngine(Engine),
    base_claim: *const frontend.air.statement.RiscVInteractionClaim,
    extension_claim: *const prover.guest_precompile.ethereum_types.ExtensionClaim,
    bridge_claim: @import("stwo_core").fields.qm31.QM31,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine),
) !void {
    comptime requireRecursiveEngine(Engine);
    try verifier.verifyWithEngineUsingChannelAndCapture(
        Engine,
        Profile,
        allocator,
        statement,
        extension,
        role_aware_public,
        profile,
        proof,
        base_claim,
        extension_claim,
        bridge_claim,
        channel,
        capture_out,
    );
}

/// Independent cold-verifier fast path. The retained lease is a process-local
/// capability minted by statement artifact decode against STWESG31 roots and
/// is moved into the fresh capture only after successful proof verification.
pub fn verifyWithEngineUsingChannelAndCaptureTakingLease(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    role_aware_public: *const public_data.PublicData,
    profile: *const Profile,
    proof: prover.ProofForEngine(Engine),
    base_claim: *const frontend.air.statement.RiscVInteractionClaim,
    extension_claim: *const prover.guest_precompile.ethereum_types.ExtensionClaim,
    bridge_claim: @import("stwo_core").fields.qm31.QM31,
    validated_lease_inout: *?public_data_v2.PublicDataV2
        .OwnedValidatedLeaseV2,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV4(Engine),
) !void {
    comptime requireRecursiveEngine(Engine);
    try verifier.verifyWithEngineUsingChannelAndCaptureTakingLease(
        Engine,
        Profile,
        allocator,
        statement,
        extension,
        role_aware_public,
        profile,
        proof,
        base_claim,
        extension_claim,
        bridge_claim,
        validated_lease_inout,
        channel,
        capture_out,
    );
}

fn requireRecursiveEngine(comptime Engine: type) void {
    if (Engine.Hasher != frontend.recursion.engine.Hasher or
        Engine.MerkleChannel != frontend.recursion.engine.MerkleChannel or
        Engine.Channel != frontend.recursion.engine.Channel)
    {
        @compileError(
            "full Ethereum incremental V4 requires the q193 Poseidon2 engine",
        );
    }
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 4)
        @compileError("incremental Ethereum full-leaf V4 activated");
}
