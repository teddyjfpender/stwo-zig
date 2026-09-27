//! Opt-in joined Ethereum SegmentV2 Stage-A transcript extension.
//!
//! The caller-owned extension may carry a projected-native V2 omission
//! authority, provider plan, and ordered-call commitment. The orchestration
//! layer treats it opaquely. It first receives the fully admitted native
//! geometry before Tree1 sizing so it can install a projected core, then
//! receives the complete joined Tree0/Tree1 commitments before the single
//! Ethereum interaction PoW.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const public_data_v2 = @import("../../air/public_data_v2.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const global_v3 = @import("../../recursion/segment_leaf_local_authority_v3.zig");
const ethereum_context = @import("../../recursion/ethereum_leaf_context_v1.zig");
const keccak_calls_mod = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const keccak_rows_mod = @import("../../runner/guest_precompile/keccakf_v1.zig");
const recovery_calls_mod = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const recovery_rows_mod = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const runner_result = @import("../../runner/result.zig");
const orchestration = @import("ethereum_segment_orchestration.zig");
const verifier = @import("ethereum_segment_verifier.zig");
const omitted_capture =
    @import("ethereum_omitted_provider_fresh_capture_v1.zig");
const ethereum_types = @import("ethereum_types.zig");
const base_types = @import("../types.zig");

/// Additive engine-generic entrypoint. `prepareProjectedCore` receives the
/// fully admitted native authority and exact full geometry before Tree1 sizing
/// or `Engine.init`; `drawChallenges` later revalidates the retained projection
/// against the exact committed roots. This layer predicts neither the
/// projected authority type nor its physical Tree1 layout.
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
    execution: orchestration.ExecutionOptions,
    transcript_extension: anytype,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    var ignored_phase: orchestration.ProvePhase = .execution_authority;
    var ignored_subphase: ?orchestration.CompositionSubphase = null;
    return orchestration.proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        true,
        false,
        transcript_extension,
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

/// Non-default physical native-provider omission entrypoint. The caller-owned
/// extension must mint `ProjectionV1` during `prepareProjectedCore`, expose its
/// exact plan/calls, and bind provider Stage-A custody in `drawChallenges`.
/// This API does not by itself activate production admission.
pub fn proveWithEngineUsingChannelAndExecutionAndNativeProviderOmission(
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
    execution: orchestration.ExecutionOptions,
    transcript_extension: anytype,
) !ethereum_types.SegmentProveOutputForEngine(Engine) {
    var ignored_phase: orchestration.ProvePhase = .execution_authority;
    var ignored_subphase: ?orchestration.CompositionSubphase = null;
    return orchestration.proveWithEngineUsingChannelAndExecutionInternal(
        Engine,
        true,
        true,
        transcript_extension,
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

/// Fresh verification under the same caller-owned joined Stage-A authority.
/// Exact Tree0/Tree1 roots are passed to `transcript_extension.verifyRelations`
/// before any shared relation challenge is returned.
pub fn verifyWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
    transcript_extension: anytype,
) !void {
    return verifier.verifyInternal(
        Engine,
        true,
        false,
        transcript_extension,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        null,
        null,
    );
}

/// Freshly verifies the physical provider-omitted core. The callback rebuilds
/// the same projection before root/log-size admission and receives the
/// verifier-derived residual only after the full STARK/PCS/FRI check succeeds.
pub fn verifyWithEngineUsingChannelAndNativeProviderOmission(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
    transcript_extension: anytype,
) !void {
    return verifier.verifyInternal(
        Engine,
        true,
        true,
        transcript_extension,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        null,
        null,
    );
}

/// Transactionally publishes the projected proof capture only after the core
/// STARK, omission authority, Ethereum context, and fresh residual all verify.
pub fn verifyWithEngineUsingChannelAndNativeProviderOmissionCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    channel: *Engine.Channel,
    transcript_extension: anytype,
    capture_out: *omitted_capture.CaptureV1(Engine),
) !void {
    if (proof_in.commitment_scheme_proof.commitments.items.len != 4)
        return error.InvalidOmittedProviderCommitmentCount;
    var commitments: [4]Engine.Hasher.Hash = undefined;
    @memcpy(
        &commitments,
        proof_in.commitment_scheme_proof.commitments.items[0..4],
    );
    var base_capture: verifier.CaptureForEngine(Engine) = undefined;
    var base_owned = false;
    defer if (base_owned) base_capture.deinit(allocator);
    var extension_context: ethereum_context.ContextV1 = undefined;
    try verifier.verifyInternal(
        Engine,
        true,
        true,
        transcript_extension,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        &base_capture,
        &extension_context,
    );
    base_owned = true;
    const projection = try transcript_extension.providerProjection();
    const shared = transcript_extension.shared_relation orelse
        return error.MissingEthereumProviderSharedAuthority;
    const fresh_core = transcript_extension.fresh_core orelse
        return error.MissingEthereumProviderFreshCore;
    const owned_full = try statement_v2.RiscVStatementV2.init(
        statement.core,
        base_capture.public_data.data,
    );
    var owned_projection = projection.*;
    owned_projection.projected_native = try statement_v2.RiscVStatementV2.init(
        projection.projected_native.core,
        base_capture.public_data.data,
    );
    var capture = omitted_capture.CaptureV1(Engine){
        .projected_base = base_capture,
        .full_statement = owned_full,
        .projection = owned_projection,
        .extension_statement = extension,
        .extension_claim = extension_claim.*,
        .ethereum_context = extension_context,
        .shared = shared,
        .fresh_core = fresh_core,
        .proof_commitments = commitments,
        .identity = undefined,
    };
    capture.identity = omitted_capture.seal(Engine, &capture);
    try capture.validate(
        transcript_extension.providerPlan(),
        transcript_extension.providerCalls(),
        transcript_extension.provider_stage_a,
    );
    capture_out.* = capture;
    base_owned = false;
}

/// Transactional V3 recursive-ingress capture under the extended transcript.
/// A failed projected-authority/root/nonce check publishes neither the base
/// proof capture nor the joined Ethereum context.
pub fn verifyWithEngineAndEthereumV3CaptureUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    statement: statement_v2.RiscVStatementV2,
    extension: ethereum_statement.Statement,
    proof_in: base_types.ProofForEngine(Engine),
    base_claim: *const base_types.RiscVInteractionClaim,
    extension_claim: *const ethereum_types.ExtensionClaim,
    global: *const global_v3.MetadataV3,
    channel: *Engine.Channel,
    transcript_extension: anytype,
    capture_out: *verifier.VerifiedEthereumSegmentV3CaptureForEngine(Engine),
) !void {
    try global.validate();
    var base_capture: verifier.CaptureForEngine(Engine) = undefined;
    var base_owned = false;
    defer if (base_owned) base_capture.deinit(allocator);
    var extension_context: ethereum_context.ContextV1 = undefined;
    try verifier.verifyInternal(
        Engine,
        true,
        false,
        transcript_extension,
        allocator,
        pcs_config,
        statement,
        extension,
        proof_in,
        base_claim,
        extension_claim,
        channel,
        &base_capture,
        &extension_context,
    );
    base_owned = true;
    const capture = try verifier.VerifiedEthereumSegmentV3CaptureForEngine(Engine)
        .initVerified(
        base_capture,
        statement.core,
        extension,
        extension_claim.*,
        extension_context,
        global.*,
    );
    capture_out.* = capture;
    base_owned = false;
}
