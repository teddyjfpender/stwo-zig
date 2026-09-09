//! Integration-owned binding for the incremental-memory native V3 proof.
//!
//! The frontend owns the generic proof/verification transaction. This module
//! binds it to the cold-derived, pointer-free Ethereum `AuthorityV3` and the
//! q193 protocol without adding a second profile or transcript authority.
//! Profile hooks are process-local; the retained fresh capture owns the exact
//! profile value and the verifier-expanded PCS/FRI capture.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_v3 = @import("ethereum_incremental_boundary_artifact_v3.zig");
const boundary_v3 = @import("ethereum_incremental_boundary_authority_v3.zig");
const profile_mod = @import("ethereum_incremental_native_leaf_profile_v3.zig");

const pcs_core = stwo_core.pcs;
const lookup_physical = frontend.air.lookup_physical_manifest_v2;
const public_data_v2 = frontend.air.public_data_v2;
const statement_v2 = frontend.air.statement_v2;
const public_data = frontend.air.public_data;
const transition_v1 = frontend.air.memory_commitment.incremental_transition_v1;
const runner = frontend.runner;
const prover = frontend.prover_mod;
const witness_v3 = prover.incremental_commitment_witness_v3;
const orchestration_v3 = prover.incremental_native_orchestration_v3;
const verifier_v3 = prover.incremental_native_verifier_v3;

pub const FORMAT_VERSION: u16 = 3;
pub const PRODUCTION_ACTIVE = false;
pub const Profile = profile_mod.AuthorityV3;

pub fn FreshVerifiedCaptureV3(comptime Engine: type) type {
    return verifier_v3.FreshVerifiedCaptureV3(Engine, Profile);
}

/// Reconstructs the full base+bridge witness exactly once from STWIMT03.
/// The returned owner remains borrowed by statement preparation and proving.
pub fn buildFullWitnessFromColdArtifact(
    allocator: std.mem.Allocator,
    exec_trace: *const runner.trace.Trace,
    opt_memory: ?*const runner.memory_state.Snapshot,
    completion: public_data.Completion,
    artifact: *const artifact_v3.OwnedArtifactV3,
    segment_public_wire: *const public_data_v2.PublicDataV2,
    public_authority: boundary_v3.SegmentPublicAuthorityV3,
    limits: artifact_v3.Limits,
) !witness_v3.FullWitnessV3 {
    var cold = try artifact_v3.coldReconstruct(
        allocator,
        artifact,
        segment_public_wire,
        public_authority,
        limits,
    );
    defer cold.deinit();

    const touched_source = artifact.transition_v2.authority.touched_words;
    const frontier_source = artifact.transition_v2.authority.frontier_nodes;
    if (cold.transitions.len != touched_source.len or touched_source.len == 0)
        return error.IncrementalNativeLeafInventoryMismatch;
    const touched = try allocator.alloc(
        transition_v1.TouchedWord,
        touched_source.len,
    );
    defer allocator.free(touched);
    for (touched, touched_source) |*destination, source| destination.* = .{
        .address = source.address,
        .old_word = source.old_word,
        .new_word = source.new_word,
        .final_clock = source.final_clock,
    };
    const frontier = try allocator.alloc(
        transition_v1.FrontierNode,
        frontier_source.len,
    );
    defer allocator.free(frontier);
    for (frontier, frontier_source) |*destination, source| destination.* = .{
        .depth = source.depth,
        .index = source.index,
        .value = source.value,
    };

    const row_count = std.math.mul(usize, cold.transitions.len, 2) catch
        return error.IncrementalNativeLeafGeometryOverflow;
    const rows = try allocator.alloc(boundary_v3.BoundaryRowContractV3, row_count);
    defer allocator.free(rows);
    try boundary_v3.writeBoundaryRows(
        public_authority,
        cold.transitions,
        rows,
    );
    const policy = try allocator.alloc(
        witness_v3.RowPolicyV3,
        cold.transitions.len,
    );
    defer allocator.free(policy);
    for (policy, 0..) |*destination, index| destination.* = .{
        .entry_clock = rows[index * 2].clock,
        .entry_memory = mapMultiplicity(
            rows[index * 2].memory_multiplicity,
        ),
        .exit_memory = mapMultiplicity(
            rows[index * 2 + 1].memory_multiplicity,
        ),
    };
    return witness_v3.buildFull(
        allocator,
        exec_trace,
        opt_memory,
        completion,
        touched,
        frontier,
        policy,
        .{
            .entry = artifact.continuation_roots.entry,
            .exit = artifact.continuation_roots.exit,
        },
    );
}

pub fn prepareStatement(
    allocator: std.mem.Allocator,
    exec_trace: *const runner.trace.Trace,
    opt_chain: ?*const runner.state_chain.StateChainTracker,
    full_witness: *const witness_v3.FullWitnessV3,
    segment_public_wire: public_data_v2.PublicDataV2,
) !statement_v2.RiscVStatementV2 {
    return orchestration_v3.prepareStatement(
        allocator,
        exec_trace,
        opt_chain,
        full_witness,
        segment_public_wire,
    );
}

pub fn proveWithEngineUsingChannel(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    exec_trace: *const runner.trace.Trace,
    opt_chain: ?*const runner.state_chain.StateChainTracker,
    full_witness: *const witness_v3.FullWitnessV3,
    expected_statement: *const statement_v2.RiscVStatementV2,
    profile: *const Profile,
    recorder: ?*@import("stwo_prover_api").stage_profile.Recorder,
    channel: *Engine.Channel,
    execution: orchestration_v3.ExecutionOptions,
) !orchestration_v3.ProveOutputV3(Engine) {
    const pcs_config = try validateProfile(profile, expected_statement);
    return orchestration_v3.proveWithEngineUsingChannel(
        Engine,
        allocator,
        pcs_config,
        exec_trace,
        opt_chain,
        full_witness,
        expected_statement,
        @ptrCast(profile),
        profileHook(Engine, profile),
        recorder,
        channel,
        execution,
    );
}

/// Consumes `proof` on all paths and publishes `capture_out` only after the
/// complete q193 AIR/PCS/FRI verifier succeeds.
pub fn verifyWithEngineUsingChannelAndCapture(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const statement_v2.RiscVStatementV2,
    profile: *const Profile,
    proof: prover.ProofForEngine(Engine),
    base_claim: *const frontend.air.statement.RiscVInteractionClaim,
    bridge_claim: stwo_core.fields.qm31.QM31,
    channel: *Engine.Channel,
    capture_out: *FreshVerifiedCaptureV3(Engine),
) !void {
    const pcs_config = try validateProfile(profile, statement);
    try verifier_v3.verifyWithEngineUsingChannelAndCapture(
        Engine,
        Profile,
        allocator,
        pcs_config,
        statement,
        &profile.bridge_geometry,
        profile,
        profileHook(Engine, profile),
        proof,
        base_claim,
        bridge_claim,
        channel,
        capture_out,
    );
}

pub fn profileHook(
    comptime Engine: type,
    profile: *const Profile,
) orchestration_v3.ProfileHookV3(Engine) {
    return .{
        .context = @ptrCast(profile),
        .profile_address = @ptrCast(profile),
        .profile_identity_sha256 = profile.identity_sha256,
        .validate_fn = HookAdapter(Engine).validate,
        .mix_pre_tree0_fn = HookAdapter(Engine).mixPreTree0,
        .mix_post_tree1_fn = HookAdapter(Engine).mixPostTree1,
    };
}

fn HookAdapter(comptime Engine: type) type {
    return struct {
        fn profile(context: *const anyopaque) *const Profile {
            return @ptrCast(@alignCast(context));
        }

        fn validate(
            context: *const anyopaque,
            pcs_config: pcs_core.PcsConfig,
            statement: *const statement_v2.RiscVStatementV2,
            bridge_geometry: *const prover.incremental_bridge_external_v3.GeometryV3,
            manifest: *const lookup_physical.Manifest,
            authenticated: *const lookup_physical.AuthenticatedStatement,
        ) !void {
            const authority = profile(context);
            const expected_config = try validateProfile(authority, statement);
            try manifest.validate();
            try authenticated.validateAgainst(&statement.core, manifest);
            if (!std.meta.eql(pcs_config, expected_config) or
                !std.meta.eql(bridge_geometry.*, authority.bridge_geometry) or
                !std.meta.eql(
                    authenticated.*,
                    authority.base_geometry.lookup_activation,
                ))
            {
                return error.IncrementalNativeLeafProfileMismatch;
            }
        }

        fn mixPreTree0(
            context: *const anyopaque,
            statement: *const statement_v2.RiscVStatementV2,
            channel: *Engine.Channel,
        ) !void {
            try profile(context).mixPreTree0(statement, channel);
        }

        fn mixPostTree1(
            context: *const anyopaque,
            statement: *const statement_v2.RiscVStatementV2,
            channel: *Engine.Channel,
        ) !void {
            try profile(context).mixPostTree1(statement, channel);
        }
    };
}

fn validateProfile(
    profile: *const Profile,
    statement: *const statement_v2.RiscVStatementV2,
) !pcs_core.PcsConfig {
    try profile.validateAgainstStatement(statement);
    return profile.protocol.pcs.config();
}

fn mapMultiplicity(
    value: boundary_v3.MemoryMultiplicityV3,
) witness_v3.MemoryMultiplicityV3 {
    return switch (value) {
        .entry => .entry,
        .none => .none,
        .exit => .exit,
    };
}

comptime {
    if (PRODUCTION_ACTIVE or FORMAT_VERSION != 3)
        @compileError("incremental native leaf proof V3 activation drifted");
}
