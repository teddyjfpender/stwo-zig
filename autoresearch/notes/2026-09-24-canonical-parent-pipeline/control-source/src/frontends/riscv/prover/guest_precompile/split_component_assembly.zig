//! Role-separated component and relation-boundary substrate for R-008.
//!
//! This module deliberately stops short of an independently serialized leaf
//! proof. It provides the allocation-free component assemblies and the exact
//! post-verification algebra that such proofs need:
//!
//! - a core proof appends only the caller/request component;
//! - a provider proof contains only the Poseidon2 provider component;
//! - both components use the guest relation derived from one prepared R-007
//!   aggregation session; and
//! - each leaf closes all local terms after exporting exactly its terminal
//!   guest-relation sum. Only the ordered pair may cancel those exports.
//!
//! `candidate*AfterStarkVerification` is intentionally named as a sequencing
//! contract. It does not verify a STARK and its result is not proof-bound by
//! itself. A production leaf verifier must first authenticate the supplied
//! transcript identities and component claims, then call this allocation-free
//! finalizer. In particular, the current AIR does not yet prove the public
//! ordered call commitment, so these candidates must not cross a trust
//! boundary or be presented as recursive verification results.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const base_claims = @import("../../air/transcript/claims.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const base_statement = @import("../../air/statement.zig");
const proof_workspace = @import("../proof_workspace.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_summary = @import("../../aggregation/summary.zig");
const aggregation_types = @import("../../aggregation/types.zig");

pub const RESEARCH_ONLY = true;
pub const VERIFIES_STARK_PROOFS = false;
pub const PROVES_CALL_COMMITMENT = false;
pub const RECURSIVE_PAIR_VERIFICATION = false;

pub const caller_guest_batch: usize = caller_component.batch_count - 1;
pub const provider_guest_batch: usize = provider_component.batch_count - 1;
pub const max_caller_component_handles: usize =
    proof_workspace.MAX_COMPONENT_HANDLES + 1;

/// Verifier-replayed identities, never self-declared summary metadata.
///
/// The future leaf verifier obtains these from its accepted statement and
/// commitment transcript. Comparing them to the pre-challenge manifest here
/// makes the direction of authority explicit.
pub const VerifierReplayIdentity = struct {
    statement_digest: aggregation_hash.Digest,
    air_artifact_digest: aggregation_hash.Digest,
    preprocessed_root: aggregation_hash.Digest,
    main_root: aggregation_hash.Digest,
};

pub const CallerCandidate = struct {
    summary: aggregation_summary.LeafRelationSummaryV1,
};

pub const ProviderCandidate = struct {
    summary: aggregation_summary.LeafRelationSummaryV1,
};

pub const PairCandidates = struct {
    caller: ?CallerCandidate,
    provider: ?ProviderCandidate,
};

pub const CallerAuthority = struct {
    leaf: *const aggregation_manifest.PreparedLeafV1,
    construction: component_registry.CallerConstruction,
};

pub const ProviderAuthority = struct {
    leaf: *const aggregation_manifest.PreparedLeafV1,
    construction: component_registry.ProviderConstruction,
};

/// Resolve the caller construction from verifier-owned session membership.
pub fn resolveCallerAuthority(
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf_index: u32,
) !CallerAuthority {
    const leaf = try session.leaf(leaf_index);
    if (leaf.descriptor.role != .core_request) return error.LeafRoleMismatch;
    const n_rows = std.math.cast(u32, leaf.descriptor.guest_call_count) orelse
        return error.CallCountOutOfRange;
    const descriptor = try component_registry.Descriptor.canonical(
        .guest_poseidon2_call_v1,
        n_rows,
    );
    const construction = switch (try componentRegistry().verifierConstruction(descriptor)) {
        .caller => |value| value,
        .provider => return error.ConstructionAuthorityMismatch,
    };
    try construction.validate();
    return .{ .leaf = leaf, .construction = construction };
}

/// Resolve the provider construction from verifier-owned session membership.
pub fn resolveProviderAuthority(
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf_index: u32,
) !ProviderAuthority {
    const leaf = try session.leaf(leaf_index);
    if (leaf.descriptor.role != .poseidon2_provider)
        return error.LeafRoleMismatch;
    const n_rows = std.math.cast(u32, leaf.descriptor.guest_call_count) orelse
        return error.CallCountOutOfRange;
    const descriptor = try component_registry.Descriptor.canonical(
        .guest_poseidon2_provider_compat_v1,
        n_rows,
    );
    const construction = switch (try componentRegistry().verifierConstruction(descriptor)) {
        .provider => |value| value,
        .caller => return error.ConstructionAuthorityMismatch,
    };
    try construction.validate();
    return .{ .leaf = leaf, .construction = construction };
}

/// Caller columns follow the unchanged base proof columns directly.
pub fn callerPlacement(
    core: *const base_statement.RiscVStatement,
) error{ColumnOffsetOverflow}!caller_component.Placement {
    const first = @as(usize, core.nPreprocessedColumns());
    return .{
        .is_first_col_idx = first,
        .is_active_col_idx = try checkedAdd(first, 1),
        .main_col_offset = @as(usize, core.nMainColumns()),
        .interaction_col_offset = @as(usize, core.nInteractionColumns()),
    };
}

/// A standalone provider owns all three of its commitment-tree column runs.
pub const provider_placement = provider_component.Placement{
    .is_first_col_idx = 0,
    .is_active_col_idx = 1,
    .main_col_offset = 0,
    .interaction_col_offset = 0,
};

/// Stable caller-owned storage for one base-plus-caller prover component set.
/// Initialize this value at its final address and do not move it while handles
/// returned by `active` are live.
pub const CallerProverAssembly = struct {
    caller: caller_component.CallerComponent,
    handles: [max_caller_component_handles]prover_component.ComponentProver,
    len: usize,

    pub fn initInto(
        self: *@This(),
        core: *const base_statement.RiscVStatement,
        authority: component_registry.CallerConstruction,
        relations: *const guest_relations.Poseidon2V1Relations,
        base: []const prover_component.ComponentProver,
        claim: caller_component.Claim,
    ) !void {
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        self.caller = try caller_component.CallerComponent.initProver(
            authority,
            claim,
            try callerPlacement(core),
            relations,
        );
        @memcpy(self.handles[0..base.len], base);
        self.handles[base.len] = self.caller.asProverComponent();
        self.len = base.len + 1;
    }

    pub fn active(self: *const @This()) []const prover_component.ComponentProver {
        return self.handles[0..self.len];
    }
};

/// Stable caller-owned storage for one base-plus-caller verifier component set.
pub const CallerVerifierAssembly = struct {
    caller: caller_component.CallerComponent,
    handles: [max_caller_component_handles]core_air_components.Component,
    len: usize,

    pub fn initInto(
        self: *@This(),
        core: *const base_statement.RiscVStatement,
        authority: component_registry.CallerConstruction,
        relations: *const guest_relations.Poseidon2V1Relations,
        base: []const core_air_components.Component,
        claim: caller_component.Claim,
    ) !void {
        if (base.len > proof_workspace.MAX_COMPONENT_HANDLES)
            return error.TooManyComponentHandles;
        self.caller = try caller_component.CallerComponent.initVerifier(
            authority,
            claim,
            try callerPlacement(core),
            relations,
        );
        @memcpy(self.handles[0..base.len], base);
        self.handles[base.len] = self.caller.asVerifierComponent();
        self.len = base.len + 1;
    }

    pub fn active(self: *const @This()) []const core_air_components.Component {
        return self.handles[0..self.len];
    }
};

/// Provider-only prover component storage. No allocation or dynamic dispatch
/// occurs while placing the single handle.
pub const ProviderProverAssembly = struct {
    provider: provider_component.ProviderComponent,
    handles: [1]prover_component.ComponentProver,

    pub fn initInto(
        self: *@This(),
        authority: component_registry.ProviderConstruction,
        relations: *const guest_relations.Poseidon2V1Relations,
        claim: provider_component.Claim,
    ) !void {
        self.provider = try provider_component.ProviderComponent.initProver(
            authority,
            claim,
            provider_placement,
            relations,
        );
        self.handles[0] = self.provider.asProverComponent();
    }

    pub fn active(self: *const @This()) []const prover_component.ComponentProver {
        return &self.handles;
    }
};

/// Provider-only verifier component storage.
pub const ProviderVerifierAssembly = struct {
    provider: provider_component.ProviderComponent,
    handles: [1]core_air_components.Component,

    pub fn initInto(
        self: *@This(),
        authority: component_registry.ProviderConstruction,
        relations: *const guest_relations.Poseidon2V1Relations,
        claim: provider_component.Claim,
    ) !void {
        self.provider = try provider_component.ProviderComponent.initVerifier(
            authority,
            claim,
            provider_placement,
            relations,
        );
        self.handles[0] = self.provider.asVerifierComponent();
    }

    pub fn active(self: *const @This()) []const core_air_components.Component {
        return &self.handles;
    }
};

/// Replace only the guest relation in an otherwise leaf-local relation bundle.
/// This is the two-phase handshake seam: base relations remain local to the
/// core proof while the guest pair is a function of every session main root.
pub fn bindSessionGuestRelation(
    session: *const aggregation_manifest.PreparedSessionV1,
    local: guest_relations.Poseidon2V1Relations,
) !guest_relations.Poseidon2V1Relations {
    try session.challenge.validate();
    var result = local;
    result.guest_poseidon2_io = .init(
        secureFromWire(session.challenge.z),
        secureFromWire(session.challenge.alpha),
    );
    return result;
}

pub fn validateSessionGuestRelation(
    session: *const aggregation_manifest.PreparedSessionV1,
    relations: *const guest_relations.Poseidon2V1Relations,
) !void {
    try session.challenge.validate();
    const expected = @TypeOf(relations.guest_poseidon2_io).init(
        secureFromWire(session.challenge.z),
        secureFromWire(session.challenge.alpha),
    );
    if (!relations.guest_poseidon2_io.z.eql(expected.z) or
        !relations.guest_poseidon2_io.alpha.eql(expected.alpha))
    {
        return error.ChallengeContextMismatch;
    }
    for (relations.guest_poseidon2_io.alpha_powers, expected.alpha_powers) |actual, wanted| {
        if (!actual.eql(wanted)) return error.ChallengeContextMismatch;
    }
}

/// The caller's terminal physical batch contains only the negative guest
/// request event. Its other 76 batches remain ordinary core-local relations.
pub fn callerExportedGuestSum(claim: caller_component.Claim) QM31 {
    return claim.batch_sums[caller_guest_batch];
}

/// The provider's terminal batch has only one nonzero contribution: the
/// positive guest supply. Its paired legacy event has a fixed zero numerator.
pub fn providerExportedGuestSum(claim: provider_component.Claim) QM31 {
    return claim.batch_sums[provider_guest_batch];
}

/// Verify that a core/caller leaf closes after removing, not cancelling, its
/// exported guest request. `base_total` and `public_boundary` must come from
/// the successfully replayed core verifier.
pub fn verifyCallerLocalRemainder(
    authority: component_registry.CallerConstruction,
    base_total: QM31,
    public_boundary: QM31,
    claim: caller_component.Claim,
) !void {
    try claim.validate(authority);
    const exported = callerExportedGuestSum(claim);
    const remainder = public_boundary
        .add(base_total)
        .add(claim.total())
        .add(exported.neg());
    if (!remainder.isZero()) return error.UnclosedCallerLocalRelations;
}

/// Verify that a provider leaf closes after removing its exported supply.
/// Compatibility batch zero is independently required to be exactly zero by
/// `ProviderComponent.Claim.validate`.
pub fn verifyProviderLocalRemainder(
    authority: component_registry.ProviderConstruction,
    claim: provider_component.Claim,
) !void {
    try claim.validate(authority);
    const exported = providerExportedGuestSum(claim);
    if (!claim.total().add(exported.neg()).isZero())
        return error.UnclosedProviderLocalRelations;
}

/// Finalize the public candidate only after the caller STARK verifier succeeds.
/// This authenticates session membership, transcript identities, the shared
/// draw, role geometry, and local relation closure. It does not yet prove the
/// ordered call commitment against the trace.
pub fn candidateCallerAfterStarkVerification(
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf_index: u32,
    replay: VerifierReplayIdentity,
    relations: *const guest_relations.Poseidon2V1Relations,
    base_total: QM31,
    public_boundary: QM31,
    claim: caller_component.Claim,
) !CallerCandidate {
    const authority = try resolveCallerAuthority(session, leaf_index);
    try validateReplayIdentity(authority.leaf, replay);
    try validateSessionGuestRelation(session, relations);
    try verifyCallerLocalRemainder(
        authority.construction,
        base_total,
        public_boundary,
        claim,
    );
    const result = CallerCandidate{ .summary = summaryForLeaf(
        session,
        authority.leaf,
        secureToWire(callerExportedGuestSum(claim)),
    ) };
    try aggregation_summary.validateLeafStructure(session, result.summary);
    return result;
}

/// Finalize the provider public candidate only after its STARK verifier
/// succeeds. The same proof-binding limitation as the caller candidate applies.
pub fn candidateProviderAfterStarkVerification(
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf_index: u32,
    replay: VerifierReplayIdentity,
    relations: *const guest_relations.Poseidon2V1Relations,
    claim: provider_component.Claim,
) !ProviderCandidate {
    const authority = try resolveProviderAuthority(session, leaf_index);
    try validateReplayIdentity(authority.leaf, replay);
    try validateSessionGuestRelation(session, relations);
    try verifyProviderLocalRemainder(authority.construction, claim);
    const result = ProviderCandidate{ .summary = summaryForLeaf(
        session,
        authority.leaf,
        secureToWire(providerExportedGuestSum(claim)),
    ) };
    try aggregation_summary.validateLeafStructure(session, result.summary);
    return result;
}

/// Runtime ingress for a decoded pair artifact. Missing children reject before
/// entering the typed ordered-pair merger.
pub fn closeOptionalPair(
    session: *const aggregation_manifest.PreparedSessionV1,
    candidates: PairCandidates,
) !aggregation_summary.NodeSummaryV1 {
    const caller = candidates.caller orelse return error.MissingCallerProof;
    const provider = candidates.provider orelse return error.MissingProviderProof;
    return closePair(session, caller, provider);
}

/// Native reference closure. This is useful acceptance evidence but is not a
/// recursive proof; the constants above intentionally make that impossible to
/// confuse at call sites performing capability checks.
pub fn closePair(
    session: *const aggregation_manifest.PreparedSessionV1,
    caller: CallerCandidate,
    provider: ProviderCandidate,
) !aggregation_summary.NodeSummaryV1 {
    return aggregation_summary.mergePair(
        session,
        caller.summary,
        provider.summary,
    );
}

fn componentRegistry() component_registry.Registry {
    return component_registry.Registry.forProfile(
        execution_profile.ExecutionProfile.rv32im_zkvm_poseidon2_v1,
    );
}

fn validateReplayIdentity(
    leaf: *const aggregation_manifest.PreparedLeafV1,
    replay: VerifierReplayIdentity,
) !void {
    const descriptor = leaf.descriptor;
    if (!aggregation_hash.eql(replay.statement_digest, descriptor.leaf_statement_digest))
        return error.StatementIdentityMismatch;
    if (!aggregation_hash.eql(replay.air_artifact_digest, descriptor.leaf_air_artifact_digest))
        return error.AirArtifactIdentityMismatch;
    if (!aggregation_hash.eql(replay.preprocessed_root, descriptor.preprocessed_root))
        return error.PreprocessedRootMismatch;
    if (!aggregation_hash.eql(replay.main_root, descriptor.main_root))
        return error.MainRootMismatch;
}

fn summaryForLeaf(
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf: *const aggregation_manifest.PreparedLeafV1,
    signed_sum: aggregation_types.SecureFelt,
) aggregation_summary.LeafRelationSummaryV1 {
    const descriptor = leaf.descriptor;
    const request = descriptor.role == .core_request;
    return .{
        .session_digest = session.session_digest,
        .challenge_context_digest = session.challenge.challenge_context_digest,
        .leaf_index = descriptor.leaf_index,
        .leaf_role = descriptor.role,
        .leaf_statement_digest = descriptor.leaf_statement_digest,
        .guest_call_commitment = descriptor.guest_call_commitment,
        .guest_call_count = descriptor.guest_call_count,
        .request_count = if (request) descriptor.guest_call_count else 0,
        .supply_count = if (request) 0 else descriptor.guest_call_count,
        .signed_guest_sum = signed_sum,
    };
}

fn secureFromWire(value: aggregation_types.SecureFelt) QM31 {
    return QM31.fromM31Array(.{
        M31.fromCanonical(value.limbs[0]),
        M31.fromCanonical(value.limbs[1]),
        M31.fromCanonical(value.limbs[2]),
        M31.fromCanonical(value.limbs[3]),
    });
}

fn secureToWire(value: QM31) aggregation_types.SecureFelt {
    const limbs = value.toM31Array();
    return .{ .limbs = .{ limbs[0].v, limbs[1].v, limbs[2].v, limbs[3].v } };
}

fn checkedAdd(left: usize, right: usize) error{ColumnOffsetOverflow}!usize {
    return std.math.add(usize, left, right) catch error.ColumnOffsetOverflow;
}

comptime {
    if (base_claims.COMPONENT_COUNT != 28 or
        caller_component.batch_count != 77 or
        provider_component.batch_count != 2 or
        caller_guest_batch != 76 or provider_guest_batch != 1)
    {
        @compileError("split guest relation boundary geometry drifted");
    }
    if (component_registry.caller_batches[caller_guest_batch].second_event != null or
        component_registry.caller_batches[caller_guest_batch].first_event != 152 or
        component_registry.provider_batches[provider_guest_batch].second_event != 3)
    {
        @compileError("terminal guest batches are no longer isolated exports");
    }
}
