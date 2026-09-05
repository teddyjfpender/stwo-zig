//! Shared-transcript source and adapter that bind D5 provider shard proofs to
//! one V4 incremental leaf whose native Poseidon2 provider was omitted.
//!
//! The ordinary omit route (`ethereum_omit_provider_proof_v1.Source` +
//! `OrdinaryTranscriptAdapter`) replays a SegmentV2-shaped pre-Tree0 prefix:
//! PCS config, native public transcript, authenticated lookup, Ethereum
//! statement. The V4 leaf's pre-Tree0 prefix is the profile's
//! `AuthorityV4.mixPreTree0` plus the route's `IncrementalOmissionFrameV4`,
//! and it mixes `AuthorityV4.mixPostTree1` between the Tree 1 root and the
//! relation draw. A shard proved under either prefix therefore cannot be
//! replayed under the other, which is the point: the shards and the core must
//! share exactly one Fiat-Shamir order, and nothing else may be relabelled
//! into it.
//!
//! Three seams live here:
//!
//!   * `SourceV1(Engine)` is the ordinary source plus the four route
//!     authorities (profile, projected bridge geometry, pre-Tree0 frame, leaf
//!     omission digest). `validate()` re-derives all four and refuses any
//!     value it did not recompute itself; `ordinary()` projects back down to
//!     the plain source that `closeFreshClaimsV2` consumes.
//!   * `Stage101TranscriptAdapterV1` is the `TranscriptAdapter` the D5 shard
//!     prover and fresh verifier take. Its `replayShared` calls the very
//!     `mixRoutePreTree0` the producer core and the cold core verifier call,
//!     so transcript steps [1] and [2] cannot drift between the three sides.
//!   * The engine retype helpers move Stage-A roots, the shared relation
//!     authority and the Stage-A manifest from the producer engine (Metal) to
//!     the cold CPU verifier engine. They are field copies guarded at comptime
//!     on `Hasher`/`Channel`/`MerkleChannel` identity, so no transcript type
//!     can silently change across the hand-off.
//!
//! Nothing here proves, verifies or activates: `ACTIVATES_PRODUCTION_PROOF`
//! stays false and every authority this module mints is diagnostic until the
//! fresh joint closure closes.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_pcs = stwo_core.pcs;
const frontend = @import("stwo_riscv_frontend");

const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");

const prover = frontend.prover_mod;
const public_data = frontend.air.public_data;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const lookup_physical_v2 = frontend.air.lookup_physical_manifest_v2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const ethereum_transcript = prover.guest_precompile.ethereum_transcript;
const incremental_bridge = prover.incremental_bridge_external_v3;
const omission = prover.guest_precompile.native_provider_omit_v1;
const protocol = prover.ethereum_native_provider_omit_protocol_v1;
const route = prover.guest_precompile.incremental_ethereum_omit_protocol_v4;
const ordinary_source =
    frontend.testing.narrow_memory_provider_ethereum_omit_proof_v1;
const degree5 =
    frontend.testing.narrow_memory_provider_degree5_ethereum_omit_proof_v1;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const provider_order = frontend.testing.narrow_memory_provider_order_component;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const orchestration =
    frontend.testing.incremental_ethereum_omit_orchestration_v4_internal;

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const FORMAT_VERSION: u32 = 1;

pub const Digest = provider_authority.Digest;
pub const AuthorityId = route.AuthorityId;
pub const AuthorityV4 = profile_mod.AuthorityV4;
pub const IncrementalOmissionFrameV4 = route.IncrementalOmissionFrameV4;
pub const LeafOmissionAuthorityV4 = route.LeafOmissionAuthorityV4;
pub const ProviderOmissionPinsV1 = route.ProviderOmissionPinsV1;
pub const ProjectedRouteGeometryV4 = orchestration.ProjectedRouteGeometryV4;
pub const ProviderStatementV1 = degree5.ProviderStatementV1;

/// Every refusal this module owns. Errors raised by the ordinary omit route,
/// by the profile, or by the route protocol module keep their own names.
pub const Error = error{
    MissingValidatedProviderPlanCallAuthorityV1,
    IncrementalOmittedProviderSourcePcsMismatchV1,
    IncrementalOmittedProviderSourceBridgeMismatchV1,
    IncrementalOmittedProviderSourceFrameMismatchV1,
    IncrementalOmittedProviderSourceLeafOmissionMismatchV1,
    IncrementalOmittedProviderFrameProjectionMismatchV1,
    IncrementalOmittedProviderStageARootCountMismatchV1,
    IncrementalOmittedProviderManifestIdentityMismatchV1,
    InvalidLeafProviderStatementV4,
};

// ---------------------------------------------------------------------------
// The four route bindings, at digest level
// ---------------------------------------------------------------------------

/// Everything `validateRouteAuthorityBindings` needs to re-derive the three
/// route authorities, with no statement, projection or engine in sight.
///
/// `SourceV1.validate` fills it from the live objects; the unit gate fills it
/// from synthetic values, which is what makes the whole rejection matrix
/// reachable without a proved leaf.
pub const RouteBindingsV1 = struct {
    profile_identity_sha256: [32]u8,
    projection_identity: Digest,
    shared_identity: Digest,
    full_statement_authority_id: AuthorityId,
    full_bridge_geometry: incremental_bridge.GeometryV3,
    projected_prefix: incremental_bridge.PrefixColumnsV3,
};

/// Fail-closed re-derivation of the projected bridge geometry, the pre-Tree0
/// frame and the leaf omission digest. Every one of the three is rebuilt from
/// `bindings` and compared whole-value: a mutation of any bound field, or of
/// any recomputed authority, names its own error.
pub fn validateRouteAuthorityBindings(
    bindings: RouteBindingsV1,
    projected_bridge: *const incremental_bridge.GeometryV3,
    frame: *const IncrementalOmissionFrameV4,
    leaf_omission: *const LeafOmissionAuthorityV4,
) !void {
    const geometry = try orchestration.projectedRouteGeometryFromPrefix(
        &bindings.full_bridge_geometry,
        bindings.projected_prefix,
    );
    if (!std.meta.eql(geometry.bridge, projected_bridge.*))
        return error.IncrementalOmittedProviderSourceBridgeMismatchV1;
    const expected_frame = try IncrementalOmissionFrameV4.canonicalFromGeometry(
        bindings.projection_identity,
        geometry.bridge,
    );
    if (!std.meta.eql(expected_frame, frame.*))
        return error.IncrementalOmittedProviderSourceFrameMismatchV1;
    const expected_leaf = try LeafOmissionAuthorityV4.canonical(
        bindings.profile_identity_sha256,
        expected_frame.identity,
        bindings.shared_identity,
        bindings.full_statement_authority_id,
    );
    if (!std.meta.eql(expected_leaf, leaf_omission.*))
        return error.IncrementalOmittedProviderSourceLeafOmissionMismatchV1;
}

// ---------------------------------------------------------------------------
// SourceV1
// ---------------------------------------------------------------------------

/// The ordinary omit-route source widened by the V4 leaf's route authorities.
///
/// The `native` statement is always the FULL one: ordinary admission requires
/// the omitted 445-column descriptor and can never accept a projected core, so
/// the projected core only ever appears as `projection.projected_native.core`.
pub fn SourceV1(comptime Engine: type) type {
    return struct {
        native: *const statement_v2.RiscVStatementV2,
        extension: *const ethereum_statement.Statement,
        lookup_manifest: *const lookup_physical_v2.Manifest,
        /// Authenticated lookup statement of the FULL core.
        authenticated_lookup: *const lookup_physical_v2.AuthenticatedStatement,
        projection: *const omission.ProjectionV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        calls: []const poseidon2_air.Call,
        /// G1: the route refuses to run without the O(1) corpus authority, so
        /// no shard proof is ever preceded by a 6.67M-call rehash.
        validated_calls: ?*const provider_authority
            .OwnedValidatedPlanCallAuthorityV1 = null,
        provider_stage_a: *const protocol.ProviderStageAManifestV1(Engine),
        shared: protocol.SharedRelationAuthorityV1(Engine),

        profile: *const AuthorityV4,
        role_aware_public: *const public_data.PublicData,
        projected_bridge: incremental_bridge.GeometryV3,
        frame_v4: IncrementalOmissionFrameV4,
        leaf_omission: LeafOmissionAuthorityV4,
        pcs_config: core_pcs.PcsConfig,

        const Self = @This();

        /// The plain source `closeFreshClaimsV2` and every ordinary omit-route
        /// authority consume. The V4 profile authenticates its own retirements
        /// through `base_geometry.validateAgainstWithRetirementSupplementV2`,
        /// so no supplement is threaded here.
        pub fn ordinary(self: Self) ordinary_source.Source(Engine) {
            return .{
                .native = self.native,
                .extension = self.extension,
                .lookup_manifest = self.lookup_manifest,
                .authenticated_lookup = self.authenticated_lookup,
                .projection = self.projection,
                .plan = self.plan,
                .calls = self.calls,
                .provider_stage_a = self.provider_stage_a,
                .shared = self.shared,
                .retirement_supplement = null,
                .validated_calls = self.validated_calls,
            };
        }

        /// Ordinary corpus/projection/manifest/shared readmission first, then
        /// the route half. Both must pass before a single shard byte exists.
        pub fn validate(self: Self) !void {
            if (self.validated_calls == null)
                return error.MissingValidatedProviderPlanCallAuthorityV1;
            try self.ordinary().validate();
            try self.validateRouteAuthorities();
        }

        /// Route half of `validate`: the profile must admit the FULL statement
        /// and the role-aware public data, and the three route authorities must
        /// be exactly the ones this source can rebuild for itself.
        pub fn validateRouteAuthorities(self: Self) !void {
            try self.profile.validateAgainstStatement(
                self.native,
                self.extension,
                self.role_aware_public,
            );
            const expected_pcs = try self.profile.pcsConfig();
            if (!std.meta.eql(expected_pcs, self.pcs_config))
                return error.IncrementalOmittedProviderSourcePcsMismatchV1;
            const geometry = try self.projectedRouteGeometry();
            try validateRouteAuthorityBindings(
                .{
                    .profile_identity_sha256 = self.profile.identity_sha256,
                    .projection_identity = self.projection.identity,
                    .shared_identity = self.shared.identity,
                    .full_statement_authority_id = self.native.authority_id,
                    .full_bridge_geometry = self.profile.bridge_geometry,
                    .projected_prefix = geometry.prefix,
                },
                &self.projected_bridge,
                &self.frame_v4,
                &self.leaf_omission,
            );
        }

        /// Projected committed prefix and bridge placement implied by this
        /// source's projection. Fails closed unless exactly the omitted
        /// component's (2, 445, 8) columns left.
        pub fn projectedRouteGeometry(
            self: Self,
        ) !ProjectedRouteGeometryV4 {
            return orchestration.projectedRouteGeometry(
                &self.profile.bridge_geometry,
                &self.projection.projected_native.core,
                self.extension,
                self.authenticated_lookup,
                self.lookup_manifest,
            );
        }

        /// The projected core every shard replays `mixMainClaim` against.
        pub fn projectedCore(self: Self) *const statement_mod.RiscVStatement {
            return &self.projection.projected_native.core;
        }
    };
}

// ---------------------------------------------------------------------------
// The shared transcript
// ---------------------------------------------------------------------------

/// Transcript steps [1], [2], Tree 0/1 roots, [5] and the shared draw [6],
/// with no source object.
///
/// The profile is `anytype` for exactly one reason: it lets a unit gate drive
/// this order against a hand-built channel without minting a real
/// `AuthorityV4`. Production callers reach it through
/// `Stage101TranscriptAdapterV1.replayShared`, which validates the source
/// first.
pub fn replaySharedTranscriptV4(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    profile: anytype,
    native: *const statement_v2.RiscVStatementV2,
    role_aware_public: *const public_data.PublicData,
    frame: *const IncrementalOmissionFrameV4,
    projected_core: *const statement_mod.RiscVStatement,
    plan: *const provider_authority.ProviderShardPlanV1,
    provider_stage_a: *const protocol.ProviderStageAManifestV1(Engine),
    shared: protocol.SharedRelationAuthorityV1(Engine),
) !protocol.Replay(Engine) {
    if (!std.mem.eql(
        u8,
        &frame.projection_identity,
        &shared.projection_identity,
    )) return error.IncrementalOmittedProviderFrameProjectionMismatchV1;
    var channel = Engine.Channel{};
    // [1] full-statement profile prefix and [2] the pre-Tree0 omission frame,
    // through the one helper the producer and the cold verifier also call.
    try orchestration.mixRoutePreTree0(
        profile,
        native,
        role_aware_public,
        frame,
        &channel,
    );
    // [3] and [4]: the joined Tree 0 and Tree 1 roots.
    Engine.MerkleChannel.mixRoot(&channel, shared.tree0_root);
    Engine.MerkleChannel.mixRoot(&channel, shared.tree1_root);
    // [5] the full-core post-Tree1 frame.
    try profile.mixPostTree1(native, role_aware_public, &channel);
    // [6] the single shared draw: projected-core main claim, provider Stage-A
    // frame, 16-bit interaction PoW, then every relation.
    const relations = try ethereum_transcript.verifyToRelationsWithExtension(
        allocator,
        &channel,
        projected_core,
        shared.interaction_pow,
        protocol.ProviderFrameV1(Engine){
            .projection_identity = frame.projection_identity,
            .provider_stage_a = provider_stage_a,
            .tree0_root = shared.tree0_root,
            .tree1_root = shared.tree1_root,
        },
    );
    const relation_context = try provider_authority.PoseidonRelationContextV1
        .canonical(
        plan.session,
        relations.base.poseidon2.z,
        relations.base.poseidon2.alpha,
    );
    if (!std.meta.eql(relation_context, shared.relation_context))
        return error.EthereumProviderRelationContextMismatch;
    return .{
        .channel = channel,
        .relations = relations,
        .authority_value = shared,
    };
}

/// Shard-local prefix appended to a replayed channel: the ordinary provider
/// V2 statement frame, then this leaf's non-portability frame.
///
/// Splitting it out is what makes the byte order testable: the route prefix is
/// the ordinary prefix followed by exactly `mixIntoLocalPrefix`, and nothing
/// else.
pub fn appendLeafProviderLocalFrame(
    channel: anytype,
    plan: *const provider_authority.ProviderShardPlanV1,
    provider_stage_a: anytype,
    shared_relation_context_identity: Digest,
    leaf_omission: *const LeafOmissionAuthorityV4,
    claim: provider_authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
) !void {
    try protocol.appendProviderLocalFrameV2(
        channel,
        plan,
        provider_stage_a,
        shared_relation_context_identity,
        claim,
        ordered_call_claim,
    );
    try leaf_omission.validate();
    leaf_omission.mixIntoLocalPrefix(channel);
}

/// The `TranscriptAdapter` of `proveProviderPreparedValidatedWithTranscriptV2`
/// and `verifyProviderFreshValidatedWithTranscriptV2` for this route.
pub const Stage101TranscriptAdapterV1 = struct {
    pub fn replayShared(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: SourceV1(Engine),
    ) !protocol.Replay(Engine) {
        try source.validate();
        if (!std.meta.eql(pcs_config, source.pcs_config))
            return error.IncrementalOmittedProviderSourcePcsMismatchV1;
        return replaySharedTranscriptV4(
            Engine,
            allocator,
            source.profile,
            source.native,
            source.role_aware_public,
            &source.frame_v4,
            source.projectedCore(),
            source.plan,
            source.provider_stage_a,
            source.shared,
        );
    }

    pub fn providerLocalPrefix(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        pcs_config: core_pcs.PcsConfig,
        source: SourceV1(Engine),
        claim: provider_authority.ProviderShardClaimV1,
        ordered: provider_order.ClaimV1,
    ) !Engine.Channel {
        var replay = try replayShared(Engine, allocator, pcs_config, source);
        try appendLeafProviderLocalFrame(
            &replay.channel,
            source.plan,
            source.provider_stage_a,
            source.shared.relation_context.identity,
            &source.leaf_omission,
            claim,
            ordered,
        );
        return replay.channel;
    }
};

// ---------------------------------------------------------------------------
// Statement wrapper
// ---------------------------------------------------------------------------

/// The D5 provider statement wrapped in this leaf's omission digest.
///
/// The shard proof already mixes `leaf_omission.identity` into its local
/// prefix, so a shard proved for another leaf cannot verify here. This wrapper
/// makes the same binding visible to the artifact codec and the batch
/// authority, which compare statements before they ever open a proof.
pub const LeafProviderStatementV4 = struct {
    format: u32 = FORMAT_VERSION,
    leaf_omission_identity: Digest,
    provider: ProviderStatementV1,
    identity: Digest,

    pub fn canonical(
        leaf_omission_identity: Digest,
        provider: ProviderStatementV1,
    ) !LeafProviderStatementV4 {
        var result = LeafProviderStatementV4{
            .format = FORMAT_VERSION,
            .leaf_omission_identity = leaf_omission_identity,
            .provider = provider,
            .identity = undefined,
        };
        result.identity = leafProviderStatementIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const LeafProviderStatementV4) !void {
        if (self.format != FORMAT_VERSION or
            isZeroDigest(self.leaf_omission_identity) or
            isZeroDigest(self.provider.identity) or
            !std.mem.eql(
                u8,
                &self.identity,
                &leafProviderStatementIdentity(self),
            ))
        {
            return error.InvalidLeafProviderStatementV4;
        }
    }

    /// Fail-closed readmission against the live leaf omission authority and
    /// the provider statement the shard prover actually produced.
    pub fn validateAgainst(
        self: *const LeafProviderStatementV4,
        leaf_omission: *const LeafOmissionAuthorityV4,
        provider: ProviderStatementV1,
    ) !void {
        try self.validate();
        try leaf_omission.validate();
        if (!std.mem.eql(
            u8,
            &self.leaf_omission_identity,
            &leaf_omission.identity,
        ) or !std.meta.eql(self.provider, provider))
            return error.InvalidLeafProviderStatementV4;
    }
};

/// Wrapper constructor for a shard prover holding a route source, mirroring
/// `makeCandidateStatement` on the candidate route.
pub fn makeLeafProviderStatement(
    source: anytype,
    provider: ProviderStatementV1,
) !LeafProviderStatementV4 {
    return LeafProviderStatementV4.canonical(
        source.leaf_omission.identity,
        provider,
    );
}

// ---------------------------------------------------------------------------
// Engine retype helpers
// ---------------------------------------------------------------------------

/// Whether two engines share the exact transcript types this route hands
/// across the producer/cold-verifier boundary.
///
/// It exists as a value-level predicate so a unit gate can assert the guard
/// rejects a mismatched pair without the assertion itself being a compile
/// error.
pub fn transcriptTypesCompatible(
    comptime From: type,
    comptime To: type,
) bool {
    return From.Hasher == To.Hasher and From.Channel == To.Channel and
        From.MerkleChannel == To.MerkleChannel;
}

fn requireTranscriptTypes(comptime From: type, comptime To: type) void {
    comptime {
        if (!transcriptTypesCompatible(From, To)) {
            @compileError(
                "omitted-provider route producer and cold verifier " ++
                    "transcript types differ",
            );
        }
    }
}

/// Retypes one Stage-A commitment pair. Both engines share `Hasher`, so the
/// root values are the same type and this is a pure field copy.
pub fn retypeStageACommitment(
    comptime From: type,
    comptime To: type,
    value: harness.StageACommitment(From),
) harness.StageACommitment(To) {
    requireTranscriptTypes(From, To);
    return .{
        .preprocessed_root = value.preprocessed_root,
        .main_root = value.main_root,
    };
}

/// Allocating slice sibling of `retypeStageACommitment`. The caller owns the
/// result.
pub fn retypeStageARoots(
    comptime From: type,
    comptime To: type,
    allocator: std.mem.Allocator,
    roots: []const harness.StageACommitment(From),
) ![]harness.StageACommitment(To) {
    requireTranscriptTypes(From, To);
    const result = try allocator.alloc(harness.StageACommitment(To), roots.len);
    for (roots, result) |source, *destination|
        destination.* = retypeStageACommitment(From, To, source);
    return result;
}

/// Retypes the shared relation authority. Every field is engine-independent
/// except the two roots, whose type is `From.Hasher.Hash == To.Hasher.Hash`,
/// so the identity is preserved by construction.
pub fn retypeSharedRelation(
    comptime From: type,
    comptime To: type,
    value: protocol.SharedRelationAuthorityV1(From),
) protocol.SharedRelationAuthorityV1(To) {
    requireTranscriptTypes(From, To);
    return .{
        .format = value.format,
        .plan_identity = value.plan_identity,
        .manifest_identity = value.manifest_identity,
        .projection_identity = value.projection_identity,
        .tree0_root = value.tree0_root,
        .tree1_root = value.tree1_root,
        .interaction_pow_bits = value.interaction_pow_bits,
        .interaction_pow = value.interaction_pow,
        .relation_context = value.relation_context,
        .identity = value.identity,
    };
}

/// Rebuilds the Stage-A manifest for the cold verifier engine from the
/// producer manifest's roots, through the same `createFromRootsValidated`
/// constructor the producer used, and refuses any result whose identity is not
/// the producer's.
///
/// The manifest is *rebuilt*, never retyped whole: its identity is a hash of
/// the plan fields and the root bytes, so an equal identity is evidence that
/// the cold side re-derived the same records rather than trusting them.
pub fn manifestForVerifier(
    comptime From: type,
    comptime To: type,
    allocator: std.mem.Allocator,
    plan: *const provider_authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
    validated: *const provider_authority.OwnedValidatedPlanCallAuthorityV1,
    producer: *const protocol.ProviderStageAManifestV1(From),
) !protocol.OwnedProviderStageAManifestV1(To) {
    requireTranscriptTypes(From, To);
    if (producer.providers.len != plan.shards.len)
        return error.IncrementalOmittedProviderStageARootCountMismatchV1;
    const roots = try allocator.alloc(
        harness.StageACommitment(To),
        producer.providers.len,
    );
    defer allocator.free(roots);
    for (producer.providers, roots) |record, *destination| {
        destination.* = .{
            .preprocessed_root = record.preprocessed_root,
            .main_root = record.main_root,
        };
    }
    var result = try protocol.ProviderStageAManifestV1(To)
        .createFromRootsValidated(allocator, plan, calls, validated, roots);
    errdefer result.deinit(allocator);
    if (!std.mem.eql(
        u8,
        &result.manifest.identity,
        &producer.identity,
    )) return error.IncrementalOmittedProviderManifestIdentityMismatchV1;
    return result;
}

// ---------------------------------------------------------------------------
// Digest helpers
// ---------------------------------------------------------------------------

const leaf_provider_statement_domain =
    "stwo-zig/riscv/ethereum/incremental-leaf-d5-provider-statement/v1\x00";

fn leafProviderStatementIdentity(
    value: *const LeafProviderStatementV4,
) Digest {
    var hasher = Blake2s256.init(.{});
    hasher.update(leaf_provider_statement_domain);
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value.format, .little);
    hasher.update(&word);
    hasher.update(&value.leaf_omission_identity);
    hasher.update(&value.provider.identity);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

const Blake2s256 = blk: {
    if (@hasDecl(std.crypto.hash, "Blake2s256"))
        break :blk std.crypto.hash.Blake2s256;
    break :blk std.crypto.hash.blake2.Blake2s256;
};

fn isZeroDigest(value: Digest) bool {
    var combined: u8 = 0;
    for (value) |byte| combined |= byte;
    return combined == 0;
}

// ---------------------------------------------------------------------------
// Comptime pins
// ---------------------------------------------------------------------------

comptime {
    if (ACTIVATES_PRODUCTION_PROOF) {
        @compileError(
            "the omitted-provider shard transcript cannot claim production " ++
                "before fresh joint closure activation",
        );
    }
    // The wrapper only ever adds a binding: the D5 statement it carries stays
    // the canonical one the shard prover minted.
    if (@FieldType(LeafProviderStatementV4, "provider") != ProviderStatementV1)
        @compileError("leaf provider statement wrapper drifted from the D5 statement");
}
