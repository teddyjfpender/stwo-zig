//! Verifier-custody bridge for one binary-child composition evaluation.
//!
//! The composition circuit is protocol configuration; none of its concrete
//! inputs may come from the caller.  This bridge reconstructs them from an
//! independently validated `VerifiedOuterProofV1`, replays the universal
//! relation draws through a verifier-owned replay receipt, evaluates the
//! authenticated graph, and only then publishes the downstream authority.
//!
//! This remains role-neutral substrate.  `VerifiedChildV1.role` is retained
//! because the frozen downstream V1 authority carries it, but this module
//! neither derives nor interprets that role.  In particular it does not bless
//! the split-precompile V1 role model for adjacent temporal-span composition.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const outer = @import("recursive_fri_outer.zig");
const segment_publication = @import("recursive_segment_v2_verified_publication.zig");
const segment_artifact = @import("recursive_segment_v2_verified_artifact.zig");
const composition_workspace =
    @import("recursive_binary_composition_workspace.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const binary = recursion.binary_fri_outer_source;
const composition_abi = recursion.air.composition_circuit;
const composition_circuit = recursion.recursion_air_composition_circuit;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const capture_layout_v3 = composition_v3.capture_layout_v3;
const lowering = recursion.air.verifier_arithmetic_lowering;
const universal = recursion.air.universal_challenges;
const fixed_profile = recursion.fixed_profile;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;
const segment_manifest = recursion.air.segment_outer_adapter_manifest_v2;
const validateCaptureGeometry = composition_workspace.validateCaptureGeometry;
const validateWorkspace = composition_workspace.validateWorkspace;

pub const FORMAT_VERSION: u16 = 1;
pub const ROSTER_CLAIM_COUNT: usize = recursion.air.universal_roster.COMPONENT_COUNT;
pub const POSEIDON_PARTIAL_COUNT: usize = 2;
pub const COMPOSITION_CLAIM_COUNT: usize =
    ROSTER_CLAIM_COUNT + POSEIDON_PARTIAL_COUNT;
pub const RELATION_CHALLENGE_COUNT: usize = universal.RELATION_COUNT;
pub const POSEIDON_ROSTER_ROW: usize =
    @intFromEnum(recursion.air.universal_roster.Component.poseidon2);
pub const POSEIDON_INTERACTION_COLUMN_COUNT: usize =
    recursion.air.universal_shared_provider.POSEIDON_INTERACTION_COLUMN_COUNT;

pub const ROLE_NEUTRAL_COMPOSITION_CUSTODY = true;
/// The composition publication below is complete.  The frozen downstream V1
/// pair-role model remains protocol substrate rather than an authenticated
/// adjacent-temporal-span recursion statement.
pub const TEMPORAL_V1_DOWNSTREAM_SUBSTRATE_ONLY = true;
pub const HEAP_ALLOCATIONS_PER_PUBLISH: usize = 0;
/// Frozen V1 custody currently validates the capture once for relation/auxiliary
/// replay and once for the allocation-free canonical proof ID.  This is a
/// cold authority-publication cost, not recursive AIR or prover hot-path work;
/// a future versioned admission capability may fuse it after measurement.
pub const VERIFIED_CAPTURE_VALIDATION_PASSES_PER_PUBLISH: usize = 2;

pub const SEGMENT_V2_COMPOSITION_PROFILE_FORMAT_VERSION: u16 = 1;
pub const SEGMENT_V2_COMPOSITION_PROFILE_SCHEMA_VERSION: u16 = 1;
pub const SEGMENT_V2_PHYSICAL_CLAIM_COUNT: usize =
    segment_publication.PROVED_COMPONENT_COUNT;
pub const SEGMENT_V2_UNIVERSAL_ROSTER_COUNT: usize =
    segment_publication.UNIVERSAL_ROSTER_COUNT;
pub const SEGMENT_V2_POSEIDON_PARTIAL_COUNT: usize = POSEIDON_PARTIAL_COUNT;
pub const SEGMENT_V2_COMPOSITION_CLAIM_COUNT: usize =
    SEGMENT_V2_PHYSICAL_CLAIM_COUNT + SEGMENT_V2_POSEIDON_PARTIAL_COUNT;
pub const SEGMENT_V2_POSEIDON_ROSTER_ROW: usize = POSEIDON_ROSTER_ROW;
pub const SEGMENT_V2_PROFILE_HEAP_ALLOCATIONS: usize = 0;
pub const SEGMENT_V2_CLAIM_INPUT_HEAP_ALLOCATIONS: usize = 0;
pub const SEGMENT_V2_LEGACY_V1_PROJECTION_ALLOWED = false;
pub const SEGMENT_V2_ROSTER_ID_DOMAIN =
    "stwo-zig/recursive-segment-v2-composition-roster/v1\x00";
pub const SEGMENT_V2_PROFILE_ID_DOMAIN =
    "stwo-zig/recursive-segment-v2-composition-profile/v1\x00";
pub const SEGMENT_V2_RECORDER_BRIDGE_FORMAT_VERSION: u16 = 1;
pub const SEGMENT_V2_RECORDER_BRIDGE_SCHEMA_VERSION: u16 = 2;
pub const SEGMENT_V2_RECORDER_BRIDGE_ID_DOMAIN =
    "stwo-zig/recursive-segment-v2-composition-recorder-bridge/v1.2\x00";
pub const SEGMENT_V2_RECORDER_BRIDGE_HOT_HEAP_ALLOCATIONS: usize = 0;
pub const SEGMENT_V2_RECORDER_BRIDGE_CAPTURE_LAYOUT_ALLOCATIONS: usize =
    capture_layout_v3.TREE_COUNT;

pub const Error = error{
    AliasedWorkspace,
    CaptureIdentityMismatch,
    ChildIdentityMismatch,
    CircuitProfileMismatch,
    InvalidWorkspaceShape,
    ManifestIdentityMismatch,
    PoseidonCaptureGeometryMismatch,
    RelationReplayMismatch,
    InvalidSegmentV2CompositionProfile,
    LegacySegmentV2ProjectionForbidden,
    SegmentV2ClaimInputAlias,
    SegmentV2PoseidonPartialMismatch,
    SegmentV2RecorderArtifactMismatch,
    SegmentV2RecorderDescriptorMismatch,
    SegmentV2RecorderIdentityMismatch,
};

pub const SegmentV2ClaimOrderV1 = enum(u8) {
    physical_claims_then_poseidon_partials = 1,
};

/// Trusted claim-input ABI for a complete SegmentV2 child.  This profile is
/// intentionally not a revision of `TrustedCompositionProfileV1`: that type
/// remains the exact 36-physical-claim V1 ABI.  SegmentV2 commits all 39
/// physical component claims and appends the two independently sealed row-34
/// Poseidon coordinates, producing 41 inputs with no truncation or projection.
pub const SegmentV2CompositionProfileV1 = struct {
    format_version: u16 = SEGMENT_V2_COMPOSITION_PROFILE_FORMAT_VERSION,
    schema_version: u16 = SEGMENT_V2_COMPOSITION_PROFILE_SCHEMA_VERSION,
    proof_kind: composition_abi.ProofKind = .segment_leaf,
    claim_order: SegmentV2ClaimOrderV1 =
        .physical_claims_then_poseidon_partials,
    physical_claim_count: u8 = SEGMENT_V2_PHYSICAL_CLAIM_COUNT,
    universal_roster_count: u8 = SEGMENT_V2_UNIVERSAL_ROSTER_COUNT,
    poseidon_partial_count: u8 = SEGMENT_V2_POSEIDON_PARTIAL_COUNT,
    composition_claim_count: u8 = SEGMENT_V2_COMPOSITION_CLAIM_COUNT,
    poseidon_roster_row: u8 = SEGMENT_V2_POSEIDON_ROSTER_ROW,
    air_program_id: protocol.Digest,
    manifest_seal: [32]u8,
    catalog_identity: [32]u8,
    roster_identity: [32]u8,
    profile_identity: [32]u8,

    pub fn seal(
        manifest: *const segment_manifest.Manifest,
        air_program_id: protocol.Digest,
    ) !SegmentV2CompositionProfileV1 {
        try manifest.validate();
        try requireProtocolDigest(air_program_id);
        const program_geometry_id =
            segment_manifest.programGeometryShaId(manifest);
        var result = SegmentV2CompositionProfileV1{
            .air_program_id = air_program_id,
            .manifest_seal = program_geometry_id,
            .catalog_identity = manifest.catalog_identity,
            .roster_identity = segmentV2RosterIdentity(manifest),
            .profile_identity = undefined,
        };
        result.profile_identity = segmentV2ProfileIdentity(result);
        try result.validateAgainst(manifest);
        return result;
    }

    pub fn validateAgainst(
        self: SegmentV2CompositionProfileV1,
        manifest: *const segment_manifest.Manifest,
    ) !void {
        try manifest.validate();
        try requireProtocolDigest(self.air_program_id);
        const program_geometry_id =
            segment_manifest.programGeometryShaId(manifest);
        if (self.format_version != SEGMENT_V2_COMPOSITION_PROFILE_FORMAT_VERSION or
            self.schema_version != SEGMENT_V2_COMPOSITION_PROFILE_SCHEMA_VERSION or
            self.proof_kind != .segment_leaf or
            self.claim_order != .physical_claims_then_poseidon_partials or
            self.physical_claim_count != SEGMENT_V2_PHYSICAL_CLAIM_COUNT or
            self.universal_roster_count != SEGMENT_V2_UNIVERSAL_ROSTER_COUNT or
            self.poseidon_partial_count != SEGMENT_V2_POSEIDON_PARTIAL_COUNT or
            self.composition_claim_count != SEGMENT_V2_COMPOSITION_CLAIM_COUNT or
            self.poseidon_roster_row != SEGMENT_V2_POSEIDON_ROSTER_ROW or
            manifest.roster_count != SEGMENT_V2_PHYSICAL_CLAIM_COUNT or
            !std.mem.eql(u8, &self.manifest_seal, &program_geometry_id) or
            !std.mem.eql(u8, &self.catalog_identity, &manifest.catalog_identity) or
            !std.mem.eql(
                u8,
                &self.roster_identity,
                &segmentV2RosterIdentity(manifest),
            ) or !std.mem.eql(
            u8,
            &self.profile_identity,
            &segmentV2ProfileIdentity(self),
        )) {
            return error.InvalidSegmentV2CompositionProfile;
        }
    }

    /// Joins the CPU-side verifier profile to the frontend V3 program
    /// descriptor. Both authorities independently authenticate the same
    /// manifest and AIR program; neither digest is reinterpreted as the other.
    pub fn validateAgainstV3Descriptor(
        self: SegmentV2CompositionProfileV1,
        manifest: *const segment_manifest.Manifest,
        descriptor: composition_v3.ProgramDescriptorV3,
    ) !void {
        try self.validateAgainst(manifest);
        try descriptor.validate();
        if (descriptor.proof_kind != .segment_leaf or
            descriptor.manifest_family != .segment_v2 or
            descriptor.claim_policy != .complete_segment or
            descriptor.source_claim_count != SEGMENT_V2_PHYSICAL_CLAIM_COUNT or
            descriptor.program_roster_count !=
                SEGMENT_V2_PHYSICAL_CLAIM_COUNT or
            descriptor.poseidon_partial_count !=
                SEGMENT_V2_POSEIDON_PARTIAL_COUNT or
            descriptor.composition_claim_count !=
                SEGMENT_V2_COMPOSITION_CLAIM_COUNT or
            descriptor.poseidon_roster_row !=
                SEGMENT_V2_POSEIDON_ROSTER_ROW or
            descriptor.manifest_format_version != manifest.format_version or
            !std.meta.eql(descriptor.air_program_id, self.air_program_id) or
            !std.mem.eql(u8, &descriptor.manifest_seal, &self.manifest_seal) or
            !std.mem.eql(
                u8,
                &descriptor.catalog_identity,
                &self.catalog_identity,
            ))
        {
            return error.SegmentV2RecorderDescriptorMismatch;
        }
    }

    /// Preflights every authority and alias check before the first write, then
    /// publishes the exact fixed input order allocation-free.
    pub fn writeClaimInputs(
        self: SegmentV2CompositionProfileV1,
        manifest: *const segment_manifest.Manifest,
        claimed_sums: *const [SEGMENT_V2_PHYSICAL_CLAIM_COUNT]QM31,
        poseidon2_partials: *const [SEGMENT_V2_POSEIDON_PARTIAL_COUNT]QM31,
        destination: *[SEGMENT_V2_COMPOSITION_CLAIM_COUNT]QM31,
    ) !void {
        try self.validateAgainst(manifest);
        for (claimed_sums) |value| try requireCanonicalQm31(value);
        for (poseidon2_partials) |value| try requireCanonicalQm31(value);
        if (!poseidon2_partials[0].add(poseidon2_partials[1]).eql(
            claimed_sums[SEGMENT_V2_POSEIDON_ROSTER_ROW],
        )) return error.SegmentV2PoseidonPartialMismatch;

        const target = std.mem.asBytes(destination);
        if (overlap(target, std.mem.asBytes(claimed_sums)) or
            overlap(target, std.mem.asBytes(poseidon2_partials)))
        {
            return error.SegmentV2ClaimInputAlias;
        }

        @memcpy(
            destination[0..SEGMENT_V2_PHYSICAL_CLAIM_COUNT],
            claimed_sums,
        );
        @memcpy(
            destination[SEGMENT_V2_PHYSICAL_CLAIM_COUNT..],
            poseidon2_partials,
        );
    }

    /// There is deliberately no lossy 39 -> 36 compatibility projection.
    pub fn requireLegacyV1Projection(
        self: SegmentV2CompositionProfileV1,
        manifest: *const segment_manifest.Manifest,
    ) !void {
        try self.validateAgainst(manifest);
        return error.LegacySegmentV2ProjectionForbidden;
    }
};

/// Cold, owned chain of custody from a successfully verified SegmentV2 proof
/// to the V3 symbolic recorder. The dynamic capture remains externally owned;
/// this bridge retains only its authenticated layout and fixed verifier-minted
/// values. Schema-2 `TranscriptPrefixV1` is deliberately opaque here: the
/// existing artifact preflight validates it, and this envelope binds only its
/// published `transcript_prefix_id` rather than duplicating its hashing.
pub const SegmentV2RecorderBridgeV3 = struct {
    format_version: u16 = SEGMENT_V2_RECORDER_BRIDGE_FORMAT_VERSION,
    schema_version: u16 = SEGMENT_V2_RECORDER_BRIDGE_SCHEMA_VERSION,
    profile: SegmentV2CompositionProfileV1,
    descriptor: composition_v3.ProgramDescriptorV3,
    layout: capture_layout_v3.CaptureLayoutV3,
    publication_id: protocol.Digest,
    capture_id: protocol.Digest,
    witness_id: protocol.Digest,
    transcript_prefix_id: protocol.Digest,
    relation_draws_id: protocol.Digest,
    poseidon2_partials_id: protocol.Digest,
    claim_inputs: [SEGMENT_V2_COMPOSITION_CLAIM_COUNT]QM31,
    public_wire_boundary: QM31,
    relations: universal.UniversalRelations,
    composition_randomness: QM31,
    oods_seed: QM31,
    identity: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        profile: SegmentV2CompositionProfileV1,
        descriptor: composition_v3.ProgramDescriptorV3,
        manifest: *const segment_manifest.Manifest,
        capture: *const segment_artifact.OuterProofCapture,
        publication: *const segment_artifact.Publication,
        witness: *const segment_artifact.RecursiveWitnessV1,
    ) !SegmentV2RecorderBridgeV3 {
        try profile.validateAgainstV3Descriptor(manifest, descriptor);
        try segment_artifact.preflight(
            capture,
            publication,
            witness,
            manifest,
        );
        if (!std.meta.eql(profile.air_program_id, witness.air_program_id))
            return error.SegmentV2RecorderArtifactMismatch;

        var layout = try capture_layout_v3.CaptureLayoutV3.initSegment(
            allocator,
            manifest,
            capture,
        );
        errdefer layout.deinit();
        var claim_inputs: [SEGMENT_V2_COMPOSITION_CLAIM_COUNT]QM31 = undefined;
        try profile.writeClaimInputs(
            manifest,
            &witness.claimed_sums,
            &witness.poseidon2_partials,
            &claim_inputs,
        );
        const relations = universal.UniversalRelations.fromDraws(
            &witness.relation_draws,
        );
        try relations.validate();

        var result = SegmentV2RecorderBridgeV3{
            .profile = profile,
            .descriptor = descriptor,
            .layout = layout,
            .publication_id = publication.publication_id,
            .capture_id = witness.capture_id,
            .witness_id = witness.witness_id,
            .transcript_prefix_id = witness.transcript_prefix.transcript_prefix_id,
            .relation_draws_id = witness.relation_draws_id,
            .poseidon2_partials_id = witness.poseidon2_partials_id,
            .claim_inputs = claim_inputs,
            .public_wire_boundary = witness.transcript_prefix.public_wire_boundary_claimed_sum,
            .relations = relations,
            .composition_randomness = capture.composition_randomness,
            .oods_seed = capture.oods_seed,
            .identity = undefined,
        };
        result.identity = segmentV2RecorderBridgeIdentity(&result);
        try result.validateSelfConsistency(manifest);
        layout = undefined;
        return result;
    }

    pub fn deinit(self: *SegmentV2RecorderBridgeV3) void {
        self.layout.deinit();
        self.* = undefined;
    }

    /// Allocation-free integrity check after the cold capture layout has been
    /// derived. It authenticates the retained profile/layout/value copies but
    /// intentionally does not rehash the opaque transcript-prefix preimage.
    pub fn validateSelfConsistency(
        self: *const SegmentV2RecorderBridgeV3,
        manifest: *const segment_manifest.Manifest,
    ) !void {
        try self.profile.validateAgainstV3Descriptor(
            manifest,
            self.descriptor,
        );
        try self.layout.validateAgainstSegment(manifest);
        try composition_v3.validateClaimInputs(.segment_leaf, &self.claim_inputs);
        try requireCanonicalQm31(self.public_wire_boundary);
        try self.relations.validate();
        if (self.format_version != SEGMENT_V2_RECORDER_BRIDGE_FORMAT_VERSION or
            self.schema_version != SEGMENT_V2_RECORDER_BRIDGE_SCHEMA_VERSION or
            self.layout.sampled_value_count == 0 or
            !std.meta.eql(self.profile.air_program_id, self.descriptor.air_program_id) or
            protocolDigestIsZero(self.publication_id) or
            protocolDigestIsZero(self.capture_id) or
            protocolDigestIsZero(self.witness_id) or
            protocolDigestIsZero(self.transcript_prefix_id) or
            protocolDigestIsZero(self.relation_draws_id) or
            protocolDigestIsZero(self.poseidon2_partials_id) or
            !std.mem.eql(
                u8,
                &self.identity,
                &segmentV2RecorderBridgeIdentity(self),
            ))
        {
            return error.SegmentV2RecorderIdentityMismatch;
        }
    }

    /// Full cold re-admission against the still-owned verifier artifact. A
    /// changed capture shape is caught by rebuilding its sealed layout; a
    /// splice between otherwise valid publication/witness objects is caught by
    /// the existing artifact preflight before any comparison here.
    pub fn validateAgainst(
        self: *const SegmentV2RecorderBridgeV3,
        allocator: std.mem.Allocator,
        manifest: *const segment_manifest.Manifest,
        capture: *const segment_artifact.OuterProofCapture,
        publication: *const segment_artifact.Publication,
        witness: *const segment_artifact.RecursiveWitnessV1,
    ) !void {
        try self.validateSelfConsistency(manifest);
        try segment_artifact.preflight(
            capture,
            publication,
            witness,
            manifest,
        );
        var expected_layout = try capture_layout_v3.CaptureLayoutV3.initSegment(
            allocator,
            manifest,
            capture,
        );
        defer expected_layout.deinit();
        var expected_claims: [SEGMENT_V2_COMPOSITION_CLAIM_COUNT]QM31 = undefined;
        try self.profile.writeClaimInputs(
            manifest,
            &witness.claimed_sums,
            &witness.poseidon2_partials,
            &expected_claims,
        );
        const expected_relations = universal.UniversalRelations.fromDraws(
            &witness.relation_draws,
        );
        try expected_relations.validate();
        if (!std.mem.eql(u8, &expected_layout.identity, &self.layout.identity) or
            !std.meta.eql(expected_claims, self.claim_inputs) or
            !std.meta.eql(expected_relations, self.relations) or
            !std.meta.eql(publication.publication_id, self.publication_id) or
            !std.meta.eql(witness.capture_id, self.capture_id) or
            !std.meta.eql(witness.witness_id, self.witness_id) or
            !std.meta.eql(
                witness.transcript_prefix.transcript_prefix_id,
                self.transcript_prefix_id,
            ) or !std.meta.eql(witness.relation_draws_id, self.relation_draws_id) or
            !std.meta.eql(
                witness.poseidon2_partials_id,
                self.poseidon2_partials_id,
            ) or !witness.transcript_prefix.public_wire_boundary_claimed_sum.eql(
            self.public_wire_boundary,
        ) or !capture.composition_randomness.eql(self.composition_randomness) or
            !capture.oods_seed.eql(self.oods_seed))
        {
            return error.SegmentV2RecorderArtifactMismatch;
        }
    }

    /// Borrows the exact concrete graph inputs only after re-admitting their
    /// successful verifier artifact. The returned pointers remain valid while
    /// this bridge and the three borrowed artifact objects remain unchanged.
    pub fn concreteWitness(
        self: *const SegmentV2RecorderBridgeV3,
        allocator: std.mem.Allocator,
        manifest: *const segment_manifest.Manifest,
        capture: *const segment_artifact.OuterProofCapture,
        publication: *const segment_artifact.Publication,
        witness: *const segment_artifact.RecursiveWitnessV1,
    ) !composition_v3.WitnessV3 {
        try self.validateAgainst(
            allocator,
            manifest,
            capture,
            publication,
            witness,
        );
        return .{
            .parent_binary_selector = true,
            .proof_kind = .segment_leaf,
            .statement_words = &publication.statement_words,
            .sampled_values = capture.sampled_values,
            .claim_inputs = &self.claim_inputs,
            .public_wire_boundary = self.public_wire_boundary,
            .relations = &self.relations,
            .composition_randomness = self.composition_randomness,
            .oods_seed = self.oods_seed,
        };
    }

    /// Allocation-free handoff to the symbolic 39-row program after the cold
    /// bridge has authenticated its profile and capture-derived layout.
    pub fn beginRecorder(
        self: *const SegmentV2RecorderBridgeV3,
        manifest: *const segment_manifest.Manifest,
        builder: *composition_v3.segment_recorder_v3.graph_recorder.Builder,
        sampled_values: []const composition_v3.segment_recorder_v3.graph_recorder.Scalar,
        claim_inputs: *const [SEGMENT_V2_COMPOSITION_CLAIM_COUNT]composition_v3.segment_recorder_v3.graph_recorder.Scalar,
        challenges: *const composition_v3.segment_recorder_v3.graph_recorder.ChallengeSet,
        composition_randomness: composition_v3.segment_recorder_v3.graph_recorder.Scalar,
        oods_point: stwo_core.circle.CirclePoint(
            composition_v3.segment_recorder_v3.graph_recorder.Scalar,
        ),
        denominator_cache: *composition_v3.segment_recorder_v3.graph_recorder.DenominatorCache,
    ) !composition_v3.segment_recorder_v3.SegmentProgramRecorderV3 {
        try self.validateSelfConsistency(manifest);
        return composition_v3.segment_recorder_v3.SegmentProgramRecorderV3.init(
            builder,
            manifest,
            &self.layout,
            sampled_values,
            claim_inputs,
            challenges,
            composition_randomness,
            oods_point,
            denominator_cache,
        );
    }
};

/// Evaluates and publishes one authority transactionally.  Relation draws
/// come only from `VerifiedOuterProofV1.validateAndReplayRelations`, which
/// authenticates its embedded replay receipt against the complete outer
/// publication.  The destination remains unchanged on every rejected input.
pub fn publishInto(
    destination: *binary.VerifiedChildCompositionAuthority,
    input_scratch: []QM31,
    node_scratch: []QM31,
    verified: *const outer.VerifiedOuterProofV1,
    trusted: binary.TrustedCompositionProfileV1,
    child_index: usize,
    verified_child: pair_node.VerifiedChildV1,
    shape: fixed_profile.ProofShapeV1,
    circuit: *const composition_circuit.Circuit,
) !void {
    const relations = try verified.validateAndReplayRelations();
    const verified_proof_id = try admission.proofIdRuntime(
        verified.seal,
        &verified.receipt,
        &verified.capture,
    );
    if (!std.meta.eql(verified_proof_id, verified_child.proof_id))
        return error.ChildIdentityMismatch;
    try circuit.validate();
    try trusted.validate();
    try shape.validate();

    try validateCircuitProfile(circuit, trusted, verified);
    try validateChildIdentity(verified, child_index, verified_child, shape);
    try validateShapeCaptureGeometry(verified, shape);
    try validateCaptureGeometry(verified, trusted, circuit);
    try validateWorkspace(
        destination,
        input_scratch,
        node_scratch,
        verified,
        circuit,
    );

    var roster_claims: [ROSTER_CLAIM_COUNT]QM31 = undefined;
    for (&roster_claims, verified.receipt.claimed_sums) |*claim, words|
        claim.* = qm31FromCanonicalWords(words);
    const poseidon_total = roster_claims[POSEIDON_ROSTER_ROW];
    if (!poseidon_total.eql(
        verified.poseidon2_partials[0].add(verified.poseidon2_partials[1]),
    )) return error.RelationReplayMismatch;

    const witness = composition_circuit.Witness{
        .parent_binary_selector = true,
        .child_kind = trusted.child_proof_kind,
        .statement_words = &verified.statement_words,
        .sampled_values = verified.capture.sampled_values,
        .claimed_sums = &roster_claims,
        .poseidon2_partials = &verified.poseidon2_partials,
        .relations = &relations,
        .composition_randomness = verified.capture.composition_randomness,
        .oods_seed = verified.capture.oods_seed,
    };
    try circuit.evaluateInto(witness, input_scratch, node_scratch);

    const graph = circuit.graph();
    const evaluation = lowering.Evaluation{
        .circuit_identity = circuit.identity_digest,
        .values = node_scratch,
    };
    const staged = try binary.VerifiedChildCompositionAuthority.authenticate(
        trusted,
        child_index,
        verified_child,
        shape,
        circuit.identity_digest,
        graph,
        evaluation,
        verified.poseidon2_partials,
        poseidon_total,
    );
    destination.* = staged;
}

fn validateShapeCaptureGeometry(
    verified: *const outer.VerifiedOuterProofV1,
    shape: fixed_profile.ProofShapeV1,
) !void {
    if (verified.capture.column_log_sizes.len != fixed_profile.TREE_COUNT or
        shape.preprocessed_column_count != shape.tree_column_counts[0])
    {
        return error.CaptureIdentityMismatch;
    }
    var table_count: u32 = 0;
    for (verified.capture.column_log_sizes, 0..) |logs, tree| {
        if (logs.len == 0 or logs.len > std.math.maxInt(u32) or
            shape.tree_column_counts[tree] != logs.len)
        {
            return error.CaptureIdentityMismatch;
        }
        table_count = std.math.add(
            u32,
            table_count,
            @intCast(logs.len),
        ) catch return error.CaptureIdentityMismatch;
        var maximum_log: u32 = 0;
        for (logs) |log_size| maximum_log = @max(maximum_log, log_size);
        if (shape.tree_heights[tree] != maximum_log)
            return error.CaptureIdentityMismatch;
    }
    const final_tree_height = std.math.add(
        u32,
        shape.column_log_degree,
        admission.LOG_BLOWUP_FACTOR,
    ) catch return error.CaptureIdentityMismatch;
    if (shape.table_count != table_count or
        final_tree_height != shape.tree_heights[fixed_profile.TREE_COUNT - 1])
    {
        return error.CaptureIdentityMismatch;
    }
}

fn validateCircuitProfile(
    circuit: *const composition_circuit.Circuit,
    trusted: binary.TrustedCompositionProfileV1,
    verified: *const outer.VerifiedOuterProofV1,
) !void {
    if (!trusted.row18_input_authority or
        trusted.input_profile.sampled_value_count !=
            verified.capture.sampled_values.len or
        trusted.input_profile.claimed_sum_count != COMPOSITION_CLAIM_COUNT or
        trusted.input_profile.relation_challenge_count !=
            RELATION_CHALLENGE_COUNT or
        !std.meta.eql(trusted.input_profile, circuit.input_profile) or
        trusted.input_bindings.len != circuit.bindings.len or
        !std.mem.eql(u8, &trusted.circuit_identity, &circuit.identity_digest) or
        !std.mem.eql(
            u8,
            &trusted.graph_identity,
            &circuit.recorded.identity_digest,
        ) or !std.meta.eql(trusted.air_program_id, verified.receipt.air_program_id))
    {
        return error.CircuitProfileMismatch;
    }
    for (trusted.input_bindings, circuit.bindings) |expected, actual|
        if (!std.meta.eql(expected, actual))
            return error.CircuitProfileMismatch;

    const manifest_id = outer.manifestIdForSeal(circuit.manifest_seal);
    if (!std.meta.eql(manifest_id, verified.receipt.manifest_id))
        return error.ManifestIdentityMismatch;
}

fn validateChildIdentity(
    verified: *const outer.VerifiedOuterProofV1,
    child_index: usize,
    child: pair_node.VerifiedChildV1,
    shape: fixed_profile.ProofShapeV1,
) !void {
    if (child_index >= pair_node.CHILD_COUNT)
        return error.ChildIdentityMismatch;
    const expected_position: pair_node.ChildPosition = if (child_index == 0)
        .left
    else
        .right;
    if (child.position != expected_position or
        !std.meta.eql(child.protocol_id, protocol.PROTOCOL_ID_WORDS) or
        !std.meta.eql(child.statement_id, verified.receipt.statement_id) or
        !std.meta.eql(child.transcript_id, verified.seal.transcript_id) or
        !std.meta.eql(child.parent_vk_id, verified.receipt.verification_key_id) or
        !std.meta.eql(shape.air_program_id, verified.receipt.air_program_id) or
        shape.claimed_sum_count != ROSTER_CLAIM_COUNT or
        shape.sampled_value_count != verified.capture.sampled_values.len or
        verified.capture.commitments.len == 0 or
        !std.meta.eql(shape.preprocessing_id, verified.capture.commitments[0]))
    {
        return error.ChildIdentityMismatch;
    }
}

fn segmentV2RosterIdentity(
    manifest: *const segment_manifest.Manifest,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SEGMENT_V2_ROSTER_ID_DOMAIN);
    hashShaInt(&hash, u16, SEGMENT_V2_COMPOSITION_PROFILE_FORMAT_VERSION);
    hashShaInt(&hash, u16, SEGMENT_V2_COMPOSITION_PROFILE_SCHEMA_VERSION);
    hashShaInt(&hash, u8, manifest.roster_count);
    const program_geometry_id =
        segment_manifest.programGeometryShaId(manifest);
    hash.update(&program_geometry_id);
    hash.update(&manifest.catalog_identity);
    for (manifest.roster_rows, 0..) |row, ordinal| {
        const placement = manifest.placements[row] orelse unreachable;
        hashShaInt(&hash, u8, @intCast(ordinal));
        hashShaInt(&hash, u8, row);
        hashShaInt(&hash, u8, placement.claimed_sum_index);
        hash.update(&placement.geometry.semantic_digest);
    }
    return hash.finalResult();
}

fn segmentV2ProfileIdentity(
    profile: SegmentV2CompositionProfileV1,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SEGMENT_V2_PROFILE_ID_DOMAIN);
    hashShaInt(&hash, u16, profile.format_version);
    hashShaInt(&hash, u16, profile.schema_version);
    hashShaInt(&hash, u8, @intFromEnum(profile.proof_kind));
    hashShaInt(&hash, u8, @intFromEnum(profile.claim_order));
    hashShaInt(&hash, u8, profile.physical_claim_count);
    hashShaInt(&hash, u8, profile.universal_roster_count);
    hashShaInt(&hash, u8, profile.poseidon_partial_count);
    hashShaInt(&hash, u8, profile.composition_claim_count);
    hashShaInt(&hash, u8, profile.poseidon_roster_row);
    for (profile.air_program_id) |word| hashShaInt(&hash, u32, word);
    hash.update(&profile.manifest_seal);
    hash.update(&profile.catalog_identity);
    hash.update(&profile.roster_identity);
    return hash.finalResult();
}

fn segmentV2RecorderBridgeIdentity(
    bridge: *const SegmentV2RecorderBridgeV3,
) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SEGMENT_V2_RECORDER_BRIDGE_ID_DOMAIN);
    hashShaInt(&hash, u16, bridge.format_version);
    hashShaInt(&hash, u16, bridge.schema_version);
    hash.update(&bridge.profile.profile_identity);
    hash.update(&bridge.descriptor.identity);
    hash.update(&bridge.layout.identity);
    hashProtocolDigest(&hash, bridge.publication_id);
    hashProtocolDigest(&hash, bridge.capture_id);
    hashProtocolDigest(&hash, bridge.witness_id);
    // TranscriptPrefixV1 is opaque verified custody at this boundary. Bind its
    // verifier-minted identity without reinterpreting or rehashing its fields.
    hashProtocolDigest(&hash, bridge.transcript_prefix_id);
    hashProtocolDigest(&hash, bridge.relation_draws_id);
    hashProtocolDigest(&hash, bridge.poseidon2_partials_id);
    hashShaInt(&hash, u32, bridge.layout.sampled_value_count);
    for (bridge.claim_inputs) |value| hashQm31(&hash, value);
    hashQm31(&hash, bridge.public_wire_boundary);
    for (bridge.relations.elements) |element| {
        hashShaInt(&hash, u8, element.arity);
        hashQm31(&hash, element.z);
        hashQm31(&hash, element.alpha);
    }
    hashQm31(&hash, bridge.composition_randomness);
    hashQm31(&hash, bridge.oods_seed);
    return hash.finalResult();
}

fn protocolDigestIsZero(value: protocol.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

fn hashProtocolDigest(hash: anytype, value: protocol.Digest) void {
    for (value) |word| hashShaInt(hash, u32, word);
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word|
        hashShaInt(hash, u32, word.toU32());
}

fn requireProtocolDigest(value: protocol.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus)
            return error.InvalidSegmentV2CompositionProfile;
        aggregate |= word;
    }
    if (aggregate == 0)
        return error.InvalidSegmentV2CompositionProfile;
}

fn requireCanonicalQm31(value: QM31) !void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus)
            return error.InvalidSegmentV2CompositionProfile;
}

fn hashShaInt(
    hash: anytype,
    comptime T: type,
    value: T,
) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn qm31FromCanonicalWords(words: [4]u32) QM31 {
    return QM31.fromM31Array(.{
        M31.fromCanonical(words[0]),
        M31.fromCanonical(words[1]),
        M31.fromCanonical(words[2]),
        M31.fromCanonical(words[3]),
    });
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

comptime {
    if (FORMAT_VERSION != 1 or ROSTER_CLAIM_COUNT != 36 or
        POSEIDON_PARTIAL_COUNT != 2 or COMPOSITION_CLAIM_COUNT != 38 or
        RELATION_CHALLENGE_COUNT != 47 or POSEIDON_ROSTER_ROW != 34 or
        POSEIDON_INTERACTION_COLUMN_COUNT != 8 or
        !ROLE_NEUTRAL_COMPOSITION_CUSTODY or
        !TEMPORAL_V1_DOWNSTREAM_SUBSTRATE_ONLY or
        HEAP_ALLOCATIONS_PER_PUBLISH != 0 or
        VERIFIED_CAPTURE_VALIDATION_PASSES_PER_PUBLISH != 2)
    {
        @compileError("binary composition authority custody contract drifted");
    }
    if (SEGMENT_V2_COMPOSITION_PROFILE_FORMAT_VERSION != 1 or
        SEGMENT_V2_COMPOSITION_PROFILE_SCHEMA_VERSION != 1 or
        SEGMENT_V2_RECORDER_BRIDGE_FORMAT_VERSION != 1 or
        SEGMENT_V2_RECORDER_BRIDGE_SCHEMA_VERSION != 2 or
        SEGMENT_V2_PHYSICAL_CLAIM_COUNT != 39 or
        SEGMENT_V2_UNIVERSAL_ROSTER_COUNT != 36 or
        SEGMENT_V2_POSEIDON_PARTIAL_COUNT != 2 or
        SEGMENT_V2_COMPOSITION_CLAIM_COUNT != 41 or
        SEGMENT_V2_POSEIDON_ROSTER_ROW != 34 or
        SEGMENT_V2_PROFILE_HEAP_ALLOCATIONS != 0 or
        SEGMENT_V2_CLAIM_INPUT_HEAP_ALLOCATIONS != 0 or
        SEGMENT_V2_LEGACY_V1_PROJECTION_ALLOWED or
        COMPOSITION_CLAIM_COUNT == SEGMENT_V2_COMPOSITION_CLAIM_COUNT)
    {
        @compileError("SegmentV2 composition claim profile drifted");
    }
}
