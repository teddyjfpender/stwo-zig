//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_3 = @import("recursion_air_composition_circuit_v3_heterogeneous_session_v3.zig");
const dependency_5 = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

const HeterogeneousSessionV3 = dependency_3.HeterogeneousSessionV3;
const validateCanonicalEmptyPublication = dependency_5.validateCanonicalEmptyPublication;
const canonicalEmptyAirProgramId = dependency_5.canonicalEmptyAirProgramId;
const requireAirProgramId = dependency_5.requireAirProgramId;
const hashInt = dependency_5.hashInt;
const allZero = dependency_5.allZero;

pub const std = @import("std");

pub const stwo_core = @import("stwo_core");

pub const circle = stwo_core.circle;

pub const M31 = stwo_core.fields.m31.M31;

pub const QM31 = stwo_core.fields.qm31.QM31;

pub const m31 = stwo_core.fields.m31;

pub const qm31 = stwo_core.fields.qm31;

pub const verifier_types = stwo_core.verifier_types;

pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const graph_mod = @import("air/composition_circuit.zig");

pub const recorder = @import("air/composition_graph_recorder.zig");

pub const segment_manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");

pub const universal_manifest_mod = @import("air/universal_adapter_manifest.zig");

pub const universal_roster = @import("air/universal_roster.zig");

pub const universal = @import("air/universal_challenges.zig");

pub const statement_input = @import("air/statement_input.zig");

pub const channel = @import("poseidon2_channel.zig");

pub const span_statement = @import("span_statement.zig");

pub const temporal_pair_node = @import("temporal_pair_node.zig");

pub const capture_layout_v3 =
    @import("recursion_air_composition_capture_layout_v3.zig");

pub const segment_recorder_v3 =
    @import("recursion_air_composition_segment_recorder_v3.zig");

pub const authority_mint =
    @import("recursion_air_composition_circuit_v3_authority_mint.zig");

pub const FORMAT_VERSION: u16 = 3;

pub const SCHEMA_VERSION: u16 = 2;

pub const CIRCUIT_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-composition-circuit/v3.2\x00";

pub const ORDERED_PROGRAM_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-ordered-program/v3\x00";

pub const PROGRAM_DESCRIPTOR_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-program-descriptor/v3\x00";

pub const PROGRAM_ROSTER_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-program-roster/v3\x00";

pub const CONFIGURATION_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-configuration/v3.2\x00";

pub const CLAIM_INPUT_CONTENT_DOMAIN =
    "stwo-zig/typed-air/binary-recursion-claim-input-content/v3\x00";

pub const CANONICAL_EMPTY_PROGRAM_DOMAIN =
    "stwo-zig/typed-air/recursion-canonical-empty-program/v3.1\x00";

pub const CANONICAL_EMPTY_AIR_ID_DOMAIN =
    "stwo-zig/typed-air/recursion-canonical-empty-air-id/v3.1\x00";

pub const ProofKind = graph_mod.ProofKind;

pub const AirProgramId = channel.Digest;

pub const UNIVERSAL_PHYSICAL_CLAIM_COUNT: usize =
    universal_roster.COMPONENT_COUNT;

pub const SEGMENT_PHYSICAL_CLAIM_COUNT: usize =
    segment_manifest_mod.COMPONENT_COUNT;

pub const EMPTY_PHYSICAL_CLAIM_COUNT: usize = 0;

pub const MAX_PHYSICAL_CLAIM_COUNT: usize = SEGMENT_PHYSICAL_CLAIM_COUNT;

pub const POSEIDON_PARTIAL_COUNT: usize = 2;

pub const POSEIDON_ROSTER_ROW: usize =
    @intFromEnum(universal_roster.Component.poseidon2);

pub const POSEIDON_AUX_START: usize = MAX_PHYSICAL_CLAIM_COUNT;

pub const COMPOSITION_CLAIM_INPUT_COUNT: usize =
    MAX_PHYSICAL_CLAIM_COUNT + POSEIDON_PARTIAL_COUNT;

pub const RELATION_CHALLENGE_COUNT: usize = universal.RELATION_COUNT;

pub const STATEMENT_WORD_COUNT: usize = statement_input.CANONICAL_WORD_COUNT;

pub const PROGRAM_KIND_COUNT: usize = 3;

pub const CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT: usize =
    (SEGMENT_PHYSICAL_CLAIM_COUNT - UNIVERSAL_PHYSICAL_CLAIM_COUNT) +
    COMPOSITION_CLAIM_INPUT_COUNT + 1;

/// V3.1 reuses the first Segment-only tail slot for the deterministic public
/// statement contribution of a proofless empty leaf.  Rows 0--35 retain zero
/// claims, and the two Poseidon auxiliary slots remain zero.
pub const CANONICAL_EMPTY_PUBLIC_CLAIM_INDEX: usize =
    UNIVERSAL_PHYSICAL_CLAIM_COUNT;

pub const CANONICAL_EMPTY_PROGRAM_SCHEMA_VERSION: u16 = 1;

pub const CANONICAL_EMPTY_CLAIM_POLICY_GRAPH_CONSTRAINT_COUNT: usize =
    (SEGMENT_PHYSICAL_CLAIM_COUNT - UNIVERSAL_PHYSICAL_CLAIM_COUNT) +
    (COMPOSITION_CLAIM_INPUT_COUNT - 1) + 1;

pub const HEAP_ALLOCATIONS_PER_CLAIM_WRITE: usize = 0;

pub const HEAP_ALLOCATIONS_PER_INPUT_WRITE: usize = 0;

pub const HEAP_ALLOCATIONS_PER_AUTHORITY_MINT: usize = 0;

pub const LEGACY_V2_PROFILE_ACCEPTED = false;

pub const LOSSY_SEGMENT_PROJECTION_AVAILABLE = false;

pub const PROOF_KIND_AWARE_INPUT_AUTHORITY_AVAILABLE = true;

pub const HETEROGENEOUS_PROGRAM_ROSTER_AVAILABLE = true;

pub const CLAIM_POLICY_GRAPH_CONSTRAINTS_AVAILABLE = true;

/// The cold transaction and exact three-program orchestration exist, but the
/// production capability stays false until a real independently initialized
/// empty cohort joins the already-real Segment and binary lanes in one graph.
pub const HETEROGENEOUS_GRAPH_SESSION_SUBSTRATE_AVAILABLE = true;

/// A finalized heterogeneous recorder now mints and retains a graph authority.
/// Production admission remains false until the independently initialized
/// parent verifier consumes that authority end to end.
pub const RECORDER_MINT_SUBSTRATE_AVAILABLE = true;

pub const HETEROGENEOUS_GRAPH_RECORDER_AVAILABLE = false;

/// This is the production-admission flag, not the recorder's internal mint
/// substrate.  There is no public constructor: only a successfully finalized
/// `HeterogeneousSessionV3` can produce the retained authority.
pub const CIRCUIT_AUTHORITY_MINT_AVAILABLE = false;

pub const Error = graph_mod.Error || recorder.Error || segment_manifest_mod.Error ||
    universal_manifest_mod.Error || capture_layout_v3.Error || universal.Error || error{
    AirProgramIdentityMismatch,
    AliasedInput,
    CircuitAuthorityMismatch,
    ConfigurationIdentityMismatch,
    CanonicalEmptyProgramMismatch,
    EmptyClaimInputMustBeZero,
    EmptyProviderClaimMismatch,
    InactiveClaimInputMustBeZero,
    InvalidClaimInputCount,
    InvalidClaimInputProfile,
    InvalidProgramRoster,
    IncompleteHeterogeneousProgram,
    InvalidHeterogeneousProgram,
    InvalidWitnessShape,
    LegacyV2ProjectionForbidden,
    ManifestAuthorityMismatch,
    NonCanonicalField,
    PoseidonPartialMismatch,
};

pub const ManifestFamilyV3 = enum(u8) {
    universal_v1 = 1,
    segment_v2 = 2,
};

pub const ClaimPolicyV3 = enum(u8) {
    complete_segment = 1,
    universal_with_zero_tail = 2,
    canonical_empty = 3,
    canonical_empty_provider = 4,
};

pub const TrustedManifestsV3 = struct {
    universal: *const universal_manifest_mod.Manifest,
    segment: *const segment_manifest_mod.Manifest,
};

pub const AirProgramIdsV3 = struct {
    segment_leaf: AirProgramId,
    binary_node: AirProgramId,
    empty_leaf: AirProgramId,

    pub fn forKind(self: AirProgramIdsV3, kind: ProofKind) AirProgramId {
        return switch (kind) {
            .segment_leaf => self.segment_leaf,
            .binary_node => self.binary_node,
            .empty_leaf => self.empty_leaf,
        };
    }

    pub fn validate(self: AirProgramIdsV3) Error!void {
        try requireAirProgramId(self.segment_leaf);
        try requireAirProgramId(self.binary_node);
        try requireAirProgramId(self.empty_leaf);
    }
};

/// Statement-specific authority for the proofless empty base case.
///
/// A binary proof has a verifier capture from which OODS samples and claims
/// are authenticated.  An empty leaf has no proof, so reusing Binary's layout
/// with caller-supplied zeros would leave the public statement unauthenticated.
/// This authority instead binds the exact verified empty publication, the
/// dedicated zero-shell layout, and the universal manifest into Empty's AIR
/// program id.  Segment and Binary descriptors remain byte-for-byte unchanged.
pub const CanonicalEmptyProgramV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = CANONICAL_EMPTY_PROGRAM_SCHEMA_VERSION,
    manifest_seal: [32]u8,
    binary_layout_identity: [32]u8,
    empty_layout_identity: [32]u8,
    parameter_authority_identity: [32]u8,
    statement_words: span_statement.StatementWords,
    statement_id: AirProgramId,
    publication_id: AirProgramId,
    identity: [32]u8,
    air_program_id: AirProgramId,

    pub fn seal(
        manifest: *const universal_manifest_mod.Manifest,
        binary_layout: *const capture_layout_v3.CaptureLayoutV3,
        empty_layout: *const capture_layout_v3.CanonicalEmptyCaptureLayoutV3,
        publication: *const temporal_pair_node.VerifiedChildV2,
        parameter_authority_identity: [32]u8,
    ) Error!CanonicalEmptyProgramV3 {
        try manifest.validate();
        try binary_layout.validateAgainstBinary(manifest);
        try empty_layout.validateAgainst(manifest, binary_layout);
        try validateCanonicalEmptyPublication(publication);
        if (allZero(&parameter_authority_identity))
            return error.CanonicalEmptyProgramMismatch;
        var result = CanonicalEmptyProgramV3{
            .manifest_seal = manifest.seal,
            .binary_layout_identity = binary_layout.identity,
            .empty_layout_identity = empty_layout.identity,
            .parameter_authority_identity = parameter_authority_identity,
            .statement_words = publication.statement_words,
            .statement_id = publication.statementId() catch
                return error.CanonicalEmptyProgramMismatch,
            .publication_id = publication.id() catch
                return error.CanonicalEmptyProgramMismatch,
            .identity = undefined,
            .air_program_id = undefined,
        };
        result.identity = canonicalEmptyProgramIdentity(&result);
        result.air_program_id = canonicalEmptyAirProgramId(&result.identity);
        try result.validateAgainst(manifest, binary_layout, empty_layout);
        return result;
    }

    pub fn validateAgainst(
        self: CanonicalEmptyProgramV3,
        manifest: *const universal_manifest_mod.Manifest,
        binary_layout: *const capture_layout_v3.CaptureLayoutV3,
        empty_layout: *const capture_layout_v3.CanonicalEmptyCaptureLayoutV3,
    ) Error!void {
        try manifest.validate();
        try binary_layout.validateAgainstBinary(manifest);
        try empty_layout.validateAgainst(manifest, binary_layout);
        const statement = span_statement.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        ) catch return error.CanonicalEmptyProgramMismatch;
        if (statement.slots.height != 0) return error.CanonicalEmptyProgramMismatch;
        switch (statement.body) {
            .empty => {},
            .executed => return error.CanonicalEmptyProgramMismatch,
        }
        try requireAirProgramId(self.statement_id);
        try requireAirProgramId(self.publication_id);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != CANONICAL_EMPTY_PROGRAM_SCHEMA_VERSION or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(
                u8,
                &self.binary_layout_identity,
                &binary_layout.identity,
            ) or
            !std.mem.eql(u8, &self.empty_layout_identity, &empty_layout.identity) or
            allZero(&self.parameter_authority_identity) or
            !std.mem.eql(u8, &self.identity, &canonicalEmptyProgramIdentity(&self)) or
            !std.meta.eql(
                self.air_program_id,
                canonicalEmptyAirProgramId(&self.identity),
            ))
        {
            return error.CanonicalEmptyProgramMismatch;
        }
    }
};

pub fn proofKindIndex(kind: ProofKind) usize {
    return switch (kind) {
        .segment_leaf => 0,
        .binary_node => 1,
        .empty_leaf => 2,
    };
}

pub fn proofKindCode(kind: ProofKind) u8 {
    return @intCast(proofKindIndex(kind));
}

/// The selected kind describes the verified child.  Its selectors are active
/// only while the enclosing parent is a binary recursion node; a non-binary
/// parent therefore exposes the canonical all-zero selector vector.
pub fn activeProofKindSelectors(
    parent_binary_selector: bool,
    child_kind: ProofKind,
) [PROGRAM_KIND_COUNT]M31 {
    var result = [_]M31{M31.zero()} ** PROGRAM_KIND_COUNT;
    if (parent_binary_selector)
        result[proofKindIndex(child_kind)] = M31.one();
    return result;
}

pub fn canonicalEmptyProgramIdentity(value: *const CanonicalEmptyProgramV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CANONICAL_EMPTY_PROGRAM_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.manifest_seal);
    hash.update(&value.binary_layout_identity);
    hash.update(&value.empty_layout_identity);
    hash.update(&value.parameter_authority_identity);
    for (value.statement_words) |word| hashInt(&hash, u32, word.toU32());
    for (value.statement_id) |word| hashInt(&hash, u32, word);
    for (value.publication_id) |word| hashInt(&hash, u32, word);
    return hash.finalResult();
}
