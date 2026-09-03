//! Internal shard of recursion_air_composition_circuit_v3.zig; use the public facade.

const dependency_0 = @import("recursion_air_composition_circuit_v3_canonical_empty_program_v3.zig");
const dependency_2 = @import("recursion_air_composition_circuit_v3_circuit_view_v3.zig");
const dependency_4 = @import("recursion_air_composition_circuit_v3_write_inputs_from_validated_profile_and_policy.zig");
const dependency_5 = @import("recursion_air_composition_circuit_v3_authority_validation.zig");

const std = dependency_0.std;
const Sha256 = dependency_0.Sha256;
const graph_mod = dependency_0.graph_mod;
const recorder = dependency_0.recorder;
const segment_manifest_mod = dependency_0.segment_manifest_mod;
const universal_manifest_mod = dependency_0.universal_manifest_mod;
const universal = dependency_0.universal;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const SCHEMA_VERSION = dependency_0.SCHEMA_VERSION;
const PROGRAM_DESCRIPTOR_DOMAIN = dependency_0.PROGRAM_DESCRIPTOR_DOMAIN;
const PROGRAM_ROSTER_DOMAIN = dependency_0.PROGRAM_ROSTER_DOMAIN;
const CONFIGURATION_DOMAIN = dependency_0.CONFIGURATION_DOMAIN;
const ProofKind = dependency_0.ProofKind;
const AirProgramId = dependency_0.AirProgramId;
const SEGMENT_PHYSICAL_CLAIM_COUNT = dependency_0.SEGMENT_PHYSICAL_CLAIM_COUNT;
const COMPOSITION_CLAIM_INPUT_COUNT = dependency_0.COMPOSITION_CLAIM_INPUT_COUNT;
const RELATION_CHALLENGE_COUNT = dependency_0.RELATION_CHALLENGE_COUNT;
const PROGRAM_KIND_COUNT = dependency_0.PROGRAM_KIND_COUNT;
const Error = dependency_0.Error;
const ManifestFamilyV3 = dependency_0.ManifestFamilyV3;
const ClaimPolicyV3 = dependency_0.ClaimPolicyV3;
const TrustedManifestsV3 = dependency_0.TrustedManifestsV3;
const AirProgramIdsV3 = dependency_0.AirProgramIdsV3;
const CanonicalEmptyProgramV3 = dependency_0.CanonicalEmptyProgramV3;
const proofKindIndex = dependency_0.proofKindIndex;
const proofKindCode = dependency_0.proofKindCode;
const CircuitAuthorityStorageV3 = dependency_2.CircuitAuthorityStorageV3;
const descriptorShape = dependency_4.descriptorShape;
const descriptorShapeForManifest = dependency_4.descriptorShapeForManifest;
const h1DescriptorShape = dependency_4.h1DescriptorShape;
const canonicalEmptyDescriptorShape = dependency_4.canonicalEmptyDescriptorShape;
const validateManifests = dependency_4.validateManifests;
const segmentOrderedProgramIdentity = dependency_5.segmentOrderedProgramIdentity;
const universalOrderedProgramIdentity = dependency_5.universalOrderedProgramIdentity;
const hashManifestRows = dependency_5.hashManifestRows;
const canonicalEmptyAirProgramId = dependency_5.canonicalEmptyAirProgramId;
const requireAirProgramId = dependency_5.requireAirProgramId;
const hashInt = dependency_5.hashInt;
const allZero = dependency_5.allZero;

/// Pointer-free description of the exact ordered component program selected
/// by one proof kind.  `source_claim_count` is distinct from
/// `program_roster_count`: the empty program still has constrained rows, but
/// its entire externally supplied claim vector is canonical zero.
pub const ProgramDescriptorV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    proof_kind: ProofKind,
    manifest_family: ManifestFamilyV3,
    claim_policy: ClaimPolicyV3,
    source_claim_count: u8,
    program_roster_count: u8,
    poseidon_partial_count: u8,
    composition_claim_count: u8,
    poseidon_roster_row: u8,
    manifest_format_version: u16,
    manifest_seal: [32]u8,
    catalog_identity: [32]u8,
    air_program_id: AirProgramId,
    ordered_program_identity: [32]u8,
    identity: [32]u8,

    /// Seals the exact SegmentV2 descriptor without inventing placeholder
    /// binary/empty program identities. This is the leaf-only admission seam;
    /// a heterogeneous parent still requires `ProgramRosterV3.seal` so all
    /// three ordered programs share one authenticated roster.
    pub fn sealSegment(
        manifest: *const segment_manifest_mod.Manifest,
        air_program_id: AirProgramId,
    ) Error!ProgramDescriptorV3 {
        try manifest.validate();
        try requireAirProgramId(air_program_id);
        if (manifest.roster_count != SEGMENT_PHYSICAL_CLAIM_COUNT)
            return error.ManifestAuthorityMismatch;
        const result = descriptorForSegment(manifest, air_program_id);
        try result.validate();
        return result;
    }

    /// Mints the pointer-free binary descriptor for the authenticated
    /// 12-placement full-Ethereum H1 manifest. The manifest is validated and
    /// replayed here; a self-hashed descriptor is never promoted on its own.
    pub fn sealAuthenticatedH1(
        manifest: anytype,
        air_program_id: AirProgramId,
    ) Error!ProgramDescriptorV3 {
        const result = try descriptorForAuthenticatedH1(
            manifest,
            air_program_id,
        );
        try result.validate();
        return result;
    }

    pub fn validate(self: ProgramDescriptorV3) Error!void {
        try requireAirProgramId(self.air_program_id);
        const provider_empty = self.proof_kind == .empty_leaf and
            self.claim_policy == .canonical_empty_provider;
        const expected = if (provider_empty)
            canonicalEmptyDescriptorShape()
        else
            descriptorShapeForManifest(
                self.proof_kind,
                self.manifest_family,
            );
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.manifest_family != expected.manifest_family or
            self.claim_policy != expected.claim_policy or
            self.source_claim_count != expected.source_claim_count or
            self.program_roster_count != expected.program_roster_count or
            self.poseidon_partial_count != expected.poseidon_partial_count or
            self.composition_claim_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.poseidon_roster_row != expected.poseidon_roster_row or
            allZero(&self.manifest_seal) or
            allZero(&self.ordered_program_identity) or
            !std.mem.eql(u8, &self.identity, &programDescriptorIdentity(self)))
        {
            return error.InvalidProgramRoster;
        }
        if (self.manifest_family == .segment_v2 or provider_empty) {
            if (allZero(&self.catalog_identity))
                return error.InvalidProgramRoster;
        } else if (!allZero(&self.catalog_identity)) {
            return error.InvalidProgramRoster;
        }
        if (provider_empty and !std.meta.eql(
            self.air_program_id,
            canonicalEmptyAirProgramId(&self.catalog_identity),
        )) return error.InvalidProgramRoster;
    }
};

pub const ProgramRosterV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    programs: [PROGRAM_KIND_COUNT]ProgramDescriptorV3,
    identity: [32]u8,

    pub fn seal(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) Error!ProgramRosterV3 {
        try validateManifests(manifests);
        try air_program_ids.validate();
        var result = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                descriptorForUniversal(
                    .binary_node,
                    manifests.universal,
                    air_program_ids.binary_node,
                ),
                descriptorForUniversal(
                    .empty_leaf,
                    manifests.universal,
                    air_program_ids.empty_leaf,
                ),
            },
            .identity = undefined,
        };
        result.identity = programRosterIdentity(result);
        try result.validateAgainst(manifests, air_program_ids);
        return result;
    }

    pub fn sealWithCanonicalEmpty(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        empty_program: CanonicalEmptyProgramV3,
    ) Error!ProgramRosterV3 {
        try validateManifests(manifests);
        try air_program_ids.validate();
        if (!std.meta.eql(
            air_program_ids.empty_leaf,
            empty_program.air_program_id,
        )) return error.CanonicalEmptyProgramMismatch;
        var result = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                descriptorForUniversal(
                    .binary_node,
                    manifests.universal,
                    air_program_ids.binary_node,
                ),
                descriptorForCanonicalEmpty(
                    manifests.universal,
                    air_program_ids.empty_leaf,
                    empty_program.identity,
                ),
            },
            .identity = undefined,
        };
        result.identity = programRosterIdentity(result);
        try result.validateAgainst(manifests, air_program_ids);
        return result;
    }

    /// Replaces only the binary program in the fixed three-selector roster
    /// with a descriptor minted from the authenticated ordinary H1 manifest.
    /// Segment and Empty remain byte-identical to the legacy configuration.
    pub fn sealWithAuthenticatedH1(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) Error!ProgramRosterV3 {
        try validateManifests(manifests);
        try air_program_ids.validate();
        const binary = try ProgramDescriptorV3.sealAuthenticatedH1(
            h1_manifest,
            air_program_ids.binary_node,
        );
        var result = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                binary,
                descriptorForUniversal(
                    .empty_leaf,
                    manifests.universal,
                    air_program_ids.empty_leaf,
                ),
            },
            .identity = undefined,
        };
        result.identity = programRosterIdentity(result);
        try result.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        return result;
    }

    /// Combines the authenticated ordinary-H1 Binary descriptor with the
    /// existing proofless canonical-Empty descriptor. The selector roster is
    /// still exactly Segment/Binary/Empty; only the two already-versioned
    /// descriptor policies are selected together.
    pub fn sealWithAuthenticatedH1AndCanonicalEmpty(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
        empty_program: CanonicalEmptyProgramV3,
    ) Error!ProgramRosterV3 {
        try validateManifests(manifests);
        try air_program_ids.validate();
        if (!std.meta.eql(
            air_program_ids.empty_leaf,
            empty_program.air_program_id,
        )) return error.CanonicalEmptyProgramMismatch;
        var result = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                try ProgramDescriptorV3.sealAuthenticatedH1(
                    h1_manifest,
                    air_program_ids.binary_node,
                ),
                descriptorForCanonicalEmpty(
                    manifests.universal,
                    air_program_ids.empty_leaf,
                    empty_program.identity,
                ),
            },
            .identity = undefined,
        };
        result.identity = programRosterIdentity(result);
        try result.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        return result;
    }

    pub fn validateAgainst(
        self: ProgramRosterV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) Error!void {
        try validateManifests(manifests);
        try air_program_ids.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(u8, &self.identity, &programRosterIdentity(self)))
        {
            return error.InvalidProgramRoster;
        }
        const actual_empty = self.programs[proofKindIndex(.empty_leaf)];
        const expected_empty = if (actual_empty.claim_policy == .canonical_empty_provider) descriptorForCanonicalEmpty(
            manifests.universal,
            air_program_ids.empty_leaf,
            actual_empty.catalog_identity,
        ) else descriptorForUniversal(
            .empty_leaf,
            manifests.universal,
            air_program_ids.empty_leaf,
        );
        const expected = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                descriptorForUniversal(
                    .binary_node,
                    manifests.universal,
                    air_program_ids.binary_node,
                ),
                expected_empty,
            },
            .identity = self.identity,
        };
        for (self.programs, expected.programs, 0..) |actual, wanted, index| {
            try actual.validate();
            if (proofKindIndex(actual.proof_kind) != index or
                !std.meta.eql(actual, wanted))
            {
                return error.ManifestAuthorityMismatch;
            }
        }
    }

    /// Cold re-admission for an H1 binary roster. This rebuilds the expected
    /// descriptor from the reopened manifest instead of trusting the retained
    /// descriptor identity.
    pub fn validateAgainstAuthenticatedH1(
        self: ProgramRosterV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) Error!void {
        try validateManifests(manifests);
        try air_program_ids.validate();
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(u8, &self.identity, &programRosterIdentity(self)))
        {
            return error.InvalidProgramRoster;
        }
        const actual_empty = self.programs[proofKindIndex(.empty_leaf)];
        const expected_empty = if (actual_empty.claim_policy ==
            .canonical_empty_provider)
            descriptorForCanonicalEmpty(
                manifests.universal,
                air_program_ids.empty_leaf,
                actual_empty.catalog_identity,
            )
        else
            descriptorForUniversal(
                .empty_leaf,
                manifests.universal,
                air_program_ids.empty_leaf,
            );
        const expected = ProgramRosterV3{
            .programs = .{
                descriptorForSegment(manifests.segment, air_program_ids.segment_leaf),
                try ProgramDescriptorV3.sealAuthenticatedH1(
                    h1_manifest,
                    air_program_ids.binary_node,
                ),
                expected_empty,
            },
            .identity = self.identity,
        };
        for (self.programs, expected.programs, 0..) |actual, wanted, index| {
            try actual.validate();
            if (proofKindIndex(actual.proof_kind) != index or
                !std.meta.eql(actual, wanted))
            {
                return error.ManifestAuthorityMismatch;
            }
        }
    }

    pub fn forKind(
        self: *const ProgramRosterV3,
        kind: ProofKind,
    ) *const ProgramDescriptorV3 {
        return &self.programs[proofKindIndex(kind)];
    }
};

/// Hash-free hot-path projection of a previously authenticated V3
/// configuration.  Geometry validation is constant time and never replays a
/// manifest or roster hash.
pub const InputProfileV3 = struct {
    sampled_value_count: u32,
    claimed_sum_count: u32 = COMPOSITION_CLAIM_INPUT_COUNT,
    relation_challenge_count: u32 = RELATION_CHALLENGE_COUNT,
    public_wire_boundary_count: u32 = 1,

    pub fn validate(self: InputProfileV3) Error!void {
        if (self.claimed_sum_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.relation_challenge_count != RELATION_CHALLENGE_COUNT or
            self.public_wire_boundary_count != 1)
        {
            return error.InvalidClaimInputProfile;
        }
        _ = graph_mod.recursionInputCount(self.graphProfile()) catch
            return error.InvalidClaimInputProfile;
    }

    pub fn graphProfile(self: InputProfileV3) graph_mod.InputProfile {
        return .{
            .sampled_value_count = self.sampled_value_count,
            .claimed_sum_count = self.claimed_sum_count,
            .relation_challenge_count = self.relation_challenge_count,
            .public_wire_boundary_count = self.public_wire_boundary_count,
        };
    }
};

/// Complete pointer-free V3 input and program authority.  The fixed graph
/// input count is derived from the same `InputProfile` compiler used by V2;
/// only the claimed-sum dimension changes from 38 to 41.
pub const ConfigurationV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    sampled_value_count: u32,
    claimed_sum_count: u32 = COMPOSITION_CLAIM_INPUT_COUNT,
    relation_challenge_count: u32 = RELATION_CHALLENGE_COUNT,
    public_wire_boundary_count: u32 = 1,
    program_roster: ProgramRosterV3,
    identity: [32]u8,

    pub fn seal(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        sampled_value_count: u32,
    ) Error!ConfigurationV3 {
        const roster = try ProgramRosterV3.seal(manifests, air_program_ids);
        var result = ConfigurationV3{
            .sampled_value_count = sampled_value_count,
            .program_roster = roster,
            .identity = undefined,
        };
        _ = graph_mod.recursionInputCount(result.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        result.identity = configurationIdentity(result);
        try result.validateAgainst(manifests, air_program_ids);
        return result;
    }

    pub fn sealWithCanonicalEmpty(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        sampled_value_count: u32,
        empty_program: CanonicalEmptyProgramV3,
    ) Error!ConfigurationV3 {
        const roster = try ProgramRosterV3.sealWithCanonicalEmpty(
            manifests,
            air_program_ids,
            empty_program,
        );
        var result = ConfigurationV3{
            .sampled_value_count = sampled_value_count,
            .program_roster = roster,
            .identity = undefined,
        };
        _ = graph_mod.recursionInputCount(result.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        result.identity = configurationIdentity(result);
        try result.validateAgainst(manifests, air_program_ids);
        return result;
    }

    /// Pointer-free configuration admission for the ordinary 12-placement H1
    /// binary program. The legacy Segment/Empty descriptors and all scalar
    /// profile fields retain their existing encoding.
    pub fn sealWithAuthenticatedH1(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        sampled_value_count: u32,
        h1_manifest: anytype,
    ) Error!ConfigurationV3 {
        const roster = try ProgramRosterV3.sealWithAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        var result = ConfigurationV3{
            .sampled_value_count = sampled_value_count,
            .program_roster = roster,
            .identity = undefined,
        };
        _ = graph_mod.recursionInputCount(result.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        result.identity = configurationIdentity(result);
        try result.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        return result;
    }

    /// One pointer-free configuration for SegmentV2, ordinary H1, and the
    /// proofless canonical Empty program. Legacy constructors and their
    /// encodings are unchanged.
    pub fn sealWithAuthenticatedH1AndCanonicalEmpty(
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        sampled_value_count: u32,
        h1_manifest: anytype,
        empty_program: CanonicalEmptyProgramV3,
    ) Error!ConfigurationV3 {
        const roster = try ProgramRosterV3
            .sealWithAuthenticatedH1AndCanonicalEmpty(
            manifests,
            air_program_ids,
            h1_manifest,
            empty_program,
        );
        var result = ConfigurationV3{
            .sampled_value_count = sampled_value_count,
            .program_roster = roster,
            .identity = undefined,
        };
        _ = graph_mod.recursionInputCount(result.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        result.identity = configurationIdentity(result);
        try result.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        return result;
    }

    pub fn validateAgainst(
        self: ConfigurationV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.claimed_sum_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.relation_challenge_count != RELATION_CHALLENGE_COUNT or
            self.public_wire_boundary_count != 1)
        {
            return error.InvalidClaimInputProfile;
        }
        try self.program_roster.validateAgainst(manifests, air_program_ids);
        _ = graph_mod.recursionInputCount(self.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        if (!std.mem.eql(u8, &self.identity, &configurationIdentity(self)))
            return error.ConfigurationIdentityMismatch;
    }

    pub fn validateAgainstAuthenticatedH1(
        self: ConfigurationV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        h1_manifest: anytype,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.claimed_sum_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.relation_challenge_count != RELATION_CHALLENGE_COUNT or
            self.public_wire_boundary_count != 1)
        {
            return error.InvalidClaimInputProfile;
        }
        try self.program_roster.validateAgainstAuthenticatedH1(
            manifests,
            air_program_ids,
            h1_manifest,
        );
        _ = graph_mod.recursionInputCount(self.graphInputProfile()) catch
            return error.InvalidClaimInputProfile;
        if (!std.mem.eql(u8, &self.identity, &configurationIdentity(self)))
            return error.ConfigurationIdentityMismatch;
    }

    /// Checks pointer-free encoding consistency only.  It does not establish
    /// agreement with trusted manifests or AIR program IDs; authority callers
    /// must use `validateAgainst`.
    pub fn validateSelfConsistency(self: ConfigurationV3) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.claimed_sum_count != COMPOSITION_CLAIM_INPUT_COUNT or
            self.relation_challenge_count != RELATION_CHALLENGE_COUNT or
            self.public_wire_boundary_count != 1 or
            !std.mem.eql(u8, &self.identity, &configurationIdentity(self)))
        {
            return error.ConfigurationIdentityMismatch;
        }
        for (self.program_roster.programs) |program| try program.validate();
        if (!std.mem.eql(
            u8,
            &self.program_roster.identity,
            &programRosterIdentity(self.program_roster),
        )) return error.ConfigurationIdentityMismatch;
    }

    pub fn graphInputProfile(self: ConfigurationV3) graph_mod.InputProfile {
        return self.inputProfile().graphProfile();
    }

    pub fn inputProfile(self: ConfigurationV3) InputProfileV3 {
        return .{
            .sampled_value_count = self.sampled_value_count,
            .claimed_sum_count = self.claimed_sum_count,
            .relation_challenge_count = self.relation_challenge_count,
            .public_wire_boundary_count = self.public_wire_boundary_count,
        };
    }

    pub fn requireLegacyV2Projection(self: ConfigurationV3) Error!void {
        try self.validateSelfConsistency();
        return error.LegacyV2ProjectionForbidden;
    }
};

/// Opaque capability minted by the heterogeneous recorder.  Callers cannot
/// construct its representation or a detached self-hashed graph authority.
pub const CircuitAuthorityV3 = opaque {
    pub fn validateAgainst(
        self: *const CircuitAuthorityV3,
        configuration: ConfigurationV3,
        manifests: TrustedManifestsV3,
        air_program_ids: AirProgramIdsV3,
        graph: graph_mod.CircuitGraph,
        bindings: []const graph_mod.RecursionInputBinding,
    ) Error!void {
        try configuration.validateAgainst(manifests, air_program_ids);
        try authorityStorage(self).validateAgainstValidatedConfiguration(
            configuration,
            graph,
            bindings,
        );
    }

    pub fn identity(self: *const CircuitAuthorityV3) [32]u8 {
        return authorityStorage(self).identity;
    }
};

pub fn descriptorForSegment(
    manifest: *const segment_manifest_mod.Manifest,
    air_program_id: AirProgramId,
) ProgramDescriptorV3 {
    var result = baseDescriptor(.segment_leaf, air_program_id);
    result.manifest_format_version = manifest.format_version;
    // Segment source manifests bind statement-specific authority and differ
    // across honest adjacent leaves. The recorder program binds only their
    // independently checked common AIR geometry.
    result.manifest_seal =
        segment_manifest_mod.programGeometryShaId(manifest);
    result.catalog_identity = manifest.catalog_identity;
    result.ordered_program_identity = segmentOrderedProgramIdentity(manifest);
    result.identity = programDescriptorIdentity(result);
    return result;
}

pub fn descriptorForUniversal(
    kind: ProofKind,
    manifest: *const universal_manifest_mod.Manifest,
    air_program_id: AirProgramId,
) ProgramDescriptorV3 {
    std.debug.assert(kind != .segment_leaf);
    var result = baseDescriptor(kind, air_program_id);
    result.manifest_format_version = manifest.format_version;
    result.manifest_seal = manifest.seal;
    result.catalog_identity = [_]u8{0} ** 32;
    result.ordered_program_identity = universalOrderedProgramIdentity(manifest);
    result.identity = programDescriptorIdentity(result);
    return result;
}

pub fn descriptorForCanonicalEmpty(
    manifest: *const universal_manifest_mod.Manifest,
    air_program_id: AirProgramId,
    empty_program_identity: [32]u8,
) ProgramDescriptorV3 {
    var result = baseDescriptor(.empty_leaf, air_program_id);
    const shape = canonicalEmptyDescriptorShape();
    result.claim_policy = shape.claim_policy;
    result.source_claim_count = shape.source_claim_count;
    result.poseidon_partial_count = shape.poseidon_partial_count;
    result.manifest_format_version = manifest.format_version;
    result.manifest_seal = manifest.seal;
    result.catalog_identity = empty_program_identity;
    result.ordered_program_identity = universalOrderedProgramIdentity(manifest);
    result.identity = programDescriptorIdentity(result);
    return result;
}

/// Reconstructs the H1 descriptor from an authenticated, reopened manifest.
/// The generic manifest parameter keeps this frontend module dependency-free;
/// exact 0..11 roster ordering and the provider row are checked in addition to
/// the manifest's own validation contract.
pub fn descriptorForAuthenticatedH1(
    manifest: anytype,
    air_program_id: AirProgramId,
) Error!ProgramDescriptorV3 {
    manifest.validate() catch return error.ManifestAuthorityMismatch;
    try requireAirProgramId(air_program_id);
    const shape = h1DescriptorShape();
    if (manifest.format_version == 0 or
        manifest.roster_count != shape.program_roster_count or
        allZero(&manifest.seal))
    {
        return error.ManifestAuthorityMismatch;
    }
    for (manifest.roster_rows[0..manifest.roster_count], 0..) |row, ordinal| {
        if (row != @as(u8, @intCast(ordinal)))
            return error.ManifestAuthorityMismatch;
    }
    if (manifest.roster_rows[@as(usize, shape.poseidon_roster_row)] !=
        shape.poseidon_roster_row)
    {
        return error.ManifestAuthorityMismatch;
    }
    var result = baseDescriptorForShape(
        .binary_node,
        shape,
        air_program_id,
    );
    result.manifest_format_version = manifest.format_version;
    result.manifest_seal = manifest.seal;
    result.catalog_identity = [_]u8{0} ** 32;
    result.ordered_program_identity = authenticatedH1OrderedProgramIdentity(
        manifest,
    );
    result.identity = programDescriptorIdentity(result);
    return result;
}

pub fn baseDescriptor(
    kind: ProofKind,
    air_program_id: AirProgramId,
) ProgramDescriptorV3 {
    return baseDescriptorForShape(kind, descriptorShape(kind), air_program_id);
}

fn baseDescriptorForShape(
    kind: ProofKind,
    shape: dependency_4.DescriptorShape,
    air_program_id: AirProgramId,
) ProgramDescriptorV3 {
    return .{
        .proof_kind = kind,
        .manifest_family = shape.manifest_family,
        .claim_policy = shape.claim_policy,
        .source_claim_count = shape.source_claim_count,
        .program_roster_count = shape.program_roster_count,
        .poseidon_partial_count = shape.poseidon_partial_count,
        .composition_claim_count = COMPOSITION_CLAIM_INPUT_COUNT,
        .poseidon_roster_row = shape.poseidon_roster_row,
        .manifest_format_version = 0,
        .manifest_seal = undefined,
        .catalog_identity = undefined,
        .air_program_id = air_program_id,
        .ordered_program_identity = undefined,
        .identity = undefined,
    };
}

fn authenticatedH1OrderedProgramIdentity(manifest: anytype) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(dependency_0.ORDERED_PROGRAM_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(
        &hash,
        u8,
        @intFromEnum(ManifestFamilyV3.ethereum_poseidon_h1_v1),
    );
    hash.update(&manifest.seal);
    hashManifestRows(&hash, manifest);
    return hash.finalResult();
}

pub fn programDescriptorIdentity(value: ProgramDescriptorV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PROGRAM_DESCRIPTOR_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, proofKindCode(value.proof_kind));
    hashInt(&hash, u8, @intFromEnum(value.manifest_family));
    hashInt(&hash, u8, @intFromEnum(value.claim_policy));
    hashInt(&hash, u8, value.source_claim_count);
    hashInt(&hash, u8, value.program_roster_count);
    hashInt(&hash, u8, value.poseidon_partial_count);
    hashInt(&hash, u8, value.composition_claim_count);
    hashInt(&hash, u8, value.poseidon_roster_row);
    hashInt(&hash, u16, value.manifest_format_version);
    hash.update(&value.manifest_seal);
    hash.update(&value.catalog_identity);
    for (value.air_program_id) |word| hashInt(&hash, u32, word);
    hash.update(&value.ordered_program_identity);
    return hash.finalResult();
}

pub fn programRosterIdentity(value: ProgramRosterV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PROGRAM_ROSTER_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, PROGRAM_KIND_COUNT);
    for (value.programs) |program| hash.update(&program.identity);
    return hash.finalResult();
}

pub fn configurationIdentity(value: ConfigurationV3) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(CONFIGURATION_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.sampled_value_count);
    hashInt(&hash, u32, value.claimed_sum_count);
    hashInt(&hash, u32, value.relation_challenge_count);
    hashInt(&hash, u32, value.public_wire_boundary_count);
    hash.update(&value.program_roster.identity);
    return hash.finalResult();
}

pub fn authorityStorage(
    authority: *const CircuitAuthorityV3,
) *const CircuitAuthorityStorageV3 {
    return @ptrCast(@alignCast(authority));
}
