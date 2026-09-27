//! Source-side admission around the pure SegmentV2 manifest contract.
const pure = @import("segment_outer_manifest_contract_v2.zig");
pub const std = pure.std;
pub const stwo_core = pure.stwo_core;
pub const core_components = pure.core_components;
pub const QM31 = pure.QM31;
pub const digest = pure.digest;
pub const relation = pure.relation;
pub const universal_manifest = pure.universal_manifest;
pub const universal_roster = pure.universal_roster;
pub const typed_catalog_v2 = pure.typed_catalog_v2;
pub const FORMAT_VERSION = pure.FORMAT_VERSION;
pub const TRANSCRIPT_FORMAT_VERSION = pure.TRANSCRIPT_FORMAT_VERSION;
pub const TRANSCRIPT_DOMAIN = pure.TRANSCRIPT_DOMAIN;
pub const DOMAIN = pure.DOMAIN;
pub const CLAIM_DOMAIN = pure.CLAIM_DOMAIN;
pub const PROGRAM_GEOMETRY_DOMAIN = pure.PROGRAM_GEOMETRY_DOMAIN;
pub const TREE_COUNT = pure.TREE_COUNT;
pub const PREPROCESSED_TREE_INDEX = pure.PREPROCESSED_TREE_INDEX;
pub const MAIN_TREE_INDEX = pure.MAIN_TREE_INDEX;
pub const INTERACTION_TREE_INDEX = pure.INTERACTION_TREE_INDEX;
pub const UNIVERSAL_COMPONENT_COUNT = pure.UNIVERSAL_COMPONENT_COUNT;
pub const SOURCE_COMPONENT_COUNT = pure.SOURCE_COMPONENT_COUNT;
pub const PROVIDER_COMPONENT_COUNT = pure.PROVIDER_COMPONENT_COUNT;
pub const COMPONENT_COUNT = pure.COMPONENT_COUNT;
pub const STATEMENT_SOURCE_INDEX = pure.STATEMENT_SOURCE_INDEX;
pub const PUBLIC_LOGUP_SOURCE_INDEX = pure.PUBLIC_LOGUP_SOURCE_INDEX;
pub const VERIFIER_INPUT_PROVIDER_INDEX = pure.VERIFIER_INPUT_PROVIDER_INDEX;
pub const Error = pure.Error;
pub const ComponentKey = pure.ComponentKey;
pub const keyIndex = pure.keyIndex;
pub const fromUniversal = pure.fromUniversal;
pub const Geometry = pure.Geometry;
pub const Placement = pure.Placement;
pub const TypedCatalogV2 = pure.TypedCatalogV2;
pub const V2_AUTHORITY_CHANGED_MASK = pure.V2_AUTHORITY_CHANGED_MASK;
pub const V1_AUTHORITY_UNCHANGED_MASK = pure.V1_AUTHORITY_UNCHANGED_MASK;
pub const APPENDED_SOURCE_MASK = pure.APPENDED_SOURCE_MASK;
pub const APPENDED_PROVIDER_MASK = pure.APPENDED_PROVIDER_MASK;
pub const AuthorityIds = pure.AuthorityIds;
pub const Manifest = pure.Manifest;
pub const Assembler = pure.Assembler;
pub const validateBoundaryGeometry = pure.validateBoundaryGeometry;
pub const emptyManifest = pure.emptyManifest;
pub const manifestDigest = pure.manifestDigest;
pub const hashGeometry = pure.hashGeometry;
pub const hashQm31 = pure.hashQm31;
pub const hashInt = pure.hashInt;
pub const digestWords = pure.digestWords;
pub const checkedAdd = pure.checkedAdd;
pub const componentBit = pure.componentBit;
pub const requireNativeDigest = pure.requireNativeDigest;
pub const allZero = pure.allZero;
pub const base = @import("universal_adapter_manifest.zig");
pub const boundary_v2 = @import("../segment_leaf_outer_authority_v2.zig");
pub const provider_authority_v2 =
    @import("../segment_publication_input_provider_authority_v2.zig");
pub const prover_component = @import("stwo_prover_engine").air.component_prover;
pub const transcript_v2 = @import("../segment_transcript_outer_source_v2.zig");
pub const statement_v2 = @import("../segment_statement_outer_source_v2.zig");
pub const public_v2 = @import("../segment_public_outer_source_v2.zig");
pub const AdapterBinding = base.AdapterBinding;

pub fn validateAgainstSources(
    self: *const Manifest,
    transcript: *const transcript_v2.ManifestV2,
    statement: *const statement_v2.ManifestV2,
    public: *const public_v2.ManifestV2,
    boundary: *const boundary_v2.OuterManifestV2,
) Error!void {
    try self.validate();
    transcript.validate() catch return error.SourceManifestMismatch;
    statement.validate() catch return error.SourceManifestMismatch;
    public.validate() catch return error.SourceManifestMismatch;
    boundary.validate() catch return error.SourceManifestMismatch;
    if (!std.meta.eql(self.transcript_manifest_id, transcript.identity) or
        !std.meta.eql(self.statement_manifest_id, statement.identity) or
        !std.meta.eql(self.public_manifest_id, public.identity) or
        !std.meta.eql(self.boundary_manifest_id, boundary.identity) or
        !std.mem.eql(
            u8,
            &self.boundary_authority_sha_id,
            &boundary.authority_sha_id,
        ))
    {
        return error.SourceManifestMismatch;
    }
    for (transcript.log_sizes, 0..) |log_size, row| {
        const placement_value = self.placements[row] orelse
            return error.SourceManifestMismatch;
        if (placement_value.geometry.log_size != log_size)
            return error.SourceManifestMismatch;
    }
    if (self.placements[10].?.geometry.log_size !=
        typed_catalog_v2.INACTIVE_STATEMENT_LOG_SIZE or
        self.placements[11].?.geometry.log_size != statement.trace_log_size)
    {
        return error.SourceManifestMismatch;
    }
    for (public.log_sizes, 0..) |log_size, index| {
        if (self.placements[12 + index].?.geometry.log_size != log_size)
            return error.SourceManifestMismatch;
    }
    try validateBoundaryGeometry(
        self.placements[STATEMENT_SOURCE_INDEX].?.geometry,
        boundary.components[0],
    );
    try validateBoundaryGeometry(
        self.placements[PUBLIC_LOGUP_SOURCE_INDEX].?.geometry,
        boundary.components[1],
    );
    if (!std.mem.eql(
        u8,
        &self.provider_authority_sha_id,
        &provider_authority_v2.sourceAuthorityShaId(),
    ) or self.placements[VERIFIER_INPUT_PROVIDER_INDEX].?.geometry
        .roster_row != VERIFIER_INPUT_PROVIDER_INDEX)
    {
        return error.SourceManifestMismatch;
    }
}
