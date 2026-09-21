//! Internal segment outer adapter manifest v2 authority shard; use segment_outer_adapter_manifest_v2.zig publicly.

const dependency_0 = @import("segment_outer_adapter_manifest_v2_contract.zig");

const AdapterBinding = dependency_0.AdapterBinding;
const Assembler = dependency_0.Assembler;
const AuthorityIds = dependency_0.AuthorityIds;
const CLAIM_DOMAIN = dependency_0.CLAIM_DOMAIN;
const COMPONENT_COUNT = dependency_0.COMPONENT_COUNT;
const ComponentKey = dependency_0.ComponentKey;
const Error = dependency_0.Error;
const Manifest = dependency_0.Manifest;
const PROGRAM_GEOMETRY_DOMAIN = dependency_0.PROGRAM_GEOMETRY_DOMAIN;
const PUBLIC_LOGUP_SOURCE_INDEX = dependency_0.PUBLIC_LOGUP_SOURCE_INDEX;
const QM31 = dependency_0.QM31;
const STATEMENT_SOURCE_INDEX = dependency_0.STATEMENT_SOURCE_INDEX;
const TREE_COUNT = dependency_0.TREE_COUNT;
const TypedCatalogV2 = dependency_0.TypedCatalogV2;
const VERIFIER_INPUT_PROVIDER_INDEX = dependency_0.VERIFIER_INPUT_PROVIDER_INDEX;
const boundary_v2 = dependency_0.boundary_v2;
const componentBit = dependency_0.componentBit;
const core_components = dependency_0.core_components;
const digest = dependency_0.digest;
const digestWords = dependency_0.digestWords;
const hashGeometry = dependency_0.hashGeometry;
const hashInt = dependency_0.hashInt;
const hashQm31 = dependency_0.hashQm31;
const keyIndex = dependency_0.keyIndex;
const prover_component = dependency_0.prover_component;
const provider_authority_v2 = dependency_0.provider_authority_v2;
const public_v2 = dependency_0.public_v2;
const statement_v2 = dependency_0.statement_v2;
const std = dependency_0.std;
const transcript_v2 = dependency_0.transcript_v2;
const typed_catalog_v2 = dependency_0.typed_catalog_v2;
const universal_manifest = dependency_0.universal_manifest;

pub const ClaimVector = @import("segment_outer_manifest_contract_v2.zig").ClaimVector;

pub const ProofGate = struct {
    manifest_seal: digest.Digest,
    roster_rows: [COMPONENT_COUNT]u8,
    verifier_components: [COMPONENT_COUNT]core_components.Component,
    prover_components: [COMPONENT_COUNT]prover_component.ComponentProver,
    claims: ClaimVector,
    count: u8,
    sealed: bool,

    pub fn init(manifest: *const Manifest) Error!ProofGate {
        try manifest.validate();
        return .{
            .manifest_seal = manifest.seal,
            .roster_rows = [_]u8{0} ** COMPONENT_COUNT,
            .verifier_components = undefined,
            .prover_components = undefined,
            .claims = try ClaimVector.init(manifest),
            .count = 0,
            .sealed = false,
        };
    }

    pub fn append(
        self: *ProofGate,
        manifest: *const Manifest,
        binding: AdapterBinding,
    ) Error!void {
        if (self.sealed)
            return error.AdapterCountMismatch;
        try manifest.validate();
        if (!std.mem.eql(u8, &self.manifest_seal, &manifest.seal) or
            !std.mem.eql(u8, &binding.manifest_seal, &manifest.seal))
        {
            return error.ManifestSealMismatch;
        }
        if (self.count >= manifest.roster_count)
            return error.AdapterCountMismatch;
        const expected_row = manifest.roster_rows[self.count];
        if (binding.placement.geometry.roster_row != expected_row)
            return error.AdapterOrderMismatch;
        const expected = manifest.placements[expected_row].?;
        if (!binding.placement.eql(expected) or
            binding.verifier.nConstraints() !=
                @as(usize, expected.geometry.direct_constraints) +
                    expected.geometry.interaction_batches or
            binding.prover.nConstraints() != binding.verifier.nConstraints())
        {
            return error.AdapterGeometryMismatch;
        }

        try self.claims.bind(@enumFromInt(expected_row), binding.claimed_sum);
        self.roster_rows[self.count] = expected_row;
        self.verifier_components[self.count] = binding.verifier;
        self.prover_components[self.count] = binding.prover;
        self.count += 1;
    }

    pub fn sealGate(
        self: *ProofGate,
        manifest: *const Manifest,
    ) Error!void {
        if (self.count != manifest.roster_count)
            return error.AdapterCountMismatch;
        try self.claims.sealClaims(manifest);
        self.sealed = true;
    }

    pub fn validate(
        self: *const ProofGate,
        manifest: *const Manifest,
    ) Error!void {
        try manifest.validate();
        if (!self.sealed or self.count != manifest.roster_count or
            !std.mem.eql(u8, &self.manifest_seal, &manifest.seal))
        {
            return error.AdapterCountMismatch;
        }
        try self.claims.validate(manifest);
        for (
            self.roster_rows[0..self.count],
            manifest.roster_rows[0..manifest.roster_count],
        ) |actual, expected| {
            if (actual != expected)
                return error.AdapterOrderMismatch;
        }
    }

    pub fn verifierSlice(
        self: *const ProofGate,
    ) Error![]const core_components.Component {
        if (!self.sealed)
            return error.AdapterCountMismatch;
        return self.verifier_components[0..self.count];
    }

    pub fn proverSlice(
        self: *const ProofGate,
    ) Error![]const prover_component.ComponentProver {
        if (!self.sealed)
            return error.AdapterCountMismatch;
        return self.prover_components[0..self.count];
    }
};

pub fn build(
    log_sizes: universal_manifest.LogSizes,
    transcript: *const transcript_v2.ManifestV2,
    statement: *const statement_v2.ManifestV2,
    public: *const public_v2.ManifestV2,
    boundary: *const boundary_v2.OuterManifestV2,
) Error!Manifest {
    return buildWithProviderShape(log_sizes, transcript, statement, public, boundary, provider_authority_v2.Shape.init(21) catch unreachable);
}

pub fn buildWithProviderShape(
    log_sizes: universal_manifest.LogSizes,
    transcript: *const transcript_v2.ManifestV2,
    statement: *const statement_v2.ManifestV2,
    public: *const public_v2.ManifestV2,
    boundary: *const boundary_v2.OuterManifestV2,
    provider_shape: provider_authority_v2.Shape,
) Error!Manifest {
    transcript.validate() catch return error.SourceManifestMismatch;
    statement.validate() catch return error.SourceManifestMismatch;
    public.validate() catch return error.SourceManifestMismatch;
    boundary.validate() catch return error.SourceManifestMismatch;
    try validateBuildLogSizes(log_sizes, transcript, statement, public);
    const catalog = try typed_catalog_v2.buildWithProviderShape(log_sizes, boundary.components, provider_shape);
    const result = try assemble(&catalog, .{
        .transcript_manifest_id = transcript.identity,
        .statement_manifest_id = statement.identity,
        .public_manifest_id = public.identity,
        .boundary_manifest_id = boundary.identity,
        .boundary_authority_sha_id = boundary.authority_sha_id,
        .provider_authority_sha_id = provider_authority_v2.sourceAuthorityShaId(),
    });
    try dependency_0.validateAgainstSources(&result, transcript, statement, public, boundary);
    return result;
}

/// Strict geometry assembly for focused tests and higher-level composition.
/// Unlike the removed generic builder, this accepts a validated typed catalog
/// as a whole and therefore cannot smuggle V1 rows 10--17 into a V2 manifest.
pub fn assemble(
    catalog: *const TypedCatalogV2,
    ids: AuthorityIds,
) Error!Manifest {
    try catalog.validate();
    try ids.validate();
    var assembler = Assembler.init(catalog.identity, ids);
    for (catalog.entries) |entry|
        _ = try assembler.append(entry.geometry);
    return assembler.seal();
}

pub fn validateBuildLogSizes(
    log_sizes: universal_manifest.LogSizes,
    transcript: *const transcript_v2.ManifestV2,
    statement: *const statement_v2.ManifestV2,
    public: *const public_v2.ManifestV2,
) Error!void {
    for (transcript.log_sizes, 0..) |log_size, row| {
        if (log_sizes[row] != log_size)
            return error.SourceManifestMismatch;
    }
    if (log_sizes[10] != typed_catalog_v2.INACTIVE_STATEMENT_LOG_SIZE or
        log_sizes[11] != statement.trace_log_size)
    {
        return error.SourceManifestMismatch;
    }
    for (public.log_sizes, 0..) |log_size, index| {
        if (log_sizes[12 + index] != log_size)
            return error.SourceManifestMismatch;
    }
}

pub const validateClaimGeometry = @import("segment_outer_manifest_contract_v2.zig").validateClaimGeometry;
pub const programGeometryShaId = @import("segment_outer_manifest_contract_v2.zig").programGeometryShaId;
pub const requireSameProgramGeometry = @import("segment_outer_manifest_contract_v2.zig").requireSameProgramGeometry;
pub const claimDigest = @import("segment_outer_manifest_contract_v2.zig").claimDigest;

comptime {
    if (@typeInfo(ComponentKey).@"enum".fields.len != COMPONENT_COUNT or
        STATEMENT_SOURCE_INDEX != 36 or PUBLIC_LOGUP_SOURCE_INDEX != 37 or
        VERIFIER_INPUT_PROVIDER_INDEX != 38 or COMPONENT_COUNT != 39 or
        typed_catalog_v2.COMPONENT_COUNT != COMPONENT_COUNT or
        typed_catalog_v2.STATEMENT_SOURCE_INDEX != STATEMENT_SOURCE_INDEX or
        typed_catalog_v2.PUBLIC_LOGUP_SOURCE_INDEX !=
            PUBLIC_LOGUP_SOURCE_INDEX or
        typed_catalog_v2.VERIFIER_INPUT_PROVIDER_INDEX !=
            VERIFIER_INPUT_PROVIDER_INDEX or COMPONENT_COUNT > 64 or
        TREE_COUNT != 3)
    {
        @compileError("segment V2 outer manifest geometry drifted");
    }
}
