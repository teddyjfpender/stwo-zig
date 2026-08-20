//! Internal binary global closure outer source authority shard; use binary_global_closure_outer_source.zig publicly.

const dependency_0 = @import("binary_global_closure_outer_source_contract.zig");

const ACTIVE = dependency_0.ACTIVE;
const BOUNDARY_CLAIM_FORMAT_VERSION_V2 = dependency_0.BOUNDARY_CLAIM_FORMAT_VERSION_V2;
const BOUNDARY_CLAIM_ID_DOMAIN_V2 = dependency_0.BOUNDARY_CLAIM_ID_DOMAIN_V2;
const BoundaryAuthoritiesV2 = dependency_0.BoundaryAuthoritiesV2;
const BoundaryEvidenceV2 = dependency_0.BoundaryEvidenceV2;
const BoundaryKindV2 = dependency_0.BoundaryKindV2;
const BoundarySourceV2 = dependency_0.BoundarySourceV2;
const CONTEXT_SEAM_FORMAT_VERSION_V2 = dependency_0.CONTEXT_SEAM_FORMAT_VERSION_V2;
const CONTEXT_SEAM_ID_DOMAIN_V2 = dependency_0.CONTEXT_SEAM_ID_DOMAIN_V2;
const ContextAvailabilityV2 = dependency_0.ContextAvailabilityV2;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const INPUT_ID_DOMAIN = dependency_0.INPUT_ID_DOMAIN;
const PREFIX_ROW_COUNT = dependency_0.PREFIX_ROW_COUNT;
const PRESENT = dependency_0.PRESENT;
const PROVIDER_DOMAIN = dependency_0.PROVIDER_DOMAIN;
const PROVIDER_ROW = dependency_0.PROVIDER_ROW;
const PreparedAuthorityV1 = dependency_0.PreparedAuthorityV1;
const PreparedState = dependency_0.PreparedState;
const ProviderClaimV1 = dependency_0.ProviderClaimV1;
const QM31 = dependency_0.QM31;
const RequiredContextV2 = dependency_0.RequiredContextV2;
const RowClaimsV1 = dependency_0.RowClaimsV1;
const SOURCE_AUTHORITY_DOMAIN_V2 = dependency_0.SOURCE_AUTHORITY_DOMAIN_V2;
const SOURCE_AUTHORITY_FORMAT_VERSION_V2 = dependency_0.SOURCE_AUTHORITY_FORMAT_VERSION_V2;
const SourceAuthorityV1 = dependency_0.SourceAuthorityV1;
const TOTAL_ROW_COUNT = dependency_0.TOTAL_ROW_COUNT;
const VERIFIER_INPUT_BOUNDARY_DOMAIN = dependency_0.VERIFIER_INPUT_BOUNDARY_DOMAIN;
const WIRE_BOUNDARY_DOMAIN = dependency_0.WIRE_BOUNDARY_DOMAIN;
const WORKSPACE_FORMAT_VERSION = dependency_0.WORKSPACE_FORMAT_VERSION;
const allZero = dependency_0.allZero;
const boundaryDomainV2 = dependency_0.boundaryDomainV2;
const digestIsZero = dependency_0.digestIsZero;
const hashInt = dependency_0.hashInt;
const hashQm31 = dependency_0.hashQm31;
const relation = dependency_0.relation;
const requireCanonical = dependency_0.requireCanonical;
const requireDigest = dependency_0.requireDigest;
const roster = dependency_0.roster;
const std = dependency_0.std;

/// Fail-closed temporal seam. The only constructor in V2 publishes
/// `unavailable`; even a structurally complete caller-fabricated context is
/// rejected until a future prepared authority owns its authentication.
pub const ContextSeamV2 = struct {
    format_version: u16 = CONTEXT_SEAM_FORMAT_VERSION_V2,
    present: u8 = PRESENT,
    availability: ContextAvailabilityV2 = .unavailable,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    required: RequiredContextV2 = RequiredContextV2.zero(),
    identity: [32]u8,

    fn unavailable() ContextSeamV2 {
        var result = ContextSeamV2{ .identity = undefined };
        result.identity = contextSeamIdentityV2(&result);
        return result;
    }

    pub fn validateCurrent(self: *const ContextSeamV2) Error!void {
        if (self.format_version != CONTEXT_SEAM_FORMAT_VERSION_V2)
            return error.FormatVersionMismatch;
        if (self.present != PRESENT) return error.AuthorityMismatch;
        if (!allZero(&self.padding)) return error.InvalidPadding;
        if (digestIsZero(self.identity) or !std.mem.eql(
            u8,
            &self.identity,
            &contextSeamIdentityV2(self),
        )) return error.InvalidContextIdentity;
        switch (self.availability) {
            .unavailable => if (!self.required.isZero())
                return error.UnavailableContextNotZero,
            .authenticated => return error.TemporalContextAuthorityUnavailable,
        }
    }

    pub fn requireTemporalContext(self: *const ContextSeamV2) Error!RequiredContextV2 {
        try self.validateCurrent();
        return error.TemporalContextAuthorityUnavailable;
    }

    pub fn identityDigest(self: *const ContextSeamV2) [32]u8 {
        return contextSeamIdentityV2(self);
    }
};

/// Versioned authority record for global closure. Its temporal seam is fixed
/// to unavailable; callers may select only already-authenticated boundary
/// source publications.
pub const SourceAuthorityV2 = struct {
    format_version: u16 = SOURCE_AUTHORITY_FORMAT_VERSION_V2,
    prefix_row_count: u8 = PREFIX_ROW_COUNT,
    total_row_count: u8 = TOTAL_ROW_COUNT,
    domain_count: u8 = DOMAIN_COUNT,
    provider_row: roster.Component = PROVIDER_ROW,
    provider_domain: relation.Domain = PROVIDER_DOMAIN,
    wire_boundary_domain: relation.Domain = WIRE_BOUNDARY_DOMAIN,
    verifier_input_boundary_domain: relation.Domain = VERIFIER_INPUT_BOUNDARY_DOMAIN,
    padding: [3]u8 = .{ 0, 0, 0 },
    base_source_authority_id: [32]u8,
    provider_source_authority_id: [32]u8,
    boundaries: BoundaryAuthoritiesV2,
    context_seam: ContextSeamV2,

    pub fn init(boundaries: BoundaryAuthoritiesV2) Error!SourceAuthorityV2 {
        try boundaries.validate();
        const base = SourceAuthorityV1.pinned();
        try base.validate();
        const result = SourceAuthorityV2{
            .base_source_authority_id = base.identityDigest(),
            .provider_source_authority_id = base.provider_source_authority_id,
            .boundaries = boundaries,
            .context_seam = ContextSeamV2.unavailable(),
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SourceAuthorityV2) Error!void {
        if (self.format_version != SOURCE_AUTHORITY_FORMAT_VERSION_V2 or
            self.prefix_row_count != PREFIX_ROW_COUNT or
            self.total_row_count != TOTAL_ROW_COUNT or
            self.domain_count != DOMAIN_COUNT)
        {
            return error.FormatVersionMismatch;
        }
        if (self.provider_row != PROVIDER_ROW)
            return error.ProviderRowMismatch;
        if (self.provider_domain != PROVIDER_DOMAIN)
            return error.ProviderDomainMismatch;
        if (self.wire_boundary_domain != WIRE_BOUNDARY_DOMAIN or
            self.verifier_input_boundary_domain != VERIFIER_INPUT_BOUNDARY_DOMAIN)
        {
            return error.BoundaryDomainMismatch;
        }
        if (!allZero(&self.padding)) return error.InvalidPadding;
        const base = SourceAuthorityV1.pinned();
        try base.validate();
        if (!std.mem.eql(
            u8,
            &self.base_source_authority_id,
            &base.identityDigest(),
        ) or !std.mem.eql(
            u8,
            &self.provider_source_authority_id,
            &base.provider_source_authority_id,
        )) return error.AuthorityMismatch;
        try self.boundaries.validate();
        try self.context_seam.validateCurrent();
    }

    pub fn identityDigest(self: *const SourceAuthorityV2) [32]u8 {
        return sourceAuthorityIdentityV2(self);
    }
};

/// Cold, pointer-free capability consumed by V2 input preparation and fill.
pub const PreparedAuthorityV2 = struct {
    state: PreparedState,
    base_source_authority_id: [32]u8,
    provider_source_authority_id: [32]u8,
    boundaries: BoundaryAuthoritiesV2,
    context_seam: ContextSeamV2,
    source_authority_id: [32]u8,

    pub fn boundarySource(self: *const PreparedAuthorityV2, kind: BoundaryKindV2) BoundarySourceV2 {
        return self.boundaries.source(kind);
    }
};

pub fn prepareAuthorityV2(
    boundaries: BoundaryAuthoritiesV2,
) Error!PreparedAuthorityV2 {
    const authority = try SourceAuthorityV2.init(boundaries);
    return .{
        .state = .validated,
        .base_source_authority_id = authority.base_source_authority_id,
        .provider_source_authority_id = authority.provider_source_authority_id,
        .boundaries = authority.boundaries,
        .context_seam = authority.context_seam,
        .source_authority_id = authority.identityDigest(),
    };
}

pub const PublicBoundaryClaimV2 = struct {
    format_version: u16 = BOUNDARY_CLAIM_FORMAT_VERSION_V2,
    present: u8 = PRESENT,
    kind: BoundaryKindV2,
    domain: relation.Domain,
    padding: [3]u8 = .{ 0, 0, 0 },
    source_authority_id: [32]u8,
    snapshot_id: [32]u8,
    tuple_provenance_id: [32]u8,
    tuple_count: u32,
    claimed_sum: QM31,
    identity: [32]u8,

    pub fn initFromAuthenticatedSource(
        prepared: *const PreparedAuthorityV2,
        kind: BoundaryKindV2,
        evidence: BoundaryEvidenceV2,
    ) Error!PublicBoundaryClaimV2 {
        try requirePreparedAuthorityV2(prepared);
        const source = prepared.boundarySource(kind);
        try evidence.validateAgainst(&source);
        var result = PublicBoundaryClaimV2{
            .kind = kind,
            .domain = boundaryDomainV2(kind),
            .source_authority_id = evidence.source_authority_id,
            .snapshot_id = evidence.snapshot_id,
            .tuple_provenance_id = evidence.tuple_provenance_id,
            .tuple_count = evidence.tuple_count,
            .claimed_sum = evidence.claimed_sum,
            .identity = undefined,
        };
        result.identity = boundaryClaimIdentityV2(&result);
        try result.validateAgainst(prepared);
        return result;
    }

    pub fn init(
        prepared: *const PreparedAuthorityV2,
        kind: BoundaryKindV2,
        evidence: BoundaryEvidenceV2,
    ) Error!PublicBoundaryClaimV2 {
        return initFromAuthenticatedSource(prepared, kind, evidence);
    }

    pub fn validate(self: *const PublicBoundaryClaimV2) Error!void {
        if (self.format_version != BOUNDARY_CLAIM_FORMAT_VERSION_V2)
            return error.FormatVersionMismatch;
        if (self.present != PRESENT) return error.OmittedBoundary;
        if (!allZero(&self.padding)) return error.InvalidPadding;
        if (self.domain != boundaryDomainV2(self.kind))
            return error.BoundaryDomainMismatch;
        if (digestIsZero(self.source_authority_id))
            return error.BoundaryAuthorityMismatch;
        if (digestIsZero(self.snapshot_id))
            return error.BoundarySnapshotMismatch;
        if (digestIsZero(self.tuple_provenance_id))
            return error.InvalidBoundaryTupleProvenance;
        if (self.tuple_count == 0) return error.InvalidBoundaryTupleCount;
        try requireCanonical(self.claimed_sum);
        if (digestIsZero(self.identity) or !std.mem.eql(
            u8,
            &self.identity,
            &boundaryClaimIdentityV2(self),
        )) return error.BoundaryIdentityMismatch;
    }

    pub fn validateAgainst(
        self: *const PublicBoundaryClaimV2,
        prepared: *const PreparedAuthorityV2,
    ) Error!void {
        try requirePreparedAuthorityV2(prepared);
        try self.validate();
        const source = prepared.boundarySource(self.kind);
        if (self.domain != source.domain)
            return error.BoundaryDomainMismatch;
        if (!std.mem.eql(
            u8,
            &self.source_authority_id,
            &source.source_authority_id,
        )) return error.BoundaryAuthorityMismatch;
        if (!std.mem.eql(u8, &self.snapshot_id, &source.snapshot_id))
            return error.BoundarySnapshotMismatch;
        if (!std.mem.eql(
            u8,
            &self.tuple_provenance_id,
            &source.tuple_provenance_id,
        )) return error.InvalidBoundaryTupleProvenance;
        if (self.tuple_count != source.tuple_count)
            return error.InvalidBoundaryTupleCount;
        if (!self.claimed_sum.eql(source.claimed_sum))
            return error.BoundaryClaimMismatch;
    }

    pub fn identityDigest(self: *const PublicBoundaryClaimV2) [32]u8 {
        return boundaryClaimIdentityV2(self);
    }
};

pub const PublicBoundariesV2 = struct {
    format_version: u16 = BOUNDARY_CLAIM_FORMAT_VERSION_V2,
    present: u8 = PRESENT,
    padding: u8 = 0,
    wire: PublicBoundaryClaimV2,
    verifier_input: PublicBoundaryClaimV2,
    identity: [32]u8,

    pub fn init(
        prepared: *const PreparedAuthorityV2,
        wire_evidence: BoundaryEvidenceV2,
        verifier_input_evidence: BoundaryEvidenceV2,
    ) Error!PublicBoundariesV2 {
        var result = PublicBoundariesV2{
            .wire = try PublicBoundaryClaimV2.initFromAuthenticatedSource(
                prepared,
                .wire,
                wire_evidence,
            ),
            .verifier_input = try PublicBoundaryClaimV2.initFromAuthenticatedSource(
                prepared,
                .verifier_input,
                verifier_input_evidence,
            ),
            .identity = undefined,
        };
        result.identity = publicBoundariesIdentityV2(&result);
        try result.validateAgainst(prepared);
        return result;
    }

    pub fn validateAgainst(
        self: *const PublicBoundariesV2,
        prepared: *const PreparedAuthorityV2,
    ) Error!void {
        try self.validate();
        try self.wire.validateAgainst(prepared);
        try self.verifier_input.validateAgainst(prepared);
    }

    pub fn validate(self: *const PublicBoundariesV2) Error!void {
        if (self.format_version != BOUNDARY_CLAIM_FORMAT_VERSION_V2)
            return error.FormatVersionMismatch;
        if (self.present != PRESENT) return error.OmittedBoundary;
        if (self.padding != 0) return error.InvalidPadding;
        if (self.wire.kind != .wire or
            self.verifier_input.kind != .verifier_input)
        {
            return error.BoundaryKindMismatch;
        }
        try self.wire.validate();
        try self.verifier_input.validate();
        if (digestIsZero(self.identity) or !std.mem.eql(
            u8,
            &self.identity,
            &publicBoundariesIdentityV2(self),
        )) return error.BoundaryIdentityMismatch;
    }

    pub fn claimedSum(self: *const PublicBoundariesV2) QM31 {
        return self.wire.claimed_sum.add(self.verifier_input.claimed_sum);
    }

    pub fn identityDigest(self: *const PublicBoundariesV2) [32]u8 {
        return publicBoundariesIdentityV2(self);
    }
};

/// Retained scratch for the second pass. Reinitializing these fixed arrays is
/// cheaper and safer than allocating one accumulator per proof.
pub const Workspace = struct {
    format_version: u16 = WORKSPACE_FORMAT_VERSION,
    prefix_totals: [DOMAIN_COUNT]QM31 = zeroDomainVector(),
    closed_totals: [DOMAIN_COUNT]QM31 = zeroDomainVector(),
    framework_total: QM31 = QM31.zero(),
    active_domain_mask: u64 = 0,

    pub fn init() Workspace {
        return .{};
    }

    pub fn validate(self: *const Workspace) Error!void {
        if (self.format_version != WORKSPACE_FORMAT_VERSION)
            return error.InvalidWorkspace;
        try requireCanonicalVector(&self.prefix_totals);
        try requireCanonicalVector(&self.closed_totals);
        try requireCanonical(self.framework_total);
        if (self.active_domain_mask & ~allDomainMask() != 0)
            return error.InvalidWorkspace;
    }

    pub fn reset(self: *Workspace, active_domain_mask: u64) void {
        self.prefix_totals = zeroDomainVector();
        self.closed_totals = zeroDomainVector();
        self.framework_total = QM31.zero();
        self.active_domain_mask = active_domain_mask;
    }
};

pub const InputPreflight = struct {
    input_id: [32]u8,
    active_domain_mask: u64,
};

pub fn preflightInputs(
    prepared: *const PreparedAuthorityV1,
    rows: []const RowClaimsV1,
    provider: *const ProviderClaimV1,
) Error!InputPreflight {
    if (rows.len != PREFIX_ROW_COUNT) return error.RowCountMismatch;
    try validateProviderClaim(prepared, provider);

    var row_seen: u64 = 0;
    for (rows) |row| {
        if (row.format_version != FORMAT_VERSION)
            return error.FormatVersionMismatch;
        if (row.present != PRESENT) return error.OmittedRow;
        if (row.padding != 0 or !allZero(&row.header_padding))
            return error.InvalidPadding;
        if (row.domain_count != DOMAIN_COUNT) return error.DomainCountMismatch;
        const row_index = @intFromEnum(row.row);
        if (row_index >= PREFIX_ROW_COUNT) return error.RowOutOfRange;
        const bit = @as(u64, 1) << @intCast(row_index);
        if (row_seen & bit != 0) return error.DuplicateRow;
        row_seen |= bit;
    }
    if (row_seen != prefixRowMask()) return error.MissingRow;
    for (rows, 0..) |row, index| {
        if (@intFromEnum(row.row) != index) return error.RowOrderMismatch;
    }

    var active_domain_mask: u64 = providerDomainBit();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(INPUT_ID_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hash.update(&prepared.source_authority_id);
    hashInt(&hash, u8, PREFIX_ROW_COUNT);
    hashInt(&hash, u8, DOMAIN_COUNT);
    for (rows) |row| {
        var domain_seen: u64 = 0;
        for (row.domains) |claim| {
            const domain_index = @intFromEnum(claim.domain);
            const bit = @as(u64, 1) << @intCast(domain_index);
            if (domain_seen & bit != 0) return error.DuplicateDomain;
            domain_seen |= bit;
        }
        if (domain_seen != allDomainMask()) return error.MissingDomain;
        for (row.domains, 0..) |claim, domain_index| {
            if (@intFromEnum(claim.domain) != domain_index)
                return error.DomainOrderMismatch;
            if (claim.present != PRESENT) return error.OmittedDomain;
            if (claim.active > ACTIVE) return error.InvalidActiveFlag;
            if (!allZero(&claim.padding)) return error.InvalidPadding;
            try requireCanonical(claim.value);
            if (claim.active == 0 and !claim.value.isZero())
                return error.InactiveDomainNonZero;
            if (claim.active == ACTIVE)
                active_domain_mask |= @as(u64, 1) << @intCast(domain_index);
        }
        try requireCanonical(row.claimed_sum);
        var row_total = QM31.zero();
        for (row.domains) |claim| row_total = row_total.add(claim.value);
        if (!row_total.eql(row.claimed_sum)) return error.RowClaimMismatch;

        hashInt(&hash, u16, row.format_version);
        hashInt(&hash, u8, row.present);
        hashInt(&hash, u8, @intFromEnum(row.row));
        hashInt(&hash, u8, row.domain_count);
        for (row.domains) |claim| {
            hashInt(&hash, u8, claim.present);
            hashInt(&hash, u8, claim.active);
            hashInt(&hash, u8, @intFromEnum(claim.domain));
            hashQm31(&hash, claim.value);
        }
        hashQm31(&hash, row.claimed_sum);
    }
    hash.update(&provider.identity);
    hashInt(&hash, u64, active_domain_mask);
    return .{
        .input_id = hash.finalResult(),
        .active_domain_mask = active_domain_mask,
    };
}

pub fn validateProviderClaim(
    prepared: *const PreparedAuthorityV1,
    provider: *const ProviderClaimV1,
) Error!void {
    try provider.validate();
    if (!std.mem.eql(
        u8,
        &provider.source_authority_id,
        &prepared.provider_source_authority_id,
    )) return error.ProviderAuthorityMismatch;
}

pub fn basePreparedAuthorityV1(
    prepared: *const PreparedAuthorityV2,
) PreparedAuthorityV1 {
    return .{
        .state = .validated,
        .source_authority_id = prepared.base_source_authority_id,
        .provider_source_authority_id = prepared.provider_source_authority_id,
    };
}

pub fn requirePreparedAuthorityV2(
    prepared: *const PreparedAuthorityV2,
) Error!void {
    if (prepared.state != .validated) return error.AuthorityMismatch;
    try requireDigest(prepared.base_source_authority_id);
    try requireDigest(prepared.provider_source_authority_id);
    try requireDigest(prepared.source_authority_id);
    const authority = try SourceAuthorityV2.init(prepared.boundaries);
    if (!std.mem.eql(
        u8,
        &prepared.base_source_authority_id,
        &authority.base_source_authority_id,
    ) or !std.mem.eql(
        u8,
        &prepared.provider_source_authority_id,
        &authority.provider_source_authority_id,
    ) or !std.meta.eql(prepared.context_seam, authority.context_seam) or
        !std.mem.eql(
            u8,
            &prepared.source_authority_id,
            &authority.identityDigest(),
        ))
    {
        return error.AuthorityMismatch;
    }
}

pub fn contextSeamIdentityV2(context: *const ContextSeamV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTEXT_SEAM_ID_DOMAIN_V2);
    hashInt(&hash, u16, context.format_version);
    hashInt(&hash, u8, context.present);
    hashInt(&hash, u8, @intFromEnum(context.availability));
    hashInt(&hash, u32, context.required.statement_version);
    hash.update(&context.required.session_id);
    hash.update(&context.required.parent_vk_id);
    hash.update(&context.required.lineage_id);
    hash.update(&context.required.statement_id);
    hash.update(&context.required.authenticated_context_id);
    return hash.finalResult();
}

pub fn sourceAuthorityIdentityV2(authority: *const SourceAuthorityV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(SOURCE_AUTHORITY_DOMAIN_V2);
    hashInt(&hash, u16, authority.format_version);
    hashInt(&hash, u8, authority.prefix_row_count);
    hashInt(&hash, u8, authority.total_row_count);
    hashInt(&hash, u8, authority.domain_count);
    hashInt(&hash, u8, @intFromEnum(authority.provider_row));
    hashInt(&hash, u8, @intFromEnum(authority.provider_domain));
    hashInt(&hash, u8, @intFromEnum(authority.wire_boundary_domain));
    hashInt(
        &hash,
        u8,
        @intFromEnum(authority.verifier_input_boundary_domain),
    );
    hash.update(&authority.base_source_authority_id);
    hash.update(&authority.provider_source_authority_id);
    hash.update(&authority.boundaries.wire.identity);
    hash.update(&authority.boundaries.verifier_input.identity);
    hash.update(&authority.context_seam.identity);
    return hash.finalResult();
}

pub fn boundaryClaimIdentityV2(claim: *const PublicBoundaryClaimV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_CLAIM_ID_DOMAIN_V2);
    hashInt(&hash, u16, claim.format_version);
    hashInt(&hash, u8, claim.present);
    hashInt(&hash, u8, @intFromEnum(claim.kind));
    hashInt(&hash, u8, @intFromEnum(claim.domain));
    hash.update(&claim.source_authority_id);
    hash.update(&claim.snapshot_id);
    hash.update(&claim.tuple_provenance_id);
    hashInt(&hash, u32, claim.tuple_count);
    hashQm31(&hash, claim.claimed_sum);
    return hash.finalResult();
}

pub fn publicBoundariesIdentityV2(boundaries: *const PublicBoundariesV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/binary-global-closure-boundaries/v2\x00");
    hashInt(&hash, u16, boundaries.format_version);
    hashInt(&hash, u8, boundaries.present);
    hash.update(&boundaries.wire.identity);
    hash.update(&boundaries.verifier_input.identity);
    return hash.finalResult();
}

pub fn requireCanonicalVector(values: *const [DOMAIN_COUNT]QM31) Error!void {
    for (values) |value| try requireCanonical(value);
}

pub fn zeroDomainVector() [DOMAIN_COUNT]QM31 {
    return [_]QM31{QM31.zero()} ** DOMAIN_COUNT;
}

pub fn prefixRowMask() u64 {
    return (@as(u64, 1) << PREFIX_ROW_COUNT) - 1;
}

pub fn allDomainMask() u64 {
    return (@as(u64, 1) << DOMAIN_COUNT) - 1;
}

pub fn providerDomainBit() u64 {
    return @as(u64, 1) << @intFromEnum(PROVIDER_DOMAIN);
}
