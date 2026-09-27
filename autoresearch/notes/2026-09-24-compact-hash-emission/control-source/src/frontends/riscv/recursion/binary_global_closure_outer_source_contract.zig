//! Internal binary global closure outer source authority shard; use binary_global_closure_outer_source.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const relation = @import("../air/lang/relation.zig");
pub const provider_authority = @import("outer_parent_range_authority.zig");
pub const roster = @import("air/universal_roster.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SOURCE_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const PROVIDER_CLAIM_FORMAT_VERSION: u16 = 1;
pub const WORKSPACE_FORMAT_VERSION: u16 = 1;
pub const FORMAT_VERSION_V2: u16 = 2;
pub const SOURCE_AUTHORITY_FORMAT_VERSION_V2: u16 = 2;
pub const BOUNDARY_SOURCE_FORMAT_VERSION_V2: u16 = 2;
pub const BOUNDARY_CLAIM_FORMAT_VERSION_V2: u16 = 2;
pub const CLOSURE_INPUT_FORMAT_VERSION_V2: u16 = 2;
pub const CLOSURE_RECEIPT_FORMAT_VERSION_V2: u16 = 2;
pub const CONTEXT_SEAM_FORMAT_VERSION_V2: u16 = 2;
pub const PREFIX_ROW_COUNT: usize = @intFromEnum(roster.Component.range_check_8_8);
pub const TOTAL_ROW_COUNT: usize = roster.COMPONENT_COUNT;
pub const DOMAIN_COUNT: usize = relation.UNIVERSAL_RELATION_COUNT;
pub const PROVIDER_ROW: roster.Component = .range_check_8_8;
pub const PROVIDER_DOMAIN: relation.Domain = .range_check_8_8;
pub const WIRE_BOUNDARY_DOMAIN: relation.Domain = .recursion_wire;
pub const VERIFIER_INPUT_BOUNDARY_DOMAIN: relation.Domain =
    .recursion_verifier_input_word;
pub const PRESENT: u8 = 1;
pub const ACTIVE: u8 = 1;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const WHOLE_FRONTEND_VERIFIED = false;
pub const PARENT_PROOF_VERIFICATION = false;
pub const PARENT_PROOF_PRODUCTION = false;
pub const PRODUCTION_ACTIVATION = false;

pub const SOURCE_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/binary-global-closure-source/v1\x00";
pub const ROSTER_PREFIX_DOMAIN =
    "stwo-zig/typed-air/binary-global-closure-roster/v1\x00";
pub const PROVIDER_CLAIM_ID_DOMAIN =
    "stwo-zig/typed-air/binary-global-closure-provider/v1\x00";
pub const INPUT_ID_DOMAIN =
    "stwo-zig/typed-air/binary-global-closure-input/v1\x00";
pub const CLOSURE_ID_DOMAIN =
    "stwo-zig/typed-air/binary-global-closure-result/v1\x00";
pub const SOURCE_AUTHORITY_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-source/v2\x00";
pub const BOUNDARY_SOURCE_ID_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-boundary-source/v2\x00";
pub const BOUNDARY_CLAIM_ID_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-boundary-claim/v2\x00";
pub const CONTEXT_SEAM_ID_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-context-seam/v2\x00";
pub const INPUT_ID_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-input/v2\x00";
pub const CLOSURE_ID_DOMAIN_V2 =
    "stwo-zig/typed-air/binary-global-closure-result/v2\x00";

pub const Error = error{
    AddressOverflow,
    AliasedDestination,
    AliasedWorkspace,
    AuthorityMismatch,
    BoundaryAuthorityMismatch,
    BoundaryClaimMismatch,
    BoundaryDomainMismatch,
    BoundaryIdentityMismatch,
    BoundaryKindMismatch,
    BoundarySnapshotMismatch,
    DestinationNotFresh,
    DomainCountMismatch,
    DomainOrderMismatch,
    DuplicateDomain,
    DuplicateRow,
    FormatVersionMismatch,
    InactiveDomainNonZero,
    InvalidActiveFlag,
    InvalidBoundaryTupleCount,
    InvalidBoundaryTupleProvenance,
    InvalidContextIdentity,
    InvalidInputIdentity,
    InvalidPadding,
    InvalidProviderClaimIdentity,
    InvalidWorkspace,
    MissingDomain,
    MissingRow,
    NonCanonicalField,
    OmittedDomain,
    OmittedBoundary,
    OmittedProvider,
    OmittedRow,
    ProviderAuthorityMismatch,
    ProviderDomainMismatch,
    ProviderRowMismatch,
    RelationNotClosed,
    RowClaimMismatch,
    RowCountMismatch,
    RowOrderMismatch,
    RowOutOfRange,
    TemporalContextAuthorityUnavailable,
    UnavailableContextNotZero,
};

/// Exact heap-allocation contract. Authority preparation, workspace creation,
/// first fill, and every reused-workspace fill are fixed-storage operations.
pub const AllocationLedgerV1 = struct {
    pub const authority_preparation_heap_allocations: usize = 0;
    pub const workspace_initialization_heap_allocations: usize = 0;
    pub const fresh_hot_fill_heap_allocations: usize = 0;
    pub const reused_hot_fill_heap_allocations: usize = 0;
};

/// V2 retains the same fixed-storage hot-path contract. Boundary publications
/// and the temporal seam are pointer-free values admitted before filling.
pub const AllocationLedgerV2 = struct {
    pub const authority_preparation_heap_allocations: usize = 0;
    pub const input_preparation_heap_allocations: usize = 0;
    pub const workspace_initialization_heap_allocations: usize = 0;
    pub const fresh_hot_fill_heap_allocations: usize = 0;
    pub const reused_hot_fill_heap_allocations: usize = 0;
};

pub const DomainClaimV1 = struct {
    present: u8 = PRESENT,
    active: u8,
    padding: [2]u8 = .{ 0, 0 },
    domain: relation.Domain,
    value: QM31,
};

/// One verifier-owned framework claim decomposed in exact universal registry
/// order. `claimed_sum` must equal the sum of all 47 domain values.
pub const RowClaimsV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    present: u8 = PRESENT,
    padding: u8 = 0,
    row: roster.Component,
    domain_count: u8 = DOMAIN_COUNT,
    header_padding: [2]u8 = .{ 0, 0 },
    domains: [DOMAIN_COUNT]DomainClaimV1,
    claimed_sum: QM31,
};

/// Separately admitted row-35 claim. `snapshot_id` identifies the immutable
/// binary range-provider snapshot from which the challenge-dependent claim was
/// computed; `source_authority_id` pins its one-source binary request ledger.
pub const ProviderClaimV1 = struct {
    format_version: u16 = PROVIDER_CLAIM_FORMAT_VERSION,
    present: u8 = PRESENT,
    padding: u8 = 0,
    row: roster.Component = PROVIDER_ROW,
    domain: relation.Domain = PROVIDER_DOMAIN,
    header_padding: [2]u8 = .{ 0, 0 },
    source_authority_id: [32]u8,
    snapshot_id: [32]u8,
    claimed_sum: QM31,
    identity: [32]u8,

    pub fn init(
        prepared: *const PreparedAuthorityV1,
        snapshot_id: [32]u8,
        claimed_sum: QM31,
    ) Error!ProviderClaimV1 {
        try requirePreparedAuthority(prepared);
        try requireDigest(snapshot_id);
        try requireCanonical(claimed_sum);
        var result = ProviderClaimV1{
            .source_authority_id = prepared.provider_source_authority_id,
            .snapshot_id = snapshot_id,
            .claimed_sum = claimed_sum,
            .identity = undefined,
        };
        result.identity = providerClaimIdentity(&result);
        return result;
    }

    pub fn validate(self: *const ProviderClaimV1) Error!void {
        try validateProviderClaimHeader(self);
        try requireDigest(self.source_authority_id);
        try requireDigest(self.snapshot_id);
        try requireDigest(self.identity);
        try requireCanonical(self.claimed_sum);
        const provider_source = provider_authority.SourceAuthority.pinned();
        provider_source.validate() catch return error.ProviderAuthorityMismatch;
        if (!std.mem.eql(
            u8,
            &self.source_authority_id,
            &provider_source.identityDigest(),
        )) return error.ProviderAuthorityMismatch;
        if (!std.mem.eql(u8, &self.identity, &providerClaimIdentity(self)))
            return error.InvalidProviderClaimIdentity;
    }

    pub fn identityDigest(self: *const ProviderClaimV1) [32]u8 {
        return providerClaimIdentity(self);
    }
};

/// Fixed source contract for the 35 ordered prefix rows, the universal
/// relation registry, and the only provider authorized at row 35.
pub const SourceAuthorityV1 = struct {
    format_version: u16,
    prefix_row_count: u8,
    total_row_count: u8,
    domain_count: u8,
    provider_row: roster.Component,
    provider_domain: relation.Domain,
    roster_prefix_id: [32]u8,
    relation_registry_id: [32]u8,
    provider_source_authority_id: [32]u8,

    pub fn pinned() SourceAuthorityV1 {
        return .{
            .format_version = SOURCE_AUTHORITY_FORMAT_VERSION,
            .prefix_row_count = PREFIX_ROW_COUNT,
            .total_row_count = TOTAL_ROW_COUNT,
            .domain_count = DOMAIN_COUNT,
            .provider_row = PROVIDER_ROW,
            .provider_domain = PROVIDER_DOMAIN,
            .roster_prefix_id = canonicalRosterPrefixId(),
            .relation_registry_id = relation.registryOrderDigest(),
            .provider_source_authority_id = provider_authority.SourceAuthority.pinned().identityDigest(),
        };
    }

    pub fn validate(self: SourceAuthorityV1) Error!void {
        provider_authority.SourceAuthority.pinned().validate() catch
            return error.AuthorityMismatch;
        if (!std.meta.eql(self, pinned())) return error.AuthorityMismatch;
    }

    pub fn identityDigest(self: SourceAuthorityV1) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(SOURCE_AUTHORITY_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u8, self.prefix_row_count);
        hashInt(&hash, u8, self.total_row_count);
        hashInt(&hash, u8, self.domain_count);
        hashInt(&hash, u8, @intFromEnum(self.provider_row));
        hashInt(&hash, u8, @intFromEnum(self.provider_domain));
        hash.update(&self.roster_prefix_id);
        hash.update(&self.relation_registry_id);
        hash.update(&self.provider_source_authority_id);
        return hash.finalResult();
    }
};

pub const PreparedState = enum(u8) { invalid = 0, validated = 1 };

/// Cold capability. It contains no borrowed pointers and is not a wire type.
pub const PreparedAuthorityV1 = struct {
    state: PreparedState,
    source_authority_id: [32]u8,
    provider_source_authority_id: [32]u8,
};

pub fn prepareAuthority() Error!PreparedAuthorityV1 {
    const authority = SourceAuthorityV1.pinned();
    try authority.validate();
    return .{
        .state = .validated,
        .source_authority_id = authority.identityDigest(),
        .provider_source_authority_id = authority.provider_source_authority_id,
    };
}

/// The two public boundaries that are allowed to participate in V2 closure.
/// Their tags are semantic: a publication for one kind cannot be moved to the
/// other domain even when its scalar value happens to close the same residual.
pub const BoundaryKindV2 = enum(u8) {
    wire = 0,
    verifier_input = 1,
};

pub fn boundaryDomainV2(kind: BoundaryKindV2) relation.Domain {
    return switch (kind) {
        .wire => WIRE_BOUNDARY_DOMAIN,
        .verifier_input => VERIFIER_INPUT_BOUNDARY_DOMAIN,
    };
}

/// Identity of one independently authenticated public-boundary producer.
/// `snapshot_id` names the immutable producer snapshot whose exact tuple
/// multiset is committed by each corresponding boundary claim.
pub const BoundarySourceV2 = struct {
    format_version: u16 = BOUNDARY_SOURCE_FORMAT_VERSION_V2,
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

    pub fn init(
        kind: BoundaryKindV2,
        evidence: BoundaryEvidenceV2,
    ) Error!BoundarySourceV2 {
        if (digestIsZero(evidence.source_authority_id))
            return error.BoundaryAuthorityMismatch;
        if (digestIsZero(evidence.snapshot_id))
            return error.BoundarySnapshotMismatch;
        if (digestIsZero(evidence.tuple_provenance_id))
            return error.InvalidBoundaryTupleProvenance;
        if (evidence.tuple_count == 0)
            return error.InvalidBoundaryTupleCount;
        try requireCanonical(evidence.claimed_sum);
        var result = BoundarySourceV2{
            .kind = kind,
            .domain = boundaryDomainV2(kind),
            .source_authority_id = evidence.source_authority_id,
            .snapshot_id = evidence.snapshot_id,
            .tuple_provenance_id = evidence.tuple_provenance_id,
            .tuple_count = evidence.tuple_count,
            .claimed_sum = evidence.claimed_sum,
            .identity = undefined,
        };
        result.identity = boundarySourceIdentityV2(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const BoundarySourceV2) Error!void {
        if (self.format_version != BOUNDARY_SOURCE_FORMAT_VERSION_V2)
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
            &boundarySourceIdentityV2(self),
        )) return error.BoundaryIdentityMismatch;
    }

    pub fn identityDigest(self: *const BoundarySourceV2) [32]u8 {
        return boundarySourceIdentityV2(self);
    }
};

/// Fixed ordering prevents a caller from using the wire publication as the
/// verifier-input publication (or vice versa).
pub const BoundaryAuthoritiesV2 = struct {
    format_version: u16 = SOURCE_AUTHORITY_FORMAT_VERSION_V2,
    present: u8 = PRESENT,
    padding: u8 = 0,
    wire: BoundarySourceV2,
    verifier_input: BoundarySourceV2,

    pub fn init(
        wire: BoundarySourceV2,
        verifier_input: BoundarySourceV2,
    ) Error!BoundaryAuthoritiesV2 {
        var result = BoundaryAuthoritiesV2{
            .wire = wire,
            .verifier_input = verifier_input,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const BoundaryAuthoritiesV2) Error!void {
        if (self.format_version != SOURCE_AUTHORITY_FORMAT_VERSION_V2)
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
    }

    pub fn source(self: *const BoundaryAuthoritiesV2, kind: BoundaryKindV2) BoundarySourceV2 {
        return switch (kind) {
            .wire => self.wire,
            .verifier_input => self.verifier_input,
        };
    }
};

/// Reserved full temporal-recursion context. No V2 API accepts a value of
/// this type: it is present so the future authority boundary cannot be added
/// piecemeal or silently omit one of the required bindings.
pub const RequiredContextV2 = struct {
    statement_version: u32,
    session_id: [32]u8,
    parent_vk_id: [32]u8,
    lineage_id: [32]u8,
    statement_id: [32]u8,
    authenticated_context_id: [32]u8,

    pub fn zero() RequiredContextV2 {
        return .{
            .statement_version = 0,
            .session_id = [_]u8{0} ** 32,
            .parent_vk_id = [_]u8{0} ** 32,
            .lineage_id = [_]u8{0} ** 32,
            .statement_id = [_]u8{0} ** 32,
            .authenticated_context_id = [_]u8{0} ** 32,
        };
    }

    pub fn isZero(self: *const RequiredContextV2) bool {
        return self.statement_version == 0 and
            digestIsZero(self.session_id) and
            digestIsZero(self.parent_vk_id) and
            digestIsZero(self.lineage_id) and
            digestIsZero(self.statement_id) and
            digestIsZero(self.authenticated_context_id);
    }
};

pub const ContextAvailabilityV2 = enum(u8) {
    unavailable = 0,
    authenticated = 1,
};

/// Independently produced boundary evidence. The global closure layer does not
/// derive this scalar from its residual; it accepts it only when the source
/// and snapshot exactly match the prepared verifier authority.
pub const BoundaryEvidenceV2 = struct {
    source_authority_id: [32]u8,
    snapshot_id: [32]u8,
    tuple_provenance_id: [32]u8,
    tuple_count: u32,
    claimed_sum: QM31,

    pub fn validateAgainst(
        self: *const BoundaryEvidenceV2,
        source: *const BoundarySourceV2,
    ) Error!void {
        try source.validate();
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
        if (digestIsZero(self.tuple_provenance_id))
            return error.InvalidBoundaryTupleProvenance;
        if (self.tuple_count == 0) return error.InvalidBoundaryTupleCount;
        try requireCanonical(self.claimed_sum);
    }
};

pub fn validateProviderClaimHeader(provider: *const ProviderClaimV1) Error!void {
    if (provider.format_version != PROVIDER_CLAIM_FORMAT_VERSION)
        return error.FormatVersionMismatch;
    if (provider.present != PRESENT) return error.OmittedProvider;
    if (provider.padding != 0 or !allZero(&provider.header_padding))
        return error.InvalidPadding;
    if (provider.row != PROVIDER_ROW) return error.ProviderRowMismatch;
    if (provider.domain != PROVIDER_DOMAIN)
        return error.ProviderDomainMismatch;
}

pub fn requirePreparedAuthority(prepared: *const PreparedAuthorityV1) Error!void {
    if (prepared.state != .validated) return error.AuthorityMismatch;
    try requireDigest(prepared.source_authority_id);
    try requireDigest(prepared.provider_source_authority_id);
    const authority = SourceAuthorityV1.pinned();
    authority.validate() catch return error.AuthorityMismatch;
    if (!std.mem.eql(
        u8,
        &prepared.source_authority_id,
        &authority.identityDigest(),
    ) or !std.mem.eql(
        u8,
        &prepared.provider_source_authority_id,
        &authority.provider_source_authority_id,
    )) return error.AuthorityMismatch;
}

pub fn canonicalRosterPrefixId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(ROSTER_PREFIX_DOMAIN);
    hashInt(&hash, u16, SOURCE_AUTHORITY_FORMAT_VERSION);
    hashInt(&hash, u8, PREFIX_ROW_COUNT);
    for (roster.DESCRIPTORS[0..PREFIX_ROW_COUNT], 0..) |descriptor, index| {
        hashInt(&hash, u8, index);
        hashInt(&hash, u8, @intFromEnum(descriptor.component));
        hashBytes(&hash, descriptor.name);
        hashBytes(&hash, descriptor.reference_owner);
        hashInt(&hash, u8, @intFromEnum(descriptor.status));
        hashInt(&hash, u8, @intFromBool(descriptor.concrete_adapter));
        hashInt(&hash, u8, @intFromBool(descriptor.real_proof_gate));
    }
    return hash.finalResult();
}

pub fn providerClaimIdentity(provider: *const ProviderClaimV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(PROVIDER_CLAIM_ID_DOMAIN);
    hashInt(&hash, u16, provider.format_version);
    hashInt(&hash, u8, provider.present);
    hashInt(&hash, u8, @intFromEnum(provider.row));
    hashInt(&hash, u8, @intFromEnum(provider.domain));
    hash.update(&provider.source_authority_id);
    hash.update(&provider.snapshot_id);
    hashQm31(&hash, provider.claimed_sum);
    return hash.finalResult();
}

pub fn boundarySourceIdentityV2(source: *const BoundarySourceV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BOUNDARY_SOURCE_ID_DOMAIN_V2);
    hashInt(&hash, u16, source.format_version);
    hashInt(&hash, u8, source.present);
    hashInt(&hash, u8, @intFromEnum(source.kind));
    hashInt(&hash, u8, @intFromEnum(source.domain));
    hash.update(&source.source_authority_id);
    hash.update(&source.snapshot_id);
    hash.update(&source.tuple_provenance_id);
    hashInt(&hash, u32, source.tuple_count);
    hashQm31(&hash, source.claimed_sum);
    return hash.finalResult();
}

pub fn requireCanonical(value: QM31) Error!void {
    for (value.toM31Array()) |word|
        if (word.toU32() >= m31.Modulus) return error.NonCanonicalField;
}

pub fn requireDigest(value: [32]u8) Error!void {
    if (digestIsZero(value)) return error.AuthorityMismatch;
}

pub fn digestIsZero(value: [32]u8) bool {
    var aggregate: u8 = 0;
    for (value) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

pub fn hashBytes(hash: anytype, bytes: []const u8) void {
    hashInt(hash, u32, bytes.len);
    hash.update(bytes);
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}
