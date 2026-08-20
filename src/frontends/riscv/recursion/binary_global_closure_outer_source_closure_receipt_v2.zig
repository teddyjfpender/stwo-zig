//! Internal binary global closure outer source authority shard; use binary_global_closure_outer_source.zig publicly.

const dependency_0 = @import("binary_global_closure_outer_source_contract.zig");
const dependency_1 = @import("binary_global_closure_outer_source_public_boundary_claim_v2.zig");

const BoundaryAuthoritiesV2 = dependency_0.BoundaryAuthoritiesV2;
const BoundaryEvidenceV2 = dependency_0.BoundaryEvidenceV2;
const BoundaryKindV2 = dependency_0.BoundaryKindV2;
const BoundarySourceV2 = dependency_0.BoundarySourceV2;
const CLOSURE_ID_DOMAIN = dependency_0.CLOSURE_ID_DOMAIN;
const CLOSURE_ID_DOMAIN_V2 = dependency_0.CLOSURE_ID_DOMAIN_V2;
const CLOSURE_INPUT_FORMAT_VERSION_V2 = dependency_0.CLOSURE_INPUT_FORMAT_VERSION_V2;
const CLOSURE_RECEIPT_FORMAT_VERSION_V2 = dependency_0.CLOSURE_RECEIPT_FORMAT_VERSION_V2;
const ContextSeamV2 = dependency_1.ContextSeamV2;
const DOMAIN_COUNT = dependency_0.DOMAIN_COUNT;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const INPUT_ID_DOMAIN_V2 = dependency_0.INPUT_ID_DOMAIN_V2;
const InputPreflight = dependency_1.InputPreflight;
const PREFIX_ROW_COUNT = dependency_0.PREFIX_ROW_COUNT;
const PRESENT = dependency_0.PRESENT;
const PROVIDER_DOMAIN = dependency_0.PROVIDER_DOMAIN;
const PROVIDER_ROW = dependency_0.PROVIDER_ROW;
const PreparedAuthorityV1 = dependency_0.PreparedAuthorityV1;
const PreparedAuthorityV2 = dependency_1.PreparedAuthorityV2;
const ProviderClaimV1 = dependency_0.ProviderClaimV1;
const PublicBoundariesV2 = dependency_1.PublicBoundariesV2;
const PublicBoundaryClaimV2 = dependency_1.PublicBoundaryClaimV2;
const QM31 = dependency_0.QM31;
const RequiredContextV2 = dependency_0.RequiredContextV2;
const RowClaimsV1 = dependency_0.RowClaimsV1;
const SourceAuthorityV1 = dependency_0.SourceAuthorityV1;
const TOTAL_ROW_COUNT = dependency_0.TOTAL_ROW_COUNT;
const VERIFIER_INPUT_BOUNDARY_DOMAIN = dependency_0.VERIFIER_INPUT_BOUNDARY_DOMAIN;
const WIRE_BOUNDARY_DOMAIN = dependency_0.WIRE_BOUNDARY_DOMAIN;
const Workspace = dependency_1.Workspace;
const allDomainMask = dependency_1.allDomainMask;
const allZero = dependency_0.allZero;
const basePreparedAuthorityV1 = dependency_1.basePreparedAuthorityV1;
const digestIsZero = dependency_0.digestIsZero;
const hashInt = dependency_0.hashInt;
const hashQm31 = dependency_0.hashQm31;
const preflightInputs = dependency_1.preflightInputs;
const prepareAuthorityV2 = dependency_1.prepareAuthorityV2;
const providerDomainBit = dependency_1.providerDomainBit;
const relation = dependency_0.relation;
const requireCanonical = dependency_0.requireCanonical;
const requireCanonicalVector = dependency_1.requireCanonicalVector;
const requireDigest = dependency_0.requireDigest;
const requirePreparedAuthority = dependency_0.requirePreparedAuthority;
const requirePreparedAuthorityV2 = dependency_1.requirePreparedAuthorityV2;
const roster = dependency_0.roster;
const std = dependency_0.std;
const zeroDomainVector = dependency_1.zeroDomainVector;

/// Fully materialized, pointer-free V2 closure input. The inherited V1 input
/// digest seals all 35 rows plus row 35's provider; the V2 identity additionally
/// seals the two independently authenticated public-boundary publications.
pub const ClosureInputV2 = struct {
    format_version: u16 = CLOSURE_INPUT_FORMAT_VERSION_V2,
    present: u8 = PRESENT,
    prefix_row_count: u8 = PREFIX_ROW_COUNT,
    total_row_count: u8 = TOTAL_ROW_COUNT,
    domain_count: u8 = DOMAIN_COUNT,
    padding: [2]u8 = .{ 0, 0 },
    source_authority_id: [32]u8,
    row_input_id: [32]u8,
    rows: [PREFIX_ROW_COUNT]RowClaimsV1,
    provider_claim: ProviderClaimV1,
    public_boundaries: PublicBoundariesV2,
    identity: [32]u8,

    pub fn init(
        prepared: *const PreparedAuthorityV2,
        rows: *const [PREFIX_ROW_COUNT]RowClaimsV1,
        provider: *const ProviderClaimV1,
        public_boundaries: PublicBoundariesV2,
    ) Error!ClosureInputV2 {
        try requirePreparedAuthorityV2(prepared);
        const base = basePreparedAuthorityV1(prepared);
        const preflight = try preflightInputs(&base, rows, provider);
        try public_boundaries.validateAgainst(prepared);
        var result = ClosureInputV2{
            .source_authority_id = prepared.source_authority_id,
            .row_input_id = preflight.input_id,
            .rows = rows.*,
            .provider_claim = provider.*,
            .public_boundaries = public_boundaries,
            .identity = undefined,
        };
        result.identity = closureInputIdentityV2(&result);
        try result.validateAgainst(prepared);
        return result;
    }

    pub fn validateAgainst(
        self: *const ClosureInputV2,
        prepared: *const PreparedAuthorityV2,
    ) Error!void {
        _ = try preflightClosureInputV2(self, prepared);
    }

    pub fn identityDigest(self: *const ClosureInputV2) [32]u8 {
        return closureInputIdentityV2(self);
    }
};

/// Canonical successful result. `prefix_totals` preserves the diagnostic
/// contribution before row 35; `closed_totals` and `framework_total` are
/// required to be exactly zero.
pub const ClosureReceiptV1 = struct {
    format_version: u16,
    prefix_row_count: u8,
    total_row_count: u8,
    domain_count: u8,
    provider_row: roster.Component,
    provider_domain: relation.Domain,
    padding: u8,
    source_authority_id: [32]u8,
    input_id: [32]u8,
    active_domain_mask: u64,
    prefix_totals: [DOMAIN_COUNT]QM31,
    provider_claim: ProviderClaimV1,
    closed_totals: [DOMAIN_COUNT]QM31,
    framework_total: QM31,
    closure_id: [32]u8,

    pub fn fresh() ClosureReceiptV1 {
        return .{
            .format_version = 0,
            .prefix_row_count = 0,
            .total_row_count = 0,
            .domain_count = 0,
            .provider_row = .control,
            .provider_domain = .registers_state,
            .padding = 0,
            .source_authority_id = [_]u8{0} ** 32,
            .input_id = [_]u8{0} ** 32,
            .active_domain_mask = 0,
            .prefix_totals = zeroDomainVector(),
            .provider_claim = .{
                .format_version = 0,
                .present = 0,
                .padding = 0,
                .row = .control,
                .domain = .registers_state,
                .source_authority_id = [_]u8{0} ** 32,
                .snapshot_id = [_]u8{0} ** 32,
                .claimed_sum = QM31.zero(),
                .identity = [_]u8{0} ** 32,
            },
            .closed_totals = zeroDomainVector(),
            .framework_total = QM31.zero(),
            .closure_id = [_]u8{0} ** 32,
        };
    }

    pub fn validate(self: *const ClosureReceiptV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.prefix_row_count != PREFIX_ROW_COUNT or
            self.total_row_count != TOTAL_ROW_COUNT or
            self.domain_count != DOMAIN_COUNT)
        {
            return error.FormatVersionMismatch;
        }
        if (self.provider_row != PROVIDER_ROW) return error.ProviderRowMismatch;
        if (self.provider_domain != PROVIDER_DOMAIN)
            return error.ProviderDomainMismatch;
        if (self.padding != 0) return error.InvalidPadding;
        try requireDigest(self.source_authority_id);
        try requireDigest(self.input_id);
        try requireDigest(self.closure_id);
        const source_authority = SourceAuthorityV1.pinned();
        source_authority.validate() catch return error.AuthorityMismatch;
        if (!std.mem.eql(
            u8,
            &self.source_authority_id,
            &source_authority.identityDigest(),
        )) return error.AuthorityMismatch;
        try self.provider_claim.validate();
        try requireCanonicalVector(&self.prefix_totals);
        try requireCanonicalVector(&self.closed_totals);
        try requireCanonical(self.framework_total);
        if (self.active_domain_mask & ~allDomainMask() != 0)
            return error.AuthorityMismatch;
        if (self.active_domain_mask & providerDomainBit() == 0)
            return error.AuthorityMismatch;

        var expected_closed = self.prefix_totals;
        const provider_index = @intFromEnum(PROVIDER_DOMAIN);
        expected_closed[provider_index] = expected_closed[provider_index].add(
            self.provider_claim.claimed_sum,
        );
        for (expected_closed, self.closed_totals) |expected, actual| {
            if (!expected.eql(actual)) return error.AuthorityMismatch;
            if (!actual.isZero()) return error.RelationNotClosed;
        }
        if (!self.framework_total.isZero()) return error.RelationNotClosed;
        if (!std.mem.eql(u8, &self.closure_id, &closureIdentity(self)))
            return error.AuthorityMismatch;
    }
};

/// Canonical V2 result. The two public claims are retained with their complete
/// tuple provenance, and the reserved temporal context remains explicitly
/// unavailable. Successful substrate closure is therefore not equivalent to
/// temporal-recursion admission.
pub const ClosureReceiptV2 = struct {
    format_version: u16,
    prefix_row_count: u8,
    total_row_count: u8,
    domain_count: u8,
    provider_row: roster.Component,
    provider_domain: relation.Domain,
    wire_boundary_domain: relation.Domain,
    verifier_input_boundary_domain: relation.Domain,
    padding: [3]u8,
    source_authority_id: [32]u8,
    input_id: [32]u8,
    active_domain_mask: u64,
    prefix_totals: [DOMAIN_COUNT]QM31,
    provider_claim: ProviderClaimV1,
    public_boundaries: PublicBoundariesV2,
    context_seam: ContextSeamV2,
    closed_totals: [DOMAIN_COUNT]QM31,
    framework_total: QM31,
    closure_id: [32]u8,

    pub fn fresh() ClosureReceiptV2 {
        return .{
            .format_version = 0,
            .prefix_row_count = 0,
            .total_row_count = 0,
            .domain_count = 0,
            .provider_row = .control,
            .provider_domain = .registers_state,
            .wire_boundary_domain = .registers_state,
            .verifier_input_boundary_domain = .registers_state,
            .padding = .{ 0, 0, 0 },
            .source_authority_id = [_]u8{0} ** 32,
            .input_id = [_]u8{0} ** 32,
            .active_domain_mask = 0,
            .prefix_totals = zeroDomainVector(),
            .provider_claim = zeroProviderClaimV1(),
            .public_boundaries = zeroPublicBoundariesV2(),
            .context_seam = zeroContextSeamV2(),
            .closed_totals = zeroDomainVector(),
            .framework_total = QM31.zero(),
            .closure_id = [_]u8{0} ** 32,
        };
    }

    pub fn validate(self: *const ClosureReceiptV2) Error!void {
        if (self.format_version != CLOSURE_RECEIPT_FORMAT_VERSION_V2 or
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
        try requireDigest(self.source_authority_id);
        try requireDigest(self.input_id);
        try requireDigest(self.closure_id);
        try self.provider_claim.validate();
        try self.public_boundaries.validate();

        const boundary_authorities = try BoundaryAuthoritiesV2.init(
            try BoundarySourceV2.init(
                .wire,
                boundaryEvidenceFromClaimV2(&self.public_boundaries.wire),
            ),
            try BoundarySourceV2.init(
                .verifier_input,
                boundaryEvidenceFromClaimV2(
                    &self.public_boundaries.verifier_input,
                ),
            ),
        );
        const prepared = try prepareAuthorityV2(boundary_authorities);
        if (!std.mem.eql(
            u8,
            &self.source_authority_id,
            &prepared.source_authority_id,
        )) return error.AuthorityMismatch;
        if (!std.mem.eql(
            u8,
            &self.provider_claim.source_authority_id,
            &prepared.provider_source_authority_id,
        )) return error.ProviderAuthorityMismatch;
        try self.public_boundaries.validateAgainst(&prepared);
        try self.context_seam.validateCurrent();
        if (!std.meta.eql(self.context_seam, prepared.context_seam))
            return error.TemporalContextAuthorityUnavailable;

        try requireCanonicalVector(&self.prefix_totals);
        try requireCanonicalVector(&self.closed_totals);
        try requireCanonical(self.framework_total);
        if (self.active_domain_mask & ~allDomainMask() != 0)
            return error.AuthorityMismatch;
        const required_mask = providerDomainBit() |
            boundaryDomainBit(WIRE_BOUNDARY_DOMAIN) |
            boundaryDomainBit(VERIFIER_INPUT_BOUNDARY_DOMAIN);
        if (self.active_domain_mask & required_mask != required_mask)
            return error.AuthorityMismatch;

        var expected_closed = self.prefix_totals;
        expected_closed[@intFromEnum(PROVIDER_DOMAIN)] =
            expected_closed[@intFromEnum(PROVIDER_DOMAIN)].add(
                self.provider_claim.claimed_sum,
            );
        expected_closed[@intFromEnum(WIRE_BOUNDARY_DOMAIN)] =
            expected_closed[@intFromEnum(WIRE_BOUNDARY_DOMAIN)].add(
                self.public_boundaries.wire.claimed_sum,
            );
        expected_closed[@intFromEnum(VERIFIER_INPUT_BOUNDARY_DOMAIN)] =
            expected_closed[@intFromEnum(VERIFIER_INPUT_BOUNDARY_DOMAIN)].add(
                self.public_boundaries.verifier_input.claimed_sum,
            );
        for (expected_closed, self.closed_totals) |expected, actual| {
            if (!expected.eql(actual)) return error.AuthorityMismatch;
            if (!actual.isZero()) return error.RelationNotClosed;
        }

        var expected_framework_total = QM31.zero();
        for (self.prefix_totals) |value|
            expected_framework_total = expected_framework_total.add(value);
        expected_framework_total = expected_framework_total
            .add(self.provider_claim.claimed_sum)
            .add(self.public_boundaries.claimedSum());
        if (!expected_framework_total.eql(self.framework_total))
            return error.AuthorityMismatch;
        if (!self.framework_total.isZero()) return error.RelationNotClosed;
        if (!std.mem.eql(u8, &self.closure_id, &closureIdentityV2(self)))
            return error.AuthorityMismatch;
    }

    pub fn requireTemporalContext(self: *const ClosureReceiptV2) Error!RequiredContextV2 {
        try self.validate();
        return self.context_seam.requireTemporalContext();
    }
};

/// Allocation-free hot fill. The destination must equal `ClosureReceiptV1.fresh()`.
/// No destination field is written until every validation and closure check
/// has succeeded.
pub fn fillInto(
    workspace: *Workspace,
    prepared: *const PreparedAuthorityV1,
    rows: []const RowClaimsV1,
    provider: *const ProviderClaimV1,
    destination: *ClosureReceiptV1,
) Error!void {
    try rejectAliases(workspace, prepared, rows, provider, destination);
    if (!std.meta.eql(destination.*, ClosureReceiptV1.fresh()))
        return error.DestinationNotFresh;
    try workspace.validate();
    try requirePreparedAuthority(prepared);
    const preflight = try preflightInputs(prepared, rows, provider);

    workspace.reset(preflight.active_domain_mask);
    for (rows) |row| {
        for (row.domains, 0..) |claim, domain_index| {
            workspace.prefix_totals[domain_index] =
                workspace.prefix_totals[domain_index].add(claim.value);
        }
        workspace.framework_total = workspace.framework_total.add(row.claimed_sum);
    }
    workspace.closed_totals = workspace.prefix_totals;
    const provider_index = @intFromEnum(PROVIDER_DOMAIN);
    workspace.closed_totals[provider_index] =
        workspace.closed_totals[provider_index].add(provider.claimed_sum);
    workspace.framework_total = workspace.framework_total.add(provider.claimed_sum);

    for (workspace.closed_totals) |value|
        if (!value.isZero()) return error.RelationNotClosed;
    if (!workspace.framework_total.isZero()) return error.RelationNotClosed;

    var receipt = ClosureReceiptV1{
        .format_version = FORMAT_VERSION,
        .prefix_row_count = PREFIX_ROW_COUNT,
        .total_row_count = TOTAL_ROW_COUNT,
        .domain_count = DOMAIN_COUNT,
        .provider_row = PROVIDER_ROW,
        .provider_domain = PROVIDER_DOMAIN,
        .padding = 0,
        .source_authority_id = prepared.source_authority_id,
        .input_id = preflight.input_id,
        .active_domain_mask = preflight.active_domain_mask,
        .prefix_totals = workspace.prefix_totals,
        .provider_claim = provider.*,
        .closed_totals = workspace.closed_totals,
        .framework_total = workspace.framework_total,
        .closure_id = undefined,
    };
    receipt.closure_id = closureIdentity(&receipt);
    try receipt.validate();
    destination.* = receipt;
}

pub fn preflightClosureInputV2(
    input: *const ClosureInputV2,
    prepared: *const PreparedAuthorityV2,
) Error!InputPreflight {
    if (input.format_version != CLOSURE_INPUT_FORMAT_VERSION_V2 or
        input.prefix_row_count != PREFIX_ROW_COUNT or
        input.total_row_count != TOTAL_ROW_COUNT or
        input.domain_count != DOMAIN_COUNT)
    {
        return error.FormatVersionMismatch;
    }
    if (input.present != PRESENT) return error.OmittedRow;
    if (!allZero(&input.padding)) return error.InvalidPadding;
    try requirePreparedAuthorityV2(prepared);
    if (!std.mem.eql(
        u8,
        &input.source_authority_id,
        &prepared.source_authority_id,
    )) return error.AuthorityMismatch;
    const base = basePreparedAuthorityV1(prepared);
    const preflight = try preflightInputs(
        &base,
        &input.rows,
        &input.provider_claim,
    );
    if (!std.mem.eql(u8, &input.row_input_id, &preflight.input_id))
        return error.InvalidInputIdentity;
    try input.public_boundaries.validateAgainst(prepared);
    if (digestIsZero(input.identity) or !std.mem.eql(
        u8,
        &input.identity,
        &closureInputIdentityV2(input),
    )) return error.InvalidInputIdentity;
    return preflight;
}

pub fn boundaryEvidenceFromClaimV2(
    claim: *const PublicBoundaryClaimV2,
) BoundaryEvidenceV2 {
    return .{
        .source_authority_id = claim.source_authority_id,
        .snapshot_id = claim.snapshot_id,
        .tuple_provenance_id = claim.tuple_provenance_id,
        .tuple_count = claim.tuple_count,
        .claimed_sum = claim.claimed_sum,
    };
}

pub fn closureInputIdentityV2(input: *const ClosureInputV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(INPUT_ID_DOMAIN_V2);
    hashInt(&hash, u16, input.format_version);
    hashInt(&hash, u8, input.present);
    hashInt(&hash, u8, input.prefix_row_count);
    hashInt(&hash, u8, input.total_row_count);
    hashInt(&hash, u8, input.domain_count);
    hash.update(&input.source_authority_id);
    hash.update(&input.row_input_id);
    hash.update(&input.provider_claim.identity);
    hash.update(&input.public_boundaries.identity);
    return hash.finalResult();
}

pub fn closureIdentity(receipt: *const ClosureReceiptV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_ID_DOMAIN);
    hashInt(&hash, u16, receipt.format_version);
    hashInt(&hash, u8, receipt.prefix_row_count);
    hashInt(&hash, u8, receipt.total_row_count);
    hashInt(&hash, u8, receipt.domain_count);
    hashInt(&hash, u8, @intFromEnum(receipt.provider_row));
    hashInt(&hash, u8, @intFromEnum(receipt.provider_domain));
    hash.update(&receipt.source_authority_id);
    hash.update(&receipt.input_id);
    hashInt(&hash, u64, receipt.active_domain_mask);
    for (receipt.prefix_totals) |value| hashQm31(&hash, value);
    hash.update(&receipt.provider_claim.identity);
    for (receipt.closed_totals) |value| hashQm31(&hash, value);
    hashQm31(&hash, receipt.framework_total);
    return hash.finalResult();
}

pub fn closureIdentityV2(receipt: *const ClosureReceiptV2) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CLOSURE_ID_DOMAIN_V2);
    hashInt(&hash, u16, receipt.format_version);
    hashInt(&hash, u8, receipt.prefix_row_count);
    hashInt(&hash, u8, receipt.total_row_count);
    hashInt(&hash, u8, receipt.domain_count);
    hashInt(&hash, u8, @intFromEnum(receipt.provider_row));
    hashInt(&hash, u8, @intFromEnum(receipt.provider_domain));
    hashInt(&hash, u8, @intFromEnum(receipt.wire_boundary_domain));
    hashInt(
        &hash,
        u8,
        @intFromEnum(receipt.verifier_input_boundary_domain),
    );
    hash.update(&receipt.source_authority_id);
    hash.update(&receipt.input_id);
    hashInt(&hash, u64, receipt.active_domain_mask);
    for (receipt.prefix_totals) |value| hashQm31(&hash, value);
    hash.update(&receipt.provider_claim.identity);
    hash.update(&receipt.public_boundaries.identity);
    hash.update(&receipt.context_seam.identity);
    for (receipt.closed_totals) |value| hashQm31(&hash, value);
    hashQm31(&hash, receipt.framework_total);
    return hash.finalResult();
}

pub fn rejectAliases(
    workspace: *Workspace,
    prepared: *const PreparedAuthorityV1,
    rows: []const RowClaimsV1,
    provider: *const ProviderClaimV1,
    destination: *ClosureReceiptV1,
) Error!void {
    const workspace_range = try objectRange(workspace);
    const prepared_range = try objectRange(prepared);
    const provider_range = try objectRange(provider);
    const destination_range = try objectRange(destination);
    const rows_range = try sliceRange(RowClaimsV1, rows);

    if (workspace_range.overlaps(destination_range) or
        workspace_range.overlaps(prepared_range) or
        workspace_range.overlaps(provider_range) or
        (rows_range != null and workspace_range.overlaps(rows_range.?)))
    {
        return error.AliasedWorkspace;
    }
    if (destination_range.overlaps(prepared_range) or
        destination_range.overlaps(provider_range) or
        (rows_range != null and destination_range.overlaps(rows_range.?)))
    {
        return error.AliasedDestination;
    }
}

pub fn rejectAliasesV2(
    workspace: *Workspace,
    prepared: *const PreparedAuthorityV2,
    input: *const ClosureInputV2,
    destination: *ClosureReceiptV2,
) Error!void {
    const workspace_range = try objectRange(workspace);
    const prepared_range = try objectRange(prepared);
    const input_range = try objectRange(input);
    const destination_range = try objectRange(destination);
    if (workspace_range.overlaps(destination_range) or
        workspace_range.overlaps(prepared_range) or
        workspace_range.overlaps(input_range))
    {
        return error.AliasedWorkspace;
    }
    if (destination_range.overlaps(prepared_range) or
        destination_range.overlaps(input_range))
    {
        return error.AliasedDestination;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn objectRange(pointer: anytype) Error!AddressRange {
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(@TypeOf(pointer.*))) catch
            return error.AddressOverflow,
    };
}

pub fn sliceRange(comptime T: type, values: []const T) Error!?AddressRange {
    if (values.len == 0) return null;
    const byte_count = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.AddressOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, byte_count) catch
            return error.AddressOverflow,
    };
}

pub fn zeroProviderClaimV1() ProviderClaimV1 {
    return .{
        .format_version = 0,
        .present = 0,
        .padding = 0,
        .row = .control,
        .domain = .registers_state,
        .source_authority_id = [_]u8{0} ** 32,
        .snapshot_id = [_]u8{0} ** 32,
        .claimed_sum = QM31.zero(),
        .identity = [_]u8{0} ** 32,
    };
}

pub fn zeroBoundaryClaimV2(kind: BoundaryKindV2) PublicBoundaryClaimV2 {
    return .{
        .format_version = 0,
        .present = 0,
        .kind = kind,
        .domain = .registers_state,
        .source_authority_id = [_]u8{0} ** 32,
        .snapshot_id = [_]u8{0} ** 32,
        .tuple_provenance_id = [_]u8{0} ** 32,
        .tuple_count = 0,
        .claimed_sum = QM31.zero(),
        .identity = [_]u8{0} ** 32,
    };
}

pub fn zeroPublicBoundariesV2() PublicBoundariesV2 {
    return .{
        .format_version = 0,
        .present = 0,
        .padding = 0,
        .wire = zeroBoundaryClaimV2(.wire),
        .verifier_input = zeroBoundaryClaimV2(.verifier_input),
        .identity = [_]u8{0} ** 32,
    };
}

pub fn zeroContextSeamV2() ContextSeamV2 {
    return .{
        .format_version = 0,
        .present = 0,
        .availability = .unavailable,
        .padding = .{ 0, 0, 0, 0 },
        .required = RequiredContextV2.zero(),
        .identity = [_]u8{0} ** 32,
    };
}

pub fn boundaryDomainBit(domain: relation.Domain) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
}
