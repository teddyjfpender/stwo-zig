const std = @import("std");
const stwo_core = @import("stwo_core");

const m31 = stwo_core.fields.m31;
const QM31 = stwo_core.fields.qm31.QM31;

const owner = @import("binary_global_closure_outer_source.zig");
const relation = @import("../air/lang/relation.zig");
const roster = @import("air/universal_roster.zig");

const GOLDEN_SOURCE_AUTHORITY_ID = comptimeHex32(
    "0d6b5747e08c9c39849b4b875685c0e48aa691ea1952171f23005e40fae79e69",
);
const GOLDEN_INPUT_ID = comptimeHex32(
    "6eb550f354ffb92be90ca1bfb820f44ef398222545e89e22a8fdfc7e82d7896b",
);
const GOLDEN_CLOSURE_ID = comptimeHex32(
    "99132c5dbf0cf653bf5beff30aeb8ac866cf5c25780bb3c9ab20af66a58d1126",
);

test "binary global closure authenticates every ordered row and domain" {
    const fixture = try Fixture.init();
    var workspace = owner.Workspace.init();
    var receipt = owner.ClosureReceiptV1.fresh();
    try owner.fillInto(
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &fixture.provider,
        &receipt,
    );
    try receipt.validate();

    const range_index = @intFromEnum(relation.Domain.range_check_8_8);
    try std.testing.expect(receipt.prefix_totals[range_index].eql(RANGE_VALUE));
    for (receipt.closed_totals) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(receipt.framework_total.isZero());
    const expected_mask = domainBit(.range_check_8_8) |
        domainBit(.poseidon2) |
        domainBit(.recursion_wire) |
        domainBit(.recursion_step);
    try std.testing.expectEqual(expected_mask, receipt.active_domain_mask);
    try std.testing.expectEqual(fixture.provider, receipt.provider_claim);
    try std.testing.expect(!owner.WHOLE_FRONTEND_VERIFIED);
    try std.testing.expect(!owner.PARENT_PROOF_VERIFICATION);
    try std.testing.expect(!owner.PARENT_PROOF_PRODUCTION);
    try std.testing.expect(!owner.PRODUCTION_ACTIVATION);

    const authority = owner.SourceAuthorityV1.pinned();
    try authority.validate();
    try std.testing.expectEqual(GOLDEN_SOURCE_AUTHORITY_ID, authority.identityDigest());
    try std.testing.expectEqual(GOLDEN_INPUT_ID, receipt.input_id);
    try std.testing.expectEqual(GOLDEN_CLOSURE_ID, receipt.closure_id);
}

test "binary global closure rejects row and domain structural mutations" {
    const fixture = try Fixture.init();
    var workspace = owner.Workspace.init();

    try expectFailureAtomic(
        error.RowCountMismatch,
        &workspace,
        &fixture.prepared,
        fixture.rows[0 .. owner.PREFIX_ROW_COUNT - 1],
        &fixture.provider,
    );

    var rows = fixture.rows;
    rows[1].row = rows[0].row;
    try expectFailureAtomic(
        error.DuplicateRow,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    std.mem.swap(owner.RowClaimsV1, &rows[0], &rows[1]);
    try expectFailureAtomic(
        error.RowOrderMismatch,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    rows[2].present = 0;
    try expectFailureAtomic(
        error.OmittedRow,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    rows[3].domains[0].domain = .memory_access;
    try expectFailureAtomic(
        error.DuplicateDomain,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    std.mem.swap(
        owner.DomainClaimV1,
        &rows[4].domains[0],
        &rows[4].domains[1],
    );
    try expectFailureAtomic(
        error.DomainOrderMismatch,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    rows[5].domains[5].present = 0;
    try expectFailureAtomic(
        error.OmittedDomain,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    rows[6].domains[6].active = 2;
    try expectFailureAtomic(
        error.InvalidActiveFlag,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    const wire_index = @intFromEnum(relation.Domain.recursion_wire);
    rows[0].domains[wire_index].active = 0;
    try expectFailureAtomic(
        error.InactiveDomainNonZero,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );
}

test "binary global closure rejects field authority and corrective-provider mutations" {
    const fixture = try Fixture.init();
    var workspace = owner.Workspace.init();
    var rows = fixture.rows;

    rows[0].claimed_sum = rows[0].claimed_sum.add(QM31.one());
    try expectFailureAtomic(
        error.RowClaimMismatch,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    rows = fixture.rows;
    rows[0].domains[@intFromEnum(relation.Domain.recursion_wire)].value =
        nonCanonicalQm31();
    try expectFailureAtomic(
        error.NonCanonicalField,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    var provider = fixture.provider;
    provider.present = 0;
    try expectFailureAtomic(
        error.OmittedProvider,
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &provider,
    );

    provider = fixture.provider;
    provider.domain = .recursion_wire;
    try expectFailureAtomic(
        error.ProviderDomainMismatch,
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &provider,
    );

    provider = fixture.provider;
    provider.row = .poseidon2;
    try expectFailureAtomic(
        error.ProviderRowMismatch,
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &provider,
    );

    provider = fixture.provider;
    provider.source_authority_id[0] ^= 1;
    provider.identity = provider.identityDigest();
    try expectFailureAtomic(
        error.ProviderAuthorityMismatch,
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &provider,
    );

    var prepared = fixture.prepared;
    prepared.source_authority_id[0] ^= 1;
    try expectFailureAtomic(
        error.AuthorityMismatch,
        &workspace,
        &prepared,
        &fixture.rows,
        &fixture.provider,
    );

    prepared = fixture.prepared;
    prepared.provider_source_authority_id[0] ^= 1;
    try expectFailureAtomic(
        error.AuthorityMismatch,
        &workspace,
        &prepared,
        &fixture.rows,
        &fixture.provider,
    );

    provider = fixture.provider;
    provider.claimed_sum = nonCanonicalQm31();
    provider.identity = provider.identityDigest();
    try expectFailureAtomic(
        error.NonCanonicalField,
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &provider,
    );

    // A range-provider claim may not be repurposed as an arbitrary correction
    // for a residual in a different domain. Both residuals remain visible.
    rows = fixture.rows;
    const delta = qm31(1, 2, 3, 4);
    const wire_index = @intFromEnum(relation.Domain.recursion_wire);
    rows[0].domains[wire_index].value =
        rows[0].domains[wire_index].value.add(delta);
    recomputeRowClaim(&rows[0]);
    provider = try owner.ProviderClaimV1.init(
        &fixture.prepared,
        fixture.provider.snapshot_id,
        fixture.provider.claimed_sum.add(delta.neg()),
    );
    try expectFailureAtomic(
        error.RelationNotClosed,
        &workspace,
        &fixture.prepared,
        &rows,
        &provider,
    );
}

test "binary global closure is alias-safe and rejects late failure atomically" {
    const fixture = try Fixture.init();
    var workspace = owner.Workspace.init();

    var rows = fixture.rows;
    const delta = qm31(9, 8, 7, 6);
    const step_index = @intFromEnum(relation.Domain.recursion_step);
    rows[17].domains[step_index].value =
        rows[17].domains[step_index].value.add(delta);
    recomputeRowClaim(&rows[17]);
    try expectFailureAtomic(
        error.RelationNotClosed,
        &workspace,
        &fixture.prepared,
        &rows,
        &fixture.provider,
    );

    var nonfresh = owner.ClosureReceiptV1.fresh();
    nonfresh.format_version = owner.FORMAT_VERSION;
    const before_nonfresh = nonfresh;
    try std.testing.expectError(
        error.DestinationNotFresh,
        owner.fillInto(
            &workspace,
            &fixture.prepared,
            &fixture.rows,
            &fixture.provider,
            &nonfresh,
        ),
    );
    try std.testing.expectEqualDeep(before_nonfresh, nonfresh);

    const rows_alignment = @alignOf([owner.PREFIX_ROW_COUNT]owner.RowClaimsV1);
    const receipt_alignment = @alignOf(owner.ClosureReceiptV1);
    var destination_alias_storage: [
        @max(
            @sizeOf([owner.PREFIX_ROW_COUNT]owner.RowClaimsV1),
            @sizeOf(owner.ClosureReceiptV1),
        )
    ]u8 align(@max(rows_alignment, receipt_alignment)) = undefined;
    const alias_rows: *[owner.PREFIX_ROW_COUNT]owner.RowClaimsV1 =
        @ptrCast(&destination_alias_storage);
    alias_rows.* = fixture.rows;
    const alias_destination: *owner.ClosureReceiptV1 =
        @ptrCast(&destination_alias_storage);
    try std.testing.expectError(
        error.AliasedDestination,
        owner.fillInto(
            &workspace,
            &fixture.prepared,
            alias_rows,
            &fixture.provider,
            alias_destination,
        ),
    );

    const workspace_alignment = @alignOf(owner.Workspace);
    var workspace_alias_storage: [
        @max(
            @sizeOf([owner.PREFIX_ROW_COUNT]owner.RowClaimsV1),
            @sizeOf(owner.Workspace),
        )
    ]u8 align(@max(rows_alignment, workspace_alignment)) = undefined;
    const aliased_workspace: *owner.Workspace = @ptrCast(&workspace_alias_storage);
    const workspace_rows: *[owner.PREFIX_ROW_COUNT]owner.RowClaimsV1 =
        @ptrCast(&workspace_alias_storage);
    workspace_rows.* = fixture.rows;
    var fresh = owner.ClosureReceiptV1.fresh();
    try std.testing.expectError(
        error.AliasedWorkspace,
        owner.fillInto(
            aliased_workspace,
            &fixture.prepared,
            workspace_rows,
            &fixture.provider,
            &fresh,
        ),
    );
}

test "binary global closure retained workspace has exact zero-allocation fills" {
    const fixture = try Fixture.init();
    var workspace = owner.Workspace.init();
    var first = owner.ClosureReceiptV1.fresh();
    var second = owner.ClosureReceiptV1.fresh();

    try owner.fillInto(
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &fixture.provider,
        &first,
    );
    try owner.fillInto(
        &workspace,
        &fixture.prepared,
        &fixture.rows,
        &fixture.provider,
        &second,
    );
    try std.testing.expectEqualDeep(first, second);
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV1.authority_preparation_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV1.workspace_initialization_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV1.fresh_hot_fill_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV1.reused_hot_fill_heap_allocations,
    );
}

test "binary global closure V2 binds authenticated public boundaries" {
    const fixture = try FixtureV2.init();
    var workspace = owner.Workspace.init();
    var receipt = owner.ClosureReceiptV2.fresh();
    try owner.fillIntoV2(
        &workspace,
        &fixture.prepared,
        &fixture.input,
        &receipt,
    );
    try receipt.validate();

    const wire_index = @intFromEnum(owner.WIRE_BOUNDARY_DOMAIN);
    const verifier_input_index =
        @intFromEnum(owner.VERIFIER_INPUT_BOUNDARY_DOMAIN);
    try std.testing.expect(
        receipt.prefix_totals[wire_index].eql(WIRE_BOUNDARY_VALUE),
    );
    try std.testing.expect(
        receipt.prefix_totals[verifier_input_index].eql(
            VERIFIER_INPUT_BOUNDARY_VALUE,
        ),
    );
    for (receipt.closed_totals) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(receipt.framework_total.isZero());
    try std.testing.expectEqual(
        fixture.input.identity,
        receipt.input_id,
    );
    try std.testing.expectEqual(
        fixture.input.public_boundaries,
        receipt.public_boundaries,
    );
    try std.testing.expectEqual(
        fixture.prepared.context_seam,
        receipt.context_seam,
    );
    try std.testing.expectEqual(
        owner.ContextAvailabilityV2.unavailable,
        receipt.context_seam.availability,
    );
    try std.testing.expect(receipt.context_seam.required.isZero());
    try std.testing.expectError(
        error.TemporalContextAuthorityUnavailable,
        receipt.requireTemporalContext(),
    );

    const expected_mask = domainBit(.range_check_8_8) |
        domainBit(.poseidon2) |
        domainBit(.recursion_wire) |
        domainBit(.recursion_step) |
        domainBit(.recursion_verifier_input_word);
    try std.testing.expectEqual(expected_mask, receipt.active_domain_mask);
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV2.authority_preparation_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV2.input_preparation_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV2.fresh_hot_fill_heap_allocations,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        owner.AllocationLedgerV2.reused_hot_fill_heap_allocations,
    );
}

test "binary global closure V2 rejects stale or corrective boundary evidence" {
    const fixture = try FixtureV2.init();

    var evidence = fixture.wire_evidence;
    evidence.source_authority_id[0] ^= 1;
    try std.testing.expectError(
        error.BoundaryAuthorityMismatch,
        owner.PublicBoundaryClaimV2.init(
            &fixture.prepared,
            .wire,
            evidence,
        ),
    );

    evidence = fixture.wire_evidence;
    evidence.snapshot_id[0] ^= 1;
    try std.testing.expectError(
        error.BoundarySnapshotMismatch,
        owner.PublicBoundaryClaimV2.init(
            &fixture.prepared,
            .wire,
            evidence,
        ),
    );

    evidence = fixture.wire_evidence;
    evidence.tuple_provenance_id[0] ^= 1;
    try std.testing.expectError(
        error.InvalidBoundaryTupleProvenance,
        owner.PublicBoundaryClaimV2.init(
            &fixture.prepared,
            .wire,
            evidence,
        ),
    );

    evidence = fixture.wire_evidence;
    evidence.tuple_count += 1;
    try std.testing.expectError(
        error.InvalidBoundaryTupleCount,
        owner.PublicBoundaryClaimV2.init(
            &fixture.prepared,
            .wire,
            evidence,
        ),
    );

    // Even a fully resealed scalar cannot be changed after the independently
    // authenticated source was prepared. This is the critical distinction
    // from computing a convenient negation of the observed closure residual.
    var input = fixture.input;
    input.public_boundaries.wire.claimed_sum =
        input.public_boundaries.wire.claimed_sum.add(QM31.one());
    input.public_boundaries.wire.identity =
        input.public_boundaries.wire.identityDigest();
    input.public_boundaries.identity =
        input.public_boundaries.identityDigest();
    input.identity = input.identityDigest();
    var workspace = owner.Workspace.init();
    try expectFailureAtomicV2(
        error.BoundaryClaimMismatch,
        &workspace,
        &fixture.prepared,
        &input,
    );

    input = fixture.input;
    input.public_boundaries.wire.kind = .verifier_input;
    try expectFailureAtomicV2(
        error.BoundaryKindMismatch,
        &workspace,
        &fixture.prepared,
        &input,
    );

    input = fixture.input;
    input.public_boundaries.wire.domain =
        owner.VERIFIER_INPUT_BOUNDARY_DOMAIN;
    try expectFailureAtomicV2(
        error.BoundaryDomainMismatch,
        &workspace,
        &fixture.prepared,
        &input,
    );

    input = fixture.input;
    input.identity[0] ^= 1;
    try expectFailureAtomicV2(
        error.InvalidInputIdentity,
        &workspace,
        &fixture.prepared,
        &input,
    );
}

test "binary global closure V2 cannot move a boundary across domains" {
    const fixture = try FixtureV2.init();
    var rows = fixture.input.rows;
    const delta = qm31(71, 73, 79, 83);
    const step_index = @intFromEnum(relation.Domain.recursion_step);
    rows[12].domains[step_index].active = 1;
    rows[12].domains[step_index].value =
        rows[12].domains[step_index].value.add(delta);
    recomputeRowClaim(&rows[12]);
    const changed_input = try owner.ClosureInputV2.init(
        &fixture.prepared,
        &rows,
        &fixture.input.provider_claim,
        fixture.input.public_boundaries,
    );
    var workspace = owner.Workspace.init();
    try expectFailureAtomicV2(
        error.RelationNotClosed,
        &workspace,
        &fixture.prepared,
        &changed_input,
    );

    const input_alignment = @alignOf(owner.ClosureInputV2);
    const receipt_alignment = @alignOf(owner.ClosureReceiptV2);
    var destination_alias_storage: [
        @max(
            @sizeOf(owner.ClosureInputV2),
            @sizeOf(owner.ClosureReceiptV2),
        )
    ]u8 align(@max(input_alignment, receipt_alignment)) = undefined;
    const aliased_input: *owner.ClosureInputV2 =
        @ptrCast(&destination_alias_storage);
    aliased_input.* = fixture.input;
    const aliased_destination: *owner.ClosureReceiptV2 =
        @ptrCast(&destination_alias_storage);
    try std.testing.expectError(
        error.AliasedDestination,
        owner.fillIntoV2(
            &workspace,
            &fixture.prepared,
            aliased_input,
            aliased_destination,
        ),
    );
}

test "binary global closure V2 reserves temporal context fail closed" {
    const fixture = try FixtureV2.init();
    var workspace = owner.Workspace.init();
    var receipt = owner.ClosureReceiptV2.fresh();
    try owner.fillIntoV2(
        &workspace,
        &fixture.prepared,
        &fixture.input,
        &receipt,
    );

    var unavailable_with_data = receipt;
    unavailable_with_data.context_seam.required.statement_version = 1;
    unavailable_with_data.context_seam.required.session_id =
        digest("caller-session-must-not-be-admitted");
    unavailable_with_data.context_seam.identity =
        unavailable_with_data.context_seam.identityDigest();
    try std.testing.expectError(
        error.UnavailableContextNotZero,
        unavailable_with_data.validate(),
    );

    var fabricated = receipt;
    fabricated.context_seam.availability = .authenticated;
    fabricated.context_seam.required = .{
        .statement_version = 1,
        .session_id = digest("session"),
        .parent_vk_id = digest("parent-vk"),
        .lineage_id = digest("lineage"),
        .statement_id = digest("statement"),
        .authenticated_context_id = digest("authenticated-context"),
    };
    fabricated.context_seam.identity = fabricated.context_seam.identityDigest();
    try std.testing.expectError(
        error.TemporalContextAuthorityUnavailable,
        fabricated.validate(),
    );
}

const RANGE_VALUE = qm31(19, 23, 29, 31);
const WIRE_BOUNDARY_VALUE = qm31(89, 97, 101, 103);
const VERIFIER_INPUT_BOUNDARY_VALUE = qm31(107, 109, 113, 127);

const Fixture = struct {
    prepared: owner.PreparedAuthorityV1,
    rows: [owner.PREFIX_ROW_COUNT]owner.RowClaimsV1,
    provider: owner.ProviderClaimV1,

    fn init() !Fixture {
        const prepared = try owner.prepareAuthority();
        var rows: [owner.PREFIX_ROW_COUNT]owner.RowClaimsV1 = undefined;
        for (&rows, 0..) |*row, row_index| row.* = emptyRow(@enumFromInt(row_index));

        setDomain(&rows[0], .recursion_wire, qm31(3, 5, 7, 11));
        setDomain(&rows[1], .recursion_wire, qm31(3, 5, 7, 11).neg());
        setDomain(&rows[10], .range_check_8_8, RANGE_VALUE);
        setDomain(&rows[17], .recursion_step, qm31(37, 41, 43, 47));
        setDomain(&rows[18], .recursion_step, qm31(37, 41, 43, 47).neg());
        setDomain(&rows[20], .poseidon2, qm31(53, 59, 61, 67));
        setDomain(&rows[34], .poseidon2, qm31(53, 59, 61, 67).neg());
        for (&rows) |*row| recomputeRowClaim(row);

        const provider = try owner.ProviderClaimV1.init(
            &prepared,
            digest("authenticated-binary-range-provider-snapshot"),
            RANGE_VALUE.neg(),
        );
        return .{
            .prepared = prepared,
            .rows = rows,
            .provider = provider,
        };
    }
};

const FixtureV2 = struct {
    prepared: owner.PreparedAuthorityV2,
    wire_evidence: owner.BoundaryEvidenceV2,
    verifier_input_evidence: owner.BoundaryEvidenceV2,
    input: owner.ClosureInputV2,

    fn init() !FixtureV2 {
        const base = try Fixture.init();
        var rows = base.rows;
        setDomain(&rows[2], .recursion_wire, WIRE_BOUNDARY_VALUE);
        setDomain(
            &rows[3],
            .recursion_verifier_input_word,
            VERIFIER_INPUT_BOUNDARY_VALUE,
        );
        recomputeRowClaim(&rows[2]);
        recomputeRowClaim(&rows[3]);

        const wire_evidence = owner.BoundaryEvidenceV2{
            .source_authority_id = digest("wire-boundary-source-authority"),
            .snapshot_id = digest("wire-boundary-source-snapshot"),
            .tuple_provenance_id = digest("wire-boundary-tuple-provenance"),
            .tuple_count = 29,
            .claimed_sum = WIRE_BOUNDARY_VALUE.neg(),
        };
        const verifier_input_evidence = owner.BoundaryEvidenceV2{
            .source_authority_id = digest(
                "verifier-input-boundary-source-authority",
            ),
            .snapshot_id = digest("verifier-input-boundary-source-snapshot"),
            .tuple_provenance_id = digest(
                "verifier-input-boundary-tuple-provenance",
            ),
            .tuple_count = 16,
            .claimed_sum = VERIFIER_INPUT_BOUNDARY_VALUE.neg(),
        };
        const boundary_authorities = try owner.BoundaryAuthoritiesV2.init(
            try owner.BoundarySourceV2.init(.wire, wire_evidence),
            try owner.BoundarySourceV2.init(
                .verifier_input,
                verifier_input_evidence,
            ),
        );
        const prepared = try owner.prepareAuthorityV2(boundary_authorities);
        const public_boundaries = try owner.PublicBoundariesV2.init(
            &prepared,
            wire_evidence,
            verifier_input_evidence,
        );
        return .{
            .prepared = prepared,
            .wire_evidence = wire_evidence,
            .verifier_input_evidence = verifier_input_evidence,
            .input = try owner.ClosureInputV2.init(
                &prepared,
                &rows,
                &base.provider,
                public_boundaries,
            ),
        };
    }
};

fn emptyRow(row: roster.Component) owner.RowClaimsV1 {
    var domains: [owner.DOMAIN_COUNT]owner.DomainClaimV1 = undefined;
    for (&domains, 0..) |*claim, domain_index| claim.* = .{
        .active = 0,
        .domain = @enumFromInt(domain_index),
        .value = QM31.zero(),
    };
    return .{
        .row = row,
        .domains = domains,
        .claimed_sum = QM31.zero(),
    };
}

fn setDomain(
    row: *owner.RowClaimsV1,
    domain: relation.Domain,
    value: QM31,
) void {
    const claim = &row.domains[@intFromEnum(domain)];
    claim.active = 1;
    claim.value = value;
}

fn recomputeRowClaim(row: *owner.RowClaimsV1) void {
    var total = QM31.zero();
    for (row.domains) |claim| total = total.add(claim.value);
    row.claimed_sum = total;
}

fn expectFailureAtomic(
    expected: anyerror,
    workspace: *owner.Workspace,
    prepared: *const owner.PreparedAuthorityV1,
    rows: []const owner.RowClaimsV1,
    provider: *const owner.ProviderClaimV1,
) !void {
    var destination = owner.ClosureReceiptV1.fresh();
    const before = destination;
    try std.testing.expectError(
        expected,
        owner.fillInto(workspace, prepared, rows, provider, &destination),
    );
    try std.testing.expectEqualDeep(before, destination);
}

fn expectFailureAtomicV2(
    expected: anyerror,
    workspace: *owner.Workspace,
    prepared: *const owner.PreparedAuthorityV2,
    input: *const owner.ClosureInputV2,
) !void {
    var destination = owner.ClosureReceiptV2.fresh();
    const before = destination;
    try std.testing.expectError(
        expected,
        owner.fillIntoV2(workspace, prepared, input, &destination),
    );
    try std.testing.expectEqualDeep(before, destination);
}

fn qm31(a: u32, b: u32, c: u32, d: u32) QM31 {
    return QM31.fromU32Unchecked(a, b, c, d);
}

fn nonCanonicalQm31() QM31 {
    return QM31.fromM31(
        m31.M31.fromU32Unchecked(m31.Modulus),
        m31.M31.zero(),
        m31.M31.zero(),
        m31.M31.zero(),
    );
}

fn domainBit(domain: relation.Domain) u64 {
    return @as(u64, 1) << @as(u6, @intCast(@intFromEnum(domain)));
}

fn digest(label: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

fn comptimeHex32(comptime value: []const u8) [32]u8 {
    if (value.len != 64) @compileError("expected a 32-byte hexadecimal digest");
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch
        @compileError("invalid hexadecimal digest");
    return result;
}
