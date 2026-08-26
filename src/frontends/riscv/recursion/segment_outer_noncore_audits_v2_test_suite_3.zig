//! Focused shard of segment_outer_noncore_audits_v2_test.zig; import that suite facade.

const dependency_0 = @import("segment_outer_noncore_audits_v2_test_owned_boundary_traces.zig");
const dependency_1 = @import("segment_outer_noncore_audits_v2_test_fixture.zig");

const Fixture = dependency_1.Fixture;
const QM31 = dependency_0.QM31;
const noncoreIndex = dependency_1.noncoreIndex;
const qm31 = dependency_0.qm31;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const std = dependency_0.std;
const subject = dependency_0.subject;
const zeroAudit = dependency_1.zeroAudit;

test "family and domain mutations fail closed and installation stays atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const receipt = try subject.rebuild(std.testing.allocator, fixture.inputs());

    // One foreign-domain injection per independent source family. The row
    // total, claim, and residual are adjusted together so rejection exercises
    // the exact row/domain roster rather than only aggregate arithmetic.
    const mutations = [_]struct { row: u8, foreign_domain: usize }{
        .{ .row = 0, .foreign_domain = @intFromEnum(relation.Domain.range_check_8_8) },
        .{ .row = 11, .foreign_domain = @intFromEnum(relation.Domain.poseidon2) },
        .{ .row = 12, .foreign_domain = @intFromEnum(relation.Domain.recursion_step) },
        .{ .row = 13, .foreign_domain = @intFromEnum(relation.Domain.poseidon2) },
        .{ .row = 35, .foreign_domain = @intFromEnum(relation.Domain.recursion_wire) },
        .{ .row = 36, .foreign_domain = @intFromEnum(relation.Domain.recursion_pow_check) },
        .{ .row = 37, .foreign_domain = @intFromEnum(relation.Domain.recursion_hash_data) },
        .{ .row = 38, .foreign_domain = @intFromEnum(relation.Domain.recursion_wire) },
    };
    for (mutations) |mutation| {
        var bad = receipt;
        const index = noncoreIndex(mutation.row).?;
        bad.rows[index].values[mutation.foreign_domain] =
            bad.rows[index].values[mutation.foreign_domain].add(QM31.one());
        bad.rows[index].total = bad.rows[index].total.add(QM31.one());
        bad.claims[index] = bad.claims[index].add(QM31.one());
        bad.domain_residuals[mutation.foreign_domain] =
            bad.domain_residuals[mutation.foreign_domain].add(QM31.one());
        try std.testing.expectError(
            error.ProviderDomainMismatch,
            bad.validateAgainst(&fixture.manifest, &fixture.relations),
        );
    }

    // The row-17 audit geometry is a protocol invariant, not merely an upper
    // bound beneath its padded 128-row commitment domain.
    const row17_index = noncoreIndex(17).?;
    var short_row17 = receipt;
    short_row17.rows[row17_index].logical_rows =
        subject.ROW17_LOGICAL_ROWS - 1;
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        short_row17.validateAgainst(&fixture.manifest, &fixture.relations),
    );
    var missing_row17_term = receipt;
    missing_row17_term.rows[row17_index].event_terms =
        subject.ROW17_TYPED_EVENT_TERMS - 1;
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        missing_row17_term.validateAgainst(&fixture.manifest, &fixture.relations),
    );

    // Preserve the external relay obligation: an unrelated domain cannot be
    // injected even when all aggregate arithmetic is kept internally
    // consistent.
    var foreign_row17 = receipt;
    const foreign_domain = @intFromEnum(relation.Domain.poseidon2);
    foreign_row17.rows[row17_index].values[foreign_domain] =
        foreign_row17.rows[row17_index].values[foreign_domain].add(QM31.one());
    foreign_row17.rows[row17_index].total =
        foreign_row17.rows[row17_index].total.add(QM31.one());
    foreign_row17.claims[row17_index] =
        foreign_row17.claims[row17_index].add(QM31.one());
    foreign_row17.domain_residuals[foreign_domain] =
        foreign_row17.domain_residuals[foreign_domain].add(QM31.one());
    try std.testing.expectError(
        error.ProviderDomainMismatch,
        foreign_row17.validateAgainst(&fixture.manifest, &fixture.relations),
    );

    var audits = [_]relation_interaction.DomainAudit{zeroAudit()} **
        subject.COMPONENT_COUNT;
    var claims = [_]QM31{qm31(901)} ** subject.COMPONENT_COUNT;
    var occupied = subject.CORE_ROW_MASK;
    const audits_before = audits;
    const claims_before = claims;
    var bad_relations = fixture.relations;
    bad_relations.elements[0].z = bad_relations.elements[0].z.add(QM31.one());
    var bad_inputs = fixture.inputs();
    bad_inputs.relations = &bad_relations;
    try std.testing.expectError(
        error.ChallengeBindingMismatch,
        subject.rebuildAndInstall(
            std.testing.allocator,
            bad_inputs,
            &audits,
            &claims,
            &occupied,
        ),
    );
    try std.testing.expectEqualDeep(audits_before, audits);
    try std.testing.expectEqualDeep(claims_before, claims);
    try std.testing.expectEqual(subject.CORE_ROW_MASK, occupied);

    occupied |= @as(u64, 1) << 12;
    const overlap_before = occupied;
    try std.testing.expectError(
        error.ComponentMaskOverlap,
        receipt.installInto(
            &fixture.manifest,
            &fixture.relations,
            &audits,
            &claims,
            &occupied,
        ),
    );
    try std.testing.expectEqualDeep(audits_before, audits);
    try std.testing.expectEqualDeep(claims_before, claims);
    try std.testing.expectEqual(overlap_before, occupied);
}
