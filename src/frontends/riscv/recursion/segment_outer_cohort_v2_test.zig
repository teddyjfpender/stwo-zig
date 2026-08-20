const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const subject = @import("segment_outer_cohort_v2.zig");
const shared_schedule = @import("segment_shared_poseidon_schedule_v2.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const relation = @import("../air/lang/relation.zig");
const row17_witness_v2 =
    @import("air/vm_public_logup_control_witness_v2.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const input_provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");

test "cohort plan binds the exact 39-row roster trees and shared row-34 order" {
    const manifest = try fixtureManifest();
    const calls = try fixtureCalls(std.testing.allocator);
    defer std.testing.allocator.free(calls);
    const layout = try shared_schedule.SharedPoseidonCallLayoutV2.initComplete(
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        subject.MEASURED_CORE_POSEIDON_CALLS,
        calls,
    );
    const plan = try subject.CohortPlanV2.measuredCanonical(
        &manifest,
        &layout,
        calls,
    );
    try plan.validateAgainst(&manifest);
    try plan.provider.validateAuthenticated(&manifest, calls);

    try std.testing.expectEqual(@as(u8, 39), plan.roster.component_count);
    try std.testing.expectEqual(subject.ALL_COMPONENT_MASK, plan.roster.row_mask);
    for (plan.roster.authorities, 0..) |authority, row| {
        const expected: subject.RowAuthority = if (row < 10)
            .transcript_v2
        else if (row < 12)
            .statement_v2
        else if (row < 18)
            .public_v2
        else if (row < 35)
            .core_universal_v1_identity
        else if (row == 35)
            .range_v2
        else if (row < 38)
            .boundary_v2
        else
            .verifier_input_provider_v2;
        try std.testing.expectEqual(expected, authority);
    }

    try std.testing.expectEqual(
        @as(u32, 885),
        plan.provider.ranges[0].count,
    );
    try std.testing.expectEqual(
        @as(u32, 885),
        plan.provider.ranges[1].first,
    );
    try std.testing.expectEqual(
        @as(u32, 899),
        plan.provider.ranges[2].first,
    );
    try std.testing.expectEqual(
        @as(u32, 1_193),
        plan.provider.logical_call_count,
    );
    try std.testing.expectEqual(@as(u32, 11), plan.provider.log_size);
    try std.testing.expectEqual(
        subject.ProviderOrigin.transcript,
        plan.provider.ranges[0].origin,
    );
    try std.testing.expectEqual(
        subject.ProviderOrigin.authority,
        plan.provider.ranges[1].origin,
    );
    try std.testing.expectEqual(
        subject.ProviderOrigin.core,
        plan.provider.ranges[2].origin,
    );

    var next = [_]u32{0} ** subject.TREE_COUNT;
    for (plan.trees.rows) |row| {
        try std.testing.expectEqualDeep(next, row.offsets);
        inline for (0..subject.TREE_COUNT) |tree|
            next[tree] += row.columns[tree];
    }
    try std.testing.expectEqualDeep(plan.trees.total_columns, next);
    try std.testing.expect(plan.capabilities.has(.statement_components));
    try std.testing.expectEqual(
        subject.CORE_ROWS_MASK,
        plan.capabilities.missing_component_rows,
    );
    try std.testing.expect(!plan.capabilities.production_ready);
}

test "shared schedule rejects range order and call-buffer mutations" {
    const manifest = try fixtureManifest();
    const calls = try fixtureCalls(std.testing.allocator);
    defer std.testing.allocator.free(calls);
    const layout = try shared_schedule.SharedPoseidonCallLayoutV2.initComplete(
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        subject.MEASURED_CORE_POSEIDON_CALLS,
        calls,
    );

    var bad_order = layout;
    bad_order.transcript.end = subject.MEASURED_AUTHORITY_POSEIDON_CALLS;
    try std.testing.expectError(
        error.SourceManifestMismatch,
        subject.ProviderScheduleV2.initFromAuthenticatedLayout(
            &manifest,
            &bad_order,
            calls,
        ),
    );

    const wrong_lane_order = try shared_schedule.SharedPoseidonCallLayoutV2.initComplete(
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_CORE_POSEIDON_CALLS,
        calls,
    );
    try std.testing.expectError(
        error.InvalidProviderSchedule,
        subject.CohortPlanV2.measuredCanonical(
            &manifest,
            &wrong_lane_order,
            calls,
        ),
    );

    calls[0].input[0] +%= 1;
    try std.testing.expectError(
        error.SourceManifestMismatch,
        subject.ProviderScheduleV2.initFromAuthenticatedLayout(
            &manifest,
            &layout,
            calls,
        ),
    );
}

test "shared schedule preserves the authenticated boundary prefix on completion" {
    const all_calls = try fixtureCalls(std.testing.allocator);
    defer std.testing.allocator.free(all_calls);
    const boundary_count = subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS +
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS;
    const boundary_calls = all_calls[0..boundary_count];
    const core_calls = all_calls[boundary_count..];
    const boundary = try shared_schedule.SharedPoseidonCallLayoutV2
        .initBoundaryPrefix(
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        boundary_calls,
    );
    try boundary.validate(boundary_calls);
    try std.testing.expect(!boundary.call_set_complete);
    try std.testing.expectEqual(
        @as(usize, 0),
        try boundary.verifier_core.count(),
    );

    var completed = try shared_schedule.OwnedCompletePoseidonScheduleV2.init(
        std.testing.allocator,
        &boundary,
        boundary_calls,
        core_calls,
    );
    defer completed.deinit();
    try completed.validateAgainst(&boundary, boundary_calls);
    try std.testing.expect(completed.layout.call_set_complete);
    try std.testing.expectEqual(
        all_calls.len,
        completed.calls.len,
    );
    for (completed.calls, all_calls) |actual, expected|
        try std.testing.expectEqualDeep(expected, actual);
}

test "tree roster and cohort identities reject independent mutation" {
    const manifest = try fixtureManifest();
    const calls = try fixtureCalls(std.testing.allocator);
    defer std.testing.allocator.free(calls);
    const layout = try shared_schedule.SharedPoseidonCallLayoutV2.initComplete(
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        subject.MEASURED_CORE_POSEIDON_CALLS,
        calls,
    );
    const plan = try subject.CohortPlanV2.measuredCanonical(
        &manifest,
        &layout,
        calls,
    );

    var bad_tree = plan;
    bad_tree.trees.rows[17].offsets[1] += 1;
    try std.testing.expectError(
        error.TreeAccountingMismatch,
        bad_tree.validateAgainst(&manifest),
    );

    var bad_roster = plan;
    bad_roster.roster.authorities[12] = .core_universal_v1_identity;
    try std.testing.expectError(
        error.ComponentCoverageMismatch,
        bad_roster.validateAgainst(&manifest),
    );

    var bad_provider = plan;
    bad_provider.provider.ranges[0].origin = .core;
    try std.testing.expectError(
        error.InvalidProviderSchedule,
        bad_provider.validateAgainst(&manifest),
    );

    var bad_identity = plan;
    bad_identity.identity[0] ^= 1;
    try std.testing.expectError(
        error.CohortIdentityMismatch,
        bad_identity.validateAgainst(&manifest),
    );
}

test "47-domain closure accepts same-domain cancellation only" {
    const manifest = try fixtureManifest();
    var claims = [_]QM31{QM31.zero()} ** subject.COMPONENT_COUNT;
    var audits: [subject.COMPONENT_COUNT]relation_interaction.DomainAudit =
        undefined;
    for (&audits) |*audit| audit.* = zeroAudit();

    const one = QM31.one();
    const negative_one = one.neg();
    const domain = @intFromEnum(@import("../air/lang/relation.zig").Domain.memory_access);
    audits[0].values[domain] = one;
    audits[0].total = one;
    claims[0] = one;
    audits[1].values[domain] = negative_one;
    audits[1].total = negative_one;
    claims[1] = negative_one;
    const closed = try subject.verifyInteractionClosure(
        &manifest,
        &claims,
        &audits,
    );
    try std.testing.expect(closed.framework_total.isZero());
    try std.testing.expect(closed.domain_totals[domain].isZero());
    try std.testing.expectEqual(
        @as(u64, 1) << @intCast(domain),
        closed.active_domain_mask,
    );

    // A zero framework total cannot hide cancellation across two different
    // domains. Each of the 47 registries must close independently.
    claims = [_]QM31{QM31.zero()} ** subject.COMPONENT_COUNT;
    for (&audits) |*audit| audit.* = zeroAudit();
    const other_domain = @intFromEnum(@import("../air/lang/relation.zig").Domain.program_access);
    audits[0].values[domain] = one;
    audits[0].values[other_domain] = negative_one;
    audits[0].total = QM31.zero();
    try std.testing.expectError(
        error.RelationNotClosed,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );

    // The shared provider owns exactly the two typed Poseidon recurrence
    // domains. Both are admitted, while a numerically balanced contribution
    // spanning unrelated registries remains forbidden.
    const poseidon_domain = @intFromEnum(
        @import("../air/lang/relation.zig").Domain.poseidon2,
    );
    const poseidon_io_domain = @intFromEnum(
        @import("../air/lang/relation.zig").Domain.poseidon2_io,
    );
    for (&audits) |*audit| audit.* = zeroAudit();
    audits[subject.ROW_34].values[poseidon_domain] = one;
    audits[subject.ROW_34].values[poseidon_io_domain] = negative_one;
    audits[0].values[poseidon_domain] = negative_one;
    audits[0].total = negative_one;
    claims[0] = negative_one;
    audits[1].values[poseidon_io_domain] = one;
    audits[1].total = one;
    claims[1] = one;
    try std.testing.expect((try subject.verifyInteractionClosure(
        &manifest,
        &claims,
        &audits,
    )).framework_total.isZero());

    claims = [_]QM31{QM31.zero()} ** subject.COMPONENT_COUNT;
    for (&audits) |*audit| audit.* = zeroAudit();
    audits[subject.ROW_34].values[domain] = one;
    audits[subject.ROW_34].values[other_domain] = negative_one;
    try std.testing.expectError(
        error.ProviderDomainMismatch,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );
}

test "boundary-aware closure rejects omission sign substitution and mutation" {
    const manifest = try fixtureManifest();
    var claims = [_]QM31{QM31.zero()} ** subject.COMPONENT_COUNT;
    var audits: [subject.COMPONENT_COUNT]relation_interaction.DomainAudit =
        undefined;
    for (&audits) |*audit| audit.* = zeroAudit();

    const wire_domain = @intFromEnum(relation.Domain.recursion_wire);
    const one = QM31.one();
    const negative_one = one.neg();
    audits[0].values[wire_domain] = negative_one;
    audits[0].total = negative_one;
    claims[0] = negative_one;

    const boundary = try subject.PublicWireBoundaryV2.init(
        shaDigest(173),
        521,
        one,
    );
    const closed = try subject.verifyInteractionClosureV2(
        &manifest,
        &claims,
        &audits,
        &boundary,
    );
    try std.testing.expect(closed.domain_totals[wire_domain].isZero());
    try std.testing.expect(closed.framework_total.isZero());
    try std.testing.expectEqual(@as(u64, subject.COMPONENT_COUNT), closed.logical_rows);
    try std.testing.expectEqual(@as(u64, subject.COMPONENT_COUNT), closed.event_terms);
    try std.testing.expectEqual(
        @as(u32, 521),
        closed.public_wire_boundary.?.term_count,
    );
    try std.testing.expectEqual(
        relation.Domain.recursion_wire,
        closed.public_wire_boundary.?.domain,
    );

    // Omitting the verifier-owned anchor cannot be confused with an empty
    // boundary: the immutable V1 fixture API still sees the row residual.
    try std.testing.expectError(
        error.RelationNotClosed,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );

    const wrong_sign = try subject.PublicWireBoundaryV2.init(
        boundary.source_authority_id,
        boundary.term_count,
        boundary.claimed_sum.neg(),
    );
    try std.testing.expectError(
        error.RelationNotClosed,
        subject.verifyInteractionClosureV2(
            &manifest,
            &claims,
            &audits,
            &wrong_sign,
        ),
    );

    var mutated = boundary;
    mutated.term_count += 1;
    try std.testing.expectError(
        error.PublicWireBoundaryMismatch,
        subject.verifyInteractionClosureV2(
            &manifest,
            &claims,
            &audits,
            &mutated,
        ),
    );
    mutated = boundary;
    mutated.claimed_sum = negative_one;
    try std.testing.expectError(
        error.PublicWireBoundaryMismatch,
        subject.verifyInteractionClosureV2(
            &manifest,
            &claims,
            &audits,
            &mutated,
        ),
    );
}

test "47-domain closure admits only the exact canonical empty-row audit" {
    const manifest = try fixtureManifest();
    var claims = [_]QM31{QM31.zero()} ** subject.COMPONENT_COUNT;
    var audits: [subject.COMPONENT_COUNT]relation_interaction.DomainAudit =
        undefined;
    for (&audits) |*audit| audit.* = zeroAudit();

    // A fold profile may have no logical work for a typed row. Such a row is
    // absent, not padded: both geometry counters and every algebraic field
    // must be zero. The remaining 38 rows retain their ordinary audit shape.
    audits[26] = emptyAudit();
    const closed = try subject.verifyInteractionClosure(
        &manifest,
        &claims,
        &audits,
    );
    try std.testing.expect(closed.framework_total.isZero());
    try std.testing.expectEqual(@as(u64, 38), closed.logical_rows);
    try std.testing.expectEqual(@as(u64, 38), closed.event_terms);

    audits[26].logical_rows = 1;
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );

    audits[26] = emptyAudit();
    claims[26] = QM31.one();
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );

    claims[26] = QM31.zero();
    audits[26].values[0] = QM31.one();
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );

    audits[26] = emptyAudit();
    audits[26].total = QM31.one();
    try std.testing.expectError(
        error.InvalidAuditGeometry,
        subject.verifyInteractionClosure(&manifest, &claims, &audits),
    );
}

test "claim component coverage and readiness remain fail closed" {
    const manifest = try fixtureManifest();
    const calls = try fixtureCalls(std.testing.allocator);
    defer std.testing.allocator.free(calls);
    const layout = try shared_schedule.SharedPoseidonCallLayoutV2.initComplete(
        subject.MEASURED_TRANSCRIPT_POSEIDON_CALLS,
        subject.MEASURED_AUTHORITY_POSEIDON_CALLS,
        subject.MEASURED_CORE_POSEIDON_CALLS,
        calls,
    );
    const plan = try subject.CohortPlanV2.measuredCanonical(
        &manifest,
        &layout,
        calls,
    );

    var claims = try manifest_mod.ClaimVector.init(&manifest);
    for (0..subject.COMPONENT_COUNT) |row|
        try claims.bind(@enumFromInt(row), QM31.zero());
    try claims.sealClaims(&manifest);
    try claims.validate(&manifest);
    try std.testing.expectEqual(subject.ALL_COMPONENT_MASK, claims.bound_mask);

    var empty_gate = try manifest_mod.ProofGate.init(&manifest);
    try std.testing.expectError(
        error.AdapterCountMismatch,
        subject.GateReceiptV2.capture(&plan, &manifest, &empty_gate),
    );

    const readiness = try subject.ProductionReadinessReceiptV2.current(&plan);
    try readiness.validateAgainst(&plan);
    try std.testing.expect(!readiness.production_ready);
    try std.testing.expectEqual(subject.CORE_ROWS_MASK, readiness.missing_component_mask);
    try std.testing.expectError(
        error.ProductionReadinessUnavailable,
        readiness.requireProductionReady(&plan),
    );
    var escalated = readiness;
    escalated.production_ready = true;
    try std.testing.expectError(
        error.CapabilityEscalation,
        escalated.validateAgainst(&plan),
    );
}

test "pending generic engine seam is compile complete and unconstructible" {
    const StubOwner = struct {
        pub const AuthorityInputs = u8;
        pub const GeneratedInteractionsV2 = u8;
        pub const Components = struct {};
    };
    const Pending = subject.Cohort(StubOwner, StubOwner);
    inline for (.{
        "AuthorityInputs",
        "GeneratedInteractionsV2",
        "init",
        "deinit",
        "validate",
        "manifest",
        "mixAuthority",
        "mixPublicWireBoundary",
        "fillPreprocessedInto",
        "fillMainInto",
        "fillInteractionInto",
        "validateGenerated",
        "auditGlobalClosure",
        "claimVector",
        "rebuildGeneratedInteractions",
        "initComponents",
    }) |name| try std.testing.expect(@hasDecl(Pending, name));
    try std.testing.expectError(
        error.ProductionReadinessUnavailable,
        Pending.init(std.testing.allocator, .{ .statement = 0, .core = 0 }),
    );
    try std.testing.expect(!subject.CONCRETE_PRODUCTION_COHORT_AVAILABLE);
}

fn fixtureManifest() !manifest_mod.Manifest {
    const logs = fixtureLogSizes();
    const catalog = try catalog_mod.build(logs, boundaryComponents(8));
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = nativeDigest(11),
        .statement_manifest_id = nativeDigest(29),
        .public_manifest_id = nativeDigest(47),
        .boundary_manifest_id = nativeDigest(71),
        .boundary_authority_sha_id = shaDigest(89),
        .provider_authority_sha_id = input_provider_authority.sourceAuthorityShaId(),
    });
}

fn fixtureLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    result[0] = 5;
    result[1] = 6;
    result[5] = 7;
    result[11] = 8;
    result[12] = 5;
    result[13] = 4;
    result[14] = 4;
    result[15] = 6;
    result[16] = 5;
    result[17] = row17_witness_v2.TRACE_LOG_SIZE;
    result[@intFromEnum(universal_roster.Component.poseidon2)] = 11;
    result[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    return result;
}

fn boundaryComponents(
    statement_log_size: u8,
) [boundary_manifest.COMPONENT_COUNT]boundary_manifest.ComponentGeometryV2 {
    return .{
        .{
            .kind = .statement_source,
            .component_tag = boundary_manifest.STATEMENT_COMPONENT_TAG,
            .logical_rows = (@as(u32, 1) << @intCast(statement_log_size - 1)) + 1,
            .trace_log_size = statement_log_size,
            .trace_rows = @as(u32, 1) << @intCast(statement_log_size),
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_manifest.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_manifest.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_manifest.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
}

fn fixtureCalls(allocator: std.mem.Allocator) ![]shared_schedule.Call {
    const calls = try allocator.alloc(
        shared_schedule.Call,
        subject.MEASURED_TOTAL_POSEIDON_CALLS,
    );
    for (calls, 0..) |*call, index| {
        call.* = .{
            .input = [_]u32{0} ** 16,
            .io = true,
        };
        call.input[0] = @intCast(index);
    }
    return calls;
}

fn zeroAudit() relation_interaction.DomainAudit {
    return .{
        .values = [_]QM31{QM31.zero()} ** subject.DOMAIN_COUNT,
        .total = QM31.zero(),
        .logical_rows = 1,
        .event_terms = 1,
    };
}

fn emptyAudit() relation_interaction.DomainAudit {
    return .{
        .values = [_]QM31{QM31.zero()} ** subject.DOMAIN_COUNT,
        .total = QM31.zero(),
        .logical_rows = 0,
        .event_terms = 0,
    };
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

comptime {
    if (subject.COMPONENT_COUNT != 39 or subject.DOMAIN_COUNT != 47 or
        subject.TREE_COUNT != 3 or
        shared_schedule.PROVIDER_INSTANCE_COUNT != 1 or
        shared_schedule.HOT_VALIDATION_HEAP_ALLOCATIONS != 0 or
        subject.HOT_ASSEMBLY_HEAP_ALLOCATIONS != 0 or
        subject.HOT_VALIDATION_HEAP_ALLOCATIONS != 0)
    {
        @compileError("SegmentV2 cohort focused-test assumptions drifted");
    }
}
