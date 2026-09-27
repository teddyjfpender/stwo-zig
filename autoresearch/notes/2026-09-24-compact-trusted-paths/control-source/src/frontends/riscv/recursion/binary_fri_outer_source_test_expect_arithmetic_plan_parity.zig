//! Focused shard of binary_fri_outer_source_test.zig; import that suite facade.

const dependency_0 = @import("binary_fri_outer_source_test_capture_fixture.zig");
const dependency_1 = @import("binary_fri_outer_source_test_fixture.zig");

const Fixture = dependency_1.Fixture;
const M31 = dependency_0.M31;
const POSEIDON2_SAMPLE_LAYOUT_START = dependency_0.POSEIDON2_SAMPLE_LAYOUT_START;
const QM31 = dependency_0.QM31;
const Source = dependency_0.Source;
const Tree = dependency_1.Tree;
const air = dependency_0.air;
const authority = dependency_0.authority;
const sample_point_layout = dependency_0.sample_point_layout;
const source_mod = dependency_0.source_mod;
const std = dependency_0.std;

test "R-015 row-18 binds both ordered Poseidon provider partials" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();
    const original = fixture.source.children[0].composition.?;
    const trusted = fixture.source.children[0].trusted_composition_profile.?;

    fixture.source.children[0].composition.?.poseidon2_partials[0] =
        original.poseidon2_partials[0].add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].composition = original;

    fixture.source.children[0].composition.?.poseidon2_partials[1] =
        original.poseidon2_partials[1].add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].composition = original;

    fixture.source.children[0].composition.?.authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].composition = original;

    const swapped_partials = [2]QM31{
        original.poseidon2_partials[1],
        original.poseidon2_partials[0],
    };
    const swapped = try source_mod.VerifiedChildCompositionAuthority.authenticate(
        trusted,
        0,
        fixture.prepared.authority.children[0],
        fixture.pair.shape,
        original.circuit_identity,
        original.graph,
        original.evaluation,
        swapped_partials,
        original.poseidon2_roster_total,
    );
    fixture.source.children[0].composition = swapped;
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].composition = original;

    const corrective_partials = [2]QM31{
        original.poseidon2_partials[0].add(QM31.one()),
        original.poseidon2_partials[1].sub(QM31.one()),
    };
    const corrective = try source_mod.VerifiedChildCompositionAuthority.authenticate(
        trusted,
        0,
        fixture.prepared.authority.children[0],
        fixture.pair.shape,
        original.circuit_identity,
        original.graph,
        original.evaluation,
        corrective_partials,
        original.poseidon2_roster_total,
    );
    fixture.source.children[0].composition = corrective;
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].composition = original;
    try fixture.source.validate();

    const layouts = @constCast(
        fixture.capture_children[0].capture.sample_layouts,
    );
    const start: usize = POSEIDON2_SAMPLE_LAYOUT_START;
    const saved: [source_mod.POSEIDON2_INTERACTION_COLUMN_COUNT]sample_point_layout.Layout =
        layouts[start..][0..source_mod.POSEIDON2_INTERACTION_COLUMN_COUNT].*;
    @memset(layouts[start..][0..4], .current);
    @memset(layouts[start + 4 ..][0..4], .previous_current);
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    @memcpy(
        layouts[start..][0..source_mod.POSEIDON2_INTERACTION_COLUMN_COUNT],
        &saved,
    );
    try fixture.source.validate();
}

test "R-015 binary FRI mutation fleet rejects custody reordering" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();

    std.mem.swap(
        @TypeOf(fixture.source.children[0]),
        &fixture.source.children[0],
        &fixture.source.children[1],
    );
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    std.mem.swap(
        @TypeOf(fixture.source.children[0]),
        &fixture.source.children[0],
        &fixture.source.children[1],
    );

    const right_child = fixture.source.children[1];
    fixture.source.children[1] = fixture.source.children[0];
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[1] = right_child;

    const queries = @constCast(fixture.capture_children[0].capture.raw_queries);
    std.mem.swap(M31, &queries[0], &queries[1]);
    try std.testing.expectError(
        error.InvalidQuerySchedule,
        fixture.source.validate(),
    );
    std.mem.swap(M31, &queries[0], &queries[1]);

    const sibling = @constCast(
        fixture.capture_children[0].capture.trace_siblings[0],
    );
    sibling[0][0] ^= 1;
    try std.testing.expectError(
        error.CaptureWireMismatch,
        fixture.source.validate(),
    );
    sibling[0][0] ^= 1;

    const layer_profile = @constCast(
        fixture.capture_children[0].capture.fri_layer_profiles,
    );
    const original_width = layer_profile[0].width;
    layer_profile[0].width = 8;
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.source.validate(),
    );
    layer_profile[0].width = original_width;

    const openings = @constCast(
        fixture.capture_children[0].capture.fri_layer_openings[0].values,
    );
    const original_opening = openings[0];
    openings[0] = original_opening.add(M31.one());
    try std.testing.expectError(
        error.CaptureWireMismatch,
        fixture.source.validate(),
    );
    openings[0] = original_opening;

    const samples = @constCast(
        fixture.capture_children[0].capture.sampled_values,
    );
    const original_sample = samples[0];
    samples[0] = original_sample.add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.validate(),
    );
    samples[0] = original_sample;
    try fixture.source.validate();
}

test "R-015 binary FRI retains exact interaction rows 18--33" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();

    var composition_workspace = try Source.CompositionWorkspace.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer composition_workspace.deinit();
    var fri_workspace = try Source.Workspace.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer fri_workspace.deinit();
    var fri_main = try Tree.init(
        std.testing.allocator,
        fixture.source.friLogSizes(),
        source_mod.MAIN_COLUMNS_PER_ROW,
    );
    defer fri_main.deinit();
    try fixture.source.fillFriMainInto(&fri_workspace, fri_main.columns);

    var arithmetic_workspace = try Source.ArithmeticWorkspace.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer arithmetic_workspace.deinit();
    var arithmetic_main = try Tree.init(
        std.testing.allocator,
        try fixture.source.arithmeticLogSizes(),
        source_mod.ARITHMETIC_MAIN_COLUMNS_PER_ROW,
    );
    defer arithmetic_main.deinit();
    try fixture.source.fillArithmeticMainInto(
        &arithmetic_workspace,
        arithmetic_main.columns,
    );

    var merkle_workspace = try Source.MerkleWorkspace.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer merkle_workspace.deinit();
    try fixture.source.prepareMerkleWorkspace(
        &fri_workspace,
        &merkle_workspace,
    );

    var relation_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var relation_rows = try Source.RelationRows.init(
        relation_meter.allocator(),
        &fixture.source,
    );
    defer relation_rows.deinit();
    try std.testing.expectEqual(
        source_mod.RELATION_ROWS_WORKSPACE_HEAP_ALLOCATIONS,
        relation_meter.alloc_index,
    );
    try fixture.source.prepareRelationRows(
        &composition_workspace,
        &fri_workspace,
        &arithmetic_workspace,
        &merkle_workspace,
        &relation_rows,
    );
    const retained = try fixture.source.retainedRelationRows(&relation_rows);
    try std.testing.expect(retained.storage.len != 0);
    try std.testing.expectEqual(
        merkle_workspace.logical_rows.len,
        retained.merkle_path.len,
    );
    for (merkle_workspace.logical_rows, retained.merkle_path) |expected, actual|
        try std.testing.expectEqualSlices(M31, &expected, &actual);

    const hot_before = relation_meter.alloc_index;
    try fixture.source.prepareRelationRows(
        &composition_workspace,
        &fri_workspace,
        &arithmetic_workspace,
        &merkle_workspace,
        &relation_rows,
    );
    try std.testing.expectEqual(
        source_mod.RELATION_ROWS_REUSED_HOT_HEAP_ALLOCATIONS,
        relation_meter.alloc_index - hot_before,
    );

    const relations = air.universal_challenges.UniversalRelations.dummy();
    var interaction_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var interaction_workspace = try Source.RelationInteractionWorkspace.init(
        interaction_meter.allocator(),
        &fixture.source,
        &relation_rows,
    );
    defer interaction_workspace.deinit();
    try std.testing.expectEqual(
        source_mod.RELATION_INTERACTION_WORKSPACE_HEAP_ALLOCATIONS,
        interaction_meter.alloc_index,
    );
    var interaction = try Tree.init(
        std.testing.allocator,
        try fixture.source.typedRelationLogSizes(),
        source_mod.TYPED_INTERACTION_COLUMNS_PER_ROW,
    );
    defer interaction.deinit();
    const claims = try fixture.source.fillTypedInteractionsInto(
        &relation_rows,
        &interaction_workspace,
        &relations,
        interaction.columns,
    );
    try std.testing.expect(interaction.anyNonZero());
    const audits = try fixture.source.auditTypedInteractionDomains(
        std.testing.allocator,
        &relation_rows,
        &relations,
        claims,
    );
    for (audits, claims) |audit, claim|
        try std.testing.expect(audit.total.eql(claim));

    const interaction_hot_before = interaction_meter.alloc_index;
    _ = try fixture.source.fillTypedInteractionsInto(
        &relation_rows,
        &interaction_workspace,
        &relations,
        interaction.columns,
    );
    try std.testing.expectEqual(
        source_mod.RELATION_INTERACTION_REUSED_HOT_HEAP_ALLOCATIONS,
        interaction_meter.alloc_index - interaction_hot_before,
    );

    const provider_partials = [2]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    };
    const bundle_claims = source_mod.Claims{
        .typed_rows = claims,
        .poseidon2_partials = provider_partials,
    };
    try std.testing.expect(bundle_claims.asRows18Through34()[16].eql(
        provider_partials[0].add(provider_partials[1]),
    ));
    try (source_mod.Poseidon2DomainAudit{
        .poseidon2 = provider_partials[0],
        .poseidon2_io = provider_partials[1],
        .total = provider_partials[0].add(provider_partials[1]),
    }).validate(bundle_claims);

    relation_rows.merkle_path[0][0] =
        relation_rows.merkle_path[0][0].add(M31.one());
    const sentinel = M31.fromCanonical(9_901);
    interaction.fill(sentinel);
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        fixture.source.fillTypedInteractionsInto(
            &relation_rows,
            &interaction_workspace,
            &relations,
            interaction.columns,
        ),
    );
    try interaction.expectFilled(sentinel);
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        fixture.source.retainedRelationRows(&relation_rows),
    );
}

test "R-015 binary FRI rows 20--29 write transactionally with zero hot allocations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const logs = fixture.source.friLogSizes();

    var workspace_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var workspace = try Source.Workspace.init(
        workspace_meter.allocator(),
        &fixture.source,
    );
    defer workspace.deinit();
    try std.testing.expectEqual(
        source_mod.ROWS_20_29_WORKSPACE_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index,
    );

    var preprocessed = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.PREPROCESSED_COLUMNS_PER_ROW,
    );
    defer preprocessed.deinit();
    var main = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.MAIN_COLUMNS_PER_ROW,
    );
    defer main.deinit();
    try fixture.source.fillFriPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillFriMainInto(&workspace, main.columns);
    try std.testing.expect(preprocessed.anyNonZero());
    try std.testing.expect(main.anyNonZero());

    const hot_before = workspace_meter.alloc_index;
    try fixture.source.fillFriPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillFriMainInto(&workspace, main.columns);
    try std.testing.expectEqual(
        source_mod.ROWS_20_29_REUSED_HOT_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index - hot_before,
    );

    const sentinel = M31.fromCanonical(1_337);
    main.fill(sentinel);
    const saved_query = fixture.capture_children[0].capture.raw_queries[0];
    @constCast(fixture.capture_children[0].capture.raw_queries)[0] =
        saved_query.add(M31.one());
    try std.testing.expectError(
        error.InvalidQuerySchedule,
        fixture.source.fillFriMainInto(&workspace, main.columns),
    );
    @constCast(fixture.capture_children[0].capture.raw_queries)[0] = saved_query;
    try main.expectFilled(sentinel);

    const original = main.columns[1];
    main.columns[1] = main.columns[0];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillFriMainInto(&workspace, main.columns),
    );
    main.columns[1] = original;
    try main.expectFilled(sentinel);

    workspace.source_authority_digest[0] ^= 1;
    try std.testing.expectError(
        error.WorkspaceAuthorityMismatch,
        fixture.source.fillFriMainInto(&workspace, main.columns),
    );
    workspace.source_authority_digest[0] ^= 1;
    try main.expectFilled(sentinel);
}

pub const RIGHT_CHILD: usize = 1;

pub fn expectArithmeticPlanParity(
    source: *const Source,
    workspace: *const Source.ArithmeticWorkspace,
    preprocessed: *const Tree,
    main: *const Tree,
) !void {
    const rows = source.arithmetic_rows.?;
    const counts = rows.plan.counts(.binary_node);
    try std.testing.expectEqual(counts.multiply, workspace.multiply_invocations.len);
    try std.testing.expectEqual(counts.inverse, workspace.inverse_invocations.len);
    try std.testing.expectEqual(counts.linear, workspace.linear_invocations.len);

    const multiply_pp_offset: usize = 0;
    const inverse_pp_offset = multiply_pp_offset +
        air.qm31_mul_full_witness.PREPROCESSED_COLUMN_COUNT;
    const linear_pp_offset = inverse_pp_offset +
        air.qm31_inv_witness.PREPROCESSED_COLUMN_COUNT;
    for (rows.plan.multiply_rows, 0..) |row, row_index| try expectColumnRow(
        preprocessed.columns,
        multiply_pp_offset,
        row_index,
        air.qm31_mul_full_witness.preprocessedRow(row),
    );
    for (rows.plan.inverse_rows, 0..) |row, row_index| try expectColumnRow(
        preprocessed.columns,
        inverse_pp_offset,
        row_index,
        air.qm31_inv_witness.preprocessedRow(row),
    );
    for (rows.plan.linear_rows, 0..) |row, row_index| try expectColumnRow(
        preprocessed.columns,
        linear_pp_offset,
        row_index,
        air.linear_ops_witness.preprocessedRow(row),
    );

    const multiply_main_offset: usize = 0;
    const inverse_main_offset = multiply_main_offset +
        air.qm31_mul_full_witness.MAIN_COLUMN_COUNT;
    const linear_main_offset = inverse_main_offset +
        air.qm31_inv_witness.MAIN_COLUMN_COUNT;
    for (workspace.multiply_invocations, 0..) |invocation, row_index| {
        try expectColumnRow(
            main.columns,
            multiply_main_offset,
            row_index,
            air.qm31_mul_full_witness.mainRow(invocation),
        );
    }
    for (workspace.inverse_invocations, 0..) |invocation, row_index| {
        try expectColumnRow(
            main.columns,
            inverse_main_offset,
            row_index,
            try air.qm31_inv_witness.mainRow(invocation),
        );
    }
    for (workspace.linear_invocations, 0..) |invocation, row_index| {
        try expectColumnRow(
            main.columns,
            linear_main_offset,
            row_index,
            try air.linear_ops_witness.mainRow(invocation),
        );
    }
    try expectZeroPadding(
        main.columns,
        multiply_main_offset,
        air.qm31_mul_full_witness.MAIN_COLUMN_COUNT,
        workspace.multiply_invocations.len,
        rows.log_sizes[0],
    );
    try expectZeroPadding(
        main.columns,
        inverse_main_offset,
        air.qm31_inv_witness.MAIN_COLUMN_COUNT,
        workspace.inverse_invocations.len,
        rows.log_sizes[1],
    );
    try expectZeroPadding(
        main.columns,
        linear_main_offset,
        air.linear_ops_witness.MAIN_COLUMN_COUNT,
        workspace.linear_invocations.len,
        rows.log_sizes[2],
    );
}

pub fn expectColumnRow(
    columns: [][]M31,
    column_offset: usize,
    row_index: usize,
    expected: anytype,
) !void {
    for (expected, 0..) |value, column| {
        const trace = columns[column_offset + column];
        const log_size: u32 = @intCast(std.math.log2_int(usize, trace.len));
        const committed = air.framework_interaction.committedRow(
            row_index,
            log_size,
        );
        try std.testing.expect(trace[committed].eql(value));
    }
}

pub fn expectZeroPadding(
    columns: [][]M31,
    column_offset: usize,
    column_count: usize,
    first_padding_row: usize,
    log_size: u32,
) !void {
    const row_count = @as(usize, 1) << @intCast(log_size);
    for (columns[column_offset..][0..column_count]) |column| {
        for (first_padding_row..row_count) |logical_row| {
            const committed = air.framework_interaction.committedRow(
                logical_row,
                log_size,
            );
            try std.testing.expect(column[committed].isZero());
        }
    }
}
