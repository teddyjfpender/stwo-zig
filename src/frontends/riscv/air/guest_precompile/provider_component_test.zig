//! End-to-end and adversarial evidence for the C-009 provider adapter.

const std = @import("std");
const core = @import("stwo_core");
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const circle = core.circle;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const pcs = core.pcs;
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const components = @import("component_registry.zig");
const direct = @import("direct_constraints.zig");
const interaction = @import("interaction.zig");
const logup = @import("../logup.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const challenges = @import("relation_challenges.zig");
const registry = @import("relation_registry.zig");
const statement_mod = @import("statement.zig");
const subject = @import("provider_component.zig");

const Relations = challenges.Poseidon2V1Relations;

fn q(value: u64) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn addOne(value: QM31) QM31 {
    return value.add(QM31.one());
}

const Fixture = struct {
    main: main_trace.Result,
    interactions: interaction.Result,

    fn init(allocator: std.mem.Allocator, count: u32, relations: *const Relations) !Fixture {
        var statement = support.coreFixture(count);
        const extension = try statement_mod.ExtensionStatement.canonical(
            &statement,
            count,
        );
        var logs = try support.logsFixture(allocator, count);
        defer logs.deinit();
        var main = try main_trace.generate(
            allocator,
            &statement,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        errdefer main.deinit();
        const interactions = try interaction.generate(
            allocator,
            &statement,
            &extension,
            &main,
            relations,
        );
        return .{ .main = main, .interactions = interactions };
    }

    fn deinit(self: *Fixture) void {
        self.interactions.deinit();
        self.main.deinit();
        self.* = undefined;
    }
};

fn providerAuthority(count: u32) !components.ProviderConstruction {
    const descriptor = try components.Descriptor.canonical(
        .guest_poseidon2_provider_compat_v1,
        count,
    );
    return switch (try components.Registry.forProfile(
        .rv32im_zkvm_poseidon2_v1,
    ).verifierConstruction(descriptor)) {
        .provider => |authority| authority,
        .caller => unreachable,
    };
}

fn componentFor(
    authority: components.ProviderConstruction,
    claims: [subject.batch_count]QM31,
    relations: *const Relations,
) !subject.ProviderComponent {
    const claim = try subject.Claim.canonical(authority, claims);
    return subject.ProviderComponent.initProver(
        authority,
        claim,
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
        relations,
    );
}

fn expectInitError(
    expected: anyerror,
    authority: components.ProviderConstruction,
    claim: subject.Claim,
    placement: subject.Placement,
    relations: *const Relations,
) !void {
    try std.testing.expectError(expected, subject.ProviderComponent.initVerifier(
        authority,
        claim,
        placement,
        relations,
    ));
}

fn providerRow(
    trace: *const main_trace.Result,
    logical_row: usize,
) [subject.main_column_count]QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    var result: [subject.main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(trace.providerMain(column)[row]);
    }
    return result;
}

fn providerSums(
    generated: *const interaction.Result,
    logical_row: usize,
) [subject.batch_count]QM31 {
    const row = main_trace.committedRow(logical_row, generated.log_size);
    var result: [subject.batch_count]QM31 = undefined;
    inline for (components.provider_batches) |batch| {
        const start: usize = batch.interaction_column_start;
        result[batch.ordinal] = QM31.fromM31(
            generated.providerColumn(start)[row],
            generated.providerColumn(start + 1)[row],
            generated.providerColumn(start + 2)[row],
            generated.providerColumn(start + 3)[row],
        );
    }
    return result;
}

fn selector(
    trace: *const main_trace.Result,
    index: usize,
    logical_row: usize,
) QM31 {
    const row = main_trace.committedRow(logical_row, trace.log_size);
    return QM31.fromBase(trace.providerPreprocessed(index)[row]);
}

fn expectAnyNonzero(values: []const QM31) !void {
    for (values) |value| if (!value.isZero()) return;
    return error.TestExpectedNonZero;
}

fn expectHonestFixture(count: u32) !void {
    const relations = Relations.dummy();
    var fixture = try Fixture.init(std.testing.allocator, count, &relations);
    defer fixture.deinit();
    const authority = try providerAuthority(count);
    const claim = try subject.Claim.canonical(
        authority,
        fixture.interactions.provider_claims,
    );
    try std.testing.expect(claim.component_sum.eql(
        fixture.interactions.providerTotal(),
    ));
    const component = try componentFor(
        authority,
        fixture.interactions.provider_claims,
        &relations,
    );
    const domain_size = fixture.main.domainSize();
    for (0..domain_size) |logical_row| {
        const previous_row = (logical_row + domain_size - 1) % domain_size;
        const evaluation = try component.evaluateRow(
            &providerRow(&fixture.main, logical_row),
            providerSums(&fixture.interactions, logical_row),
            providerSums(&fixture.interactions, previous_row),
            selector(&fixture.main, 0, logical_row),
            selector(&fixture.main, 1, logical_row),
        );
        try std.testing.expect(evaluation.allZero());
    }
}

test "guest provider component: honest C007 C008 active padding and zero-call rows" {
    try expectHonestFixture(2);
    try expectHonestFixture(0);
}

test "guest provider component: direct interaction and claim mutations reject" {
    const relations = Relations.dummy();
    var fixture = try Fixture.init(std.testing.allocator, 1, &relations);
    defer fixture.deinit();
    const authority = try providerAuthority(1);
    const component = try componentFor(
        authority,
        fixture.interactions.provider_claims,
        &relations,
    );
    const current = providerSums(&fixture.interactions, 0);
    const previous = providerSums(
        &fixture.interactions,
        fixture.main.domainSize() - 1,
    );
    const active = providerRow(&fixture.main, 0);
    try std.testing.expect((try component.evaluateRow(
        &active,
        current,
        previous,
        QM31.one(),
        QM31.one(),
    )).allZero());

    for ([_]usize{ 1, 17, 410, 427, 442, 443, 444 }) |column| {
        var mutated = active;
        mutated[column] = addOne(mutated[column]);
        const evaluation = try component.evaluateRow(
            &mutated,
            current,
            previous,
            QM31.one(),
            QM31.one(),
        );
        try expectAnyNonzero(evaluation.values[0..subject.direct_constraint_count]);
    }

    var padding = providerRow(&fixture.main, 1);
    padding[1] = QM31.one();
    const padding_evaluation = try component.evaluateRow(
        &padding,
        providerSums(&fixture.interactions, 1),
        current,
        QM31.zero(),
        QM31.zero(),
    );
    try expectAnyNonzero(
        padding_evaluation.values[0..subject.direct_constraint_count],
    );

    for (0..subject.batch_count) |batch| {
        var forged = current;
        forged[batch] = addOne(forged[batch]);
        const evaluation = try component.evaluateRow(
            &active,
            forged,
            previous,
            QM31.one(),
            QM31.one(),
        );
        try std.testing.expect(!evaluation.values[
            subject.ConstraintOrder.interaction(batch)
        ].isZero());
    }

    var forged_claims = fixture.interactions.provider_claims;
    forged_claims[1] = addOne(forged_claims[1]);
    const forged_component = try componentFor(authority, forged_claims, &relations);
    const forged_evaluation = try forged_component.evaluateRow(
        &active,
        current,
        previous,
        QM31.one(),
        QM31.one(),
    );
    try std.testing.expect(!forged_evaluation.values[
        subject.ConstraintOrder.interaction(1)
    ].isZero());

    try std.testing.expectError(error.InvalidProofShape, component.evaluateRow(
        active[0 .. subject.main_column_count - 1],
        current,
        previous,
        QM31.one(),
        QM31.one(),
    ));
}

test "guest provider component: authenticated four-event coefficient program is atomic" {
    const relations = Relations.dummy();
    var fixture = try Fixture.init(std.testing.allocator, 1, &relations);
    defer fixture.deinit();
    const active = providerRow(&fixture.main, 0);
    const padding = providerRow(&fixture.main, 1);

    var entries: [subject.event_count]interaction.Entry = undefined;
    for (&entries, 0..) |*entry, event| {
        entry.* = try interaction.providerEntry(&active, event);
        try std.testing.expectEqual(components.provider_events[event].schema, entry.schema);
        try std.testing.expectEqual(components.provider_events[event].role, entry.role);
        try std.testing.expectEqual(components.provider_events[event].arity, entry.arity);
        if (event < 3) try std.testing.expect(entry.numerator.isZero());
    }
    try std.testing.expect(entries[3].numerator.eql(QM31.one()));
    for (entries[0..3]) |entry| {
        try std.testing.expectEqual(@as(u32, 4), @intFromEnum(entry.schema));
        try std.testing.expectEqual(components.Role.request, entry.role);
    }
    try std.testing.expectEqual(registry.guest_schema_id, entries[3].schema);
    try std.testing.expectEqual(components.Role.emit, entries[3].role);
    try std.testing.expectEqual(@as(u8, registry.guest_relation_arity), entries[3].arity);
    for (0..16) |lane| {
        try std.testing.expect(entries[3].values[lane].eql(active[1 + lane]));
        try std.testing.expect(entries[3].values[16 + lane].eql(active[427 + lane]));
    }
    try std.testing.expect((try interaction.providerEntry(&padding, 3)).numerator.isZero());

    const pairs = try interaction.providerRowPairs(&active, &relations);
    try std.testing.expect(pairs[0].n1.isZero() and pairs[0].n2.isZero());
    try std.testing.expect(pairs[1].n1.isZero());
    try std.testing.expect(pairs[1].n2.eql(QM31.one()));
    const padding_pairs = try interaction.providerRowPairs(&padding, &relations);
    for (padding_pairs) |pair| {
        try std.testing.expect(pair.n1.isZero() and pair.n2.isZero());
    }
    try std.testing.expectEqual(@as(u8, 0), components.provider_batches[0].first_event);
    try std.testing.expectEqual(@as(?u8, 1), components.provider_batches[0].second_event);
    try std.testing.expectEqual(@as(u16, 0), components.provider_batches[0].interaction_column_start);
    try std.testing.expectEqual(@as(u8, 2), components.provider_batches[1].first_event);
    try std.testing.expectEqual(@as(?u8, 3), components.provider_batches[1].second_event);
    try std.testing.expectEqual(@as(u16, 4), components.provider_batches[1].interaction_column_start);

    const base_denominator = try entries[0].denominator(&relations);
    const guest_denominator = try entries[3].denominator(&relations);
    var guest_changed = relations;
    guest_changed.guest_poseidon2_io.z = addOne(
        guest_changed.guest_poseidon2_io.z,
    );
    try std.testing.expect((try entries[0].denominator(&guest_changed)).eql(
        base_denominator,
    ));
    try std.testing.expect(!(try entries[3].denominator(&guest_changed)).eql(
        guest_denominator,
    ));
    var base_changed = relations;
    base_changed.base.poseidon2.z = addOne(base_changed.base.poseidon2.z);
    try std.testing.expect(!(try entries[0].denominator(&base_changed)).eql(
        base_denominator,
    ));
    try std.testing.expect((try entries[3].denominator(&base_changed)).eql(
        guest_denominator,
    ));
}

test "guest provider component: claim geometry placement and identity fail closed" {
    const relations = Relations.dummy();
    const authority = try providerAuthority(1);
    const zero_claims = [_]QM31{QM31.zero()} ** subject.batch_count;
    const claim = try subject.Claim.canonical(authority, zero_claims);
    const placement = subject.Placement{
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
    };

    var bad_claims = zero_claims;
    bad_claims[0] = QM31.one();
    try std.testing.expectError(
        error.NonzeroLegacyBatchClaim,
        subject.Claim.canonical(authority, bad_claims),
    );
    const empty_authority = try providerAuthority(0);
    bad_claims = zero_claims;
    bad_claims[1] = QM31.one();
    try std.testing.expectError(
        error.NonZeroEmptyClaim,
        subject.Claim.canonical(empty_authority, bad_claims),
    );
    try std.testing.expectError(
        error.ComponentClaimMismatch,
        subject.Claim.init(authority, zero_claims, QM31.one()),
    );

    var malformed_claim = claim;
    malformed_claim.descriptor.log_size += 1;
    try expectInitError(
        error.ComponentLogSizeMismatch,
        authority,
        malformed_claim,
        placement,
        &relations,
    );
    malformed_claim = claim;
    malformed_claim.descriptor.main_columns -= 1;
    try expectInitError(error.ComponentGeometryMismatch, authority, malformed_claim, placement, &relations);
    malformed_claim = claim;
    malformed_claim.descriptor.n_rows = 2;
    try expectInitError(error.ClaimDescriptorMismatch, authority, malformed_claim, placement, &relations);

    var malformed_authority = authority;
    malformed_authority.compatibility_identity.maximum_constraint_degree = 2;
    try expectInitError(error.ProviderCompatibilityMismatch, malformed_authority, claim, placement, &relations);
    malformed_authority = authority;
    malformed_authority.enabled_mode = 0;
    try expectInitError(error.ConstructionAuthorityMismatch, malformed_authority, claim, placement, &relations);
    malformed_authority = authority;
    malformed_authority.compatibility_layout_digest[0] ^= 1;
    try expectInitError(error.ConstructionAuthorityMismatch, malformed_authority, claim, placement, &relations);
    var malformed_events = components.provider_events;
    malformed_events[3].numerator = .zero_in_guest_mode;
    malformed_authority = authority;
    malformed_authority.events = &malformed_events;
    try expectInitError(error.ConstructionAuthorityMismatch, malformed_authority, claim, placement, &relations);
    var malformed_batches = components.provider_batches;
    malformed_batches[1].interaction_column_start = 0;
    malformed_authority = authority;
    malformed_authority.batches = &malformed_batches;
    try expectInitError(error.ConstructionAuthorityMismatch, malformed_authority, claim, placement, &relations);

    var malformed_placement = placement;
    malformed_placement.is_active_col_idx = 2;
    try expectInitError(error.InvalidColumnPlacement, authority, claim, malformed_placement, &relations);
    malformed_placement = placement;
    malformed_placement.main_col_offset = std.math.maxInt(usize);
    try expectInitError(error.InvalidColumnPlacement, authority, claim, malformed_placement, &relations);

    const huge_descriptor = try components.Descriptor.canonical(
        .guest_poseidon2_provider_compat_v1,
        std.math.maxInt(u32),
    );
    const huge_authority = switch (try components.Registry.forProfile(
        .rv32im_zkvm_poseidon2_v1,
    ).verifierConstruction(huge_descriptor)) {
        .provider => |value| value,
        .caller => unreachable,
    };
    const huge_claim = try subject.Claim.canonical(huge_authority, zero_claims);
    try expectInitError(error.InvalidTraceLogSize, huge_authority, huge_claim, placement, &relations);
}

fn allocateMetadata(
    allocator: std.mem.Allocator,
    component: *const subject.ProviderComponent,
) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
}

test "guest provider component: exact adapter metadata order degree and allocation" {
    const relations = Relations.dummy();
    const authority = try providerAuthority(1);
    const component = try componentFor(
        authority,
        .{QM31.zero()} ** subject.batch_count,
        &relations,
    );
    try std.testing.expectEqual(@as(usize, 2), subject.preprocessed_column_count);
    try std.testing.expectEqual(@as(usize, 445), subject.main_column_count);
    try std.testing.expectEqual(@as(usize, 8), subject.interaction_column_count);
    try std.testing.expectEqual(@as(usize, 4), subject.event_count);
    try std.testing.expectEqual(@as(usize, 2), subject.batch_count);
    try std.testing.expectEqual(@as(usize, 875), subject.direct_constraint_count);
    try std.testing.expectEqual(@as(usize, 877), subject.constraint_count);
    try std.testing.expectEqual(@as(usize, 875), subject.ConstraintOrder.interaction_start);
    try std.testing.expectEqual(@as(usize, 876), subject.ConstraintOrder.interaction(1));
    try std.testing.expectEqual(@as(u8, 3), subject.maximum_constraint_degree);
    try std.testing.expectEqual(@as(usize, 0), subject.row_evaluation_allocation_count);
    try std.testing.expectEqual(@as(usize, 877), component.nConstraints());
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());

    var maximum: u8 = 0;
    for (0..subject.constraint_count) |index| {
        maximum = @max(maximum, try component.constraintDegreeBound(index));
    }
    try std.testing.expectEqual(subject.maximum_constraint_degree, maximum);
    try std.testing.expectEqual(
        @as(u8, 3),
        try component.constraintDegreeBound(subject.ConstraintOrder.interaction(0)),
    );
    try std.testing.expectEqual(
        @as(u8, 3),
        try component.constraintDegreeBound(subject.ConstraintOrder.interaction(1)),
    );
    try std.testing.expectError(
        error.InvalidConstraintIndex,
        component.constraintDegreeBound(subject.constraint_count),
    );

    const verifier = component.asVerifierComponent();
    const prover = component.asProverComponent();
    try std.testing.expectEqual(subject.constraint_count, verifier.nConstraints());
    try std.testing.expectEqual(subject.constraint_count, prover.nConstraints());
    try std.testing.expect(prover.prepare_domain_evaluator != null);

    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(@as(usize, 2), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 445), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, 8), bounds.items[2].len);
    for (bounds.items) |tree| for (tree) |log_size| {
        try std.testing.expectEqual(@as(u32, 4), log_size);
    };

    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var masks = try component.maskPoints(std.testing.allocator, point, 5);
    defer masks.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), masks.items.len);
    try std.testing.expectEqual(@as(usize, 2), masks.items[0].len);
    try std.testing.expectEqual(@as(usize, 445), masks.items[1].len);
    try std.testing.expectEqual(@as(usize, 8), masks.items[2].len);
    for (masks.items[0]) |column| try std.testing.expectEqual(@as(usize, 1), column.len);
    for (masks.items[1]) |column| try std.testing.expectEqual(@as(usize, 1), column.len);
    const previous = logup.prevRowPoint(5, point);
    for (masks.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(std.meta.eql(point, column[0]));
        try std.testing.expect(std.meta.eql(previous, column[1]));
    }
    try std.testing.expectError(
        error.InvalidProofShape,
        component.maskPoints(std.testing.allocator, point, 4),
    );
    const indices = try component.preprocessedColumnIndices(std.testing.allocator);
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1 }, indices);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateMetadata,
        .{&component},
    );
}

test "guest provider component: OODS sampling uses exact global offsets" {
    const relations = Relations.dummy();
    var fixture = try Fixture.init(std.testing.allocator, 1, &relations);
    defer fixture.deinit();
    const authority = try providerAuthority(1);
    const first_index: usize = 2;
    const active_index: usize = 3;
    const main_offset: usize = 5;
    const interaction_offset: usize = 7;
    const claim = try subject.Claim.canonical(
        authority,
        fixture.interactions.provider_claims,
    );
    const component = try subject.ProviderComponent.initVerifier(
        authority,
        claim,
        .{
            .is_first_col_idx = first_index,
            .is_active_col_idx = active_index,
            .main_col_offset = main_offset,
            .interaction_col_offset = interaction_offset,
        },
        &relations,
    );
    const active = providerRow(&fixture.main, 0);
    const current = providerSums(&fixture.interactions, 0);
    const previous = providerSums(
        &fixture.interactions,
        fixture.main.domainSize() - 1,
    );

    var pp_storage = [_][1]QM31{.{q(19)}} ** 5;
    pp_storage[first_index][0] = QM31.one();
    pp_storage[active_index][0] = QM31.one();
    var pp: [pp_storage.len][]QM31 = undefined;
    for (&pp, &pp_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{q(23)}} **
        (main_offset + subject.main_column_count + 2);
    for (main_storage[main_offset..][0..subject.main_column_count], active) |
        *destination,
        value,
    | destination[0] = value;
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var interaction_storage = [_][2]QM31{.{ q(29), q(31) }} **
        (interaction_offset + subject.interaction_column_count + 2);
    for (0..subject.batch_count) |batch| {
        const current_coordinates = current[batch].toM31Array();
        const previous_coordinates = previous[batch].toM31Array();
        for (0..4) |coordinate| {
            const column = interaction_offset + 4 * batch + coordinate;
            interaction_storage[column][0] = QM31.fromBase(
                current_coordinates[coordinate],
            );
            interaction_storage[column][1] = QM31.fromBase(
                previous_coordinates[coordinate],
            );
        }
    }
    var interaction_columns: [interaction_storage.len][]QM31 = undefined;
    for (&interaction_columns, &interaction_storage) |*column, *values| {
        column.* = values;
    }
    var composition_tree = [_][]QM31{};
    var trees = [_][][]QM31{
        &pp,
        &main,
        &interaction_columns,
        &composition_tree,
    };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &honest, 5);
    try std.testing.expect(honest.finalize().isZero());

    interaction_storage[interaction_offset + 4][0] = addOne(
        interaction_storage[interaction_offset + 4][0],
    );
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(point, &mask, &mutated, 5);
    try std.testing.expect(!mutated.finalize().isZero());
    interaction_storage[interaction_offset + 4][0] = interaction_storage[
        interaction_offset + 4
    ][0].sub(QM31.one());

    var ignored = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try std.testing.expectError(error.InvalidProofShape, component.evaluateConstraintQuotientsAtPoint(point, &mask, &ignored, 4));
    var short_trees = [_][][]QM31{
        &pp,
        main[0 .. main_offset + subject.main_column_count - 1],
        &interaction_columns,
    };
    const short_mask = core_air_components.MaskValues.initOwned(&short_trees);
    try std.testing.expectError(error.InvalidProofShape, component.evaluateConstraintQuotientsAtPoint(point, &short_mask, &ignored, 5));
    const saved_interaction = interaction_columns[interaction_offset];
    interaction_columns[interaction_offset] = saved_interaction[0..1];
    try std.testing.expectError(error.InvalidProofShape, component.evaluateConstraintQuotientsAtPoint(point, &mask, &ignored, 5));
    interaction_columns[interaction_offset] = saved_interaction;
}

fn taskContext(
    context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

fn runPreparedBounded(
    prepared: *prepared_domain.PreparedDomainEvaluation,
) !void {
    const Runner = struct {
        prepared: *prepared_domain.PreparedDomainEvaluation,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            var cancellation = prover_task_graph.CancellationToken{};
            var context = taskContext(self.prepared.context, &cancellation);
            self.prepared.run(&context) catch |err| {
                self.failure = err;
            };
        }
    };
    var runner = Runner{ .prepared = prepared };
    const thread = try std.Thread.spawn(
        .{ .stack_size = prepared.resources.worker_stack_bytes },
        Runner.run,
        .{&runner},
    );
    thread.join();
    if (runner.failure) |err| return err;
}

fn prepareAndRun(
    allocator: std.mem.Allocator,
    component: *const subject.ProviderComponent,
    trace_data: *const prover_component.Trace,
    eval_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
    try runPreparedBounded(&prepared);
}

test "guest provider component: prepared zero-call domain is exact bounded and allocation-safe" {
    const allocator = std.testing.allocator;
    const relations = Relations.dummy();
    const authority = try providerAuthority(0);
    const component = try componentFor(
        authority,
        .{QM31.zero()} ** subject.batch_count,
        &relations,
    );
    const eval_log_size: u32 = 5;
    const eval_size: usize = 1 << eval_log_size;
    var zero_values = [_]M31{M31.zero()} ** eval_size;
    const zero_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = &zero_values,
    };
    var preprocessed = [_]prover_component.Poly{zero_poly} **
        subject.preprocessed_column_count;
    var main = [_]prover_component.Poly{zero_poly} ** subject.main_column_count;
    var interaction_columns = [_]prover_component.Poly{zero_poly} **
        subject.interaction_column_count;
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction_columns,
    };
    const trace_data = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var one_values = [_]M31{M31.one()} ** eval_size;
    preprocessed[1] = .{ .log_size = eval_log_size, .values = &one_values };
    var mutated_accumulator = try prover_air_accumulation
        .DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer mutated_accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        &trace_data,
        &mutated_accumulator,
    );
    var mutated_result = try mutated_accumulator.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row| {
        saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    }
    try std.testing.expect(saw_nonzero);
    preprocessed[1] = zero_poly;

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(
        eval_size * 4 * @sizeOf(M31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(
        subject.prepared_row_stack_bytes,
        prepared.resources.worker_stack_bytes,
    );
    const allocation_count = failing.alloc_index;
    failing.fail_index = allocation_count;
    try runPreparedBounded(&prepared);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(prepared_allocator);
    for (0..result.len()) |row| try std.testing.expect(result.at(row).isZero());

    var short_trees = [_][]const prover_component.Poly{ &preprocessed, &main };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    var shape_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer shape_accumulator.deinit();
    try std.testing.expectError(error.InvalidProofShape, prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &short_trace,
        &shape_accumulator,
    ));
    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareAndRun,
        .{ &component, &trace_data, eval_log_size },
    );
}
