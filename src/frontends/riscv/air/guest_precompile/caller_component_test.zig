//! Focused correctness, geometry, and verifier evidence for the caller adapter.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const components = @import("component_registry.zig");
const direct = @import("direct_constraints.zig");
const guest_interaction = @import("interaction.zig");
const main_trace = @import("main_trace.zig");
const support = @import("main_trace_test_support.zig");
const relations_mod = @import("relation_challenges.zig");
const statement_mod = @import("statement.zig");
const subject = @import("caller_component.zig");

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn callerAuthority(
    descriptor: components.Descriptor,
) !components.CallerConstruction {
    return switch (try components.Registry.forProfile(.rv32im_zkvm_poseidon2_v1)
        .verifierConstruction(descriptor)) {
        .caller => |authority| authority,
        .provider => error.TestExpectedCallerAuthority,
    };
}

fn callerMainRow(
    main: *const main_trace.Result,
    row: usize,
) [subject.main_column_count]QM31 {
    var result: [subject.main_column_count]QM31 = undefined;
    for (&result, 0..) |*value, column| {
        value.* = QM31.fromBase(main.callerMain(column)[row]);
    }
    return result;
}

fn callerSums(
    interaction: *const guest_interaction.Result,
    row: usize,
) [subject.batch_count]QM31 {
    var result: [subject.batch_count]QM31 = undefined;
    for (&result, 0..) |*value, batch| {
        value.* = QM31.fromM31Array(.{
            interaction.callerColumn(4 * batch)[row],
            interaction.callerColumn(4 * batch + 1)[row],
            interaction.callerColumn(4 * batch + 2)[row],
            interaction.callerColumn(4 * batch + 3)[row],
        });
    }
    return result;
}

fn expectAllZero(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

fn expectSomeNonZero(values: anytype) !void {
    for (values) |value| if (!value.isZero()) return;
    return error.TestExpectedSomeNonZero;
}

fn initComponent(
    extension: *const statement_mod.ExtensionStatement,
    relations: *const relations_mod.Poseidon2V1Relations,
    claim: subject.Claim,
    placement: subject.ColumnPlacement,
) !subject.CallerComponent {
    return subject.CallerComponent.initProver(
        try callerAuthority(extension.components[0]),
        claim,
        placement,
        relations,
    );
}

fn canonicalClaim(
    extension: *const statement_mod.ExtensionStatement,
    batch_sums: [subject.batch_count]QM31,
) !subject.Claim {
    return subject.Claim.canonical(
        try callerAuthority(extension.components[0]),
        batch_sums,
    );
}

fn explicitClaim(
    extension: *const statement_mod.ExtensionStatement,
    batch_sums: [subject.batch_count]QM31,
    component_sum: QM31,
) !subject.Claim {
    return subject.Claim.init(
        try callerAuthority(extension.components[0]),
        batch_sums,
        component_sum,
    );
}

test "caller component owns exact geometry constraint order and degree bounds" {
    const allocator = std.testing.allocator;
    var core = support.coreFixture(3);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 3);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, .{QM31.zero()} ** subject.batch_count),
        .{
            .is_first_col_idx = 7,
            .is_active_col_idx = 8,
            .main_col_offset = 11,
            .interaction_col_offset = 17,
        },
    );

    try std.testing.expectEqual(@as(usize, 2), subject.preprocessed_column_count);
    try std.testing.expectEqual(@as(usize, 286), subject.main_column_count);
    try std.testing.expectEqual(@as(usize, 153), subject.event_count);
    try std.testing.expectEqual(@as(usize, 77), subject.batch_count);
    try std.testing.expectEqual(@as(usize, 308), subject.interaction_column_count);
    try std.testing.expectEqual(@as(usize, 417), subject.direct_constraint_count);
    try std.testing.expectEqual(@as(usize, 494), subject.constraint_count);
    try std.testing.expectEqual(@as(usize, 0), subject.row_evaluation_allocation_count);
    try std.testing.expectEqual(subject.direct_constraint_count, subject.ConstraintOrder.interaction_start);
    try std.testing.expectEqual(subject.constraint_count, subject.ConstraintOrder.end);
    for (0..subject.batch_count) |batch| {
        try std.testing.expectEqual(
            subject.ConstraintOrder.interaction_start + batch,
            subject.ConstraintOrder.interactionBatch(batch),
        );
    }

    const verifier = component.asVerifierComponent();
    const prover = component.asProverComponent();
    try std.testing.expectEqual(subject.constraint_count, verifier.nConstraints());
    try std.testing.expectEqual(subject.constraint_count, prover.nConstraints());
    try std.testing.expectEqual(@as(u32, 5), verifier.maxConstraintLogDegreeBound());
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    for (0..subject.direct_constraint_count) |index| {
        try std.testing.expectEqual(
            direct.callerConstraintDegreeBound(index),
            try component.constraintDegreeBound(index),
        );
    }
    for (subject.ConstraintOrder.interaction_start..subject.ConstraintOrder.end) |index| {
        try std.testing.expectEqual(
            @as(u8, 3),
            try component.constraintDegreeBound(index),
        );
    }
    try std.testing.expectError(
        error.InvalidConstraintIndex,
        component.constraintDegreeBound(subject.constraint_count),
    );

    var bounds = try verifier.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), bounds.items.len);
    try std.testing.expectEqual(subject.preprocessed_column_count, bounds.items[0].len);
    try std.testing.expectEqual(subject.main_column_count, bounds.items[1].len);
    try std.testing.expectEqual(subject.interaction_column_count, bounds.items[2].len);
    for (bounds.items) |tree| for (tree) |log_size| {
        try std.testing.expectEqual(@as(u32, 4), log_size);
    };

    const indices = try verifier.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 7, 8 }, indices);

    var masks = try verifier.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        verifier.maxConstraintLogDegreeBound() + 2,
    );
    defer masks.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 3), masks.items.len);
    try std.testing.expectEqual(subject.preprocessed_column_count, masks.items[0].len);
    try std.testing.expectEqual(subject.main_column_count, masks.items[1].len);
    try std.testing.expectEqual(subject.interaction_column_count, masks.items[2].len);
    for (masks.items[0]) |column| try std.testing.expectEqual(@as(usize, 1), column.len);
    for (masks.items[1]) |column| try std.testing.expectEqual(@as(usize, 1), column.len);
    for (masks.items[2]) |column| try std.testing.expectEqual(@as(usize, 2), column.len);
    try std.testing.expectError(
        error.InvalidProofShape,
        verifier.maskPoints(
            allocator,
            circle.SECURE_FIELD_CIRCLE_GEN,
            component.claim.descriptor.log_size,
        ),
    );
}

test "caller component accepts every honest C007 C008 active padding and cyclic row" {
    var core = support.coreFixture(3);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 3);
    var logs = try support.logsFixture(std.testing.allocator, 3);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var interaction = try guest_interaction.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();
    const claim = try explicitClaim(
        &extension,
        interaction.caller_claims,
        interaction.callerTotal(),
    );
    const component = try initComponent(
        &extension,
        &relations,
        claim,
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );

    for (0..main.domainSize()) |logical_row| {
        const row = main_trace.committedRow(logical_row, main.log_size);
        const previous_logical = if (logical_row == 0)
            main.domainSize() - 1
        else
            logical_row - 1;
        const previous_row = main_trace.committedRow(previous_logical, main.log_size);
        const main_row = callerMainRow(&main, row);
        const current = callerSums(&interaction, row);
        const previous = callerSums(&interaction, previous_row);
        const evaluation = try component.evaluateRow(
            main_row,
            current,
            previous,
            q(@intFromBool(logical_row == 0)),
            q(@intFromBool(logical_row < main.n_rows)),
        );
        try std.testing.expect(evaluation.allZero());

        const expected_direct = direct.evaluateCaller(
            main_row,
            q(@intFromBool(logical_row < main.n_rows)),
        );
        const expected_interaction = try guest_interaction.callerInteractionConstraints(
            &main_row,
            q(@intFromBool(logical_row == 0)),
            current,
            previous,
            interaction.caller_claims,
            &relations,
        );
        for (expected_direct, evaluation.values[0..subject.direct_constraint_count]) |expected, actual| {
            try std.testing.expect(actual.eql(expected));
        }
        for (expected_interaction, evaluation.values[subject.ConstraintOrder.interaction_start..]) |expected, actual| {
            try std.testing.expect(actual.eql(expected));
        }
    }
}

test "caller component zero-call claim and all sixteen rows are canonical" {
    var core = support.coreFixture(0);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 0);
    var logs = try support.logsFixture(std.testing.allocator, 0);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var interaction = try guest_interaction.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();
    const claim = try canonicalClaim(&extension, interaction.caller_claims);
    const component = try initComponent(
        &extension,
        &relations,
        claim,
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );
    try std.testing.expect(claim.component_sum.isZero());
    try std.testing.expectEqual(@as(usize, 16), main.domainSize());

    for (0..main.domainSize()) |logical_row| {
        const row = main_trace.committedRow(logical_row, main.log_size);
        const previous_row = main_trace.committedRow(
            if (logical_row == 0) main.domainSize() - 1 else logical_row - 1,
            main.log_size,
        );
        const evaluation = try component.evaluateRow(
            callerMainRow(&main, row),
            callerSums(&interaction, row),
            callerSums(&interaction, previous_row),
            q(@intFromBool(logical_row == 0)),
            QM31.zero(),
        );
        try std.testing.expect(evaluation.allZero());
    }
}

test "caller component isolates a direct-only materialization mutation" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var interaction = try guest_interaction.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, interaction.caller_claims),
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );
    const row = main_trace.committedRow(0, main.log_size);
    const previous_row = main_trace.committedRow(main.domainSize() - 1, main.log_size);
    var forged_main = callerMainRow(&main, row);
    const materialization = components.caller_layout.canonicalMaterialization(
        false,
        0,
        0,
    );
    forged_main[materialization] = forged_main[materialization].add(QM31.one());
    const evaluation = try component.evaluateRow(
        forged_main,
        callerSums(&interaction, row),
        callerSums(&interaction, previous_row),
        QM31.one(),
        QM31.one(),
    );
    try expectSomeNonZero(evaluation.values[0..subject.direct_constraint_count]);
    try expectAllZero(evaluation.values[subject.ConstraintOrder.interaction_start..]);
}

test "caller component rejects interaction mutation and aggregate-preserving cancellation" {
    var core = support.coreFixture(1);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    var main = try main_trace.generate(
        std.testing.allocator,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer main.deinit();
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var interaction = try guest_interaction.generate(
        std.testing.allocator,
        &core,
        &extension,
        &main,
        &relations,
    );
    defer interaction.deinit();
    const row = main_trace.committedRow(0, main.log_size);
    const previous_row = main_trace.committedRow(main.domainSize() - 1, main.log_size);
    const main_row = callerMainRow(&main, row);
    const previous = callerSums(&interaction, previous_row);
    const honest_current = callerSums(&interaction, row);
    const total = interaction.callerTotal();
    const component = try initComponent(
        &extension,
        &relations,
        try explicitClaim(&extension, interaction.caller_claims, total),
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );

    var forged_current = honest_current;
    forged_current[0] = forged_current[0].add(QM31.one());
    forged_current[1] = forged_current[1].sub(QM31.one());
    const forged_columns = try component.evaluateRow(
        main_row,
        forged_current,
        previous,
        QM31.one(),
        QM31.one(),
    );
    try expectAllZero(forged_columns.values[0..subject.direct_constraint_count]);
    try std.testing.expect(!forged_columns.values[
        subject.ConstraintOrder.interactionBatch(0)
    ].isZero());
    try std.testing.expect(!forged_columns.values[
        subject.ConstraintOrder.interactionBatch(1)
    ].isZero());

    var forged_batch_claims = interaction.caller_claims;
    forged_batch_claims[0] = forged_batch_claims[0].add(QM31.one());
    forged_batch_claims[1] = forged_batch_claims[1].sub(QM31.one());
    const forged_claim = try explicitClaim(&extension, forged_batch_claims, total);
    const forged_component = try initComponent(
        &extension,
        &relations,
        forged_claim,
        component.placement,
    );
    const forged_boundary = try forged_component.evaluateRow(
        main_row,
        honest_current,
        previous,
        QM31.one(),
        QM31.one(),
    );
    try std.testing.expect(!forged_boundary.values[
        subject.ConstraintOrder.interactionBatch(0)
    ].isZero());
    try std.testing.expect(!forged_boundary.values[
        subject.ConstraintOrder.interactionBatch(1)
    ].isZero());
}

test "caller component fails closed on malformed claims authority and placement" {
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var core = support.coreFixture(3);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 3);
    const authority = try callerAuthority(extension.components[0]);
    const zero_sums = [_]QM31{QM31.zero()} ** subject.batch_count;
    const placement = subject.Placement{
        .is_first_col_idx = 0,
        .is_active_col_idx = 1,
        .main_col_offset = 0,
        .interaction_col_offset = 0,
    };
    const honest_claim = try subject.Claim.canonical(authority, zero_sums);

    try std.testing.expectError(
        error.ComponentClaimMismatch,
        subject.Claim.init(authority, zero_sums, QM31.one()),
    );

    var forged_authority = authority;
    forged_authority.descriptor.main_columns -= 1;
    try std.testing.expectError(
        error.ComponentGeometryMismatch,
        subject.CallerComponent.initProver(
            forged_authority,
            honest_claim,
            placement,
            &relations,
        ),
    );

    try std.testing.expectError(
        error.InvalidColumnPlacement,
        subject.CallerComponent.initProver(
            authority,
            honest_claim,
            .{
                .is_first_col_idx = 0,
                .is_active_col_idx = 2,
                .main_col_offset = 0,
                .interaction_col_offset = 0,
            },
            &relations,
        ),
    );
    try std.testing.expectError(
        error.InvalidColumnPlacement,
        subject.CallerComponent.initProver(
            authority,
            honest_claim,
            .{
                .is_first_col_idx = 0,
                .is_active_col_idx = 1,
                .main_col_offset = std.math.maxInt(usize),
                .interaction_col_offset = 0,
            },
            &relations,
        ),
    );

    var mismatched_claim = honest_claim;
    mismatched_claim.descriptor = try components.Descriptor.canonical(
        .guest_poseidon2_provider_compat_v1,
        authority.descriptor.n_rows,
    );
    try std.testing.expectError(
        error.ClaimDescriptorMismatch,
        subject.CallerComponent.initVerifier(
            authority,
            mismatched_claim,
            placement,
            &relations,
        ),
    );

    var forged_identity = authority;
    forged_identity.constraint_identity.maximum_constraint_degree -= 1;
    try std.testing.expectError(
        error.CallerConstraintIdentityMismatch,
        subject.CallerComponent.initVerifier(
            forged_identity,
            honest_claim,
            placement,
            &relations,
        ),
    );
    try std.testing.expectError(
        error.ProfileDoesNotAdmitComponent,
        components.Registry.forProfile(.rv32im_zkvm_v1)
            .verifierConstruction(authority.descriptor),
    );

    var empty_core = support.coreFixture(0);
    const empty_extension = try statement_mod.ExtensionStatement.canonical(&empty_core, 0);
    const empty_authority = try callerAuthority(empty_extension.components[0]);
    var nonzero_empty = zero_sums;
    nonzero_empty[0] = QM31.one();
    try std.testing.expectError(
        error.NonZeroEmptyClaim,
        subject.Claim.init(empty_authority, nonzero_empty, QM31.one()),
    );

    const oversized_descriptor = try components.Descriptor.canonical(
        .guest_poseidon2_call_v1,
        std.math.maxInt(u32),
    );
    const oversized_authority = try callerAuthority(oversized_descriptor);
    const oversized_claim = try subject.Claim.canonical(oversized_authority, zero_sums);
    try std.testing.expectError(
        error.InvalidTraceLogSize,
        subject.CallerComponent.initVerifier(
            oversized_authority,
            oversized_claim,
            placement,
            &relations,
        ),
    );
}

test "caller component preserves non-base secure-field order exactly" {
    var core = support.coreFixture(2);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 2);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    var batch_claims: [subject.batch_count]QM31 = undefined;
    var current: [subject.batch_count]QM31 = undefined;
    var previous: [subject.batch_count]QM31 = undefined;
    for (&batch_claims, &current, &previous, 0..) |*claim, *sum, *prev, index| {
        claim.* = QM31.fromU32Unchecked(@intCast(index + 1), 2, 3, 4);
        sum.* = QM31.fromU32Unchecked(5, @intCast(index + 6), 7, 8);
        prev.* = QM31.fromU32Unchecked(9, 10, @intCast(index + 11), 12);
    }
    var main: [subject.main_column_count]QM31 = undefined;
    for (&main, 0..) |*value, index| {
        value.* = QM31.fromU32Unchecked(
            @intCast(index + 13),
            @intCast(index + 17),
            @intCast(index + 19),
            @intCast(index + 23),
        );
    }
    const claim = try canonicalClaim(&extension, batch_claims);
    const component = try initComponent(
        &extension,
        &relations,
        claim,
        .{
            .is_first_col_idx = 0,
            .is_active_col_idx = 1,
            .main_col_offset = 0,
            .interaction_col_offset = 0,
        },
    );
    const is_first = QM31.fromU32Unchecked(31, 37, 41, 43);
    const is_active = QM31.fromU32Unchecked(47, 53, 59, 61);
    const evaluation = try component.evaluateRow(
        main,
        current,
        previous,
        is_first,
        is_active,
    );
    const expected_direct = direct.evaluateCaller(main, is_active);
    const expected_interaction = try guest_interaction.callerInteractionConstraints(
        &main,
        is_first,
        current,
        previous,
        batch_claims,
        &relations,
    );
    for (expected_direct, evaluation.values[0..subject.direct_constraint_count]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
    for (expected_interaction, evaluation.values[subject.ConstraintOrder.interaction_start..]) |expected, actual| {
        try std.testing.expect(actual.eql(expected));
    }
}

test "caller component verifier samples exact offsets and rejects malformed masks" {
    const first_index: usize = 1;
    const active_index: usize = 2;
    const main_offset: usize = 3;
    const interaction_offset: usize = 5;
    var core = support.coreFixture(0);
    const extension = try statement_mod.ExtensionStatement.canonical(&core, 0);
    const relations = relations_mod.Poseidon2V1Relations.dummy();
    const component = try initComponent(
        &extension,
        &relations,
        try canonicalClaim(&extension, .{QM31.zero()} ** subject.batch_count),
        .{
            .is_first_col_idx = first_index,
            .is_active_col_idx = active_index,
            .main_col_offset = main_offset,
            .interaction_col_offset = interaction_offset,
        },
    );

    var preprocessed_storage = [_][1]QM31{.{q(17)}} ** 5;
    preprocessed_storage[first_index][0] = QM31.one();
    preprocessed_storage[active_index][0] = QM31.zero();
    var preprocessed: [preprocessed_storage.len][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values| column.* = values;

    var main_storage = [_][1]QM31{.{q(19)}} **
        (main_offset + subject.main_column_count + 2);
    for (main_storage[main_offset..][0..subject.main_column_count]) |*value| {
        value[0] = QM31.zero();
    }
    var main_mask: [main_storage.len][]QM31 = undefined;
    for (&main_mask, &main_storage) |*column, *values| column.* = values;

    var interaction_storage = [_][2]QM31{.{ q(23), q(29) }} **
        (interaction_offset + subject.interaction_column_count + 2);
    for (interaction_storage[interaction_offset..][0..subject.interaction_column_count]) |*value| {
        value.* = .{ QM31.zero(), QM31.zero() };
    }
    var interaction_mask: [interaction_storage.len][]QM31 = undefined;
    for (&interaction_mask, &interaction_storage) |*column, *values| column.* = values;

    var composition_tree = [_][]QM31{};
    var trees = [_][][]QM31{
        &preprocessed,
        &main_mask,
        &interaction_mask,
        &composition_tree,
    };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(q(7));
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());

    main_storage[main_offset + components.caller_layout.canonical_materializations][0] =
        QM31.one();
    var forged = core_air_accumulation.PointEvaluationAccumulator.init(q(7));
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &forged,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!forged.finalize().isZero());

    var short_trees = [_][][]QM31{ &preprocessed, &main_mask };
    const short_mask = core_air_components.MaskValues.initOwned(&short_trees);
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(
            point,
            &short_mask,
            &forged,
            component.maxConstraintLogDegreeBound(),
        ),
    );
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(
            point,
            &mask,
            &forged,
            component.claim.descriptor.log_size,
        ),
    );
}
