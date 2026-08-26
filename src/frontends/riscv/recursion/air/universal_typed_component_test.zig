//! Proof-adapter gates over real typed universal rows 29 and 33.

const std = @import("std");
const stwo_core = @import("stwo_core");
const core_accumulation = stwo_core.air.accumulation;
const core_components = stwo_core.air.components;
const circle = stwo_core.circle;
const pcs = stwo_core.pcs;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const manifest_mod = @import("universal_adapter_manifest.zig");
const adapter = @import("universal_typed_component.zig");
const universal_binding = @import("universal_relation_binding.zig");
const universal = @import("universal_challenges.zig");
const framework = @import("framework_interaction.zig");
const catalog = @import("universal_catalog.zig");
const roster = @import("universal_roster.zig");
const fri_input = @import("fri_verifier_input.zig");
const fri_relation = @import("fri_verifier_input_relation.zig");
const merkle = @import("merkle_path.zig");
const merkle_relation = @import("merkle_path_relation.zig");
const merkle_witness = @import("merkle_path_witness.zig");
const qm31_mul_relation = @import("qm31_mul_full_relation.zig");
const relation_challenges = @import("../../air/relation_challenges.zig");

const qm31_mul = @import("qm31_mul_full.zig");

const FriAdapter = adapter.Component(fri_input, fri_relation);
const MerkleAdapter = adapter.Component(merkle, merkle_relation);
const MerkleFramework = framework.Runtime(merkle_relation.Runtime);

test "R-012 universal manifest pins roster order offsets claims and transcript" {
    var builder = manifest_mod.Builder{};
    const fri_placement = try builder.append(friGeometry(4));
    const merkle_placement = try builder.append(merkleGeometry(4));
    const manifest = try builder.seal();
    try manifest.validate();

    try std.testing.expectEqual(@as(u32, 0), fri_placement.preprocessed_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.main_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.interaction_offset);
    try std.testing.expectEqual(@as(u32, 0), fri_placement.constraint_offset);
    try std.testing.expectEqual(@as(u32, 20), merkle_placement.preprocessed_offset);
    try std.testing.expectEqual(@as(u32, 2), merkle_placement.main_offset);
    try std.testing.expectEqual(@as(u32, 20), merkle_placement.interaction_offset);
    try std.testing.expectEqual(@as(u32, 8), merkle_placement.constraint_offset);
    try std.testing.expectEqual(@as(u32, 20), manifest.total_preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 48), manifest.total_main_columns);
    try std.testing.expectEqual(@as(u32, 28), manifest.total_interaction_columns);
    try std.testing.expectEqual(@as(u32, 21), manifest.total_constraints);

    var reverse = manifest_mod.Builder{};
    _ = try reverse.append(merkleGeometry(4));
    try std.testing.expectError(
        error.RosterOrderMismatch,
        reverse.append(friGeometry(4)),
    );
    var invalid = manifest_mod.Builder{};
    try std.testing.expectError(
        error.InvalidRosterRow,
        invalid.append(.{
            .roster_row = roster.COMPONENT_COUNT,
            .log_size = 4,
            .preprocessed_columns = 1,
            .main_columns = 1,
            .interaction_columns = 4,
            .direct_constraints = 1,
            .interaction_batches = 1,
            .protocol_constraint_degree = 3,
            .profiled_constraint_degree = 3,
            .semantic_digest = [_]u8{0} ** 32,
        }),
    );

    var claims = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bind(.fri_verifier_input, QM31.fromU32Unchecked(1, 2, 3, 4));
    try std.testing.expectError(
        error.ClaimAlreadyBound,
        claims.bind(.fri_verifier_input, QM31.zero()),
    );
    try std.testing.expectError(error.ClaimMissing, claims.sealClaims(&manifest));
    try claims.bind(.merkle_path, QM31.fromU32Unchecked(5, 6, 7, 8));
    try claims.sealClaims(&manifest);
    try claims.validate(&manifest);

    const Blake2sChannel = stwo_core.channel.blake2s.Blake2sChannel;
    var prover_channel = Blake2sChannel{};
    var verifier_channel = Blake2sChannel{};
    try manifest.mixStatementPrefix(&prover_channel);
    try claims.mixInteractionClaims(&manifest, &prover_channel);
    try manifest.mixStatementPrefix(&verifier_channel);
    try claims.mixInteractionClaims(&manifest, &verifier_channel);
    try std.testing.expect(
        prover_channel.drawSecureFelt().eql(verifier_channel.drawSecureFelt()),
    );

    var mutated = manifest;
    mutated.total_main_columns += 1;
    try std.testing.expectError(error.ManifestSealMismatch, mutated.validate());
    var mutated_claims = claims;
    mutated_claims.values[@intFromEnum(roster.Component.merkle_path)] = QM31.zero();
    try std.testing.expectError(
        error.ClaimSealMismatch,
        mutated_claims.validate(&manifest),
    );
}

test "R-012 generic adapter closes row 33 on every domain row" {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    const invocation = fixtureInvocation(1);
    const row = try merkle_witness.logicalRow(invocation);
    const rows = [_]merkle_relation.Row{row};
    var interaction = try MerkleFramework.generatePrepared(
        std.testing.allocator,
        &relation_plan,
        &rows,
        log_size,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);

    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        interaction.claimed_sum,
    );
    try std.testing.expectEqual(@as(usize, 13), component.nConstraints());
    try std.testing.expectEqual(@as(u32, log_size + 1), component.maxConstraintLogDegreeBound());

    const size: usize = 1 << log_size;
    for (0..size) |logical_row| {
        const committed = framework.committedRow(logical_row, log_size);
        const previous = framework.committedRow((logical_row + size - 1) % size, log_size);
        const logical = if (logical_row == 0)
            row
        else
            [_]M31{M31.zero()} ** merkle.LOGICAL_INPUT_COUNT;
        var current: [merkle.INTERACTION_BATCH_COUNT]QM31 = undefined;
        for (&current, 0..) |*value, batch|
            value.* = committedSecure(
                merkle.INTERACTION_BATCH_COUNT,
                &interaction.columns,
                batch,
                committed,
            );
        var roots: [MerkleAdapter.CONSTRAINT_COUNT_TOTAL]QM31 = undefined;
        try component.evaluateBaseRowInto(
            logical,
            current,
            committedSecure(
                merkle.INTERACTION_BATCH_COUNT,
                &interaction.columns,
                merkle.INTERACTION_BATCH_COUNT - 1,
                previous,
            ),
            &roots,
        );
        for (roots) |root| try std.testing.expect(root.isZero());
    }
}

test "R-012 generic adapter exposes a sealed outer proof gate" {
    var fri_definition = try fri_input.build(std.testing.allocator);
    defer fri_definition.deinit();
    const fri_plan = try fri_relation.authenticate(&fri_definition);
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    const row = try merkle_witness.logicalRow(fixtureInvocation(0));
    var interaction = try MerkleFramework.generatePrepared(
        std.testing.allocator,
        &relation_plan,
        &.{row},
        log_size,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(friGeometry(log_size));
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const fri_component = try FriAdapter.init(
        &fri_definition,
        fri_plan,
        &manifest,
        .fri_verifier_input,
        log_size,
        [_]M31{M31.zero()} ** FriAdapter.PARAMETER_COLUMN_COUNT,
        &relations,
        QM31.zero(),
    );
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        interaction.claimed_sum,
    );

    var gate = try manifest_mod.ProofGate.init(&manifest);
    try std.testing.expectError(
        error.AdapterOrderMismatch,
        gate.append(&manifest, try component.binding(&manifest)),
    );
    try gate.append(&manifest, try fri_component.binding(&manifest));
    try gate.append(&manifest, try component.binding(&manifest));
    try gate.sealGate(&manifest);
    try gate.validate(&manifest);
    const verifier = try gate.verifierSlice();
    const prover = try gate.proverSlice();
    try std.testing.expectEqual(@as(usize, 2), verifier.len);
    try std.testing.expectEqual(@as(usize, 2), prover.len);
    for (verifier, prover) |verifier_component, prover_component_value| {
        try std.testing.expectEqual(
            verifier_component.nConstraints(),
            prover_component_value.nConstraints(),
        );
    }

    const components = core_components.Components{
        .components = verifier,
        .n_preprocessed_columns = manifest.total_preprocessed_columns,
    };
    var bounds = try components.columnLogSizes(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, manifest_mod.TREE_COUNT), bounds.items.len);
    try std.testing.expectEqual(@as(usize, manifest.total_preprocessed_columns), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, manifest.total_main_columns), bounds.items[1].len);
    try std.testing.expectEqual(@as(usize, manifest.total_interaction_columns), bounds.items[2].len);
}

test "R-012 generic adapter prepared domain loop is allocation-free" {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        log_size,
        .{},
        &relations,
        QM31.zero(),
    );

    const eval_log_size = component.maxConstraintLogDegreeBound();
    const eval_size: usize = @as(usize, 1) << @intCast(eval_log_size);
    const zero_values = try std.testing.allocator.alloc(M31, eval_size);
    defer std.testing.allocator.free(zero_values);
    @memset(zero_values, M31.zero());
    const zero_poly = prover_component.Poly{
        .log_size = eval_log_size,
        .values = zero_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var main = [_]prover_component.Poly{zero_poly} **
        merkle.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{zero_poly} **
        merkle.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees),
    };

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = measured.allocator();
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(
        allocator,
        &trace,
        &accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(
        eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );
    const allocation_count = measured.alloc_index;
    measured.fail_index = allocation_count;
    measured.resize_fail_index = measured.resize_index;
    var cancellation = prover_task_graph.CancellationToken{};
    var task_context = testTaskContext(prepared.context, &cancellation);
    try prepared.run(&task_context);
    try std.testing.expectEqual(allocation_count, measured.alloc_index);
    try std.testing.expect(!measured.has_induced_failure);
    measured.fail_index = std.math.maxInt(usize);
    measured.resize_fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    for (0..result.len()) |row| try std.testing.expect(result.at(row).isZero());

    var cancelled_accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        std.testing.allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try prover.prepareConstraintQuotientsOnDomain(
        std.testing.allocator,
        &trace,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    var cancelled_context = testTaskContext(cancelled.context, &cancelled_token);
    try cancelled.run(&cancelled_context);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(std.testing.allocator);
    for (0..cancelled_result.len()) |row|
        try std.testing.expect(cancelled_result.at(row).isZero());

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        prepareFailureCase,
        .{ &component, &trace, eval_log_size },
    );
}

test "R-012 row 29 keeps the pinned cubic quotient budget despite conservative profiling" {
    var definition = try fri_input.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try fri_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 4;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(friGeometry(log_size));
    const manifest = try builder.seal();
    const parameters = [_]M31{M31.zero()} ** fri_input.PARAMETER_COUNT;
    const component = try FriAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .fri_verifier_input,
        log_size,
        parameters,
        &relations,
        QM31.zero(),
    );
    try std.testing.expectEqual(@as(u32, log_size + 1), component.maxConstraintLogDegreeBound());
    try std.testing.expectEqual(
        @as(usize, fri_input.DIRECT_CONSTRAINT_COUNT + fri_input.INTERACTION_BATCH_COUNT),
        component.nConstraints(),
    );
}

test "R-012 one compiler-owned adapter factory admits all 34 typed logical rows" {
    const relations = universal.UniversalRelations.dummy();
    inline for (catalog.LOGICAL_ROWS) |entry|
        try admitTypedRow(entry.Air, entry.row, entry.requires_location, &relations);
}

test "R-012 universal wire lowering is identical to the dedicated row 30 plan" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const UniversalRelation = universal_binding.Binding(qm31_mul);
    const universal_plan = try UniversalRelation.authenticate(&definition);
    const dedicated_plan = try qm31_mul_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();

    var row: UniversalRelation.Row = undefined;
    for (&row, 0..) |*value, index|
        value.* = M31.fromU64(@as(u64, @intCast(index)) + 1);
    const actual = try universal_plan.preparedRowPairs(row, &relations);
    const wire_elements = relations.get(.recursion_wire);
    const wire_challenge = relation_challenges.RelationElements(6).init(
        wire_elements.z,
        wire_elements.alpha,
    );
    const expected = try dedicated_plan.rowPairs(
        &definition,
        row[0..qm31_mul.PHYSICAL_MAIN_COLUMN_COUNT].*,
        wire_challenge,
    );
    try expectPairArraysEqual(expected, actual);

    var secure_row: UniversalRelation.Runtime.SecureRow = undefined;
    for (&secure_row, row) |*secure, base| secure.* = QM31.fromBase(base);
    const secure = try universal_plan.preparedSecureRowPairs(
        secure_row,
        &relations,
    );
    try expectPairArraysEqual(expected, secure);
}

fn friGeometry(log_size: u32) manifest_mod.Geometry {
    return FriAdapter.manifestGeometry(.fri_verifier_input, log_size);
}

fn merkleGeometry(log_size: u32) manifest_mod.Geometry {
    return MerkleAdapter.manifestGeometry(.merkle_path, log_size);
}

fn admitTypedRow(
    comptime Air: type,
    comptime roster_row: roster.Component,
    comptime has_location: bool,
    relations: *const universal.UniversalRelations,
) !void {
    const Relation = universal_binding.Binding(Air);
    const TypedAdapter = adapter.Component(Air, Relation);
    std.testing.refAllDecls(TypedAdapter);

    var definition = if (has_location)
        try Air.build(std.testing.allocator, .generated)
    else
        try Air.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try Relation.authenticate(&definition);
    const log_size: u32 = 4;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(TypedAdapter.manifestGeometry(roster_row, log_size));
    const manifest = try builder.seal();
    const parameters = [_]M31{M31.zero()} ** TypedAdapter.PARAMETER_COLUMN_COUNT;
    const component = try TypedAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        roster_row,
        log_size,
        parameters,
        relations,
        QM31.zero(),
    );
    try std.testing.expectEqual(
        @as(usize, Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT),
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        log_size + @max(
            @as(u32, 1),
            std.math.log2_int_ceil(
                u32,
                TypedAdapter.PROTOCOL_CONSTRAINT_DEGREE - 1,
            ),
        ),
        component.maxConstraintLogDegreeBound(),
    );
    const binding = try component.binding(&manifest);
    try std.testing.expectEqual(component.nConstraints(), binding.verifier.nConstraints());
    try std.testing.expectEqual(component.nConstraints(), binding.prover.nConstraints());
}

fn expectPairArraysEqual(expected: anytype, actual: @TypeOf(expected)) !void {
    for (expected, actual) |lhs, rhs| {
        try std.testing.expect(lhs.n1.eql(rhs.n1));
        try std.testing.expect(lhs.d1.eql(rhs.d1));
        try std.testing.expect(lhs.n2.eql(rhs.n2));
        try std.testing.expect(lhs.d2.eql(rhs.d2));
    }
}

fn fixtureInvocation(direction: u32) merkle_witness.Invocation {
    return .{
        .tree_id = 17,
        .depth = 2,
        .index = 3,
        .child = fixtureDigest(11),
        .step = .{ .direction = direction, .sibling = fixtureDigest(101) },
        .is_leaf = false,
    };
}

fn fixtureDigest(start: u32) [merkle.DIGEST_WORD_COUNT]u32 {
    var result: [merkle.DIGEST_WORD_COUNT]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = start + @as(u32, @intCast(index * 7));
    return result;
}

fn committedSecure(
    comptime batch_count: usize,
    columns: *const [4 * batch_count][]M31,
    secure_column: usize,
    row: usize,
) QM31 {
    return QM31.fromM31Array(.{
        columns[4 * secure_column][row],
        columns[4 * secure_column + 1][row],
        columns[4 * secure_column + 2][row],
        columns[4 * secure_column + 3][row],
    });
}

fn testTaskContext(
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

fn prepareFailureCase(
    allocator: std.mem.Allocator,
    component: *const MerkleAdapter,
    trace: *const prover_component.Trace,
    eval_log_size: u32,
) !void {
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        eval_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        trace,
        &accumulator,
    )).?;
    defer prepared.deinit();
    try prepared.validate();
}

test "R-012 generic adapter verifier point path consumes manifest offsets" {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(4));
    const manifest = try builder.seal();
    const claimed_sum = QM31.fromU32Unchecked(17, 19, 23, 29);
    const component = try MerkleAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .merkle_path,
        4,
        .{},
        &relations,
        claimed_sum,
    );
    const point = circle.SECURE_FIELD_CIRCLE_GEN;
    var masks = try component.maskPoints(
        std.testing.allocator,
        point,
        component.log_size,
    );
    defer masks.deinitDeep(std.testing.allocator);
    var values_items = try std.testing.allocator.alloc([][]QM31, masks.items.len);
    var initialized: usize = 0;
    defer {
        for (values_items[0..initialized]) |tree| {
            for (tree) |column| std.testing.allocator.free(column);
            std.testing.allocator.free(tree);
        }
        std.testing.allocator.free(values_items);
    }
    for (masks.items, values_items) |point_tree, *value_tree| {
        value_tree.* = try std.testing.allocator.alloc([]QM31, point_tree.len);
        for (point_tree, value_tree.*, 0..) |point_column, *value_column, column| {
            value_column.* = try std.testing.allocator.alloc(QM31, point_column.len);
            @memset(value_column.*, QM31.zero());
            _ = column;
        }
        initialized += 1;
    }
    // The final secure column is sampled as [previous, current].  With a
    // zero relation numerator its recurrence closes at current = -claim / N.
    // This non-symmetric assignment catches an accidental point-order swap.
    const shift = try claimed_sum.divM31(M31.fromU64(1 << 4));
    const current_coordinates = shift.neg().toM31Array();
    const final_start = 4 * (merkle.INTERACTION_BATCH_COUNT - 1);
    for (current_coordinates, 0..) |coordinate, index| {
        values_items[manifest_mod.INTERACTION_TREE_INDEX][final_start + index][1] =
            QM31.fromBase(coordinate);
    }
    var values = pcs.TreeVec([][]QM31).initOwned(values_items);
    // Ownership remains with the explicit defer above.
    var accumulator = core_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &values,
        &accumulator,
        component.log_size,
    );
    try std.testing.expect(accumulator.finalize().isZero());
}
