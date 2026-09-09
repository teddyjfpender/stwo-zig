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

test "Ethereum typed quotient domains reject recovery larger than quotient buffer" {
    const helpers = @import("universal_typed_component_contract.zig");
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const trace_log: u32 = 4;
    const committed_log: u32 = trace_log + 4;
    const quotient_log: u32 = trace_log + 2;
    const committed = [_]M31{M31.zero()} ** (1 << committed_log);
    const coefficients = [_]M31{M31.zero()} ** (1 << trace_log);
    var poly = prover_component.Poly{ .log_size = committed_log, .values = &committed };
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(poly, trace_log, quotient_log));
    poly.coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    try std.testing.expect(try helpers.sourceNeedsExtension(poly, trace_log, quotient_log));
    try std.testing.expect(!try helpers.sourceNeedsExtension(poly, trace_log, committed_log));
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(poly, trace_log + 1, quotient_log));
}

test "Ethereum typed quotient domains recover released coefficients with exact polynomial parity" {
    const helpers = @import("universal_typed_component_contract.zig");
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
    const allocator = std.testing.allocator;
    for ([_]u32{ 2, 4, 6, 7, 8 }) |trace_log| {
        const source_domain = helpers.canonic.CanonicCoset.new(trace_log + 1).circleDomain();
        const quotient_domain = helpers.canonic.CanonicCoset.new(trace_log + 2).circleDomain();
        const native_size = @as(usize, 1) << @intCast(trace_log);
        const coefficients = try allocator.alloc(M31, native_size);
        defer allocator.free(coefficients);
        for (coefficients, 0..) |*coefficient, index|
            coefficient.* = M31.fromCanonical(@intCast(index * index + 3 * index + 7));
        const polynomial = try circle_poly.CircleCoefficients.initBorrowed(coefficients);
        const committed = try polynomial.evaluate(allocator, source_domain);
        defer allocator.free(@constCast(committed.values));
        const original_committed = try allocator.dupe(M31, committed.values);
        defer allocator.free(original_committed);
        const expected = try polynomial.evaluate(allocator, quotient_domain);
        defer allocator.free(@constCast(expected.values));
        var empty_buffers: [0][]M31 = .{};
        var borrowed_count: usize = 0;
        const borrowed = try helpers.evaluationValues(
            allocator,
            .{ .log_size = trace_log + 1, .values = committed.values },
            trace_log,
            trace_log + 1,
            source_domain.size(),
            null,
            &empty_buffers,
            &borrowed_count,
        );
        try std.testing.expect(borrowed.ptr == committed.values.ptr);
        try std.testing.expectEqual(@as(usize, 0), borrowed_count);
        var twiddles = try twiddles_mod.precomputeM31(allocator, quotient_domain.half_coset);
        defer twiddles_mod.deinitM31(allocator, &twiddles);
        const transform = twiddles_mod.TwiddleTree([]const M31).init(
            twiddles.root_coset,
            twiddles.twiddles,
            twiddles.itwiddles,
        );
        for ([_]bool{ false, true }) |retained| {
            const source = prover_component.Poly{
                .log_size = trace_log + 1,
                .values = committed.values,
                .coefficients = if (retained) polynomial else null,
            };
            try std.testing.expect(try helpers.sourceNeedsExtension(source, trace_log, trace_log + 2));
            var buffers: [1][]M31 = undefined;
            var initialized: usize = 0;
            defer for (buffers[0..initialized]) |buffer| allocator.free(buffer);
            const values = helpers.evaluationValues(
                allocator,
                source,
                trace_log,
                trace_log + 2,
                quotient_domain.size(),
                transform,
                &buffers,
                &initialized,
            ) catch |err| {
                std.debug.print("QUOTIENT_RECOVERY_PARITY trace_log={d} retained={} source_log={d} quotient_log={d} tower_matches={} error={s}\n", .{
                    trace_log,                                                   retained,        source.log_size, quotient_domain.logSize(),
                    source_domain.half_coset.isDoublingOf(transform.root_coset), @errorName(err),
                });
                var recovered = try circle_poly.poly.interpolateFromEvaluationWithTwiddles(
                    allocator,
                    committed,
                    transform,
                );
                defer recovered.deinit(allocator);
                for (recovered.coefficients(), 0..) |actual, index| {
                    const want = if (index < coefficients.len) coefficients[index] else M31.zero();
                    if (!actual.eql(want)) {
                        std.debug.print("QUOTIENT_RECOVERY_COEFFICIENT index={d} actual={d} expected={d}\n", .{ index, actual.v, want.v });
                        break;
                    }
                }
                return err;
            };
            try std.testing.expectEqual(@as(usize, 1), initialized);
            try std.testing.expect(values.ptr == buffers[0].ptr);
            try std.testing.expectEqualSlices(M31, coefficients, values[0..native_size]);
            for (values[native_size..]) |coefficient| try std.testing.expect(coefficient.isZero());
            try circle_poly.poly.evaluateBuffersWithTwiddles(&buffers, quotient_domain, transform);
            try std.testing.expectEqualSlices(M31, expected.values, values);
            try std.testing.expectEqualSlices(M31, original_committed, committed.values);
        }
    }
}

test "Ethereum typed quotient domains reject recovered high degree before truncation" {
    const helpers = @import("universal_typed_component_contract.zig");
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
    const allocator = std.testing.allocator;
    const trace_log: u32 = 4;
    const source_domain = helpers.canonic.CanonicCoset.new(trace_log + 1).circleDomain();
    const quotient_domain = helpers.canonic.CanonicCoset.new(trace_log + 2).circleDomain();
    var coefficients = [_]M31{M31.zero()} ** 32;
    coefficients[0] = M31.one();
    coefficients[16] = M31.one();
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    const committed = try polynomial.evaluate(allocator, source_domain);
    defer allocator.free(@constCast(committed.values));
    const source = prover_component.Poly{ .log_size = trace_log + 1, .values = committed.values };
    var twiddles = try twiddles_mod.precomputeM31(allocator, quotient_domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddles);
    var buffers: [1][]M31 = undefined;
    var initialized: usize = 0;
    defer for (buffers[0..initialized]) |buffer| allocator.free(buffer);
    try std.testing.expectError(error.InvalidProofShape, helpers.evaluationValues(
        allocator,
        source,
        trace_log,
        trace_log + 2,
        quotient_domain.size(),
        .{ .root_coset = twiddles.root_coset, .twiddles = twiddles.twiddles, .itwiddles = twiddles.itwiddles },
        &buffers,
        &initialized,
    ));
    try std.testing.expectEqual(@as(usize, 0), initialized);
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(source, trace_log + 2, trace_log + 3));
}

const RawQuotientAir = @import("ethereum_transcript_payload_raw_v1.zig");
const RawQuotientAdapter = adapter.Component(RawQuotientAir, RawQuotientAir.Relation);

fn runRawQuotientStorage(
    allocator: std.mem.Allocator,
    values_allocator: ?std.mem.Allocator,
    component: *const RawQuotientAdapter,
    source_trace: *const prover_component.Trace,
) ![64]QM31 {
    var trace = source_trace.*;
    trace.quotient_values_allocator = values_allocator;
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var context = testTaskContext(prepared.context, &cancellation);
    try prepared.run(&context);
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 64), result.len());
    var values: [64]QM31 = undefined;
    for (&values, 0..) |*value, index| value.* = result.at(index);
    return values;
}

fn failRawQuotientValues(
    allocator: std.mem.Allocator,
    component: *const RawQuotientAdapter,
    trace: *const prover_component.Trace,
) !void {
    _ = try runRawQuotientStorage(std.testing.allocator, allocator, component, trace);
}

fn failRawQuotientMetadata(
    allocator: std.mem.Allocator,
    component: *const RawQuotientAdapter,
    trace: *const prover_component.Trace,
) !void {
    // A distinct value allocator catches wrong-owner cleanup when metadata,
    // twiddles, the accumulator or prepared state fails after value allocation.
    var values = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    defer std.debug.assert(values.allocated_bytes == values.freed_bytes);
    _ = try runRawQuotientStorage(allocator, values.allocator(), component, trace);
}

test "Ethereum typed quotient domains route owned values and preserve mapped quotient results" {
    const allocator = std.testing.allocator;
    var definition = try RawQuotientAir.build(allocator);
    defer definition.deinit();
    const relation_plan = try RawQuotientAir.Relation.authenticate(&definition);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(RawQuotientAdapter.manifestGeometry(.transcript_payload, 4));
    const manifest = try builder.seal();
    const relations = universal.UniversalRelations.dummy();
    const component = try RawQuotientAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .transcript_payload,
        4,
        [_]M31{M31.zero()} ** RawQuotientAir.PARAMETER_COUNT,
        &relations,
        QM31.zero(),
    );
    // Exactly the failing real route's geometry ratio: native log4, committed
    // log5, quotient log6, no retained coefficients. Nonconstant inputs make
    // both inverse and forward transforms observable in the quotient parity.
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    var coefficients: [16]M31 = undefined;
    for (&coefficients, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index * index + 7));
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    const committed = try polynomial.evaluate(allocator, stwo_core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer allocator.free(@constCast(committed.values));
    const original = try allocator.dupe(M31, committed.values);
    defer allocator.free(original);
    const poly = prover_component.Poly{ .log_size = 5, .values = committed.values };
    var pp = [_]prover_component.Poly{poly} ** RawQuotientAir.PREPROCESSED_COLUMN_COUNT;
    var main = [_]prover_component.Poly{poly} ** RawQuotientAir.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{poly} ** RawQuotientAir.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{ &pp, &main, &interaction };
    const trace = prover_component.Trace{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees) };
    const expected = try runRawQuotientStorage(allocator, null, &component, &trace);
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const actual = try runRawQuotientStorage(allocator, measured.allocator(), &component, &trace);
    try std.testing.expectEqualDeep(expected, actual);
    const source_count = pp.len + main.len + interaction.len;
    try std.testing.expectEqual(source_count, measured.alloc_index);
    try std.testing.expectEqual(source_count * 64 * @sizeOf(M31), measured.allocated_bytes);
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(directory);
    var mapped = try @import("stwo_prover_engine").mmap_alloc.FileBackedAllocator.init(directory);
    defer mapped.deinit();
    const mapped_result = try runRawQuotientStorage(allocator, mapped.allocator(), &component, &trace);
    try std.testing.expectEqualDeep(expected, mapped_result);
    try std.testing.expect(mapped.total_bytes.load(.monotonic) > 0);
    try std.testing.expectEqual(@as(usize, 0), mapped.live_bytes.load(.monotonic));
    try std.testing.expectEqualSlices(M31, original, committed.values);
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientValues, .{ &component, &trace });
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientMetadata, .{ &component, &trace });
}

test "R-012 generic adapter shards exact quotient rows with bounded workers and joins failures" {
    const allocator = std.testing.allocator;
    var definition = try merkle.build(allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    var relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 17;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(&definition, relation_plan, &manifest, .merkle_path, log_size, .{}, &relations, QM31.zero());
    const eval_log = component.maxConstraintLogDegreeBound();
    const size = @as(usize, 1) << @intCast(eval_log);
    const values = try allocator.alloc(M31, size);
    defer allocator.free(values);
    for (values, 0..) |*value, row| value.* = M31.fromU64(row * 7919 + 17);
    const poly = prover_component.Poly{ .log_size = eval_log, .values = values };
    var main = [_]prover_component.Poly{poly} ** merkle.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{poly} ** merkle.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{ &.{}, &main, &interaction };
    const trace = prover_component.Trace{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees) };
    var expected: [4][]M31 = undefined;
    var expected_initialized: usize = 0;
    defer for (expected[0..expected_initialized]) |column| allocator.free(column);
    for ([_]usize{ 1, 2, 4 }) |workers| {
        var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.fromU32Unchecked(3, 1, 4, 1), eval_log, 2 * component.nConstraints());
        defer accumulator.deinit();
        const prover = component.asProverComponent();
        var fresh = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
        defer fresh.deinit();
        var additive = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
        defer additive.deinit();
        try std.testing.expectEqual(prover_task_graph.TaskClass.pool_exclusive, fresh.task_class);
        for ([_]*prepared_domain.PreparedDomainEvaluation{ &fresh, &additive }) |prepared| {
            const before = MerkleAdapter.preparedParallelTelemetrySnapshot();
            try runTypedPreparedWithWorkers(prepared, workers, false);
            const after = MerkleAdapter.preparedParallelTelemetrySnapshot();
            try std.testing.expectEqual(@as(u64, @intCast(workers - 1)), after.child_submissions - before.child_submissions);
            try std.testing.expectEqual(after.child_submissions - before.child_submissions, after.child_completions - before.child_completions);
            try std.testing.expectEqual(before.range_failures, after.range_failures);
        }
        var result = try accumulator.finalize();
        defer result.deinit(allocator);
        for (result.columns, 0..) |column, coordinate| {
            if (workers == 1) {
                expected[coordinate] = try allocator.dupe(M31, column);
                expected_initialized += 1;
            } else try std.testing.expectEqualSlices(M31, expected[coordinate], column);
        }
    }

    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.one(), eval_log, component.nConstraints());
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
    defer prepared.deinit();
    // Exercise cancellation on the actual four-worker path, before any row
    // writes. Every submitted range must still join before producer teardown.
    const before = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try runTypedPreparedWithWorkers(&prepared, 4, true);
    const after = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 3), after.child_submissions - before.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), after.child_completions - before.child_completions);
    const column = accumulator.sub_accumulations[eval_log].?;
    for (0..column.len()) |row| try std.testing.expect(column.at(row).isZero());

    // An invalid borrowed challenge arity induces a real row-evaluation error
    // after admission. A failing helper cannot outlive the prepared owner.
    var failure_accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.one(), eval_log, component.nConstraints());
    defer failure_accumulator.deinit();
    var failure_prepared = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &failure_accumulator)).?;
    defer failure_prepared.deinit();
    relations.elements[@intFromEnum(relation_plan.events[0].domain)].arity = 0;
    const failure_before = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectError(error.InvalidArity, runTypedPreparedWithWorkers(&failure_prepared, 4, false));
    const failure_after = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 3), failure_after.child_submissions - failure_before.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), failure_after.child_completions - failure_before.child_completions);
    try std.testing.expect(failure_after.range_failures > failure_before.range_failures);
}

fn runTypedPreparedWithWorkers(prepared: *prepared_domain.PreparedDomainEvaluation, workers: usize, cancel: bool) !void {
    const Runner = struct {
        prepared: *prepared_domain.PreparedDomainEvaluation,
        cancel: bool,
        fn run(context: *prover_task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            if (self.cancel) {
                var token = prover_task_graph.CancellationToken{};
                _ = token.request();
                const prior = context.cancellation;
                context.cancellation = &token;
                defer context.cancellation = prior;
                try self.prepared.run(context);
            } else try self.prepared.run(context);
        }
    };
    var runner = Runner{ .prepared = prepared, .cancel = cancel };
    var graph = try prover_task_graph.ComponentTaskGraph.init(std.testing.allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = .{ .epoch = 0, .stage_rank = 0, .component_registry_index = 0, .shard_or_chunk_index = 0 },
        .name = "typed-quotient-domain",
        .func = Runner.run,
        .context = &runner,
        .class = prepared.task_class,
        .resources = prepared.resources,
        .work_estimate = 1,
    });
    var pool: prover_work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES });
    defer pool.deinit();
    _ = try graph.execute(.{ .worker_budget = try prover_work_pool.WorkerBudget.init(workers), .pool = &pool });
}
