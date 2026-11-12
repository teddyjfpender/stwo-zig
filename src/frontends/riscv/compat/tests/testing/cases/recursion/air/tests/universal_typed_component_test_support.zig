//! Test-only fixtures retained from the pre-restructure typed component gates.
//! Proof-adapter gates over real typed universal rows 29 and 33.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const core_accumulation = stwo_core.air.accumulation;
pub const core_components = stwo_core.air.components;
pub const circle = stwo_core.circle;
pub const pcs = stwo_core.pcs;
pub const M31 = stwo_core.fields.m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;
pub const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
pub const prover_component = @import("stwo_prover_engine").air.component_prover;
pub const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
pub const prover_task_graph = @import("stwo_prover_engine").task_graph;
pub const prover_work_pool = @import("stwo_prover_engine").work_pool;
pub const manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
pub const adapter = @import("stwo_riscv_air_lang").framework.universal_typed_component;
pub const universal_binding = @import("stwo_riscv_air_lang").framework.universal_relation_binding;
pub const universal = @import("stwo_riscv_air_lang").framework.universal_challenges;
pub const framework = @import("stwo_riscv_air_lang").framework.framework_interaction;
pub const catalog = @import("stwo_riscv_recursion_air").universal_catalog;
pub const roster = @import("stwo_riscv_air_lang").framework.universal_roster;
pub const fri_input = @import("stwo_riscv_recursion_air").fri.verifier_input;
pub const fri_relation = @import("stwo_riscv_recursion_air").fri.verifier_input_relation;
pub const merkle = @import("stwo_riscv_recursion_air").merkle.path;
pub const merkle_relation = @import("stwo_riscv_recursion_air").merkle.path_relation;
pub const merkle_witness = @import("stwo_riscv_recursion_air").merkle.path_witness;
pub const qm31_mul_relation = @import("stwo_riscv_recursion_air").testing.tests.qm31_mul_full_relation_test_support;
pub const relation_challenges = @import("stwo_riscv_air_lang").evaluation.relation_challenges;

pub const qm31_mul = @import("stwo_riscv_recursion_air").qm31.mul_full;

pub const FriAdapter = adapter.Component(fri_input, fri_relation);
pub const MerkleAdapter = adapter.Component(merkle, merkle_relation);
pub const MerkleFramework = framework.Runtime(merkle_relation.Runtime);

pub fn friGeometry(log_size: u32) manifest_mod.Geometry {
    return FriAdapter.manifestGeometry(.fri_verifier_input, log_size);
}

pub fn merkleGeometry(log_size: u32) manifest_mod.Geometry {
    return MerkleAdapter.manifestGeometry(.merkle_path, log_size);
}

pub fn admitTypedRow(
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
    const Verifier = @import("stwo_riscv_air_lang").framework.universal_typed_verifier_component.ComponentForManifest(
        Air,
        Relation,
        @import("stwo_riscv_air_lang").framework.universal_manifest_contract,
    );
    try std.testing.expect(!@hasDecl(Verifier, "asProverComponent"));
    const verifier = try Verifier.init(
        &definition,
        relation_plan,
        &manifest,
        roster_row,
        log_size,
        parameters,
        relations,
        QM31.zero(),
    );
    const verifier_binding = verifier.asVerifierComponent();
    try std.testing.expectEqual(component.nConstraints(), verifier_binding.nConstraints());
    try std.testing.expectEqual(component.maxConstraintLogDegreeBound(), verifier_binding.maxConstraintLogDegreeBound());
    const binding = try component.binding(&manifest);
    try std.testing.expectEqual(component.nConstraints(), binding.verifier.nConstraints());
    try std.testing.expectEqual(component.nConstraints(), binding.prover.nConstraints());
}

pub fn expectPairArraysEqual(expected: anytype, actual: @TypeOf(expected)) !void {
    for (expected, actual) |lhs, rhs| {
        try std.testing.expect(lhs.n1.eql(rhs.n1));
        try std.testing.expect(lhs.d1.eql(rhs.d1));
        try std.testing.expect(lhs.n2.eql(rhs.n2));
        try std.testing.expect(lhs.d2.eql(rhs.d2));
    }
}

pub fn fixtureInvocation(direction: u32) merkle_witness.Invocation {
    return .{
        .tree_id = 17,
        .depth = 2,
        .index = 3,
        .child = fixtureDigest(11),
        .step = .{ .direction = direction, .sibling = fixtureDigest(101) },
        .is_leaf = false,
    };
}

pub fn fixtureDigest(start: u32) [merkle.DIGEST_WORD_COUNT]u32 {
    var result: [merkle.DIGEST_WORD_COUNT]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = start + @as(u32, @intCast(index * 7));
    return result;
}

pub fn committedSecure(
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

pub fn testTaskContext(
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

pub fn prepareFailureCase(
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

pub fn verifierPointCase(comptime Component: type) !void {
    var definition = try merkle.build(std.testing.allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(4));
    const manifest = try builder.seal();
    const claimed_sum = QM31.fromU32Unchecked(17, 19, 23, 29);
    const component = try Component.init(
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
    try component.asVerifierComponent().evaluateConstraintQuotientsAtPoint(
        point,
        &values,
        &accumulator,
        component.log_size,
    );
    try std.testing.expect(accumulator.finalize().isZero());
    // Previous/current reversal must fail even though geometry and claims match.
    for (0..4) |index| std.mem.swap(QM31, &values_items[manifest_mod.INTERACTION_TREE_INDEX][final_start + index][0], &values_items[manifest_mod.INTERACTION_TREE_INDEX][final_start + index][1]);
    var reversed = core_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.asVerifierComponent().evaluateConstraintQuotientsAtPoint(
        point,
        &values,
        &reversed,
        component.log_size,
    );
    try std.testing.expect(!reversed.finalize().isZero());
}

pub const RawQuotientAir = @import("../../../../../../product_tree/recursion/air/ethereum_transcript_payload_raw.zig");
pub const RawQuotientAdapter = adapter.Component(RawQuotientAir, RawQuotientAir.Relation);

pub fn runRawQuotientStorage(
    allocator: std.mem.Allocator,
    values_allocator: ?std.mem.Allocator,
    component: *const RawQuotientAdapter,
    source_trace: *const prover_component.Trace,
) ![64]QM31 {
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = measured.allocator();
    var trace = source_trace.*;
    trace.quotient_values_allocator = values_allocator;
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        tracked,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(tracked, &trace, &accumulator)).?;
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var context = testTaskContext(prepared.context, &cancellation);
    const allocations = measured.alloc_index;
    measured.fail_index = allocations;
    measured.resize_fail_index = measured.resize_index;
    try prepared.run(&context);
    try std.testing.expectEqual(allocations, measured.alloc_index);
    try std.testing.expect(!measured.has_induced_failure);
    measured.fail_index = std.math.maxInt(usize);
    measured.resize_fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(tracked);
    try std.testing.expectEqual(@as(usize, 64), result.len());
    var values: [64]QM31 = undefined;
    for (&values, 0..) |*value, index| value.* = result.at(index);
    return values;
}

pub fn failRawQuotientValues(
    allocator: std.mem.Allocator,
    component: *const RawQuotientAdapter,
    trace: *const prover_component.Trace,
) !void {
    _ = try runRawQuotientStorage(std.testing.allocator, allocator, component, trace);
}

pub fn failRawQuotientMetadata(
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

pub fn runTypedPreparedWithWorkers(prepared: *prepared_domain.PreparedDomainEvaluation, workers: usize, cancel: bool) !void {
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
