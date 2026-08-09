//! Focused contract tests for coordinator-prepared opcode lookup evaluation.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const pcs = @import("stwo_core").pcs;
const utils = @import("stwo_core").utils;
const prover_air_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_domain = @import("stwo_prover_engine").air.prepared_domain;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const work_pool = @import("stwo_prover_engine").work_pool;
const infra = @import("../../infra_trace.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");
const component_mod = @import("opcode_component.zig");
const entry = @import("entry.zig");
const opcode_entries = @import("opcode_entries.zig");
const opcode_interaction = @import("opcode_interaction.zig");

const OpcodeLookupComponent = component_mod.OpcodeLookupComponent;

fn activeAddiRow() trace.TraceRow {
    return .{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .rd_prev_val = 0,
        .rd_prev_clk = 0,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x0010_0093,
    };
}

test "opcode lookup component: every family has exact variable-width metadata" {
    const relations = relations_mod.Relations.dummy();
    for (0..trace.N_FAMILIES) |index| {
        const family: trace.OpcodeFamily = @enumFromInt(index);
        const n_batches = opcode_entries.batchCount(family);
        const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        const component = try OpcodeLookupComponent.initVerifier(
            family,
            4,
            0,
            0,
            0,
            &relations,
            claims[0..n_batches],
        );
        try std.testing.expectEqual(n_batches, component.nConstraints());
        var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
        defer bounds.deinitDeep(std.testing.allocator);
        try std.testing.expectEqual(
            opcode_entries.interactionColumnCount(family),
            bounds.items[2].len,
        );
        try std.testing.expectEqual(@as(usize, 0), bounds.items[1].len);
        _ = component.asVerifierComponent();
    }
}

test "opcode lookup component: large domains expose coordinator-prepared leaf work" {
    const relations = relations_mod.Relations.dummy();
    const family: trace.OpcodeFamily = .base_alu_imm;
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        12,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );
    const prover = component.asProverComponent();
    try std.testing.expect(prover.prepare_domain_evaluator != null);
    try std.testing.expect(prover.domain_parallel_evaluator == null);
    try std.testing.expect(!prover.pool_exclusive_domain);
}

test "opcode lookup component: generated active row satisfies every batch" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const size = @as(usize, 1) << @intCast(log_size);
    const n_main = trace.nColumnsForFamily(family);
    var main_storage: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (main_storage[0..n_main]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (main_storage[0..n_main]) |column| allocator.free(column);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    trace.fillFamilyColumns(&main_storage, placement.map(0), activeAddiRow(), family);
    const relations = relations_mod.Relations.dummy();
    var generated = try opcode_interaction.generate(
        allocator,
        family,
        main_storage[0..n_main],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        generated.claims[0..generated.n_batches],
    );
    var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
    const committed_row = placement.map(0);
    for (main_storage[0..n_main], sampled[0..n_main]) |column, *value| {
        value.* = QM31.fromBase(column[committed_row]);
    }
    var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const previous_row = placement.map(size - 1);
    for (0..generated.n_batches) |batch| {
        current[batch] = secureAt(generated.columns[4 * batch ..][0..4], committed_row);
        previous[batch] = secureAt(generated.columns[4 * batch ..][0..4], previous_row);
    }
    const honest = try component.evaluateRow(
        sampled[0..n_main],
        current[0..generated.n_batches],
        previous[0..generated.n_batches],
        QM31.one(),
    );
    try std.testing.expect(honest.allZero());
    current[0] = current[0].add(QM31.one());
    const mutated = try component.evaluateRow(
        sampled[0..n_main],
        current[0..generated.n_batches],
        previous[0..generated.n_batches],
        QM31.one(),
    );
    try std.testing.expect(!mutated.allZero());
}

test "opcode lookup component: prover construction rejects wrong claim count" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    try std.testing.expectError(
        error.InvalidTraceShape,
        OpcodeLookupComponent.initProver(.div, 4, 0, 0, 0, &relations, claims[0..1]),
    );
}

test "opcode lookup component: OODS uses exact global offsets" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    const size = @as(usize, 1) << @intCast(log_size);
    const n_main = trace.nColumnsForFamily(family);
    const n_interaction = opcode_entries.interactionColumnCount(family);
    const main_offset: usize = 3;
    const interaction_offset: usize = 5;
    const is_first_col_idx: usize = 2;
    var main_columns: [trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (main_columns[0..n_main]) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
    }
    defer for (main_columns[0..n_main]) |column| allocator.free(column);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    trace.fillFamilyColumns(&main_columns, placement.map(0), activeAddiRow(), family);
    const relations = relations_mod.Relations.dummy();
    var generated = try opcode_interaction.generate(
        allocator,
        family,
        main_columns[0..n_main],
        log_size,
        &relations,
    );
    defer generated.deinit(allocator);
    const component = try OpcodeLookupComponent.initVerifier(
        family,
        log_size,
        is_first_col_idx,
        main_offset,
        interaction_offset,
        &relations,
        generated.claims[0..generated.n_batches],
    );

    var pp_storage = [_][1]QM31{.{QM31.fromU32Unchecked(17, 3, 5, 7)}} ** 4;
    pp_storage[is_first_col_idx][0] = QM31.one();
    var preprocessed: [pp_storage.len][]QM31 = undefined;
    for (&preprocessed, &pp_storage) |*column, *values| column.* = values;
    var main_storage = [_][1]QM31{.{QM31.fromU32Unchecked(19, 2, 11, 13)}} **
        (trace.MAX_FAMILY_COLUMNS + main_offset + 2);
    const committed_row = placement.map(0);
    const previous_row = placement.map(size - 1);
    for (main_columns[0..n_main], main_storage[main_offset..][0..n_main]) |column, *value| {
        value[0] = QM31.fromBase(column[committed_row]);
    }
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values| column.* = values;
    var interaction_storage = [_][2]QM31{.{
        QM31.fromU32Unchecked(23, 17, 5, 3),
        QM31.fromU32Unchecked(29, 19, 7, 2),
    }} ** (opcode_interaction.MAX_COLUMNS + interaction_offset + 2);
    for (0..generated.n_batches) |batch| for (0..4) |coordinate| {
        interaction_storage[interaction_offset + 4 * batch + coordinate][0] =
            QM31.fromBase(generated.columns[4 * batch + coordinate][committed_row]);
        interaction_storage[interaction_offset + 4 * batch + coordinate][1] =
            QM31.fromBase(generated.columns[4 * batch + coordinate][previous_row]);
    };
    var secure: [interaction_storage.len][]QM31 = undefined;
    for (&secure, &interaction_storage) |*column, *values| column.* = values;
    var trees = [_][][]QM31{ &preprocessed, &main, &secure };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());
    interaction_storage[interaction_offset][0] =
        interaction_storage[interaction_offset][0].add(QM31.one());
    var mutated = core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());
    try std.testing.expectEqual(n_interaction, 4 * generated.n_batches);
}

fn allocateAdapterMetadata(
    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
) !void {
    var bounds = try component.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    var masks = try component.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound() + 2,
    );
    defer masks.deinitDeep(allocator);
    const indices = try component.preprocessedColumnIndices(allocator);
    defer allocator.free(indices);
    const expected_previous = logup.prevRowPoint(
        component.maxConstraintLogDegreeBound() + 2,
        circle.SECURE_FIELD_CIRCLE_GEN,
    );
    for (masks.items[2]) |column| {
        try std.testing.expectEqual(@as(usize, 2), column.len);
        try std.testing.expect(column[1].x.eql(expected_previous.x));
        try std.testing.expect(column[1].y.eql(expected_previous.y));
    }
}

test "opcode lookup component: metadata allocations roll back completely" {
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initVerifier(
        .div,
        4,
        7,
        11,
        13,
        &relations,
        claims[0..opcode_entries.batchCount(.div)],
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAdapterMetadata,
        .{&component},
    );
}

const OpcodeFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    preprocessed: [1]prover_component.Poly,
    main: [trace.MAX_FAMILY_COLUMNS]prover_component.Poly,
    secure: [opcode_interaction.MAX_COLUMNS]prover_component.Poly,
    trees: [3][]const prover_component.Poly,
    trace_data: prover_component.Trace,
    eval_log_size: u32,
    eval_size: usize,
    n_main: usize,
    n_interaction: usize,

    fn init(self: *@This(), allocator: std.mem.Allocator, family: trace.OpcodeFamily, log_size: u32) !void {
        const eval_log_size = log_size + 1;
        const eval_size = @as(usize, 1) << @intCast(eval_log_size);
        const n_main = trace.nColumnsForFamily(family);
        const n_interaction = opcode_entries.interactionColumnCount(family);
        const source_count = 1 + n_main + n_interaction;
        self.* = undefined;
        self.allocator = allocator;
        self.storage = try allocator.alloc(M31, source_count * eval_size);
        self.eval_log_size = eval_log_size;
        self.eval_size = eval_size;
        self.n_main = n_main;
        self.n_interaction = n_interaction;
        var source: usize = 0;
        self.preprocessed[0] = self.poly(source);
        source += 1;
        for (self.main[0..n_main]) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        for (self.secure[0..n_interaction]) |*destination| {
            destination.* = self.poly(source);
            source += 1;
        }
        self.trees = .{
            self.preprocessed[0..],
            self.main[0..n_main],
            self.secure[0..n_interaction],
        };
        self.trace_data = .{
            .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&self.trees),
        };
    }

    fn poly(self: *@This(), source: usize) prover_component.Poly {
        const start = source * self.eval_size;
        const values = self.storage[start .. start + self.eval_size];
        for (values, 0..) |*value, row| {
            value.* = M31.fromU64((@as(u64, source) + 1) * 65_537 + row * 257 + 1);
        }
        return .{ .log_size = self.eval_log_size, .values = values };
    }

    fn deinit(self: *@This()) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};

fn legacyEvaluateOpcodeDomain(
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    const allocator = accumulator.allocator;
    const eval_log_size = component.log_size + 1;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const eval_size = eval_domain.size();
    const n_main = trace.nColumnsForFamily(component.family);
    const n_interaction = opcode_entries.interactionColumnCount(component.family);
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const secure = trace_data.polys.items[2];
    const evaluations = try allocator.alloc([]const M31, 1 + n_main + n_interaction);
    defer allocator.free(evaluations);
    var source: usize = 0;
    evaluations[source] = preprocessed[component.is_first_col_idx].values;
    source += 1;
    for (main[component.main_col_offset..][0..n_main]) |poly| {
        evaluations[source] = poly.values;
        source += 1;
    }
    for (secure[component.interaction_col_offset..][0..n_interaction]) |poly| {
        evaluations[source] = poly.values;
        source += 1;
    }
    const denominator_inv = try allocator.alloc(M31, 2);
    defer allocator.free(denominator_inv);
    const coset = canonic.CanonicCoset.new(component.log_size).coset();
    for (denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = eval_log_size, .n_cols = component.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const direct_store = column_accumulator.next_fresh_index == 0;
    const interaction_start = 1 + n_main;
    const batch_count = component.nConstraints();
    const powers = column_accumulator.random_coeff_powers;
    for (0..eval_size) |row| {
        const previous_row = utils.previousBitReversedCircleDomainIndex(
            row,
            component.log_size,
            eval_log_size,
        );
        var sampled: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
        for (sampled[0..n_main], evaluations[1..][0..n_main]) |*value, column| {
            value.* = QM31.fromBase(column[row]);
        }
        var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
        for (0..batch_count) |batch| {
            current[batch] = secureAt(evaluations[interaction_start + 4 * batch ..][0..4], row);
            previous[batch] = secureAt(
                evaluations[interaction_start + 4 * batch ..][0..4],
                previous_row,
            );
        }
        const constraints = try component.evaluateRow(
            sampled[0..n_main],
            current[0..batch_count],
            previous[0..batch_count],
            QM31.fromBase(evaluations[0][row]),
        );
        var folded = QM31.zero();
        for (constraints.values[0..constraints.len], 0..) |constraint, index| {
            folded = folded.add(powers[powers.len - 1 - index].mul(constraint));
        }
        const contribution = folded.mulM31(
            denominator_inv[row >> @intCast(component.log_size)],
        );
        const output = column_accumulator.col;
        if (direct_store) output.set(row, contribution) else output.set(row, output.at(row).add(contribution));
    }
    column_accumulator.next_fresh_index = if (direct_store) eval_size else null;
}

fn serialTaskContext(
    user_context: *anyopaque,
    cancellation: *const prover_task_graph.CancellationToken,
) prover_task_graph.TaskContext {
    return .{
        .user_context = user_context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

const PreparedThreadInvocation = struct {
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
    failure: ?anyerror = null,

    fn run(self: *@This()) void {
        var context = serialTaskContext(self.prepared.context, self.cancellation);
        self.prepared.run(&context) catch |failure| {
            self.failure = failure;
        };
    }
};

fn runPreparedOnReviewedStack(
    prepared: *prepared_domain.PreparedDomainEvaluation,
    cancellation: *const prover_task_graph.CancellationToken,
) !void {
    var invocation = PreparedThreadInvocation{
        .prepared = prepared,
        .cancellation = cancellation,
    };
    const thread = try std.Thread.spawn(
        .{ .stack_size = prepared_domain.ROW_EVALUATOR_STACK_BYTES },
        PreparedThreadInvocation.run,
        .{&invocation},
    );
    thread.join();
    if (invocation.failure) |failure| return failure;
}

fn prepareOpcodeDomainForFailure(
    allocator: std.mem.Allocator,
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        trace_data,
        &accumulator,
    )).?;
    defer prepared.deinit();
}

fn expectByteEquivalent(expected: anytype, actual: anytype) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    inline for (0..4) |coordinate| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected.columns[coordinate]),
            std.mem.sliceAsBytes(actual.columns[coordinate]),
        );
    }
}

test "opcode prepared domain: legacy bytes allocation freedom stack and cancellation" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    var fixture: OpcodeFixture = undefined;
    try fixture.init(allocator, family, log_size);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );
    const random_coeff = QM31.fromU32Unchecked(3, 1, 0, 0);
    var legacy_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer legacy_accumulator.deinit();
    try legacyEvaluateOpcodeDomain(&component, &fixture.trace_data, &legacy_accumulator);
    var legacy = try legacy_accumulator.finalize();
    defer legacy.deinit(allocator);
    var saw_nonzero = false;
    for (0..legacy.len()) |row| saw_nonzero = saw_nonzero or !legacy.at(row).isZero();
    try std.testing.expect(saw_nonzero);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    const prepared_allocator = failing.allocator();
    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        prepared_allocator,
        random_coeff,
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    var prepared = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        prepared_allocator,
        &fixture.trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try std.testing.expectEqual(prover_task_graph.TaskClass.leaf, prepared.task_class);
    try std.testing.expectEqual(
        fixture.eval_size * @sizeOf(QM31),
        prepared.resources.final_output_bytes,
    );
    try std.testing.expect(prepared.resources.shared_resident_bytes > 0);
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.exclusive_scratch_bytes);
    try std.testing.expectEqual(@as(usize, 0), prepared.resources.device_resident_bytes);
    try std.testing.expectEqual(
        prepared_domain.ROW_EVALUATOR_STACK_BYTES,
        prepared.resources.worker_stack_bytes,
    );
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    var cancellation = prover_task_graph.CancellationToken{};
    try runPreparedOnReviewedStack(&prepared, &cancellation);
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
    failing.fail_index = std.math.maxInt(usize);
    failing.resize_fail_index = std.math.maxInt(usize);
    var actual = try prepared_accumulator.finalize();
    defer actual.deinit(prepared_allocator);
    try expectByteEquivalent(legacy, actual);

    try std.testing.checkAllAllocationFailures(
        allocator,
        prepareOpcodeDomainForFailure,
        .{ &component, &fixture.trace_data },
    );

    var cancelled_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        QM31.one(),
        fixture.eval_log_size,
        component.nConstraints(),
    );
    defer cancelled_accumulator.deinit();
    var cancelled = (try component.asProverComponent().prepareConstraintQuotientsOnDomain(
        allocator,
        &fixture.trace_data,
        &cancelled_accumulator,
    )).?;
    defer cancelled.deinit();
    var cancelled_token = prover_task_graph.CancellationToken{};
    _ = cancelled_token.request();
    try runPreparedOnReviewedStack(&cancelled, &cancelled_token);
    var cancelled_result = try cancelled_accumulator.finalize();
    defer cancelled_result.deinit(allocator);
    for (0..cancelled_result.len()) |row| {
        try std.testing.expect(cancelled_result.at(row).isZero());
    }
}

fn expectPrepareError(
    expected: anyerror,
    component: *const OpcodeLookupComponent,
    trace_data: *const prover_component.Trace,
    accumulator_log_size: u32,
) !void {
    var accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        std.testing.allocator,
        QM31.one(),
        accumulator_log_size,
        component.nConstraints(),
    );
    defer accumulator.deinit();
    try std.testing.expectError(
        expected,
        component.asProverComponent().prepareConstraintQuotientsOnDomain(
            std.testing.allocator,
            trace_data,
            &accumulator,
        ),
    );
}

test "opcode prepared domain: adversarial committed shapes fail closed" {
    const allocator = std.testing.allocator;
    const family: trace.OpcodeFamily = .base_alu_imm;
    const log_size: u32 = 4;
    var fixture: OpcodeFixture = undefined;
    try fixture.init(allocator, family, log_size);
    defer fixture.deinit();
    const relations = relations_mod.Relations.dummy();
    const claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    const component = try OpcodeLookupComponent.initProver(
        family,
        log_size,
        0,
        0,
        0,
        &relations,
        claims[0..opcode_entries.batchCount(family)],
    );

    var short_trees = [_][]const prover_component.Poly{
        fixture.trees[0],
        fixture.trees[1],
    };
    const short_trace = prover_component.Trace{
        .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&short_trees),
    };
    try expectPrepareError(
        error.InvalidProofShape,
        &component,
        &short_trace,
        fixture.eval_log_size,
    );
    var overflowing_offset = component;
    overflowing_offset.main_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    overflowing_offset = component;
    overflowing_offset.interaction_col_offset = std.math.maxInt(usize);
    try expectPrepareError(
        error.InvalidProofShape,
        &overflowing_offset,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    var impossible_log = component;
    impossible_log.log_size = std.math.maxInt(u32);
    try expectPrepareError(
        error.InvalidProofShape,
        &impossible_log,
        &fixture.trace_data,
        fixture.eval_log_size,
    );
    {
        const saved = fixture.main[0];
        defer fixture.main[0] = saved;
        fixture.main[0] = .{
            .log_size = fixture.eval_log_size - 1,
            .values = saved.values[0 .. fixture.eval_size / 2],
        };
        try expectPrepareError(
            error.InvalidProofShape,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
    {
        const saved = fixture.secure[0];
        defer fixture.secure[0] = saved;
        fixture.secure[0].values = saved.values[0 .. saved.values.len - 1];
        try expectPrepareError(
            error.InvalidColumnLength,
            &component,
            &fixture.trace_data,
            fixture.eval_log_size,
        );
    }
}

fn secureAt(columns: []const []const M31, row: usize) QM31 {
    return QM31.fromM31(columns[0][row], columns[1][row], columns[2][row], columns[3][row]);
}
