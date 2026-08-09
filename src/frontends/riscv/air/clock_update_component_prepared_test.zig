//! Independent traversal oracle for the prepared clock-update AIR domain.

const std = @import("std");
const core_constraints = @import("stwo_core").constraints;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const pcs = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const core_utils = @import("stwo_core").utils;
const prover_engine = @import("stwo_prover_engine");
const prover_air_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prover_task_graph = prover_engine.task_graph;
const prover_work_pool = prover_engine.work_pool;
const ClockUpdateComponent = @import("clock_update_component.zig").ClockUpdateComponent;
const interaction = @import("clock_update_interaction.zig");
const relations_mod = @import("relation_challenges.zig");

const LOG_SIZE: u32 = 4;
const EVAL_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVAL_SIZE: usize = @as(usize, 1) << @intCast(EVAL_LOG_SIZE);
const IS_FIRST_INDEX: usize = 2;
const IS_ACTIVE_INDEX: usize = 5;
const MAIN_OFFSET: usize = 3;
const INTERACTION_OFFSET: usize = 4;
const PREPROCESSED_COUNT: usize = @max(IS_FIRST_INDEX, IS_ACTIVE_INDEX) + 1;
const MAIN_COUNT: usize = MAIN_OFFSET + interaction.N_MAIN_COLUMNS;
const INTERACTION_COUNT: usize = INTERACTION_OFFSET + interaction.N_INTERACTION_COLUMNS;
const SOURCE_COUNT: usize =
    2 + interaction.N_MAIN_COLUMNS + interaction.N_INTERACTION_COLUMNS;

const DomainFixture = struct {
    allocator: std.mem.Allocator,
    values: []M31,
    preprocessed: []prover_component.Poly,
    main: []prover_component.Poly,
    interaction_columns: []prover_component.Poly,
    trees: [][]const prover_component.Poly,

    fn init(allocator: std.mem.Allocator) !DomainFixture {
        const total_columns = PREPROCESSED_COUNT + MAIN_COUNT + INTERACTION_COUNT;
        const values = try allocator.alloc(M31, total_columns * EVAL_SIZE);
        errdefer allocator.free(values);
        const preprocessed = try allocator.alloc(prover_component.Poly, PREPROCESSED_COUNT);
        errdefer allocator.free(preprocessed);
        const main = try allocator.alloc(prover_component.Poly, MAIN_COUNT);
        errdefer allocator.free(main);
        const interaction_columns = try allocator.alloc(
            prover_component.Poly,
            INTERACTION_COUNT,
        );
        errdefer allocator.free(interaction_columns);
        const trees = try allocator.alloc([]const prover_component.Poly, 3);
        errdefer allocator.free(trees);

        var cursor: usize = 0;
        initTree(preprocessed, values, &cursor, 1);
        initTree(main, values, &cursor, 2);
        initTree(interaction_columns, values, &cursor, 3);
        std.debug.assert(cursor == values.len);
        trees[0] = preprocessed;
        trees[1] = main;
        trees[2] = interaction_columns;
        return .{
            .allocator = allocator,
            .values = values,
            .preprocessed = preprocessed,
            .main = main,
            .interaction_columns = interaction_columns,
            .trees = trees,
        };
    }

    fn trace(self: *const DomainFixture) prover_component.Trace {
        return .{
            .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(self.trees),
        };
    }

    fn deinit(self: *DomainFixture) void {
        const allocator = self.allocator;
        allocator.free(self.trees);
        allocator.free(self.interaction_columns);
        allocator.free(self.main);
        allocator.free(self.preprocessed);
        allocator.free(self.values);
        self.* = undefined;
    }
};

fn initTree(
    polys: []prover_component.Poly,
    values: []M31,
    cursor: *usize,
    tree_tag: usize,
) void {
    for (polys, 0..) |*poly, column_index| {
        const column = values[cursor.* .. cursor.* + EVAL_SIZE];
        cursor.* += EVAL_SIZE;
        for (column, 0..) |*value, row| {
            // Every tree, offset slot, source column, and row is distinct.
            const encoded = @as(u64, tree_tag) * 100_003 +
                @as(u64, column_index) * 1_009 + @as(u64, row) * 37 + 11;
            value.* = M31.fromU64(encoded);
        }
        poly.* = .{
            .log_size = EVAL_LOG_SIZE,
            .values = column,
        };
    }
}

fn referenceValues(poly: prover_component.Poly) ![]const M31 {
    try poly.validate();
    if (poly.log_size != EVAL_LOG_SIZE) return error.InvalidProofShape;
    return poly.values;
}

fn referenceSecure(
    evaluations: *const [SOURCE_COUNT][]const M31,
    offset: usize,
    row: usize,
) QM31 {
    return QM31.fromM31(
        evaluations[offset][row],
        evaluations[offset + 1][row],
        evaluations[offset + 2][row],
        evaluations[offset + 3][row],
    );
}

fn referenceFold(powers: []const QM31, constraints: []const QM31) QM31 {
    var result = QM31.zero();
    for (constraints, 0..) |constraint, index| {
        result = result.add(powers[powers.len - 1 - index].mul(constraint));
    }
    return result;
}

/// Reconstructs the legacy domain traversal without entering either component
/// domain-evaluation entry point. The row constraint kernel remains shared,
/// exactly as it was before the prepared execution boundary was introduced.
fn evaluateReferenceDomain(
    allocator: std.mem.Allocator,
    component_value: *const ClockUpdateComponent,
    trace_data: *const prover_component.Trace,
    accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
) !void {
    if (trace_data.polys.items.len < 3) return error.InvalidProofShape;
    const preprocessed = trace_data.polys.items[0];
    const main = trace_data.polys.items[1];
    const interaction_columns = trace_data.polys.items[2];
    if (preprocessed.len <= @max(
        component_value.is_first_col_idx,
        component_value.is_active_col_idx,
    ) or
        main.len < component_value.main_col_offset + interaction.N_MAIN_COLUMNS or
        interaction_columns.len <
            component_value.interaction_col_offset + interaction.N_INTERACTION_COLUMNS)
    {
        return error.InvalidProofShape;
    }

    var evaluations: [SOURCE_COUNT][]const M31 = undefined;
    evaluations[0] = try referenceValues(preprocessed[component_value.is_first_col_idx]);
    evaluations[1] = try referenceValues(preprocessed[component_value.is_active_col_idx]);
    var source: usize = 2;
    for (main[component_value.main_col_offset..][0..interaction.N_MAIN_COLUMNS]) |poly| {
        evaluations[source] = try referenceValues(poly);
        source += 1;
    }
    for (interaction_columns[component_value.interaction_col_offset..][0..interaction.N_INTERACTION_COLUMNS]) |poly| {
        evaluations[source] = try referenceValues(poly);
        source += 1;
    }
    std.debug.assert(source == evaluations.len);

    const eval_domain = canonic.CanonicCoset.new(EVAL_LOG_SIZE).circleDomain();
    var denominator_inv: [2]M31 = undefined;
    const trace_coset = canonic.CanonicCoset.new(component_value.log_size).coset();
    for (&denominator_inv, 0..) |*inverse, index| {
        inverse.* = try core_constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core_utils.bitReverseIndex(index, 1)),
        ).inv();
    }

    const accumulators = try accumulator.columns(
        allocator,
        &.{.{ .log_size = EVAL_LOG_SIZE, .n_cols = component_value.nConstraints() }},
    );
    defer allocator.free(accumulators);
    const column_accumulator = &accumulators[0];
    const main_start: usize = 2;
    const interaction_start = main_start + interaction.N_MAIN_COLUMNS;
    for (0..EVAL_SIZE) |row| {
        const previous_row = core_utils.previousBitReversedCircleDomainIndex(
            row,
            component_value.log_size,
            EVAL_LOG_SIZE,
        );
        var sampled: [interaction.N_MAIN_COLUMNS]QM31 = undefined;
        for (&sampled, evaluations[main_start..][0..interaction.N_MAIN_COLUMNS]) |*value, column| {
            value.* = QM31.fromBase(column[row]);
        }
        var current: [interaction.N_SUMS]QM31 = undefined;
        var previous: [interaction.N_SUMS]QM31 = undefined;
        for (0..interaction.N_SUMS) |index| {
            const offset = interaction_start + index * 4;
            current[index] = referenceSecure(&evaluations, offset, row);
            previous[index] = referenceSecure(&evaluations, offset, previous_row);
        }
        const evaluation = try component_value.evaluateRow(
            &sampled,
            current,
            previous,
            QM31.fromBase(evaluations[0][row]),
            QM31.fromBase(evaluations[1][row]),
        );
        const folded = referenceFold(
            column_accumulator.random_coeff_powers,
            &evaluation.values,
        );
        column_accumulator.accumulate(
            row,
            folded.mulM31(denominator_inv[row >> @intCast(component_value.log_size)]),
        );
    }
}

fn runPrepared(prepared: anytype) !void {
    var cancellation = prover_task_graph.CancellationToken{};
    var context = prover_task_graph.TaskContext{
        .user_context = prepared.context,
        .cancellation = &cancellation,
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
    try prepared.run(&context);
}

fn expectSameColumn(lhs: anytype, rhs: anytype) !void {
    try std.testing.expectEqual(lhs.len(), rhs.len());
    for (0..lhs.len()) |row| try std.testing.expect(lhs.at(row).eql(rhs.at(row)));
}

test "clock prepared domain matches an independent offset-aware traversal" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    const claims = [interaction.N_SUMS]QM31{
        QM31.fromU32Unchecked(5, 8, 13, 21),
        QM31.fromU32Unchecked(34, 55, 89, 144),
    };
    const component_value = try ClockUpdateComponent.initProver(
        LOG_SIZE,
        IS_FIRST_INDEX,
        IS_ACTIVE_INDEX,
        MAIN_OFFSET,
        INTERACTION_OFFSET,
        &relations,
        claims,
    );
    var fixture = try DomainFixture.init(allocator);
    defer fixture.deinit();
    var trace_data = fixture.trace();
    const random_coeff = QM31.fromU32Unchecked(3, 1, 4, 1);

    var reference_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        EVAL_LOG_SIZE,
        component_value.nConstraints(),
    );
    defer reference_accumulator.deinit();
    try evaluateReferenceDomain(
        allocator,
        &component_value,
        &trace_data,
        &reference_accumulator,
    );
    var reference = try reference_accumulator.finalize();
    defer reference.deinit(allocator);
    var saw_nonzero = false;
    for (0..reference.len()) |row| saw_nonzero = saw_nonzero or !reference.at(row).isZero();
    try std.testing.expect(saw_nonzero);

    var prepared_accumulator = try prover_air_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        random_coeff,
        EVAL_LOG_SIZE,
        component_value.nConstraints(),
    );
    defer prepared_accumulator.deinit();
    var prepared = (try component_value.asProverComponent()
        .prepareConstraintQuotientsOnDomain(
        allocator,
        &trace_data,
        &prepared_accumulator,
    )).?;
    defer prepared.deinit();
    try runPrepared(&prepared);
    var actual = try prepared_accumulator.finalize();
    defer actual.deinit(allocator);
    try expectSameColumn(&reference, &actual);
}
