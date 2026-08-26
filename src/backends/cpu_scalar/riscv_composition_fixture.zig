//! Shared authenticated-composition fixture.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const composition = @import("riscv_composition.zig");
const lanes = @import("riscv_composition_lanes.zig");
const profile_test = @import("riscv_composition_profile_test.zig");
const composition_work = prover.air.composition_work;

const constraints = core.constraints;
const m31 = core.fields.m31;
const qm31 = core.fields.qm31;
const packed_qm31 = core.fields.packed_qm31;
const canonic = core.poly.circle.canonic;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const PackedM31 = m31.PackedM31;
const PackedQM31 = packed_qm31.PackedQM31;
const Component = prover.air.component_prover.ComponentProver;
const BaseProgram = prover.air.component_prover.OwnedBasePolynomialProgram;
const LookupProgram = prover.air.component_prover.OwnedLookupPolynomialProgram;
const LookupProgramV2 = prover.air.component_prover.OwnedLookupPolynomialProgramV2;
const LookupAuthorityV2 = prover.air.component_prover.LookupPolynomialAuthorityV2;
const Poly = prover.air.component_prover.Poly;
const Trace = prover.air.component_prover.Trace;
const Accumulator = prover.air.accumulation.DomainEvaluationAccumulator;
const ColumnAccumulator = prover.air.accumulation.ColumnAccumulator;
const PreparedDomainEvaluation = prover.air.prepared_domain.PreparedDomainEvaluation;
const TaskContext = prover.task_graph.TaskContext;

const evaluate = composition.evaluate;
const evaluateWithExecution = composition.evaluateWithExecution;
const telemetrySnapshot = composition.telemetrySnapshot;

fn denominatorScalars(eval_log_size: u32) ![2]M31 {
    if (eval_log_size == 0) return error.InvalidCompositionLogSize;
    const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
    const trace_coset = canonic.CanonicCoset.new(eval_log_size - 1).coset();
    var result: [2]M31 = undefined;
    for (&result, 0..) |*inverse, index| {
        inverse.* = try constraints.cosetVanishing(
            M31,
            trace_coset,
            eval_domain.at(core.utils.bitReverseIndex(index, 1)),
        ).inv();
    }
    return result;
}

pub const DifferentialPair = struct {
    trace_log_size: u32,
    relation_z: QM31,
    relation_alpha: QM31,
    relation_z_2: QM31 = QM31.zero(),
    relation_alpha_2: QM31 = QM31.zero(),
    claim: QM31,
    selected_pair: bool = false,
    lookup_v2_authority: LookupAuthorityV2 = undefined,
    legacy_semantic_calls: ?*std.atomic.Value(usize) = null,
    prepared_semantic_calls: ?*std.atomic.Value(usize) = null,
    prepared_semantic_runs: ?*std.atomic.Value(usize) = null,

    pub fn cast(ctx: *const anyopaque) *const DifferentialPair {
        return @ptrCast(@alignCast(ctx));
    }

    pub fn semanticComponent(self: *const DifferentialPair) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateSemanticReference,
            },
            .backend_composition_capability = .{
                .base_polynomial_v1 = .{
                    .program_id = 0x1001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 1,
                    .main_tree_index = 1,
                    .first_main_column = 0,
                    .main_column_count = 2,
                    .export_program = exportSemanticProgram,
                },
            },
            .composition_work_profile = semanticWorkProfile,
            .prepare_domain_evaluator = prepareSemanticDomain,
        };
    }

    pub fn lookupComponent(self: *const DifferentialPair, mismatched_offset: bool) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateLookupReference,
            },
            .backend_composition_capability = .{
                .lookup_polynomial_v1 = .{
                    .program_id = 0x2001,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 0,
                    .main_tree_index = 1,
                    .first_main_column = if (mismatched_offset) 1 else 0,
                    .main_column_count = 2,
                    .interaction_tree_index = 2,
                    .first_interaction_column = 0,
                    .interaction_column_count = 4,
                    .export_program = exportLookupProgram,
                    .export_parameters = exportLookupParameters,
                },
            },
            .composition_work_profile = lookupWorkProfile,
        };
    }

    pub fn lookupV2Component(self: *const DifferentialPair) Component {
        return .{
            .ctx = self,
            .vtable = &.{
                .nConstraints = oneConstraint,
                .maxConstraintLogDegreeBound = evalLogSize,
                .traceLogDegreeBounds = unusedTraceBounds,
                .maskPoints = unusedMaskPoints,
                .preprocessedColumnIndices = noPreprocessedIndices,
                .evaluateConstraintQuotientsAtPoint = unusedPointEvaluation,
                .evaluateConstraintQuotientsOnDomain = evaluateLookupReference,
            },
            .backend_composition_capability = .{
                .lookup_polynomial_v2 = .{
                    .authority = &self.lookup_v2_authority,
                    .trace_log_size = self.trace_log_size,
                    .selector_tree_index = 0,
                    .selector_column = 0,
                    .main_tree_index = 1,
                    .first_main_column = 0,
                    .main_column_count = 2,
                    .interaction_tree_index = 2,
                    .first_interaction_column = 0,
                    .interaction_column_count = qm31.SECURE_EXTENSION_DEGREE,
                    .export_program = exportLookupProgramV2,
                    .export_parameters = exportLookupParameters,
                },
            },
            .composition_work_profile = lookupV2WorkProfile,
        };
    }

    pub fn initializeV2Authority(
        self: *DifferentialPair,
        allocator: std.mem.Allocator,
    ) !void {
        var program = try exportLookupProgramV2(self, allocator);
        defer program.deinit();
        self.lookup_v2_authority = try program.authority();
    }

    pub fn oneConstraint(_: *const anyopaque) usize {
        return 1;
    }

    pub fn evalLogSize(ctx: *const anyopaque) u32 {
        return cast(ctx).trace_log_size + 1;
    }

    pub fn unusedTraceBounds(
        _: *const anyopaque,
        _: std.mem.Allocator,
    ) !core.air.components.TraceLogDegreeBounds {
        return error.UnusedDifferentialHook;
    }

    pub fn unusedMaskPoints(
        _: *const anyopaque,
        _: std.mem.Allocator,
        _: core.circle.CirclePointQM31,
        _: u32,
    ) !core.air.components.MaskPoints {
        return error.UnusedDifferentialHook;
    }

    pub fn noPreprocessedIndices(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]usize {
        return allocator.alloc(usize, 0);
    }

    pub fn unusedPointEvaluation(
        _: *const anyopaque,
        _: core.circle.CirclePointQM31,
        _: *const core.air.components.MaskValues,
        _: *core.air.accumulation.PointEvaluationAccumulator,
        _: u32,
    ) !void {}

    pub fn exportSemanticProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !BaseProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
            .{ .op = .mul, .lhs = 0, .rhs = 1 },
            .{ .op = .column, .value = 2 },
            .{ .op = .sub, .lhs = 2, .rhs = 3 },
        });
        errdefer allocator.free(nodes);
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .roots = try allocator.dupe(u32, &.{4}),
            .column_count = 3,
        };
    }

    pub fn exportLookupProgram(
        _: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !LookupProgram {
        const nodes = try allocator.dupe(prover.air.component_prover.BasePolynomialNode, &.{
            .{ .op = .column, .value = 0 },
            .{ .op = .column, .value = 1 },
        });
        errdefer allocator.free(nodes);
        const entries = try allocator.alloc(prover.air.component_prover.LookupPolynomialEntry, 1);
        errdefer allocator.free(entries);
        var roots: [prover.air.component_prover.MAX_LOOKUP_POLYNOMIAL_ARITY]u32 = undefined;
        roots[0] = 0;
        entries[0] = .{ .numerator = 1, .values = roots, .arity = 1 };
        return .{
            .allocator = allocator,
            .nodes = nodes,
            .entries = entries,
            .column_count = 2,
            .batch_size = 1,
        };
    }

    pub fn exportLookupProgramV2(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) !LookupProgramV2 {
        const self = cast(ctx);
        const nodes = try allocator.dupe(
            prover.air.component_prover.BasePolynomialNode,
            &.{
                .{ .op = .column, .value = 0 },
                .{ .op = .column, .value = 1 },
            },
        );
        errdefer allocator.free(nodes);
        const entry_count: usize = if (self.selected_pair) 2 else 1;
        const entries = try allocator.alloc(
            prover.air.component_prover.LookupPolynomialEntry,
            entry_count,
        );
        errdefer allocator.free(entries);
        var first_roots: [prover.air.component_prover.MAX_LOOKUP_POLYNOMIAL_ARITY]u32 =
            undefined;
        first_roots[0] = 0;
        entries[0] = .{
            .numerator = 1,
            .values = first_roots,
            .arity = 1,
        };
        if (self.selected_pair) {
            var second_roots: [prover.air.component_prover.MAX_LOOKUP_POLYNOMIAL_ARITY]u32 =
                undefined;
            second_roots[0] = 1;
            entries[1] = .{
                .numerator = 0,
                .values = second_roots,
                .arity = 1,
            };
        }
        const event_degrees = try allocator.alloc(
            prover.air.component_prover.LookupPolynomialEventDegreeV2,
            entry_count,
        );
        errdefer allocator.free(event_degrees);
        for (event_degrees, 0..) |*event, ordinal| {
            event.* = .{
                .ordinal = @intCast(ordinal),
                .numerator_degree = 1,
                .denominator_degree = 1,
            };
        }
        const batches = try allocator.alloc(
            prover.air.component_prover.LookupPolynomialBatchV2,
            1,
        );
        errdefer allocator.free(batches);
        batches[0] = .{
            .first_entry = 0,
            .entry_count = @intCast(entry_count),
            .interaction_degree = if (self.selected_pair) 3 else 2,
        };
        const component_identity = [_]u8{0x31} ** 32;
        const partition_identity = if (self.selected_pair)
            [_]u8{0x52} ** 32
        else
            [_]u8{0x41} ** 32;
        const layout = try prover.air.component_prover.LookupPolynomialLayoutV2.init(
            component_identity,
            partition_identity,
            2,
            3,
            event_degrees,
            batches,
        );
        var program = LookupProgramV2{
            .allocator = allocator,
            .layout = layout,
            .nodes = nodes,
            .entries = entries,
            .event_degrees = event_degrees,
            .batches = batches,
            .program_identity = .{0} ** 32,
        };
        errdefer program.deinit();
        try program.seal();
        return program;
    }

    pub fn exportLookupParameters(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) ![]QM31 {
        const self = cast(ctx);
        if (self.selected_pair) {
            return allocator.dupe(QM31, &.{
                self.relation_z,
                self.relation_alpha,
                self.relation_z_2,
                self.relation_alpha_2,
                self.claim,
            });
        }
        return allocator.dupe(QM31, &.{
            self.relation_z,
            self.relation_alpha,
            self.claim,
        });
    }

    pub fn semanticWorkProfile(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work.ComponentProfile {
        var program = try exportSemanticProgram(ctx, allocator);
        defer program.deinit();
        const expression = try allNodeWork(allocator, program.nodes);
        const constraint = try composition_work.rootFoldWork(program.roots.len);
        const evaluation_log_size = evalLogSize(ctx);
        const authority = composition_work.sourceAuthority(
            "cpu-riscv-composition-test-semantic-v1",
            &.{
                evaluation_log_size,
                program.nodes.len,
                program.roots.len,
                program.column_count,
            },
            expression,
            constraint,
        );
        return composition_work.ComponentProfile.init(
            .base_polynomial,
            authority,
            evaluation_log_size,
            program.roots.len,
            expression,
            constraint,
            .{},
        );
    }

    pub fn lookupWorkProfile(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work.ComponentProfile {
        var program = try exportLookupProgram(ctx, allocator);
        defer program.deinit();
        const expression = try allNodeWork(allocator, program.nodes);
        const constraint = try composition_work.lookupConstraintWork(&program);
        const evaluation_log_size = evalLogSize(ctx);
        const authority = composition_work.sourceAuthority(
            "cpu-riscv-composition-test-lookup-v1",
            &.{
                evaluation_log_size,
                program.nodes.len,
                program.entries.len,
                program.batchCount(),
                program.column_count,
            },
            expression,
            constraint,
        );
        return composition_work.ComponentProfile.init(
            .lookup_polynomial_v1,
            authority,
            evaluation_log_size,
            program.batchCount(),
            expression,
            constraint,
            .{},
        );
    }

    pub fn lookupV2WorkProfile(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
    ) anyerror!composition_work.ComponentProfile {
        var program = try exportLookupProgramV2(ctx, allocator);
        defer program.deinit();
        const expression = try allNodeWork(allocator, program.nodes);
        const constraint = try composition_work.lookupConstraintWorkV2(&program);
        const evaluation_log_size = evalLogSize(ctx);
        const authority = composition_work.sourceAuthority(
            "cpu-riscv-composition-test-lookup-v2",
            &.{
                evaluation_log_size,
                program.nodes.len,
                program.entries.len,
                program.batches.len,
                program.layout.column_count,
            },
            expression,
            constraint,
        );
        return composition_work.ComponentProfile.init(
            .lookup_polynomial_v2,
            authority,
            evaluation_log_size,
            program.batches.len,
            expression,
            constraint,
            .{},
        );
    }

    pub fn allNodeWork(
        allocator: std.mem.Allocator,
        nodes: []const prover.air.component_prover.BasePolynomialNode,
    ) !composition_work.FieldOperations {
        // Every node in these minimal test exports is reachable from a root or
        // lookup entry. Keep that fixture invariant explicit and cold-path only.
        const reachable = try allocator.alloc(bool, nodes.len);
        defer allocator.free(reachable);
        @memset(reachable, true);
        return composition_work.nodeWork(nodes, reachable);
    }

    pub fn evaluateSemanticReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        if (self.legacy_semantic_calls) |calls| _ = calls.fetchAdd(1, .monotonic);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_active = trace.polys.items[0][1].values;
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const constraint = main[0].values[row].mul(main[1].values[row])
                .sub(is_active[row]);
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mulM31(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    pub fn evaluateLookupReference(
        ctx: *const anyopaque,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !void {
        const self = cast(ctx);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        const main = trace.polys.items[1];
        const is_first = trace.polys.items[0][0].values;
        const interaction = trace.polys.items[2];
        const denominators = try denominatorScalars(eval_log_size);
        var columns = try accumulator.columns(
            accumulator.allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        defer accumulator.allocator.free(columns);
        for (0..row_count) |row| {
            const previous_row = core.utils.previousBitReversedCircleDomainIndex(
                row,
                self.trace_log_size,
                eval_log_size,
            );
            const current = secureAt(interaction, row);
            const previous = secureAt(interaction, previous_row);
            const relation_denominator = self.relation_alpha.mulM31(main[0].values[row])
                .sub(self.relation_z);
            const delta = current.sub(previous).add(self.claim.mulM31(is_first[row]));
            const constraint = if (self.selected_pair) selected: {
                const second_denominator = self.relation_alpha_2
                    .mulM31(main[1].values[row])
                    .sub(self.relation_z_2);
                break :selected delta.mul(relation_denominator)
                    .mul(second_denominator)
                    .sub(second_denominator.mulM31(main[1].values[row]))
                    .sub(relation_denominator.mulM31(main[0].values[row]));
            } else delta.mul(relation_denominator)
                .sub(QM31.fromBase(main[1].values[row]));
            columns[0].accumulate(
                row,
                columns[0].random_coeff_powers[0].mul(constraint)
                    .mulM31(denominators[@intFromBool(row >= row_count / 2)]),
            );
        }
    }

    const PreparedSemanticState = struct {
        allocator: std.mem.Allocator,
        owner: *const DifferentialPair,
        main_0: []const M31,
        main_1: []const M31,
        is_active: []const M31,
        denominators: [2]M31,
        column_accumulators: []ColumnAccumulator,

        const vtable = prover.air.prepared_domain.VTable{
            .run = runErased,
            .deinit = deinitErased,
        };

        fn runErased(context: *anyopaque, task_context: *TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.owner.prepared_semantic_runs) |runs| {
                _ = runs.fetchAdd(1, .monotonic);
            }
            const column = &self.column_accumulators[0];
            for (self.main_0, self.main_1, self.is_active, 0..) |lhs, rhs, active, row| {
                if (task_context.isCancelled()) return;
                const constraint = lhs.mul(rhs).sub(active);
                column.accumulate(
                    row,
                    column.random_coeff_powers[0].mulM31(constraint)
                        .mulM31(self.denominators[@intFromBool(row >= self.main_0.len / 2)]),
                );
            }
        }

        fn deinitErased(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const allocator = self.allocator;
            allocator.free(self.column_accumulators);
            allocator.destroy(self);
        }
    };

    pub fn prepareSemanticDomain(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        trace: *const Trace,
        accumulator: *Accumulator,
    ) !PreparedDomainEvaluation {
        const self = cast(ctx);
        if (self.prepared_semantic_calls) |calls| _ = calls.fetchAdd(1, .monotonic);
        const eval_log_size = self.trace_log_size + 1;
        const row_count = @as(usize, 1) << @intCast(eval_log_size);
        if (trace.polys.items.len < 2 or trace.polys.items[0].len < 2 or
            trace.polys.items[1].len < 2)
        {
            return error.InvalidProofShape;
        }
        const main = trace.polys.items[1];
        const is_active = trace.polys.items[0][1].values;
        if (main[0].values.len != row_count or main[1].values.len != row_count or
            is_active.len != row_count)
        {
            return error.InvalidProofShape;
        }

        const denominators = try denominatorScalars(eval_log_size);
        const state = try allocator.create(PreparedSemanticState);
        errdefer allocator.destroy(state);
        const columns = try accumulator.columns(
            allocator,
            &.{.{ .log_size = eval_log_size, .n_cols = 1 }},
        );
        errdefer allocator.free(columns);
        state.* = .{
            .allocator = allocator,
            .owner = self,
            .main_0 = main[0].values,
            .main_1 = main[1].values,
            .is_active = is_active,
            .denominators = denominators,
            .column_accumulators = columns,
        };
        return .{
            .context = state,
            .vtable = &PreparedSemanticState.vtable,
            .resources = .{
                .final_output_bytes = row_count * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31),
                .shared_resident_bytes = @sizeOf(PreparedSemanticState) + @sizeOf(ColumnAccumulator),
                .worker_stack_bytes = prover.air.prepared_domain.ROW_EVALUATOR_STACK_BYTES,
            },
        };
    }

    pub fn secureAt(columns: []const Poly, row: usize) QM31 {
        return QM31.fromM31(
            columns[0].values[row],
            columns[1].values[row],
            columns[2].values[row],
            columns[3].values[row],
        );
    }
};
