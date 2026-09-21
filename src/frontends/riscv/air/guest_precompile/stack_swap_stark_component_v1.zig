//! Genuine Stwo adapter for the nonproduction atomic-U256-swap components.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const verifier_types = @import("stwo_core").verifier_types;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_engine = @import("stwo_prover_engine");
const prover_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const task_graph = prover_engine.task_graph;
const contract = @import("stack_swap_component_v1.zig");
const trace_mod = @import("stack_swap_trace_v1.zig");
const logup = @import("../logup.zig");
const prepared_evaluation = @import("../prepared_evaluation_owner.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const production_active = false;
pub const quotient_expansion_bits: u32 = 2;
pub const composition_log_split: u32 = 2;
pub const prepared_row_stack_bytes: usize = 512 * 1024;

pub const Placement = struct {
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
};

pub fn Component(comptime Config: type) type {
    return ComponentWithCompositionLogSplit(Config, composition_log_split);
}

/// Additive adapter for embedding this AIR in a proof whose global quotient
/// commitment uses a different split. The local degree expansion remains two
/// bits; only the proof-wide composition commitment split is selected here.
pub fn ComponentWithCompositionLogSplit(
    comptime Config: type,
    comptime selected_composition_log_split: u32,
) type {
    if (selected_composition_log_split == 0 or
        selected_composition_log_split > verifier_types.MAX_COMPOSITION_LOG_SPLIT)
    {
        @compileError("invalid stack-swap composition log split");
    }
    const pp_count = trace_mod.preprocessed_column_count;
    const main_count = Config.main_column_count;
    const interaction_count = Config.interaction_column_count;
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    const source_count = pp_count + main_count + interaction_count;

    return struct {
        const Self = @This();
        pub const ClaimType = contract.Claim(Config);

        claim: ClaimType,
        placement: Placement,
        inputs: contract.Inputs,

        const Adapter = core_air_derive.ComponentAdapter(
            Self,
            prover_component.ComponentProver,
            prover_component.Trace,
            prover_accumulation.DomainEvaluationAccumulator,
        );

        pub fn init(
            claim: ClaimType,
            placement: Placement,
            inputs: contract.Inputs,
        ) !Self {
            try claim.validate();
            try inputs.authority.validate();
            if (claim.log_size + quotient_expansion_bits >=
                circle.M31_CIRCLE_LOG_ORDER)
            {
                return error.InvalidTraceLogSize;
            }
            _ = std.math.add(usize, placement.preprocessed_offset, pp_count) catch
                return error.InvalidPlacement;
            _ = std.math.add(usize, placement.main_offset, main_count) catch
                return error.InvalidPlacement;
            _ = std.math.add(usize, placement.interaction_offset, interaction_count) catch
                return error.InvalidPlacement;
            return .{ .claim = claim, .placement = placement, .inputs = inputs };
        }

        pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.prepare_domain_evaluator = prepareDomainEvaluatorErased;
            return result;
        }

        pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
            return Adapter.asVerifierComponent(self);
        }

        pub fn nConstraints(_: *const Self) usize {
            return constraint_count;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.claim.log_size + quotient_expansion_bits;
        }

        pub fn compositionLogSplit(_: *const Self) u32 {
            return selected_composition_log_split;
        }

        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= constraint_count) return error.InvalidProofShape;
            return if (index < Config.direct_constraint_count)
                Config.maximum_constraint_degree
            else
                3;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const pp = try filledLogs(allocator, pp_count, self.claim.log_size);
            errdefer allocator.free(pp);
            const main = try filledLogs(allocator, main_count, self.claim.log_size);
            errdefer allocator.free(main);
            const interaction = try filledLogs(
                allocator,
                interaction_count,
                self.claim.log_size,
            );
            errdefer allocator.free(interaction);
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &.{ pp, main, interaction }),
            );
        }

        pub fn maskPoints(
            self: *const Self,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) !core_air_components.MaskPoints {
            if (max_log_degree_bound < self.claim.log_size)
                return error.InvalidMaskDegreeBound;
            const previous = shiftedPoint(max_log_degree_bound, point, -1);
            const pp = try pointColumns(allocator, pp_count, &.{point});
            errdefer freePointColumns(allocator, pp);
            const next = shiftedPoint(max_log_degree_bound, point, 1);
            const main = try pointColumns(allocator, main_count, &.{ point, next });
            errdefer freePointColumns(allocator, main);
            const interaction = try pointColumns(
                allocator,
                interaction_count,
                &.{ point, previous },
            );
            errdefer freePointColumns(allocator, interaction);
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &.{ pp, main, interaction }),
            );
        }

        pub fn preprocessedColumnIndices(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            const result = try allocator.alloc(usize, pp_count);
            for (result, 0..) |*value, index|
                value.* = self.placement.preprocessed_offset + index;
            return result;
        }

        pub fn evaluateConstraintQuotientsAtPoint(
            self: *const Self,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) !void {
            if (mask.items.len < 3 or max_log_degree_bound < self.claim.log_size)
                return error.InvalidPointMaskShape;
            const pp_mask = mask.items[0];
            const main_mask = mask.items[1];
            const secure = mask.items[2];
            if (pp_mask.len < self.placement.preprocessed_offset + pp_count or
                main_mask.len < self.placement.main_offset + main_count or
                secure.len < self.placement.interaction_offset + interaction_count)
            {
                return error.InvalidSampledMaskShape;
            }
            var main: [main_count]QM31 = undefined;
            var next_main: [main_count]QM31 = undefined;
            for (0..main_count) |column| {
                const values = main_mask[self.placement.main_offset + column];
                main[column] = try pointAt(values, 0);
                next_main[column] = try pointAt(values, 1);
            }
            const pp = self.placement.preprocessed_offset;
            const domain_first = try pointAt(
                pp_mask[pp + trace_mod.domain_first_column],
                0,
            );
            const active_prefix = try pointAt(
                pp_mask[pp + trace_mod.active_prefix_column],
                0,
            );
            const lane_last = try pointAt(
                pp_mask[pp + trace_mod.lane_last_column],
                0,
            );
            const denominator_inv = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(self.claim.log_size).coset(),
                point.repeatedDouble(max_log_degree_bound - self.claim.log_size),
            ).inv();
            var sink = PointSink{
                .accumulator = accumulator,
                .denominator_inv = denominator_inv,
            };
            try Config.evaluate(
                QM31,
                &main,
                &next_main,
                domain_first,
                active_prefix,
                lane_last,
                self.inputs,
                &sink,
            );
            const pairs = Config.rowPairs(QM31, &main, lane_last, self.inputs);
            for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
                try sampledSecure(
                    secure,
                    self.placement.interaction_offset + 4 * batch,
                    0,
                ),
                try sampledSecure(
                    secure,
                    self.placement.interaction_offset + 4 * batch,
                    1,
                ),
                domain_first,
                self.claim.batch_sums[batch],
                pair,
            ), 3);
        }

        pub fn evaluateConstraintQuotientsOnDomain(
            self: *const Self,
            trace_data: *const prover_component.Trace,
            accumulator: *prover_accumulation.DomainEvaluationAccumulator,
        ) !void {
            var prepared = try self.prepareDomainEvaluator(
                accumulator.allocator,
                trace_data,
                accumulator,
            );
            defer prepared.deinit();
            var cancellation = task_graph.CancellationToken{};
            var context = serialTaskContext(prepared.context, &cancellation);
            try prepared.run(&context);
        }

        fn prepareDomainEvaluatorErased(
            context: *const anyopaque,
            allocator: std.mem.Allocator,
            trace_data: *const prover_component.Trace,
            accumulator: *prover_accumulation.DomainEvaluationAccumulator,
        ) anyerror!prepared_domain.PreparedDomainEvaluation {
            const self: *const Self = @ptrCast(@alignCast(context));
            return self.prepareDomainEvaluator(allocator, trace_data, accumulator);
        }

        fn prepareDomainEvaluator(
            self: *const Self,
            allocator: std.mem.Allocator,
            trace_data: *const prover_component.Trace,
            accumulator: *prover_accumulation.DomainEvaluationAccumulator,
        ) !prepared_domain.PreparedDomainEvaluation {
            if (trace_data.polys.items.len != 3)
                return error.InvalidTraceTreeCount;
            const eval_log_size = std.math.add(
                u32,
                self.claim.log_size,
                quotient_expansion_bits,
            ) catch return error.InvalidEvaluationLogSize;
            if (eval_log_size > accumulator.logSize())
                return error.InvalidEvaluationLogSize;
            const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
            const eval_size = eval_domain.size();
            const trees = trace_data.polys.items;
            const pp_end = self.placement.preprocessed_offset + pp_count;
            const main_end = self.placement.main_offset + main_count;
            const interaction_end = self.placement.interaction_offset + interaction_count;
            if (trees[0].len < pp_end or trees[1].len < main_end or
                trees[2].len < interaction_end)
            {
                return error.InvalidTraceColumnCount;
            }
            const slices = .{
                trees[0][self.placement.preprocessed_offset..pp_end],
                trees[1][self.placement.main_offset..main_end],
                trees[2][self.placement.interaction_offset..interaction_end],
            };
            var extension_counts = prepared_evaluation.ExtensionCounts{};
            inline for (slices) |polys| {
                for (polys) |poly| {
                    try extension_counts.add(try prepared_evaluation.extensionSource(
                        poly,
                        self.claim.log_size,
                        eval_log_size,
                    ));
                }
            }
            var evaluations: [source_count][]const M31 = undefined;
            var evaluation_owner = try prepared_evaluation.RetainedLdeOwner.init(
                allocator,
                extension_counts,
            );
            errdefer evaluation_owner.deinit();
            var source: usize = 0;
            inline for (slices) |polys| for (polys) |poly| {
                evaluations[source] = try evaluation_owner.value(
                    poly,
                    self.claim.log_size,
                    eval_log_size,
                    eval_size,
                );
                source += 1;
            };
            try evaluation_owner.finish(eval_domain);
            const denominator_inv = try quotientDenominators(
                self.claim.log_size,
                eval_log_size,
                eval_domain,
            );
            var resources = try prepared_support.resourcesWithStack(
                eval_size,
                source_count,
                extension_counts.owned,
                @sizeOf(PreparedState(Config, selected_composition_log_split)),
                prepared_row_stack_bytes,
            );
            resources.shared_resident_bytes = std.math.add(
                usize,
                resources.shared_resident_bytes,
                try prepared_evaluation.retainedLdeAdditionalResidentBytes(
                    extension_counts,
                ),
            ) catch return error.ResourceReservationOverflow;
            const columns = try accumulator.columns(
                allocator,
                &.{.{ .log_size = eval_log_size, .n_cols = constraint_count }},
            );
            defer allocator.free(columns);
            const state = try allocator.create(PreparedState(
                Config,
                selected_composition_log_split,
            ));
            state.* = .{
                .allocator = allocator,
                .component = self,
                .evaluations = evaluations,
                .evaluation_owner = evaluation_owner,
                .denominator_inv = denominator_inv,
                .column_accumulator = columns[0],
                .eval_log_size = eval_log_size,
                .eval_size = eval_size,
            };
            return .{
                .context = state,
                .vtable = &PreparedState(
                    Config,
                    selected_composition_log_split,
                ).vtable,
                .task_class = .leaf,
                .resources = resources,
            };
        }
    };
}

fn PreparedState(
    comptime Config: type,
    comptime selected_composition_log_split: u32,
) type {
    const ComponentType = ComponentWithCompositionLogSplit(
        Config,
        selected_composition_log_split,
    );
    const pp_count = trace_mod.preprocessed_column_count;
    const main_count = Config.main_column_count;
    const interaction_count = Config.interaction_column_count;
    const source_count = pp_count + main_count + interaction_count;
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        component: *const ComponentType,
        evaluations: [source_count][]const M31,
        evaluation_owner: prepared_evaluation.RetainedLdeOwner,
        denominator_inv: [4]M31,
        column_accumulator: prover_accumulation.ColumnAccumulator,
        eval_log_size: u32,
        eval_size: usize,

        pub const vtable = prepared_domain.VTable{
            .run = runErased,
            .deinit = deinitErased,
        };

        fn runErased(context: *anyopaque, task_context: *task_graph.TaskContext) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.run(task_context);
        }

        fn deinitErased(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            const allocator = self.allocator;
            self.evaluation_owner.deinit();
            allocator.destroy(self);
        }

        fn run(self: *Self, context: *task_graph.TaskContext) !void {
            const main_start = pp_count;
            const interaction_start = main_start + main_count;
            const denominator_shift: std.math.Log2Int(usize) =
                @intCast(self.component.claim.log_size);
            for (0..self.eval_size) |row| {
                if ((row & 4095) == 0 and context.isCancelled()) return;
                const previous_row = utils.offsetBitReversedCircleDomainIndex(
                    row,
                    self.component.claim.log_size,
                    self.eval_log_size,
                    -1,
                );
                const next_row = utils.offsetBitReversedCircleDomainIndex(
                    row,
                    self.component.claim.log_size,
                    self.eval_log_size,
                    1,
                );
                var main: [main_count]M31 = undefined;
                var next_main: [main_count]M31 = undefined;
                for (0..main_count) |column| {
                    const values = self.evaluations[main_start + column];
                    main[column] = values[row];
                    next_main[column] = values[next_row];
                }
                const domain_first = self.evaluations[trace_mod.domain_first_column][row];
                const active_prefix = self.evaluations[trace_mod.active_prefix_column][row];
                const lane_last = self.evaluations[trace_mod.lane_last_column][row];
                var sink = FoldSink{ .powers = self.column_accumulator.random_coeff_powers };
                try Config.evaluate(
                    M31,
                    &main,
                    &next_main,
                    domain_first,
                    active_prefix,
                    lane_last,
                    self.component.inputs,
                    &sink,
                );
                const pairs = Config.rowPairs(
                    M31,
                    &main,
                    lane_last,
                    self.component.inputs,
                );
                for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
                    secureAt(&self.evaluations, interaction_start + 4 * batch, row),
                    secureAt(
                        &self.evaluations,
                        interaction_start + 4 * batch,
                        previous_row,
                    ),
                    QM31.fromBase(domain_first),
                    self.component.claim.batch_sums[batch],
                    pair,
                ), 3);
                std.debug.assert(sink.index == constraint_count);
                self.column_accumulator.accumulate(
                    row,
                    sink.folded.mulM31(self.denominator_inv[row >> denominator_shift]),
                );
            }
        }
    };
}

const PointSink = struct {
    accumulator: *core_air_accumulation.PointEvaluationAccumulator,
    denominator_inv: QM31,

    pub fn add(self: *@This(), value: QM31, degree: u8) void {
        _ = degree;
        self.accumulator.accumulate(value.mul(self.denominator_inv));
    }
};

const FoldSink = struct {
    powers: []const QM31,
    index: usize = 0,
    folded: QM31 = QM31.zero(),

    pub fn add(self: *@This(), value: anytype, degree: u8) void {
        _ = degree;
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.folded = self.folded.add(
            self.powers[self.powers.len - 1 - self.index].mul(lifted),
        );
        self.index += 1;
    }
};

fn filledLogs(allocator: std.mem.Allocator, count: usize, log_size: u32) ![]u32 {
    const result = try allocator.alloc(u32, count);
    @memset(result, log_size);
    return result;
}

fn quotientDenominators(
    log_size: u32,
    eval_log_size: u32,
    eval_domain: anytype,
) ![4]M31 {
    if (eval_log_size != log_size + quotient_expansion_bits)
        return error.InvalidEvaluationLogSize;
    var result: [4]M31 = undefined;
    const coset = canonic.CanonicCoset.new(log_size).coset();
    for (&result, 0..) |*inverse, index| inverse.* =
        try core_constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(utils.bitReverseIndex(index, quotient_expansion_bits)),
        ).inv();
    return result;
}

fn shiftedPoint(log_size: u32, point: CirclePointQM31, offset: isize) CirclePointQM31 {
    const step = logup.liftPoint(canonic.CanonicCoset.new(log_size).coset_value.step);
    return point.add(step.mulSigned(offset));
}

fn pointColumns(
    allocator: std.mem.Allocator,
    count: usize,
    points: []const CirclePointQM31,
) ![][]CirclePointQM31 {
    const result = try allocator.alloc([]CirclePointQM31, count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(column);
        allocator.free(result);
    }
    for (result) |*column| {
        column.* = try allocator.dupe(CirclePointQM31, points);
        initialized += 1;
    }
    return result;
}

fn freePointColumns(allocator: std.mem.Allocator, columns: [][]CirclePointQM31) void {
    for (columns) |column| allocator.free(column);
    allocator.free(columns);
}

fn pointAt(values: []const QM31, index: usize) !QM31 {
    if (values.len <= index) return error.MissingMaskPoint;
    return values[index];
}

fn sampledSecure(columns: [][]QM31, offset: usize, point: usize) !QM31 {
    if (columns.len < offset + 4) return error.InvalidSecureMaskShape;
    return QM31.fromPartialEvals(.{
        try pointAt(columns[offset], point),
        try pointAt(columns[offset + 1], point),
        try pointAt(columns[offset + 2], point),
        try pointAt(columns[offset + 3], point),
    });
}

fn secureAt(columns: []const []const M31, offset: usize, row: usize) QM31 {
    return QM31.fromM31(
        columns[offset][row],
        columns[offset + 1][row],
        columns[offset + 2][row],
        columns[offset + 3][row],
    );
}

fn serialTaskContext(
    context: *anyopaque,
    cancellation: *const task_graph.CancellationToken,
) task_graph.TaskContext {
    return .{
        .user_context = context,
        .cancellation = cancellation,
        .key = .{
            .epoch = 0,
            .stage_rank = 0,
            .component_registry_index = 0,
            .shard_or_chunk_index = 0,
        },
        .worker_budget = prover_engine.work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
}

comptime {
    if (production_active or contract.production_active or
        quotient_expansion_bits != 2 or composition_log_split != 2)
    {
        @compileError("stack-swap STARK component contract drifted");
    }
}
