//! Generic Stwo adapter for one compact secp256k1 row family.

const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const core_air_derive = @import("stwo_core").air.derive;
const core_constraints = @import("stwo_core").constraints;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const canonic = @import("stwo_core").poly.circle.canonic;
const utils = @import("stwo_core").utils;
const prover_engine = @import("stwo_prover_engine");
const prover_accumulation = prover_engine.air.accumulation;
const prover_component = prover_engine.air.component_prover;
const prepared_domain = prover_engine.air.prepared_domain;
const task_graph = prover_engine.task_graph;
const prover_poly = prover_engine.poly.circle.poly;
const prover_twiddles = prover_engine.poly.twiddles;
const logup = @import("../logup.zig");
const prepared_support = @import("../memory_commitment/hash_component_prepared_support.zig");
const relations_mod = @import("secp256k1_relations.zig");
const trace_mod = @import("secp256k1_component_trace.zig");

const CirclePointQM31 = circle.CirclePointQM31;

pub const Placement = struct {
    preprocessed_offset: usize,
    main_offset: usize,
    interaction_offset: usize,
};

pub fn Claim(comptime Config: type) type {
    return struct {
        log_size: u32,
        n_rows: u32,
        batch_sums: [Config.batch_count]QM31,
        component_sum: QM31,

        pub fn canonical(
            trace: *const trace_mod.Trace(Config),
            batch_sums: [Config.batch_count]QM31,
        ) !@This() {
            return canonicalLogical(trace, @intCast(trace.n_rows), batch_sums);
        }

        /// Bind a logical empty family to its canonical one-row all-zero
        /// physical padding trace. Non-empty callers must pass the exact trace
        /// row count.
        pub fn canonicalLogical(
            trace: *const trace_mod.Trace(Config),
            logical_n_rows: u32,
            batch_sums: [Config.batch_count]QM31,
        ) !@This() {
            if (logical_n_rows != 0 and
                @as(usize, logical_n_rows) != trace.n_rows)
                return error.InvalidClaim;
            const result = @This(){
                .log_size = trace.log_size,
                .n_rows = logical_n_rows,
                .batch_sums = batch_sums,
                .component_sum = sumClaims(Config, batch_sums),
            };
            try result.validate();
            return result;
        }

        pub fn validate(self: @This()) !void {
            if (self.n_rows == 0) {
                if (self.log_size != 1 or !allZero(&self.batch_sums) or
                    !self.component_sum.eql(QM31.zero()))
                {
                    return error.InvalidClaim;
                }
                return;
            }
            if (self.log_size == 0 or self.log_size >= circle.M31_CIRCLE_LOG_ORDER or
                self.n_rows > @as(u64, 1) << @intCast(self.log_size) or
                !sumClaims(Config, self.batch_sums).eql(self.component_sum))
            {
                return error.InvalidClaim;
            }
        }
    };
}

fn allZero(values: []const QM31) bool {
    for (values) |value| if (!value.eql(QM31.zero())) return false;
    return true;
}

pub fn Component(comptime Config: type) type {
    const preprocessed_count = trace_mod.preprocessed_column_count;
    const main_count = Config.main_column_count;
    const interaction_count = 4 * Config.batch_count;
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    const source_count = preprocessed_count + main_count + interaction_count;

    return struct {
        const Self = @This();
        pub const ClaimType = Claim(Config);

        claim: ClaimType,
        placement: Placement,
        relations: *const relations_mod.Relations,

        const Adapter = core_air_derive.ComponentAdapter(
            Self,
            prover_component.ComponentProver,
            prover_component.Trace,
            prover_accumulation.DomainEvaluationAccumulator,
        );

        pub fn init(
            claim: ClaimType,
            placement: Placement,
            relations: *const relations_mod.Relations,
        ) !Self {
            try claim.validate();
            _ = std.math.add(usize, placement.preprocessed_offset, preprocessed_count) catch
                return error.InvalidPlacement;
            _ = std.math.add(usize, placement.main_offset, main_count) catch
                return error.InvalidPlacement;
            _ = std.math.add(usize, placement.interaction_offset, interaction_count) catch
                return error.InvalidPlacement;
            return .{ .claim = claim, .placement = placement, .relations = relations };
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
            return self.claim.log_size + 1;
        }

        pub fn constraintDegreeBound(_: *const Self, index: usize) !u8 {
            if (index >= constraint_count) return error.InvalidProofShape;
            return 3;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try filledLogs(allocator, preprocessed_count, self.claim.log_size);
            errdefer allocator.free(preprocessed);
            const main = try filledLogs(allocator, main_count, self.claim.log_size);
            errdefer allocator.free(main);
            const interaction = try filledLogs(allocator, interaction_count, self.claim.log_size);
            errdefer allocator.free(interaction);
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &.{ preprocessed, main, interaction }),
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
            const preprocessed = try pointColumns(allocator, preprocessed_count, &.{point});
            errdefer freePointColumns(allocator, preprocessed);
            const main = try pointColumns(allocator, main_count, &.{
                point,
                shiftedPoint(max_log_degree_bound, point, -1),
                shiftedPoint(max_log_degree_bound, point, 1),
            });
            errdefer freePointColumns(allocator, main);
            const interaction = try pointColumns(allocator, interaction_count, &.{
                point,
                shiftedPoint(max_log_degree_bound, point, -1),
            });
            errdefer freePointColumns(allocator, interaction);
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &.{ preprocessed, main, interaction }),
            );
        }

        pub fn preprocessedColumnIndices(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            const result = try allocator.alloc(usize, preprocessed_count);
            for (result, 0..) |*value, index| value.* =
                self.placement.preprocessed_offset + index;
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
            const preprocessed = mask.items[0];
            const main_mask = mask.items[1];
            const secure = mask.items[2];
            if (preprocessed.len < self.placement.preprocessed_offset + preprocessed_count or
                main_mask.len < self.placement.main_offset + main_count or
                secure.len < self.placement.interaction_offset + interaction_count)
            {
                return error.InvalidSampledMaskShape;
            }
            var main: [main_count]QM31 = undefined;
            var previous: [main_count]QM31 = undefined;
            var next: [main_count]QM31 = undefined;
            for (0..main_count) |column| {
                const values = main_mask[self.placement.main_offset + column];
                main[column] = try pointAt(values, 0);
                previous[column] = try pointAt(values, 1);
                next[column] = try pointAt(values, 2);
            }
            const pp = self.placement.preprocessed_offset;
            const is_first = try pointAt(preprocessed[pp + trace_mod.logup_first_column], 0);
            const group_first = try pointAt(preprocessed[pp + trace_mod.group_first_column], 0);
            const group_last = try pointAt(preprocessed[pp + trace_mod.group_last_column], 0);
            const denominator_inv = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(self.claim.log_size).coset(),
                point.repeatedDouble(max_log_degree_bound - self.claim.log_size),
            ).inv();
            var sink = PointSink{
                .accumulator = accumulator,
                .denominator_inv = denominator_inv,
            };
            Config.evaluate(
                QM31,
                &main,
                &previous,
                &next,
                group_first,
                group_last,
                self.relations,
                &sink,
            );
            const pairs = Config.rowPairs(QM31, &main, &previous, &next, self.relations);
            for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
                try sampledSecure(secure, self.placement.interaction_offset + 4 * batch, 0),
                try sampledSecure(secure, self.placement.interaction_offset + 4 * batch, 1),
                is_first,
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
            if (trace_data.polys.items.len != 3) return error.InvalidTraceTreeCount;
            const eval_log_size = self.claim.log_size + 1;
            const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
            const eval_size = eval_domain.size();
            const trees = trace_data.polys.items;
            const pp_end = self.placement.preprocessed_offset + preprocessed_count;
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
            var owned_count: usize = 0;
            inline for (slices) |polys| {
                for (polys) |poly| {
                    owned_count += @intFromBool(try prepared_support.sourceNeedsExtension(
                        poly,
                        self.claim.log_size,
                        eval_log_size,
                    ));
                }
            }
            var evaluations: [source_count][]const M31 = undefined;
            const owned_buffers = try allocator.alloc([]M31, owned_count);
            var initialized: usize = 0;
            errdefer {
                for (owned_buffers[0..initialized]) |values| allocator.free(values);
                allocator.free(owned_buffers);
            }
            var source: usize = 0;
            inline for (slices) |polys| for (polys) |poly| {
                evaluations[source] = try prepared_support.evaluationValues(
                    allocator,
                    poly,
                    eval_log_size,
                    eval_size,
                    owned_buffers,
                    &initialized,
                );
                source += 1;
            };
            if (owned_buffers.len != 0) {
                var twiddles = try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset);
                defer prover_twiddles.deinitM31(allocator, &twiddles);
                try prover_poly.evaluateBuffersWithTwiddles(
                    owned_buffers,
                    eval_domain,
                    prover_twiddles.TwiddleTree([]const M31).init(
                        twiddles.root_coset,
                        twiddles.twiddles,
                        twiddles.itwiddles,
                    ),
                );
            }
            const denominator_inv = try prepared_support.quotientDenominators(
                2,
                self.claim.log_size,
                eval_log_size,
                eval_domain,
            );
            const resources = try prepared_support.resourcesWithStack(
                eval_size,
                0,
                owned_count,
                @sizeOf(PreparedState(Config)),
                512 * 1024,
            );
            const columns = try accumulator.columns(
                allocator,
                &.{.{ .log_size = eval_log_size, .n_cols = constraint_count }},
            );
            defer allocator.free(columns);
            const state = try allocator.create(PreparedState(Config));
            state.* = .{
                .allocator = allocator,
                .component = self,
                .evaluations = evaluations,
                .owned_buffers = owned_buffers,
                .denominator_inv = denominator_inv,
                .column_accumulator = columns[0],
                .eval_log_size = eval_log_size,
                .eval_size = eval_size,
            };
            return .{
                .context = state,
                .vtable = &PreparedState(Config).vtable,
                .task_class = .leaf,
                .resources = resources,
            };
        }
    };
}

fn PreparedState(comptime Config: type) type {
    const ComponentType = Component(Config);
    const preprocessed_count = trace_mod.preprocessed_column_count;
    const main_count = Config.main_column_count;
    const interaction_count = 4 * Config.batch_count;
    const source_count = preprocessed_count + main_count + interaction_count;
    const constraint_count = Config.direct_constraint_count + Config.batch_count;
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        component: *const ComponentType,
        evaluations: [source_count][]const M31,
        owned_buffers: [][]M31,
        denominator_inv: [2]M31,
        column_accumulator: prover_accumulation.ColumnAccumulator,
        eval_log_size: u32,
        eval_size: usize,

        pub const vtable = prepared_domain.VTable{ .run = runErased, .deinit = deinitErased };

        fn runErased(context: *anyopaque, task_context: *task_graph.TaskContext) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(context));
            try self.run(task_context);
        }

        fn deinitErased(context: *anyopaque) void {
            const self: *Self = @ptrCast(@alignCast(context));
            const allocator = self.allocator;
            for (self.owned_buffers) |values| allocator.free(values);
            allocator.free(self.owned_buffers);
            allocator.destroy(self);
        }

        fn run(self: *Self, context: *task_graph.TaskContext) !void {
            const log_size = self.component.claim.log_size;
            const shift: std.math.Log2Int(usize) = @intCast(log_size);
            const main_start = preprocessed_count;
            const interaction_start = main_start + main_count;
            for (0..self.eval_size) |row| {
                if ((row & 4095) == 0 and context.isCancelled()) return;
                const previous_row = utils.offsetBitReversedCircleDomainIndex(
                    row,
                    log_size,
                    self.eval_log_size,
                    -1,
                );
                const next_row = utils.offsetBitReversedCircleDomainIndex(
                    row,
                    log_size,
                    self.eval_log_size,
                    1,
                );
                var main: [main_count]M31 = undefined;
                var previous: [main_count]M31 = undefined;
                var next: [main_count]M31 = undefined;
                for (0..main_count) |column| {
                    const values = self.evaluations[main_start + column];
                    main[column] = values[row];
                    previous[column] = values[previous_row];
                    next[column] = values[next_row];
                }
                var sink = FoldSink{
                    .powers = self.column_accumulator.random_coeff_powers,
                };
                Config.evaluate(
                    M31,
                    &main,
                    &previous,
                    &next,
                    self.evaluations[trace_mod.group_first_column][row],
                    self.evaluations[trace_mod.group_last_column][row],
                    self.component.relations,
                    &sink,
                );
                const pairs = Config.rowPairs(
                    M31,
                    &main,
                    &previous,
                    &next,
                    self.component.relations,
                );
                for (pairs, 0..) |pair, batch| sink.add(logup.pairConstraint(
                    secureAt(&self.evaluations, interaction_start + 4 * batch, row),
                    secureAt(&self.evaluations, interaction_start + 4 * batch, previous_row),
                    QM31.fromBase(self.evaluations[trace_mod.logup_first_column][row]),
                    self.component.claim.batch_sums[batch],
                    pair,
                ), 3);
                std.debug.assert(sink.index == constraint_count);
                self.column_accumulator.accumulate(
                    row,
                    sink.folded.mulM31(self.denominator_inv[row >> shift]),
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

fn sumClaims(comptime Config: type, claims: [Config.batch_count]QM31) QM31 {
    var result = QM31.zero();
    for (claims) |claim| result = result.add(claim);
    return result;
}
