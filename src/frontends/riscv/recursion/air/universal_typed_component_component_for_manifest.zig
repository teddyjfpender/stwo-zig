//! Internal universal typed component authority shard; use universal_typed_component.zig publicly.

const verifier = @import("universal_typed_verifier_component.zig");
const dependency_0 = @import("universal_typed_component_contract.zig");

const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const canonic = dependency_0.canonic;
const checkedEnd = dependency_0.checkedEnd;
const circle = dependency_0.circle;
const core_air_derive = dependency_0.core_air_derive;
const default_manifest = dependency_0.default_manifest;
const direct_program = dependency_0.direct_program;
const evaluationValues = dependency_0.evaluationValues;
const preparedResources = dependency_0.preparedResources;
const prepared_domain = dependency_0.prepared_domain;
const prover_air_accumulation = dependency_0.prover_air_accumulation;
const prover_circle = dependency_0.prover_circle;
const prover_component = dependency_0.prover_component;
const prover_task_graph = dependency_0.prover_task_graph;
const prover_twiddles = dependency_0.prover_twiddles;
const quotientDenominators = dependency_0.quotientDenominators;
const serialTaskContext = dependency_0.serialTaskContext;
const secureAt = dependency_0.secureAt;
const sourceNeedsExtension = dependency_0.sourceNeedsExtension;
const std = dependency_0.std;
const work_pool = dependency_0.prover_work_pool;
const prepared_parallel = @import("../../air/prepared_parallel.zig");
const universal = dependency_0.universal;
const utils = dependency_0.utils;

pub fn Component(comptime Air: type, comptime Relation: type) type {
    return ComponentForManifest(Air, Relation, default_manifest);
}

/// The evaluator is independent of roster cardinality and component naming.
/// V1 uses `Component` above; versioned outer protocols may supply a manifest
/// contract with the same geometry/placement interface and a distinct key
/// enum without copying this performance-critical adapter.
pub fn ComponentForManifest(
    comptime Air: type,
    comptime Relation: type,
    comptime manifest_mod: type,
) type {
    const VerifierState = verifier.ComponentForManifest(Air, Relation, manifest_mod);
    const Shape = verifier.Layout(Air, Relation);
    const Runtime = Shape.Runtime;
    const DIRECT_COUNT = Shape.DIRECT_COUNT;
    const LOGUP_COUNT = Shape.LOGUP_COUNT;
    const CONSTRAINT_COUNT = Shape.CONSTRAINT_COUNT;
    const PP_COUNT = Shape.PP_COUNT;
    const MAIN_COUNT = Shape.MAIN_COUNT;
    const PARAMETER_COUNT = Shape.PARAMETER_COUNT;
    const SOURCE_COUNT = Shape.SOURCE_COUNT;
    const PROTOCOL_MAXIMUM_DEGREE = Shape.PROTOCOL_MAXIMUM_DEGREE;
    const DENOMINATOR_COUNT = Shape.DENOMINATOR_COUNT;

    return struct {
        const Self = @This();
        const VerifierMethods = verifier.Methods(Self, Air, Relation, manifest_mod);
        /// Public compiler/runtime association used by equation-agnostic
        /// composition recorders.  Exposing the type removes a second manual
        /// AIR-to-relation switch at heterogeneous assembly sites; the sealed
        /// `relation_plan` remains the runtime value authority.
        pub const RelationRuntime = Runtime;
        pub const DIRECT_CONSTRAINT_COUNT = DIRECT_COUNT;
        pub const INTERACTION_BATCH_COUNT = LOGUP_COUNT;
        pub const CONSTRAINT_COUNT_TOTAL = CONSTRAINT_COUNT;
        pub const PARAMETER_COLUMN_COUNT = PARAMETER_COUNT;
        pub const PROTOCOL_CONSTRAINT_DEGREE = PROTOCOL_MAXIMUM_DEGREE;
        pub const PROFILED_CONSTRAINT_DEGREE = Air.MAXIMUM_CONSTRAINT_DEGREE;
        pub const PARALLEL_DOMAIN_ROWS: usize = 1 << 18;
        var parallel_telemetry: prepared_parallel.Telemetry = .{};

        pub fn preparedParallelTelemetrySnapshot() prepared_parallel.TelemetrySnapshot {
            return parallel_telemetry.snapshot();
        }

        /// The component factory, rather than an assembly-site transcription,
        /// owns the equation-free manifest geometry.
        pub const manifestGeometry = VerifierMethods.manifestGeometry;

        log_size: @FieldType(VerifierState, "log_size"),
        placement: @FieldType(VerifierState, "placement"),
        parameters: @FieldType(VerifierState, "parameters"),
        relations: @FieldType(VerifierState, "relations"),
        claimed_sum: @FieldType(VerifierState, "claimed_sum"),
        claimed_sum_shift: @FieldType(VerifierState, "claimed_sum_shift"),
        direct: @FieldType(VerifierState, "direct"),
        relation_plan: @FieldType(VerifierState, "relation_plan"),

        const Adapter = core_air_derive.ComponentAdapter(
            Self,
            prover_component.ComponentProver,
            prover_component.Trace,
            prover_air_accumulation.DomainEvaluationAccumulator,
        );

        /// Cold admission compiles and authenticates both program halves once.
        pub const init = VerifierMethods.init;

        pub const asVerifierComponent = VerifierMethods.asVerifierComponent;

        pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.prepare_domain_evaluator = prepareDomainEvaluatorErased;
            result.backend_composition_capability = .{ .framework_polynomial_v1 = @import("framework_polynomial_export_v1.zig").capability(Air, Self, self.log_size) };
            return result;
        }

        pub fn binding(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
        ) !manifest_mod.AdapterBinding {
            try manifest.validate();
            if (!self.placement.eql(manifest.placements[
                self.placement.geometry.roster_row
            ].?)) return error.InvalidProofShape;
            return .{
                .manifest_seal = manifest.seal,
                .placement = self.placement,
                .claimed_sum = self.claimed_sum,
                .verifier = self.asVerifierComponent(),
                .prover = self.asProverComponent(),
            };
        }

        pub const nConstraints = VerifierMethods.nConstraints;

        pub const maxConstraintLogDegreeBound = VerifierMethods.maxConstraintLogDegreeBound;

        pub const traceLogDegreeBounds = VerifierMethods.traceLogDegreeBounds;

        pub const maskPoints = VerifierMethods.maskPoints;

        /// Allocation-free row kernel used by admission and differential
        /// tests. `current` is the same-row cumulative value of every secure
        /// interaction column; only the final column has a previous-row term.
        pub const evaluateBaseRowInto = VerifierMethods.evaluateBaseRowInto;

        pub const preprocessedColumnIndices = VerifierMethods.preprocessedColumnIndices;

        pub const evaluateConstraintQuotientsAtPoint = VerifierMethods.evaluateConstraintQuotientsAtPoint;

        pub fn evaluateConstraintQuotientsOnDomain(
            self: *const Self,
            trace: *const prover_component.Trace,
            accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !void {
            var prepared = try self.prepareDomainEvaluator(
                accumulator.allocator,
                trace,
                accumulator,
            );
            defer prepared.deinit();
            var cancellation = prover_task_graph.CancellationToken{};
            var task_context = serialTaskContext(prepared.context, &cancellation);
            try prepared.run(&task_context);
        }

        fn prepareDomainEvaluatorErased(
            context: *const anyopaque,
            allocator: std.mem.Allocator,
            trace: *const prover_component.Trace,
            accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) anyerror!prepared_domain.PreparedDomainEvaluation {
            const self: *const Self = @ptrCast(@alignCast(context));
            return self.prepareDomainEvaluator(allocator, trace, accumulator);
        }

        fn prepareDomainEvaluator(
            self: *const Self,
            allocator: std.mem.Allocator,
            trace: *const prover_component.Trace,
            accumulator: *prover_air_accumulation.DomainEvaluationAccumulator,
        ) !prepared_domain.PreparedDomainEvaluation {
            if (trace.polys.items.len != manifest_mod.TREE_COUNT)
                return error.InvalidProofShape;
            const eval_log_size = self.maxConstraintLogDegreeBound();
            if (eval_log_size >= circle.M31_CIRCLE_LOG_ORDER)
                return error.InvalidProofShape;
            const eval_domain = canonic.CanonicCoset.new(eval_log_size).circleDomain();
            const eval_size = eval_domain.size();
            const pp = trace.polys.items[manifest_mod.PREPROCESSED_TREE_INDEX];
            const main = trace.polys.items[manifest_mod.MAIN_TREE_INDEX];
            const interaction = trace.polys.items[manifest_mod.INTERACTION_TREE_INDEX];
            const pp_end = try checkedEnd(self.placement.preprocessed_offset, PP_COUNT);
            const main_end = try checkedEnd(self.placement.main_offset, MAIN_COUNT);
            const interaction_end = try checkedEnd(
                self.placement.interaction_offset,
                Air.INTERACTION_COLUMN_COUNT,
            );
            if (pp.len < pp_end or main.len < main_end or interaction.len < interaction_end)
                return error.InvalidProofShape;

            var sources: [SOURCE_COUNT]prover_component.Poly = undefined;
            @memcpy(sources[0..MAIN_COUNT], main[self.placement.main_offset..main_end]);
            @memcpy(
                sources[MAIN_COUNT .. MAIN_COUNT + PP_COUNT],
                pp[self.placement.preprocessed_offset..pp_end],
            );
            @memcpy(
                sources[MAIN_COUNT + PP_COUNT ..],
                interaction[self.placement.interaction_offset..interaction_end],
            );
            // Validate source geometry before allocating local quotient buffers.
            // Missing coefficients are recovered and degree-checked from the
            // complete committed LDE, without retaining a second source set.
            var owned_count: usize = 0;
            for (sources, 0..) |poly, source_index| {
                const needs_extension = sourceNeedsExtension(poly, self.log_size, eval_log_size) catch |err| {
                    if (err == error.InvalidProofShape) std.debug.print(
                        "RECURSION_COMPONENT_SHAPE air={s} roster_row={d} source={d} trace_log={d} quotient_log={d} committed_log={d} coefficient_log={?d} error={s}\n",
                        .{ @typeName(Air), self.placement.geometry.roster_row, source_index, self.log_size, eval_log_size, poly.log_size, if (poly.coefficients) |coefficients| coefficients.logSize() else null, @errorName(err) },
                    );
                    return err;
                };
                owned_count += @intFromBool(needs_extension);
            }
            const values_allocator = trace.quotient_values_allocator orelse allocator;
            const owned_buffers = try allocator.alloc([]M31, owned_count);
            var owned_initialized: usize = 0;
            errdefer {
                for (owned_buffers[0..owned_initialized]) |values|
                    values_allocator.free(values);
                allocator.free(owned_buffers);
            }
            var evaluations: [SOURCE_COUNT][]const M31 = undefined;
            {
                var twiddles: ?prover_twiddles.TwiddleTree([]M31) = if (owned_count != 0)
                    try prover_twiddles.precomputeM31(allocator, eval_domain.half_coset)
                else
                    null;
                defer if (twiddles) |*tree| prover_twiddles.deinitM31(allocator, tree);
                const transform: ?prover_twiddles.TwiddleTree([]const M31) = if (twiddles) |tree|
                    .{ .root_coset = tree.root_coset, .twiddles = tree.twiddles, .itwiddles = tree.itwiddles }
                else
                    null;
                for (sources, &evaluations) |poly, *target| {
                    target.* = try evaluationValues(
                        values_allocator,
                        poly,
                        self.log_size,
                        eval_log_size,
                        eval_size,
                        transform,
                        owned_buffers,
                        &owned_initialized,
                    );
                }
                std.debug.assert(owned_initialized == owned_count);
                if (owned_count != 0) {
                    try prover_circle.poly.evaluateBuffersWithTwiddles(
                        owned_buffers,
                        eval_domain,
                        transform.?,
                    );
                }
            }
            const denominator_inverse = try quotientDenominators(
                DENOMINATOR_COUNT,
                self.log_size,
                eval_log_size,
                eval_domain,
            );
            const accumulator_columns = try accumulator.columns(
                allocator,
                &.{.{ .log_size = eval_log_size, .n_cols = CONSTRAINT_COUNT }},
            );
            defer allocator.free(accumulator_columns);
            if (accumulator_columns.len != 1) {
                return error.InvalidProofShape;
            }
            const state = try allocator.create(PreparedDomainState);
            errdefer allocator.destroy(state);
            state.* = .{
                .allocator = allocator,
                .component = self,
                .evaluations = evaluations,
                .owned_buffers = owned_buffers,
                .values_allocator = values_allocator,
                .denominator_inverse = denominator_inverse,
                .column_accumulator = accumulator_columns[0],
                .eval_size = eval_size,
                .direct_store = accumulator_columns[0].next_fresh_index == 0,
            };
            return .{
                .context = state,
                .vtable = &PreparedDomainState.vtable,
                .task_class = if (eval_size >= PARALLEL_DOMAIN_ROWS) .pool_exclusive else .leaf,
                .resources = try preparedResources(
                    eval_size,
                    owned_count,
                    @sizeOf(PreparedDomainState),
                ),
            };
        }

        fn runPreparedRange(
            self: *const Self,
            state: *PreparedDomainState,
            cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
        ) !bool {
            const evaluations = &state.evaluations;
            const interaction_start = MAIN_COUNT + PP_COUNT;
            const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
            const powers = state.column_accumulator.random_coeff_powers;
            if (powers.len < CONSTRAINT_COUNT) return error.InvalidProofShape;
            for (row_start..row_end) |row_index| {
                if ((row_index & (PreparedDomainState.CANCELLATION_POLL_ROWS - 1)) == 0 and
                    (cancellation.isCancelled() or state.failure_boundary.shouldCancel(range_index))) return false;
                const previous_row = utils.previousBitReversedCircleDomainIndex(
                    row_index,
                    self.log_size,
                    self.maxConstraintLogDegreeBound(),
                );
                var row: Runtime.Row = undefined;
                for (row[0..MAIN_COUNT], evaluations[0..MAIN_COUNT]) |*value, column|
                    value.* = column[row_index];
                for (
                    row[MAIN_COUNT .. MAIN_COUNT + PP_COUNT],
                    evaluations[MAIN_COUNT .. MAIN_COUNT + PP_COUNT],
                ) |*value, column| value.* = column[row_index];
                row[MAIN_COUNT + PP_COUNT ..].* = self.parameters;

                var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
                var direct_roots: [DIRECT_COUNT]M31 = undefined;
                try self.direct.evaluateBaseInto(&row, &direct_scratch, &direct_roots);
                const pairs = try self.relation_plan.preparedRowPairs(
                    row,
                    self.relations,
                );
                var folded = QM31.zero();
                for (direct_roots, 0..) |root, constraint| {
                    folded = folded.add(powers[
                        powers.len - 1 - constraint
                    ].mulM31(root));
                }
                for (0..LOGUP_COUNT) |batch| {
                    const base = interaction_start + 4 * batch;
                    const current = secureAt(evaluations[base .. base + 4], row_index);
                    const previous_column = if (batch == 0)
                        QM31.zero()
                    else
                        secureAt(evaluations[base - 4 .. base], row_index);
                    const previous_value = if (batch + 1 == LOGUP_COUNT)
                        secureAt(evaluations[base .. base + 4], previous_row)
                    else
                        QM31.zero();
                    const shift = if (batch + 1 == LOGUP_COUNT)
                        self.claimed_sum_shift
                    else
                        QM31.zero();
                    const root = frameworkConstraint(
                        current,
                        previous_value,
                        previous_column,
                        shift,
                        pairs[batch],
                    );
                    const constraint = DIRECT_COUNT + batch;
                    folded = folded.add(powers[
                        powers.len - 1 - constraint
                    ].mul(root));
                }
                const contribution = folded.mulM31(state.denominator_inverse[row_index >> denominator_shift]);
                const output = state.column_accumulator.col;
                if (state.direct_store) {
                    output.set(row_index, contribution);
                } else {
                    output.set(row_index, output.at(row_index).add(contribution));
                }
            }
            return true;
        }

        const PreparedDomainState = struct {
            const CANCELLATION_POLL_ROWS: usize = 4096;
            comptime {
                if (!std.math.isPowerOfTwo(CANCELLATION_POLL_ROWS) or
                    CANCELLATION_POLL_ROWS > 4096)
                {
                    @compileError("recursion cancellation tile drifted");
                }
            }

            allocator: std.mem.Allocator,
            component: *const Self,
            evaluations: [SOURCE_COUNT][]const M31,
            owned_buffers: [][]M31,
            values_allocator: std.mem.Allocator,
            denominator_inverse: [DENOMINATOR_COUNT]M31,
            column_accumulator: prover_air_accumulation.ColumnAccumulator,
            eval_size: usize,
            direct_store: bool,
            failure_boundary: prepared_parallel.FailureBoundary = .{},
            range_workers: [work_pool.MAX_WORKERS]RangeWorker = undefined,

            const vtable = prepared_domain.VTable{
                .run = runErased,
                .deinit = deinitErased,
            };

            fn runErased(
                context: *anyopaque,
                task_context: *prover_task_graph.TaskContext,
            ) anyerror!void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
                const count = self.prepareRanges(task_context.cancellation, task_context.worker_budget.count);
                // Keep the same prepared state alive until every submitted
                // child joins, including partial-submission failures.
                defer task_context.joinChildren();
                for (self.range_workers[1..count]) |*worker| {
                    try task_context.spawnChild(RangeWorker.run, .{worker});
                    parallel_telemetry.recordChildSubmission();
                }
                self.range_workers[0].run();
                if (count > 1) try task_context.waitForChildren();
                try self.finishRanges(count);
            }

            fn prepareRanges(self: *PreparedDomainState, cancellation: *const prover_task_graph.CancellationToken, budget: usize) usize {
                self.failure_boundary.reset();
                const tiles = (self.eval_size + CANCELLATION_POLL_ROWS - 1) / CANCELLATION_POLL_ROWS;
                const count = @min(budget, tiles);
                std.debug.assert(count != 0 and count <= self.range_workers.len);
                var start_tile: usize = 0;
                for (self.range_workers[0..count], 0..) |*worker, index| {
                    const end_tile = start_tile + tiles / count + @intFromBool(index < tiles % count);
                    worker.* = .{
                        .state = self,
                        .cancellation = cancellation,
                        .range_index = index,
                        .row_start = start_tile * CANCELLATION_POLL_ROWS,
                        .row_end = @min(self.eval_size, end_tile * CANCELLATION_POLL_ROWS),
                    };
                    start_tile = end_tile;
                }
                std.debug.assert(start_tile == tiles);
                return count;
            }

            fn finishRanges(self: *PreparedDomainState, count: usize) !void {
                // Deterministic failure selection follows ascending row order,
                // never worker completion order.
                for (self.range_workers[0..count]) |worker| if (worker.failure) |failure| return failure;
                for (self.range_workers[0..count]) |worker| if (!worker.completed) return;
                self.column_accumulator.next_fresh_index = if (self.direct_store) self.eval_size else null;
            }

            fn deinitErased(context: *anyopaque) void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
                const allocator = self.allocator;
                for (self.owned_buffers) |values| self.values_allocator.free(values);
                allocator.free(self.owned_buffers);
                allocator.destroy(self);
            }
        };

        const RangeWorker = struct {
            state: *PreparedDomainState,
            cancellation: *const prover_task_graph.CancellationToken,
            range_index: usize,
            row_start: usize,
            row_end: usize,
            completed: bool = false,
            failure: ?anyerror = null,

            fn run(self: *RangeWorker) void {
                defer if (self.range_index != 0) {
                    parallel_telemetry.recordChildCompletion();
                };
                self.completed = self.state.component.runPreparedRange(
                    self.state,
                    self.cancellation,
                    self.range_index,
                    self.row_start,
                    self.row_end,
                ) catch |failure| {
                    self.failure = failure;
                    parallel_telemetry.recordRangeFailure();
                    if (self.state.failure_boundary.recordFailure(self.range_index))
                        parallel_telemetry.recordLocalCancellation();
                    return;
                };
            }
        };
    };
}

const frameworkConstraint = verifier.frameworkConstraint;
