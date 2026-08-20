//! Internal universal typed component authority shard; use universal_typed_component.zig publicly.

const dependency_0 = @import("universal_typed_component_contract.zig");

const CirclePointQM31 = dependency_0.CirclePointQM31;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const canonic = dependency_0.canonic;
const checkedEnd = dependency_0.checkedEnd;
const circle = dependency_0.circle;
const core_air_accumulation = dependency_0.core_air_accumulation;
const core_air_components = dependency_0.core_air_components;
const core_air_derive = dependency_0.core_air_derive;
const core_constraints = dependency_0.core_constraints;
const currentPointColumns = dependency_0.currentPointColumns;
const default_manifest = dependency_0.default_manifest;
const direct_program = dependency_0.direct_program;
const emptyOrFilledLogs = dependency_0.emptyOrFilledLogs;
const evaluationValues = dependency_0.evaluationValues;
const freePointColumns = dependency_0.freePointColumns;
const logup = dependency_0.logup;
const manifestGeometryForAir = dependency_0.manifestGeometryForAir;
const preparedResources = dependency_0.preparedResources;
const prepared_domain = dependency_0.prepared_domain;
const protocolMaximumConstraintDegree = dependency_0.protocolMaximumConstraintDegree;
const prover_air_accumulation = dependency_0.prover_air_accumulation;
const prover_circle = dependency_0.prover_circle;
const prover_component = dependency_0.prover_component;
const prover_task_graph = dependency_0.prover_task_graph;
const prover_twiddles = dependency_0.prover_twiddles;
const quotientDenominators = dependency_0.quotientDenominators;
const sampledSecure = dependency_0.sampledSecure;
const serialTaskContext = dependency_0.serialTaskContext;
const secureAt = dependency_0.secureAt;
const sourceNeedsExtension = dependency_0.sourceNeedsExtension;
const std = dependency_0.std;
const types = dependency_0.types;
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
    const Runtime = Relation.Runtime;
    const DIRECT_COUNT = Air.DIRECT_CONSTRAINT_COUNT;
    const LOGUP_COUNT = Air.INTERACTION_BATCH_COUNT;
    const CONSTRAINT_COUNT = DIRECT_COUNT + LOGUP_COUNT;
    const PP_COUNT = Air.PREPROCESSED_COLUMN_COUNT;
    const MAIN_COUNT = Air.PHYSICAL_MAIN_COLUMN_COUNT;
    const PARAMETER_COUNT = Air.LOGICAL_INPUT_COUNT - PP_COUNT - MAIN_COUNT;
    // Proof-kind and circuit parameters are verifier-owned scalars, not PCS
    // columns.  Keeping them out of the extension source array avoids both
    // uninitialized Poly descriptors and needless interpolation work.
    const SOURCE_COUNT = MAIN_COUNT + PP_COUNT + Air.INTERACTION_COLUMN_COUNT;
    // The local static profile describes direct compiler roots, while a
    // component may publish the exact degree of its compiler-lowered LogUp
    // recurrence.  That lowered bound is authoritative for this adapter: a
    // pinned source declaration describes the borrowed AIR, but must never
    // under-size quotient geometry after lowering introduces derived tuple
    // expressions. Components without an explicit lowered audit retain the
    // compatibility-v1 source declaration and cubic interaction floor.
    const PROTOCOL_MAXIMUM_DEGREE: u32 = protocolMaximumConstraintDegree(Air);
    // Even a quadratic constraint needs one evaluation-domain extension: the
    // trace-domain vanishing polynomial is zero on the unextended domain and
    // therefore cannot be inverted there.  Degree still describes the AIR;
    // this floor is strictly a quotient-evaluation geometry requirement.
    const QUOTIENT_LOG_BLOWUP: u32 = @max(
        @as(u32, 1),
        std.math.log2_int_ceil(u32, PROTOCOL_MAXIMUM_DEGREE - 1),
    );
    const DENOMINATOR_COUNT: usize = @as(usize, 1) <<
        @intCast(QUOTIENT_LOG_BLOWUP);

    comptime {
        if (Runtime.LOGICAL_INPUT_COUNT != Air.LOGICAL_INPUT_COUNT or
            Runtime.BATCH_COUNT != LOGUP_COUNT or
            Runtime.INTERACTION_COLUMN_COUNT != Air.INTERACTION_COLUMN_COUNT or
            Air.INTERACTION_COLUMN_COUNT != 4 * LOGUP_COUNT or
            CONSTRAINT_COUNT > direct_program.MAX_CONSTRAINTS)
        {
            @compileError("generic recursion component geometry drifted");
        }
        if (PP_COUNT > std.math.maxInt(u16) or
            MAIN_COUNT > std.math.maxInt(u16) or
            Air.INTERACTION_COLUMN_COUNT > std.math.maxInt(u16) or
            DIRECT_COUNT > std.math.maxInt(u16) or
            LOGUP_COUNT > std.math.maxInt(u16) or
            PROTOCOL_MAXIMUM_DEGREE > std.math.maxInt(u8) or
            Air.MAXIMUM_CONSTRAINT_DEGREE > std.math.maxInt(u8))
        {
            @compileError("generic recursion component manifest geometry overflow");
        }
    }

    return struct {
        const Self = @This();
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

        /// The component factory, rather than an assembly-site transcription,
        /// owns the equation-free manifest geometry.
        pub fn manifestGeometry(
            comptime roster_row: manifest_mod.ComponentKey,
            log_size: u32,
        ) manifest_mod.Geometry {
            return manifestGeometryForAir(
                Air,
                manifest_mod,
                roster_row,
                log_size,
            );
        }

        log_size: u32,
        placement: manifest_mod.Placement,
        parameters: [PARAMETER_COUNT]M31,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
        claimed_sum_shift: QM31,
        direct: direct_program.Program,
        relation_plan: Runtime.Plan,

        const Adapter = core_air_derive.ComponentAdapter(
            Self,
            prover_component.ComponentProver,
            prover_component.Trace,
            prover_air_accumulation.DomainEvaluationAccumulator,
        );

        /// Cold admission compiles and authenticates both program halves once.
        pub fn init(
            definition: *const Air.Definition,
            relation_plan: Runtime.Plan,
            manifest: *const manifest_mod.Manifest,
            comptime roster_row: manifest_mod.ComponentKey,
            log_size: u32,
            parameters: [PARAMETER_COUNT]M31,
            relations: *const universal.UniversalRelations,
            claimed_sum: QM31,
        ) !Self {
            if (log_size == 0 or log_size >= circle.M31_CIRCLE_LOG_ORDER)
                return error.InvalidProofShape;
            try definition.validate();
            try relations.validate();
            try relation_plan.validateAgainst(
                &definition.arena,
                Air.SEMANTIC_DIGEST,
                eventIds(definition),
            );
            const direct = try direct_program.authenticate(
                &definition.arena,
                Air.SEMANTIC_DIGEST,
                Air.LOGICAL_INPUT_COUNT,
            );
            if (direct.constraint_count != DIRECT_COUNT)
                return error.InvalidProofShape;

            const placement = try manifest.placement(roster_row);
            const geometry = placement.geometry;
            if (geometry.roster_row != manifest_mod.keyIndex(roster_row) or
                geometry.log_size != log_size or
                geometry.preprocessed_columns != PP_COUNT or
                geometry.main_columns != MAIN_COUNT or
                geometry.interaction_columns != Air.INTERACTION_COLUMN_COUNT or
                geometry.direct_constraints != DIRECT_COUNT or
                geometry.interaction_batches != LOGUP_COUNT or
                geometry.protocol_constraint_degree != PROTOCOL_MAXIMUM_DEGREE or
                geometry.profiled_constraint_degree != Air.MAXIMUM_CONSTRAINT_DEGREE or
                !std.mem.eql(u8, &geometry.semantic_digest, &Air.SEMANTIC_DIGEST))
            {
                return error.InvalidProofShape;
            }

            const n = M31.fromU64(@as(u64, 1) << @intCast(log_size));
            return .{
                .log_size = log_size,
                .placement = placement,
                .parameters = parameters,
                .relations = relations,
                .claimed_sum = claimed_sum,
                .claimed_sum_shift = try claimed_sum.divM31(n),
                .direct = direct,
                .relation_plan = relation_plan,
            };
        }

        pub fn asVerifierComponent(self: *const Self) core_air_components.Component {
            return Adapter.asVerifierComponent(self);
        }

        pub fn asProverComponent(self: *const Self) prover_component.ComponentProver {
            var result = Adapter.asProverComponent(self);
            result.prepare_domain_evaluator = prepareDomainEvaluatorErased;
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

        pub fn nConstraints(_: *const Self) usize {
            return CONSTRAINT_COUNT;
        }

        pub fn maxConstraintLogDegreeBound(self: *const Self) u32 {
            return self.log_size + QUOTIENT_LOG_BLOWUP;
        }

        pub fn traceLogDegreeBounds(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const pp = try emptyOrFilledLogs(allocator, PP_COUNT, self.log_size);
            errdefer allocator.free(pp);
            const main = try emptyOrFilledLogs(allocator, MAIN_COUNT, self.log_size);
            errdefer allocator.free(main);
            const interaction = try emptyOrFilledLogs(
                allocator,
                Air.INTERACTION_COLUMN_COUNT,
                self.log_size,
            );
            errdefer allocator.free(interaction);
            const trees = try allocator.alloc([]u32, manifest_mod.TREE_COUNT);
            trees[0] = pp;
            trees[1] = main;
            trees[2] = interaction;
            return core_air_components.TraceLogDegreeBounds.initOwned(trees);
        }

        pub fn maskPoints(
            self: *const Self,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) !core_air_components.MaskPoints {
            // The core callback supplies the largest committed trace degree,
            // not the larger quotient-evaluation degree.
            if (max_log_degree_bound < self.log_size)
                return error.InvalidProofShape;
            const pp = try currentPointColumns(allocator, PP_COUNT, point);
            errdefer freePointColumns(allocator, pp);
            const main = try currentPointColumns(allocator, MAIN_COUNT, point);
            errdefer freePointColumns(allocator, main);
            const interaction = try interactionPointColumns(
                allocator,
                point,
                max_log_degree_bound,
            );
            errdefer freePointColumns(allocator, interaction);
            const trees = try allocator.alloc(
                [][]CirclePointQM31,
                manifest_mod.TREE_COUNT,
            );
            trees[0] = pp;
            trees[1] = main;
            trees[2] = interaction;
            return core_air_components.MaskPoints.initOwned(trees);
        }

        /// Allocation-free row kernel used by admission and differential
        /// tests. `current` is the same-row cumulative value of every secure
        /// interaction column; only the final column has a previous-row term.
        pub fn evaluateBaseRowInto(
            self: *const Self,
            row: Runtime.Row,
            current: [LOGUP_COUNT]QM31,
            final_previous: QM31,
            roots: *[CONSTRAINT_COUNT]QM31,
        ) !void {
            var direct_scratch: [direct_program.MAX_NODES]M31 = undefined;
            var direct_roots: [DIRECT_COUNT]M31 = undefined;
            try self.direct.evaluateBaseInto(&row, &direct_scratch, &direct_roots);
            for (direct_roots, roots[0..DIRECT_COUNT]) |root, *target|
                target.* = QM31.fromBase(root);
            const pairs = try self.relation_plan.preparedRowPairs(
                row,
                self.relations,
            );
            for (pairs, DIRECT_COUNT..) |pair, constraint| {
                const batch = constraint - DIRECT_COUNT;
                roots[constraint] = frameworkConstraint(
                    current[batch],
                    if (batch + 1 == LOGUP_COUNT) final_previous else QM31.zero(),
                    if (batch == 0) QM31.zero() else current[batch - 1],
                    if (batch + 1 == LOGUP_COUNT)
                        self.claimed_sum_shift
                    else
                        QM31.zero(),
                    pair,
                );
            }
        }

        pub fn preprocessedColumnIndices(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) ![]usize {
            const result = try allocator.alloc(usize, PP_COUNT);
            for (result, 0..) |*index, local|
                index.* = try checkedEnd(self.placement.preprocessed_offset, local);
            return result;
        }

        pub fn evaluateConstraintQuotientsAtPoint(
            self: *const Self,
            point: CirclePointQM31,
            mask: *const core_air_components.MaskValues,
            accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            max_log_degree_bound: u32,
        ) !void {
            if (max_log_degree_bound < self.log_size or
                mask.items.len < manifest_mod.TREE_COUNT)
            {
                return error.InvalidProofShape;
            }
            const pp_end = try checkedEnd(
                self.placement.preprocessed_offset,
                PP_COUNT,
            );
            const main_end = try checkedEnd(self.placement.main_offset, MAIN_COUNT);
            const interaction_end = try checkedEnd(
                self.placement.interaction_offset,
                Air.INTERACTION_COLUMN_COUNT,
            );
            const pp_tree = mask.items[manifest_mod.PREPROCESSED_TREE_INDEX];
            const main_tree = mask.items[manifest_mod.MAIN_TREE_INDEX];
            const interaction_tree = mask.items[manifest_mod.INTERACTION_TREE_INDEX];
            if (pp_tree.len < pp_end or main_tree.len < main_end or
                interaction_tree.len < interaction_end)
            {
                return error.InvalidProofShape;
            }

            var row: Runtime.SecureRow = undefined;
            for (row[0..MAIN_COUNT], main_tree[self.placement.main_offset..main_end]) |
                *value,
                column,
            | {
                if (column.len != 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            for (row[MAIN_COUNT .. MAIN_COUNT + PP_COUNT], pp_tree[self.placement.preprocessed_offset..pp_end]) |*value, column| {
                if (column.len != 1) return error.InvalidProofShape;
                value.* = column[0];
            }
            for (row[MAIN_COUNT + PP_COUNT ..], self.parameters) |*value, parameter|
                value.* = QM31.fromBase(parameter);

            var direct_scratch: [direct_program.MAX_NODES]QM31 = undefined;
            var direct_roots: [DIRECT_COUNT]QM31 = undefined;
            try self.direct.evaluateSecureInto(&row, &direct_scratch, &direct_roots);
            const pairs = try self.relation_plan.preparedSecureRowPairs(
                row,
                self.relations,
            );
            const interaction = interaction_tree[self.placement.interaction_offset..interaction_end];
            const denominator_inverse = try core_constraints.cosetVanishing(
                QM31,
                canonic.CanonicCoset.new(self.log_size).coset(),
                point.repeatedDouble(max_log_degree_bound - self.log_size),
            ).inv();
            for (direct_roots) |root|
                accumulator.accumulate(root.mul(denominator_inverse));
            for (0..LOGUP_COUNT) |batch| {
                const final = batch + 1 == LOGUP_COUNT;
                const current = try sampledSecure(
                    interaction,
                    4 * batch,
                    if (final) 1 else 0,
                );
                const previous_column = if (batch == 0)
                    QM31.zero()
                else
                    try sampledSecure(interaction, 4 * (batch - 1), 0);
                const previous_row = if (final)
                    try sampledSecure(interaction, 4 * batch, 0)
                else
                    QM31.zero();
                const shift = if (final)
                    self.claimed_sum_shift
                else
                    QM31.zero();
                accumulator.accumulate(frameworkConstraint(
                    current,
                    previous_row,
                    previous_column,
                    shift,
                    pairs[batch],
                ).mul(denominator_inverse));
            }
        }

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
            var owned_count: usize = 0;
            for (sources) |poly| if (try sourceNeedsExtension(
                poly,
                self.log_size,
                eval_log_size,
            )) {
                owned_count += 1;
            };
            const owned_buffers = try allocator.alloc([]M31, owned_count);
            var owned_initialized: usize = 0;
            errdefer {
                for (owned_buffers[0..owned_initialized]) |values|
                    allocator.free(values);
                allocator.free(owned_buffers);
            }
            var evaluations: [SOURCE_COUNT][]const M31 = undefined;
            for (sources, &evaluations) |poly, *target| {
                target.* = try evaluationValues(
                    allocator,
                    poly,
                    eval_log_size,
                    eval_size,
                    owned_buffers,
                    &owned_initialized,
                );
            }
            std.debug.assert(owned_initialized == owned_count);
            if (owned_count != 0) {
                var twiddles = try prover_twiddles.precomputeM31(
                    allocator,
                    eval_domain.half_coset,
                );
                defer prover_twiddles.deinitM31(allocator, &twiddles);
                try prover_circle.poly.evaluateBuffersWithTwiddles(
                    owned_buffers,
                    eval_domain,
                    prover_twiddles.TwiddleTree([]const M31).init(
                        twiddles.root_coset,
                        twiddles.twiddles,
                        twiddles.itwiddles,
                    ),
                );
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
                .denominator_inverse = denominator_inverse,
                .column_accumulator = accumulator_columns[0],
                .eval_size = eval_size,
            };
            return .{
                .context = state,
                .vtable = &PreparedDomainState.vtable,
                .task_class = .leaf,
                .resources = try preparedResources(
                    eval_size,
                    owned_count,
                    @sizeOf(PreparedDomainState),
                ),
            };
        }

        fn runPreparedDomain(
            self: *const Self,
            state: *PreparedDomainState,
            task_context: *prover_task_graph.TaskContext,
        ) !void {
            const evaluations = &state.evaluations;
            const interaction_start = MAIN_COUNT + PP_COUNT;
            const denominator_shift: std.math.Log2Int(usize) = @intCast(self.log_size);
            const powers = state.column_accumulator.random_coeff_powers;
            if (powers.len < CONSTRAINT_COUNT) return error.InvalidProofShape;
            for (0..state.eval_size) |row_index| {
                if ((row_index & (PreparedDomainState.CANCELLATION_POLL_ROWS - 1)) == 0 and
                    task_context.isCancelled()) return;
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
                state.column_accumulator.accumulate(
                    row_index,
                    folded.mulM31(state.denominator_inverse[
                        row_index >> denominator_shift
                    ]),
                );
            }
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
            denominator_inverse: [DENOMINATOR_COUNT]M31,
            column_accumulator: prover_air_accumulation.ColumnAccumulator,
            eval_size: usize,

            const vtable = prepared_domain.VTable{
                .run = runErased,
                .deinit = deinitErased,
            };

            fn runErased(
                context: *anyopaque,
                task_context: *prover_task_graph.TaskContext,
            ) anyerror!void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
                try self.component.runPreparedDomain(self, task_context);
            }

            fn deinitErased(context: *anyopaque) void {
                const self: *PreparedDomainState = @ptrCast(@alignCast(context));
                const allocator = self.allocator;
                for (self.owned_buffers) |values| allocator.free(values);
                allocator.free(self.owned_buffers);
                allocator.destroy(self);
            }
        };

        fn interactionPointColumns(
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            max_log_degree_bound: u32,
        ) ![][]CirclePointQM31 {
            const columns = try allocator.alloc(
                []CirclePointQM31,
                Air.INTERACTION_COLUMN_COUNT,
            );
            var initialized: usize = 0;
            errdefer {
                for (columns[0..initialized]) |column| allocator.free(column);
                allocator.free(columns);
            }
            const final_start = 4 * (LOGUP_COUNT - 1);
            for (columns, 0..) |*column, index| {
                column.* = if (index < final_start)
                    try allocator.dupe(CirclePointQM31, &.{point})
                else
                    try allocator.dupe(CirclePointQM31, &.{
                        logup.prevRowPoint(max_log_degree_bound, point),
                        point,
                    });
                initialized += 1;
            }
            return columns;
        }

        fn eventIds(
            definition: *const Air.Definition,
        ) [Air.RELATION_EVENT_COUNT]types.EffectId {
            if (comptime @hasDecl(Relation, "events")) {
                return Relation.events(definition);
            } else if (comptime @hasField(Air.Definition, "events")) {
                const Events = @TypeOf(definition.events);
                if (comptime @typeInfo(Events) == .array)
                    return definition.events;
                if (comptime @hasDecl(Events, "ordered"))
                    return definition.events.ordered();
                @compileError(
                    "typed recursion relation events must expose canonical order",
                );
            } else if (comptime Air.RELATION_EVENT_COUNT == 1 and
                @hasField(Air.Definition, "event"))
            {
                return .{definition.event};
            } else {
                @compileError(
                    "typed recursion relation must expose canonical event order",
                );
            }
        }
    };
}

inline fn frameworkConstraint(
    current: QM31,
    previous_row: QM31,
    previous_column: QM31,
    shift: QM31,
    pair: logup.RowPair,
) QM31 {
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    const denominator = pair.d1.mul(pair.d2);
    return current.sub(previous_row).sub(previous_column).add(shift)
        .mul(denominator).sub(numerator);
}
