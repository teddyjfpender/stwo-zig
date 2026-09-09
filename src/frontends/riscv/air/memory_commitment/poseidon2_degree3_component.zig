//! Shared native prover/verifier adapter for versioned degree-three Poseidon
//! layouts. Reuses hash-domain sampling and source preparation.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const canonic = core.poly.circle.canonic;
const components = core.air.components;
const component_prover = prover.air.component_prover;
const accumulation = prover.air.accumulation;
const prepared = prover.air.prepared_domain;
const task_graph = prover.task_graph;
const work_pool = prover.work_pool;
const logup = @import("../logup.zig");
const Relations = @import("../relation_challenges.zig").Relations;
const work = @import("../composition_work_support.zig");
const preparation = @import("hash_component_prepared_support.zig");
const sampling = @import("hash_component_sampling.zig").Namespace(.{ .std = std, .M31 = M31, .QM31 = QM31, .CirclePointQM31 = Point });

/// Shared prover/verifier adapter for admitted degree-three Poseidon layouts.
pub fn Namespace(comptime air: type, comptime backend_module: ?type) type {
    return struct {
        pub const N_CONSTRAINTS = air.N_CONSTRAINTS + air.N_SUMS;
        const ACTIVE = if (@hasDecl(air, "BINDS_ACTIVE_SELECTOR")) air.BINDS_ACTIVE_SELECTOR else true;
        const PP: usize = if (ACTIVE) 2 else 1;
        const N_SOURCES = PP + air.N_MAIN_COLUMNS + air.N_INTERACTION_COLUMNS;

        pub const Component = struct {
            log_size: u32,
            n_rows: u32,
            is_first_col_idx: usize,
            is_active_col_idx: usize,
            main_col_offset: usize,
            interaction_col_offset: usize,
            relations: *const Relations,
            claims: [air.N_SUMS]QM31,

            const Adapter = core.air.derive.ComponentAdapter(@This(), component_prover.ComponentProver, component_prover.Trace, accumulation.DomainEvaluationAccumulator);

            pub fn validate(self: *const Component) !void {
                if (self.log_size == 0 or self.log_size >= core.circle.M31_CIRCLE_LOG_ORDER - 1 or (ACTIVE and self.n_rows == 0) or @as(u64, self.n_rows) > @as(u64, 1) << @intCast(self.log_size)) return error.InvalidPoseidonNarrowComponentV1;
                _ = try std.math.add(usize, self.main_col_offset, air.N_MAIN_COLUMNS);
                _ = try std.math.add(usize, self.interaction_col_offset, air.N_INTERACTION_COLUMNS);
                if (ACTIVE and self.is_first_col_idx == self.is_active_col_idx) return error.InvalidPoseidonNarrowComponentV1;
            }

            pub fn asProverComponent(self: *const Component) component_prover.ComponentProver {
                var result = Adapter.asProverComponent(self);
                result.prepare_domain_evaluator = prepareErased;
                if (backend_module) |backend| result.backend_composition_capability = backend.Namespace(Component).capability();
                result.composition_work_profile = workProfile;
                result.oods_work_profile = oodsProfile;
                return result;
            }

            fn workProfile(context: *const anyopaque, _: std.mem.Allocator) anyerror!work.ComponentProfile {
                const self: *const Component = @ptrCast(@alignCast(context));
                const S = work.Scalar;
                const relations = work.Relations.init();
                const main = work.values(air.N_MAIN_COLUMNS, 0);
                const sums = work.values(air.N_SUMS, 500);
                const previous = work.values(air.N_SUMS, 520);
                const claims = work.values(air.N_SUMS, 540);
                const first = work.values(1, 900)[0];
                const active = work.values(1, 910)[0];
                var expression: work.FieldOperations = undefined;
                try work.begin(&expression);
                defer work.end();
                _ = if (ACTIVE) air.evaluateGeneric(S, main, active) else air.evaluateGeneric(S, main);
                _ = air.interactionConstraintsGeneric(S, main, first, sums, previous, claims, &relations);
                return work.profile(.poseidon2, air.STABLE_NAME, self.maxConstraintLogDegreeBound(), N_CONSTRAINTS, expression, .{}, &.{ air.SCHEMA_VERSION, self.log_size, air.N_MAIN_COLUMNS, air.N_SUMS });
            }

            fn oodsProfile(context: *const anyopaque, _: std.mem.Allocator, max_log_degree_bound: u32, source: *const work.ComponentProfile) anyerror!work.OodsComponentProfile {
                const self: *const Component = @ptrCast(@alignCast(context));
                return work.oodsProfile(source, self.log_size, max_log_degree_bound, 2 * air.N_SUMS, true);
            }

            pub fn asVerifierComponent(self: *const Component) components.Component {
                return Adapter.asVerifierComponent(self);
            }
            pub fn nPreprocessedColumns(_: *const Component) usize {
                return PP;
            }
            pub fn nConstraints(_: *const Component) usize {
                return N_CONSTRAINTS;
            }
            pub fn maxConstraintLogDegreeBound(self: *const Component) u32 {
                return self.log_size + 1;
            }
            pub fn compositionLogSplit(_: *const Component) u32 {
                return 1;
            }

            pub fn traceLogDegreeBounds(self: *const Component, allocator: std.mem.Allocator) !components.TraceLogDegreeBounds {
                try self.validate();
                const outer = try allocator.alloc([]u32, 3);
                var initialized: usize = 0;
                errdefer {
                    for (outer[0..initialized]) |slice| allocator.free(slice);
                    allocator.free(outer);
                }
                for (outer, [_]usize{ PP, air.N_MAIN_COLUMNS, air.N_INTERACTION_COLUMNS }) |*slice, count| {
                    slice.* = try allocator.alloc(u32, count);
                    @memset(slice.*, self.log_size);
                    initialized += 1;
                }
                return components.TraceLogDegreeBounds.initOwned(outer);
            }

            pub fn preprocessedColumnIndices(self: *const Component, allocator: std.mem.Allocator) ![]usize {
                try self.validate();
                return allocator.dupe(usize, if (ACTIVE) &.{ self.is_first_col_idx, self.is_active_col_idx } else &.{self.is_first_col_idx});
            }

            pub fn maskPoints(self: *const Component, allocator: std.mem.Allocator, point: Point, max_log_degree_bound: u32) !components.MaskPoints {
                try self.validate();
                if (max_log_degree_bound < self.log_size) return error.InvalidProofShape;
                const pp = try sampling.currentPointColumns(allocator, PP, point);
                errdefer sampling.freePointColumns(allocator, pp);
                const main = try sampling.currentPointColumns(allocator, air.N_MAIN_COLUMNS, point);
                errdefer sampling.freePointColumns(allocator, main);
                const interaction = try sampling.currentAndPreviousPointColumns(allocator, air.N_INTERACTION_COLUMNS, point, logup.prevRowPoint(max_log_degree_bound, point));
                errdefer sampling.freePointColumns(allocator, interaction);
                return components.MaskPoints.initOwned(try allocator.dupe([][]Point, &.{ pp, main, interaction }));
            }

            pub fn evaluateConstraintQuotientsAtPoint(self: *const Component, point: Point, mask: *const components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log_degree_bound: u32) !void {
                try self.validate();
                if (max_log_degree_bound < self.log_size or mask.items.len < 3) return error.InvalidProofShape;
                const pp = mask.items[0];
                if (pp.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or pp[self.is_first_col_idx].len != 1 or pp[self.is_active_col_idx].len != 1 or mask.items[2].len < self.interaction_col_offset + air.N_INTERACTION_COLUMNS) return error.InvalidProofShape;
                const main = try sampling.sampleMain(air.N_MAIN_COLUMNS, mask.items[1], self.main_col_offset);
                var sums: [air.N_SUMS]QM31 = undefined;
                var previous: [air.N_SUMS]QM31 = undefined;
                try sampling.sampleInteraction(air.N_SUMS, mask.items[2], self.interaction_col_offset, &sums, &previous);
                const inverse = try core.constraints.cosetVanishing(QM31, canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log_degree_bound - self.log_size)).inv();
                for (self.constraints(main, pp[self.is_active_col_idx][0], pp[self.is_first_col_idx][0], sums, previous)) |constraint| accumulator.accumulate(constraint.mul(inverse));
            }

            fn constraints(self: *const Component, main: [air.N_MAIN_COLUMNS]QM31, active: QM31, first: QM31, sums: [air.N_SUMS]QM31, previous: [air.N_SUMS]QM31) [N_CONSTRAINTS]QM31 {
                var result: [N_CONSTRAINTS]QM31 = undefined;
                @memcpy(result[0..air.N_CONSTRAINTS], &(if (ACTIVE) air.evaluateGeneric(QM31, main, active) else air.evaluateGeneric(QM31, main)));
                @memcpy(result[air.N_CONSTRAINTS..], &air.interactionConstraintsGeneric(QM31, main, first, sums, previous, self.claims, self.relations));
                return result;
            }

            /// The prepared owner admits geometry and powers before hot row reads.
            fn evaluatePreparedRow(self: *const Component, main: [air.N_MAIN_COLUMNS]M31, active: M31, first: M31, sums: [air.N_SUMS]QM31, previous: [air.N_SUMS]QM31, powers: []const QM31) QM31 {
                std.debug.assert(powers.len == N_CONSTRAINTS);
                const direct = if (ACTIVE) air.evaluateGeneric(M31, main, active) else air.evaluateGeneric(M31, main);
                var value = QM31.zero();
                for (direct, 0..) |residual, index| value = value.add(powers[N_CONSTRAINTS - 1 - index].mulM31(residual));
                var secure_main: [air.N_MAIN_COLUMNS]QM31 = undefined;
                for (&secure_main, main) |*destination, source| destination.* = QM31.fromBase(source);
                const interaction = air.interactionConstraintsGeneric(QM31, secure_main, QM31.fromBase(first), sums, previous, self.claims, self.relations);
                return value.add(sampling.combineConstraints(powers[0..air.N_SUMS], &interaction));
            }

            pub fn evaluateConstraintQuotientsOnDomain(self: *const Component, trace: *const component_prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !void {
                var value = try self.prepareDomain(accumulator.allocator, trace, accumulator);
                defer value.deinit();
                var cancellation = task_graph.CancellationToken{};
                const state: *State = @ptrCast(@alignCast(value.context));
                try state.evaluateRange(&cancellation, 0, state.values[0].len);
                state.finish();
            }

            fn prepareErased(context: *const anyopaque, allocator: std.mem.Allocator, trace: *const component_prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) anyerror!prepared.PreparedDomainEvaluation {
                const self: *const Component = @ptrCast(@alignCast(context));
                return self.prepareDomain(allocator, trace, accumulator);
            }

            fn prepareDomain(self: *const Component, allocator: std.mem.Allocator, trace: *const component_prover.Trace, accumulator: *accumulation.DomainEvaluationAccumulator) !prepared.PreparedDomainEvaluation {
                try self.validate();
                if (trace.polys.items.len < 3) return error.InvalidProofShape;
                const pp = trace.polys.items[0];
                const main = trace.polys.items[1];
                const interaction = trace.polys.items[2];
                if (pp.len <= @max(self.is_first_col_idx, self.is_active_col_idx) or main.len < self.main_col_offset + air.N_MAIN_COLUMNS or interaction.len < self.interaction_col_offset + air.N_INTERACTION_COLUMNS) return error.InvalidProofShape;
                var sources: [N_SOURCES]component_prover.Poly = undefined;
                sources[0] = pp[self.is_first_col_idx];
                if (ACTIVE) sources[1] = pp[self.is_active_col_idx];
                @memcpy(sources[PP..][0..air.N_MAIN_COLUMNS], main[self.main_col_offset..][0..air.N_MAIN_COLUMNS]);
                @memcpy(sources[PP + air.N_MAIN_COLUMNS ..], interaction[self.interaction_col_offset..][0..air.N_INTERACTION_COLUMNS]);
                const eval_log = self.log_size + 1;
                const domain = canonic.CanonicCoset.new(eval_log).circleDomain();
                var owned_count: usize = 0;
                for (sources) |poly| owned_count += @intFromBool(try preparation.sourceNeedsExtension(poly, self.log_size, eval_log));
                const resources = try preparation.resourcesWithStack(domain.size(), N_SOURCES, owned_count, @sizeOf(State), 1024 * 1024);
                const values = try allocator.alloc([]const M31, N_SOURCES);
                errdefer allocator.free(values);
                const owned = try allocator.alloc([]M31, owned_count);
                var initialized: usize = 0;
                errdefer {
                    for (owned[0..initialized]) |column| allocator.free(column);
                    allocator.free(owned);
                }
                for (sources, values) |poly, *column| column.* = try preparation.evaluationValues(allocator, poly, eval_log, domain.size(), owned, &initialized);
                if (owned.len != 0) {
                    var twiddles = try prover.poly.twiddles.precomputeM31(allocator, domain.half_coset);
                    defer prover.poly.twiddles.deinitM31(allocator, &twiddles);
                    try prover.poly.circle.poly.evaluateBuffersWithTwiddles(owned, domain, prover.poly.twiddles.TwiddleTree([]const M31).init(twiddles.root_coset, twiddles.twiddles, twiddles.itwiddles));
                }
                const inverse = try preparation.quotientDenominators(2, self.log_size, eval_log, domain);
                const state = try allocator.create(State);
                errdefer allocator.destroy(state);
                const columns = try accumulator.columns(allocator, &.{.{ .log_size = eval_log, .n_cols = N_CONSTRAINTS }});
                defer allocator.free(columns);
                state.* = .{ .allocator = allocator, .component = self, .values = values, .owned = owned, .inverse = inverse, .accumulator = columns[0], .direct_store = columns[0].next_fresh_index == 0 };
                return .{ .context = state, .vtable = &State.vtable, .task_class = if (eval_log >= 18) .pool_exclusive else .leaf, .resources = resources };
            }
        };

        const State = struct {
            allocator: std.mem.Allocator,
            component: *const Component,
            values: [][]const M31,
            owned: [][]M31,
            inverse: [2]M31,
            accumulator: accumulation.ColumnAccumulator,
            direct_store: bool,
            workers: [work_pool.MAX_WORKERS]Worker = undefined,
            const vtable = prepared.VTable{ .run = run, .deinit = deinit };

            fn evaluateRange(self: *State, cancellation: *const task_graph.CancellationToken, start: usize, end: usize) !void {
                const component = self.component;
                for (start..end) |row| {
                    if (row % 4096 == 0 and cancellation.isCancelled()) return error.TaskCancelled;
                    const previous_row = core.utils.previousBitReversedCircleDomainIndex(row, component.log_size, component.log_size + 1);
                    var sums: [air.N_SUMS]QM31 = undefined;
                    var previous: [air.N_SUMS]QM31 = undefined;
                    sampling.readInteraction(air.N_SUMS, self.values, PP + air.N_MAIN_COLUMNS, row, previous_row, &sums, &previous);
                    var base_main: [air.N_MAIN_COLUMNS]M31 = undefined;
                    for (&base_main, self.values[PP..][0..air.N_MAIN_COLUMNS]) |*value, column| value.* = column[row];
                    const value = component.evaluatePreparedRow(base_main, if (ACTIVE) self.values[1][row] else M31.zero(), self.values[0][row], sums, previous, self.accumulator.random_coeff_powers).mulM31(self.inverse[row >> @intCast(component.log_size)]);
                    const out = self.accumulator.col;
                    out.set(row, if (self.direct_store) value else out.at(row).add(value));
                }
            }

            fn run(context: *anyopaque, task: *task_graph.TaskContext) anyerror!void {
                const self: *State = @ptrCast(@alignCast(context));
                const size = self.values[0].len;
                const tiles = (size + 4095) / 4096;
                const count = @min(task.worker_budget.count, tiles);
                if (count <= 1) {
                    try self.evaluateRange(task.cancellation, 0, size);
                    self.finish();
                    return;
                }
                std.debug.assert(task.task_class == .pool_exclusive);
                for (self.workers[0..count], 0..) |*worker, index| worker.* = .{
                    .state = self,
                    .cancellation = task.cancellation,
                    .start = @min(size, (tiles * index / count) * 4096),
                    .end = @min(size, (tiles * (index + 1) / count) * 4096),
                };
                var joined = false;
                defer if (!joined) task.waitForChildren() catch {};
                for (self.workers[1..count]) |*worker| try task.spawnChild(Worker.run, .{worker});
                self.workers[0].run();
                try task.waitForChildren();
                joined = true;
                for (self.workers[0..count]) |worker| if (worker.failure) |failure| return failure;
                self.finish();
            }

            fn finish(self: *State) void {
                self.accumulator.next_fresh_index = if (self.direct_store) self.values[0].len else null;
            }

            const Worker = struct {
                state: *State,
                cancellation: *const task_graph.CancellationToken,
                start: usize,
                end: usize,
                failure: ?anyerror = null,
                fn run(self: *@This()) void {
                    self.state.evaluateRange(self.cancellation, self.start, self.end) catch |failure| {
                        self.failure = failure;
                    };
                }
            };

            fn deinit(context: *anyopaque) void {
                const self: *State = @ptrCast(@alignCast(context));
                for (self.owned) |column| self.allocator.free(column);
                self.allocator.free(self.owned);
                self.allocator.free(self.values);
                self.allocator.destroy(self);
            }
        };
    };
}

test "degree3 Poseidon prepared rows match full secure evaluation off-domain" {
    var prng = std.Random.DefaultPrng.init(0x303_287_32);
    const random = prng.random();
    const RandomField = struct {
        fn base(r: std.Random) M31 {
            return M31.fromCanonical(r.uintLessThan(u32, core.fields.m31.Modulus));
        }
        fn secure(r: std.Random) QM31 {
            return QM31.fromM31(base(r), base(r), base(r), base(r));
        }
    };
    inline for (.{ @import("poseidon2_narrow_degree3_v1.zig"), @import("poseidon2_universal_degree3_v1.zig") }) |Air| {
        const Component = Namespace(Air, null).Component;
        const count = Air.N_CONSTRAINTS + Air.N_SUMS;
        var relations: Relations = undefined;
        inline for (std.meta.fields(Relations)) |field| @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(RandomField.secure(random), RandomField.secure(random));
        var component = Component{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = if (@hasDecl(Air, "BINDS_ACTIVE_SELECTOR")) 0 else 1, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{QM31.zero()} ** Air.N_SUMS };
        try component.validate();
        for (0..32) |_| {
            var main: [Air.N_MAIN_COLUMNS]M31 = undefined;
            var secure_main: [Air.N_MAIN_COLUMNS]QM31 = undefined;
            for (&main, &secure_main) |*base_value, *secure_value| {
                base_value.* = RandomField.base(random);
                secure_value.* = QM31.fromBase(base_value.*);
            }
            var powers: [count]QM31 = undefined;
            for (&powers) |*value| value.* = RandomField.secure(random);
            var sums: [Air.N_SUMS]QM31 = undefined;
            var previous: [Air.N_SUMS]QM31 = undefined;
            for (&sums, &previous, &component.claims) |*current, *prior, *claim| {
                current.* = RandomField.secure(random);
                prior.* = RandomField.secure(random);
                claim.* = RandomField.secure(random);
            }
            const first = RandomField.base(random);
            const active = RandomField.base(random);
            const roots = component.constraints(secure_main, QM31.fromBase(active), QM31.fromBase(first), sums, previous);
            const expected = sampling.combineConstraints(&powers, &roots);
            try std.testing.expectEqualDeep(expected, component.evaluatePreparedRow(main, active, first, sums, previous, &powers));
        }
    }
}
