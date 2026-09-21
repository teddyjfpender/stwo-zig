//! PCS adapter for Ethereum paths with full-I/O node callers. The containing
//! protocol must reconstruct preprocessing and balance all provider claims.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const node = @import("ethereum_node_v1.zig");
const path = @import("ethereum_path_v1.zig");
const relations_mod = @import("../relation_challenges.zig");
const logup = @import("../logup.zig");
const owner_mod = @import("../prepared_evaluation_owner.zig");
const support = @import("hash_component_prepared_support.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const ComponentProver = engine.air.component_prover;
const DomainAccumulator = engine.air.accumulation.DomainEvaluationAccumulator;
const Prepared = engine.air.prepared_domain.PreparedDomainEvaluation;
const sampling = @import("hash_component_sampling.zig").Namespace(.{
    .std = std,
    .M31 = M31,
    .QM31 = QM31,
    .CirclePointQM31 = Point,
});
const widths = [_]usize{ path.PREPROCESSED_COLUMNS, node.N_MAIN_COLUMNS, node.N_INTERACTION_COLUMNS };
const source_count = widths[0] + widths[1] + widths[2];

pub const Component = struct {
    log_size: u32,
    statement: path.Statement,
    /// First-row and active-prefix selectors, then main and interaction ranges.
    offsets: [3]usize,
    relations: *const relations_mod.Relations,
    claims: [node.N_SUMS]QM31,

    const Adapter = core.air.derive.ComponentAdapter(
        @This(),
        ComponentProver.ComponentProver,
        ComponentProver.Trace,
        DomainAccumulator,
    );

    pub fn init(log_size: u32, offsets: [3]usize, relations: *const relations_mod.Relations, claims: [node.N_SUMS]QM31, statement: path.Statement) !@This() {
        if (log_size < 4 or log_size > 24) return error.InvalidTraceShape;
        try statement.validate();
        if (statement.depth > (@as(u32, 1) << @intCast(log_size))) return error.InvalidTraceShape;
        for (offsets, widths) |offset, width|
            _ = std.math.add(usize, offset, width) catch return error.InvalidPlacement;
        return .{ .log_size = log_size, .statement = statement, .offsets = offsets, .relations = relations, .claims = claims };
    }

    pub fn asProverComponent(self: *const @This()) ComponentProver.ComponentProver {
        var result = Adapter.asProverComponent(self);
        result.prepare_domain_evaluator = prepareErased;
        return result;
    }

    pub fn asVerifierComponent(self: *const @This()) core.air.components.Component {
        return Adapter.asVerifierComponent(self);
    }

    pub fn nConstraints(_: *const @This()) usize {
        return path.N_CONSTRAINTS;
    }
    pub fn maxConstraintLogDegreeBound(self: *const @This()) u32 {
        return self.log_size + 1;
    }
    pub fn constraintDegreeBound(_: *const @This(), index: usize) !u8 {
        if (index >= path.N_CONSTRAINTS) return error.InvalidProofShape;
        return 3;
    }

    pub fn traceLogDegreeBounds(self: *const @This(), allocator: std.mem.Allocator) !core.air.components.TraceLogDegreeBounds {
        var result = core.air.components.TraceLogDegreeBounds.initOwned(try allocator.alloc([]u32, 3));
        @memset(result.items, &.{});
        errdefer result.deinitDeep(allocator);
        for (widths, result.items) |width, *tree| {
            tree.* = try allocator.alloc(u32, width);
            @memset(tree.*, self.log_size);
        }
        return result;
    }

    pub fn preprocessedColumnIndices(self: *const @This(), allocator: std.mem.Allocator) ![]usize {
        const indices = try allocator.alloc(usize, widths[0]);
        for (indices, 0..) |*value, index| value.* = self.offsets[0] + index;
        return indices;
    }

    pub fn maskPoints(self: *const @This(), allocator: std.mem.Allocator, point: Point, max_log: u32) !core.air.components.MaskPoints {
        if (max_log < self.log_size) return error.InvalidMaskDegreeBound;
        const pp = try sampling.currentPointColumns(allocator, widths[0], point);
        errdefer sampling.freePointColumns(allocator, pp);
        const main = try sampling.currentAndPreviousPointColumns(allocator, widths[1], point, logup.prevRowPoint(max_log, point));
        errdefer sampling.freePointColumns(allocator, main);
        const interaction = try sampling.currentAndPreviousPointColumns(allocator, widths[2], point, logup.prevRowPoint(max_log, point));
        errdefer sampling.freePointColumns(allocator, interaction);
        return core.air.components.MaskPoints.initOwned(try allocator.dupe([][]Point, &.{ pp, main, interaction }));
    }

    pub fn evaluateConstraintQuotientsAtPoint(self: *const @This(), point: Point, mask: *const core.air.components.MaskValues, accumulator: *core.air.accumulation.PointEvaluationAccumulator, max_log: u32) !void {
        if (mask.items.len < 3 or max_log < self.log_size) return error.InvalidProofShape;
        for (mask.items[0..3], self.offsets, widths) |tree, offset, width|
            if (tree.len < offset + width) return error.InvalidProofShape;
        const pp = try sampling.sampleMain(path.PREPROCESSED_COLUMNS, mask.items[0], self.offsets[0]);
        const main = try sampling.sampleMain(node.N_MAIN_COLUMNS, mask.items[1], self.offsets[1]);
        var prior_digest: [node.DIGEST_WORDS]QM31 = undefined;
        for (&prior_digest, 0..) |*word, index| {
            const values = mask.items[1][self.offsets[1] + node.DIGEST_COLUMN + index];
            if (values.len < 2) return error.InvalidProofShape;
            word.* = values[1];
        }
        var sums: [node.N_SUMS]QM31 = undefined;
        var previous: [node.N_SUMS]QM31 = undefined;
        try sampling.sampleInteraction(node.N_SUMS, mask.items[2], self.offsets[2], &sums, &previous);
        const inverse = try core.constraints.cosetVanishing(QM31, core.poly.circle.canonic.CanonicCoset.new(self.log_size).coset(), point.repeatedDouble(max_log - self.log_size)).inv();
        for (path.evaluate(QM31, self.statement, node.fromColumns(QM31, main), prior_digest, pp, sums, previous, self.claims, self.relations)) |constraint|
            accumulator.accumulate(constraint.mul(inverse));
    }

    pub fn evaluateConstraintQuotientsOnDomain(self: *const @This(), trace: *const ComponentProver.Trace, accumulator: *DomainAccumulator) !void {
        var prepared = try self.prepare(accumulator.allocator, trace, accumulator);
        defer prepared.deinit();
        var cancellation = engine.task_graph.CancellationToken{};
        var context = engine.task_graph.TaskContext{
            .user_context = prepared.context,
            .cancellation = &cancellation,
            .key = .{ .epoch = 0, .stage_rank = 0, .component_registry_index = 0, .shard_or_chunk_index = 0 },
            .worker_budget = engine.work_pool.WorkerBudget.serial(),
            .task_class = .leaf,
            .exclusive_lease = null,
            .child_wait_group = null,
        };
        try prepared.run(&context);
    }

    fn prepareErased(ctx: *const anyopaque, allocator: std.mem.Allocator, trace: *const ComponentProver.Trace, accumulator: *DomainAccumulator) anyerror!Prepared {
        const self: *const @This() = @ptrCast(@alignCast(ctx));
        return self.prepare(allocator, trace, accumulator);
    }

    fn prepare(self: *const @This(), allocator: std.mem.Allocator, trace: *const ComponentProver.Trace, accumulator: *DomainAccumulator) !Prepared {
        if (trace.polys.items.len != 3) return error.InvalidProofShape;
        const log = self.log_size + 1;
        const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
        var sources: [source_count]ComponentProver.Poly = undefined;
        var at: usize = 0;
        var owned_count: usize = 0;
        for (trace.polys.items, self.offsets, widths) |tree, offset, width| {
            if (tree.len < offset + width) return error.InvalidProofShape;
            for (tree[offset..][0..width]) |poly| {
                owned_count += @intFromBool(try owner_mod.needsOwned(poly, self.log_size, log));
                sources[at] = poly;
                at += 1;
            }
        }
        var owner = try owner_mod.Owner.init(allocator, owned_count);
        errdefer owner.deinit();
        var evaluations: [source_count][]const M31 = undefined;
        for (sources, &evaluations) |poly, *values|
            values.* = try owner.value(poly, self.log_size, log, domain.size());
        try owner.finish(domain);
        const inverse = try support.quotientDenominators(2, self.log_size, log, domain);
        const resources = try support.resourcesWithStack(domain.size(), 0, owned_count, @sizeOf(State), 256 * 1024);
        const columns = try accumulator.columns(allocator, &.{.{ .log_size = log, .n_cols = path.N_CONSTRAINTS }});
        defer allocator.free(columns);
        const state = try allocator.create(State);
        state.* = .{ .allocator = allocator, .component = self, .owner = owner, .evaluations = evaluations, .inverse = inverse, .accumulator = columns[0] };
        return .{ .context = state, .vtable = &State.vtable, .task_class = .pool_exclusive, .resources = resources };
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    component: *const Component,
    owner: owner_mod.Owner,
    evaluations: [source_count][]const M31,
    inverse: [2]M31,
    accumulator: engine.air.accumulation.ColumnAccumulator,
    const vtable = engine.air.prepared_domain.VTable{ .run = run, .deinit = deinit };

    fn deinit(ctx: *anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const allocator = self.allocator;
        self.owner.deinit();
        allocator.destroy(self);
    }

    fn run(ctx: *anyopaque, task: *engine.task_graph.TaskContext) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const component = self.component;
        const values = &self.evaluations;
        const log = component.log_size;
        for (0..values[0].len) |row| {
            if ((row & 4095) == 0 and task.isCancelled()) return;
            const prior = core.utils.previousBitReversedCircleDomainIndex(row, log, log + 1);
            const main = sampling.readMain(node.N_MAIN_COLUMNS, values[widths[0]..][0..node.N_MAIN_COLUMNS], row);
            const pp = sampling.readMain(path.PREPROCESSED_COLUMNS, values[0..widths[0]], row);
            var prior_digest: [node.DIGEST_WORDS]QM31 = undefined;
            for (&prior_digest, 0..) |*word, index|
                word.* = QM31.fromBase(values[widths[0] + node.DIGEST_COLUMN + index][prior]);
            var sums: [node.N_SUMS]QM31 = undefined;
            var previous: [node.N_SUMS]QM31 = undefined;
            sampling.readInteraction(node.N_SUMS, values, widths[0] + node.N_MAIN_COLUMNS, row, prior, &sums, &previous);
            const constraints = path.evaluate(QM31, component.statement, node.fromColumns(QM31, main), prior_digest, pp, sums, previous, component.claims, component.relations);
            const folded = sampling.combineConstraints(self.accumulator.random_coeff_powers, &constraints);
            self.accumulator.accumulate(row, folded.mulM31(self.inverse[row >> @intCast(log)]));
        }
    }
};

test "Ethereum node V1 component validates placement and physical geometry" {
    const relations = relations_mod.Relations.dummy();
    const statement = path.Statement{ .kind = .memory, .depth = 3, .index = 1, .leaf = .{0} ** node.DIGEST_WORDS, .root = .{0} ** node.DIGEST_WORDS };
    const component = try Component.init(4, .{ 3, 7, 11 }, &relations, .{ QM31.zero(), QM31.zero() }, statement);
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(node.N_MAIN_COLUMNS, bounds.items[1].len);
    try std.testing.expectError(error.InvalidTraceShape, Component.init(32, .{ 0, 0, 0 }, &relations, component.claims, statement));
    try std.testing.expectError(error.InvalidPlacement, Component.init(4, .{ 0, std.math.maxInt(usize), 0 }, &relations, component.claims, statement));
    const row = try node.build(.program, 5, .{7} ** node.DIGEST_WORDS, .{8} ** node.DIGEST_WORDS);
    try std.testing.expectEqualDeep(row, node.fromColumns(M31, node.columns(M31, row)));
    _ = component.asProverComponent();
    _ = component.asVerifierComponent();
}
